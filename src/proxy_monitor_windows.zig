//! 系统代理变化监测 — Windows 后端（design.md §5.3）。
//!
//! Windows 把系统代理存进注册表 HKCU\Software\Microsoft\Windows\CurrentVersion\
//! Internet Settings（WinINet/浏览器层共用）：
//!   - `ProxyEnable`  (REG_DWORD)：1 = 启用显式代理服务器；
//!   - `ProxyServer`  (REG_SZ)："host:port"，或按协议 "http=h:8080;https=h:8443;socks=h:1080"；
//!   - `AutoConfigURL`(REG_SZ)：PAC 自动配置脚本 URL（无法表示为 host:port → disabled）。
//!
//! 本后端用 **RegNotifyChangeKeyValue**（advapi32，异步 + 事件）监听上述 key 变化，
//! 后台线程 WaitForMultipleObjects 阻塞等待（非忙等），变化 → 重读当前值 → diff → emit。
//! 事件驱动：Registry 写后同步到已打开 key 句柄的异步 notify（与 SCDynamicStore 同思路）。
//!
//! ⚠️ 平台说明：本文件仅 Windows 目标编译/运行；已用 x86_64-windows 交叉编译验证
//! 语法与类型（见任务记录）。**真事件触发 + 读取正确性待 windowsvm 真机验证**
//! （见文末 TODO）：本机 macOS 无法执行 advapi32 注册表调用。

const std = @import("std");
const builtin = @import("builtin");
const zf = @import("zigfoundation");
const pm = @import("proxy_monitor.zig");

const ProxySettings = pm.ProxySettings;
const Callback = pm.Callback;

const is_windows = builtin.os.tag == .windows;

const MaxSubscribers: usize = 16;
const Subscriber = struct { cb: Callback, ctx: ?*anyopaque };

// ---- Win32 类型 ----
const HKEY = ?*anyopaque;
const HANDLE = ?*anyopaque;
const BOOL = i32;

const HKEY_CURRENT_USER: HKEY = @ptrFromInt(@as(usize, 0x80000001));

// 注册表访问权（winreg.h）
const KEY_QUERY_VALUE: u32 = 0x0001;
const KEY_NOTIFY: u32 = 0x0010;
// 打开 Internet Settings key（sysproxy 读写同 key）
const WantedSam: u32 = KEY_QUERY_VALUE | KEY_NOTIFY;

// 通知过滤（winreg.h）
const REG_NOTIFY_CHANGE_NAME: u32 = 0x00000001;
const REG_NOTIFY_CHANGE_LAST_SET: u32 = 0x00000004;

// 值类型 / 返回码
const REG_SZ: u32 = 1;
const REG_DWORD: u32 = 4;
const ERROR_SUCCESS: i32 = 0;
const ERROR_MORE_DATA: i32 = 234;
const ERROR_FILE_NOT_FOUND: i32 = 2;

// 等待常量
const WAIT_OBJECT_0: u32 = 0;
const INFINITE: u32 = 0xFFFFFFFF;

const advapi32 = struct {
    extern "advapi32" fn RegOpenKeyExW(
        h_key: HKEY,
        lp_sub_key: [*:0]const u16,
        ul_options: u32,
        sam_desired: u32,
        phk_result: *HKEY,
    ) callconv(.winapi) i32;

    extern "advapi32" fn RegCloseKey(h_key: HKEY) callconv(.winapi) i32;

    extern "advapi32" fn RegNotifyChangeKeyValue(
        h_key: HKEY,
        b_watch_subtree: BOOL,
        dw_notify_filter: u32,
        h_event: HANDLE,
        f_asynchronous: BOOL,
    ) callconv(.winapi) i32;

    extern "advapi32" fn RegQueryValueExW(
        h_key: HKEY,
        lp_value_name: [*:0]const u16,
        lp_reserved: ?*anyopaque,
        lp_type: ?*u32,
        lp_data: ?[*]u8,
        lpcb_data: *u32,
    ) callconv(.winapi) i32;
};

const kernel32 = struct {
    extern "kernel32" fn CreateEventW(
        lp_attributes: ?*const anyopaque,
        b_manual_reset: BOOL,
        b_initial_state: BOOL,
        lp_name: ?[*:0]const u16,
    ) callconv(.winapi) HANDLE;

    extern "kernel32" fn ResetEvent(h_event: HANDLE) callconv(.winapi) BOOL;

    extern "kernel32" fn SetEvent(h_event: HANDLE) callconv(.winapi) BOOL;

    extern "kernel32" fn CloseHandle(h_object: HANDLE) callconv(.winapi) BOOL;

    extern "kernel32" fn WaitForMultipleObjects(
        n_count: u32,
        lp_handles: [*]const HANDLE,
        b_wait_all: BOOL,
        dw_milliseconds: u32,
    ) callconv(.winapi) u32;
};

/// ASCII 编译期 → UTF-16LE 哨兵数组（注册表键名/值名，纯 ASCII 常量）。
fn wstr(comptime s: []const u8) [s.len:0]u16 {
    var a: [s.len:0]u16 = undefined;
    for (s, 0..) |c, i| a[i] = c;
    return a;
}

const Subkey = wstr("Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings");

const val_enable = wstr("ProxyEnable");
const val_server = wstr("ProxyServer");
const val_autoconf = wstr("AutoConfigURL");

/// 系统代理变化监测器（Windows 注册表事件驱动）。
pub const Impl = struct {
    allocator: std.mem.Allocator,
    started: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    stop: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    thread: ?std.Thread = null,
    /// 共享锁：保护 current/host_buf + 订阅者注册表。
    mutex: zf.sync.Mutex = .{},
    current: ProxySettings = .{},
    host_buf: []u8 = &.{},
    snapshot_ready: bool = false,
    subs: [MaxSubscribers]Subscriber = undefined,
    sub_count: usize = 0,
    emit_scratch: [MaxSubscribers]Subscriber = undefined,
    // Windows 句柄（start 打开，close 关闭）
    hkey: HKEY = null,
    change_evt: HANDLE = null,
    stop_evt: HANDLE = null,

    pub fn init(allocator: std.mem.Allocator) !Impl {
        _ = builtin; // 显式引用：本文件仅 windows 编译
        return .{ .allocator = allocator };
    }

    /// 启动后台注册表监听线程（幂等）。
    pub fn start(self: *Impl) !void {
        if (self.started.swap(true, .acq_rel)) return;
        if (comptime !is_windows) return;

        // 打开 HKCU Internet Settings key（异步 notify 需持续打开句柄）。
        var key: HKEY = null;
        const r = advapi32.RegOpenKeyExW(HKEY_CURRENT_USER, &Subkey, 0, WantedSam, &key);
        if (r != ERROR_SUCCESS or key == null) {
            std.log.warn("[proxy] win monitor: RegOpenKeyExW failed rc={d}", .{r});
            return;
        }
        self.hkey = key;

        self.stop_evt = kernel32.CreateEventW(null, 1, 0, null);
        self.change_evt = kernel32.CreateEventW(null, 1, 0, null);
        if (self.stop_evt == null or self.change_evt == null) {
            std.log.warn("[proxy] win monitor: CreateEventW failed", .{});
            _ = advapi32.RegCloseKey(self.hkey);
            self.hkey = null;
            return;
        }
        self.stop.store(false, .release);

        self.refresh(false); // 基线
        self.thread = std.Thread.spawn(.{}, notifyLoop, .{self}) catch {
            std.log.warn("[proxy] win monitor: thread spawn failed", .{});
            return;
        };
        std.log.info("[proxy] win monitor started (HKCU Internet Settings)", .{});
    }

    pub fn subscribe(self: *Impl, cb: Callback, ctx: ?*anyopaque) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.sub_count >= MaxSubscribers) {
            std.log.warn("[proxy] subscriber registry full ({d}), subscribe ignored", .{MaxSubscribers});
            return error.TooManySubscribers;
        }
        self.subs[self.sub_count] = .{ .cb = cb, .ctx = ctx };
        self.sub_count += 1;
    }

    /// 当前系统代理快照；未 start / 从未成功读取时 null。
    pub fn snapshot(self: *Impl) ?ProxySettings {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (!self.snapshot_ready) return null;
        return self.current;
    }

    pub fn close(self: *Impl) void {
        self.started.store(false, .release);
        if (self.thread) |t| {
            self.stop.store(true, .release);
            if (self.stop_evt) |e| _ = kernel32.SetEvent(e);
            t.join();
            self.thread = null;
        }
        if (self.change_evt) |e| _ = kernel32.CloseHandle(e);
        self.change_evt = null;
        if (self.stop_evt) |e| _ = kernel32.CloseHandle(e);
        self.stop_evt = null;
        if (self.hkey) |k| _ = advapi32.RegCloseKey(k);
        self.hkey = null;
    }

    pub fn deinit(self: *Impl) void {
        self.close();
        self.allocator.free(self.host_buf);
        self.host_buf = &.{};
    }

    // ---- 后台线程 ----

    fn notifyLoop(self: *Impl) void {
        var handles = [_]HANDLE{ self.change_evt, self.stop_evt };
        while (!self.stop.load(.acquire)) {
            // re-arm：异步 notify 每次事件后需重新调用（先重置事件再注册）。
            _ = kernel32.ResetEvent(handles[0]);
            const rn = advapi32.RegNotifyChangeKeyValue(
                self.hkey.?,
                0, // 不递归子树（该 key 的直接值变化足够）
                REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET,
                handles[0],
                1, // 异步：由事件通知
            );
            if (rn != ERROR_SUCCESS) {
                std.log.warn("[proxy] win monitor: RegNotifyChangeKeyValue failed rc={d}, stop", .{rn});
                return;
            }
            const w = kernel32.WaitForMultipleObjects(handles.len, &handles, 0, INFINITE);
            if (w == WAIT_OBJECT_0) {
                std.log.info("[proxy] win: Internet Settings changed", .{});
                self.refresh(true);
            } else {
                // stop 事件（w == WAIT_OBJECT_0+1）→ 退出循环
                return;
            }
        }
    }

    /// 重读当前代理 → diff →（可选）emit。在后台线程调用。
    fn refresh(self: *Impl, do_emit: bool) void {
        var host_local: [512]u8 = undefined;
        const fetched = readSettings(self.hkey.?, &host_local) orelse ProxySettings{};

        self.mutex.lock();
        const changed = !settingsEqual(self.current, fetched);
        if (changed) {
            if (self.host_buf.len > 0) {
                self.allocator.free(self.host_buf);
                self.host_buf = &.{};
            }
            if (fetched.host) |h| {
                self.host_buf = self.allocator.dupe(u8, h) catch {
                    std.log.warn("[proxy] win: dup host failed, skip update", .{});
                    self.mutex.unlock();
                    return;
                };
            }
            self.current = ProxySettings{
                .enabled = fetched.enabled,
                .host = if (self.host_buf.len > 0) self.host_buf else null,
                .port = fetched.port,
            };
        }
        self.snapshot_ready = true;
        self.mutex.unlock();

        if (changed and do_emit) self.emit();
    }

    fn emit(self: *Impl) void {
        self.mutex.lock();
        const n = self.sub_count;
        if (n > 0) @memcpy(self.emit_scratch[0..n], self.subs[0..n]);
        self.mutex.unlock();
        for (self.emit_scratch[0..n]) |s| s.cb(&self.current, s.ctx);
    }
};

/// 读注册表显式代理 → ProxySettings（host 指向 host_buf；读失败/无显式代理返回 null）。
fn readSettings(hkey: HKEY, host_buf: []u8) ?ProxySettings {
    const enable = queryDword(hkey, &val_enable) orelse return null;
    var scratch: [512]u8 = undefined;
    if (enable == 0) {
        // 未启用显式代理：若仅 PAC（AutoConfigURL）则记 debug（disabled 语义）。
        if (querySz(hkey, &val_autoconf, &scratch)) |pac| {
            std.log.debug("[proxy] win: PAC-only (AutoConfigURL={s}), not reported as host:port", .{pac});
        }
        return ProxySettings{};
    }
    const server = querySz(hkey, &val_server, &scratch) orelse {
        std.log.warn("[proxy] win: ProxyEnable=1 but ProxyServer unreadable", .{});
        return ProxySettings{};
    };
    // parseProxyServer 把解析出的 host 拷入 host_buf 并返回其切片。
    return parseProxyServer(server, host_buf) orelse {
        std.log.debug("[proxy] win: ProxyServer '{s}' not a host:port", .{server});
        return ProxySettings{};
    };
}

/// 查 REG_DWORD 值；不存在/类型不符返回 null。
fn queryDword(hkey: HKEY, name: [*:0]const u16) ?u32 {
    var ty: u32 = 0;
    var data: u32 = 0;
    var cb: u32 = @sizeOf(u32);
    const r = advapi32.RegQueryValueExW(hkey, name, null, &ty, @ptrCast(&data), &cb);
    if (r != ERROR_SUCCESS or ty != REG_DWORD or cb < @sizeOf(u32)) return null;
    return data;
}

/// 查 REG_SZ 值并转 ASCII（proxy host/server/URL 为 ASCII）；不存在/类型不符/
/// 含非 ASCII/超出 out 返回 null。ASCII 结果写入 `out` 并返回其切片。
fn querySz(hkey: HKEY, name: [*:0]const u16, out: []u8) ?[]const u8 {
    // UTF-16LE 原始缓冲（注册表 REG_SZ 以 u16 码元存储）。
    var u16_buf: [256]u16 = undefined;
    var ty: u32 = 0;
    var cb: u32 = @sizeOf(@TypeOf(u16_buf));
    const r = advapi32.RegQueryValueExW(
        hkey,
        name,
        null,
        &ty,
        @ptrCast(&u16_buf),
        &cb,
    );
    if (r != ERROR_SUCCESS or ty != REG_SZ) return null;
    const units = @min(u16_buf.len, @as(usize, @intCast(cb)) / 2);
    if (units == 0) return null;
    const str = std.mem.sliceTo(u16_buf[0..units], 0);
    if (str.len == 0 or str.len > out.len) return null;
    for (str, 0..) |ch, i| {
        if (ch > 0x7f) return null; // 仅 ASCII（host/URL 足够）
        out[i] = @intCast(ch & 0xff);
    }
    return out[0..str.len];
}

/// 纯解析 Windows ProxyServer 字符串 → host:port（设计为可单测的纯函数）。
///
/// 两种形态：
///   - 单服务器："host:port" / "http://host:port"；
///   - 按协议列表："http=h:8080;https=h:8443;socks=h:1080" → 取 `http=` 段。
/// 返回 host 切片指向 `input`；无端口/格式非法返回 null。
pub fn parseProxyServer(input: []const u8, host_buf: []u8) ?ProxySettings {
    var server = std.mem.trim(u8, input, " \t\r\n");
    if (server.len == 0) return null;

    // 按协议列表：优先取 http= 段。
    if (std.mem.findScalar(u8, server, '=') != null) {
        var it = std.mem.splitScalar(u8, server, ';');
        var chosen: ?[]const u8 = null;
        while (it.next()) |seg_raw| {
            const seg = std.mem.trim(u8, seg_raw, " \t");
            if (std.mem.startsWith(u8, seg, "http=")) {
                chosen = std.mem.trimStart(u8, seg["http=".len..], " \t");
                break;
            }
        }
        server = chosen orelse return null;
        if (server.len == 0) return null;
    }

    // 剥掉可选的 scheme 前缀（http:// 等）。
    if (std.mem.find(u8, server, "://")) |i| server = server[i + 3 ..];

    // 分离 host:port（host 可能为 IPv6 字面量括在 [] 中，先处理）。
    var host: []const u8 = server;
    var port: u16 = 0;
    if (server.len >= 2 and server[0] == '[') {
        // "[::1]:8080"
        const close = std.mem.findScalar(u8, server, ']') orelse return null;
        host = server[1..close];
        const rest = server[close + 1 ..];
        if (rest.len > 0) {
            if (rest[0] != ':') return null;
            const ps = parsePort(rest[1..]) orelse return null;
            port = ps;
        }
    } else if (std.mem.findScalarLast(u8, server, ':')) |ci| {
        // "host:port"；若 ':' 后为空 → 非法
        if (ci + 1 >= server.len) return null;
        host = server[0..ci];
        port = parsePort(server[ci + 1 ..]) orelse return null;
    }
    if (host.len == 0 or host.len > host_buf.len) return null;
    @memcpy(host_buf[0..host.len], host);
    return ProxySettings{ .enabled = true, .host = host_buf[0..host.len], .port = port };
}

fn parsePort(s: []const u8) ?u16 {
    if (s.len == 0) return null;
    for (s) |c| if (!std.ascii.isDigit(c)) return null;
    return std.fmt.parseInt(u16, s, 10) catch null;
}

/// 去重比较。
fn settingsEqual(a: ProxySettings, b: ProxySettings) bool {
    if (a.enabled != b.enabled or a.port != b.port) return false;
    const ha = a.host orelse "";
    const hb = b.host orelse "";
    return std.mem.eql(u8, ha, hb);
}

// ============================================================
// 单元测试（纯解析部分；仅 windows 目标编译运行）
// ============================================================

const testing = std.testing;

test "proxy_monitor_windows: parseProxyServer 单服务器形态" {
    if (comptime !is_windows) return error.SkipZigTest;
    var buf: [256]u8 = undefined;
    const s = parseProxyServer("127.0.0.1:7890", &buf).?;
    try testing.expect(s.enabled);
    try testing.expectEqualStrings("127.0.0.1", s.host.?);
    try testing.expectEqual(@as(u16, 7890), s.port);
}

test "proxy_monitor_windows: parseProxyServer scheme 前缀 + IPv6" {
    if (comptime !is_windows) return error.SkipZigTest;
    var buf: [256]u8 = undefined;
    const a = parseProxyServer("http://10.0.0.2:8080", &buf).?;
    try testing.expectEqualStrings("10.0.0.2", a.host.?);
    try testing.expectEqual(@as(u16, 8080), a.port);
    const b = parseProxyServer("[::1]:1080", &buf).?;
    try testing.expectEqualStrings("::1", b.host.?);
    try testing.expectEqual(@as(u16, 1080), b.port);
}

test "proxy_monitor_windows: parseProxyServer 按协议列表取 http 段" {
    if (comptime !is_windows) return error.SkipZigTest;
    var buf: [256]u8 = undefined;
    const s = parseProxyServer("http=127.0.0.1:7890;https=127.0.0.1:7890;socks=127.0.0.1:1080", &buf).?;
    try testing.expectEqualStrings("127.0.0.1", s.host.?);
    try testing.expectEqual(@as(u16, 7890), s.port);
}

test "proxy_monitor_windows: parseProxyServer 非法 → null" {
    if (comptime !is_windows) return error.SkipZigTest;
    var buf: [256]u8 = undefined;
    try testing.expect(parseProxyServer("", &buf) == null);
    try testing.expect(parseProxyServer("host", &buf) == null); // 无端口
    try testing.expect(parseProxyServer("host:port", &buf) == null); // 端口非数字
    try testing.expect(parseProxyServer("socks=127.0.0.1:1080", &buf) == null); // 无 http 段
}

// TODO(windowsvm 真机验证)：
//  1. 真机设置 WinINet 系统代理（设置→网络→代理 / InternetSetOptionW 同源写注册表）
//     → 确认 RegNotifyChangeKeyValue 事件触发、snapshot 与注册表一致、去重正确。
//  2. ProxyServer 各形态（单服务器 / 协议列表 / IPv6 / scheme 前缀）真机覆盖。
//  3. close() 停线程无挂起（stop 事件唤醒 WaitForMultipleObjects）。
