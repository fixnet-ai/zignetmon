//! 系统代理变化监测 — Linux 后端（design.md §5.3 尽力而为）。
//!
//! 目标事件源：GNOME 桌面把系统代理存进 dconf（`~/.config/dconf/user`，
//! schema `org.gnome.system.proxy`）。本文件用 **inotify** 监听该 dconf 目录，
//! 文件被写（gsettings/任何 dconf 写）→ 事件 → 尽力读取当前代理 → diff → emit。
//!
//! 「尽力而为」边界（本文件明确限定，非全量系统代理方案）：
//!   - 只覆盖 GNOME（gsettings/dconf）写系统代理的路径；KDE/独立 WM/手动
//!     `export http_proxy` 等不在覆盖内（各自事件源不同，见 findings.md）；
//!   - 读取当前值经一次 `gsettings list-recursively org.gnome.system.proxy`
//!     子进程（比逐 key popen 少 2~3 次进程）；headless / 无 gsettings 时按
//!     disabled 处理并记 debug；
//!   - 后台线程阻塞在 poll(100ms 超时)（非忙等），close 由 stop 标志驱动；
//!   - ⚠️ 真事件 + 读取正确性待 **linuxvm 真机验证**（见文末 TODO）。
//!
//! ProxySettings 语义与 dispatcher 一致：enabled ⇔ manual 模式显式代理解析出
//! host;PAC(auto) 无法表示为 host:port → disabled（记 debug）。

const std = @import("std");
const builtin = @import("builtin");
const zf = @import("zigfoundation");
const pm = @import("proxy_monitor.zig");

const ProxySettings = pm.ProxySettings;
const Callback = pm.Callback;

const is_linux = builtin.os.tag == .linux and builtin.abi != .android;

const MaxSubscribers: usize = 16;

const Subscriber = struct {
    cb: Callback,
    ctx: ?*anyopaque,
};

const DconfDir = ".config/dconf";
const DconfFile = "user";

// inotify 常量（linux/inotify.h）。
const IN_MODIFY: u32 = 0x00000002;
const IN_CLOSE_WRITE: u32 = 0x00000008;
const IN_MOVED_TO: u32 = 0x00000080;
const IN_CREATE: u32 = 0x00000100;
const IN_NONBLOCK: u32 = 0x00000800; // = O_NONBLOCK
const IN_CLOEXEC: u32 = 0x00800000; // = O_CLOEXEC
const WatchMask: u32 = IN_MODIFY | IN_CLOSE_WRITE | IN_CREATE | IN_MOVED_TO;

const InotifyEventHdr = extern struct {
    wd: i32,
    mask: u32,
    cookie: u32,
    len: u32,
};

const libc = struct {
    extern "c" fn inotify_init1(flags: c_int) c_int;
    extern "c" fn inotify_add_watch(fd: c_int, path: [*:0]const u8, mask: u32) c_int;
    extern "c" fn popen(command: [*:0]const u8, mode: [*:0]const u8) ?*anyopaque;
    extern "c" fn pclose(stream: *anyopaque) c_int;
    extern "c" fn fgetc(stream: *anyopaque) c_int;
};

/// 后台 inotify 线程驱动的系统代理监测器（linux 桌面，尽力而为）。
pub const Impl = struct {
    allocator: std.mem.Allocator,
    /// dup 的 dconf 目录绝对路径；空 = 无 HOME（no-op）。
    dconf_dir: []u8,
    started: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    stop: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    thread: ?std.Thread = null,
    /// 共享锁：保护 current/host_buf + 订阅者注册表。
    mutex: zf.sync.Mutex = .{},
    /// 当前快照；host 指向 host_buf（借用语义见 dispatcher 文件头）。
    current: ProxySettings = .{},
    host_buf: []u8 = &.{},
    snapshot_ready: bool = false,
    subs: [MaxSubscribers]Subscriber = undefined,
    sub_count: usize = 0,
    emit_scratch: [MaxSubscribers]Subscriber = undefined,

    pub fn init(allocator: std.mem.Allocator) !Impl {
        var dir: []u8 = undefined;
        if (comptime is_linux) {
            if (std.c.getenv("HOME")) |home_raw| {
                const home = std.mem.sliceTo(home_raw, 0);
                dir = if (home.len > 0)
                    try std.fs.path.join(allocator, &.{ home, DconfDir })
                else
                    try allocator.dupe(u8, "");
            } else {
                dir = try allocator.dupe(u8, "");
            }
        } else {
            dir = try allocator.dupe(u8, "");
        }
        errdefer allocator.free(dir);
        return .{ .allocator = allocator, .dconf_dir = dir };
    }

    /// 启动后台 inotify 监测线程（幂等）。空目录（无 HOME）→ no-op。
    pub fn start(self: *Impl) !void {
        if (self.started.swap(true, .acq_rel)) return;
        if (comptime !is_linux) return;
        if (self.dconf_dir.len == 0) {
            std.log.debug("[proxy] linux monitor: no HOME, disabled", .{});
            return;
        }
        self.stop.store(false, .release);
        self.refresh(false); // 基线：尽力读一次当前值（不 emit），使 snapshot 有值
        self.thread = try std.Thread.spawn(.{}, monitorLoop, .{self});
        std.log.info("[proxy] linux monitor started dir={s}", .{self.dconf_dir});
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
            t.join();
            self.thread = null;
        }
    }

    pub fn deinit(self: *Impl) void {
        self.close();
        self.allocator.free(self.host_buf);
        self.host_buf = &.{};
        self.allocator.free(self.dconf_dir);
        self.dconf_dir = &.{};
    }

    // ---- 后台线程 ----

    fn monitorLoop(self: *Impl) void {
        const inotify_fd = libc.inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
        if (inotify_fd < 0) {
            std.log.warn("[proxy] linux monitor: inotify_init1 failed, disabled", .{});
            return;
        }
        defer _ = std.c.close(inotify_fd);

        var dir_z: [std.fs.max_path_bytes:0]u8 = undefined;
        if (self.dconf_dir.len >= dir_z.len) return;
        @memcpy(dir_z[0..self.dconf_dir.len], self.dconf_dir);
        dir_z[self.dconf_dir.len] = 0;

        // dconf 目录可能尚不存在（首次 gsettings 写才建库）：此时 add_watch 失败，
        // 仅跳过（snapshot 仍尽力读）。TODO: 退化为监听 $HOME/.config 的 IN_CREATE。
        const wd = libc.inotify_add_watch(inotify_fd, &dir_z, WatchMask);
        if (wd < 0) {
            std.log.debug("[proxy] linux monitor: dconf dir not present ({s}), event watch skipped", .{self.dconf_dir});
        }

        var pfd = [_]std.c.pollfd{.{ .fd = inotify_fd, .events = std.c.POLL.IN, .revents = 0 }};
        while (!self.stop.load(.acquire)) {
            const rc = std.c.poll(&pfd, 1, 100);
            if (rc < 0) {
                if (std.c.errno(rc) == std.posix.E.INTR) continue;
                break;
            }
            if (rc == 0) continue; // 超时：回卷检查 stop
            var buf: [4096]u8 = undefined;
            const n = std.c.read(inotify_fd, &buf, buf.len);
            if (n <= 0) continue;
            if (containsUserEvent(buf[0..@intCast(n)])) {
                std.log.info("[proxy] linux: dconf {s} changed", .{DconfFile});
                self.refresh(true);
            }
        }
    }

    /// 尽力读当前代理 → diff →（可选）emit。在后台线程调用。
    fn refresh(self: *Impl, do_emit: bool) void {
        var host_local: [256]u8 = undefined;
        const fetched = readGnomeProxyBestEffort(&host_local);

        self.mutex.lock();
        const changed = !settingsEqual(self.current, fetched);
        if (changed) {
            if (self.host_buf.len > 0) {
                self.allocator.free(self.host_buf);
                self.host_buf = &.{};
            }
            if (fetched.host) |h| {
                self.host_buf = self.allocator.dupe(u8, h) catch {
                    std.log.warn("[proxy] linux: dup host failed, skip update", .{});
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

/// 事件缓冲区是否含 dconf "user" 文件名事件。
fn containsUserEvent(buf: []const u8) bool {
    var off: usize = 0;
    while (off + @sizeOf(InotifyEventHdr) <= buf.len) {
        const hdr: *align(1) const InotifyEventHdr = @ptrCast(buf.ptr + off);
        if (hdr.len == 0) {
            off += @sizeOf(InotifyEventHdr);
            continue;
        }
        const name_start = off + @sizeOf(InotifyEventHdr);
        const name_end = @min(buf.len, name_start + hdr.len);
        const name = buf[name_start..name_end];
        const name_s = std.mem.sliceTo(name, 0);
        if (std.mem.eql(u8, name_s, DconfFile)) return true;
        off = name_end;
    }
    return false;
}

/// 尽力读 GNOME 系统代理（manual → http/https/socks 显式代理）。
/// 返回 host 指向 `host_buf`（调用方生命周期内有效）。
fn readGnomeProxyBestEffort(host_buf: []u8) ProxySettings {
    var out: [4096]u8 = undefined;
    var n: usize = 0;
    {
        var cmd_z: [256:0]u8 = undefined;
        const cmd = "gsettings list-recursively org.gnome.system.proxy 2>/dev/null";
        @memcpy(cmd_z[0..cmd.len], cmd);
        cmd_z[cmd.len] = 0;
        const pipe = libc.popen(&cmd_z, "r") orelse return ProxySettings{};
        defer _ = libc.pclose(pipe);
        while (n < out.len) : (n += 1) {
            const c = libc.fgetc(pipe);
            if (c == -1) break;
            out[n] = @intCast(c);
        }
    }
    return parseGsettingsProxy(out[0..n], host_buf);
}

const Slot = struct {
    enabled: bool = false,
    host: []const u8 = "",
    port: u16 = 0,
};

/// 纯解析：`gsettings list-recursively org.gnome.system.proxy` 输出 → ProxySettings。
///
/// 每行形如 `org.gnome.system.proxy.http host '127.0.0.1'`（空格分隔，
/// gsettings 对字符串值加单引号）。schema 前缀逐行判定后路由到 http/https/socks
/// 槽位;mode 决定最终语义：manual → 取优先 enabled 且 host 非空的槽;auto(PAC)
/// 或 none → disabled。
pub fn parseGsettingsProxy(output: []const u8, host_buf: []u8) ProxySettings {
    var mode: []const u8 = "";
    var http = Slot{};
    var https = Slot{};
    var socks = Slot{};

    const proxy_prefix = "org.gnome.system.proxy";
    var lines = std.mem.splitScalar(u8, output, '\n');
    while (lines.next()) |line_raw| {
        const line = std.mem.trim(u8, line_raw, " \t\r");
        if (line.len == 0) continue;
        const sp1 = std.mem.findScalar(u8, line, ' ') orelse continue;
        const schema = line[0..sp1];
        const after1 = std.mem.trimStart(u8, line[sp1 + 1 ..], " \t");
        const sp2 = std.mem.findScalar(u8, after1, ' ') orelse continue;
        const prop = after1[0..sp2];
        const value = stripQuotes(std.mem.trimStart(u8, after1[sp2 + 1 ..], " \t"));

        // 根 schema：mode
        if (std.mem.eql(u8, schema, proxy_prefix)) {
            if (std.mem.eql(u8, prop, "mode")) mode = value;
            continue;
        }
        // 子 schema：org.gnome.system.proxy.http / .https / .socks
        if (!std.mem.startsWith(u8, schema, proxy_prefix ++ ".")) continue;
        const subschema = schema[proxy_prefix.len + 1 ..];
        const slot = if (std.mem.eql(u8, subschema, "http"))
            &http
        else if (std.mem.eql(u8, subschema, "https"))
            &https
        else if (std.mem.eql(u8, subschema, "socks"))
            &socks
        else
            continue;

        if (std.mem.eql(u8, prop, "enabled")) {
            slot.enabled = std.mem.eql(u8, value, "true");
        } else if (std.mem.eql(u8, prop, "host")) {
            slot.host = value;
        } else if (std.mem.eql(u8, prop, "port")) {
            slot.port = std.fmt.parseInt(u16, value, 10) catch 0;
        }
    }

    if (std.mem.eql(u8, mode, "manual")) {
        return pickSlot(host_buf, http, https, socks) orelse ProxySettings{};
    }
    // auto(PAC)/none/未知：无法表示为 host:port → disabled
    if (std.mem.eql(u8, mode, "auto")) {
        std.log.debug("[proxy] linux: PAC(auto) proxy only, not reported (no host:port)", .{});
    }
    return ProxySettings{};
}

/// 优先级 http > https > socks，取第一个 enabled 且 host 非空的槽；host 拷入 buf。
fn pickSlot(host_buf: []u8, http: Slot, https: Slot, socks: Slot) ?ProxySettings {
    for ([_]Slot{ http, https, socks }) |s| {
        if (!s.enabled) continue;
        if (s.host.len == 0 or s.host.len > host_buf.len) continue;
        @memcpy(host_buf[0..s.host.len], s.host);
        return ProxySettings{ .enabled = true, .host = host_buf[0..s.host.len], .port = s.port };
    }
    return null;
}

/// 去单引号（gsettings 值形如 'manual'；空串值形如 ''）。
fn stripQuotes(s: []const u8) []const u8 {
    const t = std.mem.trim(u8, s, " \t");
    if (t.len >= 2 and t[0] == '\'' and t[t.len - 1] == '\'') return t[1 .. t.len - 1];
    return t;
}

/// 去重比较。
fn settingsEqual(a: ProxySettings, b: ProxySettings) bool {
    if (a.enabled != b.enabled or a.port != b.port) return false;
    const ha = a.host orelse "";
    const hb = b.host orelse "";
    return std.mem.eql(u8, ha, hb);
}

// ============================================================
// 单元测试（仅 linux 目标编译并运行；纯解析不依赖 OS 事件源）
// ============================================================

const testing = std.testing;

test "proxy_monitor_linux: parseGsettingsProxy manual http 优先 https" {
    if (comptime !is_linux) return error.SkipZigTest;
    const out =
        "org.gnome.system.proxy mode 'manual'\n" ++
        "org.gnome.system.proxy.http enabled true\n" ++
        "org.gnome.system.proxy.http host '127.0.0.1'\n" ++
        "org.gnome.system.proxy.http port 7890\n" ++
        "org.gnome.system.proxy.https enabled true\n" ++
        "org.gnome.system.proxy.https host '127.0.0.1'\n" ++
        "org.gnome.system.proxy.https port 7890\n";
    var buf: [256]u8 = undefined;
    const s = parseGsettingsProxy(out, &buf);
    try testing.expect(s.enabled);
    try testing.expectEqualStrings("127.0.0.1", s.host.?);
    try testing.expectEqual(@as(u16, 7890), s.port);
}

test "proxy_monitor_linux: parseGsettingsProxy http 关闭 → socks 回退" {
    if (comptime !is_linux) return error.SkipZigTest;
    const out =
        "org.gnome.system.proxy mode 'manual'\n" ++
        "org.gnome.system.proxy.http enabled false\n" ++
        "org.gnome.system.proxy.socks enabled true\n" ++
        "org.gnome.system.proxy.socks host '10.0.0.2'\n" ++
        "org.gnome.system.proxy.socks port 1080\n";
    var buf: [256]u8 = undefined;
    const s = parseGsettingsProxy(out, &buf);
    try testing.expect(s.enabled);
    try testing.expectEqualStrings("10.0.0.2", s.host.?);
    try testing.expectEqual(@as(u16, 1080), s.port);
}

test "proxy_monitor_linux: parseGsettingsProxy none / auto → disabled" {
    if (comptime !is_linux) return error.SkipZigTest;
    var buf: [256]u8 = undefined;
    const none = parseGsettingsProxy("org.gnome.system.proxy mode 'none'\n", &buf);
    try testing.expect(!none.enabled);
    try testing.expect(none.host == null);
    const auto = parseGsettingsProxy("org.gnome.system.proxy mode 'auto'\n", &buf);
    try testing.expect(!auto.enabled);
}

test "proxy_monitor_linux: containsUserEvent 文件名过滤" {
    if (comptime !is_linux) return error.SkipZigTest;
    const make = struct {
        fn f(name: []const u8) [128]u8 {
            var b = [_]u8{0} ** 128;
            const hdr = InotifyEventHdr{ .wd = 1, .mask = IN_CLOSE_WRITE, .cookie = 0, .len = @intCast(name.len + 1) };
            @memcpy(b[0..@sizeOf(InotifyEventHdr)], std.mem.asBytes(&hdr));
            @memcpy(b[@sizeOf(InotifyEventHdr) .. @sizeOf(InotifyEventHdr) + name.len], name);
            return b;
        }
    }.f;
    try testing.expect(containsUserEvent(&make("user")));
    try testing.expect(!containsUserEvent(&make("other")));
}

// TODO(linuxvm 真机验证)：
//  1. 真机 gsettings set org.gnome.system.proxy mode manual + http host/port
//     → 确认 inotify 事件触发、snapshot 与 gsettings 一致、去重正确。
//  2. dconf 目录首次写前不存在 → 当前 add_watch 失败跳过、事件丢失
//     （尽力而为边界；将来可退化为监听父目录 IN_CREATE）。
//  3. 非 GNOME 桌面返回 disabled 属预期。
