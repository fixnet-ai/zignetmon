//! 系统 DNS 变化监测 — Windows 后端（design.md §3/§5）。
//!
//! Windows 把每适配器的 DNS 服务器存进注册表
//! `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\<GUID>` 下的
//! `NameServer` / `DhcpNameServer`（REG_SZ）等值（DHCP/静态配置写这里）。
//!
//! 本后端用 **RegNotifyChangeKeyValue**（advapi32，异步 + 事件）**递归监听**该
//! Interfaces 根键子树（b_watch_subtree=TRUE：任一接口子键的值变化/增删都会触发），
//! 后台线程 WaitForMultipleObjects 阻塞等待（非忙等），变化 → 重读当前 DNS
//! （network_params.queryDnsServers → GetAdaptersAddresses 读 effective DNS）
//! → diff → emit。读取与门面同源（GAA），保证 diff 判定一致。
//!
//! ⚠️ 平台说明：本文件仅 Windows 目标编译/运行；已用 x86_64-windows 交叉编译验证
//! 语法与类型（见任务记录）。**真事件触发 + 读取正确性待 windowsvm 真机验证**
//! （见文末 TODO）：本机 macOS 无法执行 advapi32 注册表调用。

const std = @import("std");
const builtin = @import("builtin");
const zf = @import("zigfoundation");
const dm = @import("dns_monitor.zig");
const params = @import("network_params.zig");

const DnsSettings = dm.DnsSettings;
const Callback = dm.Callback;

const is_windows = builtin.os.tag == .windows;

const MaxSubscribers: usize = 16;
const Subscriber = struct { cb: Callback, ctx: ?*anyopaque };

/// DNS 服务器上限：对齐 network.zig MAX_DNS_SERVERS（8），保证与门面快照一致。
const MaxDnsServers: usize = 8;

// ---- Win32 类型 ----
const HKEY = ?*anyopaque;
const HANDLE = ?*anyopaque;
const BOOL = i32;

const HKEY_LOCAL_MACHINE: HKEY = @ptrFromInt(@as(usize, 0x80000002));

// 注册表访问权（winreg.h）：KEY_NOTIFY 供 RegNotifyChangeKeyValue；KEY_QUERY_VALUE 备用。
const KEY_QUERY_VALUE: u32 = 0x0001;
const KEY_NOTIFY: u32 = 0x0010;
const WantedSam: u32 = KEY_QUERY_VALUE | KEY_NOTIFY;

// 通知过滤（winreg.h）：值名/子键增删（NAME）+ 值数据变更（LAST_SET）。
const REG_NOTIFY_CHANGE_NAME: u32 = 0x00000001;
const REG_NOTIFY_CHANGE_LAST_SET: u32 = 0x00000004;

const ERROR_SUCCESS: i32 = 0;

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

/// ASCII 编译期 → UTF-16LE 哨兵数组（注册表键名，纯 ASCII 常量）。
fn wstr(comptime s: []const u8) [s.len:0]u16 {
    var a: [s.len:0]u16 = undefined;
    for (s, 0..) |c, i| a[i] = c;
    return a;
}

/// Tcpip 参数根键：DNS 服务器值在其实例接口子键（GUID）下。
const Subkey = wstr("SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces");

/// 系统 DNS 变化监测器（Windows 注册表子树事件驱动）。
pub const Impl = struct {
    allocator: std.mem.Allocator,
    started: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    stop: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    thread: ?std.Thread = null,
    /// 共享锁：保护 buf/current + 订阅者注册表。
    mutex: zf.sync.Mutex = .{},
    buf: [MaxDnsServers]zf.net.IpAddr = undefined,
    buf_count: usize = 0,
    current: DnsSettings = .{},
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

        // 打开 HKLM Tcpip Interfaces 根键（递归 notify 需持续打开句柄）。
        var key: HKEY = null;
        const r = advapi32.RegOpenKeyExW(HKEY_LOCAL_MACHINE, &Subkey, 0, WantedSam, &key);
        if (r != ERROR_SUCCESS or key == null) {
            std.log.warn("[dns] win monitor: RegOpenKeyExW failed rc={d}", .{r});
            return;
        }
        self.hkey = key;

        self.stop_evt = kernel32.CreateEventW(null, 1, 0, null);
        self.change_evt = kernel32.CreateEventW(null, 1, 0, null);
        if (self.stop_evt == null or self.change_evt == null) {
            std.log.warn("[dns] win monitor: CreateEventW failed", .{});
            _ = advapi32.RegCloseKey(self.hkey);
            self.hkey = null;
            return;
        }
        self.stop.store(false, .release);

        self.refresh(false); // 基线
        self.thread = std.Thread.spawn(.{}, notifyLoop, .{self}) catch {
            std.log.warn("[dns] win monitor: thread spawn failed", .{});
            return;
        };
        std.log.info("[dns] win monitor started (HKLM Tcpip Parameters Interfaces, subtree)", .{});
    }

    pub fn subscribe(self: *Impl, cb: Callback, ctx: ?*anyopaque) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.sub_count >= MaxSubscribers) {
            std.log.warn("[dns] subscriber registry full ({d}), subscribe ignored", .{MaxSubscribers});
            return error.TooManySubscribers;
        }
        self.subs[self.sub_count] = .{ .cb = cb, .ctx = ctx };
        self.sub_count += 1;
    }

    /// 当前系统 DNS 快照；未 start / 从未成功读取时 null。
    pub fn snapshot(self: *Impl) ?DnsSettings {
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
    }

    // ---- 后台线程 ----

    fn notifyLoop(self: *Impl) void {
        var handles = [_]HANDLE{ self.change_evt, self.stop_evt };
        while (!self.stop.load(.acquire)) {
            // re-arm：异步 notify 每次事件后需重新调用（先重置事件再注册）。
            _ = kernel32.ResetEvent(handles[0]);
            const rn = advapi32.RegNotifyChangeKeyValue(
                self.hkey.?,
                1, // 递归子树：监听所有接口 GUID 子键的 DNS 值
                REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET,
                handles[0],
                1, // 异步：由事件通知
            );
            if (rn != ERROR_SUCCESS) {
                std.log.warn("[dns] win monitor: RegNotifyChangeKeyValue failed rc={d}, stop", .{rn});
                return;
            }
            const w = kernel32.WaitForMultipleObjects(handles.len, &handles, 0, INFINITE);
            if (w == WAIT_OBJECT_0) {
                std.log.info("[dns] win: Tcpip Parameters Interfaces changed", .{});
                self.refresh(true);
            } else {
                // stop 事件（w == WAIT_OBJECT_0+1）→ 退出循环
                return;
            }
        }
    }

    /// 重读当前 DNS → diff →（可选）emit。在后台线程调用。
    fn refresh(self: *Impl, do_emit: bool) void {
        var fetched: [MaxDnsServers]zf.net.IpAddr = undefined;
        const fetched_slice = params.queryDnsServers(&fetched);

        self.mutex.lock();
        const changed = !ipListEqual(self.current.servers, fetched_slice);
        if (changed) {
            if (fetched_slice.len > 0) @memcpy(self.buf[0..fetched_slice.len], fetched_slice);
            self.buf_count = fetched_slice.len;
            self.current = .{ .servers = self.buf[0..self.buf_count] };
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

/// 去重比较：两 IP 列表逐地址判等（顺序敏感：DNS 服务器顺序有意义）。
pub fn ipListEqual(a: []const zf.net.IpAddr, b: []const zf.net.IpAddr) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (!ipEqual(x, y)) return false;
    }
    return true;
}

/// IpAddr 判等（union(enum) 载荷为数组，避免依赖 == 合成；同 mod.zig ipEqual）。
fn ipEqual(a: zf.net.IpAddr, b: zf.net.IpAddr) bool {
    return switch (a) {
        .v4 => |x| switch (b) {
            .v4 => |y| std.mem.eql(u8, &x, &y),
            else => false,
        },
        .v6 => |x| switch (b) {
            .v6 => |y| std.mem.eql(u8, &x, &y),
            else => false,
        },
    };
}

// ============================================================
// 单元测试（纯 diff 部分；仅 windows 目标编译运行）
// ============================================================

const testing = std.testing;

test "dns_monitor_windows: ipListEqual 去重语义" {
    if (comptime !is_windows) return error.SkipZigTest;
    const a = [_]zf.net.IpAddr{ .{ .v4 = .{ 223, 5, 5, 5 } }, .{ .v4 = .{ 8, 8, 8, 8 } } };
    const same = [_]zf.net.IpAddr{ .{ .v4 = .{ 223, 5, 5, 5 } }, .{ .v4 = .{ 8, 8, 8, 8 } } };
    const reordered = [_]zf.net.IpAddr{ .{ .v4 = .{ 8, 8, 8, 8 } }, .{ .v4 = .{ 223, 5, 5, 5 } } };
    try testing.expect(ipListEqual(&a, &same));
    try testing.expect(!ipListEqual(&a, &reordered)); // 顺序敏感
    try testing.expect(!ipListEqual(&a, &.{}));
}

test "dns_monitor_windows: lifecycle 启停幂等" {
    if (comptime !is_windows) return error.SkipZigTest;
    var mon = try Impl.init(testing.allocator);
    defer mon.deinit();

    try testing.expect(mon.snapshot() == null); // 未 start → null
    try mon.start();
    try mon.start(); // 幂等
    mon.close();
    mon.close(); // 幂等
    try testing.expect(mon.thread == null);
}

// TODO(windowsvm 真机验证)：
//  1. 真机改适配器 DNS（netsh interface ip set dns / 设置面板 / DHCP 变更）
//     → 确认 RegNotifyChangeKeyValue 递归触发、snapshot 与 GAA 一致、去重正确。
//  2. close() 停线程无挂起（stop 事件唤醒 WaitForMultipleObjects）。
