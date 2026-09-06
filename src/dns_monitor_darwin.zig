//! 系统 DNS 变化监测 — macOS 后端（design.md §3/§5）。
//!
//! 事件源：**SystemConfiguration / SCDynamicStore** 的全局 DNS key
//! `State:/Network/Global/DNS`。configd 在系统 DNS 设置被修改时更新该 key 并通知
//! 订阅者（对标 sing-box proxy_darwin DNS 路径 + Apple 推荐做法）。变化 → 后台
//! CFRunLoop 线程触发 callout → 经 network_params.queryDnsServers 重读当前值
//! → diff → emit。
//!
//! 实现方式：**运行时 dlopen + dlsym** 解析 SystemConfiguration / CoreFoundation 符号
//! （不引入 framework 链接依赖；先例见 proxy_monitor_darwin.zig）。符号解析在 init 时
//! 完成一次，解析失败（极端环境缺 framework）→ start no-op + snapshot null。
//!
//! iOS：同一 darwin 文件分发（design 语义 stub），但 SCDynamicStore 对沙箱 app 不可用，
//! 因此内部 `if (comptime !is_macos)` 恒 no-op（不建线程、不解析符号）。
//!
//! 读取说明：复用 `network_params.queryDnsServers`（macOS 上尽力读 /etc/resolv.conf）。
//! 该函数与门面 network.zig 快照同源，保证 diff 判定一致；resolv.conf 非 SCDynamicStore
//! 权威源属既有局限（configd 通常同步刷新该文件，事件信号 key 变化 → 重读即可覆盖）。
//! TODO(权威读)：改 SCDynamicStoreCopyDNS 直读需把解析器加进本文件（与 proxy 解析同构），
//!   届时 network 门面同步升级，本文件按 design 保持与门面同读函数。
//!
//! 数据面说明：低频事件监测（非 DNS 热路径），允许后台线程 + 阻塞 CFRunLoop 等待
//! （非忙等）。事件回调在 CFRunLoop 线程触发，应尽快返回。

const std = @import("std");
const builtin = @import("builtin");
const zf = @import("zigfoundation");
const dm = @import("dns_monitor.zig");
const params = @import("network_params.zig");

const DnsSettings = dm.DnsSettings;
const Callback = dm.Callback;

const is_macos = builtin.os.tag == .macos;

const MaxSubscribers: usize = 16;
const Subscriber = struct { cb: Callback, ctx: ?*anyopaque };

/// DNS 服务器上限：对齐 network.zig MAX_DNS_SERVERS（8），保证与门面快照一致。
const MaxDnsServers: usize = 8;

// ---- CoreFoundation / SystemConfiguration 类型 ----
const CFTypeRef = ?*anyopaque;
const CFAllocatorRef = ?*const anyopaque;

// ---- C 运行时（动态符号解析）----
const dl = struct {
    extern "c" fn dlopen(path: [*:0]const u8, mode: c_int) ?*anyopaque;
    extern "c" fn dlsym(handle: ?*anyopaque, symbol: [*:0]const u8) ?*anyopaque;
};
const RTLD_LAZY: c_int = 1;

// CF 常量（不猜值）
const kCFStringEncodingASCII: u32 = 0x0600;

const SYSCONF_PATH = "/System/Library/Frameworks/SystemConfiguration.framework/SystemConfiguration";
const COREFOUNDATION_PATH = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation";

const DnsKey = "State:/Network/Global/DNS";

/// SCDynamicStoreCallBack：系统 DNS key 变化时在 CFRunLoop 线程被调用。
const SCDynCallout = *const fn (store: CFTypeRef, changed_keys: CFTypeRef, info: ?*anyopaque) callconv(.c) void;

/// SCDynamicStoreContext（info 承载 Impl 指针；create 时整结构被拷贝）。
const SCDynamicStoreContext = extern struct {
    version: isize,
    info: ?*anyopaque,
    retain: ?*const anyopaque,
    release: ?*const anyopaque,
    copy_description: ?*const anyopaque,
};

/// 解析得到的函数表（每条为一个 callconv(.c) fn 指针）。只需 proxy_darwin 符号表的
/// 子集：本后端读取走 network_params（无需 CFDictionary/CFBoolean 解析）。
const Sys = struct {
    // SystemConfiguration
    sc_create: *const fn (alloc: CFAllocatorRef, name: CFTypeRef, callout: SCDynCallout, ctx: ?*const anyopaque) callconv(.c) CFTypeRef,
    sc_set_notif: *const fn (store: CFTypeRef, keys: CFTypeRef, patterns: CFTypeRef) callconv(.c) bool,
    sc_mk_rls: *const fn (alloc: CFAllocatorRef, store: CFTypeRef, order: isize) callconv(.c) CFTypeRef,
    // CoreFoundation
    cf_release: *const fn (cf: CFTypeRef) callconv(.c) void,
    cf_mk_string: *const fn (alloc: CFAllocatorRef, cstr: [*:0]const u8, enc: u32) callconv(.c) CFTypeRef,
    cf_array_create: *const fn (alloc: CFAllocatorRef, values: [*]const CFTypeRef, count: isize, callbacks: ?*const anyopaque) callconv(.c) CFTypeRef,
    // CFRunLoop
    cf_rl_get_current: *const fn () callconv(.c) CFTypeRef,
    cf_rl_add_source: *const fn (rl: CFTypeRef, source: CFTypeRef, mode: CFTypeRef) callconv(.c) void,
    cf_rl_remove_source: *const fn (rl: CFTypeRef, source: CFTypeRef, mode: CFTypeRef) callconv(.c) void,
    cf_rl_run: *const fn () callconv(.c) void,
    cf_rl_stop: *const fn (rl: CFTypeRef) callconv(.c) void,
};

fn lookupFn(handle: ?*anyopaque, comptime T: type, comptime name: [:0]const u8) ?T {
    const h = handle orelse return null;
    const sym = dl.dlsym(h, name.ptr) orelse return null;
    const addr: usize = @intFromPtr(sym);
    return @ptrFromInt(addr);
}

/// 运行时解析全部符号；任一关键符号缺失返回 null（start 将 no-op）。
/// 注意：struct 字段名不是 decl，不能用 `Sys.sc_create` 取「字段类型」——改用
/// `@TypeOf(s.sc_create)`（仅取字段类型、不读未初始化值）。
fn loadSys() ?Sys {
    if (!is_macos) return null;
    const sc_h = dl.dlopen(SYSCONF_PATH, RTLD_LAZY) orelse return null;
    const cf_h = dl.dlopen(COREFOUNDATION_PATH, RTLD_LAZY) orelse return null;
    var s: Sys = undefined;
    s.sc_create = lookupFn(sc_h, @TypeOf(s.sc_create), "SCDynamicStoreCreate") orelse return null;
    s.sc_set_notif = lookupFn(sc_h, @TypeOf(s.sc_set_notif), "SCDynamicStoreSetNotificationKeys") orelse return null;
    s.sc_mk_rls = lookupFn(sc_h, @TypeOf(s.sc_mk_rls), "SCDynamicStoreCreateRunLoopSource") orelse return null;
    s.cf_release = lookupFn(cf_h, @TypeOf(s.cf_release), "CFRelease") orelse return null;
    s.cf_mk_string = lookupFn(cf_h, @TypeOf(s.cf_mk_string), "CFStringCreateWithCString") orelse return null;
    s.cf_array_create = lookupFn(cf_h, @TypeOf(s.cf_array_create), "CFArrayCreate") orelse return null;
    s.cf_rl_get_current = lookupFn(cf_h, @TypeOf(s.cf_rl_get_current), "CFRunLoopGetCurrent") orelse return null;
    s.cf_rl_add_source = lookupFn(cf_h, @TypeOf(s.cf_rl_add_source), "CFRunLoopAddSource") orelse return null;
    s.cf_rl_remove_source = lookupFn(cf_h, @TypeOf(s.cf_rl_remove_source), "CFRunLoopRemoveSource") orelse return null;
    s.cf_rl_run = lookupFn(cf_h, @TypeOf(s.cf_rl_run), "CFRunLoopRun") orelse return null;
    s.cf_rl_stop = lookupFn(cf_h, @TypeOf(s.cf_rl_stop), "CFRunLoopStop") orelse return null;
    return s;
}

fn mkString(s: *const Sys, cstr: [:0]const u8) CFTypeRef {
    return s.cf_mk_string(null, cstr.ptr, kCFStringEncodingASCII);
}

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

fn release(s: *const Sys, cf: CFTypeRef) void {
    if (cf != null) s.cf_release(cf);
}

// ============================================================
// Impl（与 dispatcher 契约一致：init/start/subscribe/snapshot/close/deinit）
// ============================================================

/// 系统 DNS 变化监测器（macOS SCDynamicStore；iOS no-op）。
pub const Impl = struct {
    allocator: std.mem.Allocator,
    started: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    stop: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    thread: ?std.Thread = null,
    /// 共享锁：保护 buf/current + 订阅者注册表。
    mutex: zf.sync.Mutex = .{},
    /// DNS 服务器内部缓冲（current.servers 借用此处；固定容量无 per-refresh 分配）。
    buf: [MaxDnsServers]zf.net.IpAddr = undefined,
    buf_count: usize = 0,
    current: DnsSettings = .{},
    snapshot_ready: bool = false,
    subs: [MaxSubscribers]Subscriber = undefined,
    sub_count: usize = 0,
    emit_scratch: [MaxSubscribers]Subscriber = undefined,
    // macOS SCDynamicStore 状态（dlopen 解析；iOS 不用）
    sys: ?Sys = null,
    store: CFTypeRef = null, // SCDynamicStoreRef
    source: CFTypeRef = null, // CFRunLoopSourceRef
    key_str: CFTypeRef = null, // 监听 key CFString
    name_str: CFTypeRef = null, // store 名 CFString
    mode_str: CFTypeRef = null, // "kCFRunLoopDefaultMode"
    /// 后台 CFRunLoop 引用（线程置位，close 经其停止）；0 = 未运行。
    rl_ref: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),

    pub fn init(allocator: std.mem.Allocator) !Impl {
        var mon = Impl{ .allocator = allocator };
        mon.sys = loadSys();
        if (mon.sys == null and is_macos) {
            std.log.warn("[dns] mac monitor: SystemConfiguration/CoreFoundation symbols unresolvable", .{});
        }
        return mon;
    }

    /// 启动后台 CFRunLoop 监听线程（幂等）。
    pub fn start(self: *Impl) !void {
        if (self.started.swap(true, .acq_rel)) return;
        if (comptime !is_macos) {
            // iOS：SCDynamicStore 对沙箱 app 不可用，恒 no-op。
            std.log.debug("[dns] mac monitor no-op on iOS", .{});
            return;
        }
        const s_val = self.sys orelse {
            std.log.warn("[dns] mac monitor: not started (sys load failed)", .{});
            return;
        };
        const s: *const Sys = &s_val;

        // 建 store + 通知 key（configd 侧注册，无需运行循环即可生效）。
        self.key_str = mkString(s, DnsKey);
        if (self.key_str == null) {
            std.log.warn("[dns] mac monitor: mkString(key) failed", .{});
            return;
        }
        self.mode_str = mkString(s, "kCFRunLoopDefaultMode");
        self.name_str = mkString(s, "fixnet.dns.monitor");
        if (self.mode_str == null or self.name_str == null) {
            self.releaseObjects();
            std.log.warn("[dns] mac monitor: mkString failed", .{});
            return;
        }

        var ctx = SCDynamicStoreContext{
            .version = 0,
            .info = self,
            .retain = null,
            .release = null,
            .copy_description = null,
        };
        self.store = s.sc_create(null, self.name_str.?, onDnsChange, &ctx);
        if (self.store == null) {
            self.releaseObjects();
            self.started.store(false, .release);
            std.log.warn("[dns] mac monitor: SCDynamicStoreCreate failed", .{});
            return error.FailedToStartMonitor;
        }
        // 通知 keys：单个全局 DNS key。
        const keys_val = [_]CFTypeRef{self.key_str.?};
        const keys_arr = s.cf_array_create(null, &keys_val, keys_val.len, null);
        if (keys_arr == null) {
            self.releaseObjects();
            self.started.store(false, .release);
            return error.FailedToStartMonitor;
        }
        const ok = s.sc_set_notif(self.store.?, keys_arr, null);
        s.cf_release(keys_arr);
        if (!ok) {
            self.releaseObjects();
            self.started.store(false, .release);
            std.log.warn("[dns] mac monitor: SCDynamicStoreSetNotificationKeys failed", .{});
            return error.FailedToStartMonitor;
        }
        self.source = s.sc_mk_rls(null, self.store.?, 0);
        if (self.source == null) {
            self.releaseObjects();
            self.started.store(false, .release);
            return error.FailedToStartMonitor;
        }

        // 基线：先同步读一次当前值（不 emit），使 snapshot 立即可用。
        self.refresh(false);

        self.stop.store(false, .release);
        self.thread = std.Thread.spawn(.{}, runLoopThread, .{self}) catch {
            self.releaseObjects();
            self.started.store(false, .release);
            std.log.warn("[dns] mac monitor: thread spawn failed", .{});
            return error.FailedToStartMonitor;
        };
        std.log.info("[dns] mac monitor started (SCDynamicStore Global/DNS)", .{});
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

    /// 停止后台线程（幂等）：置 stop + CFRunLoopStop + join。
    pub fn close(self: *Impl) void {
        self.started.store(false, .release);
        if (self.thread) |t| {
            self.stop.store(true, .release);
            // 等待线程把 runloop ref 置位（最多 ~200ms），然后 stop 之。
            var waited: usize = 0;
            while (self.rl_ref.load(.acquire) == 0 and waited < 200) : (waited += 1) {
                zf.platform.sleepNs(1 * std.time.ns_per_ms);
            }
            const rl = self.rl_ref.load(.acquire);
            if (rl != 0) {
                if (self.sys) |s| s.cf_rl_stop(@ptrFromInt(rl));
            }
            t.join();
            self.thread = null;
            std.log.debug("[dns] mac monitor stopped", .{});
        }
        self.releaseObjects();
    }

    pub fn deinit(self: *Impl) void {
        self.close();
    }

    // ---- 后台 CFRunLoop 线程 ----

    fn runLoopThread(self: *Impl) void {
        const s_val = self.sys orelse return;
        const s: *const Sys = &s_val;
        const rl = s.cf_rl_get_current();
        if (rl == null) return;
        self.rl_ref.store(@intFromPtr(rl), .release);
        s.cf_rl_add_source(rl, self.source.?, self.mode_str.?);
        s.cf_rl_run();
        s.cf_rl_remove_source(rl, self.source.?, self.mode_str.?);
        self.rl_ref.store(0, .release);
    }

    /// 重读当前 DNS → diff →（可选）emit。在 CFRunLoop 线程/start 同步调用。
    fn refresh(self: *Impl, do_emit: bool) void {
        if (comptime !is_macos) return;
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

    /// 释放 CF 对象（close 或 start 中途失败后调用）。
    fn releaseObjects(self: *Impl) void {
        const s_val = self.sys orelse return;
        const s: *const Sys = &s_val;
        release(s, self.store);
        self.store = null;
        release(s, self.source);
        self.source = null;
        release(s, self.key_str);
        self.key_str = null;
        release(s, self.name_str);
        self.name_str = null;
        release(s, self.mode_str);
        self.mode_str = null;
    }
};

/// SCDynamicStore 变化 callout（CFRunLoop 线程触发）。
fn onDnsChange(store: CFTypeRef, changed_keys: CFTypeRef, info: ?*anyopaque) callconv(.c) void {
    _ = store;
    _ = changed_keys;
    const self: *Impl = @ptrCast(@alignCast(info orelse return));
    std.log.info("[dns] mac: Global/DNS changed", .{});
    self.refresh(true);
}

// ============================================================
// 单元测试（macOS 上运行：纯 diff 解析 + 生命周期 + 真值读取）
// ============================================================

const testing = std.testing;

/// 测试回调上下文（后台线程写、主线程读 → 锁保护）。
const TestCtx = struct {
    mutex: zf.sync.Mutex = .{},
    fired: bool = false,
};

fn onChange(settings: *const DnsSettings, ctx: ?*anyopaque) void {
    _ = settings;
    const c: *TestCtx = @ptrCast(@alignCast(ctx.?));
    c.mutex.lock();
    defer c.mutex.unlock();
    c.fired = true;
}

fn firedFlag(ctx: ?*anyopaque) bool {
    const c: *TestCtx = @ptrCast(@alignCast(ctx.?));
    c.mutex.lock();
    defer c.mutex.unlock();
    return c.fired;
}

test "dns_monitor_darwin: ipListEqual 去重语义" {
    if (comptime !is_macos) return error.SkipZigTest;
    const a = [_]zf.net.IpAddr{ .{ .v4 = .{ 223, 5, 5, 5 } }, .{ .v4 = .{ 8, 8, 8, 8 } } };
    const same = [_]zf.net.IpAddr{ .{ .v4 = .{ 223, 5, 5, 5 } }, .{ .v4 = .{ 8, 8, 8, 8 } } };
    const reordered = [_]zf.net.IpAddr{ .{ .v4 = .{ 8, 8, 8, 8 } }, .{ .v4 = .{ 223, 5, 5, 5 } } };
    const v6 = [_]zf.net.IpAddr{ .{ .v4 = .{ 223, 5, 5, 5 } }, .{ .v6 = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } } };
    try testing.expect(ipListEqual(&a, &same));
    try testing.expect(!ipListEqual(&a, &reordered)); // 顺序敏感
    try testing.expect(!ipListEqual(&a, &v6)); // v4/v6 不相等
    try testing.expect(!ipListEqual(&a, &.{}));
}

test "dns_monitor_darwin: lifecycle 启停幂等 + snapshot 一致性" {
    if (comptime !is_macos) return error.SkipZigTest;
    var mon = try Impl.init(testing.allocator);
    defer mon.deinit();

    // snapshot 未 start → null
    try testing.expect(mon.snapshot() == null);

    try mon.start();
    try mon.start(); // 幂等
    try testing.expect(mon.thread != null);

    // 基线已在 start 同步读 → snapshot 就绪
    try testing.expect(mon.snapshot() != null);

    mon.close();
    mon.close(); // 幂等
    try testing.expect(mon.thread == null);

    // close 后可再 start（线程可复用）
    try mon.start();
    try testing.expect(mon.thread != null);
    mon.close();
    try testing.expect(mon.thread == null);
}

test "dns_monitor_darwin: 真读系统 DNS 返回格式正确快照" {
    // 端到端：queryDnsServers 真读（macOS 尽力 /etc/resolv.conf），不依赖事件。
    // 验证 snapshot 非空时每个条目都是合法 IP（v4/v6 载荷长度正确）且与真读一致。
    if (comptime !is_macos) return error.SkipZigTest;
    var mon = try Impl.init(testing.allocator);
    defer mon.deinit();

    var local: [MaxDnsServers]zf.net.IpAddr = undefined;
    const real = params.queryDnsServers(&local);
    if (real.len == 0) return; // 本机 resolv.conf 无 nameserver：合法，跳过断言

    try mon.start();
    defer mon.close();
    const got = mon.snapshot() orelse return error.SkipZigTest;
    try testing.expectEqual(real.len, got.servers.len);
    for (got.servers) |ip| {
        switch (ip) {
            .v4 => |v| try testing.expectEqual(@as(usize, 4), v.len),
            .v6 => |v| try testing.expectEqual(@as(usize, 16), v.len),
        }
    }
    try testing.expect(ipListEqual(real, got.servers));
}

// TODO(mac 真机事件验证)：
//  design.md §6 要求真事件经真实机器验证——本机自动化不修改系统 DNS，故事件触发
//  （System Settings / networksetup 改 DNS → callout 触发 → 重读 → emit）留到
//  macvm 真机：改 DNS → 确认 emit 且 snapshot 与系统一致、还原 → 去重正确。
