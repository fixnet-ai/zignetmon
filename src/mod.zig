//! zignetmon — 网络变化监测与自适应库（统一语义事件门面）
//!
//! 覆盖「路由 / 系统 DNS / 任意网卡 / 系统代理 / hosts 文件」五类关键网络设置变化
//! × 五平台（macOS / Windows / Linux / iOS / Android）的事件源监测与归一化。
//!
//! 本文件是 **归一化层（门面）**（design.md §4 ②）：订阅三个子监测（network /
//! hosts_monitor / proxy_monitor）的裸事件，比对缓存快照 → diff → 映射为 6 值
//! ChangeKind 语义事件，以统一 Callback(kind, Snapshot) 派发给决策层（消费方）。
//!
//! ## 语义映射（design.md §5.4）
//! 收到 network 回调（NetworkInfo）与上次缓存快照 diff：
//!   - gateway 变化            → ChangeKind.route
//!   - 默认接口身份变化（含无→有/有→无）→ ChangeKind.default_route
//!   - DNS 列表变化             → ChangeKind.dns
//!   - 同接口属性变化（mtu/up/地址）  → ChangeKind.interface
//! hosts / proxy 子监测回调 → ChangeKind.hosts / ChangeKind.proxy。
//!
//! ## 基线（baseline）语义
//! 首个 network 事件仅建立基线（不派发），避免消费方在 start 时收到一次
//! 「从无到有」的伪变化；start 后若尚未收到事件则用 network.snapshot() 播种基线。
//! 相同事件连续到达（network 内部已有 1s 防抖，门面不叠加）→ diff 为空 → 不派发。
//!
//! ## Snapshot 所有权
//! Snapshot 内 default_interface / dns_servers / proxy.host 均为底层 monitor 内部
//! 缓冲的**借用**，仅在下一次对应事件前有效；消费方需持久使用时自行拷贝。
//!
//! ## 线程模型
//! network / hosts / proxy 回调各在自己的后台线程触发；门面内部订阅注册表与
//! 快照基线用 `zf.sync.Mutex` 保护，回调在锁外派发（避免重入死锁）。
//!
//! ## 可观测（design.md §5.5）
//! `ZF_NETWORK_TRACE=1` 开启 info 级全流程日志（事件源 → diff → 分发），默认关。

const std = @import("std");
const builtin = @import("builtin");
const zf = @import("zigfoundation");
const types = @import("types.zig");
const ntypes = @import("network_types.zig"); // 仅门面内部（Facts 物化）引用

/// 网络门面（单例 + 回调 + 快照）。移植自 zf.network（#43）。
pub const network = @import("network.zig");

/// 宿主系统代理副作用（set/restore 原语）。移植自 zf.system_proxy（#79）。
pub const system_proxy = @import("system_proxy.zig");

/// hosts 文件变化监测（跨平台后台线程 stat diff）。
pub const hosts_monitor = @import("hosts_monitor.zig");

/// 系统代理变化监测（分平台）。
pub const proxy_monitor = @import("proxy_monitor.zig");

/// 语义事件类型（六值，见 design.md §5.1）。
pub const ChangeKind = types.ChangeKind;

/// 归一化快照 — 回调携带 + `snapshot()` 主动查询共用。
/// 字段为借用（见文件头「Snapshot 所有权」）。
pub const Snapshot = struct {
    default_interface: ?network.Interface = null,
    gateway: ?zf.net.IpAddr = null,
    dns_servers: []const zf.net.IpAddr = &.{},
    proxy: ?proxy_monitor.ProxySettings = null,
    hosts_mtime: ?i128 = null,
};

/// 统一语义事件回调：kind 指示哪一类变化，snap 为变化后全量快照。
pub const Callback = *const fn (kind: ChangeKind, snap: *const Snapshot, ctx: ?*anyopaque) void;

/// 门面可选项。
pub const Opt = struct {
    /// hosts 监测文件路径；null → 各平台默认（iOS/Android 空路径 = 监测 no-op）。
    hosts_path: ?[]const u8 = null,
    /// 排除接口（TUN 自身防路由循环），透传 network。
    excluded_interfaces: []const network.ExcludedInterface = &.{},
    /// iOS NetworkExtension 内运行时置 true（透传 network）。
    under_network_extension: bool = false,
};

// ============================================================================
// 快照物化（Facts）与 diff 纯函数
// ============================================================================
// network 回调的 NetworkInfo 字段（dns/addresses）指向单例内部缓冲，rebuild 时
// 会被**原地覆盖**——门面不能直接缓存 NetworkInfo 副本用于下次 diff（别名失效）。
// 因此把每次观测到的语义字段物化（深拷贝）进固定数组，再按值比较。

const MaxIfaceAddrs: usize = 16; // 对齐 network.zig MAX_IFACE_ADDRS
const MaxDnsServers: usize = 8; // 对齐 network.zig MAX_DNS_SERVERS
const IfaceNameLen: usize = 64; // network.Interface.name 长度

/// 默认接口身份 + 属性（物化拷贝，缓冲安全）。
const IfaceFacts = struct {
    present: bool = false,
    index: u32 = 0,
    mtu: u32 = 0,
    up: bool = false,
    name: [IfaceNameLen]u8 = @splat(0),
    name_len: usize = 0,
    addrs: [MaxIfaceAddrs]ntypes.AddressInfo = undefined,
    addr_len: usize = 0,
};

/// network 观测到的语义字段物化快照。
const Facts = struct {
    gateway: ?ntypes.IpAddr = null,
    iface: IfaceFacts = .{},
    dns: [MaxDnsServers]ntypes.IpAddr = undefined,
    dns_len: usize = 0,
};

/// 一次 network diff 的语义结果（不含 hosts/proxy，二者走独立回调）。
const Diff = struct {
    route: bool = false,
    interface: bool = false,
    dns: bool = false,
    default_route: bool = false,

    fn any(self: Diff) bool {
        return self.route or self.interface or self.dns or self.default_route;
    }
};

/// IpAddr 判等（union(enum) 载荷为数组，避免依赖 == 合成；同 network_params ipEql）。
fn ipEqual(a: ntypes.IpAddr, b: ntypes.IpAddr) bool {
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

fn optIpEqual(a: ?ntypes.IpAddr, b: ?ntypes.IpAddr) bool {
    if (a == null or b == null) return a == null and b == null;
    return ipEqual(a.?, b.?);
}

fn addrEqual(a: ntypes.AddressInfo, b: ntypes.AddressInfo) bool {
    return ipEqual(a.addr, b.addr) and a.prefix_len == b.prefix_len;
}

/// 将 network NetworkInfo 深拷贝为缓冲安全的 Facts。
fn factsOf(info: *const network.NetworkInfo) Facts {
    var f = Facts{ .gateway = info.gateway };
    if (info.default_interface) |ni| {
        const ifa = &f.iface;
        ifa.present = true;
        ifa.index = ni.index;
        ifa.mtu = ni.mtu;
        ifa.up = ni.up;
        ifa.name_len = @min(ni.name_len, ni.name.len);
        @memcpy(ifa.name[0..ifa.name_len], ni.name[0..ifa.name_len]);
        ifa.addr_len = @min(ni.addresses.len, MaxIfaceAddrs);
        @memcpy(ifa.addrs[0..ifa.addr_len], ni.addresses[0..ifa.addr_len]);
    }
    f.dns_len = @min(info.dns_servers.len, MaxDnsServers);
    @memcpy(f.dns[0..f.dns_len], info.dns_servers[0..f.dns_len]);
    return f;
}

/// 接口身份相等（present + index + name）。
fn ifaceIdentityEqual(a: *const IfaceFacts, b: *const IfaceFacts) bool {
    if (a.present != b.present) return false;
    if (!a.present) return true; // 都无默认接口：身份一致
    return a.index == b.index and a.name_len == b.name_len and
        std.mem.eql(u8, a.name[0..a.name_len], b.name[0..b.name_len]);
}

/// 接口属性相等（mtu/up/地址列表；前提：身份已相同）。
fn ifaceAttrsEqual(a: *const IfaceFacts, b: *const IfaceFacts) bool {
    if (a.mtu != b.mtu or a.up != b.up) return false;
    if (a.addr_len != b.addr_len) return false;
    for (0..a.addr_len) |k| {
        if (!addrEqual(a.addrs[k], b.addrs[k])) return false;
    }
    return true;
}

/// DNS 列表相等。
fn dnsEqual(a: *const Facts, b: *const Facts) bool {
    if (a.dns_len != b.dns_len) return false;
    for (0..a.dns_len) |k| {
        if (!ipEqual(a.dns[k], b.dns[k])) return false;
    }
    return true;
}

/// diff 两个 Facts → 语义结果。
fn diffFacts(prev: *const Facts, cur: *const Facts) Diff {
    var d = Diff{};
    if (!optIpEqual(prev.gateway, cur.gateway)) d.route = true;
    if (ifaceIdentityEqual(&prev.iface, &cur.iface)) {
        if (!ifaceAttrsEqual(&prev.iface, &cur.iface)) d.interface = true;
    } else {
        d.default_route = true;
    }
    if (!dnsEqual(prev, cur)) d.dns = true;
    return d;
}

/// 门面 diff 纯函数（可单测）：比较两个 NetworkInfo 快照 → 语义 diff。
/// 不依赖 network 单例状态，任何两个快照均可判定。
fn classifyNetworkChange(prev: *const network.NetworkInfo, cur: *const network.NetworkInfo) Diff {
    const a = factsOf(prev);
    const b = factsOf(cur);
    return diffFacts(&a, &b);
}

// ============================================================================
// ZF_NETWORK_TRACE 可观测开关（读一次缓存，线程安全）
// ============================================================================

const TraceUnknown: u8 = 2;
const TraceOn: u8 = 1;
const TraceOff: u8 = 0;
var g_trace_state = std.atomic.Value(u8).init(TraceUnknown);

/// ZF_NETWORK_TRACE=1 时开启 info 全流程日志；默认关。
fn traceEnabled() bool {
    const cached = g_trace_state.load(.acquire);
    if (cached != TraceUnknown) return cached == TraceOn;
    const on = envTraceFlag();
    g_trace_state.store(if (on) TraceOn else TraceOff, .release);
    return on;
}

/// 读环境变量 ZF_NETWORK_TRACE（POSIX getenv / Windows kernel32，comptime 剪枝）。
fn envTraceFlag() bool {
    const name = "ZF_NETWORK_TRACE";
    if (comptime builtin.os.tag == .windows) {
        const Win32 = struct {
            extern "kernel32" fn GetEnvironmentVariableA(
                lpName: [*:0]const u8,
                lpBuffer: [*c]u8,
                nSize: u32,
            ) callconv(.winapi) u32;
        };
        var buf: [32]u8 = undefined;
        const len = Win32.GetEnvironmentVariableA(name, &buf, buf.len);
        if (len == 0 or len >= buf.len) return false; // 未设置 / 超长不可表示
        return std.mem.eql(u8, buf[0..@intCast(len)], "1");
    }
    const raw = std.c.getenv(name) orelse return false;
    return std.mem.eql(u8, std.mem.span(raw), "1");
}

// ============================================================================
// 统一门面 Monitor
// ============================================================================

const MaxSubscribers: usize = 16;

const Subscriber = struct {
    cb: Callback,
    ctx: ?*anyopaque,
};

pub const Monitor = struct {
    allocator: std.mem.Allocator,
    hosts: hosts_monitor.HostsMonitor,
    proxy: proxy_monitor.ProxyMonitor,

    /// 共享锁：保护 subscriber 注册表 + started/subscribed 标志 + diff 基线。
    mutex: zf.sync.Mutex = .{},
    started: bool = false,
    subscribed: bool = false,
    prev_valid: bool = false,
    prev_facts: Facts = .{},

    subs: [MaxSubscribers]Subscriber = undefined,
    sub_count: usize = 0,
    emit_scratch: [MaxSubscribers]Subscriber = undefined,

    /// 初始化三个子监测（network 为全局单例，幂等 init）。
    /// 注：Monitor 是 network 单例生命周期的拥有者（deinit 时整机 reset）。
    pub fn init(allocator: std.mem.Allocator, opts: Opt) !Monitor {
        try network.init(allocator, .{
            .under_network_extension = opts.under_network_extension,
            .excluded_interfaces = opts.excluded_interfaces,
        });
        errdefer network.deinit();

        const hosts_path = opts.hosts_path orelse hosts_monitor.defaultHostsPath();
        var hosts = try hosts_monitor.HostsMonitor.init(allocator, hosts_path);
        errdefer hosts.deinit();

        const proxy = try proxy_monitor.ProxyMonitor.init(allocator);
        errdefer proxy.deinit();

        return .{ .allocator = allocator, .hosts = hosts, .proxy = proxy };
    }

    /// 启动三个子监测 + 订阅内部处理器（幂等；close 后可 restart）。
    /// 内部处理器只订阅一次（close 保留各子监测注册表），restart 不重复订阅。
    pub fn start(self: *Monitor) !void {
        self.mutex.lock();
        if (self.started) {
            self.mutex.unlock();
            return;
        }
        self.started = true;
        self.mutex.unlock();
        errdefer {
            self.mutex.lock();
            self.started = false;
            self.mutex.unlock();
        }

        // 先订阅、后 start：捕获子监测 start 内的同步首事件（Linux netlink 初次 emit）。
        if (!self.subscribed) {
            try network.subscribe(onNetworkChange, self); // 首个可能 alloc 失败（无前置订阅）
            try self.hosts.subscribe(onHostsChange, self);
            try self.proxy.subscribe(onProxyChange, self);
            self.mutex.lock();
            self.subscribed = true;
            self.mutex.unlock();
        }

        try self.hosts.start();
        errdefer self.hosts.close();
        try self.proxy.start();
        errdefer self.proxy.close();
        try network.start(); // 幂等；若 network 早已被启动则无首事件

        // 播种基线：network 若已由其他路径运行、未产生首事件，则用当前快照建立基线，
        // 使后续第一个真实变化能被正确 diff（而非被当作基线吞掉）。
        const seed = factsOf(&network.snapshot());
        self.mutex.lock();
        if (!self.prev_valid) {
            self.prev_facts = seed;
            self.prev_valid = true;
        }
        self.mutex.unlock();

        std.log.info("[monitor] started hosts_path={s}", .{self.hosts.path});
    }

    /// 注册统一语义事件回调（start 前后皆可；未 start 时事件不产生）。
    pub fn subscribe(self: *Monitor, cb: Callback, ctx: ?*anyopaque) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.sub_count >= MaxSubscribers) {
            std.log.warn("[monitor] subscriber registry full ({d}), subscribe ignored", .{MaxSubscribers});
            return error.TooManySubscribers;
        }
        self.subs[self.sub_count] = .{ .cb = cb, .ctx = ctx };
        self.sub_count += 1;
        std.log.debug("[monitor] subscriber added total={d}", .{self.sub_count});
    }

    /// 主动查询当前归一化快照（借用字段，见文件头）。
    pub fn snapshot(self: *Monitor) Snapshot {
        return self.currentSnapshot();
    }

    /// 停止三个子监测（幂等，保留订阅，可 restart）。重置 diff 基线。
    pub fn close(self: *Monitor) void {
        self.mutex.lock();
        if (!self.started) {
            self.mutex.unlock();
            return;
        }
        self.started = false;
        self.prev_valid = false; // restart 后重新播种基线，避免陈旧 diff
        self.mutex.unlock();

        // 锁外停子监测：join 可能在子监测 emit 回调内等 self.mutex，持锁 join 会死锁。
        self.hosts.close();
        self.proxy.close();
        network.close();
        std.log.debug("[monitor] stopped", .{});
    }

    /// 释放全部资源（先停线程）。重置 network 全局单例。
    pub fn deinit(self: *Monitor) void {
        self.close();
        self.hosts.deinit();
        self.proxy.deinit();
        network.deinit();
        std.log.debug("[monitor] deinit", .{});
    }

    // ---- 子监测回调（后台线程触发）----

    fn handleNetwork(self: *Monitor, info: *const network.NetworkInfo) void {
        const cur = factsOf(info);

        self.mutex.lock();
        if (!self.prev_valid) {
            // 首个事件：仅建立基线，不派发（避免 start 期「从无到有」伪事件）。
            self.prev_facts = cur;
            self.prev_valid = true;
            self.mutex.unlock();
            if (traceEnabled()) {
                std.log.info("[monitor] network baseline established (no dispatch)", .{});
            }
            return;
        }
        const d = diffFacts(&self.prev_facts, &cur);
        self.prev_facts = cur;
        self.mutex.unlock();

        if (traceEnabled()) {
            if (info.default_interface) |i| {
                std.log.info("[monitor] source=network iface={d} name={s}", .{ i.index, i.name[0..i.name_len] });
            } else {
                std.log.info("[monitor] source=network no-default-route", .{});
            }
            std.log.info("[monitor] diff route={} default_route={} interface={} dns={}", .{
                d.route, d.default_route, d.interface, d.dns,
            });
        }

        if (!d.any()) return; // 相同事件去重
        const snap = self.assembleFrom(info);
        self.dispatchNetworkDiff(d, &snap);
    }

    fn handleHosts(self: *Monitor, mtime: i128) void {
        if (traceEnabled()) std.log.info("[monitor] source=hosts mtime={d}", .{mtime});
        const snap = self.currentSnapshot();
        var s = snap;
        s.hosts_mtime = mtime; // 事件时间戳（保证与回调一致）
        self.dispatch(.hosts, &s);
    }

    fn handleProxy(self: *Monitor, settings: *const proxy_monitor.ProxySettings) void {
        if (traceEnabled()) {
            if (settings.host) |h| {
                std.log.info("[monitor] source=proxy enabled={} host={s} port={d}", .{ settings.enabled, h, settings.port });
            } else {
                std.log.info("[monitor] source=proxy disabled", .{});
            }
        }
        const snap = self.currentSnapshot();
        self.dispatch(.proxy, &snap);
    }

    // ---- 派发 ----

    fn dispatchNetworkDiff(self: *Monitor, d: Diff, snap: *const Snapshot) void {
        if (d.default_route) self.dispatch(.default_route, snap);
        if (d.route) self.dispatch(.route, snap);
        if (d.dns) self.dispatch(.dns, snap);
        if (d.interface) self.dispatch(.interface, snap);
    }

    fn dispatch(self: *Monitor, kind: ChangeKind, snap: *const Snapshot) void {
        self.mutex.lock();
        const n = self.sub_count;
        if (n > 0) @memcpy(self.emit_scratch[0..n], self.subs[0..n]);
        self.mutex.unlock();
        if (traceEnabled()) {
            std.log.info("[monitor] dispatch kind={s} subscribers={d}", .{ @tagName(kind), n });
        }
        for (self.emit_scratch[0..n]) |sub| sub.cb(kind, snap, sub.ctx);
    }

    /// 从某 network 快照装配当前归一化快照（proxy/hosts 读子监测最新值）。
    fn assembleFrom(self: *Monitor, info: *const network.NetworkInfo) Snapshot {
        var s = Snapshot{
            .default_interface = info.default_interface,
            .gateway = info.gateway,
            .dns_servers = info.dns_servers,
        };
        s.proxy = self.proxy.snapshot();
        s.hosts_mtime = self.hosts.lastMtime();
        return s;
    }

    /// 当前归一化快照（network 单例当前态）。
    fn currentSnapshot(self: *Monitor) Snapshot {
        const ni = network.snapshot();
        return self.assembleFrom(&ni);
    }
};

// ============================================================================
// 子监测回调适配（network/hosts/proxy 各自回调签名 → Monitor 方法）
// ============================================================================

fn onNetworkChange(info: *const network.NetworkInfo, ctx: ?*anyopaque) void {
    const m: *Monitor = @ptrCast(@alignCast(ctx orelse return));
    m.handleNetwork(info);
}

fn onHostsChange(mtime: i128, ctx: ?*anyopaque) void {
    const m: *Monitor = @ptrCast(@alignCast(ctx orelse return));
    m.handleHosts(mtime);
}

fn onProxyChange(settings: *const proxy_monitor.ProxySettings, ctx: ?*anyopaque) void {
    const m: *Monitor = @ptrCast(@alignCast(ctx orelse return));
    m.handleProxy(settings);
}

// ============================================================================
// 单元测试
// ============================================================================

const testing = std.testing;

/// 测试用默认接口构造（name ≤ 64，up=true）。
fn makeIfc(index: u32, name: []const u8, mtu: u32) network.Interface {
    var i = network.Interface{ .index = index, .mtu = mtu, .up = true, .name_len = name.len };
    @memcpy(i.name[0..name.len], name);
    return i;
}

/// 测试收集器：记录各类语义事件计数 + 最近快照默认接口 index。
const Collector = struct {
    mutex: zf.sync.Mutex = .{},
    route: usize = 0,
    interface_: usize = 0,
    dns: usize = 0,
    default_route: usize = 0,
    proxy: usize = 0,
    hosts: usize = 0,
    last_index: ?u32 = null,

    fn allZero(self: *Collector) bool {
        return self.route == 0 and self.interface_ == 0 and self.dns == 0 and
            self.default_route == 0 and self.proxy == 0 and self.hosts == 0;
    }
};

fn collectCb(kind: ChangeKind, snap: *const Snapshot, ctx: ?*anyopaque) void {
    const c: *Collector = @ptrCast(@alignCast(ctx.?));
    c.mutex.lock();
    defer c.mutex.unlock();
    switch (kind) {
        .route => c.route += 1,
        .interface => c.interface_ += 1,
        .dns => c.dns += 1,
        .default_route => c.default_route += 1,
        .proxy => c.proxy += 1,
        .hosts => c.hosts += 1,
    }
    c.last_index = if (snap.default_interface) |i| i.index else null;
}

test "mod: Snapshot 默认值" {
    const s = Snapshot{};
    try testing.expect(s.default_interface == null);
    try testing.expect(s.gateway == null);
    try testing.expect(s.dns_servers.len == 0);
    try testing.expect(s.proxy == null);
    try testing.expect(s.hosts_mtime == null);
}

test "mod: classifyNetworkChange — gateway 变化 → route" {
    const gw1 = zf.net.IpAddr{ .v4 = .{ 192, 168, 1, 1 } };
    const gw2 = zf.net.IpAddr{ .v4 = .{ 192, 168, 1, 254 } };
    const dns_a = [_]zf.net.IpAddr{.{ .v4 = .{ 1, 1, 1, 1 } }};
    const prev = network.NetworkInfo{ .default_interface = makeIfc(1, "en0", 1500), .gateway = gw1, .dns_servers = &dns_a };
    const cur = network.NetworkInfo{ .default_interface = makeIfc(1, "en0", 1500), .gateway = gw2, .dns_servers = &dns_a };
    const d = classifyNetworkChange(&prev, &cur);
    try testing.expect(d.route);
    try testing.expect(!d.default_route);
    try testing.expect(!d.interface);
    try testing.expect(!d.dns);
}

test "mod: classifyNetworkChange — 默认接口身份变化 → default_route" {
    const gw = zf.net.IpAddr{ .v4 = .{ 192, 168, 1, 1 } };
    const dns_a = [_]zf.net.IpAddr{.{ .v4 = .{ 1, 1, 1, 1 } }};
    const prev = network.NetworkInfo{ .default_interface = makeIfc(1, "en0", 1500), .gateway = gw, .dns_servers = &dns_a };
    const cur = network.NetworkInfo{ .default_interface = makeIfc(2, "en1", 1500), .gateway = gw, .dns_servers = &dns_a };
    const d = classifyNetworkChange(&prev, &cur);
    try testing.expect(d.default_route);
    try testing.expect(!d.route);
    try testing.expect(!d.interface);
    try testing.expect(!d.dns);
}

test "mod: classifyNetworkChange — 默认路由出现/消失 → default_route" {
    const gw = zf.net.IpAddr{ .v4 = .{ 192, 168, 1, 1 } };
    const dns_a = [_]zf.net.IpAddr{.{ .v4 = .{ 1, 1, 1, 1 } }};
    const with = network.NetworkInfo{ .default_interface = makeIfc(1, "en0", 1500), .gateway = gw, .dns_servers = &dns_a };
    const without = network.NetworkInfo{}; // 无默认接口（路由丢失语义）
    {
        const d = classifyNetworkChange(&with, &without);
        try testing.expect(d.default_route); // 消失
    }
    {
        const d = classifyNetworkChange(&without, &with); // 出现
        try testing.expect(d.default_route);
    }
}

test "mod: classifyNetworkChange — DNS 列表变化 → dns" {
    const gw = zf.net.IpAddr{ .v4 = .{ 192, 168, 1, 1 } };
    const dns_a = [_]zf.net.IpAddr{.{ .v4 = .{ 1, 1, 1, 1 } }};
    const dns_b = [_]zf.net.IpAddr{ .{ .v4 = .{ 8, 8, 8, 8 } }, .{ .v4 = .{ 8, 8, 4, 4 } } };
    const prev = network.NetworkInfo{ .default_interface = makeIfc(1, "en0", 1500), .gateway = gw, .dns_servers = &dns_a };
    const cur = network.NetworkInfo{ .default_interface = makeIfc(1, "en0", 1500), .gateway = gw, .dns_servers = &dns_b };
    const d = classifyNetworkChange(&prev, &cur);
    try testing.expect(d.dns);
    try testing.expect(!d.route);
    try testing.expect(!d.default_route);
    try testing.expect(!d.interface);
}

test "mod: classifyNetworkChange — 同接口 mtu 变化 → interface" {
    const gw = zf.net.IpAddr{ .v4 = .{ 192, 168, 1, 1 } };
    const dns_a = [_]zf.net.IpAddr{.{ .v4 = .{ 1, 1, 1, 1 } }};
    const prev = network.NetworkInfo{ .default_interface = makeIfc(1, "en0", 1500), .gateway = gw, .dns_servers = &dns_a };
    const cur = network.NetworkInfo{ .default_interface = makeIfc(1, "en0", 9000), .gateway = gw, .dns_servers = &dns_a };
    const d = classifyNetworkChange(&prev, &cur);
    try testing.expect(d.interface);
    try testing.expect(!d.route);
    try testing.expect(!d.default_route);
    try testing.expect(!d.dns);
}

test "mod: classifyNetworkChange — 同接口地址列表变化 → interface" {
    const gw = zf.net.IpAddr{ .v4 = .{ 192, 168, 1, 1 } };
    const dns_a = [_]zf.net.IpAddr{.{ .v4 = .{ 1, 1, 1, 1 } }};
    const addrs_x = [_]ntypes.AddressInfo{.{ .addr = .{ .v4 = .{ 10, 0, 0, 5 } }, .prefix_len = 24 }};
    const addrs_y = [_]ntypes.AddressInfo{.{ .addr = .{ .v4 = .{ 10, 0, 0, 9 } }, .prefix_len = 24 }};
    var iface_x = makeIfc(1, "en0", 1500);
    var iface_y = makeIfc(1, "en0", 1500);
    iface_x.addresses = &addrs_x;
    iface_y.addresses = &addrs_y;
    const prev = network.NetworkInfo{ .default_interface = iface_x, .gateway = gw, .dns_servers = &dns_a };
    const cur = network.NetworkInfo{ .default_interface = iface_y, .gateway = gw, .dns_servers = &dns_a };
    const d = classifyNetworkChange(&prev, &cur);
    try testing.expect(d.interface);
    try testing.expect(!d.route);
    try testing.expect(!d.default_route);
    try testing.expect(!d.dns);
}

test "mod: classifyNetworkChange — 快照完全一致 → 无变化" {
    const gw = zf.net.IpAddr{ .v4 = .{ 192, 168, 1, 1 } };
    const dns_a = [_]zf.net.IpAddr{.{ .v4 = .{ 1, 1, 1, 1 } }};
    const prev = network.NetworkInfo{ .default_interface = makeIfc(1, "en0", 1500), .gateway = gw, .dns_servers = &dns_a };
    const cur = network.NetworkInfo{ .default_interface = makeIfc(1, "en0", 1500), .gateway = gw, .dns_servers = &dns_a };
    const d = classifyNetworkChange(&prev, &cur);
    try testing.expect(!d.route and !d.default_route and !d.interface and !d.dns);
}

test "mod: Monitor 生命周期（start/close 幂等 + close 后重启）" {
    // 干净起点：重置可能残留的 network 全局单例。
    network.deinit();

    var mon = try Monitor.init(testing.allocator, .{ .hosts_path = "" });
    defer mon.deinit();

    // 未 start 即可 snapshot（无线程）
    _ = mon.snapshot();

    try mon.start();
    try mon.start(); // 幂等：不重复订阅/建线程

    var col = Collector{};
    try mon.subscribe(collectCb, &col);

    mon.close();
    mon.close(); // 幂等
    try mon.start(); // close 后可重启
    _ = mon.snapshot();
    mon.close();
    // defer mon.deinit() 重置 network 全局
}

test "mod: 门面把 network diff 分发为统一语义事件（确定性，无真实事件源）" {
    // 直接经 handleNetwork 注入 NetworkInfo，绕开真实事件源（幂等确定性）。
    network.deinit();

    var mon = try Monitor.init(testing.allocator, .{ .hosts_path = "" });
    defer mon.deinit();

    var col = Collector{};
    try mon.subscribe(collectCb, &col);

    const gw1 = zf.net.IpAddr{ .v4 = .{ 192, 168, 1, 1 } };
    const gw2 = zf.net.IpAddr{ .v4 = .{ 192, 168, 1, 254 } };
    const dns_a = [_]zf.net.IpAddr{.{ .v4 = .{ 1, 1, 1, 1 } }};
    const dns_b = [_]zf.net.IpAddr{.{ .v4 = .{ 8, 8, 8, 8 } }};
    const ifc_1500 = makeIfc(1, "en0", 1500);
    const ifc_9000 = makeIfc(1, "en0", 9000);
    const ifc_en1 = makeIfc(2, "en1", 9000);

    const base = network.NetworkInfo{ .default_interface = ifc_1500, .gateway = gw1, .dns_servers = &dns_a };

    // 首个事件 → 仅建立基线，不派发。
    mon.handleNetwork(&base);
    col.mutex.lock();
    try testing.expect(col.allZero());
    col.mutex.unlock();

    // 相同事件重复到达 → diff 空 → 不派发（去重）。
    mon.handleNetwork(&base);
    col.mutex.lock();
    try testing.expect(col.allZero());
    col.mutex.unlock();

    // 仅 gateway 变 → route。
    var info = base;
    info.gateway = gw2;
    mon.handleNetwork(&info);
    col.mutex.lock();
    try testing.expectEqual(@as(usize, 1), col.route);
    try testing.expectEqual(@as(usize, 0), col.dns);
    try testing.expectEqual(@as(usize, 0), col.interface_);
    try testing.expectEqual(@as(usize, 0), col.default_route);
    col.mutex.unlock();

    // DNS 列表变 → dns。
    info.dns_servers = &dns_b;
    mon.handleNetwork(&info);
    col.mutex.lock();
    try testing.expectEqual(@as(usize, 1), col.dns);
    try testing.expectEqual(@as(usize, 1), col.route);
    col.mutex.unlock();

    // 同接口 mtu 变 → interface（身份不变）。
    info.default_interface = ifc_9000;
    mon.handleNetwork(&info);
    col.mutex.lock();
    try testing.expectEqual(@as(usize, 1), col.interface_);
    try testing.expectEqual(@as(usize, 0), col.default_route);
    col.mutex.unlock();

    // 接口身份变 → default_route，且快照承载新默认接口 index。
    info.default_interface = ifc_en1;
    mon.handleNetwork(&info);
    col.mutex.lock();
    try testing.expectEqual(@as(usize, 1), col.default_route);
    try testing.expectEqual(@as(u32, 2), col.last_index.?);
    try testing.expectEqual(@as(usize, 0), col.proxy); // 无 proxy/hosts 事件
    try testing.expectEqual(@as(usize, 0), col.hosts);
    col.mutex.unlock();
}

// 单测汇总：显式引入使各文件顶层 test 块注册（network/system_proxy 的平台后端
// 由各自主文件的 comptime @import 自动带入；hosts/proxy 分平台文件同理）。
test {
    _ = @import("types.zig");
    _ = @import("network.zig");
    _ = @import("network_types.zig");
    _ = @import("network_params.zig");
    _ = @import("system_proxy.zig");
    _ = @import("system_proxy_common.zig");
    _ = @import("hosts_monitor.zig");
    _ = @import("proxy_monitor.zig");
}
