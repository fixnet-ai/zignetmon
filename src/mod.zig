//! zignetmon — 网络变化监测与自适应库（「网络变了」粗信号门面，design.md v2）
//!
//! 覆盖「路由 / 系统 DNS / 任意网卡 / 系统代理 / hosts 文件」五类关键网络设置变化
//! × 五平台（macOS / Windows / Linux / iOS / Android）的事件源监测与归一化。
//!
//! 本文件是 **归一化层（门面）**（design.md §4 ②）：订阅四个子监测（network /
//! hosts_monitor / proxy_monitor / dns_monitor）的裸事件，比对缓存快照 → diff → 收敛为
//! 「网络变了」**一个粗信号**，以统一 Callback(Snapshot) 派发给决策层（消费方）。
//! 消费方不区分「路由 / DNS / 代理哪个变了」，收到即重置依赖网络的状态。
//!
//! ## 变更门控（v2：粗信号，design.md §5/§6 验收）
//! 任一类底层变化（network diff 非空 / hosts mtime 变 / proxy 设置变 / DNS 独立变）→
//! 派发**恰好一次**粗回调 dispatch(snapshot)。network diff 内部仍按字段判定
//! 「是否变化」（gateway / 默认接口身份 / DNS 列表 / 接口属性），但只作
//! **变更门控 + ZF_NETWORK_TRACE 诊断**，不产出多 kind 事件。
//!
//! ## 门面级 1s 合并去抖（design.md §6 验收；范围 = 仅 network/dns_monitor）
//! 目的：**同一链路切换的连通性 state 被两个重叠观测源各报一次**（如「接口+DNS 同时变」
//! → network 与 dns_monitor 各触发一次）收敛为恰好一次粗回调。故 1s 合并**仅对
//! network / dns_monitor 事件生效**（二者都观测连通性，互相同变合并）。
//!
//! hosts / proxy 是**独立去重源**（内容 diff 后才 emit，各自绝不重复上报同一变化），
//! 其事件**必达**（不参与 1s 合并）：否则紧跟在一次无关派发（如 hosts 恢复回调）之后
//! <1s 到达的代理变化会被误合并丢弃且永不补发 → 消费方漏掉一次真实变化
//! （Windows real_event 真机残留 bug 根因，见 task_plan）。
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
//! network / hosts / proxy / dns 回调各在自己的后台线程触发；门面内部订阅注册表、
//! 快照基线与派发时间门控用 `zf.sync.Mutex` 保护，回调在锁外派发（避免重入死锁）。
//!
//! ## 可观测（design.md §5.5）
//! `ZF_NETWORK_TRACE=1` 开启 info 级全流程日志（事件源 → diff → 分发），默认关。

const std = @import("std");
const builtin = @import("builtin");
const zf = @import("zigfoundation");
const ntypes = @import("network_types.zig"); // 仅门面内部（Facts 物化）引用

/// 网络门面（单例 + 回调 + 快照）。网络监测/查询域唯一实现源（#43，P4 自 zigfoundation 整体迁入归位）。
pub const network = @import("network.zig");

/// 轻量查询原语 / 共享纯类型顶层 re-export（drop-in：与 zf 已删旧导出面同名同形，
/// P4 后消费方统一从本包取，杜绝跨包二次实现）。
pub const network_params = @import("network_params.zig");
pub const network_types = @import("network_types.zig");

/// 宿主系统代理副作用（set/restore 原语）。系统代理域唯一实现源（#79，P4 同上迁入归位）。
pub const system_proxy = @import("system_proxy.zig");

/// hosts 文件变化监测（跨平台后台线程 stat diff）。
pub const hosts_monitor = @import("hosts_monitor.zig");

/// 系统代理变化监测（分平台）。
pub const proxy_monitor = @import("proxy_monitor.zig");

/// 系统 DNS 变化监测（分平台；第 4 子监测）。设计.md §3「DNS」行的独立变化
/// 承载（路由/网卡未变时 DNS 单独被改）。
pub const dns_monitor = @import("dns_monitor.zig");

/// 归一化快照 — 回调携带 + `snapshot()` 主动查询共用。
/// 字段为借用（见文件头「Snapshot 所有权」）。
pub const Snapshot = struct {
    default_interface: ?network.Interface = null,
    gateway: ?zf.net.IpAddr = null,
    dns_servers: []const zf.net.IpAddr = &.{},
    proxy: ?proxy_monitor.ProxySettings = null,
    hosts_mtime: ?i128 = null,
};

/// 网络变化回调（v2 粗信号契约，design.md §5）：收到即「网络环境已变」，
/// 消费方应重置自身依赖网络的状态。snap 为变化后的当前状态快照（借用，
/// 仅在下一次变化前有效；需持久使用时自行拷贝字段）。
pub const Callback = *const fn (snap: *const Snapshot, ctx: ?*anyopaque) void;

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

/// 一次 network diff 的字段级结果（v2 内部诊断 + 变更门控，非消费方契约；
/// 不含 hosts/proxy，二者走独立回调）。消费方只收「网络变了」粗信号。
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

/// 门面 diff 纯函数（可单测）：比较两个 NetworkInfo 快照 → 字段级 diff。
/// 不依赖 network 单例状态，任何两个快照均可判定。「哪类字段变了」仍可判别，
/// 消费方据此 trace 诊断；派发层面统一收敛为一次粗回调。
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

/// 门面级 1s 合并去抖窗口（design.md §6 验收）：两次派发间隔 <1s 则本次合并不派发
/// （见文件头「门面级 1s 合并去抖」）。对齐 monoNanos 的 i64 纳秒刻度。
const MergeWindowNs: i64 = std.time.ns_per_s;

const Subscriber = struct {
    cb: Callback,
    ctx: ?*anyopaque,
};

pub const Monitor = struct {
    allocator: std.mem.Allocator,
    hosts: hosts_monitor.HostsMonitor,
    proxy: proxy_monitor.ProxyMonitor,
    dns: dns_monitor.DnsMonitor,

    /// 共享锁：保护 subscriber 注册表 + started/subscribed 标志 + diff 基线。
    mutex: zf.sync.Mutex = .{},
    started: bool = false,
    subscribed: bool = false,
    prev_valid: bool = false,
    prev_facts: Facts = .{},

    /// 上次**合并类**（network/dns_monitor）粗派发时刻（monoNanos，纳秒）。
    /// 0 = 从未派发（首次必派发）。仅 network/dns_monitor 派发更新本时钟；
    /// hosts/proxy 派发不更新（二者为独立去重源，必达且不参与合并，见文件头）。
    /// dispatch() 内做合并门控。
    last_dispatch_ns: i64 = 0,

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

        const dns = try dns_monitor.DnsMonitor.init(allocator);
        errdefer dns.deinit();

        return .{ .allocator = allocator, .hosts = hosts, .proxy = proxy, .dns = dns };
    }

    /// 启动四个子监测 + 订阅内部处理器（幂等；close 后可 restart）。
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
            try self.dns.subscribe(onDnsChange, self);
            self.mutex.lock();
            self.subscribed = true;
            self.mutex.unlock();
        }

        try self.hosts.start();
        errdefer self.hosts.close();
        try self.proxy.start();
        errdefer self.proxy.close();
        try self.dns.start();
        errdefer self.dns.close();
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

    /// 注入平台网络参数（移动端 iOS NE / Android 桥 + 测试注入入口，design.md §5）。
    /// 更新 network 单例快照后，显式走一次与真实事件相同的 diff/dispatch 路径，
    /// 使注入能通知订阅者（network.injectPlatformInfo 只 rebuildLocked 不通知）。
    pub fn injectPlatformInfo(self: *Monitor, info: network.PlatformInjectedInfo) void {
        network.injectPlatformInfo(info);
        const ni = network.snapshot();
        self.handleNetwork(&ni);
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
        self.last_dispatch_ns = 0; // restart 后首次事件应能派发（去抖门控清零）
        self.mutex.unlock();

        // 锁外停子监测：join 可能在子监测 emit 回调内等 self.mutex，持锁 join 会死锁。
        self.hosts.close();
        self.proxy.close();
        self.dns.close();
        network.close();
        std.log.debug("[monitor] stopped", .{});
    }

    /// 释放全部资源（先停线程）。重置 network 全局单例。
    pub fn deinit(self: *Monitor) void {
        self.close();
        self.hosts.deinit();
        self.proxy.deinit();
        self.dns.deinit();
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
        // 粗信号：network diff 任一字段非空 → 派发。mergeable=true：network 与
        // dns_monitor 重叠观测连通性，二者互相同变 <1s 时收敛为一次（见文件头）。
        self.dispatch(&snap, true);
    }

    fn handleHosts(self: *Monitor, mtime: i128) void {
        if (traceEnabled()) std.log.info("[monitor] source=hosts mtime={d}", .{mtime});
        const snap = self.currentSnapshot();
        var s = snap;
        s.hosts_mtime = mtime; // 事件时间戳（保证与回调一致）
        // hosts 变化 → 粗回调。mergeable=false：hosts 为独立去重源（内容 diff 后才
        // emit），真实变化必达，不参与 1s 合并（见文件头）。
        self.dispatch(&s, false);
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
        // proxy 变化 → 粗回调。mergeable=false：proxy 为独立去重源（内部读注册表 +
        // settingsEqual diff 后才 emit），真实变化必达，不参与 1s 合并（见文件头）。
        // 否则紧跟在一次无关派发（如 hosts 恢复回调）之后 <1s 到达的代理变化会被
        // 误合并丢弃且永不补发 → 消费方漏报（Windows real_event 真机残留 bug 根因）。
        self.dispatch(&snap, false);
    }

    /// dns_monitor 回调：系统 DNS 在路由/网卡未变时被单独修改（第 4 子监测）。
    /// 构造快照并**覆盖 dns_servers 为 dns_monitor 的新鲜值**（同 handleHosts 覆盖
    /// hosts_mtime 模式）——dns_monitor 独立观测，可能迟于 network 快照的 DNS 值。
    /// 与「接口+DNS 同时变」的 network 触发合并收敛为一次粗回调（门面 1s 去抖）。
    fn handleDns(self: *Monitor, settings: *const dns_monitor.DnsSettings) void {
        if (traceEnabled()) {
            std.log.info("[monitor] source=dns servers={d}", .{settings.servers.len});
        }
        var snap = self.currentSnapshot();
        snap.dns_servers = settings.servers; // 覆盖新鲜值（快照借用 settings 内部缓冲，回调期有效）
        // DNS 独立变化 → 粗回调。mergeable=true：与 network 同为连通性重叠观测源，
        // 二者互相同变 <1s 时收敛为一次（见文件头）；hosts/proxy 介入不重置本时钟。
        self.dispatch(&snap, true);
    }

    // ---- 派发 ----

    /// 派发「网络变了」粗信号：任一类底层变化恰好派发一次（design.md §5/§6）。
    ///
    /// 1s 合并去抖**仅对 mergeable 事件**（network/dns_monitor，连通性重叠观测源）
    /// 生效：距上次 mergeable 派发 <1s 则本次合并不派发（快照仍保持最新，供下次
    /// 派发 / 主动 snapshot() 承载）。首派发（last_dispatch_ns == 0）必发。
    /// hosts/proxy 事件 mergeable=false：真实变化必达（内部已内容 diff 去重），
    /// 不参与合并也不重置 last_dispatch_ns 时钟——保证独立去重源的真实变化永远
    /// 不被门面误合并丢弃（见文件头「门面级 1s 合并去抖」）。
    fn dispatch(self: *Monitor, snap: *const Snapshot, mergeable: bool) void {
        const now = zf.platform.monoNanos();

        self.mutex.lock();
        const last = self.last_dispatch_ns;
        if (mergeable and last != 0 and (now - last) < MergeWindowNs) {
            // 合并：距上次 mergeable 派发 <1s（同一链路切换被 network/dns_monitor
            // 重复上报），本次不派发。
            self.mutex.unlock();
            if (traceEnabled()) {
                std.log.info("[monitor] dispatch merged (<1s since last connectivity dispatch, snapshot stays fresh)", .{});
            }
            return;
        }
        if (mergeable) self.last_dispatch_ns = now;
        const n = self.sub_count;
        if (n > 0) @memcpy(self.emit_scratch[0..n], self.subs[0..n]);
        self.mutex.unlock();
        if (traceEnabled()) {
            std.log.info("[monitor] dispatch network-changed subscribers={d}", .{n});
        }
        for (self.emit_scratch[0..n]) |sub| sub.cb(snap, sub.ctx);
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

fn onDnsChange(settings: *const dns_monitor.DnsSettings, ctx: ?*anyopaque) void {
    const m: *Monitor = @ptrCast(@alignCast(ctx orelse return));
    m.handleDns(settings);
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

const MaxCollectDns: usize = 4;

/// 测试收集器（v2 粗信号语义）：总回调次数 + 最近一次快照关键字段。
/// 快照仅回调期有效（借用），故 record 在回调内同步拷贝字段。
const Collector = struct {
    mutex: zf.sync.Mutex = .{},
    total: usize = 0,
    last_gateway: ?zf.net.IpAddr = null,
    last_dns: [MaxCollectDns]zf.net.IpAddr = undefined,
    last_dns_len: usize = 0,
    last_iface_index: ?u32 = null,
    last_iface_addr_count: usize = 0,

    fn record(self: *Collector, snap: *const Snapshot) void {
        self.total += 1;
        self.last_gateway = snap.gateway;
        self.last_iface_index = if (snap.default_interface) |i| i.index else null;
        self.last_iface_addr_count = if (snap.default_interface) |i| i.addresses.len else 0;
        self.last_dns_len = @min(snap.dns_servers.len, MaxCollectDns);
        @memcpy(self.last_dns[0..self.last_dns_len], snap.dns_servers[0..self.last_dns_len]);
    }
};

fn collectCb(snap: *const Snapshot, ctx: ?*anyopaque) void {
    const c: *Collector = @ptrCast(@alignCast(ctx.?));
    c.mutex.lock();
    defer c.mutex.unlock();
    c.record(snap);
}

/// 锁内读总回调次数（单值便捷断言）。
fn colTotal(c: *Collector) usize {
    c.mutex.lock();
    defer c.mutex.unlock();
    return c.total;
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

test "mod: 验收准则 — 任一类 network diff 恰好一次粗回调（多字段同变收敛）" {
    // 直接经 handleNetwork 注入 NetworkInfo，绕开真实事件源（幂等确定性）。
    network.deinit();

    var mon = try Monitor.init(testing.allocator, .{ .hosts_path = "" });
    defer mon.deinit();

    var col = Collector{};
    try mon.subscribe(collectCb, &col);

    const gw1 = zf.net.IpAddr{ .v4 = .{ 192, 168, 1, 1 } };
    const gw2 = zf.net.IpAddr{ .v4 = .{ 192, 168, 1, 254 } };
    const dns_a = [_]zf.net.IpAddr{.{ .v4 = .{ 1, 1, 1, 1 } }};
    const dns_b = [_]zf.net.IpAddr{ .{ .v4 = .{ 8, 8, 8, 8 } }, .{ .v4 = .{ 8, 8, 4, 4 } } };
    const ifc_1500 = makeIfc(1, "en0", 1500);
    const ifc_en1 = makeIfc(2, "en1", 9000);

    const base = network.NetworkInfo{ .default_interface = ifc_1500, .gateway = gw1, .dns_servers = &dns_a };

    // 首个事件 → 仅建立基线，不派发。
    mon.handleNetwork(&base);
    try testing.expectEqual(@as(usize, 0), colTotal(&col));

    // 相同事件重复到达 → diff 空 → 不派发（去重）。
    mon.handleNetwork(&base);
    try testing.expectEqual(@as(usize, 0), colTotal(&col));

    // 单字段变化（仅 DNS 列表变）→ 恰好 1 次粗回调。
    var info = base;
    info.dns_servers = &dns_b;
    mon.handleNetwork(&info);
    try testing.expectEqual(@as(usize, 1), colTotal(&col));

    // 多字段同变（换网：gateway + 默认接口身份 + DNS 全变）→ 收敛为恰好 1 次，
    // 快照承载变化后的新状态（新默认接口 index）。
    mon.last_dispatch_ns = 0; // 本测试直接驱动 handle*，模拟每次真实变化间隔 >1s
    //（门面 1s 合并去抖由「1s 合并去抖」专门测试覆盖，此处不依赖亚秒内多派发）。
    info = base;
    info.gateway = gw2;
    info.default_interface = ifc_en1;
    // info.dns_servers 回到 dns_a ≠ 上一状态 dns_b → DNS 字段也变。
    mon.handleNetwork(&info);
    col.mutex.lock();
    try testing.expectEqual(@as(usize, 2), col.total);
    try testing.expectEqual(@as(u32, 2), col.last_iface_index.?);
    col.mutex.unlock();

    // 同接口属性变化（en1 mtu 9000→1500，身份不变）→ 恰好 1 次粗回调。
    mon.last_dispatch_ns = 0; // 同上：越过 1s 门控，本真实变化应派发
    const ifc_en1_mtu1500 = makeIfc(2, "en1", 1500);
    const attr = network.NetworkInfo{ .default_interface = ifc_en1_mtu1500, .gateway = gw2, .dns_servers = &dns_a };
    mon.handleNetwork(&attr);
    col.mutex.lock();
    try testing.expectEqual(@as(usize, 3), col.total);
    try testing.expectEqual(@as(u32, 2), col.last_iface_index.?);
    col.mutex.unlock();
}

test "mod: injectPlatformInfo — 注入走真实事件同路径，恰好一次粗回调 + 快照反映注入值" {
    network.deinit();

    var mon = try Monitor.init(testing.allocator, .{ .hosts_path = "" });
    defer mon.deinit();

    var col = Collector{};
    try mon.subscribe(collectCb, &col);
    try mon.start(); // 建立基线（真实默认接口 + DNS），不派发

    try testing.expectEqual(@as(usize, 0), colTotal(&col)); // 基线期无粗回调

    // network.injectPlatformInfo 的 rebuildLocked 需默认接口存在才承载注入值
    // （无默认路由时注入被丢弃，network.zig 既有行为）；离线主机如实跳过，
    // 与 darwin 特权真实事件测试的 SkipZigTest 先例一致。
    if (network.snapshot().default_interface == null) return error.SkipZigTest;

    // 注入一组与真实基线不同的 dns/gateway/addresses（198.18.0.0/15 测试段，
    // 避开真实局域网值，保证与基线产生 diff）。
    const dns = [_]zf.net.IpAddr{ .{ .v4 = .{ 9, 9, 9, 9 } }, .{ .v4 = .{ 1, 0, 0, 1 } } };
    const gw = zf.net.IpAddr{ .v4 = .{ 198, 18, 1, 1 } };
    const addrs = [_]ntypes.AddressInfo{.{ .addr = .{ .v4 = .{ 198, 18, 0, 5 } }, .prefix_len = 16 }};
    mon.injectPlatformInfo(.{ .dns_servers = &dns, .gateway = gw, .addresses = &addrs });

    // 恰好一次粗回调，且回调携带的快照反映注入值。
    col.mutex.lock();
    try testing.expectEqual(@as(usize, 1), col.total);
    try testing.expect(ipEqual(col.last_gateway.?, gw));
    try testing.expectEqual(@as(usize, 2), col.last_dns_len);
    try testing.expect(ipEqual(col.last_dns[0], dns[0]));
    try testing.expect(ipEqual(col.last_dns[1], dns[1]));
    col.mutex.unlock();

    // 主动 snapshot() 同样反映注入值（dns/gateway/addresses 挂默认接口）。
    const s = mon.snapshot();
    try testing.expect(s.default_interface != null);
    try testing.expect(ipEqual(s.gateway.?, gw));
    try testing.expectEqual(@as(usize, 2), s.dns_servers.len);
    try testing.expect(ipEqual(s.dns_servers[0], dns[0]));
    try testing.expect(ipEqual(s.dns_servers[1], dns[1]));
    try testing.expectEqual(@as(usize, 1), s.default_interface.?.addresses.len);
    try testing.expect(ipEqual(s.default_interface.?.addresses[0].addr, addrs[0].addr));

    // 重复注入相同值 → diff 空 → 去重，不额外派发。
    mon.injectPlatformInfo(.{ .dns_servers = &dns, .gateway = gw, .addresses = &addrs });
    try testing.expectEqual(@as(usize, 1), colTotal(&col));
}

test "mod: handleDns — DNS 独立变化恰好一次粗回调 + 快照 dns_servers 反映新值" {
    // 直接经 handleDns 注入 DnsSettings（仿 handleNetwork 直接驱动模式），
    // 绕开 dns_monitor 平台事件源（幂等确定性）；验证第 4 子监测接入门面。
    network.deinit();

    var mon = try Monitor.init(testing.allocator, .{ .hosts_path = "" });
    defer mon.deinit();

    var col = Collector{};
    try mon.subscribe(collectCb, &col);

    const dns_fresh = [_]zf.net.IpAddr{ .{ .v4 = .{ 1, 1, 1, 1 } }, .{ .v4 = .{ 9, 9, 9, 9 } } };
    const settings = dns_monitor.DnsSettings{ .servers = &dns_fresh };
    mon.handleDns(&settings); // 首派发（门控 0）→ 必发

    // 恰好一次粗回调，且回调携带的快照 dns_servers = dns_monitor 新鲜值
    // （覆盖 network 快照 DNS，同 handleHosts 覆盖 hosts_mtime 模式）。
    col.mutex.lock();
    try testing.expectEqual(@as(usize, 1), col.total);
    try testing.expectEqual(@as(usize, 2), col.last_dns_len);
    try testing.expect(ipEqual(col.last_dns[0], dns_fresh[0]));
    try testing.expect(ipEqual(col.last_dns[1], dns_fresh[1]));
    col.mutex.unlock();
}

test "mod: 门面 1s 合并去抖 — 连续两次派发 <1s 收敛为恰好一次粗回调" {
    // 验收场景：「接口+DNS 同时变」被 network 与 dns_monitor 各触发一次时，
    // 门面合并为恰好一次；handleDns ×2 同理。越过 1s 窗后的真实变化仍派发且
    // 快照为最新值（合并不清空状态）。测试直接驱动 handle*，<1s 由 monoNanos 判定。
    network.deinit();

    var mon = try Monitor.init(testing.allocator, .{ .hosts_path = "" });
    defer mon.deinit();

    var col = Collector{};
    try mon.subscribe(collectCb, &col);

    const gw1 = zf.net.IpAddr{ .v4 = .{ 192, 168, 1, 1 } };
    const dns_a = [_]zf.net.IpAddr{.{ .v4 = .{ 1, 1, 1, 1 } }};
    const dns_b = [_]zf.net.IpAddr{ .{ .v4 = .{ 8, 8, 8, 8 } }, .{ .v4 = .{ 8, 8, 4, 4 } } };
    const ifc_en0 = makeIfc(1, "en0", 1500);
    const ifc_en1 = makeIfc(2, "en1", 1500);

    const base = network.NetworkInfo{ .default_interface = ifc_en0, .gateway = gw1, .dns_servers = &dns_a };

    // 首个 network 事件 → 仅建立基线，不派发。
    mon.handleNetwork(&base);
    try testing.expectEqual(@as(usize, 0), colTotal(&col));

    // 「接口变」→ network 触发派发 #1（首派发必发）。
    var iface_changed = base;
    iface_changed.default_interface = ifc_en1;
    mon.handleNetwork(&iface_changed);
    try testing.expectEqual(@as(usize, 1), colTotal(&col));

    // 同一逻辑变化被 dns_monitor 补报（<1s 内）→ 合并，不再派发。
    mon.handleDns(&dns_monitor.DnsSettings{ .servers = &dns_b });
    try testing.expectEqual(@as(usize, 1), colTotal(&col));

    // handleDns ×2：越过 1s 窗后首条派发，第二条 <1s → 合并。
    mon.last_dispatch_ns = 0; // 模拟上次派发已 >1s（真实间隔由 monoNanos 判定）
    const dns_c = [_]zf.net.IpAddr{ .{ .v4 = .{ 114, 114, 114, 114 } }, .{ .v4 = .{ 1, 0, 0, 1 } } };
    mon.handleDns(&dns_monitor.DnsSettings{ .servers = &dns_c });
    try testing.expectEqual(@as(usize, 2), colTotal(&col));

    const dns_d = [_]zf.net.IpAddr{.{ .v4 = .{ 223, 5, 5, 5 } }};
    mon.handleDns(&dns_monitor.DnsSettings{ .servers = &dns_d }); // <1s 内 → 合并
    try testing.expectEqual(@as(usize, 2), colTotal(&col));

    // 合并不丢快照：越过 1s 窗后的下一次真实变化仍派发，快照为最新值。
    mon.last_dispatch_ns = 0;
    mon.handleDns(&dns_monitor.DnsSettings{ .servers = &dns_d });
    col.mutex.lock();
    try testing.expectEqual(@as(usize, 3), col.total);
    try testing.expectEqual(@as(usize, 1), col.last_dns_len);
    try testing.expect(ipEqual(col.last_dns[0], dns_d[0]));
    col.mutex.unlock();
}

// 单测汇总：显式引入使各文件顶层 test 块注册（network/system_proxy 的平台后端
// 由各自主文件的 comptime @import 自动带入；hosts/proxy/dns 分平台文件同理）。
test {
    _ = @import("types.zig");
    _ = @import("network.zig");
    _ = @import("network_types.zig");
    _ = @import("network_params.zig");
    _ = @import("system_proxy.zig");
    _ = @import("system_proxy_common.zig");
    _ = @import("hosts_monitor.zig");
    _ = @import("proxy_monitor.zig");
    _ = @import("dns_monitor.zig");
}
