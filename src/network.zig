//! network — 网络状态统一门面（#43）
//!
//! 全局单例 + 统一回调 + NetworkInfo 完整快照。
//! 上层使用者只接触本文件：
//!   zf.network.init(allocator, opts) → start() → subscribe(cb, ctx)
//!   网络变化时回调收到 *const NetworkInfo；或随时 snapshot() 主动查询。
//!
//! 分层（详见 zigbox task_plan #43）：
//!   - 事件层 NetworkUpdateMonitor: mac/iOS AF_ROUTE · Linux/Android netlink · Win iphlpapi
//!   - 状态层 DefaultInterfaceMonitor: 默认接口跟踪 + 1s 防抖 + noRoute 语义
//!   - 查询层 network_params: 地址/网关/DNS/链路参数
//!   - 注入通道 injectPlatformInfo: iOS NE / Android 受限环境由上层注入
//!
//! 设计决策（用户拍板 2026-08-17）：
//!   - 全局单例：allocator 仍经 init 注入（不在别处缓存），幂等 init
//!   - 统一单回调：回调携带完整 NetworkInfo + ChangeFlags；事件/状态分层在门面内消化
//!   - 快照所有权：snapshot()/回调的 NetworkInfo 指向单例内部缓冲，
//!     有效至下次网络变化（rebuild）或 close
//!   - excluded_interfaces 通用化自 zigtun registerMyInterface（TUN 排除自身）

const std = @import("std");
const builtin = @import("builtin");
const foundation = @import("zigfoundation");
const types = @import("network_types.zig");
const params = @import("network_params.zig");

// ============================================================================
// 公开类型
// ============================================================================

/// 变更原因标志（回调/快照携带）
pub const ChangeFlags = packed struct(u8) {
    interface_changed: bool = false, // 默认接口变化
    no_route: bool = false, // 路由丢失
    android_vpn: bool = false, // Android VPN 状态变化
    _pad: u5 = 0,
};

/// 网络状态快照 — 回调参数与 snapshot() 返回共用
pub const NetworkInfo = struct {
    default_interface: ?Interface = null,
    gateway: ?types.IpAddr = null,
    dns_servers: []const types.IpAddr = &.{},
    flags: ChangeFlags = .{},
    /// Android VPN 状态（非 Android 平台恒 false）
    android_vpn_enabled: bool = false,
};

/// 接口完整信息（基础三元组 + 地址列表 + 链路状态）
pub const Interface = struct {
    index: u32,
    mtu: u32,
    name: [64]u8 = @splat(0),
    name_len: usize = 0,
    addresses: []const types.AddressInfo = &.{},
    up: bool = true,
};

pub const NetworkChangeCallback = *const fn (info: *const NetworkInfo, ctx: ?*anyopaque) void;

/// 排除接口（原 zigtun registerMyInterface：多 TUN 实例排除自身防路由循环）
pub const ExcludedInterface = types.ExcludedInterface;

pub const Opt = struct {
    /// iOS NetworkExtension 内运行时设为 true（sysctl 等 API 不可用，走 socket 回退）
    under_network_extension: bool = false,
    excluded_interfaces: []const types.ExcludedInterface = &.{},
};

/// 注入通道数据（iOS NE / Android JNI 桥受限环境由上层注入，覆盖本地查询）
pub const PlatformInjectedInfo = struct {
    dns_servers: []const types.IpAddr = &.{},
    gateway: ?types.IpAddr = null,
    addresses: []const types.AddressInfo = &.{},
};

// ============================================================================
// 平台实现（comptime 分派；各文件提供统一形状的 NetworkUpdateMonitor /
// DefaultInterfaceMonitor，平移自 zigtun monitor 三件套）
// ============================================================================

pub const impl = switch (builtin.os.tag) {
    .macos, .ios => @import("network_darwin.zig"),
    .linux => @import("network_linux.zig"),
    .windows => @import("network_windows.zig"),
    else => @compileError("zf.network: unsupported OS " ++ @tagName(builtin.os.tag)),
};

// ============================================================================
// 全局单例
// ============================================================================

const MAX_IFACE_ADDRS = 16;
const MAX_DNS_SERVERS = 8;
const MAX_EXCLUDED = 8;
const MAX_SUBSCRIBERS = 32;

const CallbackNode = struct {
    callback: NetworkChangeCallback,
    ctx: ?*anyopaque = null,
    next: ?*CallbackNode = null,
};

const Injected = struct {
    dns: [MAX_DNS_SERVERS]types.IpAddr = undefined,
    dns_count: usize = 0,
    gateway: ?types.IpAddr = null,
    has_gateway: bool = false,
    addrs: [MAX_IFACE_ADDRS]types.AddressInfo = undefined,
    addr_count: usize = 0,
};

const State = struct {
    allocator: std.mem.Allocator,
    opts: Opt = .{},
    started: bool = false,

    update_monitor: impl.NetworkUpdateMonitor,
    iface_monitor: impl.DefaultInterfaceMonitor,

    // macOS/iOS 事件源为 poll 模式（AF_ROUTE fd 需驱动），门面内部线程轮询；
    // Linux/Windows 事件源 start() 内已自建线程，此字段恒 null
    poll_thread: ?std.Thread = null,
    poll_stop: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    // close 打断 darwinPollLoop 阻塞 poll 的自我唤醒管道（stop 专用；仅 macOS/iOS 创建）。
    // 用 [2]i32 而非 [2]std.c.fd_t —— Windows 上 fd_t=*anyopaque，跨平台编译不成立；
    // macOS/Linux fd_t 均为 i32，语义一致。
    wake_pipe: [2]i32 = .{ -1, -1 },

    callbacks: ?*CallbackNode = null,

    // 排除接口（init 时 dup，close/_testReset 时释放）
    excluded: [MAX_EXCLUDED]types.ExcludedInterface = undefined,
    excluded_count: usize = 0,

    injected: Injected = .{},

    // 快照缓冲（snapshot/回调返回此区域，下次 rebuild 前有效）
    addr_buf: [MAX_IFACE_ADDRS]types.AddressInfo = undefined,
    addr_count: usize = 0,
    dns_buf: [MAX_DNS_SERVERS]types.IpAddr = undefined,
    dns_count: usize = 0,
    info: NetworkInfo = .{},
};

var g_mutex: foundation.sync.Mutex = .{};
var g_state: State = undefined;
var g_inited: bool = false;

// ============================================================================
// 生命周期
// ============================================================================

/// 初始化单例（幂等）。allocator 仅在本模块内使用（订阅链表/排除接口 dup），
/// 不在别处缓存。事件源与防抖线程由 start() 启动。
pub fn init(allocator: std.mem.Allocator, opts: Opt) !void {
    g_mutex.lock();
    defer g_mutex.unlock();
    if (g_inited) return;

    var excluded: [MAX_EXCLUDED]types.ExcludedInterface = undefined;
    var excluded_count: usize = 0;
    for (opts.excluded_interfaces) |e| {
        if (excluded_count >= MAX_EXCLUDED) break;
        excluded[excluded_count] = .{
            .name = try allocator.dupe(u8, e.name),
            .index = e.index,
        };
        excluded_count += 1;
    }
    errdefer for (excluded[0..excluded_count]) |e| allocator.free(e.name);

    var st = State{
        .allocator = allocator,
        .opts = opts,
        .update_monitor = impl.NetworkUpdateMonitor.init(allocator),
        .iface_monitor = impl.DefaultInterfaceMonitor.init(
            params.defaultInterfaceFinder(),
            allocator,
            opts.under_network_extension,
        ),
        .excluded = excluded,
        .excluded_count = excluded_count,
    };
    st.iface_monitor.setExcludedInterfaces(st.excluded[0..st.excluded_count]);

    // 事件层 → 状态层：系统事件触发防抖重查
    try st.update_monitor.registerCallback(onPlatformEvent, &g_state);
    errdefer st.update_monitor.destroy();
    // 状态层 → 门面：接口确认变化后重建快照并分发
    try st.iface_monitor.registerCallback(onInterfaceUpdate);
    errdefer st.iface_monitor.destroy();

    g_state = st;
    g_inited = true;
}

/// 启动事件源 + 防抖线程（幂等）
pub fn start() !void {
    {
        g_mutex.lock();
        defer g_mutex.unlock();
        if (!g_inited) return error.NotInitialized;
        if (g_state.started) return;
        g_state.started = true; // 先行置位（并发重入防护）
    }
    // 锁外启动 monitor：初始快照会同步走 emit 回调链（平台状态层 →
    // onInterfaceUpdate → _onInterfaceChanged，后者拿 g_mutex）——若此处
    // 仍持锁即自死锁。Linux 初次 checkUpdate 必 emit（default_interface
    // 从 null → enp0s1 视为变化）；macOS 初始不 emit 故未暴露
    // （2026-08-19 linuxvm 实机回归 gdb 定位）。started 已置位，失败路径
    // 由 close() 幂等清理兜底。
    g_state.update_monitor.start() catch |err| {
        // 事件源不可用不致命——快照/注入通道仍可用
        std.log.warn("[network] event monitor start failed: {s}", .{@errorName(err)});
    };
    g_state.iface_monitor.start() catch |err| {
        // NoDefaultRoute 非致命（路由稍后出现），其余错误上抛
        if (err != error.NoDefaultRoute) return err;
    };
    // macOS/iOS 事件源 poll 模式：门面内部线程驱动（Linux/Windows 平台文件自建线程）
    if (comptime builtin.os.tag == .macos or builtin.os.tag == .ios) {
        g_state.poll_stop.store(false, .release);
        ensureWakePipe(); // 创建唤醒管道（幂等 restart；失败退化为 1s 超时轮询）
        g_state.poll_thread = try std.Thread.spawn(.{}, darwinPollLoop, .{&g_state});
    }
}

/// 停止事件源与防抖线程（幂等）。不释放订阅与注入数据（可 restart）。
pub fn close() void {
    {
        g_mutex.lock();
        defer g_mutex.unlock();
        if (!g_inited or !g_state.started) return;
        g_state.started = false;
    }
    // 锁外 join：防抖/事件线程可能正在 emit 回调链内等 g_mutex（与 start
    // 同一死锁面），持锁 join 会永久挂起
    if (g_state.poll_thread) |*t| {
        g_state.poll_stop.store(true, .release);
        wakePollLoop(); // 写 wake_pipe 打断 darwinPollLoop 的阻塞 poll，join 立即返回
        t.join();
        g_state.poll_thread = null;
    }
    // join 后无并发引用，回收唤醒管道 fd（含 spawn 失败仅建管道的残留）
    closeWakePipe();
    g_state.iface_monitor.close();
    g_state.update_monitor.close();
}

/// 销毁单例 — 释放全部资源（monitor 回调节点、订阅链表、排除接口 dup、poll 线程）。
/// 进程退出前调用；调用后 g_inited=false，可重新 init。
/// 与 close() 区别：close 幂等可 restart（保留订阅/注入数据），deinit 彻底释放。
pub fn deinit() void {
    _testReset();
}

// ============================================================================
// 订阅
// ============================================================================

/// 注册网络变化回调。回调携带完整 NetworkInfo 快照（指针指向单例内部缓冲，
/// 有效至下次网络变化），由防抖线程上下文同步调用——回调内禁止阻塞。
pub fn subscribe(callback: NetworkChangeCallback, ctx: ?*anyopaque) !void {
    g_mutex.lock();
    defer g_mutex.unlock();
    if (!g_inited) return error.NotInitialized;
    const node = try g_state.allocator.create(CallbackNode);
    node.* = .{ .callback = callback, .ctx = ctx };
    if (g_state.callbacks) |head| {
        node.next = head;
    }
    g_state.callbacks = node;
}

/// 取消注册（移除所有匹配 callback+ctx 的节点）
pub fn unsubscribe(callback: NetworkChangeCallback, ctx: ?*anyopaque) void {
    g_mutex.lock();
    defer g_mutex.unlock();
    if (!g_inited) return;
    var prev: ?*CallbackNode = null;
    var node = g_state.callbacks;
    while (node) |cb| {
        if (@intFromPtr(cb.callback) == @intFromPtr(callback) and cb.ctx == ctx) {
            if (prev) |p| {
                p.next = cb.next;
            } else {
                g_state.callbacks = cb.next;
            }
            const to_free = cb;
            node = cb.next;
            g_state.allocator.destroy(to_free);
        } else {
            prev = cb;
            node = cb.next;
        }
    }
}

// ============================================================================
// 轻量参数查询（无需 init/start 单例）
// ============================================================================

/// 查询当前默认网关（IPv4）。底层 network_params.queryGateway()，无单例依赖——
/// 供一次性 CLI/诊断路径（如 zigbox envinfo --version）在引擎初始化前使用；
/// 常驻路径优先 snapshot().gateway（订阅快照，含注入覆盖）。
pub fn queryDefaultGateway() ?types.IpAddr {
    return params.queryGateway();
}

/// 枚举本机全部接口地址（v4+v6，去重，含虚拟/TUN/容器网卡如 utun/docker/
/// vEthernet，也含环回与链路本地）。底层 network_params.queryAllAddresses()，
/// 无单例依赖——供装配期一次性查询（如 box hosts `lan` 展开）在引擎初始化前
/// 使用；调用方须自行过滤 isLoopback/isLinkLocal（zf.net.IpAddr 谓词）。
/// 所有权：返回切片由 allocator 分配，调用方用同一 allocator free
/// （或交 Arena/会话 allocator 统一回收）。
pub fn queryAllAddresses(allocator: std.mem.Allocator) ![]types.IpAddr {
    return params.queryAllAddresses(allocator);
}

// ============================================================================
// 快照与注入
// ============================================================================

/// 主动查询当前网络状态快照。返回数据指向单例内部缓冲，
/// 有效至下次网络变化（rebuild）或 close。
pub fn snapshot() NetworkInfo {
    g_mutex.lock();
    defer g_mutex.unlock();
    if (!g_inited) return .{};
    return g_state.info;
}

/// 注入平台网络参数（iOS NE / Android 受限环境），覆盖本地查询结果。
/// 数据按值拷贝进单例，调用后立即重建快照。
pub fn injectPlatformInfo(info: PlatformInjectedInfo) void {
    g_mutex.lock();
    defer g_mutex.unlock();
    if (!g_inited) {
        std.log.warn("[network] injectPlatformInfo before init ignored", .{});
        return;
    }
    const st = &g_state;

    var n: usize = 0;
    for (info.dns_servers) |d| {
        if (n >= MAX_DNS_SERVERS) break;
        st.injected.dns[n] = d;
        n += 1;
    }
    st.injected.dns_count = n;
    st.injected.gateway = info.gateway;
    st.injected.has_gateway = info.gateway != null;

    n = 0;
    for (info.addresses) |a| {
        if (n >= MAX_IFACE_ADDRS) break;
        st.injected.addrs[n] = a;
        n += 1;
    }
    st.injected.addr_count = n;

    rebuildLocked(st.iface_monitor.defaultInterface(), 0);
}

// ============================================================================
// 平台实现内部钩子
// ============================================================================

/// 平台状态层检测到接口变化后调用（仅 platform 实现使用，勿在上层调用）。
/// iface == null 表示路由丢失（noRoute）。platform_flags 支持 FlagAndroidVPNUpdate 位。
pub fn _onInterfaceChanged(iface: ?*const types.NetworkInterface, platform_flags: i32) void {
    // 锁内重建快照 + 复制订阅列表，锁外调用回调（避免回调 re-enter 死锁）
    var cbs: [MAX_SUBSCRIBERS]struct {
        callback: NetworkChangeCallback,
        ctx: ?*anyopaque,
    } = undefined;
    var count: usize = 0;

    g_mutex.lock();
    if (!g_inited) {
        g_mutex.unlock();
        return;
    }
    rebuildLocked(iface, platform_flags);
    var node = g_state.callbacks;
    while (node) |cb| : (node = cb.next) {
        if (count < MAX_SUBSCRIBERS) {
            cbs[count] = .{ .callback = cb.callback, .ctx = cb.ctx };
            count += 1;
        }
    }
    g_mutex.unlock();

    for (cbs[0..count]) |cb| {
        cb.callback(&g_state.info, cb.ctx);
    }
}

// ============================================================================
// 内部实现
// ============================================================================

/// 事件层回调：系统事件 → 状态层防抖重查（1s 防抖在状态层内）
fn onPlatformEvent(ctx: ?*anyopaque) void {
    const st: *State = @ptrCast(@alignCast(ctx orelse return));
    st.iface_monitor.notifyNetworkChanged();
}

// ============================================================================
// macOS/iOS poll 线程唤醒管道（POSIX only：Windows fd_t=*anyopaque 且无 std.c.poll，
// 编译期剪除，不引入 libc 链接依赖）
// ============================================================================

/// 创建自我唤醒管道（幂等 restart：close 后复位 -1，重开新建）。
/// 创建失败（EMFILE）保持 {-1,-1}，darwinPollLoop 退化为仅 route_fd 的 1s 超时轮询。
fn ensureWakePipe() void {
    if (comptime builtin.os.tag == .macos or builtin.os.tag == .ios) {
        if (g_state.wake_pipe[0] < 0) {
            var fds: [2]std.c.fd_t = undefined;
            if (std.c.pipe(&fds) == 0) {
                g_state.wake_pipe = .{ @intCast(fds[0]), @intCast(fds[1]) };
            }
        }
    }
}

/// 打断 darwinPollLoop 的阻塞 poll（stop 语义）：置 poll_stop 后写 1 字节唤醒。
fn wakePollLoop() void {
    if (comptime builtin.os.tag == .macos or builtin.os.tag == .ios) {
        if (g_state.wake_pipe[1] >= 0) {
            _ = std.c.write(g_state.wake_pipe[1], &[_]u8{1}, 1);
        }
    }
}

/// 回收唤醒管道 fd（须在 poll 线程 join 后调用，此时无并发引用）。
fn closeWakePipe() void {
    if (comptime builtin.os.tag == .macos or builtin.os.tag == .ios) {
        if (g_state.wake_pipe[0] >= 0) {
            _ = std.c.close(g_state.wake_pipe[0]);
            _ = std.c.close(g_state.wake_pipe[1]);
            g_state.wake_pipe = .{ -1, -1 };
        }
    }
}

/// macOS/iOS 事件源 poll 驱动线程：poll([route_fd, wake_pipe], 1s) 事件驱动阻塞等待，
/// 取代原 100ms 轮询（空闲从 10 唤醒/s 降到 1/s，CPU≈0）。
/// （Linux/Windows 事件源自建线程，不使用此路径）
///  - route_fd 读就绪 → update_monitor.poll() 读路由事件并 emit
///  - wake_pipe 读就绪 → close() 的 stop 信号，清空后回主循环退出
///  - rc==0（1s 看门狗超时）→ 兜底 poll()：覆盖「poll 对 AF_ROUTE 不触发」的悲观场景
fn darwinPollLoop(st: *State) void {
    var drain_buf: [64]u8 = undefined;
    while (!st.poll_stop.load(.acquire)) {
        const route_fd = st.update_monitor.routeFd();
        if (route_fd < 0) break;
        const wake_fd = st.wake_pipe[0];

        // wake_pipe 创建失败（EMFILE）时仅 poll route_fd（退化为 1s 超时轮询）
        var fds: [2]std.c.pollfd = undefined;
        var nfds: usize = 0;
        fds[nfds] = .{ .fd = @intCast(route_fd), .events = std.c.POLL.IN, .revents = 0 };
        nfds += 1;
        if (wake_fd >= 0) {
            fds[nfds] = .{ .fd = @intCast(wake_fd), .events = std.c.POLL.IN, .revents = 0 };
            nfds += 1;
        }

        const rc = std.c.poll(&fds, @intCast(nfds), 1000);
        if (rc < 0) {
            const err = std.c.errno(rc);
            if (err == std.posix.E.INTR) continue;
            break;
        }

        // wake_pipe 有信号（close 置 poll_stop 后写 pipe）— 优先响应 stop
        if (wake_fd >= 0 and fds[1].revents & std.c.POLL.IN != 0) {
            // 清空管道（poll 已保证可读不阻塞；每次 stop 写 1 字节）
            _ = std.c.read(wake_fd, &drain_buf, drain_buf.len);
            continue;
        }

        // route 读就绪 或 1s 看门狗超时（悲观场景兜底）→ 读路由事件并 emit
        if (rc == 0 or fds[0].revents & std.c.POLL.IN != 0) {
            st.update_monitor.poll() catch |err| {
                // 事件源 socket 已关闭（close 路径）— 退出循环
                if (err == error.ReadFailed) break;
            };
        } else if (rc > 0) {
            // 罕见异常：poll 返回但无可读 fd（route fd 置 ERR/HUP 等）→ 退避避免忙等
            // （仅异常路径触发，不影响空闲 1 唤醒/s 的零 CPU 目标）
            foundation.platform.sleepNs(100 * std.time.ns_per_ms);
        }
    }
}

/// 状态层回调：接口确认变化 → 门面重建快照并分发
fn onInterfaceUpdate(iface: *const types.NetworkInterface, flags: i32) void {
    _onInterfaceChanged(iface, flags);
}

/// 锁内重建快照（调用方已持 g_mutex）
fn rebuildLocked(iface: ?*const types.NetworkInterface, platform_flags: i32) void {
    const st = &g_state;
    var flags = ChangeFlags{};
    if (platform_flags & types.FlagAndroidVPNUpdate != 0) flags.android_vpn = true;

    if (iface == null or iface.?.index == 0) {
        // 路由丢失（平台状态层以空接口 index=0 表示，参考 sing-tun monitor_shared.go
        // noRoute 路径 emit nil interface）：清空默认接口
        flags.no_route = true;
        st.info = .{
            .flags = flags,
            .android_vpn_enabled = st.iface_monitor.isAndroidVPNEnabled(),
        };
        return;
    }

    flags.interface_changed = true;
    const src = iface.?;
    var dst = Interface{
        .index = src.index,
        .mtu = src.mtu,
        .name_len = src.name_len,
    };
    @memcpy(dst.name[0..src.name_len], src.name[0..src.name_len]);
    dst.up = params.queryLinkUp(src.index);

    // 地址：注入优先，否则本地查询（stub 阶段返回空）
    if (st.injected.addr_count > 0) {
        dst.addresses = st.injected.addrs[0..st.injected.addr_count];
    } else {
        st.addr_count = params.queryAddresses(src.index, &st.addr_buf).len;
        dst.addresses = st.addr_buf[0..st.addr_count];
    }

    st.info = .{
        .default_interface = dst,
        .gateway = if (st.injected.has_gateway) st.injected.gateway else params.queryGateway(),
        .dns_servers = dnsLocked(),
        .flags = flags,
        .android_vpn_enabled = st.iface_monitor.isAndroidVPNEnabled(),
    };
}

/// 锁内取 DNS 列表（注入优先，否则本地查询）
fn dnsLocked() []const types.IpAddr {
    const st = &g_state;
    if (st.injected.dns_count > 0) return st.injected.dns[0..st.injected.dns_count];
    st.dns_count = params.queryDnsServers(&st.dns_buf).len;
    return st.dns_buf[0..st.dns_count];
}

/// 仅测试使用：完全重置单例（释放订阅链表 + 排除接口 dup + 销毁监视器）
pub fn _testReset() void {
    g_mutex.lock();
    defer g_mutex.unlock();
    if (!g_inited) return;
    const st = &g_state;
    if (st.started) {
        if (st.poll_thread) |*t| {
            st.poll_stop.store(true, .release);
            wakePollLoop();
            t.join();
            st.poll_thread = null;
        }
        closeWakePipe();
        st.iface_monitor.close();
        st.update_monitor.close();
        st.started = false;
    }
    var node = st.callbacks;
    while (node) |cb| {
        const next = cb.next;
        st.allocator.destroy(cb);
        node = next;
    }
    st.callbacks = null;
    for (st.excluded[0..st.excluded_count]) |e| st.allocator.free(e.name);
    st.excluded_count = 0;
    st.update_monitor.destroy();
    st.iface_monitor.destroy();
    g_inited = false;
}

// ============================================================================
// 单元测试
// ============================================================================

const testing = std.testing;

test "network: ChangeFlags/NetworkInfo 默认值" {
    const flags = ChangeFlags{};
    try testing.expect(!flags.interface_changed);
    try testing.expect(!flags.no_route);
    try testing.expect(!flags.android_vpn);

    const info = NetworkInfo{};
    try testing.expect(info.default_interface == null);
    try testing.expect(info.dns_servers.len == 0);
}

test "network: 未 init 时 subscribe/snapshot 行为" {
    _testReset();
    defer _testReset();
    const cb = struct {
        fn f(_: *const NetworkInfo, _: ?*anyopaque) void {}
    }.f;
    try testing.expectError(error.NotInitialized, subscribe(cb, null));
    const info = snapshot();
    try testing.expect(info.default_interface == null);
}

test "network: init 幂等 + subscribe 分发快照" {
    _testReset();
    defer _testReset();

    try init(testing.allocator, .{});
    try init(testing.allocator, .{}); // 幂等

    // mock 接口变化 → 回调收到完整快照
    var mock = types.NetworkInterface{ .index = 7, .mtu = 1500, .name_len = 3 };
    @memcpy(mock.name[0..3], "eth");

    const TestCtx = struct {
        count: usize = 0,
        last: ?NetworkInfo = null,
    };
    var tctx = TestCtx{};
    const cb = struct {
        fn f(info: *const NetworkInfo, ctx: ?*anyopaque) void {
            const c: *TestCtx = @ptrCast(@alignCast(ctx.?));
            c.count += 1;
            c.last = info.*;
        }
    };
    try subscribe(cb.f, &tctx);
    defer unsubscribe(cb.f, &tctx);

    _onInterfaceChanged(&mock, 0);
    try testing.expectEqual(@as(usize, 1), tctx.count);
    try testing.expect(tctx.last != null);
    try testing.expect(tctx.last.?.default_interface != null);
    try testing.expectEqual(@as(u32, 7), tctx.last.?.default_interface.?.index);
    try testing.expect(tctx.last.?.flags.interface_changed);

    // snapshot 返回同一快照
    const snap = snapshot();
    try testing.expectEqual(@as(u32, 7), snap.default_interface.?.index);
}

test "network: noRoute 语义 — 路由丢失清空默认接口" {
    _testReset();
    defer _testReset();
    try init(testing.allocator, .{});

    _onInterfaceChanged(null, 0);
    var snap = snapshot();
    try testing.expect(snap.default_interface == null);
    try testing.expect(snap.flags.no_route);
    try testing.expect(!snap.flags.interface_changed);

    // 平台状态层以空接口 index=0 表示路由丢失（参考 sing-tun noRoute emit nil）
    const empty = types.NetworkInterface{ .index = 0, .mtu = 0 };
    _onInterfaceChanged(&empty, 0);
    snap = snapshot();
    try testing.expect(snap.default_interface == null);
    try testing.expect(snap.flags.no_route);
    try testing.expect(!snap.flags.interface_changed);
}

test "network: injectPlatformInfo 覆盖本地查询" {
    _testReset();
    defer _testReset();
    try init(testing.allocator, .{});

    var mock = types.NetworkInterface{ .index = 1, .mtu = 1280, .name_len = 3 };
    @memcpy(mock.name[0..3], "en0");
    _onInterfaceChanged(&mock, 0);

    const dns = [_]types.IpAddr{ .{ .v4 = .{ 1, 1, 1, 1 } }, .{ .v4 = .{ 8, 8, 8, 8 } } };
    const gw = types.IpAddr{ .v4 = .{ 192, 168, 1, 1 } };
    injectPlatformInfo(.{
        .dns_servers = &dns,
        .gateway = gw,
    });
    // stub 状态层无接口存储，注入后的 rebuild 由下次接口变化携带生效
    _onInterfaceChanged(&mock, 0);

    const snap = snapshot();
    try testing.expectEqual(@as(usize, 2), snap.dns_servers.len);
    try testing.expectEqual(dns[0], snap.dns_servers[0]);
    try testing.expect(snap.gateway != null);
    try testing.expectEqual(gw, snap.gateway.?);
}

test "network: excluded_interfaces dup 与释放" {
    _testReset();
    defer _testReset();
    try init(testing.allocator, .{
        .excluded_interfaces = &.{.{ .name = "utun8", .index = 42 }},
    });
    // _testReset（defer）释放 dup — testing.allocator 检测泄漏
}

test "network: Android VPN 标志透传" {
    _testReset();
    defer _testReset();
    try init(testing.allocator, .{});

    var mock = types.NetworkInterface{ .index = 2, .mtu = 1500, .name_len = 2 };
    @memcpy(mock.name[0..2], "w0");
    _onInterfaceChanged(&mock, types.FlagAndroidVPNUpdate);
    const snap = snapshot();
    try testing.expect(snap.flags.android_vpn);
}
