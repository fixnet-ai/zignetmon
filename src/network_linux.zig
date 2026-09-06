//! network_linux — Linux/Android 网络监控平台实现（43-P1b）
//!
//! 平移自 zigtun src/monitor_linux.zig，参考 vendor/sing-tun/monitor_linux.go
//! + monitor_linux_default.go + monitor_android.go。
//!
//! 核心功能:
//!   - DefaultInterfaceMonitor.checkUpdate(): 读 /proc/net/route + /proc/net/ipv6_route 查找默认路由
//!   - NetworkUpdateMonitor: netlink RTMGRP 监听链路/路由变化
//!
//! Linux 不提供 sysctl 路由表，使用 /proc 文件系统读取路由信息。
//! 参考 Go 的 netlink.RouteListFiltered，但无需 root 权限。
//!
//! Android 兼容性 (重要):
//!   Android 也使用此文件（os.tag == .linux + abi == .android）。
//!   - /proc/net/route 在所有 Android 版本上可用，无需 root
//!   - Go 版本使用 netlink.RuleList() 检测 VPN 状态 (mask=0x20000)，但这需要系统权限
//!   - 本实现直接使用 /proc/net/route 作为主要路径，非系统 app 也能正常工作
//!   - VPN protect 检测 (android_vpn_enabled) 通过 netlink RTM_GETRULE 扫描 fwmark=0x20000，
//!     非系统 app 无 netlink 权限时静默失败，由上层 setOverrideAndroidVPN() 传入
//!   (参考 vendor/sing-tun/monitor_android.go:8-68 checkUpdate)
//!
//! 解耦（相对 zigtun）:
//!   - tun.InterfaceFinderFn/InterfaceInfo → types.InterfaceFinderFn/InterfaceInfo
//!   - monitor_shared 类型 re-export → 直接从 types 取（文件内私有 const 别名，不 re-export）
//!   - registerMyInterface → setExcludedInterfaces（[8]types.ExcludedInterface + count）
//!   - tun.DefaultInterfaceMonitor vtable 构造 → 删除（TUN 耦合）
//!   - 日志组件标识 [monitor] → [network]（zf.network 门面规范）
//!
//! 参考文件:
//!   - vendor/sing-tun/monitor_linux_default.go — 标准 Linux checkUpdate (非 Android)
//!   - vendor/sing-tun/monitor_android.go — Android checkUpdate (netlink RuleList VPN 检测)
//!   - vendor/sing-tun/monitor_linux.go — netlink 监听

const std = @import("std");
const builtin = @import("builtin");
const types = @import("network_types.zig");
const zf = @import("zigfoundation");

// ============================================================================
// 从 network_types.zig 取共享类型（文件内私有别名，不 re-export 到 pub API）
// ============================================================================

const NetworkUpdateCallback = types.NetworkUpdateCallback;
const DefaultInterfaceUpdateCallback = types.DefaultInterfaceUpdateCallback;
const NetworkInterface = types.NetworkInterface;
const InterfaceFinderFn = types.InterfaceFinderFn;
const InterfaceInfo = types.InterfaceInfo;
const ExcludedInterface = types.ExcludedInterface;
const FlagAndroidVPNUpdate = types.FlagAndroidVPNUpdate;

/// 状态层回调节点（平移自 zigtun monitor.zig InterfaceCallbackNode）
const InterfaceCallbackNode = struct {
    callback: DefaultInterfaceUpdateCallback,
    next: ?*InterfaceCallbackNode = null,
};

/// 事件层回调节点（平移自 zigtun monitor_linux.zig NetworkUpdateCallbackNode）
const NetworkUpdateCallbackNode = struct {
    callback: NetworkUpdateCallback,
    ctx: ?*anyopaque = null,
    next: ?*NetworkUpdateCallbackNode = null,
};

// ============================================================================
// DefaultInterfaceMonitor — Linux 实现 (参考 monitor_linux_default.go:12-40)
// ============================================================================

pub const DefaultInterfaceMonitor = struct {
    default_interface: ?NetworkInterface = null,
    interface_update_callbacks: ?*InterfaceCallbackNode = null,
    interface_finder: InterfaceFinderFn,
    // 排除接口（通用化自 zigtun registerMyInterface：多 TUN 实例排除自身防路由循环）
    // 参考 monitor_shared.go:50 myInterfaces []string
    excluded: [8]ExcludedInterface = undefined,
    excluded_count: usize = 0,
    allocator: std.mem.Allocator,

    // 使用 zf.sync.Mutex 保护 default_interface 多线程访问
    interface_lock: zf.sync.Mutex = .{},

    // D73 fix: noRoute state tracking — 路由丢失时通知 callback
    no_route: bool = true,

    // Android VPN 状态 (参考 monitor_shared.go:52-53)
    override_android_vpn: bool = false,
    android_vpn_enabled: bool = false,

    // 防抖定时器 (参考 Go monitor_shared.go:74-78 delayCheckUpdate)
    debounce_thread: ?std.Thread = null,
    debounce_stop: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    debounce_triggered: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    /// under_network_extension 为 iOS NE 概念，Linux 无此语义，原样忽略。
    pub fn init(interface_finder: InterfaceFinderFn, allocator: std.mem.Allocator, _: bool) @This() {
        return .{
            .interface_finder = interface_finder,
            .allocator = allocator,
        };
    }

    pub fn start(self: *DefaultInterfaceMonitor) !void {
        // 初始检查 (参考 Go postCheckUpdate)
        self.postCheckUpdate() catch |err| {
            if (err != error.NoDefaultRoute) return err;
        };
        // 启动防抖线程
        self.debounce_stop.store(false, .release);
        self.debounce_thread = try std.Thread.spawn(.{}, debounceLoop, .{self});
    }

    /// notifyNetworkChanged — 由 NetworkUpdateMonitor 回调触发防抖
    pub fn notifyNetworkChanged(self: *DefaultInterfaceMonitor) void {
        self.debounce_triggered.store(true, .release);
    }

    fn debounceLoop(self: *DefaultInterfaceMonitor) void {
        while (!self.debounce_stop.load(.acquire)) {
            if (self.debounce_triggered.load(.acquire)) {
                self.debounce_triggered.store(false, .release);
                zf.platform.sleepNs(std.time.ns_per_s); // 1 秒防抖 — 独立防抖线程控制面，非数据面热路径 // io-audit: allow
                if (!self.debounce_stop.load(.acquire)) {
                    // M3 fix: 不吞掉 postCheckUpdate 错误，至少记录日志
                    self.postCheckUpdate() catch |err| {
                        std.log.warn("[network] debounce postCheckUpdate failed: {s}", .{@errorName(err)});
                    };
                }
            } else {
                zf.platform.sleepNs(100 * std.time.ns_per_ms); // 防抖线程轮询间隔 // io-audit: allow
            }
        }
    }

    /// postCheckUpdate — 包装 checkUpdate，处理 noRoute 状态
    /// (参考 Go monitor_shared.go:80-103 postCheckUpdate)
    pub fn postCheckUpdate(self: *DefaultInterfaceMonitor) !void {
        self.checkUpdate() catch |err| {
            if (err == error.NoDefaultRoute) {
                if (!self.no_route) {
                    self.no_route = true;
                    self.interface_lock.lock();
                    defer self.interface_lock.unlock();
                    self.default_interface = null;
                    const empty_iface = NetworkInterface{ .index = 0, .mtu = 0 };
                    self.emitLocked(&empty_iface, 0);
                }
                return;
            }
            return err;
        };
        self.no_route = false;
    }

    /// close — 停止防抖线程 (参考 Go monitor_shared.go:105-110 Close)
    pub fn close(self: *DefaultInterfaceMonitor) void {
        self.debounce_stop.store(true, .release);
        if (self.debounce_thread) |*t| {
            t.join();
            self.debounce_thread = null;
        }
    }

    pub fn defaultInterface(self: *DefaultInterfaceMonitor) ?*const NetworkInterface {
        self.interface_lock.lock();
        defer self.interface_lock.unlock();
        if (self.default_interface) |*iface| return iface;
        return null;
    }

    /// 返回首个排除接口名 (参考 monitor.go:34 MyInterface())
    pub fn myInterface(self: *const DefaultInterfaceMonitor) ?[]const u8 {
        if (self.excluded_count == 0) return null;
        return self.excluded[0].name;
    }

    /// Android VPN 是否启用 (参考 monitor_shared.go AndroidVPNEnabled)
    pub fn isAndroidVPNEnabled(self: *const DefaultInterfaceMonitor) bool {
        return self.android_vpn_enabled;
    }

    /// 是否强制覆盖 Android VPN (参考 monitor_shared.go OverrideAndroidVPN)
    pub fn shouldOverrideAndroidVPN(self: *const DefaultInterfaceMonitor) bool {
        return self.override_android_vpn;
    }

    /// 设置 Android VPN 覆盖标志
    pub fn setOverrideAndroidVPN(self: *DefaultInterfaceMonitor, v: bool) void {
        self.override_android_vpn = v;
    }

    /// Android VPN 状态变化通知 — emit FlagAndroidVPNUpdate
    /// (参考 monitor_android.go:30-31 — 变化时 emit flags=FlagAndroidVPNUpdate)
    fn notifyAndroidVPNChanged(self: *DefaultInterfaceMonitor) void {
        self.interface_lock.lock();
        defer self.interface_lock.unlock();
        if (self.default_interface) |*iface| {
            const iface_copy = iface.*;
            self.emitLocked(&iface_copy, FlagAndroidVPNUpdate);
        } else {
            const empty_iface = NetworkInterface{ .index = 0, .mtu = 0 };
            self.emitLocked(&empty_iface, FlagAndroidVPNUpdate);
        }
    }

    pub fn registerCallback(self: *DefaultInterfaceMonitor, callback: DefaultInterfaceUpdateCallback) !void {
        const node = try self.allocator.create(InterfaceCallbackNode);
        node.* = .{ .callback = callback, .next = null };
        if (self.interface_update_callbacks) |head| {
            node.next = head;
        }
        self.interface_update_callbacks = node;
    }

    /// 取消注册接口更新回调
    pub fn unregisterCallback(self: *DefaultInterfaceMonitor, callback: DefaultInterfaceUpdateCallback) void {
        var prev: ?*InterfaceCallbackNode = null;
        var node = self.interface_update_callbacks;
        while (node) |cb| {
            if (@intFromPtr(cb.callback) == @intFromPtr(callback)) {
                if (prev) |p| {
                    p.next = cb.next;
                } else {
                    self.interface_update_callbacks = cb.next;
                }
                const to_free = cb;
                node = cb.next;
                self.allocator.destroy(to_free);
            } else {
                prev = cb;
                node = cb.next;
            }
        }
    }

    /// 销毁监视器 — 释放所有回调节点
    pub fn destroy(self: *DefaultInterfaceMonitor) void {
        self.close();
        var node = self.interface_update_callbacks;
        while (node) |cb| {
            const next = cb.next;
            self.allocator.destroy(cb);
            node = next;
        }
        self.interface_update_callbacks = null;
    }

    /// 设置排除接口列表（通用化自 registerMyInterface：排除自身防路由循环）。
    /// 最多容纳 8 个，超出静默截断；name 按值复制（由门面 dup 后传入，生命周期归门面）。
    pub fn setExcludedInterfaces(self: *DefaultInterfaceMonitor, list: []const ExcludedInterface) void {
        self.excluded_count = 0;
        for (list) |e| {
            if (self.excluded_count >= self.excluded.len) break;
            self.excluded[self.excluded_count] = e;
            self.excluded_count += 1;
        }
    }

    /// emitLocked — 已持有 interface_lock 时调用
    fn emitLocked(self: *DefaultInterfaceMonitor, iface: *const NetworkInterface, flags: i32) void {
        var node = self.interface_update_callbacks;
        while (node) |cb| {
            cb.callback(iface, flags);
            node = cb.next;
        }
    }

    /// emit — 复制回调列表后调用，避免回调中 re-enter 导致死锁
    fn emit(self: *DefaultInterfaceMonitor, iface: *const NetworkInterface, flags: i32) void {
        const CopiedCallback = struct {
            callback: DefaultInterfaceUpdateCallback,
        };
        var copy_buf: [32]CopiedCallback = undefined;
        var count: usize = 0;
        var node = self.interface_update_callbacks;
        while (node) |cb| : (node = cb.next) {
            if (count < copy_buf.len) {
                copy_buf[count] = .{ .callback = cb.callback };
                count += 1;
            }
        }
        for (copy_buf[0..count]) |cb| {
            cb.callback(iface, flags);
        }
    }

    /// 检查并更新默认接口 (参考 monitor_linux_default.go:12-40 + monitor_android.go:8-68)
    /// 读取 /proc/net/route 查找最低 metric 的默认路由。
    /// Android 上也使用此路径 — /proc/net/route 无需 root 即可读取。
    ///
    /// Android VPN 检测: 使用 RTM_GETRULE netlink 检查 fwmark=0x20000 规则。
    /// 如果 netlink 不可用 (非系统应用)，回退到仅 /proc 路由检测。
    /// 调用方也可通过 setOverrideAndroidVPN() 强制覆盖检测结果。
    pub fn checkUpdate(self: *DefaultInterfaceMonitor) !void {
        if (builtin.os.tag != .linux) return error.UnsupportedOS;

        // 查找 IPv4 默认路由 (优先)
        checkProcRoute(self) catch {};

        // 查找 IPv6 默认路由
        checkProcRoute6(self) catch {};

        // Android VPN 检测: 通过 netlink RTM_GETRULE 扫描 fwmark=0x20000 规则
        // (参考 vendor/sing-tun/monitor_android.go:20-40)
        if (builtin.abi == .android and !self.override_android_vpn) {
            self.checkAndroidVPN();
        }

        if (self.default_interface == null) {
            return error.NoDefaultRoute;
        }
    }

    /// 通过 netlink RTM_GETRULE 检测 Android VPN 状态
    /// (参考 vendor/sing-tun/monitor_android.go:20-40)
    ///
    /// 发送 RTM_GETRULE dump 请求 → 解析响应中 RTM_NEWRULE 消息 →
    /// 检查 FRA_FWMARK 属性是否为 0x20000 (AndroidProtectMark)。
    ///
    /// Android 非系统应用没有 netlink 权限 (EACCES/EPERM)，
    /// 此时静默失败，android_vpn_enabled 保持上次的状态。
    /// 调用方应通过 setOverrideAndroidVPN() 从 Java/Kotlin 层传入 VPN 状态。
    pub fn checkAndroidVPN(self: *DefaultInterfaceMonitor) void {
        const SOCK_DGRAM: u32 = 2;
        const sock = std.c.socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
        if (sock < 0) return;
        defer _ = std.c.close(sock);

        // Bind to netlink
        var addr = SockaddrNl{ .nl_family = @intCast(AF_NETLINK) };
        if (std.c.bind(sock, @ptrCast(&addr), @sizeOf(SockaddrNl)) < 0) return;

        // Build RTM_GETRULE message: nlmsghdr + rtgenmsg{family=AF_UNSPEC}
        var msg: [@sizeOf(NlMsgHdr) + 1]u8 = @splat(0);
        const hdr: *NlMsgHdr = @ptrCast(&msg);
        hdr.len = @intCast(msg.len);
        hdr.type = RTM_GETRULE;
        hdr.flags = NLM_F_REQUEST | NLM_F_DUMP;
        hdr.seq = 1;

        // rtgenmsg.family = AF_UNSPEC (0) → get rules for all families
        msg[@sizeOf(NlMsgHdr)] = 0;

        if (std.c.send(sock, &msg, msg.len, 0) < 0) return; // netlink 监控面查询，非代理数据面 // io-audit: allow

        // 设置 recv 超时 (1 秒)，防止 debounce 线程在异常情况下永久挂起
        const tv = std.posix.timeval{ .sec = 1, .usec = 0 };
        _ = std.posix.system.setsockopt(sock, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, @ptrCast(&tv), @sizeOf(std.posix.timeval));

        // 循环接收多段 netlink 响应，直到收到 NLMSG_DONE
        var recv_buf: [4096]u8 = undefined;
        while (true) {
            const n = std.c.recv(sock, &recv_buf, recv_buf.len, 0); // netlink 监控面查询，非代理数据面 // io-audit: allow
            if (n <= @sizeOf(NlMsgHdr)) return;

            // Parse netlink messages in the buffer
            var offset: usize = 0;
            while (offset + @sizeOf(NlMsgHdr) <= @as(usize, @intCast(n))) {
                const msg_hdr: *const NlMsgHdr = @ptrCast(&recv_buf[offset]);
                const msg_len = msg_hdr.len;
                if (msg_len < @sizeOf(NlMsgHdr) or offset + msg_len > @as(usize, @intCast(n))) break;

                // Look for RTM_NEWRULE messages (response to RTM_GETRULE)
                if (msg_hdr.type == RTM_NEWRULE) {
                    // Scan attributes in the message body for FRA_FWMARK=0x20000
                    // M4 fix: 使用 @sizeOf(FibRuleHdr) 替代硬编码 12
                    const hdr_end: usize = @sizeOf(NlMsgHdr) + @sizeOf(FibRuleHdr); // nlmsghdr + fib_rule_hdr
                    var attr_off: usize = hdr_end;

                    while (attr_off + 4 <= offset + msg_len) {
                        const attr_len: u16 = zf.endian.readIntLittle(u16, recv_buf[attr_off .. attr_off + 2]);
                        const attr_type: u16 = zf.endian.readIntLittle(u16, recv_buf[attr_off + 2 .. attr_off + 4]);

                        if (attr_len < 4) break;

                        // FRA_FWMARK: u32 value in big-endian (network byte order)
                        if (attr_type == FRA_FWMARK and attr_len >= 8) {
                            const val = zf.endian.readIntBig(u32, recv_buf[attr_off + 4 .. attr_off + 8]);
                            if (val == 0x20000) {
                                // VPN 规则发现 — 检查状态是否变化 (参考 monitor_android.go:30-31)
                                if (!self.android_vpn_enabled) {
                                    self.android_vpn_enabled = true;
                                    // 通过 defaultInterface 的 emit 通知 FlagAndroidVPNUpdate
                                    self.notifyAndroidVPNChanged();
                                }
                                return;
                            }
                        }

                        // Advance to next attribute (NLA_ALIGN = 4-byte aligned)
                        attr_off += (attr_len + 3) & ~@as(usize, 3);
                    }
                } else if (msg_hdr.type == NLMSG_DONE) {
                    // End of multi-part message — no VPN rule found
                    // (参考 monitor_android.go:54-58 — 未找到时清除 VPN 状态)
                    if (self.android_vpn_enabled) {
                        self.android_vpn_enabled = false;
                        self.notifyAndroidVPNChanged();
                    }
                    return;
                }

                offset += (msg_len + 3) & ~@as(usize, 3); // NLMSG_ALIGN
            }
        }
    }
};

// ============================================================================
// /proc/net/route 解析 (IPv4)
// ============================================================================

/// 读取 /proc/net/route，查找 metric 最低的默认路由 (destination=00000000, mask=00000000)
/// 参考 monitor_linux_default.go:13-39 的 netlink 等价逻辑
fn checkProcRoute(self: *DefaultInterfaceMonitor) !void {
    // 0.16 移除 std.fs.openFileAbsolute，改用 std.c.open（与 egress.zig 读 /proc 一致）
    const fd = std.c.open("/proc/net/route", .{});
    if (fd < 0) return error.NoDefaultRoute;
    defer _ = std.c.close(fd);

    // 使用动态缓冲区避免大路由表截断
    var content: std.ArrayList(u8) = .empty;
    defer content.deinit(self.allocator);
    var chunk: [4096]u8 = undefined;
    while (true) {
        const n = std.c.read(fd, &chunk, chunk.len);
        if (n <= 0) break;
        try content.appendSlice(self.allocator, chunk[0..@intCast(n)]);
    }
    const data = content.items;

    // 解析每行: Iface Dest Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
    // 跳过第一行 (header)
    var lines = std.mem.splitScalar(u8, data, '\n');
    _ = lines.first(); // 跳过 header

    var lowest_metric: u32 = std.math.maxInt(u32);
    var best_iface: ?[64]u8 = null;

    while (lines.next()) |line| {
        if (line.len < 11) continue;

        var cols = std.mem.tokenizeAny(u8, line, " \t");

        const iface_name = cols.next() orelse continue;
        const dest_str = cols.next() orelse continue;
        // skip Gateway, Flags, RefCnt, Use → Metric is the 7th column
        _ = cols.next(); // Gateway
        _ = cols.next(); // Flags
        _ = cols.next(); // RefCnt
        _ = cols.next(); // Use
        const metric_str = cols.next() orelse continue;
        const mask_str = cols.next() orelse continue;

        // 默认路由: Destination=00000000, Mask=00000000
        if (!std.mem.eql(u8, dest_str, "00000000")) continue;
        if (!std.mem.eql(u8, mask_str, "00000000")) continue;

        // 跳过排除接口自身 (支持多实例)
        var is_excluded = false;
        for (self.excluded[0..self.excluded_count]) |ex| {
            if (std.mem.eql(u8, iface_name, ex.name)) {
                is_excluded = true;
                break;
            }
        }
        if (is_excluded) continue;

        const metric = std.fmt.parseInt(u32, metric_str, 16) catch continue;

        if (metric < lowest_metric) {
            lowest_metric = metric;
            var name_buf: [64]u8 = @splat(0);
            @memcpy(name_buf[0..@min(iface_name.len, 63)], iface_name[0..@min(iface_name.len, 63)]);
            best_iface = name_buf;
        }
    }

    if (best_iface) |bn| {
        const iface = try resolveInterface(self, bn[0..@min(std.mem.indexOfScalar(u8, &bn, 0) orelse 64, 63)]);
        if (iface) |new_iface| {
            self.interface_lock.lock();
            defer self.interface_lock.unlock();
            if (self.default_interface) |old| {
                if (old.eql(new_iface)) return;
            }
            self.default_interface = new_iface;
            self.emit(&new_iface, 0);
            return;
        }
    }

    return error.NoDefaultRoute;
}

/// 读取 /proc/net/ipv6_route，查找默认 IPv6 路由
fn checkProcRoute6(self: *DefaultInterfaceMonitor) !void {
    // 0.16 移除 std.fs.openFileAbsolute，改用 std.c.open（与 egress.zig 读 /proc 一致）
    const fd = std.c.open("/proc/net/ipv6_route", .{});
    if (fd < 0) return error.NoDefaultRoute;
    defer _ = std.c.close(fd);

    // 使用动态缓冲区避免大路由表截断
    var content: std.ArrayList(u8) = .empty;
    defer content.deinit(self.allocator);
    var chunk: [4096]u8 = undefined;
    while (true) {
        const n = std.c.read(fd, &chunk, chunk.len);
        if (n <= 0) break;
        try content.appendSlice(self.allocator, chunk[0..@intCast(n)]);
    }
    const data = content.items;

    var lowest_metric: u32 = std.math.maxInt(u32);
    var best_iface: ?[64]u8 = null;

    var lines = std.mem.splitScalar(u8, data, '\n');
    while (lines.next()) |line| {
        if (line.len < 32) continue;

        // 格式: dest(32hex) dest_prefix(2hex) src(32hex) src_prefix(2hex) next_hop(32hex) metric(8hex) ...
        const dest_str = line[0..32];
        const dest_prefix_str = line[33..35];

        // 默认路由: destination 全 0，prefix 00
        // 严格检查全部 32 个十六进制字符 (不可仅靠前 3 字符)
        var all_zero = true;
        for (dest_str) |ch| {
            if (ch != '0') {
                all_zero = false;
                break;
            }
        }
        if (!all_zero) continue;
        if (!std.mem.eql(u8, dest_prefix_str, "00")) continue;

        // 从末尾解析: 10 字段行（dst dstlen src srclen nexthop metric refcnt
        // use flags iface），跳过前两字段后 8 个 token，环形缓冲保留最后 6 个：
        // [flags, iface, nexthop, metric, refcnt, use] — metric 在 (i-5)%6，
        // iface 在 (i-1)%6。原实现 metric 取 (i-4)%6（读到 refcnt 列），使
        // 内核无 v6 网关时挂在 lo 上的 unreachable 占位默认路由以"metric 1"
        // 胜出，默认接口在 enp0s1↔lo 间翻转 → 每次翻转触发 net-change 重建
        // （2026-08-19 linuxvm 实机回归定位）
        var tokens = std.mem.tokenizeAny(u8, line[36..], " \t");
        var metric_str: ?[]const u8 = null;
        var iface_str: ?[]const u8 = null;
        var last6: [6][]const u8 = undefined;
        var i: usize = 0;
        while (tokens.next()) |tok| {
            last6[i % 6] = tok;
            i += 1;
        }
        if (i >= 6) {
            metric_str = last6[(i - 5) % 6];
            iface_str = last6[(i - 1) % 6];
        } else {
            continue;
        }

        const metric = std.fmt.parseInt(u32, metric_str.?, 16) catch continue;
        const iface_name = iface_str.?;

        // 回环接口永远不是合法出口：内核 unreachable 占位默认路由（metric=
        // ffffffff）经 metric 比较已被排除，此处再挡一层其他形态的 lo 默认路由
        if (std.mem.eql(u8, iface_name, "lo")) continue;

        var is_excluded = false;
        for (self.excluded[0..self.excluded_count]) |ex| {
            if (std.mem.eql(u8, iface_name, ex.name)) {
                is_excluded = true;
                break;
            }
        }
        if (is_excluded) continue;

        if (metric < lowest_metric) {
            lowest_metric = metric;
            var name_buf: [64]u8 = @splat(0);
            @memcpy(name_buf[0..@min(iface_name.len, 63)], iface_name[0..@min(iface_name.len, 63)]);
            best_iface = name_buf;
        }
    }

    if (best_iface) |bn| {
        const iface = try resolveInterface(self, bn[0..@min(std.mem.indexOfScalar(u8, &bn, 0) orelse 64, 63)]);
        if (iface) |new_iface| {
            self.interface_lock.lock();
            defer self.interface_lock.unlock();
            if (self.default_interface) |old| {
                if (old.eql(new_iface)) return;
            }
            self.default_interface = new_iface;
            self.emit(&new_iface, 0);
            return;
        }
    }

    return error.NoDefaultRoute;
}

/// 通过接口名称查找接口索引
fn resolveInterface(self: *DefaultInterfaceMonitor, name: []const u8) !?NetworkInterface {
    // 通过 if_nametoindex 获取 index，然后用 interface_finder 获取完整信息
    const idx = if (builtin.os.tag == .linux) blk: {
        // 使用 C 的 if_nametoindex
        const c_name = try self.allocator.allocSentinel(u8, name.len, 0);
        defer self.allocator.free(c_name);
        @memcpy(c_name[0..name.len], name);
        c_name[name.len] = 0;
        break :blk std.c.if_nametoindex(c_name);
    } else {
        return null;
    };

    if (idx == 0) return null;

    const if_info = self.interface_finder(@intCast(idx)) catch return null;

    var iface = NetworkInterface{
        .index = @intCast(idx),
        .mtu = if_info.mtu,
        .name_len = @min(if_info.name.len, 63),
    };
    @memcpy(iface.name[0..iface.name_len], if_info.name);
    return iface;
}

// ============================================================================
// NetworkUpdateMonitor — Linux netlink 网络变化监听
// 参考 vendor/sing-tun/monitor_linux.go:17-99
//
// Android 兼容性:
//   Google 在 Android 上禁止非系统应用使用 netlink socket。
//   start() 在 Android 上探测 netlink 可用性: 创建 AF_NETLINK socket → bind → 关闭。
//   如果失败，返回 error.NetlinkBanned，调用者应回退到轮询 /proc/net/route。
//
//   参考 Go 原版:
//     - vendor/sing-tun/monitor_linux.go:27-31 ErrNetlinkBanned
//     - vendor/sing-tun/monitor_linux.go:33-55 NewNetworkUpdateMonitor
// ============================================================================

/// Linux netlink 常量
const AF_NETLINK: u32 = 16; // Linux AF_NETLINK
const NETLINK_ROUTE: u32 = 0; // NETLINK_ROUTE protocol

// Netlink message types (for RTM_GETRULE VPN detection)
const RTM_GETRULE: u16 = 34; // RTM_GETRULE — dump all routing rules
const RTM_NEWRULE: u16 = 32; // RTM_NEWRULE — response to RTM_GETRULE

// Netlink message flags
const NLMSG_DONE: u16 = 3;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_DUMP: u16 = 0x300; // NLM_F_ROOT | NLM_F_MATCH

// fib_rules.h: FRA attribute types
const FRA_FWMARK: u16 = 10; // u32 — fwmark value in rule

/// Linux fib_rule_hdr (include/uapi/linux/fib_rules.h)
/// 12 bytes on all architectures.
const FibRuleHdr = extern struct {
    family: u8,
    dst_len: u8,
    src_len: u8,
    tos: u8,
    table: u8,
    res1: u8,
    res2: u8,
    action: u8,
    flags: u32,
};

// Netlink message header (linux/netlink.h)
const NlMsgHdr = extern struct {
    len: u32 = 0,
    type: u16 = 0,
    flags: u16 = 0,
    seq: u32 = 0,
    pid: u32 = 0,
};

/// Linux sockaddr_nl (netlink 地址结构)
const SockaddrNl = extern struct {
    nl_family: u16 = 0,
    nl_pad: u16 = 0,
    nl_pid: u32 = 0,
    nl_groups: u32 = 0,
};

/// 探测 netlink socket 在 Android 上是否可用
/// 如果 socket() 或 bind() 失败，表示 netlink 被系统禁止
/// 参考 vendor/sing-tun/monitor_linux.go:41-52
fn probeNetlink() !void {
    const SOCK_DGRAM: u32 = 2;
    const sock = std.c.socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
    if (sock < 0) return error.NetlinkBanned;
    defer _ = std.c.close(sock);

    var addr = SockaddrNl{
        .nl_family = @intCast(AF_NETLINK),
    };
    const rc = std.c.bind(sock, @ptrCast(&addr), @sizeOf(SockaddrNl));
    if (rc < 0) return error.NetlinkBanned;
}

/// Google 在 Android 上禁止非系统应用使用 netlink socket
/// 参考 vendor/sing-tun/monitor_linux.go:27-31 ErrNetlinkBanned
pub const NetlinkBannedError = error{NetlinkBanned};

/// Linux NetworkUpdateMonitor — netlink 路由/链路变化监听
/// 参考 vendor/sing-tun/monitor_linux.go:17-99
///
/// 通过 NETLINK_ROUTE socket 订阅 RTMGRP_LINK + RTNLGRP_IPV4_ROUTE + RTNLGRP_IPV6_ROUTE
/// 多播组，当路由表或网络接口发生变化时，内核自动推送通知。
/// 事件处理使用 1 秒 debounce 避免高频抖动。
pub const NetworkUpdateMonitor = struct {
    closed: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    sock_fd: std.c.fd_t = -1,
    callbacks: ?*NetworkUpdateCallbackNode = null,
    thread: ?std.Thread = null,
    allocator: std.mem.Allocator,

    // D75 fix: spinlock 保护 callback 链表并发访问
    cb_lock: bool = false,

    // D78 fix: 追踪 close 是否已调用，确保幂等
    closed_called: bool = false,

    const RTMGRP_LINK: u32 = 1;
    const RTNLGRP_IPV4_ROUTE: u32 = 0x80;
    const RTNLGRP_IPV6_ROUTE: u32 = 0x100;

    /// 创建 NetworkUpdateMonitor（stub 契约：非 error 返回）。
    /// Android 的 netlink 可用性探测推迟到 start()（start 返回 !void，可上报 NetlinkBanned）。
    /// 参考 vendor/sing-tun/monitor_linux.go:33-55
    pub fn init(allocator: std.mem.Allocator) @This() {
        return .{ .allocator = allocator };
    }

    /// D78 fix: 幂等 close — 多次调用安全
    pub fn close(self: *NetworkUpdateMonitor) void {
        if (self.closed_called) return;
        self.closed_called = true;
        self.closed.store(true, .release);
        if (self.sock_fd >= 0) {
            _ = std.c.close(self.sock_fd);
            self.sock_fd = -1;
        }
        if (self.thread) |*t| {
            t.join();
            self.thread = null;
        }
    }

    /// D75 fix: lock/unlock for callback list
    fn lockCb(self: *NetworkUpdateMonitor) void {
        while (@atomicRmw(bool, &self.cb_lock, .Xchg, true, .acquire)) {
            std.atomic.spinLoopHint();
        }
    }
    fn unlockCb(self: *NetworkUpdateMonitor) void {
        @atomicStore(bool, &self.cb_lock, false, .release);
    }

    /// 注册回调 — 路由/链路变化时调用
    pub fn registerCallback(self: *NetworkUpdateMonitor, callback: NetworkUpdateCallback, ctx: ?*anyopaque) !void {
        self.lockCb();
        defer self.unlockCb();
        const node = try self.allocator.create(NetworkUpdateCallbackNode);
        node.* = .{ .callback = callback, .ctx = ctx };
        node.next = self.callbacks;
        self.callbacks = node;
    }

    /// 取消注册回调 — 移除所有匹配的 callback+ctx 节点
    pub fn unregisterCallback(self: *NetworkUpdateMonitor, callback: NetworkUpdateCallback, ctx: ?*anyopaque) void {
        self.lockCb();
        defer self.unlockCb();
        var prev: ?*NetworkUpdateCallbackNode = null;
        var node = self.callbacks;
        while (node) |cb| {
            if (@intFromPtr(cb.callback) == @intFromPtr(callback) and cb.ctx == ctx) {
                if (prev) |p| {
                    p.next = cb.next;
                } else {
                    self.callbacks = cb.next;
                }
                const to_free = cb;
                node = cb.next;
                self.allocator.destroy(to_free);
            } else {
                prev = cb;
                node = cb.next;
            }
        }
    }

    /// 销毁监视器 — 释放所有回调节点并关闭 socket
    pub fn destroy(self: *NetworkUpdateMonitor) void {
        self.close();
        self.lockCb();
        defer self.unlockCb();
        var node = self.callbacks;
        while (node) |cb| {
            const next = cb.next;
            self.allocator.destroy(cb);
            node = next;
        }
        self.callbacks = null;
    }

    /// 启动 netlink 事件监听
    /// 对应 Go monitor_linux.go:57-68 Start() + loopUpdate:70-89
    pub fn start(self: *NetworkUpdateMonitor) !void {
        // Android: 先探测 netlink 可用性（参考 monitor_linux.go:33-55 的构造时探测，
        // 因 stub 契约 init 非 error 返回，探测移至此）
        if (builtin.abi == .android) {
            try probeNetlink();
        }

        const SOCK_DGRAM: u32 = 2;
        const SOCK_CLOEXEC: u32 = 0x80000;

        const fd = std.c.socket(AF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC, NETLINK_ROUTE);
        if (fd < 0) return error.SocketFailed;

        // 订阅链路变化 + IPv4/IPv6 路由变化多播组
        const nl_groups = RTMGRP_LINK | RTNLGRP_IPV4_ROUTE | RTNLGRP_IPV6_ROUTE;
        var addr = SockaddrNl{
            .nl_family = @intCast(AF_NETLINK),
            .nl_groups = nl_groups,
        };
        const rc = std.c.bind(fd, @ptrCast(&addr), @sizeOf(SockaddrNl));
        if (rc < 0) {
            _ = std.c.close(fd);
            return error.BindFailed;
        }

        self.sock_fd = fd;

        // 启动事件循环线程
        self.thread = try std.Thread.spawn(.{}, eventLoop, .{self});
    }

    /// 通知所有已注册回调
    /// 对应 Go loopUpdate 中的 m.emit()
    pub fn emit(self: *NetworkUpdateMonitor) void {
        // 锁内复制回调，锁外调用 (避免 re-enter 死锁)
        const CopiedCb = struct {
            callback: NetworkUpdateCallback,
            ctx: ?*anyopaque,
        };
        var copy_buf: [32]CopiedCb = undefined;
        var count: usize = 0;
        self.lockCb();
        defer self.unlockCb();
        var node = self.callbacks;
        while (node) |n| {
            if (count < copy_buf.len) {
                copy_buf[count] = .{ .callback = n.callback, .ctx = n.ctx };
                count += 1;
            }
            node = n.next;
        }
        for (copy_buf[0..count]) |cb| {
            cb.callback(cb.ctx);
        }
    }

    /// netlink 事件循环 — 在独立线程中运行
    /// 对应 Go loopUpdate():70-89 — select on routeUpdate/linkUpdate → emit → debounce
    fn eventLoop(self: *NetworkUpdateMonitor) void {
        var buf: [4096]u8 = undefined;
        var consecutive_errors: u32 = 0;

        while (!self.closed.load(.acquire)) {
            // 阻塞读取 netlink 消息 — 超时 1 秒以便检查 closed 标志
            const n = readWithTimeout(self.sock_fd, &buf, 1000) catch {
                if (self.closed.load(.acquire)) return;
                consecutive_errors += 1;
                // 防止 poll/read 持续失败导致 CPU 无限旋转
                if (consecutive_errors > 5) {
                    zf.platform.sleepNs(100 * std.time.ns_per_ms); // 事件循环线程连错退避 // io-audit: allow
                }
                continue;
            };
            consecutive_errors = 0;

            if (n > 0) {
                // 检测到变化 → 通知所有回调
                self.emit();

                // Debounce: 等待 1 秒，期间丢弃多余事件 (对应 Go 的 timer 机制)
                var debounce_buf: [4096]u8 = undefined;
                while (!self.closed.load(.acquire)) {
                    const m = readWithTimeout(self.sock_fd, &debounce_buf, 1000) catch break;
                    if (m == 0) break; // 超时，debounce 窗口结束
                }
            }
        }
    }

    /// 带超时的 netlink 读取 — 使用 poll
    fn readWithTimeout(fd: std.c.fd_t, buf: []u8, timeout_ms: i32) !usize {
        var pfd = std.c.pollfd{
            .fd = @intCast(fd),
            .events = std.c.POLL.IN,
            .revents = 0,
        };
        const ret = std.c.poll(@as([*]std.c.pollfd, @ptrCast(&pfd)), 1, timeout_ms);
        if (ret < 0) return error.PollFailed;
        if (ret == 0) return 0; // 超时

        const n = std.c.read(fd, buf.ptr, buf.len);
        if (n < 0) return error.ReadFailed;
        return @intCast(n);
    }
};

// ============================================================================
// 单元测试（skip 条件改为 builtin.os.tag != .linux）
// ============================================================================

const testing = std.testing;

test "DefaultInterfaceMonitor init Linux" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const finder = struct {
        fn find(_: u32) anyerror!InterfaceInfo {
            return error.InterfaceNotFound;
        }
    }.find;
    var mon = DefaultInterfaceMonitor.init(finder, testing.allocator, false);
    try testing.expect(mon.defaultInterface() == null);
}

test "checkUpdate parses /proc/net/route" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const finder = struct {
        fn find(_: u32) anyerror!InterfaceInfo {
            return InterfaceInfo{ .name = "eth0", .mtu = 1500 };
        }
    }.find;
    var mon = DefaultInterfaceMonitor.init(finder, testing.allocator, false);
    mon.checkUpdate() catch {};
    // 成功不崩溃即通过 (CI 环境可能有或无默认路由)
}
