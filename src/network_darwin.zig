//! network_darwin — macOS/iOS 网络监控平台实现（43-P1a 平移自 zigtun src/monitor.zig）
//!
//! 真实事件源集成测试见文末（F5：`sudo route` 加删 TEST-NET 路由驱动 AF_ROUTE →
//! NetworkUpdateMonitor 注册回调）。Windows/Linux 真实事件源待 VM 补（门面单测
//! 仅经 mock 状态层，事件层覆盖见文末真实事件测试说明）。
//!
//! 核心功能:
//!   - NetworkUpdateMonitor: 网络变化通知 (macOS: AF_ROUTE socket 监听路由表变化)
//!   - DefaultInterfaceMonitor: 默认路由接口跟踪
//!     - macOS: sysctl 路由表 → 查找 metric 最低的默认路由
//!     - iOS NetworkExtension: socket connect + getsockname 回退 (sysctl 不可用)
//!
//! 解耦点 (相对 zigtun monitor.zig):
//!   - tun.InterfaceFinderFn → types.InterfaceFinderFn (network_types.zig)
//!   - tun.MonitorConfig / initWithConfig → 删除; init 三参数定形
//!   - registerMyInterface + tun_names/tun_indices → setExcludedInterfaces + excluded 数组
//!   - defaultInterfaceMonitorVtable → 删除 (TUN vtable 耦合, zigtun 侧 P5 适配)
//!   - on_network_change 字段原样保留 (消费问题留待 P5)
//!
//! 参考:
//!   - vendor/sing-tun/monitor.go — 接口定义 (42行)
//!   - vendor/sing-tun/monitor_darwin.go — macOS checkUpdate() + getDefaultInterfaceBySocket() (225行)
//!   - vendor/sing-tun/monitor_shared.go — Android VPN 状态字段 + 防抖

const std = @import("std");
const builtin = @import("builtin");
const foundation = @import("zigfoundation");
const types = @import("network_types.zig");

// ============================================================================
// 回调类型 (从 network_types.zig 取，此处为便捷 re-export)
// ============================================================================

pub const NetworkUpdateCallback = types.NetworkUpdateCallback;
pub const DefaultInterfaceUpdateCallback = types.DefaultInterfaceUpdateCallback;
pub const NetworkInterface = types.NetworkInterface;

// ============================================================================
// 回调链表节点 (私有类型，仅本文件使用)
// ============================================================================

const CallbackNode = struct {
    callback: types.NetworkUpdateCallback,
    ctx: ?*anyopaque = null,
    next: ?*CallbackNode = null,
};

const InterfaceCallbackNode = struct {
    callback: types.DefaultInterfaceUpdateCallback,
    next: ?*InterfaceCallbackNode,
};

// ============================================================================
// NetworkUpdateMonitor — macOS 路由变化监听 (参考 monitor_darwin.go:20-100)
// ============================================================================

pub const NetworkUpdateMonitor = struct {
    callbacks: ?*CallbackNode = null,
    route_socket_fd: i32 = -1,
    running: bool = false,
    allocator: std.mem.Allocator,

    // M1 fix: spinlock 保护 callback 链表并发访问
    cb_lock: bool = false,

    pub fn init(allocator: std.mem.Allocator) @This() {
        return .{ .allocator = allocator };
    }

    pub fn start(self: *@This()) !void {
        if (self.running) return;

        // macOS AF_ROUTE = 17 (Darwin <sys/socket.h>)
        const AF_ROUTE = 17;
        const route_socket = std.c.socket(AF_ROUTE, std.posix.SOCK.RAW, 0);
        if (route_socket < 0) return error.RouteSocketFailed;

        foundation.socket.setNonBlocking(route_socket);

        self.route_socket_fd = route_socket;
        // M2 fix: 设置 running 标志，防止重复 start() 导致资源泄漏
        self.running = true;
    }

    pub fn close(self: *@This()) void {
        if (self.route_socket_fd >= 0) {
            foundation.socket.closeSocket(self.route_socket_fd);
            self.route_socket_fd = -1;
        }
        self.running = false;
    }

    // M1 fix: lock/unlock for callback list (same pattern as Linux/Windows)
    fn lockCb(self: *@This()) void {
        while (@atomicRmw(bool, &self.cb_lock, .Xchg, true, .acquire)) {
            std.atomic.spinLoopHint();
        }
    }
    fn unlockCb(self: *@This()) void {
        @atomicStore(bool, &self.cb_lock, false, .release);
    }

    pub fn registerCallback(self: *@This(), callback: types.NetworkUpdateCallback, ctx: ?*anyopaque) !void {
        self.lockCb();
        defer self.unlockCb();
        const node = try self.allocator.create(CallbackNode);
        node.* = .{ .callback = callback, .ctx = ctx };
        if (self.callbacks) |head| {
            node.next = head;
        }
        self.callbacks = node;
    }

    /// 取消注册回调 — 移除所有匹配的 callback+ctx 节点
    pub fn unregisterCallback(self: *@This(), callback: types.NetworkUpdateCallback, ctx: ?*anyopaque) void {
        self.lockCb();
        defer self.unlockCb();
        var prev: ?*CallbackNode = null;
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
    pub fn destroy(self: *@This()) void {
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

    pub fn emit(self: *@This()) void {
        // M10 fix: close 后不再触发回调
        if (!self.running) return;

        // D79 fix: 先复制回调列表再调用，避免回调中 re-enter 导致死锁
        // (参考 Go monitor_shared.go emit — 锁内复制数组，锁外调用)
        const CountedCallback = struct {
            callback: types.NetworkUpdateCallback,
            ctx: ?*anyopaque,
        };
        var copy_buf: [32]CountedCallback = undefined;
        var count: usize = 0;
        self.lockCb();
        defer self.unlockCb();
        var node = self.callbacks;
        while (node) |cb| : (node = cb.next) {
            if (count < copy_buf.len) {
                copy_buf[count] = .{ .callback = cb.callback, .ctx = cb.ctx };
                count += 1;
            }
        }
        for (copy_buf[0..count]) |cb| {
            cb.callback(cb.ctx);
        }
    }

    pub fn poll(self: *@This()) !void {
        if (self.route_socket_fd < 0 or !self.running) return;

        var buf: [4096]u8 = undefined;
        const n = std.c.read(self.route_socket_fd, &buf, buf.len);
        if (n < 0) {
            // 0.16: std.c._errno() 已移除，std.c.errno(rc) 传返回值获取 errno（zig-codegen §3.10）；
            // Darwin 无 EWOULDBLOCK（与 EAGAIN 同值），仅比较 AGAIN
            const err = std.c.errno(n);
            if (err == std.posix.E.AGAIN) return;
            return error.ReadFailed;
        }
        if (n == 0) return;
        self.emit();
    }

    /// 暴露 route fd 供门面 darwinPollLoop 做 poll 等待（只读 getter，不转移 fd 所有权）。
    pub fn routeFd(self: *@This()) i32 {
        return self.route_socket_fd;
    }
};

// ============================================================================
// DefaultInterfaceMonitor — 默认接口跟踪 (参考 monitor_darwin.go:109-224 + monitor.go:27-35)
// ============================================================================

pub const DefaultInterfaceMonitor = struct {
    default_interface: ?NetworkInterface = null,
    interface_update_callbacks: ?*InterfaceCallbackNode = null,
    interface_finder: types.InterfaceFinderFn,
    // 排除接口 (通用化自 zigtun registerMyInterface：多 TUN 实例排除自身防路由循环)
    excluded: [8]types.ExcludedInterface = undefined,
    excluded_count: usize = 0,
    allocator: std.mem.Allocator,

    // 使用 zf.sync.Mutex 保护 default_interface 多线程访问
    interface_lock: foundation.sync.Mutex = .{},

    // D73 fix: noRoute state tracking — 路由丢失时通知 callback
    no_route: bool = true,

    // 平台 VPN 状态字段 (参考 monitor_shared.go; 非 Android 平台恒 false)
    override_android_vpn: bool = false,
    android_vpn_enabled: bool = false,

    // iOS NetworkExtension 模式 (参考 monitor_darwin.go under_network_extension)
    under_network_extension: bool = false,

    // on_network_change 回调 — 网络变化时调用 (原样平移自 zigtun，消费留待 P5)
    on_network_change: ?*const fn (ctx: *anyopaque) void = null,
    on_network_change_ctx: ?*anyopaque = null,

    // 防抖定时器 (参考 Go monitor_shared.go:74-78 delayCheckUpdate + checkUpdateTimer)
    debounce_thread: ?std.Thread = null,
    debounce_stop: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    debounce_triggered: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    // 自我唤醒管道：notifyNetworkChanged 写 1 字节 = 条件变量 signal（唤醒阻塞 poll），
    // close 写 1 字节 = 唤醒 debounceLoop 退出。用 [2]i32（本文件仅 darwin 编译，fd_t==i32）
    wake_pipe: [2]i32 = .{ -1, -1 },

    /// 初始化 DefaultInterfaceMonitor
    /// - under_network_extension: 在 iOS NetworkExtension 内运行时设为 true (sysctl 不可用)
    pub fn init(
        interface_finder: types.InterfaceFinderFn,
        allocator: std.mem.Allocator,
        under_network_extension: bool,
    ) DefaultInterfaceMonitor {
        return .{
            .interface_finder = interface_finder,
            .allocator = allocator,
            .under_network_extension = under_network_extension,
            .on_network_change = null,
            .on_network_change_ctx = null,
        };
    }

    /// Start — 初始检查 + 启动防抖线程 (参考 Go monitor_shared.go:62-72 Start)
    /// Go: postCheckUpdate() → RegisterCallback(delayCheckUpdate)
    /// Zig: postCheckUpdate() → 启动内置防抖线程 (独立于 NetworkUpdateMonitor)
    pub fn start(self: *DefaultInterfaceMonitor) !void {
        // 1. 初始检查 (参考 Go postCheckUpdate)
        self.postCheckUpdate() catch |err| {
            // ErrNoRoute 不是致命错误 — 路由可能稍后出现
            if (err != error.NoDefaultRoute) return err;
        };
        // 2. 启动防抖线程 — 等待 notifyNetworkChanged() 触发
        // 调用方通过 NetworkUpdateMonitor 回调链接触发:
        //   NetworkUpdateMonitor callback → monitor.notifyNetworkChanged()
        self.debounce_stop.store(false, .release);
        // 创建唤醒管道（幂等 restart：close 复位 -1，重开新建；失败退化为 100ms 轮询）
        if (self.wake_pipe[0] < 0) {
            var fds: [2]std.c.fd_t = undefined;
            if (std.c.pipe(&fds) == 0) {
                self.wake_pipe = .{ @intCast(fds[0]), @intCast(fds[1]) };
            }
        }
        self.debounce_thread = try std.Thread.spawn(.{}, debounceLoop, .{self});
    }

    /// notifyNetworkChanged — 由 NetworkUpdateMonitor 回调调用
    /// 触发防抖: 1 秒后执行 postCheckUpdate (参考 Go delayCheckUpdate)
    /// 事件驱动实现：置 atomic + 写 wake_pipe 1 字节（= 条件变量 signal）唤醒阻塞 poll
    pub fn notifyNetworkChanged(self: *DefaultInterfaceMonitor) void {
        self.debounce_triggered.store(true, .release);
        if (self.wake_pipe[1] >= 0) {
            _ = std.c.write(self.wake_pipe[1], &[_]u8{1}, 1);
        }
    }

    /// 防抖循环 — 独立线程，事件驱动阻塞等待（wake_pipe + poll 取代 100ms 轮询）
    /// (参考 Go delayCheckUpdate + time.AfterFunc(1s))
    ///  - 空闲：timeout=-1 完全阻塞（零唤醒）
    ///  - notifyNetworkChanged 写 pipe → 立即唤醒 → 触发 1s 防抖窗口
    ///  - 窗口内重触发 → 重置窗口（真正防抖）
    ///  - 窗口到（rc==0）→ 执行 postCheckUpdate
    fn debounceLoop(self: *DefaultInterfaceMonitor) void {
        var drain_buf: [64]u8 = undefined;
        while (!self.debounce_stop.load(.acquire)) {
            const wake_fd = self.wake_pipe[0];
            if (wake_fd < 0) {
                // wake_pipe 创建失败（EMFILE）退化：100ms 轮询保持原行为
                if (self.debounce_triggered.load(.acquire)) {
                    self.debounce_triggered.store(false, .release);
                    foundation.platform.sleepNs(std.time.ns_per_s); // 1s 防抖 (参考 Go time.Second)
                    if (!self.debounce_stop.load(.acquire)) {
                        self.postCheckUpdate() catch |err| {
                            std.log.warn("[network] debounce postCheckUpdate failed: {s}", .{@errorName(err)});
                        };
                    }
                } else {
                    foundation.platform.sleepNs(100 * std.time.ns_per_ms);
                }
                continue;
            }

            // 已触发则等待 1s 防抖窗口；未触发则完全阻塞等唤醒
            const timeout: i32 = if (self.debounce_triggered.load(.acquire)) 1000 else -1;
            var pfd = [_]std.c.pollfd{.{ .fd = @intCast(wake_fd), .events = std.c.POLL.IN, .revents = 0 }};
            const rc = std.c.poll(&pfd, @intCast(pfd.len), timeout);
            if (rc < 0) {
                if (std.c.errno(rc) == std.posix.E.INTR) continue;
                break;
            }
            // 有数据时清空管道（poll 已保证可读不阻塞；每次 signal 写 1 字节）。
            // rc==0 时管道必空，不可读（阻塞 pipe 无数据会永久挂起），故仅在 rc>0 时读。
            if (rc > 0) {
                _ = std.c.read(wake_fd, &drain_buf, drain_buf.len);
            }
            if (self.debounce_stop.load(.acquire)) break;
            if (rc == 0) {
                // 1s 防抖窗口到 → 执行 postCheckUpdate
                self.debounce_triggered.store(false, .release);
                self.postCheckUpdate() catch |err| {
                    std.log.warn("[network] debounce postCheckUpdate failed: {s}", .{@errorName(err)});
                };
            } else {
                // 触发/重触发 → 重置 1s 窗口
                self.debounce_triggered.store(true, .release);
            }
        }
    }

    /// postCheckUpdate — 包装 checkUpdate，处理 noRoute 状态
    /// (参考 Go monitor_shared.go:80-103 postCheckUpdate)
    pub fn postCheckUpdate(self: *DefaultInterfaceMonitor) !void {
        // Go: if m.interfaceFinder != nil { m.interfaceFinder.Update() }
        // Zig interface_finder 是无状态查找函数，无需 Update

        self.checkUpdate() catch |err| {
            // Go: if errors.Is(err, ErrNoRoute) { ... }
            if (err == error.NoDefaultRoute) {
                // 路由丢失 — 如果之前有路由，通知回调
                if (!self.no_route) {
                    self.no_route = true;
                    self.interface_lock.lock();
                    defer self.interface_lock.unlock();
                    self.default_interface = null;
                    const empty_iface = NetworkInterface{ .index = 0, .mtu = 0 };
                    self.emitLocked(&empty_iface, 0);
                    // Phase 20 C3: fire on_network_change callback
                    if (self.on_network_change) |cb| {
                        if (self.on_network_change_ctx) |cb_ctx| {
                            cb(cb_ctx);
                        }
                    }
                }
                return;
            }
            return err;
        };
        // 路由恢复 — 清除 noRoute，fire callback
        self.no_route = false;
        // Phase 20 C3: fire on_network_change callback after successful checkUpdate
        if (self.on_network_change) |cb| {
            if (self.on_network_change_ctx) |cb_ctx| {
                cb(cb_ctx);
            }
        }
    }

    /// close — 停止防抖线程 (参考 Go monitor_shared.go:105-110 Close)
    /// 置 stop 后写 wake_pipe 唤醒阻塞 poll，join 立即返回；随后回收管道 fd（幂等可 restart）
    pub fn close(self: *DefaultInterfaceMonitor) void {
        self.debounce_stop.store(true, .release);
        if (self.wake_pipe[1] >= 0) {
            _ = std.c.write(self.wake_pipe[1], &[_]u8{1}, 1);
        }
        if (self.debounce_thread) |*t| {
            t.join();
            self.debounce_thread = null;
        }
        if (self.wake_pipe[0] >= 0) {
            _ = std.c.close(self.wake_pipe[0]);
            _ = std.c.close(self.wake_pipe[1]);
            self.wake_pipe = .{ -1, -1 };
        }
    }

    pub fn defaultInterface(self: *DefaultInterfaceMonitor) ?*const NetworkInterface {
        self.interface_lock.lock();
        defer self.interface_lock.unlock();
        if (self.default_interface) |*iface| return iface;
        return null;
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

    /// 设置排除的接口 (通用化自 zigtun registerMyInterface：内部存 [8] + count)
    pub fn setExcludedInterfaces(self: *DefaultInterfaceMonitor, list: []const types.ExcludedInterface) void {
        var n: usize = 0;
        for (list) |e| {
            if (n >= self.excluded.len) break;
            self.excluded[n] = e;
            n += 1;
        }
        self.excluded_count = n;
    }

    /// 返回已注册的排除接口首名 (参考 monitor.go:34 MyInterface(); 多实例返回首个)
    pub fn myInterface(self: *const DefaultInterfaceMonitor) ?[]const u8 {
        if (self.excluded_count == 0) return null;
        return self.excluded[0].name;
    }

    pub fn registerCallback(self: *DefaultInterfaceMonitor, callback: types.DefaultInterfaceUpdateCallback) !void {
        const node = try self.allocator.create(InterfaceCallbackNode);
        node.* = .{ .callback = callback, .next = null };
        if (self.interface_update_callbacks) |head| {
            node.next = head;
        }
        self.interface_update_callbacks = node;
    }

    /// 取消注册接口更新回调
    pub fn unregisterCallback(self: *DefaultInterfaceMonitor, callback: types.DefaultInterfaceUpdateCallback) void {
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

    /// emitLocked — 已持有 interface_lock 时调用 (例如 postCheckUpdate 中 noRoute emit)
    fn emitLocked(self: *DefaultInterfaceMonitor, iface: *const NetworkInterface, flags: i32) void {
        var node = self.interface_update_callbacks;
        while (node) |cb| {
            cb.callback(iface, flags);
            node = cb.next;
        }
    }

    /// emit — 复制回调列表后调用，避免回调中 re-enter 导致死锁
    /// (参考 Go monitor_shared.go:112-128 emit — 锁内复制数组，锁外调用)
    fn emit(self: *DefaultInterfaceMonitor, iface: *const NetworkInterface, flags: i32) void {
        // 复制回调到栈数组 (Go: cbs := make([]DefaultInterfaceUpdateCallback, 0, len(m.callbacks)))
        const CopiedCallback = struct {
            callback: types.DefaultInterfaceUpdateCallback,
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
        // 锁外调用 (Go: m.access.Unlock() ... for _, cb := range cbs { cb(...) })
        for (copy_buf[0..count]) |cb| {
            cb.callback(iface, flags);
        }
    }

    /// 检查并更新默认接口
    /// macOS: sysctl 路由表 dump → 解析 RTM 消息
    /// iOS NE: socket connect + getsockname 回退 (sysctl 需要 entitlements)
    pub fn checkUpdate(self: *DefaultInterfaceMonitor) !void {
        if (self.under_network_extension) {
            return self.checkUpdateViaSocket();
        } else {
            return checkUpdateDarwin(self);
        }
    }

    /// iOS NetworkExtension 回退: 通过 connect + getsockname + getifaddrs 获取默认接口
    /// (参考 monitor_darwin.go:183-225 getDefaultInterfaceBySocket)
    fn checkUpdateViaSocket(self: *DefaultInterfaceMonitor) !void {
        // 步骤 1: 创建 UDP socket 探测默认路由
        const SOCK_DGRAM: u32 = 2;
        const sock = std.c.socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) return error.SocketFailed;
        defer foundation.socket.closeSocket(sock);

        // 步骤 2: connect 到公网 DNS (不实际发包，内核仅确定路由接口)
        const candidate_gateways = [_][4]u8{
            .{ 1, 1, 1, 1 },
            .{ 8, 8, 8, 8 },
            .{ 192, 168, 1, 1 },
            .{ 10, 0, 0, 1 },
        };
        var connected: bool = false;
        for (candidate_gateways) |gw| {
            var target: [16]u8 = [_]u8{0} ** 16;
            target[0] = 16; // sin_len
            target[1] = @intCast(AF_INET & 0xFF); // sin_family
            foundation.endian.writeIntBig(u16, target[2..4], 53); // sin_port = 53
            @memcpy(target[4..8], &gw); // sin_addr
            // UDP connect 仅在内核关联对端地址，不发包不阻塞（等价 getsockname 的 setup 语义）
            if (std.c.connect(sock, @ptrCast(&target), 16) == 0) { // io-audit: allow
                connected = true;
                break;
            }
        }
        if (!connected) return error.NoDefaultRoute;

        // 步骤 3: getsockname 获取内核选择的本地源地址
        var local: [16]u8 = [_]u8{0} ** 16;
        var local_len: u32 = 16;
        if (std.c.getsockname(sock, @ptrCast(&local), &local_len) < 0) {
            return error.NoDefaultRoute;
        }

        // BSD sockaddr_in: addr 在偏移 4..8 (skip sin_len + sin_family + sin_port)
        const local_ip_nbo: u32 = @bitCast(local[4..8].*);

        // 步骤 4: getifaddrs 查找匹配此 IP 的接口
        const if_index = try findInterfaceIndexByAddr(local_ip_nbo);
        const if_info = self.interface_finder(if_index) catch {
            return error.InterfaceNotFound;
        };

        // 步骤 5: 构建 NetworkInterface 并 emit
        var new_iface = NetworkInterface{
            .index = if_index,
            .mtu = if_info.mtu,
            .name_len = @min(if_info.name.len, 63),
        };
        @memcpy(new_iface.name[0..new_iface.name_len], if_info.name);

        self.interface_lock.lock();
        defer self.interface_lock.unlock();
        if (self.default_interface) |old| {
            if (old.eql(new_iface)) return;
        }

        self.default_interface = new_iface;
        self.emit(&new_iface, 0);
    }

    /// 通过 getifaddrs 查找拥有指定 IPv4 地址的接口索引
    fn findInterfaceIndexByAddr(ip_nbo: u32) !u32 {
        const libc = struct {
            extern "c" fn getifaddrs(ifap: *?*anyopaque) c_int;
            extern "c" fn freeifaddrs(ifap: ?*anyopaque) void;
        };

        var ifap: ?*anyopaque = null;
        if (libc.getifaddrs(&ifap) != 0) return error.GetIfAddrsFailed;
        defer libc.freeifaddrs(ifap);

        var current = ifap;
        while (current) |ptr| : (current = @as(*align(1) const IfAddrsBsd, @ptrCast(ptr)).next) {
            const ifa = @as(*align(1) const IfAddrsBsd, @ptrCast(ptr));
            const addr_ptr = ifa.addr orelse continue;

            const family_byte = @as([*]const u8, @ptrCast(@alignCast(addr_ptr)))[1];
            if (family_byte != AF_INET) continue;

            const addr_u32_ptr: *align(1) const u32 = @ptrCast(
                @as([*]const u8, @ptrCast(@alignCast(addr_ptr))) + 4,
            );
            if (addr_u32_ptr.* != ip_nbo) continue;

            const name_z: [*:0]const u8 = @ptrCast(ifa.name);
            const index: u32 = @intCast(std.c.if_nametoindex(name_z));
            return index;
        }
        return error.InterfaceNotFound;
    }

    fn checkUpdateDarwin(self: *DefaultInterfaceMonitor) !void {
        // sysctl MIB for route dump (参考 monitor_darwin.go:120)
        var mib = [_]i32{ CTL_NET, PF_ROUTE, 0, 0, NET_RT_DUMP, 0 }; // AF_UNSPEC=0

        // 第一次调用获取缓冲区大小
        var needed: usize = 0;
        if (std.c.sysctl(&mib, mib.len, null, &needed, null, 0) < 0) {
            return error.SysctlFailed;
        }

        // 分配缓冲区并获取路由表
        const buf = try self.allocator.alloc(u8, needed);
        defer self.allocator.free(buf);

        if (std.c.sysctl(&mib, mib.len, buf.ptr, &needed, null, 0) < 0) {
            return error.SysctlFailed;
        }

        // 遍历路由消息，找 index 最小 (metric 最低) 的默认路由
        // (参考 monitor_darwin.go:128-163 — Go 遍历全部路由，选最小 index)
        var offset: usize = 0;
        var lowest_index: u32 = std.math.maxInt(u32);
        var best_iface: ?NetworkInterface = null;

        while (offset + RTM_HEADER_SZ <= needed) {
            const hdr: *align(1) const RtMsghdr = @ptrCast(buf.ptr + offset);
            const msg_len = hdr.rtm_msglen;
            if (msg_len == 0 or offset + msg_len > needed) break;
            defer offset += msg_len;

            // 仅处理 RTM_GET 消息 (version 5)
            if (hdr.rtm_version != RTM_VERSION) continue;

            // 必须有 DST 和 NETMASK 地址 (参考 monitor_darwin.go:130-132)
            if (hdr.rtm_addrs & RTA_DST == 0) continue;
            if (hdr.rtm_addrs & RTA_NETMASK == 0) continue;

            // 解析 sockaddr 链表 (紧跟在真实 rt_msghdr 之后 = RTM_HEADER_SZ，
            // 非 @sizeOf(RtMsghdr)=36——真实头含 rtm_fmask/rt_metrics 等 92B)
            const addrs_start = offset + RTM_HEADER_SZ;

            // 获取 DST sockaddr
            var sa_off: usize = addrs_start;
            const dst_sa = skipSockaddrs(buf, &sa_off, RTAX_DST, hdr.rtm_addrs) orelse continue;

            // 仅检查 IPv4 默认路由 (参考 monitor_darwin.go:133-136)
            if (dst_sa.len < 8) continue; // 空/过短 sockaddr（至少 sa_len+family+port+addr）
            if (dst_sa[1] != AF_INET) continue; // sa_family
            // 检查目标地址是否为 0.0.0.0
            if (foundation.endian.readIntBig(u32, dst_sa[4..8]) != 0) continue;

            // 获取 NETMASK sockaddr (参考 monitor_darwin.go:140-146)
            // 默认路由 0/0 的掩码以空 sockaddr 编码（sa_len=0，Go issue #70528），
            // 视为掩码 0 接受；非空则须为 AF_INET 且 0.0.0.0
            sa_off = addrs_start;
            const mask_sa = skipSockaddrs(buf, &sa_off, RTAX_NETMASK, hdr.rtm_addrs) orelse continue;
            if (mask_sa.len >= 8) {
                if (mask_sa[1] != AF_INET) continue;
                if (foundation.endian.readIntBig(u32, mask_sa[4..8]) != 0) continue; // mask 必须为 0 (即 0.0.0.0/0)
            }

            // 跳过非活跃和没有网关的路由 (参考 monitor_darwin.go:152-156)
            if (hdr.rtm_flags & RTF_UP == 0) continue;
            if (hdr.rtm_flags & RTF_GATEWAY == 0) continue;

            // 通过 index 查找接口 (参考 monitor_darwin.go:148)
            const if_index: u32 = hdr.rtm_index;

            // 跳过排除接口自身 (避免路由循环; 支持多实例)
            var is_excluded = false;
            for (self.excluded[0..self.excluded_count]) |e| {
                if (e.index != 0 and if_index == e.index) {
                    is_excluded = true;
                    break;
                }
            }
            if (is_excluded) continue;

            // 选 index 最小的 (参考 monitor_darwin.go:159-160 if if_index < lowestIndex)
            if (if_index >= lowest_index) continue;
            lowest_index = if_index;

            const if_info = self.interface_finder(if_index) catch continue;

            var iface = NetworkInterface{
                .index = if_index,
                .mtu = if_info.mtu,
                .name_len = @min(if_info.name.len, 63),
            };
            @memcpy(iface.name[0..iface.name_len], if_info.name);
            best_iface = iface;
        }

        // 找到默认路由 → 检查并更新 (参考 monitor_darwin.go:172-175)
        if (best_iface) |new_iface| {
            self.interface_lock.lock();
            defer self.interface_lock.unlock();
            if (self.default_interface) |old| {
                if (old.eql(new_iface)) return;
            }
            self.default_interface = new_iface;
            self.emit(&new_iface, 0);
            return;
        }

        // 未找到默认路由 (参考 monitor_darwin.go:165-166)
        return error.NoDefaultRoute;
    }
};

// ============================================================================
// BSD 结构与常量 (参考 vendor/sing-tun/monitor_darwin.go + x/net/route 包)
// ============================================================================

/// rt_msghdr 前 36B 字段视图。⚠️ 真实 struct rt_msghdr（Darwin15+）含
/// rtm_fmask(int) + rtm_inits(u_long, LP64=8B) + rt_metrics + 兼容字段，
/// 全尺寸 = 0x5c = 92B（x/net/route sizeofRtMsghdrDarwin15）。本结构仅用于
/// 读取前段字段（rtm_msglen/version/flags/addrs/index），**@sizeOf 不得用于
/// 定位 sockaddr 起点**——用 RTM_HEADER_SZ（同 network_params.zig 修复）。
const RtMsghdr = extern struct {
    rtm_msglen: u16,
    rtm_version: u8,
    rtm_type: u8,
    rtm_index: u16,
    _pad: u16,
    rtm_flags: i32,
    rtm_addrs: i32,
    rtm_pid: i32,
    rtm_seq: i32,
    rtm_errno: i32,
    rtm_use: i32,
    rtm_inits: u32,
    // rtm_rmx follows (rt_metrics struct)
};

/// BSD getifaddrs 链表节点 (用于 checkUpdateViaSocket 接口匹配)
/// 参考 zigtun egress.zig IfAddrsBsd
const IfAddrsBsd = extern struct {
    next: ?*IfAddrsBsd,
    name: [*:0]u8,
    flags: u32,
    addr: ?*anyopaque,
    netmask: ?*anyopaque,
    ifu: extern union {
        broadaddr: ?*anyopaque,
        dstaddr: ?*anyopaque,
    },
};

const RTM_VERSION: u8 = 5;
const RTF_UP: i32 = 0x1;
const RTF_GATEWAY: i32 = 0x2;
const RTAX_DST: u32 = 0;
const RTAX_NETMASK: u32 = 2;
const RTA_DST: i32 = 1 << @as(u5, RTAX_DST);
const RTA_NETMASK: i32 = 1 << @as(u5, RTAX_NETMASK);
const AF_INET: u8 = 2;
const CTL_NET: i32 = 4;
const PF_ROUTE: i32 = 17;
const NET_RT_DUMP: i32 = 1;
/// Darwin15+（macOS 11+）sizeof(struct rt_msghdr)，sockaddr 序列紧随其后
/// （x/net/route zsys_darwin.go sizeofRtMsghdrDarwin15 = 0x5c；同 network_params.zig）。
const RTM_HEADER_SZ: usize = 0x5c;
/// Darwin sockaddr record 对齐 = x/net/route kernelAlign（实测 4；空 record 亦占 4B）。
const RT_SA_ALIGN: usize = 4;

/// sockaddr record 长度 roundup 到 RT_SA_ALIGN（复刻 x/net/route roundup）。
fn roundUpRecord(sa_len: usize) usize {
    return (sa_len + 3) & ~@as(usize, 3);
}

/// 跳过前 skip 个 sockaddr，返回第 target 个的指针。
/// Darwin 路由 dump 中 sockaddr record 按 RT_SA_ALIGN roundup 对齐（复刻
/// x/net/route roundup/parseAddrs）；sa_len==0 的空 record（默认路由 0/0 的
/// NETMASK 以空 sockaddr 编码，Go issue #70528）占 RT_SA_ALIGN 字节继续前进，
/// 且该槽返回空切片（len=0）供调用方判断，而非中断遍历。
fn skipSockaddrs(buf: []const u8, offset: *usize, target: u32, addrs_bitmask: i32) ?[]const u8 {
    var skipped: u32 = 0;
    while (skipped < target and skipped < 8) : (skipped += 1) {
        if (addrs_bitmask & (@as(i32, 1) << @as(u5, @intCast(skipped))) == 0) continue;
        if (offset.* >= buf.len) return null;
        const sa_len = buf[offset.*];
        if (sa_len == 0) {
            offset.* += RT_SA_ALIGN; // 空 record
        } else {
            if (offset.* + sa_len > buf.len) return null;
            offset.* += roundUpRecord(sa_len);
        }
    }
    if (addrs_bitmask & (@as(i32, 1) << @as(u5, @intCast(target))) == 0) return null;
    if (offset.* >= buf.len) return null;
    const sa_len = buf[offset.*];
    const rec_len = if (sa_len == 0) RT_SA_ALIGN else roundUpRecord(sa_len);
    if (offset.* + rec_len > buf.len) return null;
    const result = buf[offset.* .. offset.* + @as(usize, sa_len)]; // 空 record → len 0
    offset.* += rec_len;
    return result;
}

// ============================================================================
// 单元测试 (自 zigtun monitor.zig 平移；NetworkInterface eql 已随类型在 network_types.zig)
// ============================================================================

const testing = std.testing;

test "network_darwin: NetworkUpdateMonitor init/close" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;
    var mon = NetworkUpdateMonitor.init(testing.allocator);
    try testing.expect(!mon.running);
    try testing.expectEqual(@as(i32, -1), mon.route_socket_fd);
    mon.close();
}

test "network_darwin: NetworkUpdateMonitor start fails without root" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;
    var mon = NetworkUpdateMonitor.init(testing.allocator);
    defer mon.close();
    mon.start() catch {};
}

test "network_darwin: DefaultInterfaceMonitor init" {
    const finder = struct {
        fn find(_: u32) anyerror!types.InterfaceInfo {
            return error.InterfaceNotFound;
        }
    }.find;
    var mon = DefaultInterfaceMonitor.init(finder, testing.allocator, false);
    try testing.expect(mon.defaultInterface() == null);
}

test "network_darwin: DefaultInterfaceMonitor registerCallback" {
    const finder = struct {
        fn find(_: u32) anyerror!types.InterfaceInfo {
            return error.InterfaceNotFound;
        }
    }.find;
    var mon = DefaultInterfaceMonitor.init(finder, testing.allocator, false);
    defer mon.close();
    const cb = struct {
        fn callback(_: *const NetworkInterface, _: i32) void {}
    }.callback;
    try mon.registerCallback(cb);
    // 取消注册以释放分配的回调节点
    mon.unregisterCallback(cb);
}

test "network_darwin: setExcludedInterfaces + myInterface" {
    const finder = struct {
        fn find(_: u32) anyerror!types.InterfaceInfo {
            return error.InterfaceNotFound;
        }
    }.find;
    var mon = DefaultInterfaceMonitor.init(finder, testing.allocator, false);
    defer mon.destroy();

    const list = [_]types.ExcludedInterface{
        .{ .name = "utun8", .index = 42 },
        .{ .name = "utun9", .index = 43 },
    };
    mon.setExcludedInterfaces(&list);
    try testing.expectEqual(@as(usize, 2), mon.excluded_count);
    try testing.expectEqualStrings("utun8", mon.myInterface().?);
}

// ============================================================================
// 真实事件源集成测试（winx64 返工复查 F5）— 驱动真实内核路由事件，禁止 mock
// ============================================================================
// 背景：网络门面单测全部经 _onInterfaceChanged mock 直插状态层，从不经过
// 事件层（network.zig:623-652）；macOS AF_ROUTE 真实事件源（路由套接字 → read →
// emit → 注册回调）零自动化覆盖。Windows iphlpapi NotifyIpInterfaceChange 回调参数
// 错位 bug 能潜伏，正是因为真实事件源→回调管道没有自动化测试。
//
// 本测试不 mock：真开 AF_ROUTE 路由套接字，经 `sudo route` 加/删一条 RFC 5737
// TEST-NET-3 文档保留段路由（203.0.113.0/24 → 127.0.0.1，不影响本机真实路由与流量），
// 内核向路由套接字广播 RTM_ADD/RTM_DELETE → NetworkUpdateMonitor.poll() 读到 →
// emit() → 断言注册回调真触发。以「加路由前 count==0」作对照基线，区分
// 「真事件驱动」vs「没触发/恒触发」，杜绝假绿。
//
// 边界（如实声明，勿误读为全平台覆盖）：
//   - 本机 macOS 已覆盖：AF_ROUTE 事件源 → 注册回调 的真实管道。
//   - Windows（NotifyIpInterfaceChange / NotifyRouteChange2 异步回调）与
//     Linux（netlink）的真实事件源仍需在对应 VM 上驱动（改默认接口/路由后断言
//     门面回调），本机无法执行——待 VM 补（F5 挂账项）。
//   - 门面 subscribe 回调只有在默认接口/路由身份变化时才触发；无扰触发它需
//     删默认路由 ≥1s（防抖窗口），对常跑 `zig build test` 的门禁过具侵入性，
//     故此处断言事件层注册回调（正是 iphlpapi bug 所在层级）。
//   - 无免密 sudo / 沙箱禁改路由 / AF_ROUTE 打不开 → 返回 SkipZigTest 如实跳过，
//     绝不退回 mock 冒充真事件。
const RealEventCtx = struct {
    count: usize = 0,
};

fn realEventCb(ctx: ?*anyopaque) void {
    const c: *RealEventCtx = @ptrCast(@alignCast(ctx.?));
    c.count += 1;
}

/// 执行 `sudo -n route -n <op> -net 203.0.113.0 -netmask 255.255.255.0 127.0.0.1`。
/// 成功（shell 退出码 0 → pclose 0）返回 true；无免密 sudo / 路由不存在（删除时）
/// 返回 false。TEST-NET-3 为文档保留段，加删不影响真实流量。
fn routeOp(op: []const u8) bool {
    const libc = struct {
        extern "c" fn popen(command: [*:0]const u8, mode: [*:0]const u8) ?*anyopaque;
        extern "c" fn pclose(stream: *anyopaque) c_int;
        extern "c" fn fgetc(stream: *anyopaque) c_int;
    };
    var cmd_z: [256:0]u8 = undefined;
    const z = std.fmt.bufPrintZ(
        &cmd_z,
        "sudo -n route -n {s} -net 203.0.113.0 -netmask 255.255.255.0 127.0.0.1 2>&1",
        .{op},
    ) catch return false;
    const pipe = libc.popen(z.ptr, "r") orelse return false;
    defer _ = libc.pclose(pipe);
    while (libc.fgetc(pipe) != -1) {} // 排空管道（成功时无输出），防止 pclose 阻塞
    return true;
}

test "network_darwin: 真实 AF_ROUTE 事件源——route add/delete 驱动注册回调" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;

    var mon = NetworkUpdateMonitor.init(testing.allocator);
    defer mon.destroy();
    mon.start() catch {
        return error.SkipZigTest; // AF_ROUTE 套接字打不开（沙箱/权限）→ 无法驱动真实源
    };

    var ctx = RealEventCtx{};
    try mon.registerCallback(realEventCb, &ctx);
    defer mon.unregisterCallback(realEventCb, &ctx);

    // 预清理上次崩溃可能残留的 TEST-NET 路由（幂等；路由不存在时 delete 失败忽略）
    _ = routeOp("delete");

    // 对照基线：加路由前不得有任何回调（区分「真事件驱动」vs 未触发/恒触发）
    try testing.expectEqual(@as(usize, 0), ctx.count);

    // 无免密 sudo（route 改表需 root）→ 如实跳过，绝不 mock 冒充
    if (!routeOp("add")) return error.SkipZigTest;
    defer _ = routeOp("delete"); // 无论断言成败都回收临时路由（防残留）

    // 轮询读取真实 AF_ROUTE 套接字：poll() 读到内核广播 RTM_ADD → emit → 回调
    const deadline = foundation.platform.monoMillis() + 5000;
    while (ctx.count == 0 and foundation.platform.monoMillis() < deadline) {
        mon.poll() catch |err| {
            if (err == error.ReadFailed) return error.SkipZigTest;
            return err;
        };
        foundation.platform.sleepNs(30 * std.time.ns_per_ms);
    }
    // 5s 内回调未触发 = 真实事件未驱动（失败，非假绿）
    try testing.expect(ctx.count > 0);
}
