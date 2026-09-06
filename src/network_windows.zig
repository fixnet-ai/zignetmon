//! network_windows — Windows 网络监控平台实现（43-P1c）
//!
//! 平移自 zigtun src/monitor_windows.zig + win_net.zig 监控 API，
//! 参考 vendor/sing-tun/monitor_windows.go (115行)。
//!
//! 核心功能:
//!   - NetworkUpdateMonitor: NotifyRouteChange2 + NotifyIpInterfaceChange 异步回调
//!   - DefaultInterfaceMonitor.checkUpdate(): GetIPForwardTable2 查找最低 metric 默认路由
//!
//! 所有 API 通过 iphlpapi.dll 动态加载，不静态链接（用户级 CLAUDE.md Windows 规范）:
//! Zig 内置的 mingw 静态库对 Vista+ 网络 API 兼容性不足。
//!
//! 解耦（相对 zigtun）:
//!   - tun.InterfaceFinderFn / tun.InterfaceInfo → types.*
//!   - registerMyInterface（tun_names/tun_indices）→ setExcludedInterfaces（[8]ExcludedInterface + count）
//!   - init 两参数 → 三参数（新增 under_network_extension 原样忽略）
//!   - 删除 defaultInterfaceMonitorVtable（TUN vtable 耦合）
//!   - win_net 监控 API 随迁内联；TUN/路由/DNS 配置 API 留 zigtun
//!
//! 参考文件:
//!   - vendor/sing-tun/monitor_windows.go — 路由和接口变化监听 + checkUpdate
//!   - vendor/sing-tun/internal/winipcfg/winipcfg.go — syscall 声明
//!   - vendor/sing-tun/internal/winipcfg/types.go — 结构体定义

const std = @import("std");
const builtin = @import("builtin");
const windows = std.os.windows;
const foundation = @import("zigfoundation");
const types = @import("network_types.zig");

pub const NetworkUpdateCallback = types.NetworkUpdateCallback;
pub const DefaultInterfaceUpdateCallback = types.DefaultInterfaceUpdateCallback;
pub const NetworkInterface = types.NetworkInterface;

/// 接口更新回调链表节点（源 zigtun monitor.zig InterfaceCallbackNode）
const InterfaceCallbackNode = struct {
    callback: DefaultInterfaceUpdateCallback,
    next: ?*InterfaceCallbackNode,
};

// ============================================================================
// iphlpapi 监控 API（随迁自 zigtun win_net.zig，仅保留监控所需子集）
// ============================================================================

extern "kernel32" fn LoadLibraryA(lpLibFileName: [*:0]const u8) ?windows.HMODULE;
extern "kernel32" fn GetProcAddress(hModule: ?windows.HMODULE, lpProcName: [*:0]const u8) callconv(.winapi) ?windows.FARPROC;
extern "kernel32" fn FreeLibrary(hLibModule: windows.HMODULE) callconv(.winapi) windows.BOOL;

var iphlpapi_handle: ?windows.HMODULE = null;
var net_dll_initialized: std.atomic.Value(u32) = std.atomic.Value(u32).init(0);

/// 加载 iphlpapi.dll (CAS 守卫单次初始化)
fn loadIphlpapi() !void {
    if (net_dll_initialized.load(.acquire) == 2) return;
    if (net_dll_initialized.cmpxchgStrong(0, 1, .acquire, .acquire) != null) {
        while (net_dll_initialized.load(.acquire) != 2) {}
        return;
    }

    iphlpapi_handle = LoadLibraryA("iphlpapi.dll") orelse {
        net_dll_initialized.store(0, .release);
        return error.DllNotFound;
    };
    net_dll_initialized.store(2, .release);
}

fn getProc(handle: windows.HMODULE, name: [:0]const u8) !windows.FARPROC {
    const proc = GetProcAddress(handle, name) orelse return error.DllProcNotFound;
    return proc;
}

// ============================================================================
// 类型定义 (参考 winipcfg/types.go)
// ============================================================================

/// LUID — 本地唯一标识符 (参考 winipcfg/luid.go:16)
const LUID = u64;

/// AddressFamily (参考 types.go:28)
const AddressFamily = u16;
const AF_INET: AddressFamily = 2;
const AF_INET6: AddressFamily = 23;
const AF_UNSPEC: AddressFamily = 0;

/// IN_ADDR — IPv4 address (struct in_addr from WinSock)
const IN_ADDR = extern union {
    S_un: extern struct {
        S_addr: u32,
    },
};

/// SOCKADDR_IN — IPv4 socket address (struct sockaddr_in, 16 bytes)
const SOCKADDR_IN = extern struct {
    sin_family: AddressFamily,
    sin_port: u16,
    sin_addr: IN_ADDR,
    sin_zero: [8]u8,
};

/// SOCKADDR_IN6 — IPv6 socket address (struct sockaddr_in6, 28 bytes)
const SOCKADDR_IN6 = extern struct {
    sin6_family: AddressFamily,
    sin6_port: u16,
    sin6_flowinfo: u32,
    sin6_addr: [16]u8,
    anon: u32, // sin6_scope_id
};

/// SOCKADDR — generic socket address (struct sockaddr, 16 bytes)
const SOCKADDR = extern struct {
    sa_family: AddressFamily,
    sa_data: [14]u8,
};

/// SOCKADDR_INET — union of IPv4/IPv6 socket addresses (28 bytes)
const SOCKADDR_INET = extern union {
    Ipv4: SOCKADDR_IN,
    Ipv6: SOCKADDR_IN6,
    si: SOCKADDR,
    si_family: AddressFamily,
};

/// IPAddressPrefix
const IPAddressPrefix = extern struct {
    prefix: SOCKADDR_INET,
    prefix_length: u8,
    _padding: [3]u8,
};

/// MibIPforwardRow2 (参考 types.go:919-937 + types_test.go:128-142 偏移量验证)
/// Size: 104 bytes. 字段顺序必须与 Windows SDK 完全一致。
/// 注意: 布尔字段在 Windows SDK 中为 BOOLEAN (u8)，不是 BOOL (i32)。
const MibIPforwardRow2 = extern struct {
    interface_luid: LUID, // offset 0, 8 bytes
    interface_index: u32, // offset 8, 4 bytes
    destination_prefix: IPAddressPrefix, // offset 12, 32 bytes
    next_hop: SOCKADDR_INET, // offset 44, 28 bytes
    site_prefix_length: u8, // offset 72, 1 byte
    // 3 bytes implicit padding to align u32 at 76
    valid_lifetime: u32, // offset 76, 4 bytes
    preferred_lifetime: u32, // offset 80, 4 bytes
    metric: u32, // offset 84, 4 bytes
    protocol: u32, // offset 88, 4 bytes
    loopback: windows.BOOLEAN, // offset 92, 1 byte
    autoconfigure_address: windows.BOOLEAN, // offset 93, 1 byte
    publish: windows.BOOLEAN, // offset 94, 1 byte
    immortal: windows.BOOLEAN, // offset 95, 1 byte
    age: u32, // offset 96, 4 bytes
    origin: u32, // offset 100, 4 bytes
    // Total: 104 bytes
};

// ============================================================================
// iphlpapi 函数指针 — 全部动态加载，不静态链接
// ============================================================================

const FreeMibTableFn = *const fn (memory: ?*anyopaque) callconv(.winapi) void;
const GetIpForwardTable2Fn = *const fn (family: AddressFamily, table: **anyopaque) callconv(.winapi) windows.DWORD;
const NotifyRouteChange2Fn = *const fn (family: AddressFamily, callback: ?*anyopaque, caller_context: ?*anyopaque, initial_notification: windows.BOOL, handle: *windows.HANDLE) callconv(.winapi) windows.DWORD;
const NotifyIPInterfaceChangeFn = *const fn (family: AddressFamily, callback: ?*anyopaque, caller_context: ?*anyopaque, initial_notification: windows.BOOL, handle: *windows.HANDLE) callconv(.winapi) windows.DWORD;
const CancelMibChangeNotify2Fn = *const fn (notification_handle: windows.HANDLE) callconv(.winapi) windows.DWORD;
// 返回值 NETIO_STATUS：0 = NO_ERROR（参考 winipcfg.go //sys error 映射）
const ConvertInterfaceIndexToLuidFn = *const fn (if_index: u32, luid: *u64) callconv(.winapi) windows.DWORD;
const ConvertInterfaceLuidToNameAFn = *const fn (luid: *const u64, name: [*]u8, length: usize) callconv(.winapi) windows.DWORD;

/// 缓存的函数指针 — 惰性加载
var _free_mib_table: ?FreeMibTableFn = null;
var _get_ip_forward_table2: ?GetIpForwardTable2Fn = null;
var _notify_route_change2: ?NotifyRouteChange2Fn = null;
var _notify_ip_interface_change: ?NotifyIPInterfaceChangeFn = null;
var _cancel_mib_change_notify2: ?CancelMibChangeNotify2Fn = null;
var _convert_index_to_luid: ?ConvertInterfaceIndexToLuidFn = null;
var _luid_to_name_a: ?ConvertInterfaceLuidToNameAFn = null;

/// 惰性加载 iphlpapi.dll 监控函数
fn ensureIphlpapiLoaded() !void {
    if (_notify_route_change2 != null) return;
    const h = iphlpapi_handle orelse return error.DllNotLoaded;

    _free_mib_table = @ptrCast(@alignCast(try getProc(h, "FreeMibTable")));
    _get_ip_forward_table2 = @ptrCast(@alignCast(try getProc(h, "GetIpForwardTable2")));
    _notify_route_change2 = @ptrCast(@alignCast(try getProc(h, "NotifyRouteChange2")));
    _notify_ip_interface_change = @ptrCast(@alignCast(try getProc(h, "NotifyIpInterfaceChange")));
    _cancel_mib_change_notify2 = @ptrCast(@alignCast(try getProc(h, "CancelMibChangeNotify2")));
    _convert_index_to_luid = @ptrCast(@alignCast(try getProc(h, "ConvertInterfaceIndexToLuid")));
    _luid_to_name_a = @ptrCast(@alignCast(try getProc(h, "ConvertInterfaceLuidToNameA")));
}

/// 接口 index → 接口名反查（#64，补 43-P3 遗留 TODO）。
///
/// ConvertInterfaceIndexToLuid + ConvertInterfaceLuidToNameA（iphlpapi，Vista+；
/// 调用序列参考 winipcfg/zwinipcfg_windows.go:45,93）。返回 ifAlias 名
/// （如 "Ethernet"，语义对应 POSIX 侧的 "en0"/"enp0s1"）。
///
/// buf 需 ≥ NDIS_IF_MAX_STRING_SIZE(256)（含 null 终止）；返回 null = 查询失败。
/// 仅查询不持锁：门面单例保证查询无并发（与 defaultInterfaceFinder 契约一致）。
pub fn ifIndexToName(index: u32, buf: []u8) ?[]const u8 {
    loadIphlpapi() catch return null;
    ensureIphlpapiLoaded() catch return null;

    var luid: u64 = 0;
    if (_convert_index_to_luid.?(index, &luid) != 0) return null;
    if (_luid_to_name_a.?(&luid, buf.ptr, buf.len) != 0) return null;

    const len = std.mem.indexOfScalar(u8, buf, 0) orelse buf.len;
    return buf[0..len];
}

/// 释放 MIB 表 (参考 winipcfg.go:19)
fn freeMibTable(ptr: ?*anyopaque) void {
    _free_mib_table.?(ptr);
}

// ============================================================================
// 通知回调 (参考 monitor_windows.go:29-47)
// ============================================================================

/// 注册路由变化回调 (参考 monitor_windows.go:30-33)
fn notifyRouteChange2(family: AddressFamily, callback: ?*anyopaque, ctx: ?*anyopaque, initial: bool) !windows.HANDLE {
    const fn_ptr = _notify_route_change2 orelse return error.DllNotLoaded;
    var handle: windows.HANDLE = windows.INVALID_HANDLE_VALUE;
    const ret = fn_ptr(family, callback, ctx, @enumFromInt(@as(c_int, @intFromBool(initial))), &handle);
    if (ret != 0) return error.NotifyRouteChangeFailed;
    return handle;
}

/// 注册 IP 接口变化回调 (参考 monitor_windows.go:37-40)
fn notifyIpInterfaceChange(family: AddressFamily, callback: ?*anyopaque, ctx: ?*anyopaque, initial: bool) !windows.HANDLE {
    const fn_ptr = _notify_ip_interface_change orelse return error.DllNotLoaded;
    var handle: windows.HANDLE = windows.INVALID_HANDLE_VALUE;
    const ret = fn_ptr(family, callback, ctx, @enumFromInt(@as(c_int, @intFromBool(initial))), &handle);
    if (ret != 0) return error.NotifyIPInterfaceChangeFailed;
    return handle;
}

/// 取消通知 (参考 monitor_windows.go:49-53)
fn cancelMibChangeNotify2(handle: windows.HANDLE) !void {
    const fn_ptr = _cancel_mib_change_notify2 orelse return error.DllNotLoaded;
    const ret = fn_ptr(handle);
    if (ret != 0) return error.CancelMibChangeNotifyFailed;
}

// ============================================================================
// NetworkUpdateMonitor — via iphlpapi (参考 monitor_windows.go:29-57)
// ============================================================================

pub const NetworkUpdateMonitor = struct {
    route_handle: windows.HANDLE,
    interface_handle: windows.HANDLE,
    callbacks: std.ArrayList(NetworkUpdateCallbackEntry),
    allocator: std.mem.Allocator,

    // spinlock 保护 callback 列表并发访问
    cb_lock: bool = false,

    pub fn init(allocator: std.mem.Allocator) NetworkUpdateMonitor {
        return .{
            .route_handle = windows.INVALID_HANDLE_VALUE,
            .interface_handle = windows.INVALID_HANDLE_VALUE,
            .callbacks = std.ArrayList(NetworkUpdateCallbackEntry).empty,
            .allocator = allocator,
        };
    }

    pub fn start(self: *NetworkUpdateMonitor) !void {
        Iphlpapi.init() catch |err| {
            std.log.warn("[network] iphlpapi load failed: {s}", .{@errorName(err)});
            return err;
        };

        const emit_ptr: *anyopaque = @ptrCast(@constCast(self));

        self.route_handle = try notifyRouteChange2(
            AF_UNSPEC,
            @ptrCast(@constCast(&routeChangeCallback)),
            emit_ptr,
            false,
        );

        self.interface_handle = notifyIpInterfaceChange(
            AF_UNSPEC,
            @ptrCast(@constCast(&interfaceChangeCallback)),
            emit_ptr,
            false,
        ) catch |err| {
            cancelMibChangeNotify2(self.route_handle) catch {};
            self.route_handle = windows.INVALID_HANDLE_VALUE;
            return err;
        };
    }

    pub fn close(self: *NetworkUpdateMonitor) void {
        if (self.route_handle != windows.INVALID_HANDLE_VALUE) {
            cancelMibChangeNotify2(self.route_handle) catch {};
            self.route_handle = windows.INVALID_HANDLE_VALUE;
        }
        if (self.interface_handle != windows.INVALID_HANDLE_VALUE) {
            cancelMibChangeNotify2(self.interface_handle) catch {};
            self.interface_handle = windows.INVALID_HANDLE_VALUE;
        }
    }

    /// Windows 走系统回调，无需手动 poll（保留统一形状）
    pub fn poll(_: *NetworkUpdateMonitor) !void {}

    /// lock/unlock for callback list
    fn lockCb(self: *NetworkUpdateMonitor) void {
        while (@atomicRmw(bool, &self.cb_lock, .Xchg, true, .acquire)) {
            std.atomic.spinLoopHint();
        }
    }
    fn unlockCb(self: *NetworkUpdateMonitor) void {
        @atomicStore(bool, &self.cb_lock, false, .release);
    }

    pub fn registerCallback(self: *NetworkUpdateMonitor, cb: NetworkUpdateCallback, ctx: ?*anyopaque) !void {
        self.lockCb();
        defer self.unlockCb();
        try self.callbacks.append(self.allocator, .{ .callback = cb, .ctx = ctx });
    }

    /// 取消注册回调 — 从 ArrayList 中移除 (顺序无关)
    pub fn unregisterCallback(self: *NetworkUpdateMonitor, cb: NetworkUpdateCallback, ctx: ?*anyopaque) void {
        self.lockCb();
        defer self.unlockCb();
        for (self.callbacks.items, 0..) |entry, i| {
            if (@intFromPtr(entry.callback) == @intFromPtr(cb) and entry.ctx == ctx) {
                _ = self.callbacks.swapRemove(i);
                return;
            }
        }
    }

    /// 销毁监视器 — 释放所有资源
    pub fn destroy(self: *NetworkUpdateMonitor) void {
        self.close();
        self.callbacks.deinit(self.allocator);
    }

    pub fn emit(self: *NetworkUpdateMonitor) void {
        // 锁内复制，锁外调用 (避免 re-enter 死锁)
        const CopiedCb = struct {
            callback: NetworkUpdateCallback,
            ctx: ?*anyopaque,
        };
        var copy_buf: [32]CopiedCb = undefined;
        var count: usize = 0;
        self.lockCb();
        defer self.unlockCb();
        for (self.callbacks.items) |entry| {
            if (count < copy_buf.len) {
                copy_buf[count] = .{ .callback = entry.callback, .ctx = entry.ctx };
                count += 1;
            }
        }
        for (copy_buf[0..count]) |cb| {
            cb.callback(cb.ctx);
        }
    }
};

const NetworkUpdateCallbackEntry = struct {
    callback: NetworkUpdateCallback,
    ctx: ?*anyopaque = null,
};

// 原始 iphlpapi 回调签名 (winipcfg/route_change_handler.go:76 routeChanged 同款):
//   (PVOID CallerContext, PMIB_*_ROW Row, MIB_NOTIFICATION_TYPE NotificationType)
// x64 ABI 下 CallerContext=RCX(参数1)、Row=RDX(参数2)、NotificationType=R8(参数3)。
// CallerContext = start() 注册时 notifyRouteChange2/notifyIpInterfaceChange 第 3 参传入
// 的 emit_ptr，即唯一的 self 携带通道；另两参本监视器不消费，弃名忽略。
// ⚠️ 曾错读第 3 参 (NotificationType 小整数) 为 ctx → ctx.? 对 0 解包 panic
//    (attempt to use null value)，winx64 disconnect 实测触发（继承自 zigtun
//    monitor_windows.zig 的潜伏 bug）。参数顺序勿改。

fn routeChangeCallback(
    ctx: ?*anyopaque, // CallerContext
    _: ?*anyopaque, // Row
    _: ?*anyopaque, // NotificationType
) callconv(.winapi) void {
    const self: *NetworkUpdateMonitor = @ptrCast(@alignCast(ctx orelse return));
    self.emit();
}

fn interfaceChangeCallback(
    ctx: ?*anyopaque, // CallerContext
    _: ?*anyopaque, // Row
    _: ?*anyopaque, // NotificationType
) callconv(.winapi) void {
    const self: *NetworkUpdateMonitor = @ptrCast(@alignCast(ctx orelse return));
    self.emit();
}

// ============================================================================
// DefaultInterfaceMonitor — Windows 实现 (参考 monitor_windows.go:60-115)
// ============================================================================

pub const DefaultInterfaceMonitor = struct {
    default_interface: ?NetworkInterface = null,
    interface_update_callbacks: ?*InterfaceCallbackNode = null,
    interface_finder: types.InterfaceFinderFn,
    // 排除接口 (通用化自 registerMyInterface，多 TUN 实例排除自身防路由循环)
    excluded: [8]types.ExcludedInterface = undefined,
    excluded_count: usize = 0,
    allocator: std.mem.Allocator,

    // 使用 foundation.sync.Mutex 保护 default_interface 多线程访问
    interface_lock: foundation.sync.Mutex = .{},

    // noRoute state tracking — 路由丢失时通知 callback
    no_route: bool = true,

    // 防抖定时器 (参考 Go monitor_shared.go:74-78 delayCheckUpdate)
    debounce_thread: ?std.Thread = null,
    debounce_stop: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    debounce_triggered: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    pub fn init(
        interface_finder: types.InterfaceFinderFn,
        allocator: std.mem.Allocator,
        _: bool, // under_network_extension — Windows 平台不使用，原样忽略
    ) DefaultInterfaceMonitor {
        return .{
            .interface_finder = interface_finder,
            .allocator = allocator,
        };
    }

    pub fn start(self: *DefaultInterfaceMonitor) !void {
        self.postCheckUpdate() catch |err| {
            if (err != error.NoDefaultRoute) return err;
        };
        self.debounce_stop.store(false, .release);
        self.debounce_thread = try std.Thread.spawn(.{}, debounceLoop, .{self});
    }

    pub fn notifyNetworkChanged(self: *DefaultInterfaceMonitor) void {
        self.debounce_triggered.store(true, .release);
    }

    fn debounceLoop(self: *DefaultInterfaceMonitor) void {
        while (!self.debounce_stop.load(.acquire)) {
            if (self.debounce_triggered.load(.acquire)) {
                self.debounce_triggered.store(false, .release);
                foundation.platform.sleepNs(1 * std.time.ns_per_s);
                if (!self.debounce_stop.load(.acquire)) {
                    // 不吞掉 postCheckUpdate 错误，至少记录日志
                    self.postCheckUpdate() catch |err| {
                        std.log.warn("[network] debounce postCheckUpdate failed: {s}", .{@errorName(err)});
                    };
                }
            } else {
                foundation.platform.sleepNs(100 * std.time.ns_per_ms);
            }
        }
    }

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

    /// 非 Android 平台恒 false（统一接口，门面无 comptime 分支）
    pub fn isAndroidVPNEnabled(_: *const DefaultInterfaceMonitor) bool {
        return false;
    }

    /// 返回首个排除接口名 (通用化自 registerMyInterface / myInterface)
    pub fn myInterface(self: *const DefaultInterfaceMonitor) ?[]const u8 {
        if (self.excluded_count == 0) return null;
        return self.excluded[0].name;
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

    /// 设置排除接口列表 (通用化自 registerMyInterface)。
    /// name 生命周期由门面单例保证（init 时已 dup），此处不额外拷贝。
    pub fn setExcludedInterfaces(self: *DefaultInterfaceMonitor, list: []const types.ExcludedInterface) void {
        var n: usize = 0;
        for (list) |e| {
            if (n >= self.excluded.len) break;
            self.excluded[n] = e;
            n += 1;
        }
        self.excluded_count = n;
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

    /// 检查并更新默认接口 (参考 monitor_windows.go:60-115)
    /// 使用 GetIPForwardTable2 查找默认路由 (destination 0.0.0.0/0) 中 metric 最低的接口
    pub fn checkUpdate(self: *DefaultInterfaceMonitor) !void {
        if (builtin.os.tag != .windows) return error.UnsupportedOS;

        // 加载 iphlpapi (参考 monitor_windows.go:61-62)
        try Iphlpapi.init();

        // GetIPForwardTable2(AF_INET) 获取 IPv4 路由表 (参考 monitor_windows.go:61)
        var tab: ?*anyopaque = null;
        const ret = _get_ip_forward_table2.?(AF_INET, @ptrCast(&tab));
        if (ret != 0) return error.GetIPForwardTableFailed;
        if (tab == null) return error.NoDefaultRoute;
        defer freeMibTable(tab);

        // 遍历路由表 (参考 monitor_windows.go:64-99)
        const num_entries: *align(1) const u32 = @ptrCast(tab.?);
        // ARM64 fix: MIB 表行偏移需按结构体对齐计算，硬编码 +4 在 64 位平台上错误
        const header_offset = std.mem.alignForward(usize, 4, @alignOf(MibIPforwardRow2));
        const rows: [*]MibIPforwardRow2 = @ptrCast(@alignCast(@as([*]u8, @ptrCast(tab.?)) + header_offset));

        var lowest_metric: u32 = std.math.maxInt(u32);
        var best_index: u32 = 0;

        for (0..num_entries.*) |i| {
            const row = rows[i];

            // 检查是否为默认路由: destination 0.0.0.0/0 (参考 monitor_windows.go:67)
            if (row.destination_prefix.prefix_length != 0) continue;

            // 通过 SOCKADDR_INET 检查 IPv4 address
            const family = row.destination_prefix.prefix.si_family;
            if (family != AF_INET) continue;

            const addr = row.destination_prefix.prefix.Ipv4.sin_addr.S_un.S_addr;
            if (addr != 0) continue; // 不是 0.0.0.0

            // 跳过排除接口 (支持多实例)
            if (self.isExcluded(row.interface_index)) continue;

            // 跳过回环和虚拟接口 (参考 monitor_windows.go:78-80)
            if (@intFromEnum(row.loopback) != 0) continue;

            // 跳过自动配置地址 (autoconfigure_address)
            // if (row.autoconfigure_address != 0) continue;

            // 选 metric 最低的 (参考 monitor_windows.go:89-97)
            const metric = row.metric;
            if (metric < lowest_metric) {
                lowest_metric = metric;
                best_index = row.interface_index;
            }
        }

        if (best_index == 0) {
            // 尝试 IPv6 默认路由
            return checkUpdateIPv6(self);
        }

        // 通过 interface_finder 查找接口 (参考 monitor_windows.go:105-110)
        try self.applyInterface(best_index);
    }

    /// 判断接口索引是否为排除接口
    fn isExcluded(self: *const DefaultInterfaceMonitor, index: u32) bool {
        for (self.excluded[0..self.excluded_count]) |e| {
            if (e.index != 0 and index == e.index) return true;
        }
        return false;
    }

    /// 通过 interface_finder 查询接口信息，比较并更新默认接口
    fn applyInterface(self: *DefaultInterfaceMonitor, best_index: u32) !void {
        const if_info = self.interface_finder(best_index) catch return error.InterfaceNotFound;

        var new_iface = NetworkInterface{
            .index = best_index,
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

    /// 辅助: 检查 IPv6 默认路由
    fn checkUpdateIPv6(self: *DefaultInterfaceMonitor) !void {
        var tab: ?*anyopaque = null;
        const ret = _get_ip_forward_table2.?(AF_INET6, @ptrCast(&tab));
        if (ret != 0) return error.NoDefaultRoute;
        if (tab == null) return error.NoDefaultRoute;
        defer freeMibTable(tab);

        const num_entries: *align(1) const u32 = @ptrCast(tab.?);
        const header_offset = std.mem.alignForward(usize, 4, @alignOf(MibIPforwardRow2));
        const rows: [*]MibIPforwardRow2 = @ptrCast(@alignCast(@as([*]u8, @ptrCast(tab.?)) + header_offset));

        var lowest_metric: u32 = std.math.maxInt(u32);
        var best_index: u32 = 0;

        for (0..num_entries.*) |i| {
            const row = rows[i];
            if (row.destination_prefix.prefix_length != 0) continue;
            if (row.destination_prefix.prefix.si_family != AF_INET6) continue;

            // 检查 IPv6 地址是否全零
            const addr = row.destination_prefix.prefix.Ipv6.sin6_addr;
            var is_zero = true;
            for (addr) |byte| {
                if (byte != 0) {
                    is_zero = false;
                    break;
                }
            }
            if (!is_zero) continue;

            if (self.isExcluded(row.interface_index)) continue;
            if (@intFromEnum(row.loopback) != 0) continue;

            if (row.metric < lowest_metric) {
                lowest_metric = row.metric;
                best_index = row.interface_index;
            }
        }

        if (best_index == 0) return error.NoDefaultRoute;

        try self.applyInterface(best_index);
    }
};

// ============================================================================
// iphlpapi 初始化门面（供 NetworkUpdateMonitor.start / checkUpdate 使用）
// ============================================================================

const Iphlpapi = struct {
    fn init() !void {
        try loadIphlpapi();
        try ensureIphlpapiLoaded();
    }
};

// ============================================================================
// 单元测试
// ============================================================================

const testing = std.testing;

test "DefaultInterfaceMonitor init Windows" {
    if (builtin.os.tag != .windows) return error.SkipZigTest;
    const finder = struct {
        fn find(_: u32) anyerror!types.InterfaceInfo {
            return error.InterfaceNotFound;
        }
    }.find;
    var mon = DefaultInterfaceMonitor.init(finder, testing.allocator, false);
    try testing.expect(mon.defaultInterface() == null);
}
