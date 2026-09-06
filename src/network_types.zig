//! network_types — zf.network 共享类型（门面与平台实现共用，避免循环 import）
//!
//! 从 zigtun monitor.zig 平移的跨平台共享类型：
//!   - NetworkUpdateCallback / DefaultInterfaceUpdateCallback — 平台内部回调签名
//!   - NetworkInterface — 接口基础三元组 (index/mtu/name)
//!   - InterfaceFinderFn / InterfaceInfo — 接口信息查询函数类型
//!   - FlagAndroidVPNUpdate — Android VPN 状态变化标志

const std = @import("std");
const zf_net = @import("zigfoundation").net;

/// IpAddr re-export（避免上层同时 import net.zig 与 network 系列）
pub const IpAddr = zf_net.IpAddr;

/// 接口地址（AddressInfo）— 43-P3 网络参数查询产出
pub const AddressInfo = struct {
    addr: zf_net.IpAddr,
    prefix_len: u8 = 0,
};

/// 排除接口（通用化自 zigtun registerMyInterface：多 TUN 实例排除自身防路由循环）
pub const ExcludedInterface = struct {
    name: []const u8,
    index: u32,
};

// ============================================================================
// 回调类型（平移自 zigtun monitor.zig，参考 sing-tun monitor.go:11-16）
// ============================================================================

pub const NetworkUpdateCallback = *const fn (ctx: ?*anyopaque) void;
pub const DefaultInterfaceUpdateCallback = *const fn (defaultInterface: *const NetworkInterface, flags: i32) void;

/// Android VPN 状态变化标志（参考 sing-tun monitor.go:25 FlagAndroidVPNUpdate = 1 << 0）
pub const FlagAndroidVPNUpdate: i32 = 1 << 0;

// ============================================================================
// NetworkInterface — 网络接口基础信息（平移自 zigtun monitor.zig，
// 参考 sing/common/control.Interface）
// ============================================================================

pub const NetworkInterface = struct {
    index: u32,
    mtu: u32,
    name: [64]u8 = @splat(0),
    name_len: usize = 0,

    pub fn eql(self: *const NetworkInterface, other: NetworkInterface) bool {
        return self.index == other.index and self.name_len == other.name_len and
            std.mem.eql(u8, self.name[0..self.name_len], other.name[0..other.name_len]);
    }
};

// ============================================================================
// 接口信息查询（平移自 zigtun tun.zig:423-429）
// ============================================================================

pub const InterfaceFinderFn = *const fn (index: u32) anyerror!InterfaceInfo;

pub const InterfaceInfo = struct {
    mtu: u32,
    name: []const u8,
};
