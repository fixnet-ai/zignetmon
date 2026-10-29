//! network_types — zignetmon.network 共享类型（门面与平台实现共用，避免循环 import）
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

// ============================================================================
// 接口类型分类（S12 2026-10-30：本机网络数值由 kc 统一提供——壳不再各自猜）
// ============================================================================

/// 接口类型（消费方显示口径：Wi-Fi / 蜂窝 / 以太网 / 回环 / 隧道 / 其他）。
pub const InterfaceKind = enum { wifi, cellular, ethernet, loopback, tun, other };

/// 按接口名分类（best-effort 名族表；**默认路由接口**的分类才是「网络类型」——
/// 多网卡 / Wi-Fi+蜂窝并存时逐个接口分类无意义，调用方先取默认接口再分类）。
/// ⚠️ darwin en0 在 iOS=Wi-Fi、macOS 笔电同口径；macOS 台式 en0 若为以太网会
/// 误判 wifi（桌面形态消费方可按 need 再精化，v1 接受）。
/// Windows 的 name 若为 friendly name（"WLAN"/"以太网"…）走包含式启发。
pub fn classifyInterfaceName(name: []const u8) InterfaceKind {
    if (name.len == 0) return .other;
    const os = builtin.os.tag;
    if (os.isDarwin()) {
        if (std.mem.startsWith(u8, name, "lo")) return .loopback;
        if (std.mem.startsWith(u8, name, "pdp_ip")) return .cellular;
        if (std.mem.startsWith(u8, name, "utun")) return .tun;
        if (std.mem.startsWith(u8, name, "awdl") or std.mem.startsWith(u8, name, "llw") or
            std.mem.startsWith(u8, name, "bridge") or std.mem.startsWith(u8, name, "anpi")) return .other;
        if (std.mem.eql(u8, name, "en0")) return .wifi;
        if (std.mem.startsWith(u8, name, "en")) return .ethernet;
        return .other;
    }
    if (os == .linux) {
        if (std.mem.startsWith(u8, name, "lo")) return .loopback;
        if (std.mem.startsWith(u8, name, "tun") or std.mem.startsWith(u8, name, "tap") or
            std.mem.startsWith(u8, name, "wg")) return .tun;
        if (std.mem.startsWith(u8, name, "rmnet") or std.mem.startsWith(u8, name, "ccmni") or
            std.mem.startsWith(u8, name, "wwan")) return .cellular;
        if (std.mem.startsWith(u8, name, "wlan") or std.mem.startsWith(u8, name, "wlp") or
            std.mem.startsWith(u8, name, "iwl")) return .wifi;
        if (std.mem.startsWith(u8, name, "eth") or std.mem.startsWith(u8, name, "enp") or
            std.mem.startsWith(u8, name, "ens") or std.mem.startsWith(u8, name, "enx") or
            std.mem.startsWith(u8, name, "usb")) return .ethernet;
        return .other;
    }
    // Windows：friendly name 包含式启发（大小写不敏感）
    var lower_buf: [64]u8 = undefined;
    const n = @min(name.len, lower_buf.len);
    const lower = std.ascii.lowerString(lower_buf[0..n], name[0..n]);
    if (std.mem.indexOf(u8, lower, "loopback") != null) return .loopback;
    if (std.mem.indexOf(u8, lower, "wi-fi") != null or std.mem.indexOf(u8, lower, "wifi") != null or
        std.mem.indexOf(u8, lower, "wlan") != null or std.mem.indexOf(u8, lower, "无线") != null) return .wifi;
    if (std.mem.indexOf(u8, lower, "cellular") != null or std.mem.indexOf(u8, lower, "移动") != null) return .cellular;
    if (std.mem.indexOf(u8, lower, "ethernet") != null or std.mem.indexOf(u8, lower, "以太网") != null) return .ethernet;
    if (std.mem.indexOf(u8, lower, "tunnel") != null or std.mem.indexOf(u8, lower, "vpn") != null or
        std.mem.indexOf(u8, lower, "tun ") != null) return .tun;
    return .other;
}

const builtin = @import("builtin");

test "classifyInterfaceName 名族表" {
    if (builtin.os.tag.isDarwin()) {
        try @import("std").testing.expectEqual(InterfaceKind.wifi, classifyInterfaceName("en0"));
        try @import("std").testing.expectEqual(InterfaceKind.ethernet, classifyInterfaceName("en5"));
        try @import("std").testing.expectEqual(InterfaceKind.cellular, classifyInterfaceName("pdp_ip0"));
        try @import("std").testing.expectEqual(InterfaceKind.tun, classifyInterfaceName("utun3"));
        try @import("std").testing.expectEqual(InterfaceKind.loopback, classifyInterfaceName("lo0"));
    }
    if (builtin.os.tag == .linux) {
        try @import("std").testing.expectEqual(InterfaceKind.wifi, classifyInterfaceName("wlan0"));
        try @import("std").testing.expectEqual(InterfaceKind.cellular, classifyInterfaceName("rmnet_data0"));
        try @import("std").testing.expectEqual(InterfaceKind.ethernet, classifyInterfaceName("eth0"));
        try @import("std").testing.expectEqual(InterfaceKind.ethernet, classifyInterfaceName("enp2s0"));
        try @import("std").testing.expectEqual(InterfaceKind.loopback, classifyInterfaceName("lo"));
        try @import("std").testing.expectEqual(InterfaceKind.tun, classifyInterfaceName("tun0"));
    }
    try @import("std").testing.expectEqual(InterfaceKind.other, classifyInterfaceName(""));
}
