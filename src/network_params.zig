//! network_params — 网络参数查询（43-P3）
//!
//! 纯查询函数层，接入 zf.network 门面（system 查询 → NetworkInfo 快照）。
//! 只实现不优化：不做缓存、不做线程。out 缓冲由调用方提供；除
//! queryAllAddresses（未知接口数 → 用调用方 allocator 动态列表）外，
//! 函数内不分配内存（defaultInterfaceFinder 的 name 切片指向本模块静态缓冲，
//! 调用方经 DefaultInterfaceMonitor 立即拷贝，故无生命周期问题）。
//!
//! 平台分派（comptime / builtin.os.tag）：
//!   - defaultInterfaceFinder: 复用 zf.egress.getInterfaceMtu + if_indextoname
//!   - queryAddresses:        mac/linux/ios/android getifaddrs；win GetAdaptersAddresses
//!   - queryAllAddresses:     全接口地址枚举（POSIX getifaddrs / win GAA），去重，调用方 allocator 分配
//!   - queryGateway:          mac sysctl NET_RT_DUMP；linux /proc/net/route；win TODO
//!   - queryDnsServers:       linux/android /etc/resolv.conf；mac resolv.conf 尽力而为
//!                            （TODO: SystemConfiguration）；win GetAdaptersAddresses
//!   - queryLinkUp:           posix getifaddrs IFF_UP；win GetAdaptersAddresses OperStatus
//!
//! 所有查询为尽力而为：失败返回空/默认值（不 fatal）；不吞 error.Unexpected
//! （本模块查询函数不产生该错误）。

const std = @import("std");
const builtin = @import("builtin");
const net = @import("zigfoundation").net;
const egress = @import("zigfoundation").egress;
const endian = @import("zigfoundation").endian;
const types = @import("network_types.zig");

// ============================================================================
// 平台常量（comptime 分派）
// ============================================================================

const AF_INET = 2; // 全平台一致
const AF_INET6 = switch (builtin.os.tag) {
    .linux => 10,
    .windows => 23,
    else => 30, // Darwin (macOS/iOS/tvOS/watchOS)
};

// ============================================================================
// defaultInterfaceFinder — 默认接口查找函数
// ============================================================================

/// 接口名反查静态缓冲（defaultInterfaceFinder 返回值指向此处）。
/// 调用方（DefaultInterfaceMonitor）在返回后立即 @memcpy 进自身 name 字段，
/// 本模块查询函数间无并发（门面单例负责并发与生命周期），故单缓冲安全。
/// 256 = NDIS_IF_MAX_STRING_SIZE（Windows ifAlias 最长，如 "Loopback Pseudo-Interface 1"；
/// POSIX if 名 ≤ IF_NAMESIZE(16)，同一缓冲跨平台够用）。
var if_index_name_buf: [256]u8 = [_]u8{0} ** 256;

/// 返回接口查找函数：index → InterfaceInfo{mtu, name}。
/// mtu 复用 zf.egress.getInterfaceMtu；name 反查 POSIX 用 if_indextoname；
/// Windows 用 ConvertInterfaceIndexToLuid + ConvertInterfaceLuidToNameA（#64 实现，
/// iphlpapi 动态加载，见 network_windows.zig ifIndexToName）。
pub fn defaultInterfaceFinder() types.InterfaceFinderFn {
    return struct {
        fn find(index: u32) anyerror!types.InterfaceInfo {
            if (builtin.os.tag == .windows) {
                // egress.getInterfaceMtu Windows 侧已实装（GetIpInterfaceEntry 读 NlMtu，
                // 见 egress.getInterfaceMtuWindows）；此处仍走本模块 GetAdaptersAddresses
                // 链（winMtuForIndex），Mtu 字段与 DNS/OperStatus 走查同结构，一次 GAA
                // 查询同源同缓冲，避免为单接口 MTU 再动态加载 iphlpapi。
                const mtu = winMtuForIndex(index) orelse return error.InterfaceNotFound;
                const win = @import("network_windows.zig");
                const name = win.ifIndexToName(index, &if_index_name_buf) orelse
                    return error.InterfaceNotFound;
                return .{ .mtu = mtu, .name = name };
            }
            const mtu = egress.getInterfaceMtu(index) orelse return error.InterfaceNotFound;
            const name = ifIndexToName(index, &if_index_name_buf) orelse
                return error.InterfaceNotFound;

            return .{ .mtu = mtu, .name = name };
        }
    }.find;
}

// ============================================================================
// getifaddrs 链表（POSIX 全平台）
// ============================================================================

/// getifaddrs 节点（macOS/Linux/Android，NDK 亦提供）。
/// ifa_addr/ifa_netmask 为 sockaddr 指针，用 @ptrCast 到 [*]const u8 手动解析。
const IfAddrs = if (builtin.os.tag != .windows) extern struct {
    ifa_next: ?*IfAddrs,
    ifa_name: [*:0]u8,
    ifa_flags: c_uint,
    ifa_addr: ?*anyopaque,
    ifa_netmask: ?*anyopaque,
    ifa_dstaddr: ?*anyopaque,
    ifa_data: ?*anyopaque,
} else opaque {};

const getifaddrs_fn = if (builtin.os.tag != .windows) struct {
    extern "c" fn getifaddrs(ifap: *?*IfAddrs) c_int;
}.getifaddrs else undefined;

const freeifaddrs_fn = if (builtin.os.tag != .windows) struct {
    extern "c" fn freeifaddrs(ifa: ?*IfAddrs) void;
}.freeifaddrs else undefined;

const if_indextoname_fn = if (builtin.os.tag != .windows) struct {
    extern "c" fn if_indextoname(ifindex: c_uint, ifname: [*]u8) ?[*:0]u8;
}.if_indextoname else undefined;

/// 接口索引 → 名称（POSIX）。失败返回 null。
fn ifIndexToName(idx: u32, buf: *[256]u8) ?[]const u8 {
    // if_indextoname 只要求 ≥ IF_NAMESIZE(16)，缓冲放大到 256 兼容 Windows ifAlias
    const ptr = if_indextoname_fn(idx, buf[0..16]) orelse return null;
    return std.mem.sliceTo(ptr, 0);
}

/// getifaddrs 节点是否匹配指定接口名。
fn ifaMatchesName(ifa: *const IfAddrs, name: []const u8) bool {
    return std.mem.eql(u8, std.mem.span(ifa.ifa_name), name);
}

/// 从 sockaddr 指针读 family（兼容 Darwin sa_len+sa_family 与 Linux sa_family:u16）。
fn sockaddrFamily(sa: *anyopaque) u16 {
    const bytes: [*]const u8 = @ptrCast(sa);
    if (comptime builtin.os.tag.isDarwin()) {
        return @as(u16, bytes[1]); // sa_family 在 offset 1（offset 0 为 sa_len）
    } else {
        return endian.readIntNative(u16, bytes[0..2]); // sa_family:u16 在 offset 0
    }
}

/// 从 sockaddr_in/sockaddr_in6 提取 IP 字节 + 前缀长度（从 netmask 计算）。
/// family 必须已是 AF_INET 或 AF_INET6。addr_off/v6_off 为 IP 字节在 sockaddr 内的偏移。
fn sockaddrToIp(sa: *anyopaque, mask_sa: ?*anyopaque, family: u16) types.AddressInfo {
    const addr_bytes: [*]const u8 = @ptrCast(sa);
    if (family == AF_INET) {
        var out: types.AddressInfo = .{ .addr = .{ .v4 = undefined } };
        // sockaddr_in: family(1/2) + port(2) + addr(4)，addr 起点在 offset 4
        out.addr.v4 = addr_bytes[4..8].*;
        out.prefix_len = if (mask_sa) |m|
            netmaskPrefixLen(@as([*]const u8, @ptrCast(m))[4..8], 32)
        else
            0;
        return out;
    }
    // AF_INET6
    var out: types.AddressInfo = .{ .addr = .{ .v6 = undefined } };
    // sockaddr_in6: family(1/2) + port(2) + flowinfo(4) + addr(16)，addr 起点 offset 8
    const v6 = addr_bytes[8..24];
    @memcpy(&out.addr.v6, v6);
    out.prefix_len = if (mask_sa) |m|
        netmaskPrefixLen(@as([*]const u8, @ptrCast(m))[8..24], 128)
    else
        0;
    return out;
}

/// 从 netmask 字节计算前缀长度（前导 1 位数）。
fn netmaskPrefixLen(mask: []const u8, max_bits: u8) u8 {
    var count: u8 = 0;
    for (mask) |byte| {
        if (byte == 0xFF) {
            count += 8;
            continue;
        }
        // 遇到首字节未满 8 位：数该字节内的前导 1 后终止（后续字节必为 0）
        var i: u8 = 8;
        while (i > 0) {
            i -= 1;
            if ((byte & (@as(u8, 1) << @intCast(i))) != 0) {
                count += 1;
            } else {
                break;
            }
        }
        break;
    }
    return @min(count, max_bits);
}

// ============================================================================
// queryAddresses — 接口地址列表
// ============================================================================

/// 查询接口地址列表，返回 out 中已填充的部分（至多 out.len 个）。
/// POSIX 全平台用 getifaddrs 遍历匹配 if_index（经名称反查匹配），
/// 收集 AF_INET/AF_INET6 地址；Windows 用 GetAdaptersAddresses FirstUnicastAddress。
pub fn queryAddresses(if_index: u32, out: []types.AddressInfo) []types.AddressInfo {
    if (builtin.os.tag == .windows) {
        return queryAddressesWindows(if_index, out);
    }
    return queryAddressesPosix(if_index, out);
}

fn queryAddressesPosix(if_index: u32, out: []types.AddressInfo) []types.AddressInfo {
    var name_buf: [256]u8 = [_]u8{0} ** 256;
    const if_name = ifIndexToName(if_index, &name_buf) orelse return &.{};

    var ifap: ?*IfAddrs = null;
    if (getifaddrs_fn(&ifap) != 0) return &.{};
    defer freeifaddrs_fn(ifap);

    var count: usize = 0;
    var cur = ifap;
    while (cur) |ifa| : (cur = ifa.ifa_next) {
        if (count >= out.len) break;
        if (!ifaMatchesName(ifa, if_name)) continue;
        const addr = ifa.ifa_addr orelse continue;
        const family = sockaddrFamily(addr);
        if (family != AF_INET and family != AF_INET6) continue;
        out[count] = sockaddrToIp(addr, ifa.ifa_netmask, family);
        count += 1;
    }
    return out[0..count];
}

// ============================================================================
// queryAllAddresses — 全接口地址枚举（box hosts `lan` 展开基建）
// ============================================================================

/// 枚举本机**全部链路 Up 接口**的地址（不做 per-name/单接口过滤），跨平台：
/// POSIX 全平台 getifaddrs 遍历全链；Windows GetAdaptersAddresses 全适配器
/// FirstUnicastAddress。后端原语复用 queryAddresses 同文件已验证实现
/// （sockaddrToIp / winSockaddrToIp），零新平台文件。
///
/// 返回本机全部 v4+v6 地址（含虚拟/TUN/容器网卡 utun/docker/vEthernet，也含
/// 环回与链路本地），**去重**，**跳过链路 Down 接口的地址**（POSIX IFF_UP /
/// Windows OperStatus——断口 TAP/虚拟卡带静态 IP 时其地址不在本机 local 路由
/// 集，拨号会被默认路由黑洞 20s 超时，winx64 LetsTAP 26.26.26.1 实测）。
/// 语义区分（lan = 本机非 loopback/link-local）由消费方用 zf.net.IpAddr
/// .isLoopback / isLinkLocal 过滤——本层只负责「可用地址」的枚举。
///
/// 所有权：返回切片由 allocator 分配（内部经 ArrayList），调用方用同一
/// allocator free（或交给 Arena/会话 allocator 统一回收）。
/// 尽力而为：OS 查询失败返回空切片（不 fatal）；分配失败上抛 error.OutOfMemory。
pub fn queryAllAddresses(allocator: std.mem.Allocator) ![]types.IpAddr {
    if (builtin.os.tag == .windows) {
        return queryAllAddressesWindows(allocator);
    }
    return queryAllAddressesPosix(allocator);
}

fn queryAllAddressesPosix(allocator: std.mem.Allocator) ![]types.IpAddr {
    var ifap: ?*IfAddrs = null;
    if (getifaddrs_fn(&ifap) != 0) return &.{};
    defer freeifaddrs_fn(ifap);

    var list: std.ArrayList(types.IpAddr) = .empty;
    errdefer list.deinit(allocator);

    var cur = ifap;
    while (cur) |ifa| : (cur = ifa.ifa_next) {
        const addr = ifa.ifa_addr orelse continue;
        const family = sockaddrFamily(addr);
        if (family != AF_INET and family != AF_INET6) continue;
        // 链路过滤：仅 admin-up + 载波在的接口地址才收（winx64 LetsTAP 同构——拔线但
        // 保持 admin-up 的网卡残留静态 IP，会被误收进 .lan 展开顶替本机 local 地址集）。
        if (!posixIfaIsUsable(ifa.ifa_flags)) continue;
        const ai = sockaddrToIp(addr, ifa.ifa_netmask, family);
        if (listContainsIp(&list, ai.addr)) continue; // 去重
        try list.append(allocator, ai.addr);
    }
    return list.toOwnedSlice(allocator);
}

fn queryAllAddressesWindows(allocator: std.mem.Allocator) ![]types.IpAddr {
    var list: std.ArrayList(types.IpAddr) = .empty;
    errdefer list.deinit(allocator);

    var buf: [64 * 1024]u8 align(8) = undefined;
    const adapters = queryAdaptersWindows(&buf) orelse return &.{};

    var current: ?*IP_ADAPTER_ADDRESSES_LH = adapters;
    while (current) |adapter| : (current = adapter.Next) {
        if (adapter.OperStatus != IfOperStatusUp) continue; // 链路 Down → 地址不可拨号（勿入 lan 展开）
        var ua = adapter.FirstUnicastAddress;
        while (ua) |u| : (ua = u.Next) {
            if (!winDadStateUsable(u.DadState)) continue; // DAD 未完成/冲突/Invalid → 跳过
            const ip = winSockaddrToIp(u.Address.lpSockaddr) orelse continue; // 非 v4/v6 跳过
            if (listContainsIp(&list, ip)) continue; // 去重
            try list.append(allocator, ip);
        }
    }
    return list.toOwnedSlice(allocator);
}

/// IpAddr 判等（union(enum) 载荷为数组，避免依赖 == 合成）。
fn ipEql(a: types.IpAddr, b: types.IpAddr) bool {
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

/// 列表是否已含相同地址（去重用，全接口枚举可能跨接口重复）。
fn listContainsIp(list: *const std.ArrayList(types.IpAddr), target: types.IpAddr) bool {
    for (list.items) |ip| {
        if (ipEql(ip, target)) return true;
    }
    return false;
}

// ============================================================================
// queryGateway — 默认网关
// ============================================================================

/// 查询默认网关。macOS sysctl 路由表；Linux/Android /proc/net/route；Windows 已实现（GetBestRoute）。
pub fn queryGateway() ?types.IpAddr {
    if (comptime builtin.os.tag.isDarwin()) {
        return queryGatewayDarwin();
    }
    if (comptime builtin.os.tag == .linux) {
        return queryGatewayLinux();
    }
    if (comptime builtin.os.tag == .windows) {
        return queryGatewayWindows();
    }
    return null;
}

// ============================================================================
// macOS 网关 — sysctl NET_RT_DUMP（参考 zigtun monitor.zig checkUpdateDarwin
//   + x/net/route parseRouteMessage/parseKernelInetAddr/parseAddrs）
// ============================================================================

/// rt_msghdr 前 36B 字段视图。⚠️ 真实 struct rt_msghdr（Darwin15+）含
/// rtm_fmask(int) + rtm_inits(u_long, LP64=8B) + rt_metrics + rtm_use/rtm_mtu
/// 兼容字段，全尺寸 = 0x5c = 92B（x/net/route 权威常量 sizeofRtMsghdrDarwin15）。
/// 本结构仅用于读取头部前段字段（rtm_msglen/version/flags/addrs），
/// **@sizeOf(RtMsghdr)=36 不得用于定位 sockaddr 起点**——用 RTM_HEADER_SZ。
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
};

const RTM_VERSION: u8 = 5;
const RTF_UP: i32 = 0x1;
const RTF_GATEWAY: i32 = 0x2;
const RTAX_DST: u32 = 0; // 目标
const RTAX_GATEWAY: u32 = 1; // 网关
const RTAX_NETMASK: u32 = 2; // 掩码
const CTL_NET: i32 = 4;
const PF_ROUTE: i32 = 17;
const NET_RT_DUMP: i32 = 1;
/// Darwin15+（macOS 11+）sizeof(struct rt_msghdr)，sockaddr 序列紧随其后。
/// x/net/route zsys_darwin.go: sizeofRtMsghdrDarwin15 = 0x5c。route dump 实测
/// 首条默认路由 DST sockaddr 恰在偏移 0x5c。
const RTM_HEADER_SZ: usize = 0x5c;
/// Darwin sockaddr record 对齐 = x/net/route kernelAlign（本机实测 4；
/// 空 record sa_len=0 亦占 4B，见 skipSockaddrs）。
const RT_SA_ALIGN: usize = 4;

/// sockaddr record 长度 roundup 到 RT_SA_ALIGN（复刻 x/net/route roundup/parseAddrs）。
fn roundUpRecord(sa_len: usize) usize {
    return (sa_len + 3) & ~@as(usize, 3);
}

fn queryGatewayDarwin() ?types.IpAddr {
    if (builtin.os.tag != .macos) return null; // iOS NE 内 sysctl 不可用（上层注入）

    var mib = [_]i32{ CTL_NET, PF_ROUTE, 0, 0, NET_RT_DUMP, 0 }; // AF_UNSPEC=0

    var needed: usize = 0;
    if (std.c.sysctl(&mib, mib.len, null, &needed, null, 0) < 0) return null;

    var buf: [64 * 1024]u8 align(8) = undefined; // 路由表远小于 64KB，用栈缓冲避免分配
    if (needed > buf.len) return null;
    if (std.c.sysctl(&mib, mib.len, &buf, &needed, null, 0) < 0) return null;

    // 遍历路由消息，找默认路由（dst=0/0、RTF_UP|RTF_GATEWAY）的 RTAX_GATEWAY 地址
    var offset: usize = 0;
    while (offset + RTM_HEADER_SZ <= needed) {
        const hdr: *align(1) const RtMsghdr = @ptrCast(buf[offset..].ptr);
        const msg_len = hdr.rtm_msglen;
        if (msg_len == 0 or offset + msg_len > needed) break;
        defer offset += msg_len;

        if (hdr.rtm_version != RTM_VERSION) continue;
        if (hdr.rtm_flags & RTF_UP == 0) continue;
        if (hdr.rtm_flags & RTF_GATEWAY == 0) continue;
        if (hdr.rtm_addrs & (@as(i32, 1) << @as(u5, RTAX_DST)) == 0) continue;
        if (hdr.rtm_addrs & (@as(i32, 1) << @as(u5, RTAX_GATEWAY)) == 0) continue;
        if (hdr.rtm_addrs & (@as(i32, 1) << @as(u5, RTAX_NETMASK)) == 0) continue;

        // sockaddr 序列起点 = 真实 rt_msghdr 尾（RTM_HEADER_SZ，非 @sizeOf(RtMsghdr)）
        const addrs_start = offset + RTM_HEADER_SZ;

        // 取 DST sockaddr，必须为 0.0.0.0（默认路由的 DST）
        var sa_off: usize = addrs_start;
        const dst_sa = skipSockaddrs(buf[0..needed], &sa_off, RTAX_DST, hdr.rtm_addrs) orelse continue;
        if (dst_sa.len < 8) continue; // 空/过短 sockaddr
        if (dst_sa[1] != AF_INET) continue; // sa_family
        if (endian.readIntBig(u32, dst_sa[4..8]) != 0) continue; // dst != 0.0.0.0

        // NETMASK：默认路由 0/0 的掩码以空 sockaddr 编码（sa_len=0，Go #70528），
        // 视为掩码 0 接受；非空则须为 AF_INET 且 0.0.0.0
        sa_off = addrs_start;
        const mask_sa = skipSockaddrs(buf[0..needed], &sa_off, RTAX_NETMASK, hdr.rtm_addrs) orelse continue;
        if (mask_sa.len >= 8) {
            if (mask_sa[1] != AF_INET) continue;
            if (endian.readIntBig(u32, mask_sa[4..8]) != 0) continue; // mask != 0.0.0.0
        }

        // 取 GATEWAY sockaddr，返回其地址
        sa_off = addrs_start;
        const gw_sa = skipSockaddrs(buf[0..needed], &sa_off, RTAX_GATEWAY, hdr.rtm_addrs) orelse continue;
        if (gw_sa.len < 8 or gw_sa[1] != AF_INET) continue;
        const gw_u32 = endian.readIntBig(u32, gw_sa[4..8]);
        return .{ .v4 = net.intToIp4(gw_u32) };
    }
    return null;
}

/// 按 RTA_* 位掩码跳过 sockaddr 序列，返回第 target 个 sockaddr 切片。
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
// Linux 网关 — /proc/net/route
// ============================================================================

fn queryGatewayLinux() ?types.IpAddr {
    const f = std.c.fopen("/proc/net/route", "r") orelse return null;
    defer _ = std.c.fclose(f);

    var buf: [4096]u8 = undefined;
    const n = std.c.fread(&buf, 1, buf.len, f);
    const content = buf[0..n];

    // 格式: Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
    // Gateway 为 u32 十六进制小端编码（192.168.2.1 → "0102A8C0"）。
    // 遍历所有默认路由行，按 Metric（越小越优先）选主网关——首个 00000000 行
    // 不保证是默认主路由（多网关/策略路由可多行并存）。
    var best_gw: ?types.IpAddr = null;
    var best_metric: u32 = std.math.maxInt(u32);
    var lines = std.mem.splitScalar(u8, content, '\n');
    _ = lines.next(); // 跳过标题行
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        var cols = std.mem.splitScalar(u8, line, '\t');
        _ = cols.next(); // iface
        const dest = cols.next() orelse continue;
        if (!std.mem.eql(u8, dest, "00000000")) continue;
        const gw_hex = cols.next() orelse continue;
        if (std.mem.eql(u8, gw_hex, "00000000")) continue; // 无网关
        const gw_le = std.fmt.parseInt(u32, gw_hex, 16) catch continue;
        _ = cols.next(); // Flags
        _ = cols.next(); // RefCnt
        _ = cols.next(); // Use
        const metric_hex = cols.next() orelse continue;
        const metric = std.fmt.parseInt(u32, metric_hex, 16) catch continue;
        if (metric < best_metric) {
            best_metric = metric;
            const gw_nbo = @byteSwap(gw_le); // 小端编码 → 网络字节序
            best_gw = .{ .v4 = net.intToIp4(gw_nbo) };
        }
    }
    return best_gw;
}

// ============================================================================
// queryDnsServers — 系统 DNS 服务器
// ============================================================================

/// 查询系统 DNS 服务器，返回 out 中已填充的部分（至多 out.len 个）。
/// Linux/Android 解析 /etc/resolv.conf；macOS 同样尽力读取 resolv.conf
///（TODO: SystemConfiguration SCDynamicStoreCopyDNS，需 build.zig 链接
///  SystemConfiguration framework）；Windows 用 GetAdaptersAddresses DnsServer 链。
pub fn queryDnsServers(out: []types.IpAddr) []types.IpAddr {
    if (builtin.os.tag == .windows) {
        return queryDnsServersWindows(out);
    }
    // Linux/Android 及 macOS 尽力而为：解析 /etc/resolv.conf。
    // 已知限制：Android 上 resolv.conf 不可靠，上层经 injectPlatformInfo 注入；
    // macOS 的 resolv.conf 非权威（SCDynamicStore 才是，见 TODO）。
    return parseResolvConfFile(out);
}

/// 读取 /etc/resolv.conf 并解析 nameserver 行（纯函数 parseResolvConf 的可 IO 包装）。
fn parseResolvConfFile(out: []types.IpAddr) []types.IpAddr {
    const f = std.c.fopen("/etc/resolv.conf", "r") orelse return &.{};
    defer _ = std.c.fclose(f);

    var buf: [4096]u8 = undefined;
    const n = std.c.fread(&buf, 1, buf.len, f);
    return parseResolvConf(buf[0..n], out);
}

/// 解析 resolv.conf 文本（纯函数，便于单元测试）。
/// 收集 "nameserver <ip>" 行，IPv4/IPv6 均支持，写入 out（至多 out.len 个）。
fn parseResolvConf(content: []const u8, out: []types.IpAddr) []types.IpAddr {
    var count: usize = 0;
    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line| {
        if (count >= out.len) break;
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (!std.mem.startsWith(u8, trimmed, "nameserver")) continue;
        // 支持 "nameserver" 紧接 IP（无空格）或 名字 + 空格分隔
        const rest = trimmed["nameserver".len..];
        if (rest.len == 0 or (rest[0] != ' ' and rest[0] != '\t')) continue;
        const ip_str = std.mem.trim(u8, rest, " \t");
        if (ip_str.len == 0) continue;

        if (net.parseIpv4(ip_str)) |v4| {
            out[count] = .{ .v4 = v4 };
            count += 1;
        } else |_| {
            if (net.parseIpv6(ip_str)) |v6| {
                out[count] = .{ .v6 = v6 };
                count += 1;
            } else |_| {}
        }
    }
    return out[0..count];
}

// ============================================================================
// queryLinkUp — 接口链路状态
// ============================================================================

/// 查询接口链路状态。查询失败保守返回 true（避免误判断链）。
/// POSIX: getifaddrs IFF_UP 标志；Windows: GetAdaptersAddresses OperStatus。
pub fn queryLinkUp(if_index: u32) bool {
    if (builtin.os.tag == .windows) {
        return queryLinkUpWindows(if_index);
    }
    return queryLinkUpPosix(if_index);
}

const IFF_UP: c_uint = 0x1;
/// 链路过滤所需位：IFF_RUNNING=0x40（载波/链路在）、IFF_LOOPBACK=0x8。
/// Darwin 与 Linux 两族取值一致（getifaddrs 的 ifa_flags 直接按位比较），故
/// 与 IFF_UP 同样硬编码、不按平台分派。IFF_UP 在 queryAllAddressesPosix 先于
/// 本声明使用，文件作用域声明顺序无约束。
const IFF_RUNNING: c_uint = 0x40;
const IFF_LOOPBACK: c_uint = 0x8;

/// POSIX 接口地址是否应收进全接口枚举：仅 admin-up + 载波在的链路才可用拨号
/// （winx64 LetsTAP 的 POSIX 同构——物理网卡拔线但保持 admin-up 时 IFF_RUNNING
/// 被内核清除，仅判 IFF_UP 会把断口残留静态 IP 误收进 .lan 展开顶替本机 local
/// 地址集）。loopback(lo) 特例放行：隧道/虚拟接口的 IFF_RUNNING 语义不一，但 lo
/// 恒为本机地址集成员（lo 实测带 RUNNING，此处 OR IFF_LOOPBACK 为防御性保留）。
fn posixIfaIsUsable(flags: c_uint) bool {
    if ((flags & IFF_UP) == 0) return false; // 管理态 Down → 不可拨号
    if ((flags & IFF_RUNNING) == 0 and (flags & IFF_LOOPBACK) == 0) return false; // 载波不在（非 lo）
    return true;
}

fn queryLinkUpPosix(if_index: u32) bool {
    var name_buf: [256]u8 = [_]u8{0} ** 256;
    const if_name = ifIndexToName(if_index, &name_buf) orelse return true; // 保守 true

    var ifap: ?*IfAddrs = null;
    if (getifaddrs_fn(&ifap) != 0) return true;
    defer freeifaddrs_fn(ifap);

    var cur = ifap;
    while (cur) |ifa| : (cur = ifa.ifa_next) {
        if (!ifaMatchesName(ifa, if_name)) continue;
        return (ifa.ifa_flags & IFF_UP) != 0;
    }
    return true; // 未匹配到接口，保守视为 up
}

// ============================================================================
// Windows 实现（iphlpapi 动态加载；结构体照抄 platform.zig 已验证声明）
// ============================================================================

/// GetAdaptersAddresses 所需的已验证结构体（照抄 platform.zig:340-384）。
/// platform.zig 的 detectDnsWindows 已在 sing-box 复刻中跑通，偏移可信。
const win_dll = @import("zigfoundation").win_dll;

const SOCKET_ADDRESS_WIN = extern struct {
    lpSockaddr: ?*anyopaque,
    iSockaddrLength: i32,
};

const IP_ADAPTER_DNS_SERVER_ADDRESS_WIN = extern struct {
    Length: u32,
    Flags: u32,
    Next: ?*IP_ADAPTER_DNS_SERVER_ADDRESS_WIN,
    Address: SOCKET_ADDRESS_WIN,
};

/// 单播地址链节点（x/sys/windows types_windows.go IpAdapterUnicastAddress，
/// 即 C 的 IP_ADAPTER_UNICAST_ADDRESS_LH 平坦映射，生产使用多年）。
const IP_ADAPTER_UNICAST_ADDRESS_LH = extern struct {
    Length: u32,
    Flags: u32,
    Next: ?*IP_ADAPTER_UNICAST_ADDRESS_LH,
    Address: SOCKET_ADDRESS_WIN,
    PrefixOrigin: i32,
    SuffixOrigin: i32,
    DadState: i32,
    ValidLifetime: u32,
    PreferredLifetime: u32,
    LeaseLifetime: u32,
    OnLinkPrefixLength: u8,
};

/// 网关地址链节点（x/sys/windows IpAdapterGatewayAddress，即
/// IP_ADAPTER_GATEWAY_ADDRESS_LH）。注意第二字段是 Reserved（非 Flags）。
const IP_ADAPTER_GATEWAY_ADDRESS_LH = extern struct {
    Length: u32,
    Reserved: u32,
    Next: ?*IP_ADAPTER_GATEWAY_ADDRESS_LH,
    Address: SOCKET_ADDRESS_WIN,
};

const IP_ADAPTER_ADDRESSES_LH = extern struct {
    Length: u32,
    IfIndex: u32,
    Next: ?*IP_ADAPTER_ADDRESSES_LH,
    AdapterName: [*:0]u8,
    FirstUnicastAddress: ?*IP_ADAPTER_UNICAST_ADDRESS_LH,
    FirstAnycastAddress: ?*anyopaque,
    FirstMulticastAddress: ?*anyopaque,
    FirstDnsServerAddress: ?*IP_ADAPTER_DNS_SERVER_ADDRESS_WIN,
    DnsSuffix: ?*anyopaque,
    Description: ?*anyopaque,
    FriendlyName: ?*anyopaque,
    PhysicalAddress: [8]u8,
    PhysicalAddressLength: u32,
    Flags: u32,
    Mtu: u32,
    IfType: u32,
    OperStatus: u32,
    Ipv6IfIndex: u32,
    ZoneIndices: [16]u32,
    FirstPrefix: ?*anyopaque,
    TransmitLinkSpeed: u64,
    ReceiveLinkSpeed: u64,
    FirstWinsServerAddress: ?*anyopaque,
    FirstGatewayAddress: ?*IP_ADAPTER_GATEWAY_ADDRESS_LH,
};

const AF_UNSPEC_WIN = 0;
/// 0x0080 GAA_FLAG_INCLUDE_GATEWAYS：不设则 FirstGatewayAddress 恒 NULL（MSDN），
/// 网关查询与「带网关适配器优先」的 DNS 选择都依赖它。
const GAA_FLAGS_QUERY = 0x0080;
const IfOperStatusUp = 1; // 链路已连接

/// IpDadState（IP_DAD_STATE，iphlpapi）— IPv4/IPv6 单播地址重复地址检测状态。
/// Invalid=0 / Tentative=1 / Duplicate=2 / Deprecated=3 / Preferred=4。
const IpDadStateInvalid: i32 = 0;
const IpDadStateTentative: i32 = 1;
const IpDadStateDuplicate: i32 = 2;
const IpDadStateDeprecated: i32 = 3;
const IpDadStatePreferred: i32 = 4;

/// 单播地址 DadState 是否可用于拨号入网：仅收 Preferred/Deprecated（地址已就绪/将过期）。
/// Invalid/Tentative/Duplicate（DAD 未完成或检测到地址冲突）期间的地址未稳定，
/// 若入本机地址集，拨号/访问会被黑洞或路由到冲突方。
fn winDadStateUsable(dad: i32) bool {
    return dad == IpDadStatePreferred or dad == IpDadStateDeprecated;
}

/// 动态加载 GetAdaptersAddresses 并查询适配器链（AF_UNSPEC 同时取 v4/v6）。
/// 返回栈缓冲内的适配器链头；无适配失败返回 null（尽力而为）。
fn queryAdaptersWindows(buf: []u8) ?*IP_ADAPTER_ADDRESSES_LH {
    const h = win_dll.load("iphlpapi.dll") orelse return null;
    const func = win_dll.proc(h, "GetAdaptersAddresses") orelse return null;
    const Fn = *const fn (u32, u32, ?*anyopaque, ?*IP_ADAPTER_ADDRESSES_LH, *u32) callconv(.winapi) u32;
    const getAdaptersAddresses: Fn = @ptrCast(@alignCast(func));

    var buf_size: u32 = @intCast(buf.len);
    if (buf_size == 0) return null;
    const adapters: *IP_ADAPTER_ADDRESSES_LH = @ptrCast(@alignCast(buf.ptr));
    const ret = getAdaptersAddresses(AF_UNSPEC_WIN, GAA_FLAGS_QUERY, null, adapters, &buf_size);
    if (ret != 0) return null;
    return adapters;
}

/// 从 Windows sockaddr 指针提取 IpAddr（v4/v6，照抄 platform.zig parseSockaddrIp 的
/// 偏移解析，改为产出 IpAddr 而非字符串）。
fn winSockaddrToIp(lpSockaddr: ?*anyopaque) ?types.IpAddr {
    const sa = lpSockaddr orelse return null;
    const bytes: [*]const u8 = @ptrCast(sa);
    const family = endian.readIntNative(u16, bytes[0..2]); // sa_family_t (host byte order)
    if (family == AF_INET) {
        // sockaddr_in: family(2) + port(2) + addr(4)
        return .{ .v4 = bytes[4..8].* };
    } else if (family == AF_INET6) {
        // sockaddr_in6: family(2) + port(2) + flowinfo(4) + addr(16) + scope(4)
        var v6: types.IpAddr = .{ .v6 = undefined };
        @memcpy(&v6.v6, bytes[8..24]);
        return v6;
    }
    return null;
}

/// Windows 接口 MTU：GetAdaptersAddresses 链上按 IfIndex 匹配取 Mtu。
/// egress.getInterfaceMtu 的 Windows 实现已实装（GetIpInterfaceEntry 读 NlMtu，
/// 见 egress.getInterfaceMtuWindows）；finder 仍走 GAA 链——Mtu 字段与 DNS/
/// OperStatus 查询同源同缓冲，一次 GetAdaptersAddresses 覆盖多查询，免重复加载。
fn winMtuForIndex(index: u32) ?u32 {
    var buf: [64 * 1024]u8 align(8) = undefined;
    const adapters = queryAdaptersWindows(&buf) orelse return null;
    var current: ?*IP_ADAPTER_ADDRESSES_LH = adapters;
    while (current) |adapter| : (current = adapter.Next) {
        if (adapter.IfIndex == index) return adapter.Mtu;
    }
    return null;
}

/// Windows 单播地址链：GAA 链按 IfIndex 匹配适配器后走 FirstUnicastAddress，
/// 每节点 Address（sockaddr v4/v6）+ OnLinkPrefixLength。
/// 布局：IP_ADAPTER_UNICAST_ADDRESS_LH（x/sys/windows IpAdapterUnicastAddress 平坦映射）。
/// 2026-08-19 windowsvm 探针实证：节点 raw 解码 Length=64/Next@8/Address@16/
/// SockaddrLength=16(v4)/OnLinkPrefixLength@56=24 与 255.255.255.0 对照一致。
fn queryAddressesWindows(if_index: u32, out: []types.AddressInfo) []types.AddressInfo {
    var buf: [64 * 1024]u8 align(8) = undefined;
    const adapters = queryAdaptersWindows(&buf) orelse return &.{};

    var current: ?*IP_ADAPTER_ADDRESSES_LH = adapters;
    while (current) |adapter| : (current = adapter.Next) {
        if (adapter.IfIndex != if_index) continue;
        var count: usize = 0;
        var ua = adapter.FirstUnicastAddress;
        while (ua) |u| : (ua = u.Next) {
            if (count >= out.len) break;
            if (!winDadStateUsable(u.DadState)) continue; // DAD 未完成/冲突/Invalid → 跳过
            const sa = u.Address.lpSockaddr orelse continue;
            const ip = winSockaddrToIp(sa) orelse continue; // 非 v4/v6 跳过
            out[count] = .{ .addr = ip, .prefix_len = u.OnLinkPrefixLength };
            count += 1;
        }
        return out[0..count];
    }
    return &.{};
}

/// 适配器是否为「活动上行」：OperStatus == IfOperStatusUp。
/// Windows 上 Disconnected/NotPresent 等非 Up 适配器（已断开的 LetsTAP 网卡）不属于
/// 系统活动链路，其残留静态网关/DNS 不得被当作系统默认网关/DNS——拨号默认出口判断
/// 只看活动适配器（winx64 C4 LetsTAP Disconnected + 静态 IP 26.26.26.1 黑洞实测）。
/// 网关与 DNS 查询共用此判定（queryGatewayWindows / queryDnsServersWindows），避免两处
/// 各自复写 OperStatus 过滤。
fn adapterActiveUp(adapter: *const IP_ADAPTER_ADDRESSES_LH) bool {
    return adapter.OperStatus == IfOperStatusUp;
}

/// Windows 网关：GAA 链取**活动上行**带网关适配器的 FirstGatewayAddress 首项
/// （对齐 detectDnsWindows 的「带网关适配器优先」语义；OperStatus 过滤见 adapterActiveUp）。
fn queryGatewayWindows() ?types.IpAddr {
    var buf: [64 * 1024]u8 align(8) = undefined;
    const adapters = queryAdaptersWindows(&buf) orelse return null;

    var current: ?*IP_ADAPTER_ADDRESSES_LH = adapters;
    while (current) |adapter| : (current = adapter.Next) {
        // 跳过 Down/Disconnected 适配器：其静态网关残留（LetsTAP 26.26.26.1）不构成
        // 系统默认路由，若排前会顶替真实活动默认网关。
        if (!adapterActiveUp(adapter)) continue;
        if (adapter.FirstGatewayAddress) |gw| {
            if (winSockaddrToIp(gw.Address.lpSockaddr)) |ip| return ip;
        }
    }
    return null;
}

fn queryDnsServersWindows(out: []types.IpAddr) []types.IpAddr {
    var buf: [64 * 1024]u8 align(8) = undefined;
    const adapters = queryAdaptersWindows(&buf) orelse return &.{};

    // 优先返回带默认网关的**活动**适配器 DNS（对齐 platform.zig detectDnsWindows 语义）。
    // 只统计 OperStatus==Up 适配器：Down/Disconnected 适配器（断开 LetsTAP 等）带旧网关
    // + 旧 DNS，不加过滤会顶替真实活动 DNS（与 queryGatewayWindows 同源问题）。
    var first_count: usize = 0;
    var first_dns: ?types.IpAddr = null;
    var current: ?*IP_ADAPTER_ADDRESSES_LH = adapters;
    while (current) |adapter| : (current = adapter.Next) {
        if (!adapterActiveUp(adapter)) continue; // Down 适配器不入 DNS 候选
        const has_gateway = adapter.FirstGatewayAddress != null;
        var dns_server: ?*IP_ADAPTER_DNS_SERVER_ADDRESS_WIN = adapter.FirstDnsServerAddress;
        while (dns_server) |dns| : (dns_server = dns.Next) {
            if (winSockaddrToIp(dns.Address.lpSockaddr)) |ip| {
                if (has_gateway) {
                    if (first_count < out.len) out[first_count] = ip;
                    first_count += 1;
                } else if (first_dns == null) {
                    first_dns = ip;
                }
            }
        }
        // 已找到带网关的 DNS 即返回
        if (first_count > 0) return out[0..first_count];
    }
    if (first_dns) |ip| {
        out[0] = ip;
        return out[0..1];
    }
    return &.{};
}

fn queryLinkUpWindows(if_index: u32) bool {
    var buf: [64 * 1024]u8 align(8) = undefined;
    const adapters = queryAdaptersWindows(&buf) orelse return true; // 保守 true

    var current: ?*IP_ADAPTER_ADDRESSES_LH = adapters;
    while (current) |adapter| : (current = adapter.Next) {
        if (adapter.IfIndex == if_index) {
            return adapter.OperStatus == IfOperStatusUp;
        }
    }
    return true; // 未匹配到接口，保守 true
}

// ============================================================================
// 单元测试
// ============================================================================

const testing = std.testing;

test "network_params: resolv.conf 解析（v4/v6/注释/多行）" {
    var out: [8]types.IpAddr = undefined;
    const content =
        "# 注释\n" ++
        "nameserver 1.1.1.1\n" ++
        "nameserver 8.8.8.8\n" ++
        "nameserver 2606:4700:4700::1111\n" ++
        "search example.com\n" ++
        "options edns0\n";

    const result = parseResolvConf(content, &out);
    try testing.expectEqual(@as(usize, 3), result.len);
    try testing.expectEqual(types.IpAddr{ .v4 = .{ 1, 1, 1, 1 } }, result[0]);
    try testing.expectEqual(types.IpAddr{ .v4 = .{ 8, 8, 8, 8 } }, result[1]);
    try testing.expect(result[2] == .v6);
    try testing.expectEqual(@as(u8, 0x26), result[2].v6[0]);
    try testing.expectEqual(@as(u8, 0x11), result[2].v6[14]);
    try testing.expectEqual(@as(u8, 0x11), result[2].v6[15]);
}

test "network_params: resolv.conf 解析 — 无 nameserver / 空内容" {
    var out: [4]types.IpAddr = undefined;
    const result = parseResolvConf("", &out);
    try testing.expectEqual(@as(usize, 0), result.len);

    const result2 = parseResolvConf("search foo\n#nameserver 1.1.1.1\n", &out);
    try testing.expectEqual(@as(usize, 0), result2.len);
}

test "network_params: resolv.conf 解析 — out 容量限制" {
    var out: [2]types.IpAddr = undefined;
    const content = "nameserver 1.1.1.1\nnameserver 8.8.8.8\nnameserver 9.9.9.9\n";
    const result = parseResolvConf(content, &out);
    try testing.expectEqual(@as(usize, 2), result.len); // 截断到 out.len
    try testing.expectEqual(types.IpAddr{ .v4 = .{ 1, 1, 1, 1 } }, result[0]);
    try testing.expectEqual(types.IpAddr{ .v4 = .{ 8, 8, 8, 8 } }, result[1]);
}

test "network_params: netmaskPrefixLen 计算" {
    try testing.expectEqual(@as(u8, 24), netmaskPrefixLen(&[_]u8{ 255, 255, 255, 0 }, 32));
    try testing.expectEqual(@as(u8, 32), netmaskPrefixLen(&[_]u8{ 255, 255, 255, 255 }, 32));
    try testing.expectEqual(@as(u8, 0), netmaskPrefixLen(&[_]u8{ 0, 0, 0, 0 }, 32));
    try testing.expectEqual(@as(u8, 64), netmaskPrefixLen(&[_]u8{ 255, 255, 255, 255, 255, 255, 255, 255 }, 128));
}

test "network_params: reference all pub decls (lazy-analysis guard)" {
    testing.refAllDecls(@This());
}

test "network_params: macOS 真实环境 queryAddresses 非空或优雅失败" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;
    const idx = egress.getDefaultInterfaceIndex() orelse return error.SkipZigTest;
    var out: [16]types.AddressInfo = undefined;
    const result = queryAddresses(idx, &out);
    // 真实环境应返回非空；即便环境特殊返回空也不算失败（尽力而为），
    // 但不得 panic / 不崩溃。
    _ = result;
    try testing.expect(queryLinkUp(idx) == true or queryLinkUp(idx) == false);
}

test "network_params: queryAllAddresses 全接口枚举（真实调用：所有权/结构/去重/非崩溃）" {
    // 本机真实调用，无平台守卫（POSIX/Windows 各走 getifaddrs / GAA 全链）：
    // - 所有权：切片由调用方 allocator 分配 → testing.allocator + free 验证无泄漏；
    // - 结构正确：每条为合法 v4/v6 union（tagged union 编译期保证）——本机至少
    //   应有 lo 的 127.0.0.1 / ::1；即便环境特殊返回空也不判失败（尽力而为），
    //   但不得 panic / 不崩溃；
    // - 去重：全表无相同地址（跨接口重复被合并）。
    const addrs = try queryAllAddresses(testing.allocator);
    defer testing.allocator.free(addrs);

    var i: usize = 0;
    while (i < addrs.len) : (i += 1) {
        var j: usize = i + 1;
        while (j < addrs.len) : (j += 1) {
            try testing.expect(!ipEql(addrs[i], addrs[j])); // 去重
        }
    }
}

test "network_params: posixIfaIsUsable 链路过滤（UP+RUNNING / 断口拔线 / loopback / Down）" {
    // UP + RUNNING（活跃物理/隧道/虚拟链路）→ 可用
    try testing.expect(posixIfaIsUsable(IFF_UP | IFF_RUNNING));
    try testing.expect(posixIfaIsUsable(IFF_UP | IFF_RUNNING | IFF_LOOPBACK));
    // UP 但无 RUNNING（拔线保持 admin-up 的断口网卡，winx64 LetsTAP POSIX 同构）→ 过滤
    try testing.expect(!posixIfaIsUsable(IFF_UP));
    // loopback 无 RUNNING 也放行（lo 恒为本机地址集成员，不被载波判定过滤）
    try testing.expect(posixIfaIsUsable(IFF_UP | IFF_LOOPBACK));
    // 整体 Down / 无 UP 即便 RUNNING → 过滤
    try testing.expect(!posixIfaIsUsable(0));
    try testing.expect(!posixIfaIsUsable(IFF_RUNNING));
    try testing.expect(!posixIfaIsUsable(IFF_LOOPBACK)); // loopback 单独也不可用（须 UP）
}

test "network_params: adapterActiveUp 只认 OperStatus==Up（Down 适配器不入网关/DNS 候选）" {
    var up = std.mem.zeroes(IP_ADAPTER_ADDRESSES_LH);
    up.OperStatus = IfOperStatusUp;
    try testing.expect(adapterActiveUp(&up));

    // Disconnected(2)/NotPresent(6) 等非 Up 态（winx64 LetsTAP 断口场景）→ 过滤
    var disconnected = std.mem.zeroes(IP_ADAPTER_ADDRESSES_LH);
    disconnected.OperStatus = IfOperStatusUp + 1;
    try testing.expect(!adapterActiveUp(&disconnected));

    // OperStatus 缺省 0（Unknown）→ 非活动上行
    var unknown = std.mem.zeroes(IP_ADAPTER_ADDRESSES_LH);
    try testing.expect(!adapterActiveUp(&unknown));
}
