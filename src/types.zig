//! types — 门面内部诊断语义类型（v2：非消费方契约）
//!
//! ChangeKind 六值枚举保留作**内部诊断**（仅 ZF_NETWORK_TRACE 下日志标出「哪类
//! 字段变了」），**不进消费方回调签名**（design.md §5）：消费方只收「网络变了」
//! 一个粗信号，不区分下面哪类字段变化：
//!   - route          网关（next-hop）变化
//!   - default_route  默认出口接口身份变化（含默认路由出现/消失）
//!   - interface      默认接口属性变化（mtu / 链路 up / 地址列表）
//!   - dns            系统 DNS 服务器列表变化
//!   - proxy          系统代理设置变化
//!   - hosts          hosts 文件内容变化

const std = @import("std");

/// 六类字段级变化（内部诊断，非消费方契约）。
pub const ChangeKind = enum { route, interface, dns, proxy, hosts, default_route };

test "types: ChangeKind 六值枚举齐备" {
    var seen: usize = 0;
    inline for (@typeInfo(ChangeKind).@"enum".fields) |f| {
        if (std.mem.eql(u8, f.name, "route") or
            std.mem.eql(u8, f.name, "interface") or
            std.mem.eql(u8, f.name, "dns") or
            std.mem.eql(u8, f.name, "proxy") or
            std.mem.eql(u8, f.name, "hosts") or
            std.mem.eql(u8, f.name, "default_route")) seen += 1;
    }
    try std.testing.expectEqual(@as(usize, 6), seen);
}
