//! types — 归一化层共享语义类型（design.md §5.1）
//!
//! ChangeKind 是门面（mod.zig）向决策层（消费方，如 zigbox）派发的五类
//! 关键网络设置变化语义事件 + hosts 的六值枚举：
//!   - route          网关（next-hop）变化
//!   - default_route  默认出口接口身份变化（含默认路由出现/消失）
//!   - interface      默认接口属性变化（mtu / 链路 up / 地址列表）
//!   - dns            系统 DNS 服务器列表变化
//!   - proxy          系统代理设置变化
//!   - hosts          hosts 文件内容变化
//!
//! 消费方按 ChangeKind 区分同一 Snapshot 承载的不同事件来源。

const std = @import("std");

/// 六类语义变化事件。
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
