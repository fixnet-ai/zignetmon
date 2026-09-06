//! system_proxy_stub — 不支持平台（Android / 其他）的 no-op 实现（#79）
//!
//! 移动端（Android）系统代理能力未启动，setProxy/restoreProxy 均 no-op。

const std = @import("std");
const common = @import("system_proxy_common.zig");

const ProxyError = common.ProxyError;

pub fn setProxy(
    allocator: std.mem.Allocator,
    host: []const u8,
    port: u16,
    support_socks: bool,
    diag: *common.Diag,
) ProxyError!void {
    _ = allocator;
    _ = host;
    _ = port;
    _ = support_socks;
    _ = diag;
    // no-op
}

pub fn restoreProxy(allocator: std.mem.Allocator, support_socks: bool) void {
    _ = allocator;
    _ = support_socks;
    // no-op
}
