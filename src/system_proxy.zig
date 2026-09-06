//! system_proxy — 宿主系统代理副作用（set_system_proxy 底层原语，#79）
//!
//! 无状态原语：setProxy（设置）/ restoreProxy（恢复）。平台实现经 comptime 分派。
//! 应用层（zigbox）负责编排（何时设置/恢复 + 代际守卫），本模块不持有状态。
//!
//! 语义（用户拍板 2026-08-23）：
//!   - setProxy 失败返回 error.EnableFailed，diag 累积「系统原始错误信息」
//!     （命令 stderr / 退出码 / GetLastError），应用层打印日志、继续运行（best-effort）。
//!   - restoreProxy 恒 best-effort：失败仅 warn，不返回错误。
//!   - 三平台 = 系统代理（networksetup / wininet / gsettings|kwriteconfig）+ 环境变量注入
//!     （shell rc / setx），no_proxy 含 127.0.0.1 防回环（全平台必设）。
//!
//! 分层：主文件（本文件）仅 comptime 分派 + 对外入口；共享纯函数在
//! system_proxy_common.zig；平台实现 system_proxy_{darwin,linux,windows,stub}.zig。

const std = @import("std");
const builtin = @import("builtin");
const common = @import("system_proxy_common.zig");

pub const ProxyError = common.ProxyError;
pub const Diag = common.Diag;

/// 平台实现（comptime 分派；各文件提供统一形状的 setProxy/restoreProxy）。
pub const impl = switch (builtin.os.tag) {
    .macos, .ios => @import("system_proxy_darwin.zig"),
    .linux => if (builtin.abi == .android)
        @import("system_proxy_stub.zig")
    else
        @import("system_proxy_linux.zig"),
    .windows => @import("system_proxy_windows.zig"),
    else => @import("system_proxy_stub.zig"),
};

/// 地址归一化（re-export，zigbox 编排层沿用）。
pub const normalizeProxyHost = common.normalizeProxyHost;

/// 设置系统代理（系统代理 + 环境变量注入）。失败返回 error.EnableFailed，
/// diag 累积系统原始错误信息。host 须为具体可拨地址（unspecified 先 normalizeProxyHost）。
pub fn setProxy(
    allocator: std.mem.Allocator,
    host: []const u8,
    port: u16,
    support_socks: bool,
    diag: *Diag,
) ProxyError!void {
    return impl.setProxy(allocator, host, port, support_socks, diag);
}

/// 恢复系统代理（best-effort，失败仅 warn 不返回错误）。
pub fn restoreProxy(allocator: std.mem.Allocator, support_socks: bool) void {
    impl.restoreProxy(allocator, support_socks);
}

test {
    _ = @import("system_proxy_common.zig");
    _ = impl; // 触发平台 @import，使平台测试注册（懒分析守卫：impl 仅被 setProxy 引用，不在此引用则平台文件零 Sema）
}
