//! 系统代理变化监测 — stub 后端（未知平台 / Android 等移动端）。
//!
//! 恒 no-op：无系统级「桌面代理」语义（Android 网络走 app 层，无单一系统
//! 代理开关；iOS 有 SCDynamicStore 但不可用于普通 app，由 darwin 文件内部
//! 恒 no-op 处理）。start 不建任何线程，snapshot 恒返回 null。

const std = @import("std");
const builtin = @import("builtin");
const pm = @import("proxy_monitor.zig");

const ProxySettings = pm.ProxySettings;
const Callback = pm.Callback;

/// 系统代理变化监测器（stub：恒 no-op）。
pub const Impl = struct {
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) !Impl {
        _ = builtin; // 显式引用：该文件仅 stub 平台编译
        return .{ .allocator = allocator };
    }

    /// no-op：不建后台线程。
    pub fn start(self: *Impl) !void {
        _ = self;
        std.log.debug("[proxy] monitor unsupported on this platform (no-op)", .{});
    }

    /// no-op：订阅直接成功（无事件会产生）。
    pub fn subscribe(self: *Impl, cb: Callback, ctx: ?*anyopaque) !void {
        _ = self;
        _ = cb;
        _ = ctx;
    }

    /// 恒返回 null（无系统代理语义可读）。
    pub fn snapshot(self: *Impl) ?ProxySettings {
        _ = self;
        return null;
    }

    /// no-op（无线程可停）。
    pub fn close(self: *Impl) void {
        _ = self;
    }

    /// 释放资源。
    pub fn deinit(self: *Impl) void {
        _ = self;
    }
};

// ============================================================
// 单元测试
// ============================================================

const testing = std.testing;

test "proxy_monitor_stub: 恒 no-op（snapshot null）" {
    var mon = try Impl.init(testing.allocator);
    defer mon.deinit();
    try mon.start();
    try testing.expect(mon.snapshot() == null);
    mon.close();

    // close/deinit 幂等
    mon.close();
}
