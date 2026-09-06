//! 系统 DNS 变化监测 — stub 后端（未知平台 / Android 等移动端）。
//!
//! 恒 no-op：移动端（Android 受限桥 / iOS NE 之外无 SCDynamicStore）系统 DNS 无单一
//! 本进程可 watch 的权威来源，且受限环境的 DNS 由上层 `injectPlatformInfo` 注入承载
//! （design.md §3/§5）。start 不建任何线程，snapshot 恒返回 null。

const std = @import("std");
const builtin = @import("builtin");
const dm = @import("dns_monitor.zig");

const DnsSettings = dm.DnsSettings;
const Callback = dm.Callback;

/// 系统 DNS 变化监测器（stub：恒 no-op）。
pub const Impl = struct {
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) !Impl {
        _ = builtin; // 显式引用：该文件仅 stub 平台编译
        return .{ .allocator = allocator };
    }

    /// no-op：不建后台线程。
    pub fn start(self: *Impl) !void {
        _ = self;
        std.log.debug("[dns] monitor unsupported on this platform (no-op)", .{});
    }

    /// no-op：订阅直接成功（无事件会产生）。
    pub fn subscribe(self: *Impl, cb: Callback, ctx: ?*anyopaque) !void {
        _ = self;
        _ = cb;
        _ = ctx;
    }

    /// 恒返回 null（无系统 DNS 事件源/读取语义）。
    pub fn snapshot(self: *Impl) ?DnsSettings {
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

test "dns_monitor_stub: 恒 no-op（snapshot null）" {
    var mon = try Impl.init(testing.allocator);
    defer mon.deinit();
    try mon.start();
    try testing.expect(mon.snapshot() == null);
    mon.close();

    // close/deinit 幂等
    mon.close();
}
