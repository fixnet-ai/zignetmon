//! 系统代理变化监测（分平台，design.md §5.3）。
//!
//! 目标：当用户/代理工具修改「系统代理设置」时，以回调通知上层（并支持主动
//! `snapshot()` 读取当前生效值），供消费方（zigbox 等）重新适应（如：被设为
//! 系统代理的本地端口被清掉/改掉时重建 Session）。
//!
//! 本文件仅做 **comptime 平台分派 + 公共类型**。真正的事件源在平台文件：
//!   - macOS  (proxy_monitor_darwin.zig)：SCDynamicStore 监听
//!     "State:/Network/Global/Proxies"（完整实现 + 真事件，见该文件）；
//!   - iOS    (proxy_monitor_darwin.zig)：SCDynamicStore 不可用，内部恒 no-op；
//!   - Windows(proxy_monitor_windows.zig)：RegNotifyChangeKeyValue 监听
//!     HKCU\...\Internet Settings（源码实现，真事件待 VM 验证，见 TODO）；
//!   - Linux  (proxy_monitor_linux.zig)：inotify ~/.config/dconf/user（尽力而为，
//!     真事件待 VM 验证，见 TODO）；
//!   - 其他/Android(proxy_monitor_stub.zig)：恒 no-op（移动端/未知平台）。
//!
//! ## ProxySettings 语义（全平台一致）
//! 本监测只面向「显式代理服务器」（HTTP/HTTPS/SOCKS 的 host:port）。判定规则：
//!   - `enabled == true` ⇒ 有显式代理已启用且解析出 host（不变量：host != null）；
//!   - 仅 PAC（自动配置脚本 / WPAD）启用时：无法表示为 host:port，
//!     视为 disabled（记 debug 日志），消费方如需感知 PAC 请另行读取；
//!   - `host` 切片为 **monitor 内部缓冲的借用**，仅在「下一次变化 / deinit」前有效，
//!     调用方需持久使用时自行 dup。
//!
//! 线程模型（与 hosts_monitor.zig 同构）：平台 start 各自在后台线程驱动事件源
//! （CFRunLoop / RegNotify / inotify，均为阻塞等待、非忙等），变化 → 重建快照 →
//! 比较去重 → emit 全部订阅者。回调在后台线程触发，应尽快返回。

const std = @import("std");
const builtin = @import("builtin");

/// 系统代理设置快照。`host` 切片指向 monitor 内部缓冲（见文件头语义）。
pub const ProxySettings = struct {
    enabled: bool = false,
    host: ?[]const u8 = null,
    port: u16 = 0,
};

/// 系统代理变化回调：`settings` 指向 monitor 当前快照（仅当下有效）。
pub const Callback = *const fn (settings: *const ProxySettings, ctx: ?*anyopaque) void;

/// 平台实现（comptime 分派）。
///
/// Android 以 linux + android ABI 表示，归 stub（移动端无桌面系统代理语义）；
/// 其余 linux（桌面发行版）走 proxy_monitor_linux；macOS/iOS 走 darwin
/// （iOS 在 darwin 文件内部恒 no-op）；未列平台走 stub。
const Impl = if (builtin.os.tag == .macos or builtin.os.tag == .ios)
    @import("proxy_monitor_darwin.zig").Impl
else if (builtin.os.tag == .windows)
    @import("proxy_monitor_windows.zig").Impl
else if (builtin.os.tag == .linux and builtin.abi != .android)
    @import("proxy_monitor_linux.zig").Impl
else
    @import("proxy_monitor_stub.zig").Impl;

/// 系统代理变化监测器。方法契约见 design.md §5.3：
/// init / start / subscribe / snapshot / close / deinit。
pub const ProxyMonitor = Impl;

// ============================================================
// 单元测试（引用分派面）
// ============================================================

const testing = std.testing;

test "proxy_monitor: 平台分派面可实例化（lifecycle 冒烟）" {
    // 仅验证分派类型存在且 API 形状一致；平台后端真实行为由其自身测试覆盖。
    var mon = try ProxyMonitor.init(testing.allocator);
    defer mon.deinit();
    try mon.start();
    _ = mon.snapshot();
    mon.close();
}
