//! 系统 DNS 变化监测（分平台，design.md §3/§5 第 4 子监测）。
//!
//! 目标：补「系统 DNS 独立变化」缺口——DNS 在路由/网卡未变时单独被改（改 resolv.conf /
//! 系统设置 DNS / 注册表 NameServer），以回调通知上层（并支持主动 `snapshot()` 读取当前
//! 生效值），供消费方（zigbox 等）重新适应（如重建 DNS 上游 / FakeIP 后端）。
//!
//! 本文件仅做 **comptime 平台分派 + 公共类型**。真正的事件源在平台文件：
//!   - macOS  (dns_monitor_darwin.zig)：SCDynamicStore 监听
//!     "State:/Network/Global/DNS"（完整实现 + 真事件，见该文件）；
//!   - iOS    (dns_monitor_darwin.zig)：SCDynamicStore 对沙箱 app 不可用，内部恒 no-op；
//!   - Windows(dns_monitor_windows.zig)：RegNotifyChangeKeyValue 递归监听
//!     HKLM\...\Tcpip\Parameters\Interfaces（源码实现，真事件待 VM 验证，见 TODO）；
//!   - Linux  (dns_monitor_linux.zig)：inotify 监听 /etc/resolv.conf + mtime diff 兜底
//!     （源码实现，真事件待 VM 验证，见 TODO）；
//!   - 其他/Android(dns_monitor_stub.zig)：恒 no-op（移动端 DNS 由上层 injectPlatformInfo 注入）。
//!
//! ## DnsSettings 语义（全平台一致）
//! `servers` 切片为 **monitor 内部缓冲的借用**，仅在「下一次变化 / deinit」前有效，
//! 调用方需持久使用时自行 dup。空列表（无 DNS 服务器 / 读取失败）是合法状态，仍会 emit。
//!
//! ## 读取统一复用 network_params.queryDnsServers（design §5.5 决策）
//! 与门面（network.zig 快照 dns_servers）同源同函数读系统 DNS，保证 diff 判定一致
//! （mac 该函数读 /etc/resolv.conf 尽力而为、非 SCDynamicStore 权威源——既有局限，
//!   与 network 门面一致，见 network_params.zig 文件头 TODO）。
//!
//! ## 线程模型（与 proxy_monitor 同构）
//! 平台 start 各自在后台线程驱动事件源（CFRunLoop / RegNotify / inotify，均为阻塞等待、
//! 非忙等），变化 → 重读 DNS → 比较去重 → emit 全部订阅者。回调在后台线程触发，应尽快返回。
//!
//! ## 去重：变化事件 → refresh 重读 → diff（逐地址 ipEqual）→ 仅真变化 emit。
//! 事件源对同一 DNS 变更可能重复触发（inotify 多 mask / SCDynamicStore 多 key），
//! diff 保证恰好一次 emit（与 mod 门面去重语义一致）。

const std = @import("std");
const builtin = @import("builtin");
const zf = @import("zigfoundation");

/// 系统 DNS 服务器快照。`servers` 切片指向 monitor 内部缓冲（见文件头语义）。
pub const DnsSettings = struct {
    servers: []const zf.net.IpAddr = &.{},
};

/// 系统 DNS 变化回调：`settings` 指向 monitor 当前快照（仅当下有效）。
pub const Callback = *const fn (settings: *const DnsSettings, ctx: ?*anyopaque) void;

/// 平台实现（comptime 分派）。
///
/// Android 以 linux + android ABI 表示，归 stub（移动端 DNS 由上层 injectPlatformInfo
/// 注入，见 design.md §3/§5）；其余 linux（桌面发行版）走 dns_monitor_linux；
/// macOS/iOS 走 darwin（iOS 在 darwin 文件内部恒 no-op）；未列平台走 stub。
const Impl = if (builtin.os.tag == .macos or builtin.os.tag == .ios)
    @import("dns_monitor_darwin.zig").Impl
else if (builtin.os.tag == .windows)
    @import("dns_monitor_windows.zig").Impl
else if (builtin.os.tag == .linux and builtin.abi != .android)
    @import("dns_monitor_linux.zig").Impl
else
    @import("dns_monitor_stub.zig").Impl;

/// 系统 DNS 变化监测器。方法契约（同 proxy_monitor）：
/// init / start / subscribe / snapshot / close / deinit。
pub const DnsMonitor = Impl;

// ============================================================
// 单元测试（引用分派面）
// ============================================================

const testing = std.testing;

test "dns_monitor: 平台分派面可实例化（lifecycle 冒烟）" {
    // 仅验证分派类型存在且 API 形状一致；平台后端真实行为由其自身测试覆盖。
    var mon = try DnsMonitor.init(testing.allocator);
    defer mon.deinit();
    try mon.start();
    _ = mon.snapshot();
    mon.close();
}
