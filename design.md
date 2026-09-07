# Design v2: zignetmon — 网络变化监测与自适应库

> 目标、背景、研究定论见 `findings.md`；阶段进度见 `task_plan.md`。
> **v2 重设计（2026-09-07）**：据业务真实需求收敛 API——消费方只需「网络变了」一个粗信号，五类事件是**监测覆盖度**（内部），不是消费方契约。

## 1. 核心结论

1. **不是从零设计**：zigfoundation 的网络门面（#43）+ 系统代理（#79）已实现网络变化监测并历经验证；zignetmon = 提取 + 扩展（P4 起网络域唯一实现源归本包）。
2. **v2 简化**：外部 API 收敛为「网络变了」粗信号 + 当前状态快照；六值 `ChangeKind` 降级为内部诊断（trace 日志）。
3. **平台感知**：移动端 ≠ PC。hosts 文件 / 系统代理是桌面专属；移动端只有「路径/网络变化」粗信号 + 注入。
4. **可测试性优先**：三层测试架构（单元注入 / VM 真事件 / 移动注入），先自身质量、后切接。

依赖方向：`zignetmon → zigfoundation`（`zf.net/platform/sync/socket/egress/endian/win_dll/log`）。无反向。

## 2. 提取面（P1，已完成）

12 文件（`network*` + `system_proxy*`）从 zf 提取，import 适配规则见 git log `b8552d0`。此段不变。

## 3. 平台能力矩阵（移动 ≠ PC）

| 能力 | macOS | Windows | Linux | iOS | Android |
|---|---|---|---|---|---|
| 路由/网卡事件源 | AF_ROUTE + SCDynamicStore | NotifyRouteChange2 + IpInterface | netlink | NWPathMonitor / 注入 | netlink / NetworkCallback |
| DNS | SCDynamicStore / resolv.conf | 注册表 / GAA | resolv.conf | 注入 | LinkProperties / 注入 |
| 系统代理监测 | SCDynamicStore(Global/Proxies) | 注册表 notify | dconf inotify | ❌ 无 | ❌ 无（app 级） |
| hosts 文件 | ✅ stat diff | ✅ stat diff | ✅ stat diff | ❌ 无 hosts | ❌ 无 hosts |
| 默认接口判定 | sysctl | GetIPForwardTable2 | /proc/net/route | socket 回退 | /proc/net/route |

> **DNS 行标注（本补丁）**：系统 DNS 的**独立变化**（路由/网卡未变时单独被改）已由新增 `dns_monitor`
> **独立事件源（本补丁）已覆盖**——macOS `SCDynamicStore`「State:/Network/Global/DNS」/ Windows 注册表
> `Tcpip\Parameters\Interfaces` RegNotify / Linux inotify `/etc/resolv.conf`（+ mtime 兜底）；iOS 无
> （SCDynamicStore 沙箱不可用，darwin 内恒 no-op）、Android 归 stub，均由注入承载。此前 DNS 仅靠门面
> 对 network 快照 diff 的附带监测、无独立事件源，本补丁补上。

**关键**：hosts / 系统代理是**桌面专属能力**；移动端无 hosts 文件、无桌面系统代理语义，只有「网络路径/网络变化」粗信号，且 iOS NE / Android 受限环境由上层**注入**网络参数（`injectPlatformInfo`）。当前实现已正确处理（`defaultHostsPath()==""` 移动 no-op、`proxy_monitor_stub` 移动 no-op），本文把它显式化为**平台能力矩阵**，不再用「5×5 全平台」误导。

## 4. 三层架构（不变）

```
① 事件源层（平台后端）  network_*.zig / hosts_monitor / proxy_monitor_*.zig / dns_monitor*.zig
        ↓ 裸事件（各自回调）
② 归一化层（门面）     mod.zig：订阅四子监测（network / hosts / proxy / dns）→ 快照比对 → 去抖去重 → 一个粗信号
        ↓ 回调(snapshot)
③ 决策层（消费方）     zigbox 等：收到「网络变了」→ 重读快照 → 重置自身状态
```

## 5. API 契约 v2（消费方面向，极简）

```zig
// ===== 外部契约（zigbox 等消费方只用这些）=====

/// 网络变化回调：收到即「网络环境已变」，消费方应重置自身依赖网络的状态。
/// snap 为变化后的当前状态快照（借用，仅在下一次变化前有效）。
pub const Callback = *const fn (snap: *const Snapshot, ctx: ?*anyopaque) void;

/// 当前网络状态快照（消费方重置自身状态的依据）。借用语义见文件头。
pub const Snapshot = struct {
    default_interface: ?network.Interface = null,   // 默认出口接口
    gateway: ?zf.net.IpAddr = null,                 // 默认网关
    dns_servers: []const zf.net.IpAddr = &.{},       // 系统 DNS
    proxy: ?proxy_monitor.ProxySettings = null,     // 系统代理（桌面才有）
    hosts_mtime: ?i128 = null,                       // hosts mtime（桌面才有）
};

pub const Opt = struct {
    hosts_path: ?[]const u8 = null,
    excluded_interfaces: []const network.ExcludedInterface = &.{},
    under_network_extension: bool = false,
};

pub const Monitor = struct {
    pub fn init(allocator: std.mem.Allocator, opts: Opt) !Monitor;
    pub fn start(self: *Monitor) !void;                       // 启动全部事件源（幂等）
    pub fn subscribe(self: *Monitor, cb: Callback, ctx: ?*anyopaque) !void;
    pub fn snapshot(self: *Monitor) Snapshot;                 // 主动查询当前状态
    pub fn injectPlatformInfo(self: *Monitor, info: network.PlatformInjectedInfo) void; // 移动/测试注入
    pub fn close(self: *Monitor) void;                        // 停事件源（幂等，可 restart）
    pub fn deinit(self: *Monitor) void;                       // 释放 + 重置 network 单例
};

// 子模块保留导出（高级用法）
pub const network = @import("network.zig");           // 网络门面（路由/网卡/DNS）
pub const system_proxy = @import("system_proxy.zig"); // 系统代理 set/restore 原语
pub const hosts_monitor = @import("hosts_monitor.zig");
pub const proxy_monitor = @import("proxy_monitor.zig");
pub const dns_monitor = @import("dns_monitor.zig"); // 系统 DNS 独立变化监测（第 4 子监测，本补丁）
```

**关键变化（相对 v1）**：
1. **移除 `ChangeKind` 出公开契约**——回调不再携带 `kind`，五类变化都收敛为一个「网络变了」信号。消费方不区分「路由变了还是 DNS 变了」，一律重置。
2. **新增 `injectPlatformInfo`**——既是移动端（iOS NE / Android 桥）的生产入口，也是**测试注入入口**（Tier 1/3 的核心）。
3. **快照仍携带全量状态**——消费方收到信号后直接读 snap 重设自身变量，无需二次 `snapshot()` 调用。

`ChangeKind` 保留在 `types.zig` 作**内部诊断**（`ZF_NETWORK_TRACE=1` 时日志标出「哪类字段变了」），不进消费方回调签名。

## 6. 测试架构 v2（三层，业务需求驱动）

**验收准则（业务需求）**：任一类网络设置变化（路由/网卡/DNS/代理/hosts）→ 消费方**恰好收到一次**「网络变了」回调，且快照承载变化后的新状态。

### Tier 1 — 单元/注入测试（host 本机，确定性，无 OS 事件）

- **注入**：`Monitor.injectPlatformInfo(...)` 走与真实事件完全相同的 diff/dispatch 路径，确定性触发。
- **覆盖**：diff 判定（哪类字段变了→是否触发）、基线语义（首个事件建基线不派发）、去重（相同事件不派发）、去抖、快照借用、生命周期（start/close 幂等 + 重启）。
- **Tier1 dns_monitor 独立变化注入单测（本补丁）**：构造系统 DNS 服务器列表**独立**变化（路由/网卡不变）→ `dns_monitor` 子监测触发、门面 `handleDns` 恰好一次粗回调 + 快照 `dns_servers` 覆盖为新鲜值；含 darwin 启停幂等 / 逐地址去重（ipEqual）/ 真读系统 DNS 快照单测（host 全绿）。
- 平台无关，`zig build test` 全绿（61/61，含注入路径 + dns_monitor 本补丁）。

### Tier 2 — 真实事件源（3 VM，触发真实 OS 事件）

| VM | 触发手段 | 驱动的事件源 |
|---|---|---|
| macvm | `sudo route add/delete`（TEST-NET）· `networksetup -setdnsservers` · `networksetup -setwebproxy` | AF_ROUTE / SCDynamicStore / SCDynamicStore(Proxies) |
| linuxvm | `ip route add/del` · 改 `/etc/resolv.conf` · 改 `/etc/hosts` | netlink / resolv.conf / inotify |
| windowsvm | `netsh interface ipv4 add/delete route` · 注册表 Internet Settings · 改 hosts | NotifyRouteChange2 / RegNotify / ReadDirectoryChangesW |

- **断言**：订阅回调在超时窗口内触发 ≥1 次，且快照反映新状态。
- 脚本放 `tests/scripts/`，nohup 自愈（ssh 断开仍继续，用户裁定）；经 `vm-regression.sh` 白名单套件接入。
- **hosts 真实事件**在桌面三 VM 覆盖；移动端 hosts 不在矩阵内（无此能力）。

### Tier 3 — 移动端（iOS/Android，注入为主，真实设备远期）

- **iOS**：模拟 NE 桥注入 `injectPlatformInfo`（NWPathMonitor 等价信息）→ monitor 触发。
- **Android**：模拟 JNI 桥注入（ConnectivityManager/LinkProperties 等价信息）→ monitor 触发。
- **无真机需求**（单元层覆盖）；真实设备 E2E 是集成级，后续再说。
- **能力边界断言**：移动端 `defaultHostsPath()==""`、`proxy_monitor` 归 stub、hosts/proxy 不产生事件——单测锁定「移动无 hosts/proxy」语义。

## 7. 关键决策（v2 已定）

1. **API 形态**：`Monitor` 门面 = 订阅「网络变了」粗回调（带快照）+ 主动 `snapshot()` + `injectPlatformInfo`。
2. **ChangeKind**：内部诊断（trace），不进消费方契约。
3. **平台模型**：桌面五类 / 移动粗信号+注入；hosts/proxy 桌面专属。
4. **测试分层**：Tier1 单元注入（host）/ Tier2 VM 真事件（3 VM）/ Tier3 移动注入（host）。
5. **切接（P4）**：原定「待自身质量 + 测试完备后，单独出方案再动（不提前做）」——已按此于 09-07 执行闭环（zf 删 12 文件，生态消费方 import 迁本包）。

## 8. 遗留（不阻塞）

- ~~P4 切接~~（zf 删 network/system_proxy + 消费方改 import）✅ 已闭环 09-07——zf 网络监测/查询域整体归本包。
- Tier 2/3 真事件脚本落地（本轮实现）。
