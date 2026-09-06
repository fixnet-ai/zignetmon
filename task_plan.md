# Task Plan: zignetmon — 网络变化监测与自适应库

## Goal

生产级网络变化监测与自适应库：覆盖「路由 / 系统 DNS / 任意网卡 / 系统代理 / hosts 文件」五类关键网络设置变化（桌面
三 OS 全量；iOS / Android 以粗信号 + 注入承载，能力矩阵见 `design.md` §3），消费方（zigbox 等）
`@import("zignetmon")` 集成后，网络环境变化时服务重新自适应不断线。

## 阶段

| # | 阶段 | 内容 | 状态 |
|---|------|------|:---:|
| P0 | 项目骨架 | git init + build.zig + build.zig.zon + mod.zig stub + 文档 | ✅ 2026-09-07 |
| P1 | 提取 zf 模块 | 12 文件（network + system_proxy）→ zignetmon + import 适配 + 独立构建单测绿 | ✅ 2026-09-07 |
| P2 | 五类扩展（v2 简化：粗信号） | hosts 监测 + 系统代理变化监测 + 统一门面 diff；**v2 收敛为「网络变了」粗信号**（`ChangeKind` 六值降内部 trace 诊断，不进消费方契约）+ `Monitor.injectPlatformInfo` 注入入口 | ✅ 2026-09-07 |
| P3 | 测试与验收（补三层测试） | Tier1 注入单测全绿(61/61) + **Tier2 VM 真事件 harness/驱动脚本** + **Tier3 移动注入** + zigtester.yaml + ZF_NETWORK_TRACE + API/README/CLAUDE 三层文档 + **`dns_monitor` 独立 DNS 监测（本补丁：DNS 独立事件源补门面-diff 附带覆盖）** | ✅ 2026-09-07 |
| P4 | 切接 zf（后续） | zf 移除 network/system_proxy + 消费方改 @import("zignetmon")（独立阶段） | ⬜ |

## 遗留（不阻塞，后续 track）

1. **iOS/Android no-op 语义（Tier3）**：hosts/proxy 移动 no-op 已由注入单测锁定；真实设备 E2E 为集成级、远期再说。
2. **P4 切接**：zf 移除 network/system_proxy，消费方改 `@import("zignetmon")`（后续独立阶段，先自身质量完备）。

## VM 真机验证（2026-09-07，已闭环）

三 VM 真事件验证**全部 PASS**，暴露并修复 2 个真实 bug（真机才触发的低概率边界）：

| VM | 结果 | 子项 |
|----|------|------|
| macvm | 2/2 PASS | route（非默认路由 0 伪信号，正确）+ hosts（1 信号） |
| linuxvm | 3/3 PASS | route（0 伪信号）+ resolv DNS（1 信号，dns_monitor）+ hosts（1 信号） |
| windowsvm | FINAL PASS | route INFO（0，正确）+ hosts（1）+ proxy（2，proxy_monitor） |

**修复的 2 个 bug（commit `ffd78f8`）**：
1. **hosts 误报**（linuxvm 暴露）：linuxvm 的 utm-monitor 守护进程每 ~30s 对 `/etc/hosts` 做**内容字节不变、仅 mtime bump** 的保活重写，原 hosts_monitor 纯 stat-diff（mtime/size）把它误判为「hosts 变化」→ 门面误发「网络变了」。修复 = 「stat 预筛 + 内容字节 diff 确认」，仅真内容变化才 emit（读失败 fail-open 宁多报不漏报）。
2. **proxy 漏报 + 门面盲去抖**（windowsvm 暴露）：① proxy_monitor_windows 原单次 RegNotifyChangeKeyValue + INFINITE 等待，事件丢失即永久漏报；修复 = 有界 1s 等待 + 周期重读 diff 兜底 + 递归子树。② 门面 `Monitor.dispatch()` 原盲 1s 合并去抖把「hosts restore（<1s 前）→ proxy set（紧随）」的独立真实事件误吞；修复 = 合并收窄到「仅 network/dns 这一对连通性重叠源」，hosts/proxy 作为独立去重源**必达**不参与合并。

真机验证结论：`hosts_monitor`（三平台）、`dns_monitor`（linux resolv）、`proxy_monitor`（windows 注册表）真实事件均正确触发；非默认路由增删正确不产生伪信号（默认出口未变）。

## 当前状态（2026-09-07）

- **P0 骨架 ✅** / **P1 提取 ✅**（提取面 12 文件 + import 适配，独立构建单测绿）。
- **P2 v2 简化 ✅**：门面从「5 类语义事件（ChangeKind 回调）」收敛为 **「网络变了」粗回调**
  `Callback(Snapshot)`；`ChangeKind` 移出 mod 顶层导出、降为内部 trace 诊断；新增
  `Monitor.injectPlatformInfo`（移动 iOS NE / Android 桥 + 测试注入，走真实事件同 diff/dispatch 路径）。
- **P3 三层测试 ✅**：`zig build test` 61/61（含注入路径 + dns_monitor 独立变化）+ `zig fmt` 干净 + zigtester.yaml（unit/all-tests）
  + API/README/CLAUDE 三层测试文档；Tier2 真事件 harness + 三平台驱动脚本落地 `tests/`（挂 vm-regression 白名单）。
- **dns_monitor 独立 DNS 监测 ✅（本补丁）**：`src/dns_monitor*.zig`（macOS SCDynamicStore「Global/DNS」/
  Windows 注册表 Tcpip Parameters RegNotify / Linux inotify resolv.conf + mtime 兜底 / iOS no-op / Android stub）+ mod
  门面第 4 子监测（handleDns 覆盖快照 `dns_servers` 新鲜值，门面 1s 去抖合并收敛）。
- **Tier2 VM 真机验证 ✅（09-07 闭环）**：macvm/linuxvm/windowsvm 三台真事件全 PASS，暴露并修复 2 个真机 bug（hosts 内容 diff + proxy 自愈/门面去抖收窄），见「VM 真机验证」段。
- **下一步 = P4 切接（后续独立阶段）**：zf 移除 network/system_proxy，消费方改 `@import("zignetmon")`。

## 关键决策（已定，design.md §7 v2）

1. **API 形态**：统一 `Monitor` 门面 = 订阅「网络变了」粗回调（带快照）+ 主动 `snapshot()` + `injectPlatformInfo`。
2. **ChangeKind**：内部诊断（trace），不进消费方契约。
3. **平台模型**：桌面五类 / 移动粗信号 + 注入；hosts/proxy 桌面专属。
4. **测试分层**：Tier1 单元注入（host）/ Tier2 VM 真事件（3 VM）/ Tier3 移动注入（host）。
5. **切接（P4）**：待自身质量 + 测试完备后，单独出方案再动（不提前做）。

## 提取面（design.md §2）

12 文件：network.zig / network_types.zig / network_params.zig / network_{darwin,linux,windows}.zig / system_proxy{,_common,_darwin,_linux,_windows,_stub}.zig。import 适配规则见 design.md §2。

## 依赖

- Zig 0.16.0
- zigfoundation（唯一实现源：net/endian/platform/alloc/log）
