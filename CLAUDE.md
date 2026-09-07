# CLAUDE.md

> 通用规则见用户级 `~/.claude/CLAUDE.md`；Zig 编码经验见 `zig-codegen.md`（→ `../zigfoundation/zig-codegen.md`）。本文件仅含 zignetmon 项目特有信息。

## 项目概述

**zignetmon** 是 fixnet 生态的「网络变化监测与自适应」库，从 zigfoundation 分离出来的独立兄弟项目（同 zigstack 先例）。目标一句话：**当用户的关键网络设置变化时，消费方（zigbox 等）重新适应新的网络环境，服务不断线。**

覆盖五类关键网络设置变化 × 五平台：

| 维度 | macOS | Windows | Linux | iOS | Android |
|------|:---:|:---:|:---:|:---:|:---:|
| 路由变化 | ✓ | ✓ | ✓ | ✓ | ✓ |
| 系统 DNS | ✓ | ✓ | ✓ | — | ✓ |
| 任意网卡（up/down/地址） | ✓ | ✓ | ✓ | ✓ | ✓ |
| 系统代理设置 | ✓ | ✓ | ✓ | — | — |
| hosts 文件 | ✓ | ✓ | ✓ | — | — |

> **覆盖矩阵（目标态，含每平台事件源机制）权威见 `design.md` §3**：hosts 为跨平台 stat diff 轮询
> （非 kqueue/inotify）；macOS/Windows/Linux 系统代理、DNS、路由的后端细节亦以该表为准。
>
> **平台差异（移动 ≠ PC）**：iOS / Android **无 hosts 文件、无桌面系统代理语义**（`proxy_monitor`
> 归 stub、`defaultHostsPath()==""` → hosts 监测 no-op），移动端只有「网络路径 / 网络变化」粗
> 信号，受限环境（iOS NE / Android 桥）由上层 `injectPlatformInfo` **注入**网络参数承载；移动
> 边界由 Tier1/Tier3 注入单测锁定。

## 项目定位：提取 + 扩展（勿从零设计）

zignetmon **不是从零设计**，是「提取 + 扩展」：

- **提取**：zigfoundation 的网络门面（#43）+ 系统代理（#79）已实现并历经
  真机/VM/winx64 验证 → P1 抽出到本库适配 import 后独立构建（**P4 起唯一实现源归本包，zf 已删原 12 文件**）。
  **提取面 12 文件清单 + import 适配规则
  （机械替换表）见 `design.md` §2**（含验收：独立构建单测绿 + 日志前缀保留 `[network]` 防消费方 grep 失效）。
- **扩展（v2 简化）**：补齐五类事件中缺失的「hosts 文件」「系统代理变化」监测 + 统一门面收敛
  为 **「网络变了」粗信号**——`ChangeKind` 六值降为内部 trace 诊断，**不进消费方契约**（design.md §5）。
- **dns_monitor（本补丁）**：补系统 DNS **独立变化**监测（第 4 子监测，独立事件源，分平台
  darwin/windows/linux/stub）——此前 DNS 仅靠门面对 network 快照 diff 的附带监测；详见 `design.md` §3。
- **切接（P4，09-07 已闭环）**：本库现为网络监测/查询域**唯一实现源**——zf 已删原 12 文件（network +
  system_proxy，仅保留 net/egress/endian/platform 等基础件），生态消费方（zigtun/zigoutbounds/zigbox）
  已改 `@import("zignetmon")`（订阅层 v1 纯搬迁，行为零变化；v2 `Monitor` 门面未接入消费方，另立阶段）。

## 架构层次（三层，权威 = design.md §4）

```
① 事件源层（平台后端）  network_*.zig / hosts_monitor / proxy_monitor_*.zig / dns_monitor*.zig
        ↓ 裸事件
② 归一化层（门面）     mod.zig：快照比对 → diff → 去抖去重 → 「网络变了」粗信号
        ↓ 回调(Snapshot)（ChangeKind 仅 ZF_NETWORK_TRACE 内部诊断）
③ 决策层（消费方）     zigbox 等：收到「网络变了」→ 重读快照 → 重置自身状态
```

**平台能力矩阵（桌面五类 / 移动粗信号 + 注入）→ `design.md` §3**；API 契约 v2（粗回调 +
快照 + 注入，固定签名）→ `design.md` §5 + `API.md`。

## 成功标准

消费方 `@import("zignetmon")` 集成后，任何平台上的关键网络设置变化都能：
1. **被感知**（事件源层不漏报、不误报）；
2. **被归一化**（同类事件去抖合并，只上报真变化）；
3. **可观测**（`ZF_NETWORK_TRACE=1` 时全流程 info 日志可还原一次变化的完整处理链）。

## 唯一实现源原则（核心架构约束）

zigfoundation 是所有底层算法和基础类型的唯一实现源。zignetmon 只做「网络变化监测与归一化」这一层，**不重复实现** net/endian/platform/alloc/log 等基础能力，一律 `@import("zigfoundation")`（`zf.net.IpAddr`/`zf.platform`/`zf.sync.Mutex`/`zf.socket`/`zf.egress`/`zf.endian`/`zf.win_dll`/`zf.log`）。新增底层能力先评估是否应沉 zf，而非在本库局部添加。

> ⚠️ **反向依赖禁止**：依赖方向仅 `zignetmon → zigfoundation`。本库是被切接目标，不得反过来被 zf 引用。

## 构建命令

```bash
zig build                    # 构建库（ReleaseSafe）+ 安装 harness（zig-out/bin/real_event）
zig build real_event         # 仅构建 Tier2 真事件订阅 harness（见 tests/real_event_harness.zig）
zig build test               # 运行所有单元测试（61/61，Tier1 注入）
zig build test -Doptimize=Debug  # 调试内存泄漏
```

## 组件标识

> 日志前缀铁律（design.md §2 提取面）：**提取自 zf 的门面保留 `[network]` 前缀，禁止改名**（消费方 grep
> 兼容）；新增监测才用 `[hosts]`/`[proxy]`/`[dns]`/`[monitor]`。禁止裸 `std.debug.print`，一律 `zf.log` +
> 前缀 + 英文 ASCII。

| 标识 | 模块 | 来源 |
|------|------|------|
| `[network]` | 网络门面（单例 + 回调 + NetworkInfo 快照） | `src/network.zig` 提取自 zf（#43） |
| `[monitor]` | 归一化门面（快照 diff → 去抖去重 → 「网络变了」粗信号派发；ChangeKind 六值仅 trace 诊断，不进契约） | `src/mod.zig` 扩展新增 |
| `[hosts]` | hosts 文件变化监测（后台线程 5s stat diff） | `src/hosts_monitor.zig` 扩展新增 |
| `[proxy]` | 系统代理：变化监测（proxy_monitor_*.zig）+ set/restore 副作用（system_proxy_*.zig） | 扩展 + 提取自 zf（#79） |
| `[dns]` | 系统 DNS 独立变化监测（第 4 子监测，本补丁）：macOS SCDynamicStore「State:/Network/Global/DNS」/ Windows 注册表 Tcpip\Parameters\Interfaces RegNotify / Linux inotify /etc/resolv.conf（+ mtime 兜底）；iOS 恒 no-op、Android 归 stub（注入承载） | `src/dns_monitor{,_darwin,_linux,_windows,_stub}.zig` 扩展新增 |
| `[harness]` | Tier2 VM 真事件订阅 harness（zig-out/bin/real_event）：每次粗回调打印一行 `CHANGED iface=… gw=…` 供脚本断言；驱动脚本消息前缀 [linux_real_event]/[real-event]/[harness] | `tests/real_event_harness.zig` + `tests/scripts/*`（测试工具，非生产路径） |

## 测试方法（三层，权威 = design.md §6）

1. **Tier 1 单元 / 注入（host 本机，确定性，无 OS 事件）**：统一入口 zigtester（禁止直跑）：
   `zigtester_list zignetmon` / `zigtester_run zignetmon --level unit`
   （`unit/all-tests` = `zig build test`，61/61）。`Monitor.injectPlatformInfo` 走与真实事件完全
   相同的 diff/dispatch 路径，确定性覆盖 diff 判定 / 基线 / 去重 / 去抖 / 快照借用 / 生命周期。
2. **Tier 2 真实事件源（macvm / linuxvm / windowsvm）**：`zig build real_event` 构建订阅 harness
   （`zig-out/bin/real_event`）→ `tests/scripts/{macos,linux}_real_event.sh` +
   `windows_real_event.ps1` 触发真实 OS 事件（route / DNS / hosts / 代理），断言日志 ≥1 行
   CHANGED。脚本 `nohup` 自愈（ssh 断开仍继续）、平台门禁自 SKIP、经 vm-regression 白名单在对应
   VM 执行；`zigtester.yaml` functional 层留占位注释，**本机不跑**（脚本会临时改系统路由 / hosts /
   resolv，随即恢复）。
3. **Tier 3 移动注入（iOS / Android，无真机）**：模拟 NE / JNI 桥 `injectPlatformInfo` 注入；
   移动「无 hosts / 系统代理」能力边界由 Tier1 单测锁定。
4. **环境变量开关**：`ZF_NETWORK_TRACE=1` → 收到任何网络变化事件时打印整个处理流程的 info 级日志
   （事件源收到 → diff → 去抖 → 分发），还原一次变化的完整处理链。

## 参考代码（研究权威，勿重复踩坑）

`../vendor/` 下的参考实现，研究定论见 findings.md：

- **nthlink-os-{windows,android,macos,ios}** — 抗封锁工具，主动健康探测 + 多地址池 failover
- **ProtonVPN-{win-app,android-app,ios-mac-app,gtk-app}** — 生产级 VPN，Kill Switch / 重连 / 状态机
- **sing-box / mihomo / Xray-core** — 协议侧，两层事件源（networkUpdateMonitor + defaultInterfaceMonitor）
