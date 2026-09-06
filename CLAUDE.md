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

## 项目定位：提取 + 扩展（勿从零设计）

zignetmon **不是从零设计**，是「提取 + 扩展」：

- **提取**：`zf.network`（#43，网络门面）+ `zf.system_proxy`（#79，系统代理副作用）已实现并历经
  真机/VM/winx64 验证 → 抽出到本库适配 import 后独立构建。**提取面 12 文件清单 + import 适配规则
  （机械替换表）见 `design.md` §2**（含验收：独立构建单测绿 + 日志前缀保留 `[network]` 防消费方 grep 失效）。
- **扩展**：补齐五类事件中缺失的「hosts 文件」「系统代理变化」监测 + 统一 5 类语义事件门面。
- **切接**：本库成为唯一实现源后，zf 移除 network/system_proxy、消费方改 `@import("zignetmon")` ——
  **切接是后续独立阶段，不在本库内做**。

## 架构层次（三层，权威 = design.md §4）

```
① 事件源层（平台后端）  network_*.zig / hosts_monitor / proxy_monitor_*.zig
        ↓ 裸事件
② 归一化层（门面）     mod.zig：快照比对 → diff → 去抖 → 5 类语义事件
        ↓ ChangeKind + Snapshot
③ 决策层（消费方）     zigbox 等：收到事件 → 重测环境 → Session 重建
```

**五类事件 × 五平台覆盖矩阵（目标态）→ `design.md` §3**；API 契约（固定签名）→ `design.md` §5 + `API.md`。

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
zig build                    # 构建库（ReleaseSafe）
zig build test               # 运行所有单元测试
zig build test -Doptimize=Debug  # 调试内存泄漏
```

## 组件标识

> 日志前缀铁律（design.md §2.3）：**提取自 zf 的门面保留 `[network]` 前缀，禁止改名**（消费方 grep
> 兼容）；新增监测才用 `[hosts]`/`[proxy]`/`[monitor]`。禁止裸 `std.debug.print`，一律 `zf.log` +
> 前缀 + 英文 ASCII。

| 标识 | 模块 | 来源 |
|------|------|------|
| `[network]` | 网络门面（单例 + 回调 + NetworkInfo 快照） | `src/network.zig` 提取自 zf（#43） |
| `[monitor]` | 归一化门面（diff → 6 值 ChangeKind 语义事件分发） | `src/mod.zig` 扩展新增 |
| `[hosts]` | hosts 文件变化监测（后台线程 5s stat diff） | `src/hosts_monitor.zig` 扩展新增 |
| `[proxy]` | 系统代理：变化监测（proxy_monitor_*.zig）+ set/restore 副作用（system_proxy_*.zig） | 扩展 + 提取自 zf（#79） |

## 测试方法（重要）

1. **统一入口 zigtester**（禁止直跑）：`zigtester_list zignetmon` / `zigtester_run zignetmon --level unit`
   （当前仅 `unit/all-tests` = `zig build test`，54/54）。functional 真实事件源（macOS `sudo route` →
   AF_ROUTE）需特权，`zigtester.yaml` functional 层留占位注释，**挂 macvm**，本机不跑。
2. **环境变量开关**：`ZF_NETWORK_TRACE=1` → 收到任何网络变化事件时打印整个处理流程的 info 级日志
   （事件源收到 → diff → 去抖 → 分发），还原一次变化的完整处理链。
3. **被测机脚本自愈**：各平台的网络变化触发脚本 + 日志文件，`nohup` 后台跑，即使 ssh 断开也继续（触发「断网卡」类变化不中断测试）——待 P4 阶段落地。

## 参考代码（研究权威，勿重复踩坑）

`../vendor/` 下的参考实现，研究定论见 findings.md：

- **nthlink-os-{windows,android,macos,ios}** — 抗封锁工具，主动健康探测 + 多地址池 failover
- **ProtonVPN-{win-app,android-app,ios-mac-app,gtk-app}** — 生产级 VPN，Kill Switch / 重连 / 状态机
- **sing-box / mihomo / Xray-core** — 协议侧，两层事件源（networkUpdateMonitor + defaultInterfaceMonitor）
