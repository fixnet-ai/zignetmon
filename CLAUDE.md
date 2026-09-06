# CLAUDE.md

> 通用规则见用户级 `~/.claude/CLAUDE.md`；Zig 编码经验见 `zig-codegen.md`（→ `../zigfoundation/zig-codegen.md`）。本文件仅含 zignetmon 项目特有信息。

## 项目概述

**zignetmon** 是 fixnet 生态的「网络变化监测与自适应」库，从 zigfoundation 分离出来的独立兄弟项目（同 zigstack 先例）。目标一句话：**当用户的关键网络设置变化时，消费方（zigbox 等）重新适应新的网络环境，服务不断线。**

覆盖五类关键网络设置变化 × 五平台：

| 维度 | macOS | Windows | Linux | iOS | Android |
|------|-------|---------|-------|-----|---------|
| 路由变化 | SCDynamicStore / AF_ROUTE | NotifyRouteChange2 | netlink RTMGRP_* | NWPathMonitor | ConnectivityManager |
| 系统 DNS | SCDynamicStore | 注册表 / WMI | resolv.conf / DBus | — | LinkProperties |
| 任意网卡 | SCDynamicStore | NotifyIpInterfaceChange | netlink RTMGRP_LINK | NWPathMonitor | NetworkCallback |
| 系统代理 | SCDynamicStore | 注册表 Internet Settings | gsettings / DBus | — | — |
| hosts 文件 | kqueue/fs | ReadDirectoryChangesW | inotify | — | — |

> 各平台事件源的技术细节以研究定论为准（见 findings.md「平台事件源清单」+ `/tmp/zignetmon-research/*.md` 六份参考项目研究笔记）。

## 架构层次（三层）

```
① 事件源层（各平台后端）：监听五类事件 → 归一化为 NetworkInfo 快照 diff
② 归一化层（门面）：快照比对 → 只上报「关键维度真的变了」→ 防抖合并
③ 决策层（消费方，本库不实现）：收到变化 → 重测环境 → Session 完整重建
```

## 成功标准

消费方 `@import("zignetmon")` 集成后，任何平台上的关键网络设置变化都能：
1. **被感知**（事件源层不漏报、不误报）；
2. **被归一化**（同类事件去抖合并，只上报真变化）；
3. **可观测**（`ZF_NETWORK_TRACE=1` 时全流程 info 日志可还原一次变化的完整处理链）。

## 唯一实现源原则（核心架构约束）

zigfoundation 是所有底层算法和基础类型的唯一实现源。zignetmon 只做「网络变化监测与归一化」这一层，**不重复实现** net/endian/platform/alloc/log 等基础能力，一律 `@import("zigfoundation")`。新增底层能力先评估是否应沉 zf，而非在本库局部添加。

## 构建命令

```bash
zig build                    # 构建库（ReleaseSafe）
zig build test               # 运行所有单元测试
zig build test -Doptimize=Debug  # 调试内存泄漏
```

## 组件标识

| 标识 | 模块 |
|------|------|
| `[monitor]` | 事件源层：各平台后端（五类事件监测） |
| `[snapshot]` | 归一化层：NetworkInfo 快照 + diff |
| `[trace]` | 可观测：`ZF_NETWORK_TRACE` 全流程日志 |

## 测试方法（重要）

1. **环境变量开关**：`ZF_NETWORK_TRACE=1` → 收到任何网络变化事件时打印整个处理流程的 info 级日志。
2. **被测机脚本自愈**：各平台的网络变化触发脚本 + 日志文件，`nohup` 后台跑，即使 ssh 断开也继续（触发「断网卡」类变化不中断测试）。
3. **zigtester.yaml 验收**：各平台独立测试套件，保障调测验收可重复。

## 参考代码（研究权威，勿重复踩坑）

`../vendor/` 下的参考实现，研究定论见 findings.md：

- **nthlink-os-{windows,android,macos,ios}** — 抗封锁工具，主动健康探测 + 多地址池 failover
- **ProtonVPN-{win-app,android-app,ios-mac-app,gtk-app}** — 生产级 VPN，Kill Switch / 重连 / 状态机
- **sing-box / mihomo / Xray-core** — 协议侧，两层事件源（networkUpdateMonitor + defaultInterfaceMonitor）
