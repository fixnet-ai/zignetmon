# Findings: zignetmon — 网络变化监测与自适应

> 研究权威：`/tmp/zignetmon-research/*.md`（六份参考项目研究笔记，workflow `wcc76ycpr` 产出）。本文件沉淀**可指导设计的定论**。

## 研究综合（6 参考项目关键共识）

| 共识 | 来源 | 设计含义 |
|------|------|---------|
| 分层：裸事件源 → 归一化(diff/去重/防抖) → 决策(状态机) | sing/mihomo/xray + ProtonVPN | 事件源与语义判定分两层 |
| 网络信号只发「触发」，重连/回退由上层状态机裁决 | ProtonVPN win/android | 事件层不改状态，只上报语义化事件 |
| 去抖分级：重连 60s 节流 / 唤醒立即 / 首事件不计 / 2s 防抖 | ProtonVPN win | 分级去抖，防换网抖动 |
| 指数退避 + jitter + 单飞行 | ProtonVPN android/gtk | 重连调度标准模板 |
| 默认接口判定无通用算法，必须平台分文件 | sing-box/mihomo | 每平台独立后端 |
| 主动探测补充被动事件（health_check 才是真实信号） | nthlink | 出站连通性探测 + OS 事件双轨 |
| Kill Switch = 配置态，非运行监听 | ProtonVPN 全平台 | 泄漏防护与事件监测解耦 |
| hosts 用懒轮询 + stat diff(5s)，大规则才 fswatch | mihomo | 小文件监测零常驻开销 |
| TUN/自接口排除是必需品 | sing/mihomo/xray | 防自环/误判 |
| 多地址池 + 域名解耦 = 重新适应核心原语 | nthlink | 重连 = 换路由 + 换候选地址 |

## 平台事件源清单（后端骨架）

| 平台 | 路由 | DNS | 网卡 | 代理 | hosts |
|------|------|-----|------|------|-------|
| macOS | SCDynamicStore / AF_ROUTE | SCDynamicStore | SCDynamicStore | SCDynamicStore(Global/Proxies) | kqueue/fs |
| Windows | NotifyRouteChange2 | 注册表/WMI | NotifyIpInterfaceChange | 注册表 Internet Settings | ReadDirectoryChangesW |
| Linux | netlink RTMGRP_* | resolv.conf/DBus | netlink RTMGRP_LINK | gsettings/DBus | inotify |
| iOS | NWPathMonitor | — | NWPathMonitor | — | — |
| Android | ConnectivityManager | LinkProperties | NetworkCallback | — | — |

## 关键设计要点

1. **两层事件源**（sing/mihomo 模式）：`networkUpdateMonitor`（裸「网络有变化」事件）+ `defaultInterfaceMonitor`（高层「默认出口变了」判定），两层都去抖去重。
2. **默认接口判定平台分文件**：Linux 扫主表默认路由、Darwin 解 RIB 标志、Windows 比 metric+connected+非虚拟。
3. **语义化事件**（ProtonVPN 模式）：把「地址变了」细分成本地需要的语义（接口集合增删 / IPv6 GUA 变化 / 路由表变化 / 某接口转发使能）。
4. **重连探测走 protect()**（Android 教训）：换服务器前必须绕过活动隧道测物理网络真实可达性，隧道内 ping 会误判。
5. **测试方法**（用户裁定）：`ZF_NETWORK_TRACE=1` 环境变量开关 + info 日志打印全流程 + 被测机脚本自愈（nohup，ssh 断开仍继续）。
