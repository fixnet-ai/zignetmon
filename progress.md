# Progress: zignetmon — 网络变化监测与自适应库

> 当前状态/待办真相源 = task_plan.md；技术定论 = findings.md；历史会话 = git log。

## 会话日志

- **09-07 P1 提取 + P2 五类扩展 + P3 验收（workflow `wtju21let`）**：发现 `zf.network`（#43）+ `zf.system_proxy`（#79）已实现网络变化监测并历经验证 → zignetmon = **提取 12 文件 + 扩展到 5 类**（hosts/proxy 监测 + 统一门面 diff），非从零设计；54/54 全绿。
- **09-07 v2 简化 + dns_monitor + 三层测试（workflow `wfbo17ie5` + `wvoojksfx`）**：用户方向修正——消费端只需「网络变了」粗信号，五类事件是监测覆盖度非消费方契约；`Callback(Snapshot)` 粗回调 + `Monitor.injectPlatformInfo` 注入；用户裁定「补独立 DNS 监测」→ `dns_monitor` 第 4 子监测 + 门面 1s 去抖；Tier1 注入 / Tier2 VM 真事件 / Tier3 移动注入三层测试架构定型；61/61 全绿，commit `79f665e`。
- **09-07 Tier2 三 VM 真机验证全 PASS + 2 bug 修复（workflow `wqfeqtfak`）**：macvm 2/2、linuxvm 3/3、windowsvm FINAL PASS；hosts 误报 + proxy 漏报/门面盲去抖的根因与修复详见 task_plan「VM 真机验证」段；commit `7a9fa09`（脚本）+ `ffd78f8`（src）。

## 基线

| 项 | 值 |
|----|-----|
| 版本 | 0.1.0 |
| Zig | 0.16.0 |
| 依赖 | zigfoundation（唯一实现源） |
| 测试 | `zig build test` 61/61 全绿（network/system_proxy 移植 + hosts/proxy/dns 四子监测 + 门面粗信号 diff + 注入 + 去抖） |
