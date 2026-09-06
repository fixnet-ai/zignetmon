# Progress: zignetmon — 网络变化监测与自适应库

> 当前状态/待办真相源 = task_plan.md；技术定论 = findings.md；历史会话 = git log。

## 会话日志

### 2026-09-07 — P1 提取 + P2 扩展 + P3 验收（workflow `wtju21let`）

- **重大发现**：`zf.network`（#43，6 文件 ~180KB）+ `zf.system_proxy`（#79，6 文件）已实现网络变化监测并历经验证。zignetmon = **提取 + 扩展到 5 类**，非从零设计。
- **P1 提取**：12 文件（network{,_types,_params,_darwin,_linux,_windows} + system_proxy{,_common,_darwin,_linux,_windows,_stub}）从 zf 复制 + import 适配（`@import("mod.zig")`→`@import("zigfoundation")` 等 8 条规则，design.md §2.2）。独立构建绿，Linux/Windows 平台文件交叉编译通过。
- **P2 扩展**（新增 7 文件）：`types.zig`（ChangeKind 六值枚举）、`hosts_monitor.zig`（跨平台 stat diff 5s，i128 mtime 用 Mutex 而非 atomic——std.atomic.Value(i128) Windows 非法）、`proxy_monitor{,_darwin,_linux,_windows,_stub}.zig`（分平台系统代理变化监测）、`mod.zig` 统一门面（三子监测 → 归一化 diff → 5 类语义事件 + ZF_NETWORK_TRACE）。
- **P3 验收**：`zig build test` 54/54 全绿（ReleaseSafe + Debug 泄漏检查双绿）+ `zig fmt --check` 干净（3 文件格式已修）+ zigtester.yaml（zigtester_list 验证可加载）+ API.md/README/CLAUDE 文档。
- **遗留**：真事件源 VM 验证（macOS AF_ROUTE / Win·Linux 代理后端真事件）、被测机自愈脚本、iOS/Android no-op——均待后续 track。

### 2026-09-07 — v2 简化（粗信号）+ dns_monitor + 测试性（workflow `wfbo17ie5` + `wvoojksfx`）

- **用户方向修正**：消费端只需「网络变了」一个粗信号（重置自身变量），五类事件是**监测覆盖度**（内部）非消费方契约；移动端≠PC（无 hosts/系统代理，粗信号+注入）；**先自身质量、后切接**。
- **v2 API 简化**（`wfbo17ie5`）：`Callback(Snapshot)` 粗信号（移除 `ChangeKind` 出公开契约，降内部 trace）；新增 `Monitor.injectPlatformInfo`（移动 + 测试注入入口，走真实事件同 diff/dispatch 路径）。
- **三层测试架构**：Tier1 单元注入（host 确定性）/ Tier2 真事件 harness（`zig build real_event`）+ 三平台驱动脚本 / Tier3 移动注入（单测锁能力边界）。
- **dns_monitor 第 4 子监测**（`wvoojksfx`，用户裁定「补独立 DNS 监测」）：发现原实现 DNS 只在接口变化时重读、无独立事件源；补 `dns_monitor{,_darwin,_linux,_windows,_stub}.zig`（macOS SCDynamicStore DNS / Linux inotify resolv.conf / Windows 注册表 RegNotify）+ 门面 1s 合并去抖（接口+DNS 同变收敛为恰好一次）。
- **验收**：`zig build test` 61/61 全绿（ReleaseSafe + Debug 泄漏检查）+ 交叉编译 linux/windows 通过 + `zig build real_event` 编译 + fmt 干净。commit `79f665e`。

### 2026-09-07 — Tier2 VM 真机验证 + 2 bug 修复（workflow `wqfeqtfak` + agent）

- **三 VM 真事件全 PASS**：macvm 2/2、linuxvm 3/3、windowsvm FINAL PASS（hosts/dns/proxy 真事件正确触发，非默认路由正确 0 伪信号）。
- **bug1 hosts 误报**（linuxvm 暴露）：utm-monitor 守护进程对 /etc/hosts 做内容不变、仅 mtime bump 的保活重写，原纯 stat-diff 误判 → 修「stat 预筛 + 内容字节 diff」。
- **bug2 proxy 漏报 + 门面盲去抖**（windowsvm 暴露）：proxy_monitor_windows 单次 RegNotify+INFINITE 等待 → 修有界 1s+周期重读兜底；门面 `dispatch()` 盲 1s 合并把「hosts restore→proxy set」独立真实事件误吞 → 修合并收窄到 network/dns 对、hosts/proxy 必达。
- **测试脚本修复**：mac 脚本 ROOT 路径错 + CAN_SUDO 缺失（永远 SKIP）+ 路由子项从「期望≥1」改为「非默认路由 0 伪信号」负向断言。
- commit `7a9fa09`（脚本）+ `ffd78f8`（3 个 src 修复）。

## 基线

| 项 | 值 |
|----|-----|
| 版本 | 0.1.0 |
| Zig | 0.16.0 |
| 依赖 | zigfoundation（唯一实现源） |
| 测试 | `zig build test` 61/61 全绿（network/system_proxy 移植 + hosts/proxy/dns 四子监测 + 门面粗信号 diff + 注入 + 去抖） |
