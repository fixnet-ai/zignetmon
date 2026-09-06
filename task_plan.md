# Task Plan: zignetmon — 网络变化监测与自适应库

## Goal

生产级网络变化监测与自适应库：覆盖「路由 / 系统 DNS / 任意网卡 / 系统代理 / hosts 文件」五类关键网络设置变化 × 五平台（macOS / Windows / Linux / iOS / Android），消费方（zigbox 等）`@import("zignetmon")` 集成后，网络环境变化时服务重新自适应不断线。

## 阶段

| # | 阶段 | 内容 | 状态 |
|---|------|------|:---:|
| P0 | 项目骨架 | git init + build.zig + build.zig.zon + mod.zig stub + 文档 | ✅ 2026-09-07 |
| P1 | 架构设计 | 三层架构 + API 契约 + 五类事件类型 + 快照 diff 语义 | ⬜ |
| P2 | 归一化层 | NetworkInfo 快照 + diff + 防抖去重 + ZF_NETWORK_TRACE 可观测 | ⬜ |
| P3 | 事件源层（分平台） | macOS → Linux → Windows → iOS/Android 后端，逐平台 | ⬜ |
| P4 | 测试与验收 | 各平台独立测试方法 + 被测机自愈脚本 + zigtester.yaml | ⬜ |

## 当前状态（2026-09-07）

- **P0 骨架 ✅**：项目目录 + git init + build.zig（ReleaseSafe 默认）+ build.zig.zon（fingerprint 0x8d2056863c2fa135）+ src/mod.zig 占位 + CLAUDE.md/README.md + 规划三件套。`zig build test` 绿。
- **研究 ✅**：6 参考项目（nthlink ×4 + ProtonVPN ×4 + sing-box/mihomo/xray）网络变化处理研究完成，定论见 findings.md。
- **下一步 = P1 架构设计**：三层架构 + API 契约（事件类型、快照结构、回调语义）+ 五类事件 × 五平台后端矩阵。设计文档先评审再实现。

## 关键决策（待 P1 定）

1. **API 形态**：门面暴露什么（订阅回调 + 主动查询快照）？事件粒度（五类分别回调 vs 统一 diff 回调）？
2. **分层边界**：归一化层是否含「默认接口判定」这类高层语义，还是只做快照 diff？
3. **平台后端组织**：每平台一个文件（darwin/windows/linux/ios/android），共享门面与类型。
4. **可观测设计**：`ZF_NETWORK_TRACE` 日志的级别与内容（全流程可还原）。

## 依赖

- Zig 0.16.0
- zigfoundation（唯一实现源：net/endian/platform/alloc/log）
