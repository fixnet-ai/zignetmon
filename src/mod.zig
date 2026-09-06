//! zignetmon — 网络变化监测与自适应库
//!
//! 覆盖「路由 / 系统 DNS / 任意网卡 / 系统代理 / hosts 文件」五类关键网络设置变化
//! × 五平台（macOS / Windows / Linux / iOS / Android）的事件源监测与归一化。
//!
//! 目标：当用户的关键网络设置变化时，消费方（zigbox 等）能重新适应新的网络环境，
//! 服务不断线。
//!
//! 架构（三层，待实现）：
//!   ① 事件源层（各平台后端）：监听五类事件 → 归一化为 NetworkInfo 快照 diff
//!   ② 归一化层（门面）：快照比对 → 只上报「关键维度真的变了」→ 防抖合并
//!   ③ 决策层（消费方）：收到变化 → 重测环境 → Session 完整重建

const std = @import("std");

// 骨架占位：当前仅验证「依赖 zigfoundation + 测试收集」链路打通。
// 后续分阶段填充：事件源后端 / 归一化门面 / 五类事件类型 / zigtester 验收。

test "zignetmon 骨架占位（构建链路自检）" {
    try std.testing.expect(true);
}
