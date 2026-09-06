const std = @import("std");

// ================================================================
// zignetmon — 网络变化监测与自适应库（五类事件 × 五平台）
// ================================================================
// 依赖：仅 Zig std + zigfoundation（唯一实现源：net/endian/platform/alloc/log）。
// 定位：从 zigfoundation 分离出来的独立兄弟项目（同 zigstack 先例），
//       覆盖「路由 / 系统 DNS / 任意网卡 / 系统代理 / hosts 文件」五类关键网络设置变化
//       × 五平台（macOS / Windows / Linux / iOS / Android）的事件源监测与归一化。
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    // 默认 ReleaseSafe（用户级 CLAUDE.md「构建模式（强制）」）；调试用 -Doptimize=Debug
    const optimize = b.option(std.builtin.OptimizeMode, "optimize", "Prioritize performance, safety, or binary size") orelse .ReleaseSafe;

    const zf_dep = b.dependency("zigfoundation", .{ .target = target, .optimize = optimize });

    // 库模块（root = src/mod.zig），源码内 @import("zigfoundation") 经 addImport 绑定到 zf 根模块。
    // 发布模块名 = 包名 "zignetmon"。
    const zignetmon_module = b.addModule("zignetmon", .{
        .root_source_file = b.path("src/mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    zignetmon_module.addImport("zigfoundation", zf_dep.module("zigfoundation"));

    // ---- 单元测试（root = src/mod.zig test hub）----
    const lib_tests = b.addTest(.{
        .name = "zignetmon-tests",
        .root_module = zignetmon_module,
    });
    const test_run = b.addRunArtifact(lib_tests);
    // 交叉目标（如 -Dtarget=x86_64-windows）下仅编译、跳过运行（平台后端本机无法执行）。
    test_run.skip_foreign_checks = true;
    const test_step = b.step("test", "运行所有单元测试");
    test_step.dependOn(&test_run.step);

    // ---- Tier2 VM 真事件订阅 harness（测试工具二进制，design.md §6；见 tests/real_event_harness.zig）----
    // 仅用于 macvm/linuxvm/windowsvm 真事件验证：订阅 Monitor 粗回调 → 每事件向 stdout 打印
    // 一行 CHANGED iface=... gw=...，运行满 argv[1] 秒后退出 0（运行会阻塞订阅，不并入构建门禁）。
    const real_event_mod = b.createModule(.{
        .root_source_file = b.path("tests/real_event_harness.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true, // stdout std.c.write + Monitor 后台线程（POSIX pthread）
    });
    real_event_mod.addImport("zigfoundation", zf_dep.module("zigfoundation"));
    real_event_mod.addImport("zignetmon", zignetmon_module);

    const real_event = b.addExecutable(.{
        .name = "real_event",
        .root_module = real_event_mod,
    });
    b.installArtifact(real_event); // 并入默认 `zig build` 安装
    const real_event_step = b.step("real_event", "构建真事件订阅 harness 到 zig-out/bin/real_event");
    real_event_step.dependOn(&b.addInstallArtifact(real_event, .{}).step);
}
