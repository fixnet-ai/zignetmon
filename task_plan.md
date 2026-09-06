# Task Plan: zignetmon — 网络变化监测与自适应库

## Goal

生产级网络变化监测与自适应库：覆盖「路由 / 系统 DNS / 任意网卡 / 系统代理 / hosts 文件」五类关键网络设置变化 × 五平台（macOS / Windows / Linux / iOS / Android），消费方（zigbox 等）`@import("zignetmon")` 集成后，网络环境变化时服务重新自适应不断线。

## 阶段

| # | 阶段 | 内容 | 状态 |
|---|------|------|:---:|
| P0 | 项目骨架 | git init + build.zig + build.zig.zon + mod.zig stub + 文档 | ✅ 2026-09-07 |
| P1 | 提取 zf 模块 | 12 文件（network + system_proxy）→ zignetmon + import 适配 + 独立构建单测绿 | ✅ 2026-09-07 |
| P2 | 五类扩展 | hosts 监测 + 系统代理变化监测 + 统一门面（5 类语义事件）+ diff | ✅ 2026-09-07 |
| P3 | 测试与验收 | 单测全绿(54/54) + zigtester.yaml + ZF_NETWORK_TRACE + API/README/CLAUDE | ✅ 2026-09-07（真事件 VM 验证待） |
| P4 | 切接 zf（后续） | zf 移除 network/system_proxy + 消费方改 @import("zignetmon")（独立阶段） | ⬜ |

## 遗留（不阻塞，后续 track）

1. **真实事件源 VM 验证**：macOS AF_ROUTE（`sudo route` 加删 TEST-NET）真事件 + Windows/Linux 代理后端真事件（`proxy_monitor_{windows,linux}.zig` 源码已实现 + 交叉编译通过，真事件触发/读取正确性待 windowsvm/linuxvm）。
2. **被测机自愈脚本**：`tests/scripts/` nohup 脚本（ssh 断开仍继续）未落地，待真事件验证一并补。
3. **iOS/Android no-op**：iOS 系统代理对普通 app 不可用、Android 归 stub、hosts 移动端 no-op——均已在各文件头注明。

## 当前状态（2026-09-07）

- **P0 骨架 ✅**：项目目录 + git init + build.zig（ReleaseSafe 默认）+ build.zig.zon（fingerprint 0x8d2056863c2fa135）+ src/mod.zig 占位 + CLAUDE.md/README.md + 规划三件套。
- **P1 提取 ✅**：zf 的 network（#43）+ system_proxy（#79）12 文件提取到 zignetmon/src，import 适配（`@import("mod.zig")`→`@import("zigfoundation")` 等，规则见 design.md §2.2），独立构建单测绿；Linux/Windows 平台文件交叉编译通过。
- **P2 扩展 ✅**：`hosts_monitor.zig`（跨平台 stat diff）+ `proxy_monitor*.zig`（darwin SCDynamicStore / linux inotify / windows RegNotify / stub）+ `types.zig`（ChangeKind 六值）+ `mod.zig` 统一门面（network+hosts+proxy 三子监测 → 归一化 diff → 5 类语义事件 + ZF_NETWORK_TRACE）。
- **P3 验收 ✅**：`zig build test` 54/54 全绿（ReleaseSafe + Debug 泄漏检查）+ `zig fmt --check` 干净 + zigtester.yaml + API.md + README/CLAUDE 文档。
- **下一步 = P4 切接（后续独立阶段）**：zf 移除 network/system_proxy，消费方改 `@import("zignetmon")`；真实事件 VM 验证见「遗留」。

## 关键决策（已定，见 design.md §7）

1. **API 形态**：统一 `Monitor` 门面 = 订阅回调（`ChangeKind` + `Snapshot`）+ 主动 `snapshot()`。
2. **分层边界**：门面做 diff + 去抖 + 语义分类；默认接口判定留 network（平台分文件）；hosts/proxy 独立子监测。
3. **平台后端组织**：每平台一文件（`network_*.zig`/`proxy_monitor_*.zig`），comptime 分派；hosts 跨平台单文件。
4. **可观测**：`ZF_NETWORK_TRACE` 开关 + `zf.log` info + `[monitor]`/`[hosts]`/`[proxy]` 前缀。

## 提取面（design.md §2）

12 文件：network.zig / network_types.zig / network_params.zig / network_{darwin,linux,windows}.zig / system_proxy{,_common,_darwin,_linux,_windows,_stub}.zig。import 适配规则见 design.md §2.2。

## 依赖

- Zig 0.16.0
- zigfoundation（唯一实现源：net/endian/platform/alloc/log）
