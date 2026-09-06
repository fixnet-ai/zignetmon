# zignetmon

网络变化监测与自适应库 — fixnet 生态的独立兄弟项目。

当用户的关键网络设置变化时（切 WiFi、插拔网线、开 VPN、改 DNS/系统代理/hosts），zignetmon 感知这些变化并归一化上报，让消费方（如 zigbox）重新适应新的网络环境，服务不断线。

## 覆盖范围

五类关键网络设置变化 × 五平台：

| 维度 | macOS | Windows | Linux | iOS | Android |
|------|:---:|:---:|:---:|:---:|:---:|
| 路由变化 | ✓ | ✓ | ✓ | ✓ | ✓ |
| 系统 DNS | ✓ | ✓ | ✓ | — | ✓ |
| 任意网卡（up/down/地址） | ✓ | ✓ | ✓ | ✓ | ✓ |
| 系统代理设置 | ✓ | ✓ | ✓ | — | — |
| hosts 文件 | ✓ | ✓ | ✓ | — | — |

> **DNS 独立监测已补（本补丁）**：系统 DNS 在路由/网卡未变时被单独修改（改 resolv.conf / 系统
> 设置 / 注册表 NameServer）也由 `dns_monitor` **独立事件源**上报（macOS SCDynamicStore「Global/DNS」/
> Windows 注册表 notify / Linux inotify；iOS / Android 由注入承载）——此前 DNS 仅靠门面对 network
> 快照 diff 的附带监测，无独立事件源。

## 架构

```
事件源层（平台后端） → 归一化层（快照 diff + 防抖去重） → 决策层（消费方自适应）
```

## API 简介

统一接入入口 = `Monitor` 门面：任一类网络设置变化收敛为一个「网络变了」粗回调
（`Callback(Snapshot)`），另可主动 `snapshot()` 查询当前快照、`injectPlatformInfo()`
（移动端 / 测试注入）。公共签名、子监测（hosts_monitor / proxy_monitor / dns_monitor /
network / system_proxy）与用法示例见 **[API.md](API.md)**。

```zig
const zm = @import("zignetmon");

var mon = try zm.Monitor.init(allocator, .{}); // 路由/DNS/网卡/系统代理/hosts 四子监测就绪
defer mon.deinit();
try mon.start();                    // 启动全部事件源（幂等）
try mon.subscribe(onChange, ctx);   // 收到「网络变了」粗信号

fn onChange(snap: *const zm.Snapshot, ctx: ?*anyopaque) void {
    // 不区分路由/DNS/代理哪个变了 → 重测环境 → Session 重建（决策层由消费方实现）
    _ = snap;
    std.log.info("[app] network changed", .{});
}
```

> `Snapshot` 内 `default_interface` / `dns_servers` / `proxy.host` 为底层 monitor 内部缓冲的
> **借用切片**，仅在下次事件前有效；持久持有须自行 dup（详见 API.md §2）。

## 构建与测试

```bash
zig build                    # 构建库（ReleaseSafe 默认）
zig build real_event         # 构建 Tier2 真事件订阅 harness（zig-out/bin/real_event）
zig build test               # 单元测试（当前 61/61，Tier1 注入单测）
zig build test -Doptimize=Debug   # 调试内存泄漏
```

集成/回归测试一律经 zigtester 执行（`unit/all-tests` = Tier1 注入单测）：

```
zigtester_list zignetmon           # 查看套件（unit/all-tests）
zigtester_run zignetmon --level unit
zigtester_history zignetmon all-tests   # 历史趋势
```

三层测试架构（权威 = `design.md` §6）：

- **Tier 1 单元/注入**（host 本机，确定性，无 OS 事件）：`zig build test` 61/61 + zigtester
  `unit/all-tests`。`Monitor.injectPlatformInfo` 走与真实事件完全相同的 diff/dispatch 路径，
  确定性触发（覆盖 diff 判定 / 基线 / 去重 / 生命周期 / 移动注入）。
- **Tier 2 真实事件源**（macvm / linuxvm / windowsvm）：`zig build real_event` 构建订阅
  harness → `tests/scripts/` 驱动脚本触发真实 OS 事件（route / DNS / hosts / 代理），断言
  ≥1 行 `CHANGED`。脚本 nohup 自愈（ssh 断开仍继续）、平台门禁自 SKIP、经 vm-regression
  白名单在对应 VM 执行——**开发本机禁止执行**（脚本会临时改系统路由 / hosts，随即恢复）。
- **Tier 3 移动注入**（iOS / Android，无真机）：模拟 NE / JNI 桥 `injectPlatformInfo` 注入；
  移动端「无 hosts / 系统代理」边界由 Tier1 单测锁定。

> 桌面五类 / 移动粗信号的能力差异（iOS/Android 无 hosts、无系统代理，靠注入承载）见
> [API.md](API.md)「平台能力矩阵」与 `design.md` §3。

## 依赖

- **Zig 0.16.0**
- **zigfoundation**（唯一实现源：net/endian/platform/alloc/log）

## 可观测

设置 `ZF_NETWORK_TRACE=1`，收到任何网络变化事件时打印全流程 **info** 日志，可还原一次
变化的完整处理链：`事件源收到 → 归一化 diff → 去抖去重 → 事件分发`。默认关闭（无日志开销）；
实现为门面内读 env 一次缓存（POSIX `getenv` / Windows `kernel32`），日志经 zf.log、前缀
`[monitor]`/`[hosts]`/`[proxy]`/`[dns]`、英文 ASCII。

```bash
ZF_NETWORK_TRACE=1 <消费方可执行文件>   # 运行时开启 trace
```

## 参考实现

设计参照了生产级项目的网络变化处理（见 CLAUDE.md + findings.md）：

- nthlink（抗封锁工具，主动健康探测）
- ProtonVPN（生产级 VPN，Kill Switch / 重连状态机）
- sing-box / mihomo / Xray-core（协议侧，两层事件源）
