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

## 架构

```
事件源层（平台后端） → 归一化层（快照 diff + 防抖去重） → 决策层（消费方自适应）
```

## API 简介

统一接入入口 = `Monitor` 门面：五类变化收敛到一个回调（`ChangeKind` + `Snapshot`），
另可主动 `snapshot()` 查询当前快照。公共签名、子监测（hosts_monitor / proxy_monitor /
network / system_proxy）与用法示例见 **[API.md](API.md)**。

```zig
const zm = @import("zignetmon");

var mon = try zm.Monitor.init(allocator, .{}); // 路由/DNS/网卡/系统代理/hosts 三子监测就绪
defer mon.deinit();
try mon.start();                    // 启动全部事件源（幂等）
try mon.subscribe(onChange, ctx);   // kind = route/default_route/interface/dns/proxy/hosts

fn onChange(kind: zm.ChangeKind, snap: *const zm.Snapshot, ctx: ?*anyopaque) void {
    // 收到变化 → 重测环境 → Session 重建（决策层由消费方实现）
    std.log.info("[app] network change kind={s}", .{@tagName(kind)});
}
```

> `Snapshot` 内 `default_interface` / `dns_servers` / `proxy.host` 为底层 monitor 内部缓冲的
> **借用切片**，仅在下次事件前有效；持久持有须自行 dup（详见 API.md §2）。

## 构建与测试

```bash
zig build                    # 构建库（ReleaseSafe 默认）
zig build test               # 单元测试（当前 54/54）
zig build test -Doptimize=Debug   # 调试内存泄漏
```

集成/回归测试一律经 zigtester 执行：

```
zigtester_list zignetmon           # 查看套件（unit/all-tests）
zigtester_run zignetmon --level unit
zigtester_history zignetmon all-tests   # 历史趋势
```

真实事件源（macOS `sudo route` → AF_ROUTE）functional 测试需特权，挂 macvm
（`zigtester.yaml` functional 层已留占位注释），开发本机仅跑 NOTUN/unit。

## 依赖

- **Zig 0.16.0**
- **zigfoundation**（唯一实现源：net/endian/platform/alloc/log）

## 可观测

设置 `ZF_NETWORK_TRACE=1`，收到任何网络变化事件时打印全流程 **info** 日志，可还原一次
变化的完整处理链：`事件源收到 → 归一化 diff → 去抖去重 → 事件分发`。默认关闭（无日志开销）；
实现为门面内读 env 一次缓存（POSIX `getenv` / Windows `kernel32`），日志经 zf.log、前缀
`[monitor]`/`[hosts]`/`[proxy]`、英文 ASCII。

```bash
ZF_NETWORK_TRACE=1 <消费方可执行文件>   # 运行时开启 trace
```

## 参考实现

设计参照了生产级项目的网络变化处理（见 CLAUDE.md + findings.md）：

- nthlink（抗封锁工具，主动健康探测）
- ProtonVPN（生产级 VPN，Kill Switch / 重连状态机）
- sing-box / mihomo / Xray-core（协议侧，两层事件源）
