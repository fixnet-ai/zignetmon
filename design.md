# Design: zignetmon — 网络变化监测与自适应库

> 本文是 zignetmon 的架构权威文档。目标、背景、研究定论见 `findings.md`；阶段进度见 `task_plan.md`。

## 1. 核心结论：不是从零设计，是「提取 + 扩展」

「网络变化监测」已在 zigfoundation 作为 `zf.network`（#43）+ `zf.system_proxy`（#79）实现并历经真机/VM/winx64 验证。zignetmon 的职责：

1. **提取**：把 `zf.network`（路由/网卡/DNS 监测）+ `zf.system_proxy`（系统代理副作用）从 zf 抽出，适配 import 后独立构建、单测绿。
2. **扩展**：补齐五类事件中缺失的「hosts 文件」「系统代理变化」监测 + 统一的 5 类语义事件门面。
3. **成为唯一实现源**：后续 zf.network/system_proxy 从 zf 移除，消费方改 `@import("zignetmon")`（**切接是后续独立阶段，不在本项目内做**）。

依赖方向：`zignetmon → zigfoundation`（用 `zf.net.IpAddr`/`zf.platform`/`zf.sync.Mutex`/`zf.socket`/`zf.egress`/`zf.endian`/`zf.win_dll`/`zf.log`）。无反向依赖。

## 2. 提取面（P1）

### 2.1 文件清单（12 文件，zf/src → zignetmon/src）

| 源（zf/src/） | 目标（zignetmon/src/） | 角色 |
|---|---|---|
| network.zig | network.zig | 网络门面（单例 + 回调 + 快照） |
| network_types.zig | network_types.zig | 共享类型（IpAddr/AddressInfo/NetworkInterface/回调） |
| network_params.zig | network_params.zig | 参数查询（网关/地址/DNS/链路） |
| network_darwin.zig | network_darwin.zig | macOS/iOS AF_ROUTE 后端 |
| network_linux.zig | network_linux.zig | Linux/Android netlink 后端 |
| network_windows.zig | network_windows.zig | Windows iphlpapi 后端 |
| system_proxy.zig | system_proxy.zig | 系统代理 set/restore 门面 |
| system_proxy_common.zig | system_proxy_common.zig | 共享纯函数 |
| system_proxy_darwin.zig | system_proxy_darwin.zig | macOS 后端 |
| system_proxy_linux.zig | system_proxy_linux.zig | Linux 后端 |
| system_proxy_windows.zig | system_proxy_windows.zig | Windows 后端 |
| system_proxy_stub.zig | system_proxy_stub.zig | 移动/未支持 stub |

### 2.2 import 适配规则（机械替换，全 12 文件）

| 原 import（zf 内兄弟文件） | 替换为 |
|---|---|
| `@import("mod.zig")` | `@import("zigfoundation")` |
| `@import("net.zig")` | `@import("zigfoundation").net` |
| `@import("egress.zig")` | `@import("zigfoundation").egress` |
| `@import("endian.zig")` | `@import("zigfoundation").endian` |
| `@import("sync.zig")` | `@import("zigfoundation").sync` |
| `@import("socket.zig")` | `@import("zigfoundation").socket` |
| `@import("platform.zig")` | `@import("zigfoundation").platform` |
| `@import("win_dll.zig")` | `@import("zigfoundation").win_dll` |

兄弟文件 import **不改**（`@import("network_types.zig")`、`@import("network_params.zig")`、`@import("network_windows.zig")`、`@import("system_proxy_common.zig")`、`@import("system_proxy_*.zig")` 保持局部）。

变量名保持不变（`foundation`/`zf` 变量名只需指向 zigfoundation，无需改名）。若某文件还有未列出的 zf 兄弟 import（如 `log.zig`），同样映射到 `zigfoundation.*`。

### 2.3 适配后验收

- `zig build test` 全绿（含 network/system_proxy 的全部移植单测）。
- 组件日志前缀规范：zf 门面内已用 `[network]`，zignetmon 侧保留；**禁止**改日志前缀为 zignetmon 专名（避免消费方 grep 失效），如需新增用 `[hosts]`/`[proxy]`/`[monitor]`。

## 3. 五类事件 × 五平台覆盖矩阵（目标态）

| 事件类别 | macOS | Windows | Linux | iOS | Android |
|---|---|---|---|---|---|
| 路由 route | AF_ROUTE ✅(提取) | NotifyRouteChange2 ✅ | netlink ✅ | AF_ROUTE ✅ | netlink ✅ |
| 网卡 interface | SCDynamicStore/AF_ROUTE ✅ | NotifyIpInterfaceChange ✅ | netlink ✅ | NWPath 桥 ✅ | NetworkCallback ✅ |
| DNS dns | 门面 diff ✅ | 门面 diff ✅ | resolv.conf ✅(提取) | 注入 ✅ | LinkProperties ✅ |
| 系统代理 proxy | SCDynamicStore(Global/Proxies) 🆕 | 注册表 notify 🆕 | dconf inotify 🆕(尽力) | stub | stub |
| hosts 文件 | stat diff 轮询 🆕 | stat diff 轮询 🆕 | stat diff 轮询 🆕 | no-op | no-op |

> ✅ = 提取自 zf 已有；🆕 = 本阶段扩展新增；「门面 diff」= 无需独立 OS 事件源，门面层比对快照变化即产出 dns 事件（DNS 变化几乎总伴随网卡变化）。

## 4. 三层架构（最终）

```
① 事件源层（平台后端）  network_*.zig / hosts_monitor / proxy_monitor_*.zig
        ↓ 裸事件
② 归一化层（门面）     mod.zig：快照比对 → diff → 去抖 → 5 类语义事件
        ↓ ChangeKind + Snapshot
③ 决策层（消费方）     zigbox 等：收到事件 → 重测环境 → Session 重建
```

## 5. API 契约（供实现，固定签名）

### 5.1 类型 `types.zig`

```zig
pub const ChangeKind = enum { route, interface, dns, proxy, hosts, default_route };
```

### 5.2 hosts 监测 `hosts_monitor.zig`（跨平台，单文件）

```zig
pub const Callback = *const fn (mtime: i128, ctx: ?*anyopaque) void;
pub fn defaultHostsPath() []const u8; // comptime：POSIX /etc/hosts；Win C:\Windows\System32\drivers\etc\hosts
pub const HostsMonitor = struct {
    pub fn init(allocator: std.mem.Allocator, path: []const u8) !HostsMonitor; // dupe path
    pub fn start(self: *HostsMonitor) !void;   // 后台线程 5s stat diff（幂等）
    pub fn subscribe(self: *HostsMonitor, cb: Callback, ctx: ?*anyopaque) !void;
    pub fn lastMtime(self: *HostsMonitor) ?i128;
    pub fn close(self: *HostsMonitor) void;    // 停线程（幂等）
    pub fn deinit(self: *HostsMonitor) void;   // 释放
};
```

实现要点：后台线程 `sleepNs(5s)` 后 `std.Io.Dir.statFile` 比 mtime+size，变了才 emit；非忙等（5s 间隔）。iOS/Android `defaultHostsPath` 返回空 → start 立即 no-op。

### 5.3 系统代理变化监测 `proxy_monitor.zig`（分平台）

```zig
pub const ProxySettings = struct { enabled: bool = false, host: ?[]const u8 = null, port: u16 = 0 };
pub const Callback = *const fn (settings: *const ProxySettings, ctx: ?*anyopaque) void;
pub const ProxyMonitor = struct {
    pub fn init(allocator: std.mem.Allocator) !ProxyMonitor;
    pub fn start(self: *ProxyMonitor) !void;
    pub fn subscribe(self: *ProxyMonitor, cb: Callback, ctx: ?*anyopaque) !void;
    pub fn snapshot(self: *ProxyMonitor) ?ProxySettings;
    pub fn close(self: *ProxyMonitor) void;
    pub fn deinit(self: *ProxyMonitor) void;
};
```

分平台（comptime 分派）：`proxy_monitor_darwin.zig`（SCDynamicStore Global/Proxies）/ `proxy_monitor_windows.zig`（RegNotifyChangeKeyValue Internet Settings）/ `proxy_monitor_linux.zig`（inotify ~/.config/dconf/user，尽力）/ `proxy_monitor_stub.zig`（移动）。macOS 实现为完整 + 真事件；Win/Linux 为源码 + 待 VM 验证；stub 恒 no-op。

### 5.4 统一门面 `mod.zig`

```zig
pub const ChangeKind = types.ChangeKind;
pub const Snapshot = struct {
    default_interface: ?network.Interface = null,
    gateway: ?zf.net.IpAddr = null,
    dns_servers: []const zf.net.IpAddr = &.{},
    proxy: ?proxy_monitor.ProxySettings = null,
    hosts_mtime: ?i128 = null,
};
pub const Callback = *const fn (kind: ChangeKind, snap: *const Snapshot, ctx: ?*anyopaque) void;
pub const Opt = struct { hosts_path: ?[]const u8 = null, excluded_interfaces: []const network.ExcludedInterface = &.{}, under_network_extension: bool = false };
pub const Monitor = struct {
    pub fn init(allocator: std.mem.Allocator, opts: Opt) !Monitor;
    pub fn start(self: *Monitor) !void;
    pub fn subscribe(self: *Monitor, cb: Callback, ctx: ?*anyopaque) !void;
    pub fn snapshot(self: *Monitor) Snapshot;
    pub fn close(self: *Monitor) void;
    pub fn deinit(self: *Monitor) void;
};
// 子模块保留导出（高级用法）
pub const network = @import("network.zig");
pub const system_proxy = @import("system_proxy.zig");
```

门面 diff 逻辑（纯函数，可单测）：缓存上次快照，收到 network 回调时比对 → gateway 变 = `route`；默认接口变 = `default_route`；dns 列表变 = `dns`；接口集合变 = `interface`。hosts/proxy 子监测回调 → 对应 `ChangeKind`。emit 统一回调。

### 5.5 可观测 `ZF_NETWORK_TRACE`

`ZF_NETWORK_TRACE=1` 环境变量开启 info 级全流程日志：事件源收到 → 归一化 diff → 去抖 → 事件分发，经 `zf.log`（`std.log.info("[monitor] ...")`）。默认关闭。实现为门面内一个 `traceEnabled()` 判定（读取 env 一次缓存）。

## 6. 测试方法（P4）

- **单元测试**：`zig build test` 覆盖 — 门面 diff 纯函数（5 类判定）、hosts 快照、proxy 快照、network/system_proxy 移植单测全绿。
- **真实事件**（macOS，本机可跑）：`sudo route` 加删 TEST-NET 路由 → AF_ROUTE 事件（network_darwin 已有真事件测试先例）。
- **zigtester.yaml**：`unit` 层 `all-tests`（`zig build test`）；functional 真实事件源测试挂 `macvm`（TUN 类先例）。
- **被测机脚本自愈**：`tests/scripts/` 下 nohup 脚本，ssh 断开仍继续（用户裁定）。

## 7. 关键决策（已定）

1. **API 形态**：统一 `Monitor` 门面 = 订阅回调（`ChangeKind` + `Snapshot`）+ 主动 `snapshot()`。五类统一单回调，按 `ChangeKind` 区分。
2. **分层边界**：归一化层（门面）做 diff + 去抖 + 语义分类；默认接口判定留在 `network`（平台分文件）；hosts/proxy 独立子监测。
3. **平台后端组织**：每平台一文件（`network_*.zig`/`proxy_monitor_*.zig`），comptime `builtin.os.tag` 分派；hosts 跨平台单文件。
4. **可观测**：`ZF_NETWORK_TRACE` 开关 + `zf.log` info 级 + `[monitor]`/`[hosts]`/`[proxy]` 前缀。
