# API — zignetmon 网络变化监测与自适应库

> 架构权威 = `design.md`；阶段进度 = `task_plan.md`。本文件是公共 API 的唯一权威文档。
> 消费方（zigbox 等）`@import("zignetmon")` 集成，无需了解平台后端内部。

## 总览：一行接入

```zig
const zm = @import("zignetmon"); // 库模块根 = src/mod.zig

var mon = try zm.Monitor.init(allocator, .{}); // 四个子监测（network/hosts/proxy/dns）就绪
defer mon.deinit();
try mon.start();                    // 启动全部事件源（幂等）
try mon.subscribe(onChange, ctx);   // 注册「网络变了」粗信号回调
_ = mon.snapshot();                 // 需要时主动查询当前快照

fn onChange(snap: *const zm.Snapshot, ctx: ?*anyopaque) void {
    // 收到即「网络环境已变」：snap 为变化后全量快照（字段为借用，见下）。
    // 消费方不区分路由/DNS/代理哪个变了，一律重置依赖网络的状态。
    _ = ctx;
    std.log.info("[app] network changed", .{});
}
```

五类关键网络设置变化（路由 / 系统 DNS / 任意网卡 / 系统代理 / hosts 文件）统一收敛为一个
**「网络变了」粗信号**（design.md v2）：任一类变化 → 消费方**恰好收到一次**回调。收到事件后
重测环境、重建 Session，即可自适应不断线。

---

## 平台能力矩阵（桌面五类 / 移动粗信号 + 注入）

**桌面五类 / 移动粗信号**：hosts 文件、系统代理是**桌面专属**能力——macOS / Windows / Linux
五类全量监测；iOS / Android **无 hosts 文件、无桌面系统代理语义**（proxy_monitor 归 stub、
`defaultHostsPath()==""` → hosts 监测 no-op），移动端只有「网络路径 / 网络变化」粗信号，受限
环境（iOS NE / Android 桥）由上层**注入**网络参数（`Monitor.injectPlatformInfo`，见 §3）。
矩阵权威 = `design.md` §3。

| 能力 | macOS | Windows | Linux | iOS | Android |
|---|---|---|---|---|---|
| 路由 / 网卡事件源 | AF_ROUTE + SCDynamicStore | NotifyRouteChange2 + IpInterface | netlink | NWPathMonitor / 注入 | netlink / NetworkCallback |
| DNS | SCDynamicStore / resolv.conf | 注册表 / GAA | resolv.conf | 注入 | LinkProperties / 注入 |
| 系统代理监测 | SCDynamicStore(Global/Proxies) | 注册表 notify | dconf inotify | ❌ 无 | ❌ 无（app 级） |
| hosts 文件 | ✅ stat diff | ✅ stat diff | ✅ stat diff | ❌ 无 hosts | ❌ 无 hosts |
| 默认接口判定 | sysctl | GetIPForwardTable2 | /proc/net/route | socket 回退 | /proc/net/route |

> **DNS 行标注（本补丁）**：系统 DNS 的**独立变化**（路由/网卡未变时单独被改）由新增 `dns_monitor`
> **独立事件源已覆盖**（macOS SCDynamicStore「State:/Network/Global/DNS」/ Windows 注册表 Tcpip
> Interfaces RegNotify / Linux inotify resolv.conf；iOS / Android 由注入承载）。详见 §4.3。

**消费方视角**：桌面五类与移动粗信号都经同一个 `Monitor` 门面收敛为「网络变了」粗回调 +
快照（§3）；差异只在事件源覆盖度与是否需注入，**外部契约不变**。

---

## 1. 内部诊断 `ChangeKind`（非消费方契约）

六值枚举保留在 `src/types.zig` 作**内部诊断**（仅 `ZF_NETWORK_TRACE` trace 用），**不进回调
签名**（design.md §5）。下表列出门面内部 diff 判定的字段级变化，供理解 trace 输出：

| 内部 diff 值 | 判定（快照比对） |
|---|---|
| `route` | 网关（next-hop）地址变化 |
| `default_route` | 默认出口接口**身份**变化（换接口 / 默认路由出现或消失） |
| `interface` | 同一默认接口属性变化（mtu / 链路 up / 地址列表） |
| `dns` | 系统 DNS 服务器列表变化 |

hosts / proxy / DNS 各经独立子监测判定变化（DNS 独立监测 = `dns_monitor`，见 §4.3）。任一类判定「变了」→ 派发**一次**粗回调（多字段同变
如换网也收敛为一次），不按字段分别派发。

## 2. 归一化快照 `Snapshot`

回调携带 + `Monitor.snapshot()` 主动查询共用同一结构。

```zig
pub const Snapshot = struct {
    default_interface: ?network.Interface = null, // 默认出口接口（index/mtu/name/up/addresses）
    gateway: ?zf.net.IpAddr = null,               // 网关（next-hop）
    dns_servers: []const zf.net.IpAddr = &.{},    // 系统 DNS 列表
    proxy: ?proxy_monitor.ProxySettings = null,   // 系统代理（host 借用）
    hosts_mtime: ?i128 = null,                    // hosts 文件最近 mtime（纳秒）
};
```

**所有权（重要）**：`default_interface` / `dns_servers` / `proxy.host` 均指向底层 monitor
内部缓冲的**借用切片**，仅在下一次对应事件 / deinit 前有效。消费方需持久持有（如跨事件比较、
存储）时必须自行 `dupe`。快照按值拷贝字段是安全的，切片所指内存会失效。

## 3. 统一门面 `Monitor`

`src/mod.zig` 是归一化层（design.md §4 ②）。`Monitor` 拥有四个子监测（network 全局单例 +
hosts + proxy + dns）的生命周期。

### 3.1 类型

```zig
pub const Opt = struct {
    hosts_path: ?[]const u8 = null,                          // 自定义 hosts 路径；null → 平台默认
    excluded_interfaces: []const network.ExcludedInterface = &.{}, // TUN 排除自身防路由循环（透传 network）
    under_network_extension: bool = false,                   // iOS NE 内运行（透传 network）
};
pub const Callback = *const fn (snap: *const Snapshot, ctx: ?*anyopaque) void; // 「网络变了」粗信号
```

### 3.2 方法

| 方法 | 签名 | 语义 |
|---|---|---|
| init | `(allocator, opts) !Monitor` | 初始化四个子监测；`hosts_path` null → `hosts_monitor.defaultHostsPath()` |
| start | `() !void` | 启动全部事件源 + 订阅内部处理器。**幂等**；close 后可 restart |
| subscribe | `(cb, ctx) !void` | 注册「网络变了」粗信号回调。start 前后皆可；注册表满（16）返回 `error.TooManySubscribers` |
| snapshot | `() Snapshot` | 主动查询当前归一化快照（借用，见 §2） |
| injectPlatformInfo | `(info: network.PlatformInjectedInfo) void` | 注入平台网络参数（移动 iOS NE / Android 桥 / 测试入口）。更新快照后走与真实事件相同 diff/dispatch 路径，通知订阅者 |
| close | `() void` | 停四个子监测（**幂等**，保留订阅，可 restart）；重置 diff 基线 |
| deinit | `() void` | 先停线程再释放全部资源；重置 network 全局单例（可重新 init） |

### 3.3 门面语义要点

- **粗信号收敛**：任一类底层变化（network diff 非空 / hosts mtime 变 / proxy 设置变 /
  dns_monitor 独立变）→ 派发**恰好一次**粗回调；多字段同变（如换网同时换 gateway + 默认接口 +
  DNS）也收敛为一次。dns_monitor 独立变化时快照 `dns_servers` 覆盖为其新鲜值（handleDns）。
- **基线（baseline）**：首个 network 事件只建立基线、不派发，避免 start 期「从无到有」伪事件；
  network 若已由其他路径运行（无首事件），start 时用当前快照播种基线。
- **去重**：相同事件连续到达 → diff 为空 → 不派发（network 内部另有 1s 防抖，门面不叠加）。
- **线程模型**：network / hosts / proxy / dns 回调各自在后台线程触发；门面内部注册表与基线用
  `zf.sync.Mutex` 保护，回调在**锁外**派发（用户回调内可安全重入 subscribe，不会死锁）。
  回调应尽快返回、不得阻塞（阻塞的是后台事件源线程）。

### 3.4 生命周期契约

- `Monitor` 是 network 全局单例生命周期的**拥有者**：`deinit()` 整机 reset，进程退出前调用一次即可。
- `start` 前即可 `snapshot()`（返回当前态，无线程）。
- `close` 后 `start`：重新播种基线（`prev_valid` 复位），不会用陈旧基线误判。

## 4. 子监测（高级用法，经 mod 顶层 re-export）

统一 `Monitor` 已覆盖绝大多数场景。需要**裸事件**（不经归一化）或定制组合时，可直接使用
四个子监测。mod 顶层全部导出：`Snapshot`、`Callback`、`Opt`、`Monitor`、
`network`、`system_proxy`、`hosts_monitor`、`proxy_monitor`、`dns_monitor`。
（`ChangeKind` 在 `types.zig` 内部保留，作 trace 诊断，**不进** mod 顶层导出。）

### 4.1 hosts 文件监测 `hosts_monitor`（跨平台单文件）

5s 后台线程 stat（mtime + size）diff，变了才 emit；空路径（iOS/Android）start 直接 no-op。

```zig
pub const Callback = *const fn (mtime: i128, ctx: ?*anyopaque) void; // mtime = 纳秒时间戳

pub fn defaultHostsPath() []const u8; // POSIX /etc/hosts；Win C:\Windows\System32\drivers\etc\hosts；iOS/Android ""

pub const HostsMonitor = struct {
    pub fn init(allocator: std.mem.Allocator, path: []const u8) !HostsMonitor; // dup path
    pub fn start(self: *HostsMonitor) !void;        // 后台线程 5s stat diff（幂等；空路径 no-op）
    pub fn subscribe(self: *HostsMonitor, cb: Callback, ctx: ?*anyopaque) !void;
    pub fn lastMtime(self: *HostsMonitor) ?i128;    // 最近观测 mtime；尚未观测到为 null
    pub fn close(self: *HostsMonitor) void;          // 停线程（幂等；join 延迟 ≤ ~100ms 分片睡眠）
    pub fn deinit(self: *HostsMonitor) void;         // 释放
};
```

- 首次观测只建立基线、不发事件（与门面一致）。
- 回调在后台轮询线程触发，须尽快返回；回调 mtime = 当次快照 `lastMtime()`。

### 4.2 系统代理变化监测 `proxy_monitor`（分平台，comptime 分派）

监听系统代理设置变化（macOS SCDynamicStore「Global/Proxies」/ Windows 注册表 notify /
Linux dconf inotify / 移动 stub 恒 no-op）。

```zig
pub const ProxySettings = struct {
    enabled: bool = false,     // true ⇒ 有显式代理已启用且解析出 host（host != null 不变量）
    host: ?[]const u8 = null,  // 借用 monitor 内部缓冲（同门面借用语义）
    port: u16 = 0,
};
pub const Callback = *const fn (settings: *const ProxySettings, ctx: ?*anyopaque) void;

pub const ProxyMonitor = struct { // 平台实现经 Impl comptime 分派
    pub fn init(allocator: std.mem.Allocator) !ProxyMonitor;
    pub fn start(self: *ProxyMonitor) !void;
    pub fn subscribe(self: *ProxyMonitor, cb: Callback, ctx: ?*anyopaque) !void;
    pub fn snapshot(self: *ProxyMonitor) ?ProxySettings; // 当前生效值；null = 尚未观测
    pub fn close(self: *ProxyMonitor) void;
    pub fn deinit(self: *ProxyMonitor) void;
};
```

- **语义边界**：只面向「显式代理服务器」host:port。仅 PAC/WPAD 启用时无法表示为 host:port，
  视为 `enabled=false`（消费方如需感知 PAC 请另行读取）。
- 变化才 emit（平台内部比较去重）；回调在后台线程触发。

### 4.3 系统 DNS 变化监测 `dns_monitor`（分平台，comptime 分派，本补丁）

监听系统 DNS 服务器配置的**独立变化**（macOS SCDynamicStore「State:/Network/Global/DNS」/
Windows 注册表 RegNotify / Linux inotify），路由 / 网卡未变时单独改 DNS 也能独立上报——
第 4 子监测（此前 DNS 仅靠门面对 network 快照 diff 的附带监测）。

```zig
pub const DnsSettings = struct {
    servers: []const zf.net.IpAddr = &.{}, // 借用 monitor 内部缓冲（同门面借用语义）
};
pub const Callback = *const fn (settings: *const DnsSettings, ctx: ?*anyopaque) void;

pub const DnsMonitor = struct { // 平台实现经 Impl comptime 分派
    pub fn init(allocator: std.mem.Allocator) !DnsMonitor;
    pub fn start(self: *DnsMonitor) !void;
    pub fn subscribe(self: *DnsMonitor, cb: Callback, ctx: ?*anyopaque) !void;
    pub fn snapshot(self: *DnsMonitor) ?DnsSettings; // 当前生效值；null = 尚未观测（stub 恒 null）
    pub fn close(self: *DnsMonitor) void;
    pub fn deinit(self: *DnsMonitor) void;
};
```

| 平台 | 事件源 | 状态 |
|---|---|---|
| macOS | SCDynamicStore「State:/Network/Global/DNS」 | 完整实现 + 真事件 |
| Windows | `RegNotifyChangeKeyValue` 递归监听 `HKLM\...\Tcpip\Parameters\Interfaces` | 源码实现，真事件待 VM 验证 |
| Linux | inotify `/etc/resolv.conf`（+ mtime diff 兜底） | 源码实现，真事件待 VM 验证 |
| iOS | （darwin 后端，SCDynamicStore 沙箱不可用）内部恒 no-op | DNS 由注入承载 |
| Android / 其他 | stub 恒 no-op（`snapshot()` 恒 null） | DNS 由注入承载 |

- **语义要点**：读取与 network 门面同源 `network_params.queryDnsServers`，保证 diff 判定一致；
  空列表（无 DNS / 读失败）是合法状态，仍 emit；平台内部逐地址 `ipEqual` 去重，仅真变化 emit。
- **借用语义**：回调 `settings.servers` 与 `snapshot().servers` 均指向 monitor 内部缓冲，
  仅在下一次变化 / deinit 前有效；持久持有须自行 `dupe`（同门面 §2）。
- **门面集成**：`Monitor` 订阅后经 `handleDns` 将快照 `dns_servers` 覆盖为 dns_monitor 新鲜值，
  与 network「接口 + DNS 同变」在门面 1s 去抖窗口合并 → 恰好一次粗回调。

### 4.4 network 门面 `network`（高级；re-export 自 zf.network #43）

全局单例 + 统一回调 + `NetworkInfo` 完整快照。事件源（AF_ROUTE / netlink / iphlpapi）
与默认接口判定（平台分文件 + 1s 防抖）在内部消化。

```zig
pub const NetworkInfo = struct {
    default_interface: ?Interface = null,
    gateway: ?types.IpAddr = null,
    dns_servers: []const types.IpAddr = &.{},
    flags: ChangeFlags = .{},
    android_vpn_enabled: bool = false,
};
pub const Interface = struct {
    index: u32, mtu: u32, name: [64]u8, name_len: usize,
    addresses: []const types.AddressInfo, up: bool,
};
pub const ChangeFlags = packed struct(u8) { interface_changed: bool, no_route: bool, android_vpn: bool, _pad: u5 };
pub const NetworkChangeCallback = *const fn (info: *const NetworkInfo, ctx: ?*anyopaque) void;

pub fn init(allocator: std.mem.Allocator, opts: Opt) !void;   // 幂等（不重复建线程）
pub fn start() !void;                                         // 幂等；NoDefaultRoute 非致命
pub fn close() void;                                          // 幂等，保留订阅可 restart
pub fn deinit() void;                                         // 彻底释放（可重新 init）
pub fn subscribe(cb: NetworkChangeCallback, ctx: ?*anyopaque) !void; // 注册网络变化回调
pub fn unsubscribe(cb: NetworkChangeCallback, ctx: ?*anyopaque) void;
pub fn snapshot() NetworkInfo;                                // 借用：有效至下次 rebuild / close
pub fn injectPlatformInfo(info: PlatformInjectedInfo) void;   // iOS NE / Android 受限环境注入
pub fn queryDefaultGateway() ?types.IpAddr;                  // 轻量查询，无单例依赖
pub fn queryAllAddresses(allocator: std.mem.Allocator) ![]types.IpAddr; // 枚举全部接口地址
```

- 快照/回调的 `NetworkInfo` 指向单例内部缓冲，**下次 rebuild 前有效**。
- 回调在防抖线程上下文触发（同步语义），禁止阻塞。

### 4.5 系统代理副作用 `system_proxy`（re-export 自 zf.system_proxy #79）

无状态原语：set / restore 宿主系统代理（系统代理 + 环境变量注入），供消费方自行编排。
**与 `proxy_monitor` 不同**：本模块是「主动设置/恢复」的副作用，非监测。

```zig
pub const ProxyError = error{ EnableFailed };
pub const Diag = struct { /* init/deinit/add/addFmt/slice */ };

pub fn setProxy(allocator: std.mem.Allocator, host: []const u8, port: u16,
                support_socks: bool, diag: *Diag) ProxyError!void; // 失败 EnableFailed + diag 累积系统原始错误
pub fn restoreProxy(allocator: std.mem.Allocator, support_socks: bool) void; // best-effort，失败仅 warn
pub fn normalizeProxyHost(listen: []const u8) []const u8; // unspecified(0.0.0.0/::) → 127.0.0.1
```

---

## 5. 可观测：`ZF_NETWORK_TRACE`

设置 `ZF_NETWORK_TRACE=1` 开启 **info 级全流程日志**，可还原一次变化的完整处理链
（design.md §5/§6）——测试/排障时能看见「事件源收到 → 归一化 diff → 去抖 → 事件分发」每一步。

- **默认关闭**（无日志开销）。实现为门面内 `traceEnabled()` 读环境变量一次并缓存
  （POSIX `getenv` / Windows `kernel32.GetEnvironmentVariableA`，comptime 剪枝）。
- 日志经 `zf.log`（`std.log` + `[monitor]`/`[hosts]`/`[proxy]`/`[dns]` 前缀 + 英文 ASCII）。
- 运行时设置示例：

```bash
ZF_NETWORK_TRACE=1 zigbox -c config.json   # 消费方进程开启 trace
```

预期 trace 输出形态（示意）：

```
[monitor] source=network iface=5 name=en0
[monitor] diff route=true default_route=false interface=false dns=true
[monitor] dispatch network-changed subscribers=1
```

`diff route=… default_route=… interface=… dns=…` 是内部诊断（ChangeKind 各字段），
trace 下可见「哪类字段变了」；派发统一为 `dispatch network-changed`（恰好一次）。

---

## 6. 测试（三层架构）

三层测试对应 `design.md` §6，业务需求驱动：**任一类网络设置变化 → 消费方恰好收到一次
「网络变了」回调，且快照承载变化后的新状态。**

### Tier 1 — 单元 / 注入（host 本机，确定性，无 OS 事件）

```bash
zig build                       # 构建库（ReleaseSafe）
zig build test                  # 单元测试（当前 61/61，含注入路径 + dns_monitor 独立变化）
zig build test -Doptimize=Debug # 调试内存泄漏
```

- `Monitor.injectPlatformInfo(...)` 走与真实事件**完全相同**的 diff/dispatch 路径（确定性触发）。
- 覆盖：diff 判定（哪类字段变了 → 是否触发）、基线语义（首事件建基线不派发）、去重（相同
  事件不派发）、去抖、快照借用、生命周期（start/close 幂等 + 重启）、移动注入路径、
  dns_monitor 独立变化注入（handleDns 恰好一次粗回调 + 快照 dns_servers 覆盖新鲜值）。
- 平台无关，`zig build test` 全绿；集成经 zigtester（`unit/all-tests`，见 `zigtester.yaml`）。

### Tier 2 — 真实事件源（macvm / linuxvm / windowsvm）

- **harness**：`zig build real_event` → `zig-out/bin/real_event`
  （`tests/real_event_harness.zig`）——订阅 Monitor 粗回调，每收到一次向 stdout 打印一行
  `CHANGED iface=... gw=...`，运行满秒数退出 0（订阅阻塞类测试工具，不接入构建门禁）。
- **驱动脚本**（nohup 自愈，ssh 断开仍继续；平台门禁——本机误跑自动 SKIP）：
  - `tests/scripts/macos_real_event.sh` — route（sudo route 加删 TEST-NET）/ hosts
  - `tests/scripts/linux_real_event.sh` — route（netlink）/ resolv.conf / hosts
  - `tests/scripts/windows_real_event.ps1` — route（INFO）+ hosts + 代理（RegNotify）
- **断言**：触发真实 OS 事件后，运行窗口内日志新增 ≥1 行 CHANGED，且快照反映新状态。
- 三 VM 经 vm-regression 白名单接入（zigbox `tests/vm/vm-regression.sh` 先例）。脚本会临时改
  系统路由 / hosts / resolv（随即恢复），**开发本机禁止执行**。

### Tier 3 — 移动端（iOS / Android，注入为主，无真机）

- **iOS**：模拟 NE 桥 `injectPlatformInfo`（NWPathMonitor 等价信息）→ monitor 触发。
- **Android**：模拟 JNI 桥注入（ConnectivityManager / LinkProperties 等价信息）→ monitor 触发。
- **能力边界断言**（Tier1 单测锁定）：移动端 `defaultHostsPath()==""`、proxy_monitor 归 stub、
  hosts / proxy 不产生事件——锁定「移动无 hosts / 系统代理」语义。真实设备 E2E 为集成级，后续再说。
