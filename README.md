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

## 快速开始

```bash
zig build          # 构建库（ReleaseSafe）
zig build test     # 运行单元测试
```

## 依赖

- **Zig 0.16.0**
- **zigfoundation**（唯一实现源：net/endian/platform/alloc/log）

## 可观测

设置 `ZF_NETWORK_TRACE=1`，收到任何网络变化事件时打印全流程 info 日志，可还原一次变化的完整处理链。

## 参考实现

设计参照了生产级项目的网络变化处理（见 CLAUDE.md + findings.md）：

- nthlink（抗封锁工具，主动健康探测）
- ProtonVPN（生产级 VPN，Kill Switch / 重连状态机）
- sing-box / mihomo / Xray-core（协议侧，两层事件源）
