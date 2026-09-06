#!/usr/bin/env bash
# ============================================================================
# linux_real_event.sh — zignetmon Tier2 linuxvm 真实事件源验证（design.md §6）
#
# 用途：用 harness 二进制（zig-out/bin/real_event：订阅 Monitor 粗回调，每次回调向
# stdout 打一行 "CHANGED ..."，跑满 argv[1] 秒 exit 0）触发三类真实 OS 事件，断言在
# 各自观察窗口内 harness 日志新增 ≥1 行 CHANGED —— 对应验收准则「任一类网络设置变化
# → 消费方恰好收到一次『网络变了』粗回调」。
#
# 子项与触发（各子项独立 PASS/FAIL/SKIP，互不阻断）：
#   route   ip route add 198.51.100.0/24 via <默认网关>（TEST-NET-1，驱动 netlink）
#           等待观察 → ip route del 清理
#   resolv  /etc/resolv.conf：备份 → 临时前置测试 nameserver → 等待 → 恢复
#   hosts   /etc/hosts：备份 → 临时追加一行 → 等待 → 恢复
#
# 模式：nohup 后台启动 harness 写日志（ssh 断开自愈，harness 继续；日志残留可事后
# 诊断）→ 就绪等待（[monitor] started + hosts 基线）→ 逐子项触发 → 观察窗口 → 校验
# CHANGED 增量 → 清理（杀 harness、恢复路由/resolv/hosts、清日志）。
#
# 权限：route / 写 /etc 下文件需 root 能力。root 直接执行；非 root 探测 sudo -n
# （passwordless），无则对应子项 SKIP（不判失败，便于无特权 CI 跑其它子项）。
# 不改用户持久系统代理：Linux 系统代理为 GNOME dconf 桌面路径，headless linuxvm 无
# 此语义（proxy_monitor_linux 归 no-op），本脚本不触碰 dconf。
#
# 零配置：harness 路径相对脚本位置自动推导（REPO_ROOT/tests/scripts/../..）。
# 失败可读：每子项明确「哪步/期望(≥1 CHANGED)/实际(delta)」，FAIL 时输出 harness 日志尾。
#
# 用法：tests/scripts/linux_real_event.sh        （root 或 passwordless sudo 用户）
# 退出：0 = 全部执行子项 PASS（全 SKIP 亦 0）；1 = 任一执行子项 FAIL
# 目标：Linux（linuxvm / 容器），勿在 macOS/Windows 跑特权路由操作。
# ============================================================================
set -u
set -o pipefail

# ---- Linux only：防止误在本机（macOS）跑特权路由操作 ----
if [ "$(uname -s)" != "Linux" ]; then
  echo "[linux_real_event] SKIP: linux only (current=$(uname -s))"
  exit 0
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
HARNESS="$REPO_ROOT/zig-out/bin/real_event"
LOG="$REPO_ROOT/tests/scripts/linux_real_event.log"

# ---- 时间参数（可调；hosts 轮询 ≤5s，观察窗口须 > 一轮） ----
SETTLE_S=6            # 就绪后额外等待：hosts 基线首轮 stat 在 start 后 ~5s
READY_TIMEOUT_S=30    # 等 harness 就绪日志超时
ROUTE_OBSERVE_S=6     # route 观察窗口（netlink 事件 → 1s 防抖 → 重查余量）
DNS_OBSERVE_S=6       # resolv 观察窗口
HOSTS_OBSERVE_S=8     # hosts 观察窗口（轮询 5s + 分派余量）
HARNESS_RUN_S=120     # harness 总时长（须覆盖全部阶段；阶段结束由脚本 kill）

# ---- 触发用保留地址/内容（RFC 5737 TEST-NET + RFC 6761 .invalid，无副作用） ----
TESTNET_ROUTE="198.51.100.0/24"      # TEST-NET-1（198.51.100.0/24）
TESTNET_RESOLV_NS="192.0.2.53"       # TEST-NET-2
TESTNET_HOSTS_LINE="192.0.2.250 netmon-test.invalid"

# ---- 全局状态/计数 ----
PASS=0; FAIL=0; SKIP=0
HARNESS_PID=""
RESOLV_MODIFIED=0; RESOLV_WAS_LINK=0; RESOLV_LINK_TARGET=""; RESOLV_BACKUP=""
HOSTS_MODIFIED=0; HOSTS_BACKUP=""
ROUTE_ADDED=0

log() { echo "[linux_real_event] $*"; }
die() { echo "[linux_real_event] FATAL: $*" >&2; exit 1; }

# 当前日志中 CHANGED 行数（harness 每次粗回调打一行，机器可解析）
count_changed() { grep -c '^CHANGED' "$LOG" 2>/dev/null || true; }

# 提权执行：root 直跑，否则 passwordless sudo（调用前已 gate 能力）
priv() {
  if [ "$(id -u)" -eq 0 ]; then "$@"; else sudo -n "$@"; fi
}

# 是否有 root 能力（root 或 passwordless sudo）
can_root() {
  [ "$(id -u)" -eq 0 ] && return 0
  command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1
}

# ============================================================================
# 恢复函数（幂等；正常路径调用 + EXIT trap 兜底，保证 ssh 中断外的残留清理）
# ============================================================================
restore_resolv() {
  [ "$RESOLV_MODIFIED" -ne 1 ] && return
  if [ "$RESOLV_WAS_LINK" -eq 1 ]; then
    priv rm -f /etc/resolv.conf
    priv ln -s "$RESOLV_LINK_TARGET" /etc/resolv.conf
  else
    [ -n "$RESOLV_BACKUP" ] && priv cp -f "$RESOLV_BACKUP" /etc/resolv.conf
  fi
  [ -n "$RESOLV_BACKUP" ] && rm -f "$RESOLV_BACKUP"
  RESOLV_MODIFIED=0; RESOLV_BACKUP=""
}

restore_hosts() {
  [ "$HOSTS_MODIFIED" -ne 1 ] && return
  [ -n "$HOSTS_BACKUP" ] && priv cp -f "$HOSTS_BACKUP" /etc/hosts
  [ -n "$HOSTS_BACKUP" ] && rm -f "$HOSTS_BACKUP"
  HOSTS_MODIFIED=0; HOSTS_BACKUP=""
}

cleanup() {
  # 1) 杀 harness（如还活着）
  if [ -n "$HARNESS_PID" ] && kill -0 "$HARNESS_PID" 2>/dev/null; then
    kill "$HARNESS_PID" 2>/dev/null
    wait "$HARNESS_PID" 2>/dev/null || true
  fi
  # 2) 恢复未完成的系统编辑（route / resolv / hosts）
  if [ "$ROUTE_ADDED" -eq 1 ]; then
    priv ip route del "$TESTNET_ROUTE" >/dev/null 2>&1 || true
    ROUTE_ADDED=0
  fi
  restore_resolv
  restore_hosts
  # 3) 清日志
  rm -f "$LOG"
}
trap cleanup EXIT

# 子项结果记录
pass() { PASS=$((PASS+1)); echo "  [PASS] $1"; }
fail() { FAIL=$((FAIL+1)); echo "  [FAIL] $1"; }
skip() { SKIP=$((SKIP+1)); echo "  [SKIP] $1"; }

# ============================================================================
# 前置：harness 存在（缺失则尝试构建）
# ============================================================================
if [ ! -x "$HARNESS" ]; then
  if command -v zig >/dev/null 2>&1; then
    log "harness missing, building (zig build real_event)"
    (cd "$REPO_ROOT" && zig build real_event) || die "zig build real_event failed"
  else
    die "harness not found: $HARNESS (run 'zig build' 先构建)"
  fi
fi

# ============================================================================
# 前置：root 能力。三个子项都需写 /etc / 路由；无则全 SKIP（不启动 harness）
# ============================================================================
if ! can_root; then
  log "no root capability (uid=$(id -u), no passwordless sudo) — 子项全 SKIP"
  for s in route resolv hosts; do skip "$s (no root/passwordless sudo)"; done
  echo "ALL-SKIPPED: no root capability, nothing to assert"
  exit 0
fi

# ============================================================================
# 启动 harness（nohup 后台，stdout+stderr 写日志；ssh 断开后 harness 继续自愈）
# ============================================================================
rm -f "$LOG"
mkdir -p "$(dirname "$LOG")"
log "starting harness: $HARNESS $HARNESS_RUN_S"
ZF_NETWORK_TRACE=1 nohup "$HARNESS" "$HARNESS_RUN_S" >>"$LOG" 2>&1 &
HARNESS_PID=$!
log "harness pid=$HARNESS_PID log=$LOG (ZF_NETWORK_TRACE=1 全流程 info 日志可还原处理链)"

# ---- 就绪等待：Monitor.start 完成（日志出现 [monitor] started）或进程退出 ----
ready=0; elapsed=0
while [ "$elapsed" -lt "$READY_TIMEOUT_S" ]; do
  if ! kill -0 "$HARNESS_PID" 2>/dev/null; then
    echo "---- harness 提前退出，日志尾 ----"; tail -20 "$LOG"
    die "harness exited early (pid=$HARNESS_PID)"
  fi
  if grep -q '\[monitor\] started' "$LOG" 2>/dev/null; then ready=1; break; fi
  sleep 1; elapsed=$((elapsed+1))
done
if [ "$ready" -ne 1 ]; then
  log "warn: '[monitor] started' 未见（${READY_TIMEOUT_S}s，进程存活，按固定 settle 兜底）"
fi
# hosts 基线（monitor start 后首轮 stat ~5s）建立，再进入事件阶段
sleep "$SETTLE_S"
log "harness ready, 基线已建立"

# ============================================================================
# [1/3] route 事件：ip route add/del TEST-NET-1 via 默认网关 → 驱动 netlink
# ============================================================================
echo "== [1/3] route 事件（netlink: ip route add/del $TESTNET_ROUTE via <默认网关>）=="
c0=$(count_changed)
GW="$(ip -4 route show default 2>/dev/null | awk '/^default/{print $3; exit}')"
case "$GW" in
  *[!0-9.]*) GW="" ;;   # 非 v4 字面量（如 onlink 无 via）→ 不作为网关
esac
if [ -z "$GW" ]; then
  skip "route (无 IPv4 默认网关可作 via)"
else
  # 清残留后添加（驱动 netlink RTM_NEWROUTE 多播事件）
  priv ip route del "$TESTNET_ROUTE" 2>/dev/null || true
  if priv ip route add "$TESTNET_ROUTE" via "$GW"; then
    ROUTE_ADDED=1
    log "route added: $TESTNET_ROUTE via $GW；观察 ${ROUTE_OBSERVE_S}s"
    sleep "$ROUTE_OBSERVE_S"
    c1=$(count_changed)
    delta=$((c1 - c0))
    log "route removed: $TESTNET_ROUTE"
    priv ip route del "$TESTNET_ROUTE" 2>/dev/null || true
    ROUTE_ADDED=0
    if [ "$delta" -eq 0 ]; then
      pass "route（非默认路由 add/del 未产生伪信号，delta=0，正确）"
    else
      fail "route：非默认路由变化产生 ${delta} 次伪信号（期望 0，默认出口未变）"
    fi
  else
    fail "route：ip route add 失败（via $GW）"
  fi
fi

# ============================================================================
# [2/3] resolv.conf DNS 事件：备份 → 临时前置测试 nameserver → 观察 → 恢复
# ============================================================================
echo "== [2/3] resolv.conf DNS 事件（备份 /etc/resolv.conf → 临时改 → 恢复）=="
c0=$(count_changed)
if [ ! -e /etc/resolv.conf ] && [ ! -L /etc/resolv.conf ]; then
  skip "resolv (/etc/resolv.conf 不存在)"
else
  RESOLV_BACKUP="$(mktemp)"
  cp -L /etc/resolv.conf "$RESOLV_BACKUP"     # -L：symlink（systemd-resolved）取目标内容
  if [ -L /etc/resolv.conf ]; then
    RESOLV_WAS_LINK=1
    RESOLV_LINK_TARGET="$(readlink /etc/resolv.conf)"
  fi
  RESOLV_MODIFIED=1                            # 标记，任一步失败 EXIT trap 也恢复
  # 替换为「测试 nameserver 前缀 + 原内容」：短暂前缀不影响 headless VM（harness 无 DNS 依赖）
  priv rm -f /etc/resolv.conf
  { printf 'nameserver %s\n' "$TESTNET_RESOLV_NS"; cat "$RESOLV_BACKUP"; } | priv tee /etc/resolv.conf >/dev/null
  log "resolv.conf 已临时改动（前置 nameserver $TESTNET_RESOLV_NS）；观察 ${DNS_OBSERVE_S}s"
  sleep "$DNS_OBSERVE_S"
  c1=$(count_changed)
  delta=$((c1 - c0))
  restore_resolv
  log "resolv.conf 已恢复（原 symlink/文件形态）"
  if [ "$delta" -ge 1 ]; then
    pass "resolv（窗口内 CHANGED+${delta}，期望 ≥1）"
  else
    fail "resolv：期望 ≥1 行 CHANGED，实际 ${delta}（已临时改写 /etc/resolv.conf nameserver）"
  fi
fi

# ============================================================================
# [3/3] hosts 事件：备份 /etc/hosts → 追加一行 → 观察 → 恢复
# ============================================================================
echo "== [3/3] hosts 事件（备份 /etc/hosts → 追加 → 恢复）=="
c0=$(count_changed)
HOSTS_BACKUP="$(mktemp)"
cp /etc/hosts "$HOSTS_BACKUP"
HOSTS_MODIFIED=1
printf '%s\n' "$TESTNET_HOSTS_LINE" | priv tee -a /etc/hosts >/dev/null
log "hosts 已追加: $TESTNET_HOSTS_LINE；观察 ${HOSTS_OBSERVE_S}s（hosts 轮询 ≤5s）"
sleep "$HOSTS_OBSERVE_S"
c1=$(count_changed)
delta=$((c1 - c0))
restore_hosts
log "hosts 已恢复原内容"
if [ "$delta" -ge 1 ]; then
  pass "hosts（窗口内 CHANGED+${delta}，期望 ≥1）"
else
  fail "hosts：期望 ≥1 行 CHANGED，实际 ${delta}（已临时向 /etc/hosts 追加 ${TESTNET_HOSTS_LINE}）"
fi

# ============================================================================
# 汇总：任一 FAIL 输出 harness 日志尾（含 ZF_NETWORK_TRACE diff 链）诊断后 exit 1
# ============================================================================
echo
echo "==== 结果汇总（期望每执行子项窗口内 ≥1 行 CHANGED）===="
echo "  PASS=$PASS  FAIL=$FAIL  SKIP=$SKIP"
if [ "$FAIL" -gt 0 ]; then
  echo "---- harness 日志尾部（诊断：monitor 若收到事件应打 [monitor] source=.../diff .../dispatch）----"
  tail -30 "$LOG"
  exit 1
fi
exit 0
