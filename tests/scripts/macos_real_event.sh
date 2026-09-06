#!/usr/bin/env bash
#
# macos_real_event.sh — zignetmon Tier2 真实事件源验证脚本（macOS / macvm 专用）
#
# 目标（design.md §6 Tier2 + task_plan 遗留 #2）：用 harness 二进制
#   tests/real_event_harness.zig → zig-out/bin/real_event
# 订阅 zignetmon Monitor 门面的「网络变了」粗回调，触发真实 OS 事件，断言日志
# 出现 ≥1 行 CHANGED（harness 每次粗回调打印一行 "CHANGED iface=... gw=..."）。
#
# 覆盖子项（各自独立 PASS/FAIL/SKIP，可读失败：报期望/实际 CHANGED 新增计数）：
#   [route] sudo route add/delete 198.51.100.0/24（RFC 5737 TEST-NET-2 文档保留段，
#           加删不影响真实流量）→ 驱动 AF_ROUTE → 期望 harness 收到 ≥1 次 CHANGED
#   [hosts] 临时向 /etc/hosts 追加一行 → stat diff（后台 5s 轮询）→ 期望 ≥1 次 CHANGED
#           → 精确恢复原始内容（不残留任何用户系统改动）
#
# 脚本模式（nohup 自愈，ssh 断开仍继续）：
#   启动 harness（nohup 后台写日志）→ sleep 等就绪 → 触发真实 OS 事件 → sleep 观察
#   窗口 → 检查日志新增 CHANGED → trap EXIT 统一清理（杀 harness / 还原 hosts /
#   删 TEST-NET 路由 / 清日志目录）。
#
# 约束：
#   - 仅 macOS（macvm）。hosts 编辑与 route 加删均需 root → 脚本需以 root 直接运行，
#     或具备免密 sudo（sudo -n 探测，无则对应子项 SKIP 并说明）。
#   - 本脚本只经 vm-regression 在 macvm 上运行；开发本机禁止执行（改动本机 /etc/hosts
#     与路由表，即使会恢复）。
#   - 不改用户持久系统代理：本脚本不触发代理事件，因此绝不动系统代理设置。
#
# 用法：
#   sudo ./tests/scripts/macos_real_event.sh        # macvm root 直接运行（推荐）
#   ./tests/scripts/macos_real_event.sh             # 非 root，走 sudo -n（需免密 sudo）
#
# 环境变量覆盖（可选，全部有默认值）：
#   ZNM_HARNESS             harness 二进制路径（默认 $ROOT/zig-out/bin/real_event）
#   ZNM_RUN_SECONDS         harness 运行总秒数（默认 45，最小钳到 40）
#   ZNM_READY_TIMEOUT       等就绪日志（[monitor] started）超时秒数（默认 20）
#   ZNM_ROUTE_OBSERVE       route add 后观察秒数（默认 6）
#   ZNM_ROUTE_SETTLE        route delete 后沉降秒数（默认 2）
#   ZNM_HOSTS_BASELINE      距 harness 启动至少等待秒数，确保 hosts 基线已建（默认 8）
#   ZNM_HOSTS_OBSERVE       hosts 追加后观察秒数（默认 9，覆盖 5s 轮询 + 裕量）
#   ZNM_HOSTS_FINAL         恢复 hosts 后沉降秒数（默认 2）
#
# 退出码：任一子项 FAIL → 1；全部 PASS / SKIP → 0。

set -u   # 未定义变量即报错。刻意不用 set -e：多个命令的预期失败需精细处理。

# ============================================================================
# 常量 / 全局状态
# ============================================================================

# RFC 5737 TEST-NET-2 文档保留段（安全：真实流量永不使用）
ROUTE_NET="198.51.100.0"
ROUTE_MASK="255.255.255.0"
# hosts marker：追加用的映射 + 唯一 token（token 用于崩溃残留的幂等清理）
MARKER_TOKEN="zignetmon-realevent"
MARKER_IP="198.51.100.250"
MARKER_HOST="zignetmon-realevent-$$.invalid"

RUN_AS_ROOT=0;  [ "$(id -u)" = "0" ] && RUN_AS_ROOT=1
CAN_SUDO=0
# 特权探测：root 直接运行即有特权；否则探免密 sudo（sudo -n true）。
[ "$RUN_AS_ROOT" = "1" ] && CAN_SUDO=1
if [ "$CAN_SUDO" != "1" ] && command -v sudo >/dev/null 2>&1; then
    sudo -n true >/dev/null 2>&1 && CAN_SUDO=1
fi
SUDO_HINT="需 root 直接运行或免密 sudo（sudo -n）"

# harness / 计时 / 结果 / 残留守卫（set -u 下先给默认值）
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HARNESS="${ZNM_HARNESS:-$ROOT/zig-out/bin/real_event}"
RUN_SECONDS="${ZNM_RUN_SECONDS:-45}"
[ "$RUN_SECONDS" -lt 40 ] && RUN_SECONDS=40
READY_TIMEOUT="${ZNM_READY_TIMEOUT:-20}"
ROUTE_OBSERVE="${ZNM_ROUTE_OBSERVE:-6}"
ROUTE_SETTLE="${ZNM_ROUTE_SETTLE:-2}"
HOSTS_BASELINE="${ZNM_HOSTS_BASELINE:-8}"
HOSTS_OBSERVE="${ZNM_HOSTS_OBSERVE:-9}"
HOSTS_FINAL="${ZNM_HOSTS_FINAL:-2}"

LOG="";            PIDFILE="";    DIR="";            HARNESS_PID=""
HARNESS_START_SEC=0;              ROUTE_STATE="SKIP"; HOSTS_STATE="SKIP"
ROUTE_ADDED=0;                    ROUTE_GW=""
HOSTS_BAK=""

# ============================================================================
# 辅助
# ============================================================================

say()   { printf '%s\n' "$*"; }
fatal() { say "[FATAL] $*"; exit 1; }

# 以 root（或 sudo -n）执行。无特权时返回 1（调用方以 || true 兜底）。
run_priv() {
    if [ "$CAN_SUDO" != "1" ]; then return 1; fi
    if [ "$RUN_AS_ROOT" = "1" ]; then "$@"; else sudo -n "$@"; fi
}

# 日志中 CHANGED 行计数（harness stdout 直写；grep 无匹配时 -c 输出 0 且退出 1）
count_changed() {
    grep -c 'CHANGED' "$LOG" 2>/dev/null || true
}

# 幂等删除 TEST-NET 路由（按目的段删除，网关可选；供预清理/事后回收）
del_testnet_route() {
    local gw="${1:-}"
    if [ -n "$gw" ]; then
        run_priv route -n delete -net "$ROUTE_NET" -netmask "$ROUTE_MASK" "$gw" >/dev/null 2>&1 || true
    fi
    run_priv route -n delete -net "$ROUTE_NET" -netmask "$ROUTE_MASK" >/dev/null 2>&1 || true
}

# harness 进程是否存活（需与启动同特权才能 kill -0）
harness_alive() {
    [ -n "$HARNESS_PID" ] || return 1
    if [ "$RUN_AS_ROOT" = "1" ]; then
        kill -0 "$HARNESS_PID" 2>/dev/null
    else
        sudo -n kill -0 "$HARNESS_PID" 2>/dev/null
    fi
}

# 杀 harness（SIGTERM 默认即终止；等 2s 让进程退出，避免清日志时文件仍被占用）
kill_harness() {
    [ -n "$HARNESS_PID" ] || return 0
    if [ "$RUN_AS_ROOT" = "1" ]; then
        kill "$HARNESS_PID" 2>/dev/null || true
    else
        sudo -n kill "$HARNESS_PID" 2>/dev/null || true
    fi
    sleep 2
    HARNESS_PID=""
}

# 距离 harness 启动已过去秒数
elapsed_since_harness() {
    echo $(( $(date +%s) - HARNESS_START_SEC ))
}

# 等到距 harness 启动 ≥ need 秒（保证 hosts 首次 stat 轮询已建基线）
wait_elapsed() {
    local need="$1" now
    now="$(elapsed_since_harness)"
    if [ "$now" -lt "$need" ]; then
        say "[hosts] 等待 hosts 基线建立（距 harness 启动 ${now}s < 需求 ${need}s）..."
        sleep $(( need - now ))
    fi
}

# ============================================================================
# 子项：route — sudo route add/delete TEST-NET 驱动 AF_ROUTE
# ============================================================================
run_route() {
    say ""
    say "=== [route] sudo route add/delete ${ROUTE_NET}/24 驱动 AF_ROUTE ==="

    # 取默认网关作为 nexthop（route add 需可达网关）；无默认路由则 SKIP 并说明。
    ROUTE_GW="$(route -n get default 2>/dev/null | awk '/gateway:/ {print $2; exit}')"
    if [ -z "$ROUTE_GW" ]; then
        ROUTE_GW="$(netstat -rn -f inet 2>/dev/null | awk '$1=="default" && $2!="link#" {print $2; exit}')"
    fi
    if [ -z "$ROUTE_GW" ]; then
        say "[route] SKIP：未取到默认网关（route -n get default / netstat 均失败）——AF_ROUTE 需默认接口"
        return 0
    fi

    # 先清上次崩溃可能残留的同段路由（幂等），再建计数基线
    del_testnet_route
    sleep 1
    local base now delta
    base="$(count_changed)"

    # add：失败即 FAIL（可读 stderr）
    if ! run_priv route -n add -net "$ROUTE_NET" -netmask "$ROUTE_MASK" "$ROUTE_GW" >/dev/null 2>"$DIR/route_add.err"; then
        say "[route] FAIL：route add 失败 — stderr: $(cat "$DIR/route_add.err" 2>/dev/null)"
        ROUTE_STATE="FAIL"
        return 0
    fi
    ROUTE_ADDED=1
    say "[route] 已 add ${ROUTE_NET}/24 via ${ROUTE_GW}，观察 ${ROUTE_OBSERVE}s（覆盖 AF_ROUTE 读 + 1s 防抖）..."

    sleep "$ROUTE_OBSERVE"
    now="$(count_changed)"; delta=$(( now - base ))
    say "[route] 观察窗口 CHANGED 新增 ${delta}（期望 ≥1）"

    # delete（无论结果都执行，ROUTE_ADDED 置 0）
    run_priv route -n delete -net "$ROUTE_NET" -netmask "$ROUTE_MASK" "$ROUTE_GW" >/dev/null 2>&1 || true
    ROUTE_ADDED=0
    sleep "$ROUTE_SETTLE"

    if [ "$delta" -eq 0 ]; then
        say "[route] PASS：非默认路由 add/delete 未产生伪「网络变了」信号（默认出口未变，正确）"
        ROUTE_STATE="PASS"
    else
        say "[route] FAIL：非默认路由变化产生了 ${delta} 次伪信号 —— 应 0（默认出口未变）"
        ROUTE_STATE="FAIL"
    fi
}

# ============================================================================
# 子项：hosts — 临时追加 /etc/hosts → stat diff(5s) 应触发
# ============================================================================
run_hosts() {
    say ""
    say "=== [hosts] 临时追加 /etc/hosts 一行 → stat diff（5s 轮询）应触发 ==="

    # 关键时序：hosts_monitor 首次成功 stat 只建基线不发事件；若在基线前改动 hosts，
    # 该改动会被当基线吞掉。必须等距启动 ≥ HOSTS_BASELINE 秒（首轮 5s 轮询后）。
    wait_elapsed "$HOSTS_BASELINE"

    # 上次崩溃残留 marker 先清理（幂等）
    if grep -q "$MARKER_TOKEN" /etc/hosts 2>/dev/null; then
        say "[hosts] 检测到上次残留 marker，先清理（幂等）"
        run_priv sed -i '' "/$MARKER_TOKEN/d" /etc/hosts || true
        sleep 2
    fi

    # 备份当前原始内容（/etc/hosts 世界可读，普通 cp 即可，无需特权）
    HOSTS_BAK="$DIR/hosts.backup"
    if ! cp /etc/hosts "$HOSTS_BAK" 2>"$DIR/hosts_cp.err"; then
        say "[hosts] FAIL：备份 /etc/hosts 失败 — $(cat "$DIR/hosts_cp.err" 2>/dev/null)"
        HOSTS_STATE="FAIL"
        HOSTS_BAK=""
        return 0
    fi

    local line base now delta
    line="${MARKER_IP} ${MARKER_HOST} # ${MARKER_TOKEN} (zignetmon real-event, pid $$)"
    base="$(count_changed)"

    # 追加一行（tee -a 经 root 写，避免 sh -c 引号转义）
    if ! printf '%s\n' "$line" | run_priv tee -a /etc/hosts >/dev/null; then
        say "[hosts] FAIL：追加 marker 到 /etc/hosts 失败（尝试还原）"
        run_priv cp "$HOSTS_BAK" /etc/hosts 2>/dev/null || true
        rm -f "$HOSTS_BAK"; HOSTS_BAK=""
        HOSTS_STATE="FAIL"
        return 0
    fi
    say "[hosts] 已追加 marker 一行，观察 ${HOSTS_OBSERVE}s（覆盖 5s stat diff 轮询）..."

    sleep "$HOSTS_OBSERVE"
    now="$(count_changed)"; delta=$(( now - base ))
    say "[hosts] 观察窗口 CHANGED 新增 ${delta}（期望 ≥1）"

    # 恢复：从备份整文件写回（保持 /etc/hosts 的 inode/owner/权限，只覆盖内容）
    if run_priv cp "$HOSTS_BAK" /etc/hosts 2>"$DIR/hosts_restore.err"; then
        rm -f "$HOSTS_BAK"; HOSTS_BAK=""
        say "[hosts] 已从备份精确恢复 /etc/hosts 原始内容"
    else
        say "[hosts] 警告：恢复 /etc/hosts 失败 — $(cat "$DIR/hosts_restore.err" 2>/dev/null)（cleanup 将重试）"
    fi
    sleep "$HOSTS_FINAL"

    if [ "$delta" -ge 1 ]; then
        say "[hosts] PASS：/etc/hosts 变化触发 stat diff → Monitor 粗回调"
        HOSTS_STATE="PASS"
    else
        say "[hosts] FAIL：0 次 CHANGED —— 期望改 /etc/hosts 后 ≤5s 内 hosts_monitor 轮询 emit"
        HOSTS_STATE="FAIL"
    fi
}

# ============================================================================
# 清理（trap EXIT 兜底 + 结尾显式调用；全部幂等）
# ============================================================================
cleanup() {
    say ""
    say "--- cleanup ---"
    kill_harness
    # 还原 hosts：有备份则整文件写回；再按 token 兜底删残留行
    if [ -n "$HOSTS_BAK" ] && [ -f "$HOSTS_BAK" ]; then
        run_priv cp "$HOSTS_BAK" /etc/hosts 2>/dev/null || true
        rm -f "$HOSTS_BAK"; HOSTS_BAK=""
    fi
    if grep -q "$MARKER_TOKEN" /etc/hosts 2>/dev/null; then
        run_priv sed -i '' "/$MARKER_TOKEN/d" /etc/hosts 2>/dev/null || true
    fi
    # 残留 TEST-NET 路由（含 add 成功但 delete 失败的崩溃现场）——幂等 dest-only 兜底
    del_testnet_route
    # 清日志与临时目录
    rm -rf "$DIR" 2>/dev/null || true
    say "--- cleanup done ---"
}

# ============================================================================
# 主流程
# ============================================================================

# 平台门禁：仅 macOS
case "$(uname -s)" in
    Darwin) ;;
    *) fatal "仅支持 macOS（macvm）；当前 $(uname -s)" ;;
esac

# 特权探测：hosts 编辑 / route 加删均需 root。无特权 → 两子项全 SKIP。
if [ "$CAN_SUDO" != "1" ]; then
    say "SKIP 全部子项：${SUDO_HINT}"
    say "       [route] 需 root 执行 route add/delete"
    say "       [hosts] 需 root 写 /etc/hosts"
    exit 0
fi

# 独立临时目录：LOG / PIDFILE / 备份 / 各步 stderr 全在此，统一清理
DIR="$(mktemp -d "${TMPDIR:-/tmp}/zignetmon_macos_real_event.XXXXXX")" || fatal "mktemp -d 失败"
LOG="$DIR/real_event.log"
PIDFILE="$DIR/harness.pid"
trap cleanup EXIT

# 预清理上次崩溃残留的 TEST-NET 路由（在启动 harness 之前，保持事件窗口干净）
del_testnet_route

# ---- 启动 harness（nohup 后台，ssh 断开仍继续）----
say ""
say "=== 启动 harness：$HARNESS 运行 ${RUN_SECONDS}s ==="
if [ ! -x "$HARNESS" ]; then
    say "[harness] 未找到 $HARNESS，尝试构建（zig build real_event）..."
    if ! (cd "$ROOT" && zig build real_event) >/dev/null 2>&1; then
        fatal "harness 缺失且自动构建失败。请先在 $ROOT 执行：zig build real_event"
    fi
    [ -x "$HARNESS" ] || fatal "构建后仍无可执行文件：$HARNESS"
fi

: > "$LOG"
HARNESS_START_SEC="$(date +%s)"
if [ "$RUN_AS_ROOT" = "1" ]; then
    nohup "$HARNESS" "$RUN_SECONDS" >>"$LOG" 2>&1 &
    HARNESS_PID=$!
else
    # 非 root：经 sudo -n 以 root 拉起（harness 需特权才能开 AF_ROUTE 读真实事件），
    # 用 bash -c 把真实子进程 pid 写进 pidfile，供后续 kill -0 / kill 使用。
    if ! sudo -n bash -c 'nohup "$1" "$2" >>"$3" 2>&1 & echo $! >"$4"' _ "$HARNESS" "$RUN_SECONDS" "$LOG" "$PIDFILE"; then
        fatal "以 sudo -n 启动 harness 失败（${SUDO_HINT}）"
    fi
    for _ in 1 2 3 4 5 6 7 8 9 10; do   # 最多等 ~3s 等 pidfile 落盘
        [ -s "$PIDFILE" ] && break
        sleep 1
    done
    HARNESS_PID="$(cat "$PIDFILE" 2>/dev/null || true)"
fi

# ---- 等待就绪（Monitor.start 完成落日志 [monitor] started）+ 存活校验 ----
say "[harness] pid=${HARNESS_PID}，日志=$LOG"
say "[harness] 等待就绪日志（[monitor] started，超时 ${READY_TIMEOUT}s）..."
ready=0
i=0
while [ "$i" -lt "$READY_TIMEOUT" ]; do
    if ! harness_alive; then
        say "[harness] FAIL：进程未存活（${i}s 时提前退出）。日志尾部："
        tail -n 40 "$LOG" 2>/dev/null || true
        fatal "harness 提前退出"
    fi
    if grep -q '\[monitor\] started' "$LOG" 2>/dev/null; then
        ready=1
        break
    fi
    sleep 1
    i=$(( i + 1 ))
done
if [ "$ready" != "1" ]; then
    say "[harness] FAIL：${READY_TIMEOUT}s 内未见 [monitor] started。日志尾部："
    tail -n 40 "$LOG" 2>/dev/null || true
    fatal "harness 未就绪"
fi
say "[harness] 就绪（Monitor.start 完成；hosts 首轮 stat 基线于 ~5s 建立，已由时序窗口覆盖）"

# ---- 触发真实事件并断言 ----
run_route
run_hosts

# ---- 汇总（读取日志尾部后 exit，触发 cleanup 清理）----
say ""
say "========== 结果汇总 =========="
say "route : $ROUTE_STATE"
say "hosts : $HOSTS_STATE"
if [ "$ROUTE_STATE" = "FAIL" ] || [ "$HOSTS_STATE" = "FAIL" ]; then
    say "--- 日志尾部（诊断，随后清理删除）---"
    tail -n 40 "$LOG" 2>/dev/null || true
    exit 1
fi
exit 0
