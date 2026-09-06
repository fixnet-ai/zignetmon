# =============================================================================
# windows_real_event.ps1 — zignetmon Tier2 真事件源验证脚本（windowsvm）
# =============================================================================
# 用途（design.md §6 Tier2）：启动 real_event 订阅 harness（zig-out/bin/real_event
# [.exe]），随后触发三路**真实 OS 事件**，断言 Monitor 粗回调产生 ≥1 行 CHANGED：
#
#   1) 路由事件   : netsh interface ipv4 add/delete route 198.51.100.0/24
#                   （TEST-NET 静态路由，驱动 NotifyRouteChange2，改后即删）
#   2) hosts 事件 : 临时在 %SystemRoot%\...\etc\hosts 追加一行（改后即恢复）
#   3) 代理事件   : HKCU Internet Settings 临时写 ProxyEnable/ProxyServer（改后即恢复）
#
# harness 契约（tests/real_event_harness.zig）：`real_event <秒数>` 订阅 Monitor，
# 每次粗回调向 stdout 打一行含 CHANGED；跑满秒数 exit 0。
#
# 语义注意（重要）：
#   - v2 Monitor 只对「连通性相关」facts（默认网关/默认接口/DNS）diff 派发；
#     NotifyRouteChange2 → 1s 防抖 → 默认路由重选，TEST-NET 静态路由不改默认路由，
#     因此**本实现下 route 阶段预期不产生粗信号**（无伪信号 = 正确）。hosts/proxy
#     为确定性触发源（5s stat diff / RegNotify 事件驱动），二者是 PASS 的强制来源。
#   - hosts 监测是 5s stat 轮询，须等首个轮询建立基线后再改文件（SettleSec 已覆盖）。
#   - 代理/路由/hosts 全部「临时改 + 立即恢复」，不留持久状态。
#
# 用法（零配置；需管理员）：
#   powershell -ExecutionPolicy Bypass -File windows_real_event.ps1
#   powershell -ExecutionPolicy Bypass -File windows_real_event.ps1 -SkipProxy
#   powershell -ExecutionPolicy Bypass -File windows_real_event.ps1 -HarnessPath C:\x\real_event.exe
#
# 构建（目标 = 被测机架构，windowsvm 为 aarch64 / winx64 为 x86_64）：
#   zig build [-Dtarget=aarch64-windows | x86_64-windows]
#   → 产物 tests/../zig-out/bin/real_event.exe
#
# 自愈（nohup 语义）：harness 经 WMI Win32_Process.Create 真分离启动（脱离 ssh job），
# ssh 断开仍继续写日志；harness 跑满 -RunSeconds 后自行 exit 0，不留长驻进程。
# 驱动脚本在 finally 兜底 taskkill 清理。日志：$env:TEMP\zignetmon_real_event.log。
#
# 退出码：0 = PASS；1 = 断言 FAIL（强制源 hosts[/proxy] 未触发）；2 = 启动/用法错误。
# 输出（English ASCII，便于 host 侧解析）：
#   [real-event] RESULT route  delta=N status=PASS|INFO|SKIP|ERROR
#   [real-event] RESULT hosts  delta=N status=PASS|MISS|ERROR
#   [real-event] RESULT proxy  delta=N status=PASS|MISS|ERROR|SKIP
#   [real-event] FINAL PASS|FAIL   reason=...
# =============================================================================

[CmdletBinding()]
param(
    # harness 可执行文件（默认 tests/../zig-out/bin/real_event.exe）
    [string]$HarnessPath = '',
    # harness 运行秒数（须盖过全部阶段；cleanup 会提前杀，长点无害）
    [int]$RunSeconds = 150,
    # 启动后等就绪（network 首事件播种基线 + hosts 首次 5s 轮询基线）
    [int]$SettleSec = 10,
    [int]$RouteWaitSec   = 4,   # 路由窗口（驱动 NotifyRouteChange2）
    [int]$HostsWaitSec   = 14,  # hosts 窗口（须盖过 5s stat 轮询）
    [int]$ProxyWaitSec   = 10,  # 代理窗口（RegNotify 事件驱动，给慢 VM 余量）
    [int]$SettleBetweenSec = 6, # 阶段间让迟到回调落定（≥ hosts 轮询余量，保证归因干净）
    # 跳过代理阶段（注册表写系统代理在某些环境不期望）
    [switch]$SkipProxy,
    # 附加结果文件（把 RESULT/FINAL 行同时写入，便于 ssh 断开后读取）
    [string]$ResultFile = ''
)

$ErrorActionPreference = 'Stop'
$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
if (-not $HarnessPath) {
    $HarnessPath = Join-Path $repoRoot 'zig-out\bin\real_event.exe'
}
$LogPath = Join-Path $env:TEMP 'zignetmon_real_event.log'

# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------

function Test-IsAdmin {
    $p = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# 日志中当前 CHANGED 行数（文件不存在/被短暂占用视为 0，带重试）
function Get-ChangedCount {
    for ($i = 0; $i -lt 6; $i++) {
        try {
            $raw = Get-Content -LiteralPath $LogPath -Raw -ErrorAction Stop
            if ($null -eq $raw) { return 0 }
            return ([regex]::Matches($raw, 'CHANGED')).Count
        } catch {
            Start-Sleep -Milliseconds 250
        }
    }
    return 0
}

# 轮询直至 CHANGED 数 > $Before 或超时
function Wait-ChangedGrowth {
    param([int]$Before, [int]$WaitSec)
    $deadline = (Get-Date).AddSeconds($WaitSec)
    while ((Get-Date) -lt $deadline) {
        if ((Get-ChangedCount) -gt $Before) { return $true }
        Start-Sleep -Milliseconds 300
    }
    return ((Get-ChangedCount) -gt $Before)
}

# 捕获网关/接口：取 IPv4 默认路由最低 metric 条目
function Get-DefaultRouteInfo {
    try {
        $r = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop |
            Sort-Object -Property @{ Expression = { $_.RouteMetric }}, @{ Expression = { $_.InterfaceMetric }} |
            Select-Object -First 1
        if ($null -eq $r) { return $null }
        $ad = Get-NetAdapter -InterfaceIndex $r.InterfaceIndex -ErrorAction Stop
        return @{ IfName = $ad.Name; Gateway = $r.NextHop; IfIndex = $r.InterfaceIndex }
    } catch {
        return $null
    }
}

# ---------------------------------------------------------------------------
# harness 启动 / 停止（WMI 真分离；finally 兜底清理）
# ---------------------------------------------------------------------------

$script:HarnessPid = 0

function Start-Harness {
    if (-not (Test-Path -LiteralPath $HarnessPath)) {
        throw "harness binary not found: $HarnessPath (build first: zig build [-Dtarget=aarch64-windows|x86_64-windows])"
    }
    # 全新日志，避免旧数据假阳性
    if (Test-Path -LiteralPath $LogPath) { Remove-Item -LiteralPath $LogPath -Force }
    # 真分离：经 WMI 脱离 ssh 会话 job，ssh 断开仍继续（cmd 负责 stdout 重定向到日志）
    $cmd = 'cmd.exe /c ""{0}" {1} > "{2}" 2>&1"' -f $HarnessPath, $RunSeconds, $LogPath
    $r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = $cmd }
    if ($null -eq $r -or $r.ReturnValue -ne 0) {
        $rc = if ($null -ne $r) { $r.ReturnValue } else { 'no-response' }
        throw "Win32_Process.Create failed rc=$rc"
    }
    $script:HarnessPid = [int]$r.ProcessId
    Write-Host "[real-event] harness started pid=$($r.ProcessId) exe=$HarnessPath runSec=$RunSeconds"
    Write-Host "[real-event] log=$LogPath"

    # 等就绪：进程存活 + 日志已建（cmd 立即建文件）+ settle 让基线建立
    $deadline = (Get-Date).AddSeconds(20)
    while ((Get-Date) -lt $deadline) {
        if (-not (Test-HarnessAlive)) { break }
        if (Test-Path -LiteralPath $LogPath) { break }
        Start-Sleep -Milliseconds 500
    }
    if (-not (Test-HarnessAlive)) {
        $tail = if (Test-Path -LiteralPath $LogPath) { (Get-Content -LiteralPath $LogPath -Tail 5 -ErrorAction SilentlyContinue) -join ' | ' } else { '(no log)' }
        throw "harness exited during startup (Monitor.init/start failed?) tail=$tail"
    }
    if (-not (Test-Path -LiteralPath $LogPath)) {
        throw 'harness alive but log file not created within 20s'
    }
    Write-Host "[real-event] settling $SettleSec s (network seed + hosts first 5s poll baseline)"
    Start-Sleep -Seconds $SettleSec
}

function Test-HarnessAlive {
    if ($script:HarnessPid -le 0) { return $false }
    return [bool](Get-Process -Id $script:HarnessPid -ErrorAction SilentlyContinue)
}

function Stop-Harness {
    if ($script:HarnessPid -gt 0) {
        & taskkill.exe /PID $script:HarnessPid /T /F 2>&1 | Out-Null
        $script:HarnessPid = 0
    }
    # 兜底：清残留（本测试工具专用进程名，测试 VM 上安全）
    Get-Process -Name 'real_event' -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue
}

# ---------------------------------------------------------------------------
# 事件阶段通用封装：记基线 → 触发 → 等 CHANGED → 恢复
# ---------------------------------------------------------------------------

function Invoke-Phase {
    param(
        [string]$Name,
        [hashtable]$Out,                       # {Status, Delta, Message}
        [scriptblock]$Trigger,
        [scriptblock]$Restore,
        [int]$WaitSec
    )
    $Out.Status = 'ERROR'
    $Out.Delta = 0
    $Out.Message = ''
    $before = Get-ChangedCount
    Write-Host "[real-event] phase=$Name trigger ..."
    try {
        & $Trigger
    } catch {
        $Out.Message = "trigger failed: $($_.Exception.Message)"
        Write-Host "[real-event] phase=$Name ERROR $($Out.Message)"
        try { & $Restore } catch { Write-Host "[real-event] phase=$Name restore-warn: $($_.Exception.Message)" }
        return
    }
    $grew = Wait-ChangedGrowth -Before $before -WaitSec $WaitSec
    $Out.Delta = (Get-ChangedCount) - $before
    try {
        & $Restore
        Write-Host "[real-event] phase=$Name restored"
    } catch {
        Write-Host "[real-event] phase=$Name restore-warn: $($_.Exception.Message)"
    }
    if ($grew) {
        $Out.Status = 'PASS'
        Write-Host "[real-event] phase=$Name PASS delta=$($Out.Delta)"
    } else {
        $Out.Status = 'MISS'
        $Out.Message = 'no new CHANGED within window'
        Write-Host "[real-event] phase=$Name MISS delta=$($Out.Delta) (expected>0)"
    }
    # 让恢复触发的迟到回调在下一阶段基线前落定
    Start-Sleep -Seconds $SettleBetweenSec
}

# ---------------------------------------------------------------------------
# 阶段定义（数据 + 触发/恢复脚本块；执行在下方 try 内、Start-Harness 之后）
# ---------------------------------------------------------------------------

# --- 1) 路由：netsh 加/删 TEST-NET 静态路由，驱动 NotifyRouteChange2 ---
$routeRes = @{ Status = 'SKIP'; Delta = 0; Message = 'no IPv4 default route, phase skipped' }
$routeInfo = Get-DefaultRouteInfo
$routeIfName = ''
$routeGw = ''
$routeAddArgs = $null
$routeDelArgs = $null
if ($null -ne $routeInfo) {
    $routeIfName = $routeInfo.IfName
    $routeGw = $routeInfo.Gateway
    # netsh 的 interface=<name> 语法不能含空格（token 传参会错析）→ 含空格则 SKIP 并提示手工
    if ($routeIfName.Contains(' ')) {
        $routeRes = @{ Status = 'SKIP'; Delta = 0; Message = "interface name contains space ('$routeIfName'); netsh token form not reliable" }
        Write-Host "[real-event] route SKIP: interface name has spaces -> run netsh add/delete manually to drive NotifyRouteChange2"
    } else {
        $routeAddArgs = @('interface', 'ipv4', 'add', 'route', '198.51.100.0/24', "interface=$routeIfName")
        if ($routeGw -and $routeGw -ne '0.0.0.0') { $routeAddArgs += "nexthop=$routeGw" }
        $routeAddArgs += 'store=active'
        $routeDelArgs = @('interface', 'ipv4', 'delete', 'route', '198.51.100.0/24', "interface=$routeIfName", 'store=active')
        $routeRes = @{ Status = ''; Delta = 0; Message = '' }
    }
}

$routeTrigger = {
    # 幂等：先删可能残留的同前缀路由（崩溃遗留自愈），忽略失败
    & netsh.exe interface ipv4 delete route '198.51.100.0/24' "interface=$routeIfName" 2>$null | Out-Null
    Write-Host "[real-event] route: netsh add 198.51.100.0/24 if=$routeIfName gw=$routeGw (store=active)"
    & netsh.exe @routeAddArgs
    if ($LASTEXITCODE -ne 0) { throw "netsh add route failed rc=$LASTEXITCODE" }
    Write-Host '[real-event] route: added, NotifyRouteChange2 driven'
}
$routeRestore = {
    Write-Host "[real-event] route: netsh delete 198.51.100.0/24 if=$routeIfName"
    & netsh.exe @routeDelArgs
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[real-event] route delete rc=$LASTEXITCODE (route already gone; continuing)"
    }
}

# --- 2) hosts：临时追加一行 → 恢复原字节 ---
$hostsRes = @{ Status = 'ERROR'; Delta = 0; Message = '' }
$hostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
$hostsMarker = "127.0.0.1 zignetmon-real-event.invalid # zignetmon-real-event-$([guid]::NewGuid().ToString('N').Substring(0, 8))"
$script:origHostsText = ''

$hostsTrigger = {
    if (-not (Test-Path -LiteralPath $hostsPath)) { throw "hosts file missing: $hostsPath" }
    $script:origHostsText = [System.IO.File]::ReadAllText($hostsPath)
    $text = $script:origHostsText
    if (-not $text.EndsWith("`n")) { $text += "`r`n" }
    $text += $hostsMarker + "`r`n"
    [System.IO.File]::WriteAllText($hostsPath, $text)
    Write-Host "[real-event] hosts: appended marker line"
}
$hostsRestore = {
    if ($script:origHostsText -ne '') {
        [System.IO.File]::WriteAllText($hostsPath, $script:origHostsText)
        Write-Host '[real-event] hosts: restored original bytes'
        $script:origHostsText = ''
    }
}

# --- 3) 代理：HKCU Internet Settings 临时改 ProxyEnable/ProxyServer → 立即恢复 ---
$proxyRes = @{ Status = 'SKIP'; Delta = 0; Message = 'proxy phase skipped (-SkipProxy)' }
$intKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
$script:origProxy = $null

$proxyTrigger = {
    # 读原始状态（值可能不存在）；临时值须与现状不同，保证 RegNotify diff 触发
    $e = Get-ItemProperty -LiteralPath $intKey -Name ProxyEnable -ErrorAction SilentlyContinue
    $s = Get-ItemProperty -LiteralPath $intKey -Name ProxyServer -ErrorAction SilentlyContinue
    $enableExists = ($null -ne $e)
    $serverExists = ($null -ne $s)
    $enableVal = 0
    $serverVal = ''
    if ($enableExists) { $enableVal = [int]$e.ProxyEnable }
    if ($serverExists) { $serverVal = [string]$s.ProxyServer }
    $script:origProxy = @{
        EnableExists = $enableExists
        Enable = $enableVal
        ServerExists = $serverExists
        Server = $serverVal
    }
    $tempServer = '127.0.0.1:19851'
    if ($enableExists -and $enableVal -eq 1 -and $serverVal -eq $tempServer) {
        $tempServer = '127.0.0.1:19852'  # 避免与现状相同导致无 diff
    }
    if ($enableExists) {
        Set-ItemProperty -LiteralPath $intKey -Name ProxyEnable -Value 1
    } else {
        New-ItemProperty -LiteralPath $intKey -Name ProxyEnable -PropertyType DWord -Value 1 -Force | Out-Null
    }
    Set-ItemProperty -LiteralPath $intKey -Name ProxyServer -Value $tempServer
    Write-Host "[real-event] proxy: temp set ProxyEnable=1 ProxyServer=$tempServer"
}
$proxyRestore = {
    if ($null -eq $script:origProxy) { return }
    $o = $script:origProxy
    if ($o.EnableExists) {
        Set-ItemProperty -LiteralPath $intKey -Name ProxyEnable -Value ([int]$o.Enable)
    } else {
        Remove-ItemProperty -LiteralPath $intKey -Name ProxyEnable -ErrorAction SilentlyContinue
    }
    if ($o.ServerExists) {
        Set-ItemProperty -LiteralPath $intKey -Name ProxyServer -Value ([string]$o.Server)
    } else {
        Remove-ItemProperty -LiteralPath $intKey -Name ProxyServer -ErrorAction SilentlyContinue
    }
    Write-Host '[real-event] proxy: restored original registry state'
    $script:origProxy = $null
}

# ---------------------------------------------------------------------------
# 主流程：admin → 启动 harness → 三阶段 → 汇总（finally 保证清理）
# ---------------------------------------------------------------------------

$final = 'FAIL reason=did not run'
try {
    if (-not (Test-IsAdmin)) {
        throw 'administrator required (netsh route + write %SystemRoot%\...\hosts). Re-run elevated.'
    }
    if ($RunSeconds -lt 20) { throw 'RunSeconds too small (<20)' }

    # 启动前兜底清残留（本测试工具专用进程名），保证干净基线
    Get-Process -Name 'real_event' -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $LogPath) { Remove-Item -LiteralPath $LogPath -Force }

    Start-Harness

    # 阶段 1：路由（预期 INFO——静态 TEST-NET 不改连通性 facts；仅驱动 NotifyRouteChange2）
    if ($routeAddArgs -eq $null) {
        Write-Host '[real-event] phase=route SKIP (no IPv4 default route on host)'
    } else {
        Invoke-Phase -Name 'route' -Out $routeRes -Trigger $routeTrigger -Restore $routeRestore -WaitSec $RouteWaitSec
        if ($routeRes.Status -eq 'MISS') {
            $routeRes.Status = 'INFO'
            $routeRes.Message = 'no coarse signal for TEST-NET static route add (v2 default-route-only diff; NotifyRouteChange2 still driven)'
            Write-Host '[real-event] route INFO: add/delete drives NotifyRouteChange2; coarse CHANGED not expected under v2 connectivity-facts diff'
        }
    }

    # 阶段 2：hosts（强制源）
    Invoke-Phase -Name 'hosts' -Out $hostsRes -Trigger $hostsTrigger -Restore $hostsRestore -WaitSec $HostsWaitSec

    # 阶段 3：代理（强制源，除非 -SkipProxy）
    if (-not $SkipProxy) {
        Invoke-Phase -Name 'proxy' -Out $proxyRes -Trigger $proxyTrigger -Restore $proxyRestore -WaitSec $ProxyWaitSec
    }

    # ---- 汇总 ----
    Write-Host ''
    Write-Host "[real-event] RESULT route  delta=$($routeRes.Delta) status=$($routeRes.Status)"
    Write-Host "[real-event] RESULT hosts  delta=$($hostsRes.Delta) status=$($hostsRes.Status)"
    Write-Host "[real-event] RESULT proxy  delta=$($proxyRes.Delta) status=$($proxyRes.Status)"

    $required = @(@{ Name = 'hosts'; Res = $hostsRes })
    if (-not $SkipProxy) { $required += @{ Name = 'proxy'; Res = $proxyRes } }

    $bad = @()
    foreach ($r in $required) {
        if ($r.Res.Status -ne 'PASS') { $bad += $r.Name }
    }
    $total = Get-ChangedCount
    if ($total -lt 1) {
        $final = "FAIL   reason=no CHANGED in log at all (harness/monitor not firing)"
    } elseif ($bad.Count -gt 0) {
        $final = "FAIL   reason=required source(s) missed: $($bad -join ',')"
    } else {
        $final = "PASS   reason=real OS events fired Monitor (total CHANGED=$total)"
    }
    Write-Host "[real-event] FINAL $final"

    if ($ResultFile) {
        "RESULT route  delta=$($routeRes.Delta) status=$($routeRes.Status)" | Out-File -FilePath $ResultFile -Encoding ascii
        "RESULT hosts  delta=$($hostsRes.Delta) status=$($hostsRes.Status)" | Out-File -FilePath $ResultFile -Append -Encoding ascii
        "RESULT proxy  delta=$($proxyRes.Delta) status=$($proxyRes.Status)" | Out-File -FilePath $ResultFile -Append -Encoding ascii
        "FINAL $final" | Out-File -FilePath $ResultFile -Append -Encoding ascii
        Write-Host "[real-event] results written to $ResultFile"
    }
} catch {
    Write-Host "[real-event] FATAL: $($_.Exception.Message)"
    Write-Host '[real-event] FINAL FAIL   reason=startup/usage error'
    if ($ResultFile) { "FINAL FAIL reason=$($_.Exception.Message)" | Out-File -FilePath $ResultFile -Encoding ascii }
    exit 2
} finally {
    # 残留清理：各阶段已 try/finally 恢复；此处收尾杀 harness + 兜底还原代理
    Stop-Harness
    if ($null -ne $script:origProxy) {
        try { & $proxyRestore } catch { Write-Host "[real-event] final proxy restore-warn: $($_.Exception.Message)" }
    }
    if ($script:origHostsText -ne '') {
        try { & $hostsRestore } catch { Write-Host "[real-event] final hosts restore-warn: $($_.Exception.Message)" }
    }
}

if ($final -like 'PASS*') { exit 0 } else { exit 1 }
