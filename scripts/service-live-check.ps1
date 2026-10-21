# Is the running service alive, not just started? Run after every install of a
# new build, before handing it over.
#
# Green gates do not prove it: a deadlock between two background tasks passes
# every unit test and still leaves the service answering nothing, with the
# system DNS pointed at its stalled resolver. The supervisor reports a task
# that misses its deadline as `supervised-task-hung`, and the log stays
# readable while the rest is stuck, so that is what this reads.
#
# Waits until the service has run -MinUptimeSeconds since its last start, then
# fails when:
#   - a task was reported hung since that start and has not recovered;
#   - the log read through the service does not come back in time;
#   - -ResolveName does not resolve through the system resolver.
# Needs no elevation. Needs lib\service-paths.ps1 beside it.

[CmdletBinding()]
param(
    [int] $MinUptimeSeconds = 150,
    [string] $ResolveName = 'api.github.com',
    [int] $AnswerTimeoutSeconds = 20,
    # nrr-cli to ask; by default the one beside the registered service.
    [string] $Cli,
    # Judge a saved log (NDJSON, e.g. from a diagnostic archive) instead of asking
    # the service; no waiting.
    [string] $LogFile
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib\service-paths.ps1')

if ($LogFile) { $Cli = 'unused' }
elseif (-not $Cli) {
    $service = Resolve-InstalledServiceBinary
    if (-not $service) { throw "$NrrServiceName is not registered or its binary is gone." }
    $Cli = Join-Path (Split-Path -Parent $service) 'nrr-cli.exe'
}
if (-not $LogFile -and -not (Test-Path -LiteralPath $Cli)) { throw "nrr-cli not found at $Cli (pass -Cli)." }

$bootKey = 'diag.event.svc-boot-stage-entered'
$hungKey = 'diag.event.supervised-task-hung'
$backKey = 'diag.event.supervised-task-responsive'

# The newest log lines as objects; $null when the service did not answer in time.
function Read-ServiceLog {
    if ($LogFile) {
        $rows = New-Object System.Collections.Generic.List[object]
        foreach ($text in (Get-Content -LiteralPath $LogFile -Encoding UTF8)) {
            if (-not $text.StartsWith('{')) { continue }
            try { $rows.Add(($text | ConvertFrom-Json)) } catch { }
        }
        return , $rows
    }
    $job = Start-Job -ScriptBlock { param($exe) & $exe diag logs --tail=2000 2>&1 } -ArgumentList $Cli
    try {
        if (-not (Wait-Job $job -Timeout $AnswerTimeoutSeconds)) { return $null }
        $rows = New-Object System.Collections.Generic.List[object]
        foreach ($line in (Receive-Job $job)) {
            $text = "$line"
            if (-not $text.StartsWith('{')) { continue }
            try { $rows.Add(($text | ConvertFrom-Json)) } catch { }
        }
        return , $rows
    }
    finally { Remove-Job $job -Force }
}

# Event fields: `args` from `diag logs`, `payload` in an archived log.
function Get-Fields($row) {
    if ($null -ne $row.args) { return $row.args }
    return $row.payload
}

function Get-LastStart($rows) {
    $start = $null
    foreach ($row in $rows) {
        if ($row.message_key -eq $bootKey -and (Get-Fields $row).stage -eq 'build-deps') { $start = [int64]$row.created_at }
    }
    return $start
}

$nowMs = { [int64]([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()) }
$failures = New-Object System.Collections.Generic.List[string]

$rows = Read-ServiceLog
if ($null -eq $rows) { throw "The service did not return its log within $AnswerTimeoutSeconds s." }
$start = Get-LastStart $rows
if ($null -eq $start) { throw 'No service start in the last 2000 log lines; is the service running?' }

$waitMs = $start + 1000 * $MinUptimeSeconds - (& $nowMs)
if ($waitMs -gt 0 -and -not $LogFile) {
    Write-Host ("[live-check] waiting {0} s until the service has run {1} s" -f [math]::Ceiling($waitMs / 1000), $MinUptimeSeconds) -ForegroundColor Cyan
    Start-Sleep -Milliseconds $waitMs
}

$watch = [Diagnostics.Stopwatch]::StartNew()
$rows = Read-ServiceLog
if ($null -eq $rows) {
    $failures.Add("the service did not return its log within $AnswerTimeoutSeconds s")
}
else {
    Write-Host ("[live-check] log answered in {0} ms" -f $watch.ElapsedMilliseconds) -ForegroundColor DarkGray
    if ((Get-LastStart $rows) -ne $start) { $failures.Add('the service restarted while being checked') }
    $hung = @{}
    foreach ($row in $rows) {
        if ([int64]$row.created_at -lt $start) { continue }
        $fields = Get-Fields $row
        if ($row.message_key -eq $hungKey) { $hung[[string]$fields.task] = [string]$fields.seconds }
        elseif ($row.message_key -eq $backKey) { $hung.Remove([string]$fields.task) }
    }
    foreach ($task in $hung.Keys) { $failures.Add("task '$task' hung ($($hung[$task]) s past its deadline)") }
}

try {
    $answer = Resolve-DnsName -Name $ResolveName -Type A -QuickTimeout -ErrorAction Stop | Where-Object { $_.IPAddress } | Select-Object -First 1
    if (-not $answer) { $failures.Add("$ResolveName resolved to no address") }
}
catch { $failures.Add("$ResolveName did not resolve: $($_.Exception.Message)") }

if ($failures.Count -gt 0) {
    $failures | ForEach-Object { Write-Host "[live-check] FAIL: $_" -ForegroundColor Red }
    exit 1
}
Write-Host '[live-check] the service is alive: no hung task, log answered, DNS resolves' -ForegroundColor Green
