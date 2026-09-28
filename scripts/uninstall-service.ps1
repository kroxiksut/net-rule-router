# Uninstall the NetRuleRouter Windows service from the command line.
# Counterpart of install-service.ps1.
#
# Self-elevates via UAC. Stops the service first (sc.exe stop), then calls the
# `uninstall` subcommand of the binary the SCM has registered (its ImagePath),
# or of the repo build when none is registered or -Profile names one. Without
# a binary that can do it, the registration is removed with `sc.exe delete`.
#
# Default: removing the service leaves its data alone — the state DB and audit
# logs under %ProgramData%\NetRuleRouter\ stay where they are.
#
# With -Purge: passes `--purge`, which additionally removes
# %ProgramData%\NetRuleRouter\ (state DB, audit, NDJSON). That is the
# application-removal path; user rule files live outside the data directory and
# are preserved either way. The `sc.exe delete` fallback removes no data.
#
# Exits 0 once the service is no longer registered (also when it never was),
# 1 while it still is.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File .\scripts\uninstall-service.ps1
#   powershell -ExecutionPolicy Bypass -File .\scripts\uninstall-service.ps1 -Profile release
#   powershell -ExecutionPolicy Bypass -File .\scripts\uninstall-service.ps1 -Purge

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('auto', 'dev', 'release')]
    [string] $Profile = 'auto',

    [Parameter()]
    [switch] $Purge
)

$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'lib\service-paths.ps1')

$root = Split-Path -Parent $PSScriptRoot

# Reading the registration needs no elevation, so an absent service costs no
# UAC prompt.
if (-not (Test-ServiceRegistered)) {
    Write-Host "Service $NrrServiceName is not registered; nothing to uninstall." -ForegroundColor DarkGray
    exit 0
}

$isAdmin = (
    New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# The script, not the binary: the sc.exe fallback needs Administrator too.
if (-not $isAdmin) {
    Write-Host "Elevating via UAC..." -ForegroundColor Cyan
    if ($Purge) {
        Write-Host "  -Purge: %ProgramData%\NetRuleRouter\ will be removed." -ForegroundColor Yellow
    }
    # One pre-quoted string: Windows PowerShell joins an -ArgumentList array with
    # bare spaces, which splits a script path containing a space.
    $argv = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Profile $Profile"
    if ($Purge) { $argv += ' -Purge' }
    $powershell = Get-SystemTool 'WindowsPowerShell\v1.0\powershell.exe'
    $p = Start-Process -FilePath $powershell -ArgumentList $argv -Verb RunAs -Wait -PassThru
    exit $p.ExitCode
}

# The registered binary is the one that answers for this service; a named
# profile is the caller asking for a particular build.
$repoBinary = Resolve-RepoServiceBinary -TargetRoot (Resolve-TargetRoot $root) -Mode $Profile
$installedBinary = Resolve-InstalledServiceBinary
$exePath = if ($Profile -ne 'auto' -and $repoBinary) { $repoBinary }
           elseif ($installedBinary) { $installedBinary }
           else { $repoBinary }

$sc = Get-SystemTool 'sc.exe'

Write-Host "==> sc stop $NrrServiceName (best-effort)" -ForegroundColor Cyan
$null = Invoke-NativeCommand -FilePath $sc -ArgumentList @('stop', $NrrServiceName) -Quiet
# A running service is only marked for deletion, and stays registered.
$null = Wait-ServiceStatus -Name $NrrServiceName -Status Stopped -Seconds 30

$uninstallArgs = @('uninstall')
if ($Purge) { $uninstallArgs += '--purge' }

$viaBinary = $false
if ($exePath) {
    Write-Host "==> $exePath $($uninstallArgs -join ' ')" -ForegroundColor Cyan
    $code = Invoke-NativeCommand -FilePath $exePath -ArgumentList $uninstallArgs
    if ($code -eq 0) { $viaBinary = $true }
    else { Write-Warning "uninstall returned $code - falling back to sc.exe delete." }
}
else {
    Write-Warning "No service binary found (registered ImagePath or repo build) - falling back to sc.exe delete."
}

if (-not $viaBinary -and (Test-ServiceRegistered)) {
    Write-Host "==> sc delete $NrrServiceName" -ForegroundColor Cyan
    $code = Invoke-NativeCommand -FilePath $sc -ArgumentList @('delete', $NrrServiceName)
    if ($code -ne 0) { Write-Warning "sc.exe delete returned $code." }
    # The binary's uninstall also sweeps filters and the DNS redirect; this path
    # cannot, and removes no data.
    Write-Host "  Network state was not swept: run reset-network.ps1 if the network misbehaves." -ForegroundColor Yellow
    if ($Purge) {
        Write-Host "  -Purge was not applied: purge-data.ps1 -Yes removes the data." -ForegroundColor Yellow
    }
}

if (Test-ServiceRegistered) {
    if (Test-ServiceDeletePending) {
        Write-Warning "$NrrServiceName is marked for deletion but still registered: its process or an open handle keeps it. It goes at the next reboot."
    }
    else {
        Write-Warning "$NrrServiceName is still registered."
    }
    exit 1
}

if ($viaBinary -and $Purge) {
    Write-Host "Service uninstalled. %ProgramData%\NetRuleRouter\ removed." -ForegroundColor Green
}
else {
    Write-Host "Service uninstalled. State DB and audit logs preserved." -ForegroundColor Green
}
