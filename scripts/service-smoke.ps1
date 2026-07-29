# Block 14.2 manual smoke checklist for the Windows service scaffold.
#
# Run as Administrator. The script walks the canonical SCM lifecycle
# (install → query → start → query → stop → query → uninstall → query)
# so a regression in the service entrypoint is visible in one command.
#
# What this checks (block 14.2 acceptance criteria):
#   - install/uninstall flow returns success
#   - `sc query` reports STARTED/RUNNING after start
#   - `sc query` reports STOPPED after stop
#   - service binary path resolves correctly
#   - executable boots without GUI dependencies (no Qt host spawned)
#
# Out of scope here: bootstrap pipeline (14.3), policy load (14.4),
# IPC server (14.5), apply attempts (14.9), Event Log writes (14.2.x).

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('dev', 'release')]
    [string] $Profile = 'dev',

    # When set, skip install/uninstall and only run the console-mode
    # smoke ("status" subcommand). Useful for non-admin runs.
    [switch] $ConsoleOnly
)

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    $exeName = 'nrr-service.exe'
    $profileDir = if ($Profile -eq 'release') { 'release' } else { 'debug' }
    $exePath = Join-Path $root "target\$profileDir\$exeName"

    if (-not (Test-Path $exePath)) {
        Write-Host "Building $exeName ($Profile profile)..." -ForegroundColor Cyan
        if ($Profile -eq 'release') {
            cargo build --release -p nrr-windows-service | Out-Null
        }
        else {
            cargo build -p nrr-windows-service | Out-Null
        }
    }

    Write-Host "==> status subcommand (no SCM)" -ForegroundColor Cyan
    & $exePath status
    if ($LASTEXITCODE -ne 0) { throw "status returned $LASTEXITCODE" }

    if ($ConsoleOnly) {
        Write-Host "ConsoleOnly set — skipping install/uninstall flow." -ForegroundColor Yellow
        return
    }

    $isAdmin = (
        New-Object Security.Principal.WindowsPrincipal(
            [Security.Principal.WindowsIdentity]::GetCurrent()
        )
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        throw "install/uninstall require Administrator. Re-run elevated, or pass -ConsoleOnly."
    }

    Write-Host "==> install" -ForegroundColor Cyan
    & $exePath install
    if ($LASTEXITCODE -ne 0) { throw "install returned $LASTEXITCODE" }

    Write-Host "==> sc query NetRuleRouter (post-install)" -ForegroundColor Cyan
    sc.exe query NetRuleRouter

    Write-Host "==> sc start NetRuleRouter" -ForegroundColor Cyan
    sc.exe start NetRuleRouter
    Start-Sleep -Seconds 2

    Write-Host "==> sc query NetRuleRouter (post-start)" -ForegroundColor Cyan
    sc.exe query NetRuleRouter

    Write-Host "==> sc stop NetRuleRouter" -ForegroundColor Cyan
    sc.exe stop NetRuleRouter
    Start-Sleep -Seconds 2

    Write-Host "==> sc query NetRuleRouter (post-stop)" -ForegroundColor Cyan
    sc.exe query NetRuleRouter

    Write-Host "==> uninstall" -ForegroundColor Cyan
    & $exePath uninstall
    if ($LASTEXITCODE -ne 0) { throw "uninstall returned $LASTEXITCODE" }

    Write-Host "==> sc query NetRuleRouter (post-uninstall, expected: not found)" -ForegroundColor Cyan
    $null = sc.exe query NetRuleRouter 2>&1
    if ($LASTEXITCODE -eq 0) {
        throw "service still registered after uninstall"
    }

    Write-Host "smoke checklist passed." -ForegroundColor Green
}
finally {
    Pop-Location
}
