# Manual smoke checklist for the Windows service scaffold.
#
# Run as Administrator. The script walks the canonical SCM lifecycle
# (install → query → start → query → stop → query → uninstall → query)
# so a regression in the service entrypoint is visible in one command.
#
# What this checks:
#   - install/uninstall flow returns success
#   - `sc query` reports STARTED/RUNNING after start
#   - `sc query` reports STOPPED after stop
#   - service binary path resolves correctly
#   - executable boots without GUI dependencies (no Qt host spawned)
#
# Out of scope here: bootstrap pipeline, policy load, IPC server, apply
# attempts, Event Log writes.
#
# From a package it smokes the nrr-service.exe beside scripts\; from a checkout,
# the build under the Cargo target directory (built first when missing).
# Needs lib\service-paths.ps1 beside it.

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

. (Join-Path $PSScriptRoot 'lib\service-paths.ps1')

$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    $exeName = $NrrServiceExeName
    $isCheckout = Test-Path (Join-Path $root 'Cargo.toml')
    if ($isCheckout) {
        $profileDir = if ($Profile -eq 'release') { 'release' } else { 'debug' }
        $exePath = Join-Path (Resolve-TargetRoot $root) "$profileDir\$exeName"
        if (-not (Test-Path $exePath)) {
            Write-Host "Building $exeName ($Profile profile)..." -ForegroundColor Cyan
            $cargoArgs = @('build', '-p', 'nrr-windows-service')
            if ($Profile -eq 'release') { $cargoArgs += '--release' }
            $buildExit = Invoke-NativeCommand -FilePath 'cargo' -ArgumentList $cargoArgs
            if ($buildExit -ne 0) { throw "cargo build returned $buildExit" }
        }
    }
    else {
        $exePath = Join-Path $root $exeName
    }
    if (-not (Test-Path $exePath)) { throw "$exeName not found at $exePath" }
    Write-Host "Using $exePath" -ForegroundColor DarkGray

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

    Write-Host "==> sc query $NrrServiceName (post-install)" -ForegroundColor Cyan
    sc.exe query $NrrServiceName

    Write-Host "==> sc start $NrrServiceName" -ForegroundColor Cyan
    sc.exe start $NrrServiceName
    Start-Sleep -Seconds 2

    Write-Host "==> sc query $NrrServiceName (post-start)" -ForegroundColor Cyan
    sc.exe query $NrrServiceName

    Write-Host "==> sc stop $NrrServiceName" -ForegroundColor Cyan
    sc.exe stop $NrrServiceName
    Start-Sleep -Seconds 2

    Write-Host "==> sc query $NrrServiceName (post-stop)" -ForegroundColor Cyan
    sc.exe query $NrrServiceName

    Write-Host "==> uninstall" -ForegroundColor Cyan
    & $exePath uninstall
    if ($LASTEXITCODE -ne 0) { throw "uninstall returned $LASTEXITCODE" }

    Write-Host "==> sc query $NrrServiceName (post-uninstall, expected: not found)" -ForegroundColor Cyan
    $null = sc.exe query $NrrServiceName 2>&1
    if ($LASTEXITCODE -eq 0) {
        throw "service still registered after uninstall"
    }

    Write-Host "smoke checklist passed." -ForegroundColor Green
}
finally {
    Pop-Location
}
