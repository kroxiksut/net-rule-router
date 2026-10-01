# Show NetRuleRouter service status. Read-only, no elevation required.
#
# Combines `sc.exe query` (SCM-canonical state) with a one-line
# diagnostic banner from the service binary's `status` subcommand.
# Useful as a quick check from any terminal — equivalent to the GUI's
# `nrrServiceController.status` property.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File .\scripts\service-status.ps1

[CmdletBinding()]
param()

$ErrorActionPreference = 'Continue'

$root = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'lib\service-paths.ps1')

Write-Host "==> sc query $NrrServiceName" -ForegroundColor Cyan
$scOutput = sc.exe query $NrrServiceName 2>&1
$scExit = $LASTEXITCODE
Write-Host $scOutput

if ($scExit -ne 0) {
    Write-Host "Service not registered (sc.exe exit=$scExit)." -ForegroundColor Yellow
    return
}

$exeName = $NrrServiceExeName
$targetRoot = Resolve-TargetRoot $root
$exePath = Resolve-RepoServiceBinary -TargetRoot $targetRoot -Mode 'auto'

if ($exePath) {
    Write-Host ""
    Write-Host "==> $exeName status" -ForegroundColor Cyan
    & $exePath status
}
else {
    Write-Host ""
    Write-Host "(Service binary not found in target/. Skipping orchestration banner.)" -ForegroundColor DarkGray
}
