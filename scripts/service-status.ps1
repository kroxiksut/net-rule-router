# Block 16.16 — show NetRuleRouter service status. Read-only, no
# elevation required.
#
# Combines `sc.exe query` (SCM-canonical state) with a one-line
# diagnostic banner from the service binary's `status` subcommand
# (block 14.2). Useful as a quick check from any terminal — equivalent
# to the GUI's `nrrServiceController.status` property.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File .\scripts\service-status.ps1

[CmdletBinding()]
param()

$ErrorActionPreference = 'Continue'

$root = Split-Path -Parent $PSScriptRoot

Write-Host "==> sc query NetRuleRouter" -ForegroundColor Cyan
$scOutput = sc.exe query NetRuleRouter 2>&1
$scExit = $LASTEXITCODE
Write-Host $scOutput

if ($scExit -ne 0) {
    Write-Host "Service not registered (sc.exe exit=$scExit)." -ForegroundColor Yellow
    return
}

$exeName = 'nrr-service.exe'

# Honour `.cargo/config.toml::build.target-dir` redirect.
function Resolve-TargetRoot {
    param([string] $RepoRoot)
    $cfg = Join-Path $RepoRoot '.cargo\config.toml'
    if (Test-Path $cfg) {
        $content = Get-Content $cfg -Raw
        if ($content -match '(?m)^\s*target-dir\s*=\s*"([^"]+)"') {
            $td = $Matches[1] -replace '/', '\'
            if ([System.IO.Path]::IsPathRooted($td)) { return $td }
            return (Join-Path $RepoRoot $td)
        }
    }
    return (Join-Path $RepoRoot 'target')
}
$targetRoot = Resolve-TargetRoot $root
$debugPath = Join-Path $targetRoot "debug\$exeName"
$releasePath = Join-Path $targetRoot "release\$exeName"
$exePath = $null
if (Test-Path $debugPath) { $exePath = $debugPath }
elseif (Test-Path $releasePath) { $exePath = $releasePath }

if ($exePath) {
    Write-Host ""
    Write-Host "==> $exeName status" -ForegroundColor Cyan
    & $exePath status
}
else {
    Write-Host ""
    Write-Host "(Service binary not found in target/. Skipping orchestration banner.)" -ForegroundColor DarkGray
}
