# Disaster-recovery "reset networking to default" for NetRuleRouter.
#
# For a machine whose NetRuleRouter service crashed (or was hard-killed)
# and left OS state behind: a non-dynamic WFP session's block filters survive
# `taskkill /F` until an explicit delete or a reboot, so an orphaned
# kill-switch / fail-closed block can lock the machine off the network; and a
# stranded Mode-B NRPT rule points all DNS at a now-dead listener, so no name
# resolves at all — either way, with no running service left to lift it.
#
# This wrapper:
#   1. stops the service if it is running (best-effort — OK if not installed),
#   2. invokes the binary's `cleanup` subcommand, which opens its own WFP
#      engine session and removes ALL NetRuleRouter filters (block AND permit),
#      any leftover NRR-owned routes, and any orphaned Mode-B NRPT/DNS-redirect
#      rule — WITHOUT the service running,
#   3. prints guidance (a reboot fully clears any remainder).
#
# Self-elevates via UAC (the `cleanup` subcommand needs Administrator to open
# the WFP engine). No interactive prompts.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File .\scripts\reset-network.ps1
#   powershell -ExecutionPolicy Bypass -File .\scripts\reset-network.ps1 -Profile release

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('auto', 'dev', 'release')]
    [string] $Profile = 'auto'
)

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$exeName = 'nrr-service.exe'

# Honour `.cargo/config.toml::build.target-dir` redirect — same resolution
# as install-service.ps1 / uninstall-service.ps1.
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

function Resolve-ServiceBinary {
    param([string] $Mode)
    $debugPath = Join-Path $targetRoot "debug\$exeName"
    $releasePath = Join-Path $targetRoot "release\$exeName"
    switch ($Mode) {
        'dev'     { return $debugPath }
        'release' { return $releasePath }
        default {
            if ((Test-Path $debugPath) -and (Test-Path $releasePath)) {
                $d = (Get-Item $debugPath).LastWriteTime
                $r = (Get-Item $releasePath).LastWriteTime
                return $(if ($d -ge $r) { $debugPath } else { $releasePath })
            }
            elseif (Test-Path $debugPath) { return $debugPath }
            elseif (Test-Path $releasePath) { return $releasePath }
            else { return $debugPath }
        }
    }
}

$exePath = Resolve-ServiceBinary -Mode $Profile

if (-not (Test-Path $exePath)) {
    throw "Service binary not found at $exePath. Cannot reset without it (need its `cleanup` subcommand)."
}

$isAdmin = (
    New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "Elevating via UAC..." -ForegroundColor Cyan
    Start-Process -FilePath $exePath -ArgumentList @('cleanup') -Verb RunAs -Wait
    exit $LASTEXITCODE
}

Write-Host "==> sc stop NetRuleRouter (best-effort)" -ForegroundColor Cyan
$null = sc.exe stop NetRuleRouter 2>&1
Start-Sleep -Seconds 2

Write-Host "==> $exePath cleanup" -ForegroundColor Cyan
& $exePath cleanup
$code = $LASTEXITCODE
if ($code -ne 0) { throw "cleanup returned $code" }

Write-Host "Network reset complete. Reboot to fully clear any remainder." -ForegroundColor Green
