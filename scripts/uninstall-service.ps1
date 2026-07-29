# Uninstall the NetRuleRouter Windows service from the command line.
# Counterpart of install-service.ps1.
#
# Self-elevates via UAC. Stops the service first (sc.exe stop) before
# calling the binary's `uninstall` subcommand.
#
# Default: removing the service leaves its data alone — the state DB and audit
# logs under %ProgramData%\NetRuleRouter\ stay where they are.
#
# With -Purge: passes `--purge`, which additionally removes
# %ProgramData%\NetRuleRouter\ (state DB, audit, NDJSON). That is the
# application-removal path; user rule files live outside the data directory and
# are preserved either way.
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

$root = Split-Path -Parent $PSScriptRoot
$exeName = 'nrr-service.exe'

# Honour `.cargo/config.toml::build.target-dir` redirect — see
# install-service.ps1 for the rationale.
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
    throw "Service binary not found at $exePath. Cannot uninstall without it (need its `uninstall` subcommand)."
}

$isAdmin = (
    New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$uninstallArgs = @('uninstall')
if ($Purge) { $uninstallArgs += '--purge' }

if (-not $isAdmin) {
    Write-Host "Elevating via UAC..." -ForegroundColor Cyan
    if ($Purge) {
        Write-Host "  -Purge: %ProgramData%\NetRuleRouter\ will be removed." -ForegroundColor Yellow
    }
    Start-Process -FilePath $exePath -ArgumentList $uninstallArgs -Verb RunAs -Wait
    exit $LASTEXITCODE
}

Write-Host "==> sc stop NetRuleRouter (best-effort)" -ForegroundColor Cyan
$null = sc.exe stop NetRuleRouter 2>&1
Start-Sleep -Seconds 2

Write-Host "==> $exePath $($uninstallArgs -join ' ')" -ForegroundColor Cyan
& $exePath @uninstallArgs
if ($LASTEXITCODE -ne 0) { throw "uninstall returned $LASTEXITCODE" }

if ($Purge) {
    Write-Host "Service uninstalled. %ProgramData%\NetRuleRouter\ removed." -ForegroundColor Green
} else {
    Write-Host "Service uninstalled. State DB and audit logs preserved." -ForegroundColor Green
}
