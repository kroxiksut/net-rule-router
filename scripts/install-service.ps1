# Block 16.16 — install the NetRuleRouter Windows service from the
# command line. Mirrors the GUI's `nrrServiceController.installService()`
# bridge call: same SCM API path, different driver.
#
# Self-elevates via UAC if not already running as Administrator. The
# script locates the service binary in target/debug or target/release
# (preferring whichever was built most recently).
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File .\scripts\install-service.ps1
#   powershell -ExecutionPolicy Bypass -File .\scripts\install-service.ps1 -Profile release

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('auto', 'dev', 'release')]
    [string] $Profile = 'auto'
)

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$exeName = 'nrr-service.exe'

# Honour `.cargo/config.toml::build.target-dir` (e.g. when the workspace
# redirects builds to a fast local drive away from the synced source
# tree). Falls back to `<root>/target` when no override is configured.
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
            $debugExists = Test-Path $debugPath
            $releaseExists = Test-Path $releasePath
            if ($debugExists -and $releaseExists) {
                $debugTime = (Get-Item $debugPath).LastWriteTime
                $releaseTime = (Get-Item $releasePath).LastWriteTime
                return $(if ($debugTime -ge $releaseTime) { $debugPath } else { $releasePath })
            }
            elseif ($debugExists) { return $debugPath }
            elseif ($releaseExists) { return $releasePath }
            else { return $debugPath }
        }
    }
}

$exePath = Resolve-ServiceBinary -Mode $Profile

if (-not (Test-Path $exePath)) {
    Write-Host "Service binary not found at $exePath" -ForegroundColor Yellow
    Write-Host "Building (cargo build -p nrr-windows-service)..." -ForegroundColor Cyan
    Push-Location $root
    try { cargo build -p nrr-windows-service | Out-Null }
    finally { Pop-Location }
    $exePath = Resolve-ServiceBinary -Mode $Profile
    if (-not (Test-Path $exePath)) {
        throw "Service binary still missing after build at $exePath"
    }
}

$isAdmin = (
    New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "Elevating via UAC..." -ForegroundColor Cyan
    Start-Process -FilePath $exePath -ArgumentList 'install' -Verb RunAs -Wait
    exit $LASTEXITCODE
}

Write-Host "==> install" -ForegroundColor Cyan
& $exePath install
if ($LASTEXITCODE -ne 0) { throw "install returned $LASTEXITCODE" }

Write-Host "Service installed. Starting..." -ForegroundColor Green
sc.exe start NetRuleRouter | Out-Null
Start-Sleep -Seconds 2
& "$PSScriptRoot\service-status.ps1"
