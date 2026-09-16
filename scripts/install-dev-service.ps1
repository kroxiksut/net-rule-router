# Install the NetRuleRouter service from a directory only administrators can
# write to, instead of straight from the build tree.
#
# `target\...` is writable by whoever built it, so a service registered there
# runs, as SYSTEM, whatever file is sitting at that path on the next start.
# This script copies the built binaries into a staging directory under
# Program Files and registers the service from there. The build tree stays
# where cargo wants it; only what the SCM points at moves.
#
# Self-elevates via UAC. The service is stopped before its files are replaced
# and started again afterwards unless -NoStart is given.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File .\scripts\install-dev-service.ps1
#   powershell -ExecutionPolicy Bypass -File .\scripts\install-dev-service.ps1 -Profile release

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('dev', 'release')]
    [string] $Profile = 'dev',

    [Parameter()]
    [string] $StageDir = (Join-Path $env:ProgramW6432 'NetRuleRouter-dev'),

    [Parameter()]
    [switch] $NoStart
)

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$serviceName = 'NetRuleRouter'

# Honour `.cargo/config.toml::build.target-dir`; same rule as install-service.ps1.
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

$buildDir = Join-Path (Resolve-TargetRoot $root) $(if ($Profile -eq 'release') { 'release' } else { 'debug' })

# The console is staged next to the service because it registers the service it
# finds beside itself — that is how the SCM ends up pointing here and not at
# the build tree. wintun.dll travels with them: the service checks it by hash
# and, in release, looks for it only next to its own binary.
$payload = @(
    @{ Name = 'nrr-service.exe'; From = (Join-Path $buildDir 'nrr-service.exe'); Required = $true },
    @{ Name = 'nrr-cli.exe';     From = (Join-Path $buildDir 'nrr-cli.exe');     Required = $true },
    @{ Name = 'wintun.dll';      From = (Join-Path $root 'third_party\wintun\bin\amd64\wintun.dll'); Required = $true }
)

foreach ($item in $payload) {
    if ($item.Required -and -not (Test-Path $item.From)) {
        throw "$($item.Name) not found at '$($item.From)'. Build it first: cargo build -p nrr-windows-service -p nrr-cli"
    }
}

$isAdmin = (
    New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host 'Elevating via UAC...' -ForegroundColor Cyan
    $argv = @(
        '-ExecutionPolicy', 'Bypass',
        '-NoProfile',
        '-File', "`"$PSCommandPath`"",
        '-Profile', $Profile,
        '-StageDir', "`"$StageDir`""
    )
    if ($NoStart) { $argv += '-NoStart' }
    # $LASTEXITCODE is not set by Start-Process; the child's code comes from -PassThru.
    $p = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') `
        -ArgumentList $argv -Verb RunAs -Wait -PassThru
    exit $p.ExitCode
}

$existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($existing -and $existing.Status -ne 'Stopped') {
    Write-Host "==> stopping $serviceName" -ForegroundColor Cyan
    Stop-Service -Name $serviceName -Force
    (Get-Service -Name $serviceName).WaitForStatus('Stopped', '00:00:30')
}

if (-not (Test-Path $StageDir)) {
    New-Item -ItemType Directory -Path $StageDir -Force | Out-Null
}

# Program Files inherits an administrators-only ACL, so a staging directory
# created there needs none of its own. Anywhere else is the caller's choice and
# the service's own install check is what judges it.
foreach ($item in $payload) {
    if (-not (Test-Path $item.From)) { continue }
    Copy-Item -LiteralPath $item.From -Destination (Join-Path $StageDir $item.Name) -Force
    Write-Host "    staged $($item.Name)" -ForegroundColor DarkGray
}

$console = Join-Path $StageDir 'nrr-cli.exe'
Write-Host "==> reinstall from $StageDir" -ForegroundColor Cyan
& $console reinstall
if ($LASTEXITCODE -ne 0) { throw "reinstall returned $LASTEXITCODE" }

if (-not $NoStart) {
    $state = (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)
    if ($state -and $state.Status -ne 'Running') {
        Start-Service -Name $serviceName
    }
}

& $console status
