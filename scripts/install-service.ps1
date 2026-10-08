# Install and start the NetRuleRouter Windows service from the build tree.
#
# The SCM never points at `target\`: whoever built it can rewrite that path,
# and the service runs as SYSTEM. This script copies the built binaries into a
# staging directory under Program Files (administrators-only) and registers
# the service from there. The build tree stays where cargo wants it; only what
# the SCM points at moves.
#
# -Profile auto takes the freshest build and builds when nothing exists yet.
# Self-elevates via UAC once, re-running itself with the profile already
# resolved. The service is stopped before its files are replaced and started
# again afterwards unless -NoStart is given.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File .\scripts\install-service.ps1
#   powershell -ExecutionPolicy Bypass -File .\scripts\install-service.ps1 -Profile release

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('auto', 'dev', 'release')]
    [string] $Profile = 'auto',

    # Defaults to $NrrDevStageDir, the location purge-data.ps1 cleans up.
    [Parameter()]
    [string] $StageDir,

    [Parameter()]
    [switch] $NoStart
)

$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'lib\service-paths.ps1')

$root = Split-Path -Parent $PSScriptRoot
$serviceName = $NrrServiceName
if (-not $StageDir) { $StageDir = $NrrDevStageDir }
if (-not $StageDir) { throw 'ProgramW6432 is not set; pass -StageDir.' }

$targetRoot = Resolve-TargetRoot $root

# Building happens before elevation; the elevated copy gets a resolved profile
# and finds the binary already there.
$exePath = Resolve-RepoServiceBinary -TargetRoot $targetRoot -Mode $Profile
if (-not $exePath) {
    Write-Host "Service binary not found under $targetRoot" -ForegroundColor Yellow
    $buildArgs = @('build', '-p', 'nrr-windows-service', '-p', 'nrr-cli', '-p', 'nrr-tui')
    if ($Profile -eq 'release') { $buildArgs += '--release' }
    Write-Host "Building (cargo $($buildArgs -join ' '))..." -ForegroundColor Cyan
    Push-Location $root
    try {
        & cargo @buildArgs
        if ($LASTEXITCODE -ne 0) { throw "cargo build returned $LASTEXITCODE" }
    }
    finally { Pop-Location }
    $exePath = Resolve-RepoServiceBinary -TargetRoot $targetRoot -Mode $Profile
    if (-not $exePath) { throw "Service binary still missing under $targetRoot after build" }
}

$Profile = if ($exePath -like '*\release\*') { 'release' } else { 'dev' }
$buildDir = Join-Path $targetRoot $(if ($Profile -eq 'release') { 'release' } else { 'debug' })

# The console is staged next to the service because it registers the service it
# finds beside itself, which is how the SCM ends up pointing here and not at
# the build tree. wintun.dll travels with them: the service checks it by hash
# and, in release, looks for it only next to its own binary. The terminal
# interface rides along when built, so an administrator terminal finds both
# consoles in one place.
$payload = @(
    @{ Name = 'nrr-service.exe'; From = (Join-Path $buildDir 'nrr-service.exe'); Required = $true },
    @{ Name = 'nrr-cli.exe';     From = (Join-Path $buildDir 'nrr-cli.exe');     Required = $true },
    @{ Name = 'nrr-tui.exe';     From = (Join-Path $buildDir 'nrr-tui.exe');     Required = $false },
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
    # The elevated window closes on exit; the caller still needs to see the outcome.
    $stagedConsole = Join-Path $StageDir 'nrr-cli.exe'
    if (Test-Path $stagedConsole) { & $stagedConsole status }
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
exit $LASTEXITCODE
