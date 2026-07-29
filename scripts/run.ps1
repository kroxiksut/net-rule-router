param(
    [ValidateSet('gui', 'tray', 'service')]
    [string]$Component
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Resolve the actual Cargo target directory. It is NOT always
# `<repo>/target`: `.cargo/config.toml` (`[build] target-dir`) or the
# `CARGO_TARGET_DIR` env var can redirect it elsewhere (this repo points it at
# a fast local drive, away from Yandex.Disk sync). `cargo metadata` reports the
# effective path honouring both, so the binaries are always found.
function Get-CargoTargetDir {
    $meta = & cargo metadata --format-version 1 --no-deps | ConvertFrom-Json
    if (-not $meta -or -not $meta.target_directory) {
        throw 'Could not determine the Cargo target directory from `cargo metadata`.'
    }
    return $meta.target_directory
}

if ($Component -eq 'gui') {
    $buildArgs = @('build', '-p', 'nrr-launcher', '-p', 'nrr-qt-host')
    Write-Host "[run] cargo $($buildArgs -join ' ')" -ForegroundColor Cyan
    & cargo @buildArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Build failed for component: $Component"
    }

    $nativeGui = Join-Path (Get-CargoTargetDir) 'debug\NetRuleRouter.exe'
    if (-not (Test-Path -LiteralPath $nativeGui)) {
        throw "Native GUI executable was not found: $nativeGui"
    }

    Write-Host "[run] $nativeGui" -ForegroundColor Cyan
    & $nativeGui
    exit $LASTEXITCODE
}

if ($Component -eq 'tray') {
    $buildArgs = @('build', '-p', 'nrr-launcher', '-p', 'nrr-qt-host')
    Write-Host "[run] cargo $($buildArgs -join ' ')" -ForegroundColor Cyan
    & cargo @buildArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Build failed for component: $Component"
    }

    $nativeTray = Join-Path (Get-CargoTargetDir) 'debug\NetRuleRouterTray.exe'
    if (-not (Test-Path -LiteralPath $nativeTray)) {
        throw "Native tray executable was not found: $nativeTray"
    }

    Write-Host "[run] $nativeTray" -ForegroundColor Cyan
    & $nativeTray
    exit $LASTEXITCODE
}

$package = switch ($Component) {
    'service' { 'nrr-windows-service' }
}

# `console` is REQUIRED, not optional: with an empty argv the service binary
# connects to the SCM and refuses to run a foreground runtime (the guard added
# after the duplicate-service incident). A dev run must ask for the foreground
# mode explicitly.
$args = @('run', '-p', $package, '--', 'console')

Write-Host "[run] cargo $($args -join ' ')" -ForegroundColor Cyan
& cargo @args
if ($LASTEXITCODE -ne 0) {
    throw "Run failed for component: $Component"
}
