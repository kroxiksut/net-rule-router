param(
    [ValidateSet('gui', 'tray', 'service')]
    [string]$Component,

    # Same name/values/default-less-'auto' convention as install-service.ps1's
    # -Profile; default stays 'dev' so existing bare invocations keep working.
    [Parameter()]
    [ValidateSet('auto', 'dev', 'release')]
    [string]$Profile = 'dev'
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

# Mirrors install-service.ps1's Resolve-ServiceBinary: 'dev'/'release' pick
# their subfolder directly, 'auto' picks whichever exists and is newer, so
# both scripts agree on which build a bare invocation resolves to.
function Resolve-ProfileBinary {
    param([string]$TargetRoot, [string]$ExeName, [string]$Mode)

    $debugPath = Join-Path $TargetRoot "debug\$ExeName"
    $releasePath = Join-Path $TargetRoot "release\$ExeName"

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

if ($Component -eq 'gui') {
    $buildArgs = @('build', '-p', 'nrr-launcher', '-p', 'nrr-qt-host')
    if ($Profile -eq 'release') {
        $buildArgs += '--release'
    }
    Write-Host "[run] cargo $($buildArgs -join ' ')" -ForegroundColor Cyan
    & cargo @buildArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Build failed for component: $Component"
    }

    $nativeGui = Resolve-ProfileBinary -TargetRoot (Get-CargoTargetDir) -ExeName 'NetRuleRouter.exe' -Mode $Profile
    if (-not (Test-Path -LiteralPath $nativeGui)) {
        throw "Native GUI executable was not found: $nativeGui"
    }

    Write-Host "[run] $nativeGui" -ForegroundColor Cyan
    & $nativeGui
    exit $LASTEXITCODE
}

if ($Component -eq 'tray') {
    $buildArgs = @('build', '-p', 'nrr-launcher', '-p', 'nrr-qt-host')
    if ($Profile -eq 'release') {
        $buildArgs += '--release'
    }
    Write-Host "[run] cargo $($buildArgs -join ' ')" -ForegroundColor Cyan
    & cargo @buildArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Build failed for component: $Component"
    }

    $nativeTray = Resolve-ProfileBinary -TargetRoot (Get-CargoTargetDir) -ExeName 'NetRuleRouterTray.exe' -Mode $Profile
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
$args = @('run', '-p', $package)
if ($Profile -eq 'release') {
    $args += '--release'
}
$args += @('--', 'console')

Write-Host "[run] cargo $($args -join ' ')" -ForegroundColor Cyan
& cargo @args
if ($LASTEXITCODE -ne 0) {
    throw "Run failed for component: $Component"
}
