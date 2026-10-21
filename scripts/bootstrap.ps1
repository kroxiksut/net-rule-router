param(
    [switch]$StrictQt
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-Tool([string]$Name) {
    return $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)
}

Write-Host '[bootstrap] NetRuleRouter development bootstrap' -ForegroundColor Cyan

if (-not (Test-Tool 'rustup')) {
    throw 'rustup was not found. Install Rust toolchain first.'
}
if (-not (Test-Tool 'cargo')) {
    throw 'cargo was not found. Install Rust toolchain first.'
}

# The repository root, whatever the caller's directory is.
$repoRoot = Split-Path -Parent $PSScriptRoot

# The OS architecture, not the PowerShell process's: a 32-bit shell on 64-bit
# Windows still builds for the machine.
$osArch = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
$defaultTarget = if ($osArch -eq 'ARM64') { 'aarch64-pc-windows-msvc' } else { 'x86_64-pc-windows-msvc' }
$target = if ($env:NRR_RUST_TARGET) { $env:NRR_RUST_TARGET } else { $defaultTarget }
$installedTargets = & rustup target list --installed
if ($LASTEXITCODE -ne 0) {
    throw 'Failed to query installed rustup targets.'
}

if ($installedTargets -notcontains $target) {
    Write-Host "[bootstrap] adding rust target $target"
    & rustup target add $target
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to add rust target: $target"
    }
}

# The gate's test runner (scripts\check.ps1 falls back to cargo test without it).
& cargo nextest --version *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Host '[bootstrap] installing cargo-nextest'
    & cargo install cargo-nextest --locked
    if ($LASTEXITCODE -ne 0) {
        throw 'Failed to install cargo-nextest'
    }
}

$envFile = Join-Path $repoRoot '.env'
if (-not (Test-Path $envFile)) {
    Copy-Item (Join-Path $repoRoot '.env.example') $envFile
    Write-Host '[bootstrap] created .env from .env.example'
} else {
    Write-Host '[bootstrap] .env already exists; skip'
}

$qtToolFound = (Test-Tool 'qmake') -or (Test-Tool 'qtpaths')
$cmakeFound = Test-Tool 'cmake'

if ($StrictQt) {
    if (-not $qtToolFound) {
        throw 'Qt tool not found (qmake/qtpaths). Install Qt 6.6+ for GUI integration.'
    }
    if (-not $cmakeFound) {
        throw 'cmake not found. Install CMake 3.26+ for Qt build integration.'
    }
} else {
    if (-not $qtToolFound) {
        Write-Warning 'Qt tool not found (qmake/qtpaths). Rust workspace is still bootstrap-able, but Qt GUI wiring will require it.'
    }
    if (-not $cmakeFound) {
        Write-Warning 'cmake not found. Rust workspace is still bootstrap-able, but Qt integration will require it.'
    }
}

Push-Location $repoRoot
try {
    & cargo check --workspace
    if ($LASTEXITCODE -ne 0) {
        throw 'cargo check --workspace failed during bootstrap.'
    }
}
finally {
    Pop-Location
}

Write-Host '[bootstrap] completed successfully' -ForegroundColor Green
