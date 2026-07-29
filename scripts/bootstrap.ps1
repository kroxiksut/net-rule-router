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

$target = if ($env:NRR_RUST_TARGET) { $env:NRR_RUST_TARGET } else { 'x86_64-pc-windows-msvc' }
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

if (-not (Test-Path '.env')) {
    Copy-Item '.env.example' '.env'
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

& cargo check --workspace
if ($LASTEXITCODE -ne 0) {
    throw 'cargo check --workspace failed during bootstrap.'
}

Write-Host '[bootstrap] completed successfully' -ForegroundColor Green
