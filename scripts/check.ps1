param(
    [switch]$RequireCargoDeny
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-CargoStep([string]$Label, [string[]]$CargoArgs) {
    Write-Host "[check] ${Label}: cargo $($CargoArgs -join ' ')" -ForegroundColor Cyan
    & cargo @CargoArgs
    if ($LASTEXITCODE -ne 0) {
        throw "$Label failed."
    }
}

function Invoke-ToolStep([string]$Label, [string]$ToolPath, [string[]]$ToolArgs) {
    Write-Host "[check] ${Label}: $ToolPath $($ToolArgs -join ' ')" -ForegroundColor Cyan
    & $ToolPath @ToolArgs
    if ($LASTEXITCODE -ne 0) {
        throw "$Label failed."
    }
}

Write-Host '[check] NetRuleRouter workspace quality baseline' -ForegroundColor Cyan

Invoke-CargoStep 'format' @('fmt', '--all', '--check')
Invoke-CargoStep 'clippy' @('clippy', '--workspace', '--all-targets', '--', '-D', 'warnings')
Invoke-CargoStep 'tests' @('test', '--workspace')

$cargoDeny = Get-Command 'cargo-deny' -ErrorAction SilentlyContinue
if ($null -eq $cargoDeny) {
    $message = 'cargo-deny is not installed. Install it with `cargo install --locked cargo-deny` to enable dependency/license checks.'
    if ($RequireCargoDeny) {
        throw $message
    }

    Write-Warning $message
} else {
    $workspaceRoot = Split-Path -Parent $PSScriptRoot
    $localCargoHome = Join-Path $workspaceRoot '.cargo-home'
    if (-not (Test-Path $localCargoHome)) {
        New-Item -ItemType Directory -Path $localCargoHome | Out-Null
    }

    $advisoryRoot = Join-Path $localCargoHome 'advisory-dbs'
    if (Test-Path $advisoryRoot) {
        Get-ChildItem -Path $advisoryRoot -Directory -Filter 'advisory-db-*' -ErrorAction SilentlyContinue |
            ForEach-Object {
                Write-Warning "Refreshing advisory cache: $($_.FullName)"
                Remove-Item -LiteralPath $_.FullName -Recurse -Force
            }
    }

    $previousCargoHome = $env:CARGO_HOME
    $env:CARGO_HOME = $localCargoHome
    try {
        Invoke-ToolStep 'cargo-deny' $cargoDeny.Source @('check', 'advisories', 'licenses', 'bans', 'sources')
    } finally {
        if ([string]::IsNullOrWhiteSpace($previousCargoHome)) {
            Remove-Item Env:CARGO_HOME -ErrorAction SilentlyContinue
        } else {
            $env:CARGO_HOME = $previousCargoHome
        }
    }
}

Write-Host '[check] quality baseline completed successfully' -ForegroundColor Green
