param(
    [switch]$RequireCargoDeny
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Native tools report progress on stderr. Under `$ErrorActionPreference =
# 'Stop'` PowerShell turns that into a terminating NativeCommandError, so a
# successful `cargo clippy` would fail the gate on its own build log. The exit
# code is the only verdict that counts, so stderr is demoted for the call.
function Invoke-Native([string]$Label, [scriptblock]$Call) {
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $Call
    } finally {
        $ErrorActionPreference = $previous
    }
    if ($LASTEXITCODE -ne 0) {
        throw "$Label failed."
    }
}

function Invoke-CargoStep([string]$Label, [string[]]$CargoArgs) {
    Write-Host "[check] ${Label}: cargo $($CargoArgs -join ' ')" -ForegroundColor Cyan
    Invoke-Native $Label { & cargo @CargoArgs }
}

function Invoke-ToolStep([string]$Label, [string]$ToolPath, [string[]]$ToolArgs) {
    Write-Host "[check] ${Label}: $ToolPath $($ToolArgs -join ' ')" -ForegroundColor Cyan
    Invoke-Native $Label { & $ToolPath @ToolArgs }
}

# Source comments must not carry task tracking. The repository is public, and
# block/phase/ticket numbers and dates are meaningless to anyone reading it.
# Only comment text is scanned — the same words inside string literals, test
# data or schema version facts are legitimate.
function Test-CommentHygiene {
    $roots = @('apps', 'core', 'shared', 'scripts') |
        ForEach-Object { Join-Path (Split-Path -Parent $PSScriptRoot) $_ } |
        Where-Object { Test-Path $_ }
    # The sub-block form is fenced on both sides so dotted-quad addresses in
    # comments (10.0.0.0/8, 172.16.0.0/12) are not read as block numbers.
    $markers = 'Block\s+\d|блок\s+\d|(?<![\d.])1\d\.\d+\.[0-9A-Z](?!\.?\d)|NRR-\d+|TODO\(block|Phase\s+[A-Z]\b|20\d\d-[01]\d-[0-3]\d'
    # A date used as arithmetic in a worked example is documentation, not a
    # tracking stamp.
    $exempt = 'UTC|epoch|RFC|ISO\s?8601|≈|\d_\d{3}_'
    $offences = @()

    Get-ChildItem -Path $roots -Recurse -File -Include '*.rs', '*.qml', '*.cpp', '*.h', '*.js', '*.ps1' |
        Where-Object { $_.FullName -notmatch '\\target\\' } |
        ForEach-Object {
            $file = $_
            $lineNo = 0
            foreach ($line in [System.IO.File]::ReadLines($file.FullName)) {
                $lineNo += 1
                $hit = [regex]::Match($line, $markers)
                if (-not $hit.Success) { continue }
                if ($line -match $exempt) { continue }
                $prefix = if ($file.Extension -eq '.ps1') { '#' } else { '//' }
                $commentAt = $line.IndexOf($prefix)
                if ($commentAt -ge 0 -and $commentAt -lt $hit.Index) {
                    $offences += "$($file.FullName):${lineNo}: $($line.Trim())"
                }
            }
        }

    if ($offences.Count -gt 0) {
        $offences | Select-Object -First 20 | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
        if ($offences.Count -gt 20) {
            Write-Host "  … and $($offences.Count - 20) more" -ForegroundColor Yellow
        }
        throw "comment hygiene failed: $($offences.Count) comment(s) carry task references or dates."
    }
}

Write-Host '[check] NetRuleRouter workspace quality baseline' -ForegroundColor Cyan

Write-Host '[check] sync duplicates' -ForegroundColor Cyan
& (Join-Path $PSScriptRoot 'clean-sync-duplicates.ps1')

Write-Host '[check] comment hygiene: no task references or dates in comments' -ForegroundColor Cyan
Test-CommentHygiene

# Invoked as `cargo-fmt`, not `cargo fmt`: a user-level cargo alias named `fmt`
# shadows the subcommand and makes cargo emit a warning on stderr, which this
# script would report as a failure.
$cargoFmt = Get-Command 'cargo-fmt' -ErrorAction SilentlyContinue
if ($null -eq $cargoFmt) {
    throw 'cargo-fmt is not installed. Install it with `rustup component add rustfmt`.'
}
Invoke-ToolStep 'format' $cargoFmt.Source @('--all', '--', '--check')
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
