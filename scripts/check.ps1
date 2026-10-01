param(
    [switch]$RequireCargoDeny,
    [switch]$CommentHygieneOnly
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

# Source must not carry task tracking: the repository is public, and block,
# phase and ticket numbers or dates mean nothing to its readers. The patterns
# live in lib/comment-hygiene.rules and the algorithm mirrors
# lib/comment-hygiene.pl, so both gates judge the same tree the same way.
function Read-HygieneRules([string]$Path) {
    $rule = @{}
    foreach ($l in [System.IO.File]::ReadAllLines($Path, [System.Text.Encoding]::UTF8)) {
        if ($l -match '^\s*(#|$)') { continue }
        $eq = $l.IndexOf('=')
        if ($eq -lt 0) { throw "malformed rule line: $l" }
        $rule[$l.Substring(0, $eq)] = $l.Substring($eq + 1)
    }
    foreach ($key in 'anywhere', 'comment', 'exempt', 'filename', 'slash', 'hash', 'hashnames', 'exclude', 'string_gap') {
        if (-not $rule.ContainsKey($key)) { throw "rule '$key' missing from $Path" }
    }
    $rule
}

# Tiny same-shaped lexer (mirrored in comment-hygiene.pl) that tracks enough
# Rust syntax to tell plain-string content from code, comments, char literals
# and raw strings (`r"`/`r#"`, whose content is never collected — they keep
# source formatting on purpose). Appends every plain-string span the given
# line contributes to $Spans, one entry per contiguous run: a continuation
# line's span starts at column 0 with no code before it, which is what keeps a
# multi-line literal's own leading indentation out of the `string_gap` check.
# Limits: no nested block comments; an escaped `\'` right after `r` (never
# valid Rust) is not specially handled — neither shape occurs in this tree.
function Get-RsLineStringSpans([string]$Line, [string]$Mode, [System.Collections.Generic.List[string]]$Spans) {
    $len = $Line.Length
    $i = 0
    $spanStart = if ($Mode -eq 'string') { 0 } else { -1 }
    while ($i -lt $len) {
        if ($Mode -eq 'code') {
            $c = $Line[$i]
            if ($c -eq '/' -and $i + 1 -lt $len -and $Line[$i + 1] -eq '/') {
                break
            } elseif ($c -eq '/' -and $i + 1 -lt $len -and $Line[$i + 1] -eq '*') {
                $close = $Line.IndexOf('*/', $i + 2, [StringComparison]::Ordinal)
                if ($close -ge 0) { $i = $close + 2 } else { $Mode = 'block'; break }
            } elseif ($c -eq "'") {
                if ($i + 1 -lt $len -and $Line[$i + 1] -eq '\') {
                    if ($i + 2 -lt $len -and $Line.Substring($i + 2, [Math]::Min(2, $len - $i - 2)) -eq 'u{') {
                        $brace = $Line.IndexOf('}', $i + 4, [StringComparison]::Ordinal)
                        $i = if ($brace -ge 0 -and $brace + 1 -lt $len -and $Line[$brace + 1] -eq "'") { $brace + 2 } else { $i + 1 }
                    } else {
                        $i = if ($i + 3 -lt $len -and $Line[$i + 3] -eq "'") { $i + 4 } else { $i + 1 }
                    }
                } elseif ($i + 2 -lt $len -and $Line[$i + 2] -eq "'") {
                    $i += 3
                } else {
                    $i += 1 # a lifetime, not a char literal
                }
            } elseif ($c -eq '"') {
                $Mode = 'string'
                $i += 1
                $spanStart = $i
            } elseif ($c -eq 'r' -and ($i -eq 0 -or -not [char]::IsLetterOrDigit($Line[$i - 1]) -and $Line[$i - 1] -ne '_')) {
                $j = $i + 1
                $hashes = 0
                while ($j -lt $len -and $Line[$j] -eq '#') { $hashes += 1; $j += 1 }
                if ($j -lt $len -and $Line[$j] -eq '"') { $Mode = "raw:$hashes"; $i = $j + 1 } else { $i += 1 }
            } else {
                $i += 1
            }
        } elseif ($Mode -eq 'string') {
            $c = $Line[$i]
            if ($c -eq '\') { $i += if ($i + 1 -lt $len) { 2 } else { 1 } }
            elseif ($c -eq '"') {
                $Spans.Add($Line.Substring($spanStart, $i - $spanStart))
                $Mode = 'code'
                $i += 1
                $spanStart = -1
            } else {
                $i += 1
            }
        } elseif ($Mode -like 'raw:*') {
            $hashes = [int]$Mode.Substring(4)
            $closer = '"' + ('#' * $hashes)
            if ($i + $closer.Length -le $len -and $Line.Substring($i, $closer.Length) -eq $closer) { $Mode = 'code'; $i += $closer.Length }
            else { $i += 1 }
        } elseif ($Mode -eq 'block') {
            $close = $Line.IndexOf('*/', $i, [StringComparison]::Ordinal)
            if ($close -ge 0) { $Mode = 'code'; $i = $close + 2 } else { break }
        }
    }
    if ($Mode -eq 'string' -and $spanStart -ge 0) { $Spans.Add($Line.Substring($spanStart)) }
    $Mode
}

# Returns `path:line<TAB>text` per offence; line 0 is the file name itself.
function Find-HygieneOffences([hashtable]$Rule, [string]$Root, [string[]]$Paths) {
    $anywhere = [regex]$Rule.anywhere
    $comment = [regex]$Rule.comment
    $exempt = [regex]$Rule.exempt
    $filename = [regex]$Rule.filename
    $stringGap = [regex]$Rule.string_gap
    $opener = [regex]'^\s*(?:/[/*]+!?|\*+|<#|#+)?\s*'
    $seamTail = [regex]'(\S+)\s*$'
    $slash = $Rule.slash -split '\s+'
    $hash = $Rule.hash -split '\s+'
    $hashNames = $Rule.hashnames -split '\s+'
    $exclude = $Rule.exclude -split '\s+' | Where-Object { $_ }
    $isOffence = { param($t) $anywhere.IsMatch($t) -or ($comment.IsMatch($t) -and -not $exempt.IsMatch($t)) }
    $found = New-Object System.Collections.Generic.List[string]

    foreach ($path in ($Paths | Sort-Object)) {
        if (@($exclude | Where-Object { $path.StartsWith($_, [StringComparison]::Ordinal) }).Count -gt 0) { continue }
        if ($filename.IsMatch($path)) { $found.Add("${path}:0`t$path") }

        $base = $path.Substring($path.LastIndexOf('/') + 1)
        $dot = $base.LastIndexOf('.')
        $ext = if ($dot -ge 0) { $base.Substring($dot + 1) } else { $null }
        $style = if ($hashNames -contains $base) { '#' }
            elseif ($null -eq $ext) { $null }
            elseif ($slash -contains $ext) { '//' }
            elseif ($hash -contains $ext) { '#' }
            else { $null }
        if ($null -eq $style) { continue }
        $full = Join-Path $Root $path
        if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { continue }
        $blockEnd = if ($style -eq '//') { '*/' } else { '#>' }
        $blockStart = if ($style -eq '//') { '/*' } else { '<#' }

        $isRs = $ext -eq 'rs'
        $lineNo = 0
        $inBlock = $false
        $prev = $null
        $rsMode = 'code'
        foreach ($line in [System.IO.File]::ReadLines($full, [System.Text.Encoding]::UTF8)) {
            $lineNo += 1
            if ($lineNo -eq 1) { $line = $line.TrimStart([char]0xFEFF) }
            $trimmed = $line.TrimStart()
            $text = $null
            if ($inBlock) {
                $text = $line
                if ($line.IndexOf($blockEnd, [StringComparison]::Ordinal) -ge 0) { $inBlock = $false }
            } elseif ($trimmed.StartsWith($blockStart, [StringComparison]::Ordinal)) {
                $text = $trimmed
                if ($trimmed.IndexOf($blockEnd, 2, [StringComparison]::Ordinal) -lt 0) { $inBlock = $true }
            } else {
                $at = $line.IndexOf($style, [StringComparison]::Ordinal)
                if ($at -ge 0) { $text = $line.Substring($at) }
            }

            $hit = $anywhere.IsMatch($line) -or ($null -ne $text -and (& $isOffence $text))
            # A marker broken across two comment lines: judge the seam, but only a
            # hit neither half produces alone, so one offence is not reported twice.
            if (-not $hit -and $null -ne $text -and $null -ne $prev) {
                $m = $seamTail.Match($prev)
                if ($m.Success) {
                    $tail = $m.Groups[1].Value
                    $body = $opener.Replace($text, '', 1)
                    $hit = -not (& $isOffence $tail) -and (& $isOffence "$tail $body")
                }
            }
            if ($hit) { $found.Add("${path}:${lineNo}`t$trimmed") }
            $prev = $text

            if ($isRs) {
                $spans = New-Object System.Collections.Generic.List[string]
                $rsMode = Get-RsLineStringSpans $line $rsMode $spans
                if (@($spans | Where-Object { $stringGap.IsMatch($_) })) {
                    $found.Add("${path}:${lineNo}`t$trimmed")
                }
            }
        }
    }
    , $found
}

function Test-CommentHygiene {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    $rule = Read-HygieneRules (Join-Path $PSScriptRoot 'lib\comment-hygiene.rules')

    # The gate first proves it still sees what it is meant to see: a pattern edit
    # that blinds it fails here instead of passing the whole tree silently.
    $fixture = Join-Path $PSScriptRoot 'tests\comment-hygiene'
    $fixturePaths = Get-ChildItem -LiteralPath $fixture -Recurse -File |
        Where-Object { $_.Name -ne 'expected.txt' } |
        ForEach-Object { $_.FullName.Substring($fixture.Length + 1).Replace('\', '/') }
    $fixtureOffences = Find-HygieneOffences $rule $fixture $fixturePaths
    $got = @($fixtureOffences | ForEach-Object { ($_ -split "`t", 2)[0] } | Sort-Object)
    $expected = @([System.IO.File]::ReadAllLines((Join-Path $fixture 'expected.txt')) | Where-Object { $_ } | Sort-Object)
    if ($got.Count -eq 0 -or (Compare-Object $expected $got)) {
        Compare-Object $expected $got -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "  $($_.SideIndicator) $($_.InputObject)" -ForegroundColor Yellow }
        throw "comment hygiene self-test failed: the scanner no longer matches $fixture\expected.txt."
    }

    # What git would publish: tracked plus unignored files.
    $consoleEncoding = [Console]::OutputEncoding
    try {
        [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
        $listing = & git -C $repoRoot -c core.quotepath=off ls-files --cached --others --exclude-standard
    } finally {
        [Console]::OutputEncoding = $consoleEncoding
    }
    if ($LASTEXITCODE -ne 0) { throw 'comment hygiene: git ls-files failed.' }
    $offences = Find-HygieneOffences $rule $repoRoot @($listing)
    if ($offences.Count -gt 0) {
        $offences | Select-Object -First 20 | ForEach-Object { Write-Host "  $($_ -replace "`t", ': ')" -ForegroundColor Yellow }
        if ($offences.Count -gt 20) {
            Write-Host "  ... and $($offences.Count - 20) more" -ForegroundColor Yellow
        }
        throw "comment hygiene failed: $($offences.Count) line(s) or file name(s) carry task references or dates."
    }
}

function Test-DoubledWords {
    # A word repeated back to back in a comment. Eight of these shipped at once
    # when a blind find-and-replace put a replacement word into sentences that
    # already carried it, and the hygiene gate above had no reason to look:
    # nothing about them is a task reference or a date. The next mass rename
    # gets caught here instead of by a reader months later.
    #
    # `(?!-)` keeps the legitimate "prefer under-detection over over-detection":
    # the second "over" starts a hyphenated word, not a repeat.
    $roots = @('apps', 'core', 'shared', 'scripts') |
        ForEach-Object { Join-Path (Split-Path -Parent $PSScriptRoot) $_ } |
        Where-Object { Test-Path $_ }
    $pattern = '\b([A-Za-z]{3,})\s+\1\b(?!-)'
    $offences = @()

    Get-ChildItem -Path $roots -Recurse -File -Include '*.rs', '*.qml', '*.cpp', '*.h', '*.js', '*.ps1' |
        Where-Object { $_.FullName -notmatch '\\target\\' } |
        ForEach-Object {
            $file = $_
            $lineNo = 0
            foreach ($line in [System.IO.File]::ReadLines($file.FullName)) {
                $lineNo += 1
                $prefix = if ($file.Extension -eq '.ps1') { '#' } else { '//' }
                $commentAt = $line.IndexOf($prefix)
                if ($commentAt -lt 0) { continue }
                $comment = $line.Substring($commentAt)
                $hit = [regex]::Match($comment, $pattern)
                if ($hit.Success) {
                    $offences += "$($file.FullName):${lineNo}: $($line.Trim())"
                }
            }
        }

    if ($offences.Count -gt 0) {
        $offences | Select-Object -First 20 | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
        if ($offences.Count -gt 20) {
            Write-Host "  ... and $($offences.Count - 20) more" -ForegroundColor Yellow
        }
        throw "doubled words: $($offences.Count) comment(s) repeat a word."
    }
}

function Test-PublicDocsTerms {
    # Public documentation names benefits, never internal mechanisms or private
    # documents. The terms live in lib/public-docs-terms.rules, shared with
    # check.sh; code is not scanned, the slugs are legal there.
    $repoRoot = Split-Path -Parent $PSScriptRoot
    $rulesPath = Join-Path $PSScriptRoot 'lib\public-docs-terms.rules'
    $patterns = @()
    foreach ($l in [System.IO.File]::ReadAllLines($rulesPath, [System.Text.Encoding]::UTF8)) {
        if ($l -match '^\s*(#|$)') { continue }
        $tab = $l.IndexOf("`t")
        if ($tab -lt 0) { throw "malformed rule line: $l" }
        $pattern = $l.Substring(0, $tab)
        $sample = $l.Substring($tab + 1)
        if (-not [regex]::IsMatch($sample, $pattern, 'IgnoreCase')) {
            throw "public docs gate self-test failed: '$pattern' no longer matches its sample."
        }
        $patterns += $pattern
    }
    if ($patterns.Count -eq 0) { throw "public docs gate: $rulesPath holds no patterns." }
    $combined = [regex]::new(($patterns -join '|'), 'IgnoreCase')

    $scope = '^((README|ROADMAP)[^/]*\.md|CONTRIBUTING\.md|SECURITY\.md|STRUCTURE\.md|(.*/)?AGENTS\.md|docs/.*\.md)$'
    $consoleEncoding = [Console]::OutputEncoding
    try {
        [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
        $listing = & git -C $repoRoot -c core.quotepath=off ls-files --cached --others --exclude-standard
    } finally {
        [Console]::OutputEncoding = $consoleEncoding
    }
    if ($LASTEXITCODE -ne 0) { throw 'public docs: git ls-files failed.' }

    $offences = New-Object System.Collections.Generic.List[string]
    foreach ($path in @($listing | Where-Object { $_ -match $scope })) {
        $full = Join-Path $repoRoot $path
        if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { continue }
        $lineNo = 0
        foreach ($line in [System.IO.File]::ReadLines($full, [System.Text.Encoding]::UTF8)) {
            $lineNo += 1
            if ($combined.IsMatch($line)) { $offences.Add("${path}:${lineNo}: $($line.Trim())") }
        }
    }
    if ($offences.Count -gt 0) {
        $offences | Select-Object -First 20 | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
        if ($offences.Count -gt 20) {
            Write-Host "  ... and $($offences.Count - 20) more" -ForegroundColor Yellow
        }
        throw "public docs: $($offences.Count) line(s) name an internal mechanism or a private document."
    }
}

Write-Host '[check] NetRuleRouter workspace quality baseline' -ForegroundColor Cyan

Write-Host '[check] sync duplicates' -ForegroundColor Cyan
& (Join-Path $PSScriptRoot 'clean-sync-duplicates.ps1')

Write-Host '[check] comment hygiene: no task references or dates in comments' -ForegroundColor Cyan
Test-CommentHygiene

Write-Host '[check] comment hygiene: no doubled words' -ForegroundColor Cyan
Test-DoubledWords

Write-Host '[check] public docs: no internal mechanism or private-document terms' -ForegroundColor Cyan
Test-PublicDocsTerms

if ($CommentHygieneOnly) {
    Write-Host '[check] comment hygiene only: passed' -ForegroundColor Green
    exit 0
}

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
