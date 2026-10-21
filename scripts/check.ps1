param(
    [switch]$RequireCargoDeny,
    [switch]$CommentHygieneOnly,
    # CI passes it: a runner without qmllint means the Qt install step broke.
    [switch]$RequireQmlLint,
    [switch]$QmlLintOnly,
    # Opt-in, for a VM or a test machine: also runs the `#[ignore]` tests that
    # need administrator rights and mutate real network state (WFP filters,
    # routes, DNS). Needs an elevated shell. Never part of the default gate and
    # never run by public CI.
    [switch]$IncludePrivileged
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

    Get-ChildItem -Path $roots -Recurse -File -Include '*.rs', '*.qml', '*.cpp', '*.h', '*.js', '*.ps1', '*.sh' |
        Where-Object { $_.FullName -notmatch '\\target\\' } |
        ForEach-Object {
            $file = $_
            $lineNo = 0
            foreach ($line in [System.IO.File]::ReadLines($file.FullName)) {
                $lineNo += 1
                $prefix = if (@('.ps1', '.sh') -contains $file.Extension) { '#' } else { '//' }
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

# Containing a panic on foreign bytes (catch_unwind on every parser path, the
# DNS restore in Drop) works only while panics unwind: under `abort` one bad
# packet stops the service. Cargo takes profiles from the workspace root alone,
# but a config file or the environment can force the strategy as well.
$PanicAbortPattern = 'panic\s*=\s*["'']?abort\b'

function Find-PanicAbort([string[]]$Paths) {
    $found = New-Object System.Collections.Generic.List[string]
    foreach ($path in $Paths) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
        $lineNo = 0
        foreach ($line in [System.IO.File]::ReadLines($path)) {
            $lineNo += 1
            if (($line -replace '(^|\s)#.*$', '') -match $PanicAbortPattern) {
                $found.Add("${path}:${lineNo}: $($line.Trim())")
            }
        }
    }
    , $found
}

function Test-PanicStrategy {
    $fixture = Join-Path $PSScriptRoot 'tests\panic-strategy'
    $probe = Find-PanicAbort @((Join-Path $fixture 'Cargo.toml.fixture'), (Join-Path $fixture 'config.toml.fixture'))
    if ($probe.Count -ne 3) {
        $probe | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
        throw "panic strategy self-test failed: expected 3 findings in $fixture, got $($probe.Count)."
    }

    $repoRoot = Split-Path -Parent $PSScriptRoot
    $offences = Find-PanicAbort @(
        (Join-Path $repoRoot 'Cargo.toml'),
        (Join-Path $repoRoot '.cargo\config.toml'),
        (Join-Path $repoRoot '.cargo\config'))
    foreach ($var in Get-ChildItem Env:) {
        $flags = $var.Name -match '^(RUSTFLAGS|CARGO_\w*RUSTFLAGS)$' -and $var.Value -match $PanicAbortPattern
        $strategy = $var.Name -match '^CARGO_PROFILE_\w+_PANIC$' -and $var.Value.Trim() -eq 'abort'
        if ($flags -or $strategy) { $offences.Add("environment: $($var.Name)=$($var.Value)") }
    }
    if ($offences.Count -gt 0) {
        $offences | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
        throw "panic strategy: $($offences.Count) setting(s) make panics abort; the service relies on unwinding."
    }
}

# Nothing compiles QML, so a syntax error that keeps the main window from
# loading passes every Rust gate. The verdict is a warning with id `syntax` in
# qmllint's JSON: the text form is untagged before Qt 6.9 and, on a Windows
# runner without a console, not printed at all. Its ordinary warnings
# (unresolved imports, unqualified access) are not a verdict.
function Find-QmlLint {
    $candidates = New-Object System.Collections.Generic.List[string]
    if ($env:CMAKE_PREFIX_PATH) {
        foreach ($entry in $env:CMAKE_PREFIX_PATH.Split(';')) {
            # Either the kit or its lib\cmake, as the Qt host's build script takes it.
            $kit = $entry.Trim().TrimEnd('\', '/') -replace '[\\/]lib[\\/]cmake$', ''
            if ($kit) { $candidates.Add((Join-Path $kit 'bin\qmllint.exe')) }
        }
    }
    # The fallback the Qt host's build script and package-windows.ps1 apply:
    # the newest version under C:\Qt, compared as a version, not a string.
    $kitNames = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { @('msvc2022_arm64', 'msvc2022_64') } else { @('msvc2022_64') }
    Get-ChildItem -Path 'C:\Qt' -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^\d+\.\d+\.\d+$' } |
        Sort-Object { [version]$_.Name } -Descending |
        ForEach-Object {
            foreach ($kitName in $kitNames) { $candidates.Add((Join-Path $_.FullName "$kitName\bin\qmllint.exe")) }
        }
    $onPath = Get-Command 'qmllint.exe' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -ne $onPath) { $candidates.Add($onPath.Source) }
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
    }
    $null
}

# Runs qmllint from $Dir with its JSON report on stdout. Syntax holds one
# "file:line:column: message" per syntax error; Lines is everything printed.
function Invoke-QmlLint([string]$Tool, [string]$Dir, [string[]]$Files) {
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $consoleEncoding = [Console]::OutputEncoding
    Push-Location -LiteralPath $Dir
    try {
        [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
        $lines = @(& $Tool --json - @Files 2>&1 | ForEach-Object { "$_" })
        $code = $LASTEXITCODE
    } finally {
        Pop-Location
        [Console]::OutputEncoding = $consoleEncoding
        $ErrorActionPreference = $previous
    }
    $report = $null
    foreach ($line in $lines) {
        if ($line.StartsWith('{"files"', [StringComparison]::Ordinal)) {
            try { $report = $line | ConvertFrom-Json } catch { $report = $null }
        }
    }
    $syntax = New-Object System.Collections.Generic.List[string]
    if ($null -ne $report) {
        foreach ($file in @($report.files)) {
            foreach ($warning in @($file.warnings)) {
                if ($warning.id -eq 'syntax') {
                    $syntax.Add("$($file.filename):$($warning.line):$($warning.column): $($warning.message)")
                }
            }
        }
    }
    [pscustomobject]@{ Code = $code; Lines = $lines; Report = $report; Syntax = $syntax.ToArray() }
}

function Test-QmlLint {
    $tool = Find-QmlLint
    if ($null -eq $tool) {
        $message = 'qmllint not found (CMAKE_PREFIX_PATH, C:\Qt\<version>\<kit>\bin, PATH): QML is NOT checked by this run.'
        if ($RequireQmlLint) { throw $message }
        Write-Host "[check] $message" -ForegroundColor Yellow
        return
    }

    # The gate first proves it still sees a syntax error: a qmllint that stops
    # reporting them would otherwise pass every file silently.
    $fixture = Join-Path $PSScriptRoot 'tests\qmllint'
    $probe = Invoke-QmlLint $tool $fixture @('broken.qml')
    if ($probe.Syntax.Count -eq 0) {
        $probe.Lines | Select-Object -Last 20 | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
        throw "qmllint self-test failed: '$tool' reports no syntax error for $fixture\broken.qml."
    }

    # Every QML file git would publish, wherever it lives; the fixture is not one.
    $repoRoot = Split-Path -Parent $PSScriptRoot
    $consoleEncoding = [Console]::OutputEncoding
    try {
        [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
        $listing = & git -C $repoRoot -c core.quotepath=off ls-files --cached --others --exclude-standard
    } finally {
        [Console]::OutputEncoding = $consoleEncoding
    }
    if ($LASTEXITCODE -ne 0) { throw 'qmllint: git ls-files failed.' }
    $files = @($listing | Where-Object {
            $_.EndsWith('.qml', [StringComparison]::Ordinal) -and
            -not $_.StartsWith('scripts/tests/qmllint/', [StringComparison]::Ordinal) -and
            (Test-Path -LiteralPath (Join-Path $repoRoot $_) -PathType Leaf)
        })
    if ($files.Count -eq 0) { throw 'qmllint: git lists no .qml file, so the scan would check nothing.' }

    Write-Host "[check] qmllint: $tool over $($files.Count) file(s)" -ForegroundColor Cyan
    $run = Invoke-QmlLint $tool $repoRoot $files
    if ($null -eq $run.Report) {
        $run.Lines | Select-Object -Last 20 | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
        throw "qmllint printed no JSON report (exit code $($run.Code))."
    }
    $syntax = $run.Syntax
    if ($syntax.Count -gt 0) {
        $syntax | Select-Object -First 20 | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
        if ($syntax.Count -gt 20) {
            Write-Host "  ... and $($syntax.Count - 20) more" -ForegroundColor Yellow
        }
        throw "qmllint: $($syntax.Count) syntax error(s); a QML file with one does not load."
    }
    if ($run.Code -ne 0) {
        $run.Lines | Select-Object -Last 20 | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
        throw "qmllint failed with exit code $($run.Code)."
    }
}

if ($QmlLintOnly) {
    Test-QmlLint
    Write-Host '[check] qmllint only: passed' -ForegroundColor Green
    exit 0
}

Write-Host '[check] NetRuleRouter workspace quality baseline' -ForegroundColor Cyan

Write-Host '[check] sync duplicates' -ForegroundColor Cyan
& (Join-Path $PSScriptRoot 'clean-sync-duplicates.ps1') -SelfTest
& (Join-Path $PSScriptRoot 'clean-sync-duplicates.ps1')

Write-Host '[check] comment hygiene: no task references or dates in comments' -ForegroundColor Cyan
Test-CommentHygiene

Write-Host '[check] comment hygiene: no doubled words' -ForegroundColor Cyan
Test-DoubledWords

Write-Host '[check] public docs: no internal mechanism or private-document terms' -ForegroundColor Cyan
Test-PublicDocsTerms

Write-Host '[check] panic strategy: panics unwind' -ForegroundColor Cyan
Test-PanicStrategy

if ($CommentHygieneOnly) {
    Write-Host '[check] comment hygiene only: passed' -ForegroundColor Green
    exit 0
}

Write-Host '[check] qmllint: no QML syntax errors' -ForegroundColor Cyan
Test-QmlLint

# Invoked as `cargo-fmt`, not `cargo fmt`: a user-level cargo alias named `fmt`
# shadows the subcommand and makes cargo emit a warning on stderr, which this
# script would report as a failure.
$cargoFmt = Get-Command 'cargo-fmt' -ErrorAction SilentlyContinue
if ($null -eq $cargoFmt) {
    throw 'cargo-fmt is not installed. Install it with `rustup component add rustfmt`.'
}
Invoke-ToolStep 'format' $cargoFmt.Source @('--all', '--', '--check')
Invoke-CargoStep 'clippy' @('clippy', '--workspace', '--all-targets', '--', '-D', 'warnings')

# Tests get a temp directory of their own, removed after the run: a file an
# antivirus scan still holds when a test's TempDir drops is left behind, and in
# the user's %TEMP% nothing would ever collect it.
$testTemp = Join-Path ([System.IO.Path]::GetTempPath()) "nrr-gate-$([guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $testTemp | Out-Null
$previousTmp, $previousTemp = $env:TMP, $env:TEMP
$env:TMP, $env:TEMP = $testTemp, $testTemp
try {
    Invoke-CargoStep 'tests' @('test', '--workspace')
    if ($IncludePrivileged) {
        $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            throw '-IncludePrivileged needs an elevated shell: the ignored tests open the WFP engine and edit routes.'
        }
        # One thread: these tests share the machine-wide filter engine and route table.
        Invoke-CargoStep 'privileged tests' @('test', '-p', 'nrr-platform-windows', '-p', 'nrr-service-runtime', '--', '--ignored', '--test-threads=1')
    }
} finally {
    $env:TMP, $env:TEMP = $previousTmp, $previousTemp
    foreach ($attempt in 1..5) {
        try {
            Remove-Item -LiteralPath $testTemp -Recurse -Force -ErrorAction Stop
            break
        } catch {
            if ($attempt -eq 5) { Write-Warning "test temp directory not removed: $testTemp" }
            else { Start-Sleep -Seconds 1 }
        }
    }
}

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
