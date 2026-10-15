param([switch]$SelfTest)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# A file-sync client (this repository lives under Yandex.Disk) resolves its own
# conflicts by leaving `name (2).ext` next to `name.ext`. Cargo auto-discovers
# `tests/*.rs`, so one such copy fails the build outright. A copy is deleted only
# when its bytes equal the original's: the sync client parks real edits in such
# copies, so one that differs (or cannot be read, as a dehydrated placeholder
# while the client is stopped) stops the run for a person to merge.

function Test-SameBytes([string]$A, [string]$B) {
    (Get-FileHash -LiteralPath $A -Algorithm SHA256).Hash -eq (Get-FileHash -LiteralPath $B -Algorithm SHA256).Hash
}

# Returns the number of copies left in place.
function Invoke-CleanRoot([string]$Base) {
    $roots = @('apps', 'core', 'shared', 'scripts', 'locales', 'configs', 'docs') |
        ForEach-Object { Join-Path $Base $_ } |
        Where-Object { Test-Path $_ }
    if (-not $roots) { return 0 }

    $removed = 0
    $kept = 0
    foreach ($file in Get-ChildItem -Path $roots -Recurse -File -ErrorAction SilentlyContinue) {
        if ($file.FullName -match '\\target\\') { continue }
        $copy = [regex]::Match($file.Name, '^(.+) \(\d+\)(\.[^.]+)$')
        if (-not $copy.Success) { continue }
        $original = Join-Path $file.DirectoryName ($copy.Groups[1].Value + $copy.Groups[2].Value)
        if (-not (Test-Path -LiteralPath $original)) { continue }
        try {
            $same = Test-SameBytes $file.FullName $original
        } catch {
            Write-Host "  unreadable: $($file.FullName) (is the sync client running?)" -ForegroundColor Red
            $kept += 1
            continue
        }
        if ($same) {
            Remove-Item -LiteralPath $file.FullName -Force -Confirm:$false
            Write-Host "  removed $($file.FullName)" -ForegroundColor Yellow
            $removed += 1
        } else {
            $newer = if ($file.LastWriteTimeUtc -gt (Get-Item -LiteralPath $original).LastWriteTimeUtc) { 'copy' } else { 'original' }
            Write-Host "  differs: $($file.FullName) (newer: $newer)" -ForegroundColor Red
            $kept += 1
        }
    }

    if ($removed -gt 0) {
        Write-Host "[clean] removed $removed cloud-sync duplicate file(s)" -ForegroundColor Yellow
    }
    return $kept
}

function Invoke-SelfTest {
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("nrr-sync-selftest-" + [guid]::NewGuid().ToString('N'))
    $core = Join-Path $tmp 'core'
    New-Item -ItemType Directory -Path $core -Force | Out-Null
    try {
        Set-Content -LiteralPath (Join-Path $core 'a.rs') -Value 'same' -Encoding ascii
        Set-Content -LiteralPath (Join-Path $core 'a (2).rs') -Value 'same' -Encoding ascii
        $kept = Invoke-CleanRoot $tmp 6>$null
        if ($kept -ne 0 -or (Test-Path -LiteralPath (Join-Path $core 'a (2).rs'))) {
            throw 'sync duplicates self-test failed: an identical copy was not removed.'
        }
        Set-Content -LiteralPath (Join-Path $core 'b.rs') -Value 'old' -Encoding ascii
        Set-Content -LiteralPath (Join-Path $core 'b (2).rs') -Value 'edit' -Encoding ascii
        $kept = Invoke-CleanRoot $tmp 6>$null
        if ($kept -eq 0 -or -not (Test-Path -LiteralPath (Join-Path $core 'b (2).rs'))) {
            throw 'sync duplicates self-test failed: a differing copy was deleted or did not stop the run.'
        }
    } finally {
        Remove-Item -LiteralPath $tmp -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue
    }
}

if ($SelfTest) {
    Invoke-SelfTest
    return
}

$kept = Invoke-CleanRoot (Split-Path -Parent $PSScriptRoot)
if ($kept -gt 0) {
    throw "[clean] $kept cloud-sync copy(ies) differ from the original: merge each by hand, then delete the copy."
}
