Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# A file-sync client (this repository lives under Yandex.Disk) resolves its own
# conflicts by leaving `name (2).ext` next to `name.ext`. Cargo auto-discovers
# `tests/*.rs`, so one such copy fails the build outright, and the copies are
# often left dehydrated — unreadable while the sync client isn't running, which
# fails any step that walks the tree. Deleted only when the original sits in the
# same directory: that is what makes the file a copy rather than a deliberate name.
$roots = @('apps', 'core', 'shared', 'scripts', 'locales', 'configs', 'docs') |
    ForEach-Object { Join-Path (Split-Path -Parent $PSScriptRoot) $_ } |
    Where-Object { Test-Path $_ }

$removed = 0
Get-ChildItem -Path $roots -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -notmatch '\\target\\' } |
    ForEach-Object {
        $copy = [regex]::Match($_.Name, '^(.+) \(\d+\)(\.[^.]+)$')
        if (-not $copy.Success) { return }
        $original = Join-Path $_.DirectoryName ($copy.Groups[1].Value + $copy.Groups[2].Value)
        if (-not (Test-Path -LiteralPath $original)) { return }
        Remove-Item -LiteralPath $_.FullName -Force -Confirm:$false -ErrorAction SilentlyContinue
        if (-not (Test-Path -LiteralPath $_.FullName)) {
            Write-Host "  removed $($_.FullName)" -ForegroundColor Yellow
            $removed += 1
        }
    }

if ($removed -gt 0) {
    Write-Host "[clean] removed $removed cloud-sync duplicate file(s)" -ForegroundColor Yellow
}
