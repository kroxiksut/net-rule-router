# The files a Windows package must carry: packaging\windows\package-contents.txt
# plus what the checkout names; and the symbols its archive must carry.
# Dot-sourced by package-windows.ps1 and check-windows-package.ps1, never run.

# -Symbols returns the PDBs the symbols archive must hold instead.
function Get-PackageContents {
    param(
        [Parameter(Mandatory)] [string]$RepoRoot,
        [Parameter(Mandatory)] [ValidateSet('full', 'headless')] [string]$Variant,
        [switch]$Installer,
        [switch]$Symbols
    )

    $manifest = Join-Path $RepoRoot 'packaging\windows\package-contents.txt'
    if (-not (Test-Path -LiteralPath $manifest)) {
        throw "Missing $manifest."
    }
    $symbolSets = @('symbols', 'symbols-full')
    $sets = @($(if ($Symbols) { 'symbols' } else { 'all' }))
    if ($Variant -eq 'full') { $sets += $(if ($Symbols) { 'symbols-full' } else { 'full' }) }
    if ($Installer -and -not $Symbols) { $sets += 'installer' }

    $paths = New-Object System.Collections.Generic.List[string]
    foreach ($line in [System.IO.File]::ReadAllLines($manifest)) {
        $text = ($line -replace '#.*$', '').Trim()
        if (-not $text) { continue }
        $fields = @($text -split '\s+')
        if ($fields.Count -ne 2) {
            throw "${manifest}: expected '<set> <path>', got '$text'."
        }
        if ((@('all', 'full', 'installer') + $symbolSets) -notcontains $fields[0]) {
            throw "${manifest}: unknown set '$($fields[0])'."
        }
        $isPdb = $fields[1] -like '*.pdb'
        if ($isPdb -ne ($symbolSets -contains $fields[0])) {
            throw "${manifest}: '$text' - debug symbols go in the symbols sets only, and nothing else does."
        }
        if ($sets -contains $fields[0]) { $paths.Add($fields[1]) }
    }
    if ($Symbols) {
        return @($paths | Sort-Object -Unique)
    }

    # Payload the package copies whole: every file of it must arrive.
    $payload = @('locales', 'presets')
    if ($Variant -eq 'full') { $payload += 'apps\desktop\qml' }
    foreach ($relative in $payload) {
        $source = (Resolve-Path -LiteralPath (Join-Path $RepoRoot $relative)).ProviderPath.TrimEnd('\')
        # Dot files (.gitkeep) are the checkout's, not the product's.
        foreach ($file in Get-ChildItem -LiteralPath $source -Recurse -File | Where-Object { -not $_.Name.StartsWith('.') }) {
            $paths.Add($relative + $file.FullName.Substring($source.Length))
        }
    }
    return @($paths | Sort-Object -Unique)
}

# The entries of $Expected missing under $Root.
function Get-MissingContents {
    param([Parameter(Mandatory)] [string]$Root, [Parameter(Mandatory)] [string[]]$Expected)

    return @($Expected | Where-Object { -not (Test-Path -LiteralPath (Join-Path $Root $_)) })
}
