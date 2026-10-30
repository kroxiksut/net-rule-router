#Requires -Version 5.1
<#
.SYNOPSIS
    Checks the portable zip, the MSI and the symbols archive package-windows.ps1 left in
    a folder against packaging\windows\package-contents.txt.

.DESCRIPTION
    The MSI is unpacked by an administrative install (msiexec /a): it only
    copies the files out. No service is registered and no custom action runs,
    so the machine and its network stay as they were. The EXE is not checked:
    it is built from the same folder as the MSI, and unpacking it would need
    innoextract. Neither the zip nor the MSI may carry a .pdb; both have the
    build's <name>-symbols.zip beside them holding every PDB the symbols sets
    list (<name> is the MSI's name, the zip's without -portable). The MSI's
    tables are read too, from a copy: its licence page must show the end-user
    agreement, its Russian wizard must be embedded, its options page must offer
    the offline documentation, and the full package must ask whether the
    shortcuts and PATH are for all users or only the installer.

.PARAMETER Dist
    The folder holding the -portable.zip, the .msi and the -symbols.zip of one variant.

.PARAMETER Variant
    full or headless, as packaged.
#>
param(
    [Parameter(Mandatory)] [string]$Dist,
    [ValidateSet('full', 'headless')] [string]$Variant = 'full'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'lib\package-contents.ps1')

$failures = New-Object System.Collections.Generic.List[string]

# Wherever a format nests the package folder, it is the one holding the service.
function Test-Unpacked {
    param([string]$Artifact, [string]$Under, [string[]]$Expected)

    $service = Get-ChildItem -LiteralPath $Under -Recurse -File -Filter 'nrr-service.exe' | Select-Object -First 1
    if (-not $service) {
        $failures.Add("${Artifact}: nrr-service.exe not found inside.")
        return
    }
    $missing = Get-MissingContents -Root $service.DirectoryName -Expected $Expected
    if ($missing) {
        $failures.Add("$Artifact lacks what packaging\windows\package-contents.txt requires: $($missing -join ', ')")
    } else {
        Write-Host "[contents] ${Artifact}: $($Expected.Count) paths present" -ForegroundColor Green
    }
    $pdbs = @(Get-ChildItem -LiteralPath $Under -Recurse -File -Filter '*.pdb')
    if ($pdbs) {
        $failures.Add("$Artifact carries debug symbols: $(($pdbs | ForEach-Object { $_.Name }) -join ', ')")
    }
}

# Windows Installer's automation object is reached by name, with bare values:
# a string PowerShell wrapped reaches it as a type mismatch.
function Invoke-MsiMember {
    param($Object, [string] $Member, [string] $Kind = 'InvokeMethod', [object[]] $Arguments = @())
    $bare = [object[]]@($Arguments | ForEach-Object { $_.PSObject.BaseObject })
    return $Object.GetType().InvokeMember($Member, [System.Reflection.BindingFlags]$Kind, $null, $Object, $bare)
}

function Get-MsiValues {
    param($Installer, $Database, [string] $Query)
    $view = Invoke-MsiMember $Database 'OpenView' -Arguments @($Query)
    Invoke-MsiMember $view 'Execute' | Out-Null
    $values = @()
    while ($record = Invoke-MsiMember $view 'Fetch') {
        $values += Invoke-MsiMember $record 'StringData' 'GetProperty' @(1)
        [void][System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($record)
    }
    Invoke-MsiMember $view 'Close' | Out-Null
    [void][System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($view)
    return , $values
}

# The licence page shows the agreement, not MPL-2.0, and a Russian Windows gets
# the Russian wizard: the ru-RU transform is stored under 1049 and listed in
# the package's languages. Read from a copy, opened without saving.
function Test-MsiLanguages {
    param([System.IO.FileInfo] $Msi, [string] $Copy)
    Copy-Item -LiteralPath $Msi.FullName -Destination $Copy
    $installer = New-Object -ComObject WindowsInstaller.Installer
    $database = Invoke-MsiMember $installer 'OpenDatabase' -Arguments @($Copy, 1)
    try {
        $licence = "$(Get-MsiValues $installer $database "SELECT ``Text`` FROM ``Control`` WHERE ``Dialog_`` = 'LicenseAgreementDlg' AND ``Control`` = 'LicenseText'")"
        $language = "$(Get-MsiValues $installer $database "SELECT ``Value`` FROM ``Property`` WHERE ``Property`` = 'ProductLanguage'")"
        $storages = Get-MsiValues $installer $database 'SELECT `Name` FROM `_Storages`'
        $summary = Invoke-MsiMember $database 'SummaryInformation' 'GetProperty' @(0)
        $template = "$(Invoke-MsiMember $summary 'Property' 'GetProperty' @(7))"
        [void][System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($summary)
        $before = $failures.Count
        if ($licence -notmatch 'NetRuleRouter End-User License Agreement') {
            $failures.Add("$($Msi.Name): the licence page does not show the end-user agreement.")
        }
        # package-windows.ps1 has applied the transform to a copy and seen the
        # wizard turn Russian; here it must still be inside, under its name.
        if ($language -ne '1033' -or $storages -notcontains '1049' -or $template -notmatch ';1033,1049$') {
            $failures.Add("$($Msi.Name): no Russian wizard inside (ProductLanguage '$language', storages '$($storages -join ', ')', template '$template').")
        }
        # The full package asks whose Start menu, desktop and PATH get it.
        if ($Variant -eq 'full') {
            $scopes = Get-MsiValues $installer $database "SELECT ``Value`` FROM ``RadioButton`` WHERE ``Property`` = 'NRR_INSTALL_FOR_CHOICE'"
            if ($scopes -notcontains 'all' -or $scopes -notcontains 'me') {
                $failures.Add("$($Msi.Name): the wizard does not offer all users / only me (found '$($scopes -join ', ')').")
            }
        }
        # The offline documentation is a box on the options page, as in the EXE.
        $docsBox = "$(Get-MsiValues $installer $database "SELECT ``Property`` FROM ``Control`` WHERE ``Dialog_`` = 'NrrOptionsDlg' AND ``Control`` = 'Docs'")"
        if ($docsBox -ne 'NRR_DOCS') {
            $failures.Add("$($Msi.Name): the options page has no documentation box (found '$docsBox').")
        }
        if ($failures.Count -eq $before) {
            Write-Host "[contents] $($Msi.Name): agreement on the licence page, Russian wizard embedded, documentation offered" -ForegroundColor Green
        }
    } finally {
        [void][System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($database)
        [void][System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($installer)
        [GC]::Collect()
        [GC]::WaitForPendingFinalizers()
    }
}

$symbolArchives = @(Get-ChildItem -LiteralPath $Dist -Filter '*-symbols.zip' -File)
$symbolNames = @($symbolArchives | ForEach-Object { $_.Name })
$msis = @(Get-ChildItem -LiteralPath $Dist -Filter '*.msi' -File)
$zips = @(Get-ChildItem -LiteralPath $Dist -Filter '*-portable.zip' -File)
if ($msis.Count -eq 0 -or $zips.Count -eq 0) {
    throw "Expected a -portable.zip and a .msi in '$Dist', found $($zips.Count) and $($msis.Count)."
}
# A zip that is neither would reach the release page with no name telling what it is.
$known = @($symbolNames) + @($zips | ForEach-Object { $_.Name })
foreach ($other in @(Get-ChildItem -LiteralPath $Dist -Filter '*.zip' -File | Where-Object { $known -notcontains $_.Name })) {
    $failures.Add("$($other.Name) is neither a -portable.zip nor a -symbols.zip.")
}
foreach ($artifact in @($zips) + @($msis)) {
    $expected = "$($artifact.BaseName -replace '-portable$', '')-symbols.zip"
    if ($symbolNames -notcontains $expected) {
        $failures.Add("$($artifact.Name) has no $expected beside it.")
    }
}

$work = Join-Path ([System.IO.Path]::GetTempPath()) "nrr-contents-$([guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $work | Out-Null
try {
    $index = 0
    foreach ($zip in $zips) {
        $target = Join-Path $work "zip$index"
        $index++
        Expand-Archive -LiteralPath $zip.FullName -DestinationPath $target
        Test-Unpacked -Artifact $zip.Name -Under $target -Expected (Get-PackageContents -RepoRoot $repoRoot -Variant $Variant)
    }
    foreach ($msi in $msis) {
        $target = Join-Path $work "msi$index"
        $log = Join-Path $work "msi$index.log"
        $index++
        $arguments = @('/a', "`"$($msi.FullName)`"", '/qn', "TARGETDIR=`"$target`"", '/l*v', "`"$log`"")
        $process = Start-Process -FilePath 'msiexec.exe' -ArgumentList $arguments -Wait -PassThru
        if ($process.ExitCode -ne 0) {
            if (Test-Path -LiteralPath $log) {
                Get-Content -LiteralPath $log -Tail 25 | Write-Host
            }
            $failures.Add("msiexec /a $($msi.Name) failed with exit code $($process.ExitCode).")
            continue
        }
        Test-Unpacked -Artifact $msi.Name -Under $target -Expected (Get-PackageContents -RepoRoot $repoRoot -Variant $Variant -Installer)
        Test-MsiLanguages -Msi $msi -Copy (Join-Path $work "msi$index-tables.msi")
    }
    $requiredSymbols = @(Get-PackageContents -RepoRoot $repoRoot -Variant $Variant -Symbols)
    foreach ($archive in $symbolArchives) {
        $target = Join-Path $work "symbols$index"
        $index++
        Expand-Archive -LiteralPath $archive.FullName -DestinationPath $target
        $carried = @(Get-ChildItem -LiteralPath $target -Recurse -File -Filter '*.pdb' | Where-Object { $_.Length -gt 0 } | ForEach-Object { $_.Name })
        $missing = @($requiredSymbols | Where-Object { $carried -notcontains $_ })
        if ($missing) {
            $failures.Add("$($archive.Name) lacks the symbols of: $($missing -join ', ')")
        } else {
            Write-Host "[contents] $($archive.Name): $($requiredSymbols.Count) symbol files present" -ForegroundColor Green
        }
    }
} finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}

if ($failures.Count -gt 0) {
    foreach ($failure in $failures) {
        if ($env:GITHUB_ACTIONS -eq 'true') {
            Write-Host "::error title=package contents::$failure"
        }
        Write-Host "[contents] $failure" -ForegroundColor Red
    }
    throw "$($failures.Count) package check(s) failed."
}
