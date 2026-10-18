#Requires -Version 5.1
<#
.SYNOPSIS
    Checks the zip and the MSI package-windows.ps1 left in a folder against
    packaging\windows\package-contents.txt.

.DESCRIPTION
    The MSI is unpacked by an administrative install (msiexec /a): it only
    copies the files out. No service is registered and no custom action runs,
    so the machine and its network stay as they were. The EXE is not checked:
    it is built from the same folder as the MSI, and unpacking it would need
    innoextract.

.PARAMETER Dist
    The folder holding the .zip and the .msi of one variant.

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
}

$msis = @(Get-ChildItem -LiteralPath $Dist -Filter '*.msi' -File)
$zips = @(Get-ChildItem -LiteralPath $Dist -Filter '*.zip' -File)
if ($msis.Count -eq 0 -or $zips.Count -eq 0) {
    throw "Expected a .zip and a .msi in '$Dist', found $($zips.Count) and $($msis.Count)."
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
