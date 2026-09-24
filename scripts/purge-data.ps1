# Remove every trace of the product from this machine: the service, its data
# tree under %ProgramData%, the per-user directories the desktop surfaces write,
# and the QSettings hive. Windows counterpart of purge-data.sh.
#
# Dry-run by default: it prints what it would remove and touches nothing. Only
# -Yes deletes, and only the locations declared below — no pattern is ever
# expanded against the user profile.
#
# The audit trail is not part of a user cleanup, so %ProgramData%\NetRuleRouter\
# audit survives unless -PurgeAudit says otherwise.
#
# -Yes needs an elevated console: %ProgramData%\NetRuleRouter is machine-wide,
# and elevating from here would clean the wrong profile when the console user is
# not the administrator who answers the prompt.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File .\scripts\purge-data.ps1
#   powershell -ExecutionPolicy Bypass -File .\scripts\purge-data.ps1 -Yes
#   powershell -ExecutionPolicy Bypass -File .\scripts\purge-data.ps1 -Yes -PurgeAudit

[CmdletBinding()]
param(
    [Parameter()]
    [switch] $Yes,

    [Parameter()]
    [switch] $PurgeAudit,

    [Parameter()]
    [ValidateSet('auto', 'dev', 'release')]
    [string] $Profile = 'auto'
)

$ErrorActionPreference = 'Stop'

# Keep in sync with product_identity.rs (PRODUCT_NAME) and the Qt host's
# setOrganizationName / setApplicationName pair.
$productName = 'NetRuleRouter'

$dataRoot = if ($env:ProgramData) { Join-Path $env:ProgramData $productName } else { $null }
$auditDir = if ($dataRoot) { Join-Path $dataRoot 'audit' } else { $null }
$settingsHive = "HKCU:\Software\$productName"

# %APPDATA% is first in the UI-preferences candidate list, so it is where the
# preferences file actually lands; the other two hold logs, caches and the
# desktop surfaces' runtime coordination files. A development build keeps its
# own copy in the checkout instead.
$repoRoot = Split-Path -Parent $PSScriptRoot
$devDataRoot = Join-Path $repoRoot '.devdata'
$userRoots = @(
    $(if ($env:APPDATA) { Join-Path $env:APPDATA $productName }),
    $(if ($env:LOCALAPPDATA) { Join-Path $env:LOCALAPPDATA $productName }),
    $(if ($env:TEMP) { Join-Path $env:TEMP $productName }),
    $(if (Test-Path $devDataRoot) { $devDataRoot })
) | Where-Object { $_ }

$removed = New-Object System.Collections.Generic.List[string]
$absent = New-Object System.Collections.Generic.List[string]
$failed = New-Object System.Collections.Generic.List[string]

$isAdmin = (
    New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($Yes -and -not $isAdmin) {
    Write-Host "purge-data.ps1 -Yes must run from an elevated console." -ForegroundColor Yellow
    Write-Host "Re-run as administrator:" -ForegroundColor Yellow
    $again = "powershell -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Yes"
    if ($PurgeAudit) { $again += ' -PurgeAudit' }
    Write-Host "  $again"
    exit 3
}

function Remove-ProductPath {
    param([string] $Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        Write-Host "  absent       $Path" -ForegroundColor DarkGray
        $absent.Add($Path)
        return
    }
    if (-not $Yes) {
        Write-Host "  would remove $Path" -ForegroundColor Yellow
        return
    }
    try {
        Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
        Write-Host "  removed      $Path" -ForegroundColor Green
        $removed.Add($Path)
    }
    catch {
        Write-Host "  FAILED       $Path : $($_.Exception.Message)" -ForegroundColor Yellow
        $failed.Add($Path)
    }
}

# The data tree minus the audit directory, which a user cleanup never takes.
function Remove-DataRoot {
    if (-not $dataRoot) {
        Write-Host "  absent       %ProgramData% is not set" -ForegroundColor DarkGray
        return
    }
    if ($PurgeAudit) {
        Remove-ProductPath -Path $dataRoot
        return
    }
    if (-not (Test-Path -LiteralPath $dataRoot)) {
        Write-Host "  absent       $dataRoot" -ForegroundColor DarkGray
        $absent.Add($dataRoot)
        return
    }
    if (-not $Yes) {
        Write-Host "  would remove $dataRoot\* (keeping $auditDir)" -ForegroundColor Yellow
        return
    }
    $children = @(Get-ChildItem -LiteralPath $dataRoot -Force)
    if (-not ($children | Where-Object { $_.Name -eq 'audit' })) {
        # Nothing to preserve after all, so the root itself goes too.
        Remove-ProductPath -Path $dataRoot
        return
    }
    foreach ($child in $children) {
        if ($child.Name -eq 'audit') { continue }
        try {
            Remove-Item -LiteralPath $child.FullName -Recurse -Force -ErrorAction Stop
        }
        catch {
            Write-Host "  FAILED       $($child.FullName) : $($_.Exception.Message)" -ForegroundColor Yellow
            $failed.Add($child.FullName)
        }
    }
    Write-Host "  removed      $dataRoot\* (kept $auditDir)" -ForegroundColor Green
    $removed.Add("$dataRoot\* (audit kept)")
}

# Take the service down before the data goes, so a running service cannot
# rewrite what was just deleted.
function Invoke-ServiceUninstall {
    $uninstall = Join-Path $PSScriptRoot 'uninstall-service.ps1'
    if (-not (Test-Path -LiteralPath $uninstall)) {
        Write-Host "  absent       $uninstall (skipping service uninstall)" -ForegroundColor DarkGray
        return
    }
    if (-not $Yes) {
        Write-Host "  would run    $uninstall -Profile $Profile" -ForegroundColor Yellow
        return
    }
    Write-Host "==> $uninstall -Profile $Profile" -ForegroundColor Cyan
    try {
        & $uninstall -Profile $Profile
    }
    catch {
        # No binary to run `uninstall` from is not fatal here: the data below is
        # removed either way, and the caller is told the service stayed.
        Write-Host "uninstall-service.ps1 failed: $($_.Exception.Message)" -ForegroundColor Yellow
        $failed.Add('service uninstall')
    }
}

if (-not $Yes) {
    Write-Host "==> dry run: nothing will be deleted (pass -Yes to act)" -ForegroundColor Cyan
}
if (-not $PurgeAudit) {
    Write-Host "    audit trail at $auditDir is kept (-PurgeAudit removes it)" -ForegroundColor DarkGray
}

Write-Host "==> service" -ForegroundColor Cyan
Invoke-ServiceUninstall

Write-Host "==> machine-wide footprint" -ForegroundColor Cyan
Remove-DataRoot

Write-Host "==> profile of $env:USERNAME" -ForegroundColor Cyan
foreach ($path in $userRoots) { Remove-ProductPath -Path $path }
Remove-ProductPath -Path $settingsHive

Write-Host ""
if (-not $Yes) {
    Write-Host "Dry run complete - nothing was deleted. Re-run with -Yes to act." -ForegroundColor Cyan
    exit 0
}

Write-Host "==> summary" -ForegroundColor Cyan
if ($removed.Count -gt 0) {
    Write-Host "removed:" -ForegroundColor Green
    $removed | ForEach-Object { Write-Host "  $_" }
}
else {
    Write-Host "removed: nothing" -ForegroundColor DarkGray
}
if ($absent.Count -gt 0) {
    Write-Host "not present:" -ForegroundColor DarkGray
    $absent | ForEach-Object { Write-Host "  $_" }
}
if ($failed.Count -gt 0) {
    Write-Host "could not remove:" -ForegroundColor Yellow
    $failed | ForEach-Object { Write-Host "  $_" }
    exit 1
}

Write-Host "Purge complete." -ForegroundColor Green
