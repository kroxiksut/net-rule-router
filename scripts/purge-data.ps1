# Remove every trace of the product from this machine: the service, its data
# tree under %ProgramData%, the dev staging directory, the per-user directories
# the desktop surfaces write, the tray's launch-at-login entry and the QSettings
# hive. Windows counterpart of purge-data.sh.
#
# Nothing is deleted while the service is still registered: an auto-start
# service would recreate the data tree at the next boot. The script stops with
# exit code 4 instead.
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
# Other Windows accounts' data is listed, never deleted: an elevated delete
# inside a profile its owner can rearrange could be steered elsewhere. A run
# that finished but left such data exits with 5.
#
# -UserOnly takes the console user's own data alone, needs no elevation and
# leaves the service and the machine-wide tree to an elevated run. The MSI
# removes the installing user's data this way, since its elevated half runs
# as SYSTEM.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File .\scripts\purge-data.ps1
#   powershell -ExecutionPolicy Bypass -File .\scripts\purge-data.ps1 -Yes
#   powershell -ExecutionPolicy Bypass -File .\scripts\purge-data.ps1 -Yes -PurgeAudit
#   powershell -ExecutionPolicy Bypass -File .\scripts\purge-data.ps1 -Yes -UserOnly

[CmdletBinding()]
param(
    [Parameter()]
    [switch] $Yes,

    [Parameter()]
    [switch] $PurgeAudit,

    [Parameter()]
    [switch] $UserOnly,

    [Parameter()]
    [ValidateSet('auto', 'dev', 'release')]
    [string] $Profile = 'auto'
)

$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'lib\service-paths.ps1')

# Also the Qt host's setOrganizationName / setApplicationName pair.
$productName = $NrrProductName

$dataRoot = if ($env:ProgramData) { Join-Path $env:ProgramData $productName } else { $null }
$auditDir = if ($dataRoot) { Join-Path $dataRoot 'audit' } else { $null }
$settingsHive = "HKCU:\Software\$productName"

# %APPDATA% is first in the UI-preferences candidate list, so it is where the
# preferences file actually lands; the other two hold logs, caches and the
# desktop surfaces' runtime coordination files.
$userRoots = @(
    $(if ($env:APPDATA) { Join-Path $env:APPDATA $productName }),
    $(if ($env:LOCALAPPDATA) { Join-Path $env:LOCALAPPDATA $productName }),
    $(if ($env:TEMP) { Join-Path $env:TEMP $productName })
) | Where-Object { $_ }

$removed = New-Object System.Collections.Generic.List[string]
$absent = New-Object System.Collections.Generic.List[string]
$failed = New-Object System.Collections.Generic.List[string]
$leftForOthers = New-Object System.Collections.Generic.List[string]

$isAdmin = (
    New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($Yes -and -not $isAdmin -and -not $UserOnly) {
    Write-Host "purge-data.ps1 -Yes must run from an elevated console." -ForegroundColor Yellow
    Write-Host "Re-run as administrator:" -ForegroundColor Yellow
    $again = "powershell -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Yes"
    if ($PurgeAudit) { $again += ' -PurgeAudit' }
    if ($Profile -ne 'auto') { $again += " -Profile $Profile" }
    Write-Host "  $again"
    exit 3
}

# A filesystem path names its $Root and is deleted without following links:
# elevated, under a folder its owner can write to. Registry keys pass no root.
function Remove-ProductPath {
    param([string] $Path, [string] $Root)

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
        if ($Root) {
            $refused = Remove-TreeNoFollow -Path $Path -Root $Root
            if ($refused) { throw $refused }
        }
        else {
            Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
        }
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
        Remove-ProductPath -Path $dataRoot -Root $env:ProgramData
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
        Remove-ProductPath -Path $dataRoot -Root $env:ProgramData
        return
    }
    foreach ($child in $children) {
        if ($child.Name -eq 'audit') { continue }
        try {
            $refused = Remove-TreeNoFollow -Path $child.FullName -Root $env:ProgramData
            if ($refused) { throw $refused }
        }
        catch {
            Write-Host "  FAILED       $($child.FullName) : $($_.Exception.Message)" -ForegroundColor Yellow
            $failed.Add($child.FullName)
        }
    }
    Write-Host "  removed      $dataRoot\* (kept $auditDir)" -ForegroundColor Green
    $removed.Add("$dataRoot\* (audit kept)")
}

# Take the service down before the data goes: a running service rewrites what
# was just deleted, and a registered auto-start one recreates it at boot.
function Invoke-ServiceUninstall {
    $uninstall = Join-Path $PSScriptRoot 'uninstall-service.ps1'
    if (-not (Test-ServiceRegistered)) {
        Write-Host "  absent       service $NrrServiceName (not registered)" -ForegroundColor DarkGray
        $absent.Add("service $NrrServiceName")
        return
    }
    if (-not $Yes) {
        Write-Host "  would run    $uninstall -Profile $Profile (service $NrrServiceName is registered)" -ForegroundColor Yellow
        return
    }
    Write-Host "==> $uninstall -Profile $Profile" -ForegroundColor Cyan
    try {
        & $uninstall -Profile $Profile
    }
    catch {
        Write-Host "uninstall-service.ps1 failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }
    # The registration, not the child's exit code, is what decides.
    if (Test-ServiceRegistered) {
        Write-Host ""
        if (Test-ServiceDeletePending) {
            Write-Host "Service $NrrServiceName is marked for deletion but still registered; it goes at the next reboot." -ForegroundColor Yellow
            Write-Host "Reboot, then re-run this script." -ForegroundColor Yellow
        }
        else {
            Write-Host "Service $NrrServiceName is still registered, so nothing was deleted:" -ForegroundColor Yellow
            Write-Host "it would recreate $dataRoot at the next start." -ForegroundColor Yellow
            Write-Host "Remove it first, from this elevated console:" -ForegroundColor Yellow
            Write-Host "  sc.exe stop $NrrServiceName"
            Write-Host "  sc.exe delete $NrrServiceName"
            Write-Host "then re-run this script." -ForegroundColor Yellow
        }
        exit 4
    }
    $removed.Add("service $NrrServiceName")
}

# Only a value that launches our tray: the same name written by another tool
# is that tool's entry.
function Remove-TrayAutostart {
    param([string] $RunKey = $NrrAutostartKey)

    $label = "$RunKey\$NrrAutostartValueName"
    $command = $null
    try {
        $command = (Get-ItemProperty -Path $RunKey -Name $NrrAutostartValueName -ErrorAction Stop).$NrrAutostartValueName
    }
    catch {
        Write-Host "  absent       $label" -ForegroundColor DarkGray
        $absent.Add($label)
        return
    }
    if ("$command" -notlike "*$NrrTrayExeName*") {
        Write-Host "  kept         $label (launches '$command', not $NrrTrayExeName)" -ForegroundColor DarkGray
        return
    }
    if (-not $Yes) {
        Write-Host "  would remove $label" -ForegroundColor Yellow
        return
    }
    try {
        Remove-ItemProperty -Path $RunKey -Name $NrrAutostartValueName -ErrorAction Stop
        Write-Host "  removed      $label" -ForegroundColor Green
        $removed.Add($label)
    }
    catch {
        Write-Host "  FAILED       $label : $($_.Exception.Message)" -ForegroundColor Yellow
        $failed.Add($label)
    }
}

# Profiles of real accounts (local, domain, Microsoft Entra ID) other than the
# console user's; system and service profiles never ran the desktop app.
function Get-OtherUserProfiles {
    $self = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $list = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
    foreach ($entry in @(Get-ChildItem -LiteralPath $list -ErrorAction SilentlyContinue)) {
        $sid = $entry.PSChildName
        if ($sid -eq $self -or $sid -notmatch '^S-1-(5-21|12-1)-') { continue }
        $path = (Get-ItemProperty -LiteralPath $entry.PSPath -ErrorAction SilentlyContinue).ProfileImagePath
        if ($path) { [Environment]::ExpandEnvironmentVariables($path) }
    }
}

# Read-only: what other accounts keep, for them to remove themselves.
function Show-OtherUserData {
    $found = 0
    foreach ($userProfile in @(Get-OtherUserProfiles)) {
        foreach ($relative in @('AppData\Roaming', 'AppData\Local', 'AppData\Local\Temp')) {
            $path = Join-Path $userProfile "$relative\$productName"
            if (Test-Path -LiteralPath $path) {
                Write-Host "  left         $path" -ForegroundColor Yellow
                $leftForOthers.Add($path)
                $found++
            }
        }
    }
    if ($found -eq 0) {
        Write-Host "  none found" -ForegroundColor DarkGray
    }
}

if (-not $Yes) {
    Write-Host "==> dry run: nothing will be deleted (pass -Yes to act)" -ForegroundColor Cyan
}
if (-not $PurgeAudit) {
    Write-Host "    audit trail at $auditDir is kept (-PurgeAudit removes it)" -ForegroundColor DarkGray
}

if (-not $UserOnly) {
    Write-Host "==> service" -ForegroundColor Cyan
    Invoke-ServiceUninstall

    Write-Host "==> machine-wide footprint" -ForegroundColor Cyan
    Remove-DataRoot
    # The default location only: a -StageDir of the caller's choosing is not known here.
    if ($NrrDevStageDir) { Remove-ProductPath -Path $NrrDevStageDir -Root $env:ProgramW6432 }
}

Write-Host "==> profile of $env:USERNAME" -ForegroundColor Cyan
foreach ($path in $userRoots) { Remove-ProductPath -Path $path -Root (Split-Path -Parent $path) }
Remove-ProductPath -Path $settingsHive
Remove-TrayAutostart

if (-not $UserOnly) {
    Write-Host "==> other Windows accounts (listed, not deleted)" -ForegroundColor Cyan
    Show-OtherUserData
}

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
if ($leftForOthers.Count -gt 0) {
    Write-Host "left for their own accounts to remove (sign in as that user and delete the folder):" -ForegroundColor Yellow
    $leftForOthers | ForEach-Object { Write-Host "  $_" }
}
if ($failed.Count -gt 0) {
    Write-Host "could not remove:" -ForegroundColor Yellow
    $failed | ForEach-Object { Write-Host "  $_" }
    exit 1
}

Write-Host "Purge complete." -ForegroundColor Green
# Done, but other accounts still hold data: an uninstaller tells the user so.
if ($leftForOthers.Count -gt 0) { exit 5 }
