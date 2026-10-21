#Requires -Version 5.1
# Service and data steps the Windows installers (Inno Setup, WiX) run. It is
# installed as scripts\setup-actions.ps1, beside the user scripts it reuses, so
# the installers add no second way to register the service, restore the
# network or remove data.
#
#   Stop        before files are replaced: stop the service so its binary is free
#   MarkStop    before the MSI's own stop: mark it as wanted, or the service
#               restarts itself mid-removal
#   Register    files in place: register the service from this folder and start it
#   Unregister  removal: stop and unregister the service, restore the network,
#               and remove the service copy a portable install left under
#               Program Files once nothing is registered; start again a service
#               another copy registered, which the MSI stopped by name; drop
#               the tray's launch at sign-in and the PATH entry that name this
#               folder; -RemoveData also erases the service's data and that of the
#               account running this (other accounts' data is listed, not
#               deleted), -RemoveAudit the audit trail as well
#   RemoveUserData  the running account's own data alone, without elevation:
#               the MSI's elevated half runs as SYSTEM, so it calls this as
#               the installing user
#   Rollback    a failed install: stop the service; after a fresh install
#               (no -Upgrade) also unregister it
#   Provision   files in place, before Register: hand -Primary, -Secondary,
#               -Settings and -SecondaryUnset to `nrr-service provision-stage`,
#               which checks the files and copies them into the service's
#               protected data folder; nothing named means nothing to do. The
#               exit code is the service binary's (10-14 a refused file or
#               option, see its provision-check verb)
#
# Never interactive: installers run it hidden, and the MSI runs it as SYSTEM.
# Exit code 0 means every step succeeded; 2 that removal succeeded but other
# Windows accounts keep data of their own (listed in the log).

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Stop', 'MarkStop', 'Register', 'Unregister', 'RemoveUserData', 'Rollback', 'Provision')]
    [string] $Action,

    [Parameter()]
    [switch] $RemoveData,

    [Parameter()]
    [switch] $RemoveAudit,

    [Parameter()]
    [switch] $Upgrade,

    [Parameter()]
    [string] $LogPath,

    # Provision only. Empty means not given: an unset MSI property arrives so.
    [Parameter()]
    [string] $Primary,

    [Parameter()]
    [string] $Secondary,

    [Parameter()]
    [string] $Settings,

    [Parameter()]
    [string] $SecondaryUnset,

    # The same four as one argument, `primary=<path>|secondary=<path>|
    # settings=<path>|secondary-unset=<value>`: an installer always passes it
    # whole, so an unset value never leaves a parameter without its argument.
    # A Windows path cannot hold `|`.
    [Parameter()]
    [string] $ProvisionSpec
)

$ErrorActionPreference = 'Stop'

# Setup runs Stop from its temporary folder, where both files land side by side.
$lib = Join-Path $PSScriptRoot 'lib\service-paths.ps1'
if (-not (Test-Path -LiteralPath $lib)) { $lib = Join-Path $PSScriptRoot 'service-paths.ps1' }
. $lib

$installDir = Split-Path -Parent $PSScriptRoot
$console = Join-Path $installDir 'nrr-cli.exe'

if ($LogPath) {
    try { Start-Transcript -Path $LogPath -Append | Out-Null } catch { }
}

# $true once no service process is left: stopped, or never registered.
function Test-NrrServiceStopped {
    $service = Get-Service -Name $NrrServiceName -ErrorAction SilentlyContinue
    return (-not $service -or $service.Status -eq 'Stopped')
}

function Stop-NrrService {
    if (Test-NrrServiceStopped) { return $true }
    Write-Host "==> stopping $NrrServiceName"
    Set-NrrDeliberateStop
    $null = Invoke-NativeCommand -FilePath (Get-SystemTool 'sc.exe') -ArgumentList @('stop', $NrrServiceName)
    # Teardown restores DNS and unwinds filters; give it more than SCM's usual wait.
    if (Wait-ServiceStatus -Name $NrrServiceName -Status Stopped -Seconds 60) { return $true }
    # A process stuck in its stop keeps the registration and would put back
    # what the reset removes; the files it runs from are about to go anyway.
    $servicePid = (Get-CimInstance -ClassName Win32_Service -Filter "Name='$NrrServiceName'" -ErrorAction SilentlyContinue).ProcessId
    if ($servicePid) {
        Write-Host "    $NrrServiceName did not stop; ending its process $servicePid"
        Stop-Process -Id $servicePid -Force -ErrorAction SilentlyContinue
        $null = Wait-ServiceStatus -Name $NrrServiceName -Status Stopped -Seconds 15
    }
    return (Test-NrrServiceStopped)
}

# A registration pointing elsewhere belongs to another copy (a portable folder,
# say), and removing this installation must not take it down.
function Test-RegisteredFromHere {
    $registered = Get-ServiceImagePath
    if (-not $registered) { return $true }
    $root = [IO.Path]::GetFullPath($installDir).TrimEnd('\') + '\'
    try { $full = [IO.Path]::GetFullPath($registered) } catch { return $false }
    return $full.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)
}

function Invoke-UserScript {
    param([string] $Name, [hashtable] $Arguments = @{})
    $script = Join-Path $PSScriptRoot $Name
    Write-Host "==> $Name $(($Arguments.Keys | ForEach-Object { "-$_" }) -join ' ')"
    # A script that ends without `exit` leaves the previous code standing.
    $global:LASTEXITCODE = 0
    try {
        & $script @Arguments | Out-Host
        return $LASTEXITCODE
    }
    catch {
        Write-Host "    $Name failed: $($_.Exception.Message)"
        return 1
    }
}

# Unregistering already sweeps filters and the DNS redirect when the service
# stopped cleanly; the offline reset catches whatever a crashed instance left.
# The DNS redirect is then swept once more without the binary: it lives in the
# registry, and nothing removed with the package could lift it after a reboot.
function Restore-Network {
    $code = 1
    if (Test-Path -LiteralPath $console) {
        Write-Host '==> nrr-cli reset-network --confirm'
        $code = Invoke-NativeCommand -FilePath $console -ArgumentList @('reset-network', '--confirm')
    }
    else {
        Write-Host "    $console is missing; only the DNS redirect is swept"
    }
    if (-not (Remove-NrrDnsRedirect) -and $code -eq 0) { $code = 1 }
    return $code
}

# The network back after a removal. A service that would not stop still loses
# its DNS redirect: the files and the process go with the package, and a
# redirect left in the registry would outlive every reboot with nobody to lift
# it. Returns the exit code to report.
function Restore-NetworkAfterRemoval {
    if (Test-NrrServiceStopped) { return (Restore-Network) }
    Write-Host '    the service is still running; only the DNS redirect is swept'
    $null = Remove-NrrDnsRedirect
    return 1
}

# 'gone' once no registration is left, 'foreign' when another copy owns it,
# 'stuck' when ours is still registered (marked for deletion until a reboot).
function Remove-OwnService {
    if (-not (Test-ServiceRegistered)) { return 'gone' }
    if (-not (Test-RegisteredFromHere)) {
        Write-Host "    the service is registered from '$(Get-ServiceImagePath)', not from $installDir; left in place"
        return 'foreign'
    }
    $null = Invoke-UserScript 'uninstall-service.ps1'
    if (Test-ServiceRegistered) { return 'stuck' }
    return 'gone'
}

# A service installed from a portable folder runs from a copy in
# '<Program Files>\NetRuleRouter Service' (the service names it from the same
# product name). Removed only once no registration is left, so a copy that is
# still the registered service is never taken. Program Files is asked of the
# shell, not of the environment, and both bitnesses are covered: the copy sits
# under the one matching the service build.
function Remove-ServiceCopy {
    $leaf = "$NrrProductName Service"
    $roots = @(
        [Environment]::GetFolderPath('ProgramFiles'),
        [Environment]::GetFolderPath('ProgramFilesX86')
    ) | Where-Object { $_ } | Select-Object -Unique
    $failed = $false
    foreach ($root in $roots) {
        $copy = Join-Path $root $leaf
        if (-not (Test-Path -LiteralPath $copy)) { continue }
        Write-Host "==> removing $copy"
        $refused = Remove-TreeNoFollow -Path $copy -Root $root
        if ($refused) {
            Write-Host "    $copy was not removed: $refused"
            $failed = $true
        }
    }
    return (-not $failed)
}

# The MSI stops the service by name before Unregister runs, even one another
# copy registered. That copy is started again when it starts with Windows.
function Resume-ForeignService {
    $service = Get-Service -Name $NrrServiceName -ErrorAction SilentlyContinue
    if (-not $service -or $service.Status -ne 'Stopped' -or "$($service.StartType)" -ne 'Automatic') { return }
    Write-Host "==> starting $NrrServiceName again from '$(Get-ServiceImagePath)'"
    $null = Invoke-NativeCommand -FilePath (Get-SystemTool 'sc.exe') -ArgumentList @('start', $NrrServiceName)
    if (-not (Wait-ServiceStatus -Name $NrrServiceName -Status Running -Seconds 30)) {
        Write-Host "    $NrrServiceName did not start again"
    }
}

# A PATH entry as the console's PATH action compares it: quotes, spaces and
# trailing separators dropped, slashes and case folded.
function Get-PathEntryKey {
    param([string] $Entry)
    $key = $Entry.Trim().Trim('"').Trim().TrimEnd('\', '/').Replace('/', '\')
    return $key.ToLowerInvariant()
}

# Per-user entries naming this folder: the tray's launch at sign-in and the
# console on PATH. Only hives loaded now are reachable, which covers the account
# running the removal and every signed-in one; a signed-out account keeps
# entries that now point at nothing, and is named in the log.
function Remove-UserEntries {
    $tray = [IO.Path]::GetFullPath((Join-Path $installDir $NrrTrayExeName))
    $folderKey = Get-PathEntryKey $installDir
    $runSubkey = 'Software\Microsoft\Windows\CurrentVersion\Run'
    $loaded = @()
    foreach ($sid in [Microsoft.Win32.Registry]::Users.GetSubKeyNames()) {
        # Real accounts only; `<sid>_Classes` is the same account's other hive.
        if ($sid -notmatch '^S-1-(5-21|12-1)-[\d-]+$') { continue }
        $loaded += $sid
        $run = $null
        try {
            $run = [Microsoft.Win32.Registry]::Users.OpenSubKey("$sid\$runSubkey", $true)
            $command = if ($run) { $run.GetValue($NrrAutostartValueName) } else { $null }
            if ($command) {
                $exe = "$command".Trim()
                if ($exe.StartsWith('"')) {
                    $end = $exe.IndexOf('"', 1)
                    $exe = if ($end -gt 1) { $exe.Substring(1, $end - 1) } else { $exe.Trim('"') }
                }
                elseif ($exe -match '^(?<exe>.+?\.exe)(?=\s|$)') { $exe = $Matches['exe'] }
                $same = $false
                try { $same = [IO.Path]::GetFullPath($exe).Equals($tray, [StringComparison]::OrdinalIgnoreCase) } catch { }
                if ($same) {
                    $run.DeleteValue($NrrAutostartValueName, $false)
                    Write-Host "    removed the tray's launch at sign-in for $sid"
                }
            }
        }
        catch { Write-Host "    launch at sign-in for $sid was not checked: $($_.Exception.Message)" }
        finally { if ($run) { $run.Dispose() } }

        $environment = $null
        try {
            $environment = [Microsoft.Win32.Registry]::Users.OpenSubKey("$sid\Environment", $true)
            if (-not $environment -or -not ($environment.GetValueNames() -contains 'Path')) { continue }
            # Raw and with its type: `%USERPROFILE%\bin` must stay written so.
            $list = [string] $environment.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            $entries = $list -split ';'
            $kept = @($entries | Where-Object { (Get-PathEntryKey $_) -ne $folderKey })
            if ($kept.Count -eq $entries.Count) { continue }
            $environment.SetValue('Path', ($kept -join ';'), $environment.GetValueKind('Path'))
            Write-Host "    removed $installDir from the PATH of $sid"
        }
        catch { Write-Host "    PATH of $sid was not checked: $($_.Exception.Message)" }
        finally { if ($environment) { $environment.Dispose() } }
    }
    $list = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
    foreach ($entry in @(Get-ChildItem -LiteralPath $list -ErrorAction SilentlyContinue)) {
        $sid = $entry.PSChildName
        if ($sid -match '^S-1-(5-21|12-1)-' -and $sid -notin $loaded) {
            Write-Host "    $sid is signed out; its launch at sign-in and PATH entry, if any, stay"
        }
    }
}

$exitCode = 0
$leftForOthers = $false
switch ($Action) {
    'Stop' {
        if (-not (Stop-NrrService)) {
            Write-Host "    $NrrServiceName did not stop"
            $exitCode = 1
        }
    }
    'MarkStop' {
        Set-NrrDeliberateStop
    }
    'Register' {
        if (-not (Test-Path -LiteralPath $console)) {
            Write-Host "    $console is missing"
            $exitCode = 1
            break
        }
        # Registers the service beside the console, takes over a registration
        # another copy left, keeps the start mode chosen before, and starts it.
        Write-Host '==> nrr-cli reinstall'
        $exitCode = Invoke-NativeCommand -FilePath $console -ArgumentList @('reinstall')
    }
    'Unregister' {
        # Stopped here first, so a process stuck in its stop is ended rather
        # than left to keep the registration and the DNS redirect past a reboot.
        if ((Test-RegisteredFromHere) -and -not (Stop-NrrService)) { $exitCode = 1 }
        $service = Remove-OwnService
        if ($service -ne 'gone') { $exitCode = 1 }
        # A registration merely marked for deletion is not a running service.
        if ($service -ne 'foreign' -and (Restore-NetworkAfterRemoval) -ne 0) { $exitCode = 1 }
        if ($service -eq 'gone' -and -not (Remove-ServiceCopy)) { $exitCode = 1 }
        if ($service -eq 'foreign') { Resume-ForeignService }
        Remove-UserEntries
        if ($RemoveData) {
            if ($service -eq 'foreign') {
                # purge-data.ps1 would remove that other copy's service first.
                Write-Host '    application data kept: another copy still runs the service'
            }
            else {
                # With the service still registered it refuses and says why.
                $purge = @{ Yes = $true }
                if ($RemoveAudit) { $purge.PurgeAudit = $true }
                $purged = Invoke-UserScript 'purge-data.ps1' $purge
                if ($purged -eq 5) { $leftForOthers = $true }
                elseif ($purged -ne 0) { $exitCode = 1 }
            }
        }
    }
    'RemoveUserData' {
        if ((Invoke-UserScript 'purge-data.ps1' @{ Yes = $true; UserOnly = $true }) -ne 0) { $exitCode = 1 }
    }
    'Provision' {
        foreach ($item in ($ProvisionSpec -split '\|')) {
            $key, $value = $item -split '=', 2
            switch ($key.Trim().ToLowerInvariant()) {
                'primary' { if (-not $Primary) { $Primary = $value } }
                'secondary' { if (-not $Secondary) { $Secondary = $value } }
                'settings' { if (-not $Settings) { $Settings = $value } }
                'secondary-unset' { if (-not $SecondaryUnset) { $SecondaryUnset = $value } }
            }
        }
        $stage = @()
        foreach ($pair in @(@('--primary', $Primary), @('--secondary', $Secondary),
                @('--settings', $Settings), @('--secondary-unset', $SecondaryUnset))) {
            if ($pair[1] -and $pair[1].Trim()) { $stage += @($pair[0], $pair[1].Trim()) }
        }
        if ($stage.Count -eq 0) { break }
        $service = Join-Path $installDir 'nrr-service.exe'
        if (-not (Test-Path -LiteralPath $service)) {
            Write-Host "    $service is missing"
            $exitCode = 14
            break
        }
        Write-Host "==> nrr-service provision-stage $($stage -join ' ')"
        $exitCode = Invoke-NativeCommand -FilePath $service -ArgumentList (@('provision-stage') + $stage)
    }
    'Rollback' {
        $null = Stop-NrrService
        if (-not $Upgrade) {
            $service = Remove-OwnService
            if ($service -ne 'foreign' -and (Restore-NetworkAfterRemoval) -ne 0) { $exitCode = 1 }
        }
    }
}

if ($exitCode -eq 0 -and $leftForOthers) { $exitCode = 2 }

if ($LogPath) {
    try { Stop-Transcript | Out-Null } catch { }
}
exit $exitCode
