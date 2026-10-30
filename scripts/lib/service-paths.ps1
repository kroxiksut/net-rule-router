# Shared names and lookups for the Windows service scripts (reset-network,
# uninstall-service, purge-data, install-service). Dot-sourced, never run.
# Windows counterpart of service-paths.sh.

# Keep in sync with product_identity.rs: PRODUCT_NAME (which is also the SCM
# service name) and the Service / Tray roles' Windows file names.
$NrrProductName = 'NetRuleRouter'
$NrrServiceName = $NrrProductName
$NrrServiceExeName = 'nrr-service.exe'
$NrrTrayExeName = 'NetRuleRouterTray.exe'
$NrrServiceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$NrrServiceName"

# The tray's launch-at-login entry: AUTOSTART_SUBKEY / AUTOSTART_VALUE_NAME in
# platform/windows autostart.rs.
$NrrAutostartKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$NrrAutostartValueName = 'NetRuleRouter'

# Where install-service.ps1 stages the service unless told otherwise.
$NrrDevStageDir = if ($env:ProgramW6432) { Join-Path $env:ProgramW6432 'NetRuleRouter-dev' } else { $null }

# Honour `.cargo/config.toml::build.target-dir`, which may move builds off the
# synced source tree; `<root>\target` otherwise.
function Resolve-TargetRoot {
    param([string] $RepoRoot)
    $cfg = Join-Path $RepoRoot '.cargo\config.toml'
    if (Test-Path $cfg) {
        $content = Get-Content $cfg -Raw
        if ($content -match '(?m)^\s*target-dir\s*=\s*"([^"]+)"') {
            $td = $Matches[1] -replace '/', '\'
            if ([System.IO.Path]::IsPathRooted($td)) { return $td }
            return (Join-Path $RepoRoot $td)
        }
    }
    return (Join-Path $RepoRoot 'target')
}

# The build-tree service binary for a profile, or $null; 'auto' takes the newer
# of the two that exist.
function Resolve-RepoServiceBinary {
    param([string] $TargetRoot, [string] $Mode)
    $debugPath = Join-Path $TargetRoot "debug\$NrrServiceExeName"
    $releasePath = Join-Path $TargetRoot "release\$NrrServiceExeName"
    switch ($Mode) {
        'dev'     { if (Test-Path $debugPath) { return $debugPath }; return $null }
        'release' { if (Test-Path $releasePath) { return $releasePath }; return $null }
        default {
            if ((Test-Path $debugPath) -and (Test-Path $releasePath)) {
                $d = (Get-Item $debugPath).LastWriteTime
                $r = (Get-Item $releasePath).LastWriteTime
                return $(if ($d -ge $r) { $debugPath } else { $releasePath })
            }
            elseif (Test-Path $debugPath) { return $debugPath }
            elseif (Test-Path $releasePath) { return $releasePath }
            else { return $null }
        }
    }
}

# The executable the registration names, whether or not it still exists, or
# $null. `ImagePath` carries SCM arguments and may be quoted, so take the
# executable and drop the rest.
function Get-ServiceImagePath {
    if (-not (Test-Path $NrrServiceKey)) { return $null }
    try { $imagePath = (Get-ItemProperty -Path $NrrServiceKey -Name ImagePath -ErrorAction Stop).ImagePath }
    catch { return $null }
    if ([string]::IsNullOrWhiteSpace($imagePath)) { return $null }
    $imagePath = $imagePath.Trim()
    if ($imagePath.StartsWith('"')) {
        $end = $imagePath.IndexOf('"', 1)
        if ($end -gt 1) { $imagePath = $imagePath.Substring(1, $end - 1) }
    }
    elseif ($imagePath -match '^(?<exe>.+?\.exe)(?=\s|$)') {
        $imagePath = $Matches['exe']
    }
    return $imagePath
}

# The registered service's own binary, or $null when it is gone.
function Resolve-InstalledServiceBinary {
    $imagePath = Get-ServiceImagePath
    if ($imagePath -and (Test-Path -LiteralPath $imagePath)) { return $imagePath }
    return $null
}

# Registered with the SCM, including a service already marked for deletion:
# its key stays until the last handle closes or the machine reboots.
function Test-ServiceRegistered {
    return (Test-Path $NrrServiceKey)
}

function Test-ServiceDeletePending {
    try { return ((Get-ItemProperty -Path $NrrServiceKey -Name DeleteFlag -ErrorAction Stop).DeleteFlag -eq 1) }
    catch { return $false }
}

# The service's data root, or $null unless it is a real directory owned by
# SYSTEM or Administrators: anyone may create folders in ProgramData, and a
# planted root or a link in it would steer an elevated write onto another file
# or feed this script notes nobody of ours wrote. ProgramData comes from
# Windows, not from the environment.
function Get-NrrProtectedDataRoot {
    $programData = [Environment]::GetFolderPath('CommonApplicationData')
    if (-not $programData) { return $null }
    $root = Join-Path $programData $NrrProductName
    $item = Get-Item -LiteralPath $root -Force -ErrorAction SilentlyContinue
    if (-not $item -or -not $item.PSIsContainer) { return $null }
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { return $null }
    try { $owner = (Get-Acl -LiteralPath $root).GetOwner([Security.Principal.SecurityIdentifier]).Value }
    catch { return $null }
    if ($owner -notin @('S-1-5-18', 'S-1-5-32-544')) { return $null }
    return $root
}

# The deliberate-stop marker, or $null without a protected data root.
function Get-NrrDeliberateStopMarker {
    $root = Get-NrrProtectedDataRoot
    if (-not $root) { return $null }
    return Join-Path $root 'deliberate-stop'
}

# The lines of a note the service keeps in its data root, or $null when there
# is none to trust: no protected root, no plain file, or one larger than any
# note the service writes.
function Read-NrrStateNote {
    param([string] $Name, [int] $MaxBytes = 65536)
    $root = Get-NrrProtectedDataRoot
    if (-not $root) { return $null }
    $path = Join-Path $root $Name
    $item = Get-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
    if (-not $item -or $item.PSIsContainer) { return $null }
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { return $null }
    if ($item.Length -gt $MaxBytes) { return $null }
    try { $text = [IO.File]::ReadAllText($path) }
    catch { return $null }
    return @($text -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

function Remove-NrrStateNote {
    param([string] $Name)
    $root = Get-NrrProtectedDataRoot
    if (-not $root) { return }
    Remove-Item -LiteralPath (Join-Path $root $Name) -Force -ErrorAction SilentlyContinue
}

# Marks the next stop as wanted: the service restarts itself after any stop
# without this file (DELIBERATE_STOP_MARKER in platform/windows
# service_control.rs). Never creates the data root, and creates the file anew
# rather than writing through whatever already has its name.
function Set-NrrDeliberateStop {
    $mark = Get-NrrDeliberateStopMarker
    if (-not $mark) { return }
    try {
        Remove-Item -LiteralPath $mark -Force -ErrorAction SilentlyContinue
        [System.IO.File]::Open($mark, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write).Dispose()
    }
    catch { Write-Host "    could not mark the stop as wanted: $($_.Exception.Message)" }
}

# Marks the next stop as an installer's (UPGRADE_STOP_MARKER in platform/windows
# service_control.rs): the service keeps its protection in place for the new
# files' instance. Same care as Set-NrrDeliberateStop.
function Set-NrrUpgradeStop {
    $root = Get-NrrProtectedDataRoot
    if (-not $root) { return }
    $mark = Join-Path $root 'upgrade-stop'
    try {
        Remove-Item -LiteralPath $mark -Force -ErrorAction SilentlyContinue
        [System.IO.File]::Open($mark, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write).Dispose()
    }
    catch { Write-Host "    could not mark the stop as an upgrade's: $($_.Exception.Message)" }
}

# Stops the service as a wanted stop; returns sc's exit code. A refused stop (a
# service still starting accepts no control) takes its mark back: left behind,
# it would excuse the next stop nobody asked for and keep the service down.
function Stop-NrrServiceDeliberately {
    param([string] $Name = $NrrServiceName)
    Set-NrrDeliberateStop
    $code = Invoke-NativeCommand -FilePath (Get-SystemTool 'sc.exe') -ArgumentList @('stop', $Name) -Quiet
    if ($code -ne 0) {
        $mark = Get-NrrDeliberateStopMarker
        if ($mark) { Remove-Item -LiteralPath $mark -Force -ErrorAction SilentlyContinue }
    }
    return $code
}

# $true once the service reaches $Status, $false on timeout or when it is gone.
function Wait-ServiceStatus {
    param([string] $Name, [string] $Status, [int] $Seconds = 30)
    try {
        $service = Get-Service -Name $Name -ErrorAction Stop
        $service.WaitForStatus($Status, [TimeSpan]::FromSeconds($Seconds))
        return $true
    }
    catch { return $false }
}

# Windows PowerShell turns a redirected native stderr line into a terminating
# error under `$ErrorActionPreference = 'Stop'`, so a tool that merely reports
# "already stopped" would abort the caller. The exit code is the verdict; -1
# when the program could not be started at all.
function Invoke-NativeCommand {
    param(
        [Parameter(Mandatory = $true)] [string] $FilePath,
        [string[]] $ArgumentList = @(),
        [switch] $Quiet
    )
    $ErrorActionPreference = 'Continue'
    try {
        & $FilePath @ArgumentList 2>&1 | ForEach-Object {
            if (-not $Quiet) { Write-Host "    $_" }
        }
        return $LASTEXITCODE
    }
    catch {
        if (-not $Quiet) { Write-Host "    $($_.Exception.Message)" }
        return -1
    }
}

function Test-ReparsePoint {
    param([System.IO.FileSystemInfo] $Item)
    return [bool]($Item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)
}

# Delete $Path (a directory tree or a file) without following a link: a junction
# planted in the tree would otherwise turn an elevated delete into one of
# whatever it points at. $Root bounds the walk: $Path must lie below it, and a
# link on any segment between the two stops the delete. A link met inside the
# tree is removed as a link. Checks and deletes go by path, so a swap between
# them still races: use it only where the one who could plant a link is the
# one whose data goes, or an administrator, never in another user's profile.
# Returns $null on success, otherwise the reason it stopped.
function Remove-TreeNoFollow {
    param(
        [Parameter(Mandatory = $true)] [string] $Path,
        [Parameter(Mandatory = $true)] [string] $Root
    )

    $rootFull = [System.IO.Path]::GetFullPath($Root).TrimEnd('\') + '\'
    $full = [System.IO.Path]::GetFullPath($Path).TrimEnd('\')
    if (-not $full.StartsWith($rootFull, [StringComparison]::OrdinalIgnoreCase)) {
        return "$full is not under $rootFull"
    }

    $segment = $rootFull.TrimEnd('\')
    foreach ($name in $full.Substring($rootFull.Length).Split('\')) {
        $segment = Join-Path $segment $name
        try { $item = Get-Item -LiteralPath $segment -Force -ErrorAction Stop }
        catch { return $null }
        if ((Test-ReparsePoint $item) -and $segment -ne $full) {
            return "$segment is a link; nothing below it was deleted"
        }
    }

    $removeEntry = {
        param([System.IO.FileSystemInfo] $Entry)
        if (-not $Entry.FullName.StartsWith($rootFull, [StringComparison]::OrdinalIgnoreCase)) {
            throw "$($Entry.FullName) is not under $rootFull"
        }
        if ($Entry -is [System.IO.DirectoryInfo]) {
            if (-not (Test-ReparsePoint $Entry)) {
                foreach ($child in @(Get-ChildItem -LiteralPath $Entry.FullName -Force -ErrorAction Stop)) {
                    & $removeEntry $child
                }
                $Entry.Attributes = [System.IO.FileAttributes]::Directory
            }
            # Non-recursive: on a link this removes the link alone.
            [System.IO.Directory]::Delete($Entry.FullName, $false)
        }
        else {
            if (-not (Test-ReparsePoint $Entry)) {
                $Entry.Attributes = [System.IO.FileAttributes]::Normal
            }
            [System.IO.File]::Delete($Entry.FullName)
        }
    }

    try {
        & $removeEntry (Get-Item -LiteralPath $full -Force -ErrorAction Stop)
        return $null
    }
    catch {
        return $_.Exception.Message
    }
}

# Absolute: a bare name resolves against a PATH the user can prepend to.
function Get-SystemTool {
    param([string] $Name)
    return (Join-Path ([Environment]::SystemDirectory) $Name)
}

# The service's signing key folder in its own profile (default_systemprofile in
# platform/windows key_store.rs); Sysnative reaches it from a 32-bit host.
function Get-NrrKeyStoreDir {
    $system = if ([Environment]::Is64BitProcess -or -not [Environment]::Is64BitOperatingSystem) { 'System32' } else { 'Sysnative' }
    return Join-Path ([Environment]::GetFolderPath('Windows')) "$system\config\systemprofile\AppData\Local\$NrrProductName"
}

# The record of the rules in force and the re-sign marker (RULES_ANCHOR_FILE_NAME,
# RESIGN_MARKER_FILE_NAME in key_store.rs). The key is not listed: the audit
# trail's seals are derived from it.
$NrrKeyCompanionNames = @('db-mac-rules-anchor.bin', 'db-mac-resign-pending.bin')

# Removes the files beside the key, never through a link. One result per file:
# Path, State (absent, would-remove, removed, failed) and Reason.
function Remove-KeyCompanions {
    param([string] $KeyDir = (Get-NrrKeyStoreDir), [switch] $DryRun)
    foreach ($name in $NrrKeyCompanionNames) {
        $path = Join-Path $KeyDir $name
        # Get-Item, not Test-Path: a link whose target is gone is still there.
        if (-not (Get-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue)) {
            [pscustomobject]@{ Path = $path; State = 'absent'; Reason = $null }
            continue
        }
        if ($DryRun) {
            [pscustomobject]@{ Path = $path; State = 'would-remove'; Reason = $null }
            continue
        }
        try {
            if ((Test-ReparsePoint (Get-Item -LiteralPath $KeyDir -Force -ErrorAction Stop)) -or
                (Test-ReparsePoint (Get-Item -LiteralPath $path -Force -ErrorAction Stop))) {
                throw 'a link; left alone'
            }
            try {
                [System.IO.File]::Delete($path)
            }
            catch {
                # Open to the service account alone: an administrator takes it over first.
                $null = & (Get-SystemTool 'takeown.exe') /F $path /A
                $null = & (Get-SystemTool 'icacls.exe') $path /grant '*S-1-5-32-544:F'
                [System.IO.File]::Delete($path)
            }
            [pscustomobject]@{ Path = $path; State = 'removed'; Reason = $null }
        }
        catch {
            [pscustomobject]@{ Path = $path; State = 'failed'; Reason = $_.Exception.Message }
        }
    }
}

# The state database the service opens (state_db_path in storage profile.rs).
$NrrStateDbName = 'nrr_service_state.db'

# Install time, before the service first starts: with no state database the
# store starts empty, and a record left beside the key by an earlier complete
# removal would read as a rolled-back store and block the rules. Only
# administrators can remove the database and the installer runs elevated, so
# this is a removal's leftover, not something an ordinary account can stage;
# the service's own check stays as strict. An existing database (an upgrade)
# leaves everything as it is.
function Clear-NrrOrphanedKeyCompanions {
    param([string] $DataRoot, [string] $KeyDir = (Get-NrrKeyStoreDir))
    if (-not $PSBoundParameters.ContainsKey('DataRoot')) {
        $programData = [Environment]::GetFolderPath('CommonApplicationData')
        if ($programData) { $DataRoot = Join-Path $programData $NrrProductName }
    }
    if (-not $DataRoot) { return }
    if (Get-Item -LiteralPath (Join-Path $DataRoot $NrrStateDbName) -Force -ErrorAction SilentlyContinue) { return }
    foreach ($result in @(Remove-KeyCompanions -KeyDir $KeyDir)) {
        switch ($result.State) {
            'removed' { Write-Host "    removed $($result.Path): no state database, so it described a removed one" }
            'failed' { Write-Host "    $($result.Path) was not removed: $($result.Reason)" }
        }
        $result
    }
}

# The Mode-B DNS redirect as the service writes it into the NRPT table. Must
# match `dns_redirect.rs::NRPT_MARKER`, `NRPT_EXEMPT_MARKER` and `NRPT_RULE_KEY`:
# the sweep below reproduces the binary's own, and a drifted value would either
# miss our rule or delete somebody else's.
$NrrNrptMarker = 'NetRuleRouter-ModeB-DnsRedirect'
$NrrNrptExemptMarker = 'NetRuleRouter-DnsScopeExemption'
$NrrNrptKeepMarker = 'NetRuleRouter-RuleNameKeep'
$NrrNrptRuleKey = '{5E0C2A17-8B3D-4F61-9C4A-2D7E6F1B0A93}'
$NrrNrptTable = 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig'

# Remove our DNS redirect without the binary: the rules carrying our markers,
# then the registry table itself, since the cmdlet reads the whole table and
# one half-written key (the service died between creating it and writing its
# values) fails it for every rule. Scoped to our fixed key, our markers and
# keys without `Version`, which no DNS client can use; an admin's or a VPN's
# own rules are untouched. Idempotent. $true when nothing failed.
function Remove-NrrDnsRedirect {
    $ok = $true
    Write-Host "--> removing our NRPT rules (DNS redirect)"
    try {
        $rules = @(Get-DnsClientNrptRule -ErrorAction Stop | Where-Object {
                $_.Comment -eq $NrrNrptMarker -or $_.Comment -eq $NrrNrptExemptMarker -or
                    $_.Comment -eq $NrrNrptKeepMarker
            })
        foreach ($rule in $rules) {
            Remove-DnsClientNrptRule -Name $rule.Name -Force -ErrorAction Stop
        }
        Write-Host "    NRPT rules removed: $($rules.Count)"
    }
    catch {
        Write-Warning "NRPT sweep failed: $($_.Exception.Message)"
        $ok = $false
    }
    Write-Host "--> sweeping the NRPT table in the registry"
    try {
        $swept = 0
        if (Test-Path -LiteralPath $NrrNrptTable) {
            foreach ($key in @(Get-ChildItem -LiteralPath $NrrNrptTable -ErrorAction Stop)) {
                $values = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction SilentlyContinue
                $ours = $key.PSChildName -eq $NrrNrptRuleKey -or
                    ($values -and ($values.Comment -eq $NrrNrptMarker -or
                        $values.Comment -eq $NrrNrptExemptMarker -or
                        $values.Comment -eq $NrrNrptKeepMarker))
                $halfWritten = -not ($values -and $null -ne $values.Version)
                if ($ours -or $halfWritten) {
                    Remove-Item -LiteralPath $key.PSPath -Recurse -Force -ErrorAction Stop
                    $swept += 1
                }
            }
        }
        Write-Host "    NRPT keys removed: $swept"
    }
    catch {
        Write-Warning "NRPT registry sweep failed: $($_.Exception.Message)"
        $ok = $false
    }
    Clear-DnsClientCache -ErrorAction SilentlyContinue
    return $ok
}

# Every WFP filter the service adds carries this key prefix and sits in this
# sub-layer (NRR_FILTER_KEY_DATA1..3 in wfp_filter.rs, WFP_SUBLAYER_GUID in
# platform-api types.rs); a test holds both to the code.
$NrrWfpFilterKeyPrefix = '4e525246-0001-4e52-'
$NrrWfpSubLayer = 'c1d2e3f4-5a6b-7c8d-9e0f-1a2b3c4d5e6f'
# The block a machine shutdown leaves for signed-in people (BOOT_GUARD_IDS in
# wfp_filter.rs): persistent and in the universal sub-layer, so neither the
# sub-layer match nor a BFE restart takes it. Removed by key.
$NrrWfpBootGuardKeys = @('4e525246-0001-4e52-4e52-52424f4f5434', '4e525246-0001-4e52-4e52-52424f4f5436')

$NrrWfpSweepSource = @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public static class NrrWfpSweep {
    [DllImport("fwpuclnt.dll")] static extern uint FwpmEngineOpen0([MarshalAs(UnmanagedType.LPWStr)] string server, uint authn, IntPtr identity, IntPtr session, out IntPtr engine);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmEngineClose0(IntPtr engine);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterCreateEnumHandle0(IntPtr engine, IntPtr template, out IntPtr enumHandle);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterEnum0(IntPtr engine, IntPtr enumHandle, uint requested, out IntPtr entries, out uint returned);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterDestroyEnumHandle0(IntPtr engine, IntPtr enumHandle);
    [DllImport("fwpuclnt.dll")] static extern void FwpmFreeMemory0(ref IntPtr memory);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterDeleteByKey0(IntPtr engine, ref Guid key);
    const uint RpcAuthnWinNt = 10;
    const uint FilterNotFound = 0x80320003;

    // { ours found, removed, first error (0 = none) }.
    public static uint[] Remove(string keyPrefix, Guid subLayer, Guid[] byKey) {
        IntPtr engine;
        uint code = FwpmEngineOpen0(null, RpcAuthnWinNt, IntPtr.Zero, IntPtr.Zero, out engine);
        if (code != 0) return new uint[] { 0, 0, code };
        try {
            IntPtr enumHandle;
            code = FwpmFilterCreateEnumHandle0(engine, IntPtr.Zero, out enumHandle);
            if (code != 0) return new uint[] { 0, 0, code };
            var ours = new List<Guid>();
            uint firstError = 0;
            // FWPM_FILTER0: filterKey first; subLayerKey after displayData,
            // flags, providerKey, providerData and layerKey.
            int subLayerOffset = IntPtr.Size == 8 ? 80 : 56;
            try {
                for (int page = 0; page < 4096; page++) {
                    IntPtr entries;
                    uint returned;
                    code = FwpmFilterEnum0(engine, enumHandle, 256, out entries, out returned);
                    if (code != 0) { firstError = code; break; }
                    if (entries == IntPtr.Zero) break;
                    try {
                        for (int i = 0; i < returned; i++) {
                            IntPtr row = Marshal.ReadIntPtr(entries, i * IntPtr.Size);
                            if (row == IntPtr.Zero) continue;
                            Guid key = (Guid)Marshal.PtrToStructure(row, typeof(Guid));
                            if (!key.ToString().StartsWith(keyPrefix, StringComparison.OrdinalIgnoreCase)) continue;
                            Guid layer = (Guid)Marshal.PtrToStructure(new IntPtr(row.ToInt64() + subLayerOffset), typeof(Guid));
                            if (layer == subLayer || Array.IndexOf(byKey, key) >= 0) ours.Add(key);
                        }
                    }
                    finally { FwpmFreeMemory0(ref entries); }
                    if (returned == 0) break;
                }
            }
            finally { FwpmFilterDestroyEnumHandle0(engine, enumHandle); }
            uint removed = 0;
            foreach (Guid found in ours) {
                Guid key = found;
                uint deleted = FwpmFilterDeleteByKey0(engine, ref key);
                if (deleted == 0 || deleted == FilterNotFound) removed++;
                else if (firstError == 0) firstError = deleted;
            }
            return new uint[] { (uint)ours.Count, removed, firstError };
        }
        finally { FwpmEngineClose0(engine); }
    }
}
'@

# Remove our WFP filters without the binary, leaving everyone else's in place.
# $true when none of ours is left; $false when the engine could not be asked
# or a delete failed, and the caller falls back to restarting BFE.
function Remove-NrrWfpFilters {
    Write-Host "--> removing our WFP filters"
    try {
        if (-not ('NrrWfpSweep' -as [type])) { Add-Type -TypeDefinition $NrrWfpSweepSource -ErrorAction Stop }
        $bootGuard = [Guid[]]($NrrWfpBootGuardKeys | ForEach-Object { [Guid]$_ })
        $result = [NrrWfpSweep]::Remove($NrrWfpFilterKeyPrefix, [Guid]$NrrWfpSubLayer, $bootGuard)
    }
    catch {
        Write-Warning "WFP filter sweep could not run: $($_.Exception.Message)"
        return $false
    }
    Write-Host "    WFP filters of ours: $($result[0]), removed: $($result[1])"
    if ($result[2] -ne 0) {
        Write-Warning ("WFP filter sweep failed: Win32 error 0x{0:X8}" -f $result[2])
        return $false
    }
    return ($result[1] -eq $result[0])
}

# The global DNS suffix list the service wrote outlives a reboot, and while it
# stands Windows completes single-label names with it alone. Taken back only
# while every entry is one the note lists (search_list.rs release_search_list):
# a list someone else set since stays. $true when nothing failed.
$NrrSearchListNote = 'dns-search-list.owned'

function Restore-NrrDnsSearchList {
    $noted = @(Read-NrrStateNote -Name $NrrSearchListNote |
            ForEach-Object { $_.Trim('.').ToLowerInvariant() } | Where-Object { $_ })
    if ($noted.Count -eq 0) { return $true }
    Write-Host "--> taking back the DNS suffix search list we wrote"
    try {
        $raw = (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' `
                -Name SearchList -ErrorAction SilentlyContinue).SearchList
        $global = @("$raw" -split ',' | ForEach-Object { $_.Trim().Trim('.').ToLowerInvariant() } |
                Where-Object { $_ })
        $ours = $global.Count -gt 0 -and -not ($global | Where-Object { $noted -notcontains $_ })
        if ($ours) {
            # Through the DNS client: a registry write alone stays unseen until a reboot.
            Set-DnsClientGlobalSetting -SuffixSearchList @('') -ErrorAction Stop
            Write-Host "    cleared: $($global -join ', ')"
        }
        else {
            Write-Host "    the list in force is not ours; left as it is"
        }
    }
    catch {
        Write-Warning "DNS suffix search list could not be taken back: $($_.Exception.Message)"
        return $false
    }
    Remove-NrrStateNote -Name $NrrSearchListNote
    return $true
}

# Machine-wide Base Filtering Engine options the connection observer switches
# on (wfp_events.rs): an instance killed rather than stopped leaves BFE writing
# a net event for every classify on the host. The note holds what they were.
$NrrWfpOptionsNote = 'wfp-engine-options.prior'
$NrrWfpCollectWritten = 1
$NrrWfpKeywordsWritten = 16

$NrrWfpOptionsSource = @'
using System;
using System.Runtime.InteropServices;
public static class NrrWfpEngineOptions {
    [StructLayout(LayoutKind.Sequential)]
    struct FwpValue { public uint Type; public IntPtr Value; }
    [DllImport("fwpuclnt.dll")] static extern uint FwpmEngineOpen0([MarshalAs(UnmanagedType.LPWStr)] string server, uint authn, IntPtr identity, IntPtr session, out IntPtr engine);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmEngineClose0(IntPtr engine);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmEngineGetOption0(IntPtr engine, uint option, out IntPtr value);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmEngineSetOption0(IntPtr engine, uint option, ref FwpValue value);
    [DllImport("fwpuclnt.dll")] static extern void FwpmFreeMemory0(ref IntPtr memory);
    const uint RpcAuthnWinNt = 10;
    const uint Uint32Type = 3;
    const uint CollectNetEvents = 0;
    const uint MatchAnyKeywords = 1;

    // Puts an option back only while it still holds what we wrote: something
    // else may have taken it over since. 0, or the error of the write.
    static uint PutBack(IntPtr engine, uint option, long prior, uint written) {
        if (prior < 0) return 0;
        IntPtr current;
        if (FwpmEngineGetOption0(engine, option, out current) != 0 || current == IntPtr.Zero) return 0;
        bool ours;
        try {
            FwpValue found = (FwpValue)Marshal.PtrToStructure(current, typeof(FwpValue));
            ours = found.Type == Uint32Type && (uint)(found.Value.ToInt64() & 0xFFFFFFFF) == written;
        }
        finally { FwpmFreeMemory0(ref current); }
        if (!ours) return 0;
        FwpValue value = new FwpValue();
        value.Type = Uint32Type;
        value.Value = new IntPtr((long)(uint)prior);
        return FwpmEngineSetOption0(engine, option, ref value);
    }

    // A prior of -1 is an option the note does not name. { open, collect, keywords } errors.
    public static uint[] Restore(long collect, long keywords, uint collectWritten, uint keywordsWritten) {
        IntPtr engine;
        uint code = FwpmEngineOpen0(null, RpcAuthnWinNt, IntPtr.Zero, IntPtr.Zero, out engine);
        if (code != 0) return new uint[] { code, 0, 0 };
        try {
            return new uint[] {
                0,
                PutBack(engine, CollectNetEvents, collect, collectWritten),
                PutBack(engine, MatchAnyKeywords, keywords, keywordsWritten)
            };
        }
        finally { FwpmEngineClose0(engine); }
    }
}
'@

# $true when nothing failed; without a note nothing of ours was changed.
function Restore-NrrWfpEngineOptions {
    $collect = -1
    $keywords = -1
    foreach ($line in @(Read-NrrStateNote -Name $NrrWfpOptionsNote -MaxBytes 4096)) {
        $pair = $line -split '=', 2
        $value = [uint32]0
        if ($pair.Count -ne 2 -or -not [uint32]::TryParse($pair[1].Trim(), [ref]$value)) { continue }
        switch ($pair[0].Trim()) {
            'collect' { $collect = [long]$value }
            'keywords' { $keywords = [long]$value }
        }
    }
    if ($collect -lt 0 -and $keywords -lt 0) { return $true }
    Write-Host "--> handing the Base Filtering Engine options back"
    try {
        if (-not ('NrrWfpEngineOptions' -as [type])) { Add-Type -TypeDefinition $NrrWfpOptionsSource -ErrorAction Stop }
        $result = [NrrWfpEngineOptions]::Restore($collect, $keywords, $NrrWfpCollectWritten, $NrrWfpKeywordsWritten)
    }
    catch {
        Write-Warning "BFE options could not be handed back: $($_.Exception.Message)"
        return $false
    }
    $failed = @($result | Where-Object { $_ -ne 0 })
    if ($failed.Count -gt 0) {
        Write-Warning ("BFE options could not be handed back: Win32 error 0x{0:X8}" -f $failed[0])
        return $false
    }
    Remove-NrrStateNote -Name $NrrWfpOptionsNote
    Write-Host "    done"
    return $true
}
