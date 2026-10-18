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

# The deliberate-stop marker, or $null unless the data root is a real directory
# owned by SYSTEM or Administrators: anyone may create folders in ProgramData,
# and a planted root or a link in it would steer this elevated write onto
# another file. ProgramData comes from Windows, not from the environment.
function Get-NrrDeliberateStopMarker {
    $programData = [Environment]::GetFolderPath('CommonApplicationData')
    if (-not $programData) { return $null }
    $root = Join-Path $programData $NrrProductName
    $item = Get-Item -LiteralPath $root -Force -ErrorAction SilentlyContinue
    if (-not $item -or -not $item.PSIsContainer) { return $null }
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { return $null }
    try { $owner = (Get-Acl -LiteralPath $root).GetOwner([Security.Principal.SecurityIdentifier]).Value }
    catch { return $null }
    if ($owner -notin @('S-1-5-18', 'S-1-5-32-544')) { return $null }
    return Join-Path $root 'deliberate-stop'
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
    public static uint[] Remove(string keyPrefix, Guid subLayer) {
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
                            if (layer == subLayer) ours.Add(key);
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
        $result = [NrrWfpSweep]::Remove($NrrWfpFilterKeyPrefix, [Guid]$NrrWfpSubLayer)
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
