# Shared names and lookups for the Windows service scripts (reset-network,
# uninstall-service, purge-data, install-dev-service). Dot-sourced, never run.
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

# Where install-dev-service.ps1 stages the service unless told otherwise.
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

# The registered service's own binary, or $null. `ImagePath` carries SCM
# arguments and may be quoted, so take the executable and drop the rest.
function Resolve-InstalledServiceBinary {
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
    if (Test-Path -LiteralPath $imagePath) { return $imagePath }
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

# Absolute: a bare name resolves against a PATH the user can prepend to.
function Get-SystemTool {
    param([string] $Name)
    return (Join-Path ([Environment]::SystemDirectory) $Name)
}
