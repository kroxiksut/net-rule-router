# Disaster-recovery "reset networking to default" for NetRuleRouter.
#
# For a machine whose NetRuleRouter service crashed (or was hard-killed)
# and left OS state behind: a non-dynamic WFP session's block filters survive
# `taskkill /F` until an explicit delete or a reboot, so an orphaned
# kill-switch / fail-closed block can lock the machine off the network; and a
# stranded Mode-B NRPT rule points all DNS at a now-dead listener, so no name
# resolves at all — either way, with no running service left to lift it.
#
# The binary's own `cleanup` subcommand does all of this properly, so the
# script's job is to find a binary that can run it, and to still get the
# machine online when there is none. Descending order of fidelity:
#
#   1. the repo build (`target\{debug,release}\nrr-service.exe`),
#   2. the INSTALLED service's binary, read from its registry `ImagePath` —
#      the case that matters on a user's machine, where no repo exists,
#   3. emergency mode, plain PowerShell only: drop our NRPT rule and our
#      routes by the same signatures `cleanup` uses,
#   4. restart the Base Filtering Engine, which drops every WFP filter of ours
#      without a reboot — we never set `FWPM_FILTER_FLAG_PERSISTENT`, so our
#      filters do not survive BFE. Emergency mode only: it is the one way to
#      lift a lockout with no binary to talk to the engine,
#   5. reboot — never without an explicit yes, and the default answer is no.
#
# Self-elevates via UAC (WFP, NRPT and the route table all need Administrator).
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File .\scripts\reset-network.ps1
#   powershell -ExecutionPolicy Bypass -File .\scripts\reset-network.ps1 -Profile release
#   powershell -ExecutionPolicy Bypass -File .\scripts\reset-network.ps1 -Reboot

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('auto', 'dev', 'release')]
    [string] $Profile = 'auto',

    # Reboot when the reset is done. Without it the script asks, defaulting to
    # no; a non-interactive session that did not pass it never reboots.
    [Parameter()]
    [switch] $Reboot
)

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$exeName = 'nrr-service.exe'
$serviceName = 'NetRuleRouter'
# Must match `dns_redirect.rs::NRPT_MARKER` and
# `route_codegen.rs::SECONDARY_ROUTE_METRIC` — emergency mode reproduces the
# binary's own sweeps, and a drifted constant here would either miss our state
# or delete somebody else's.
$nrptMarker = 'NetRuleRouter-ModeB-DnsRedirect'
$routeMetric = 5

# Honour `.cargo/config.toml::build.target-dir` redirect — same resolution
# as install-service.ps1 / uninstall-service.ps1.
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

$targetRoot = Resolve-TargetRoot $root

function Resolve-RepoBinary {
    param([string] $Mode)
    $debugPath = Join-Path $targetRoot "debug\$exeName"
    $releasePath = Join-Path $targetRoot "release\$exeName"
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

# The installed service's own binary. `ImagePath` carries SCM arguments and may
# be quoted, so take the executable and drop the rest.
function Resolve-InstalledBinary {
    $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"
    if (-not (Test-Path $key)) { return $null }
    try { $imagePath = (Get-ItemProperty -Path $key -Name ImagePath -ErrorAction Stop).ImagePath }
    catch { return $null }
    if ([string]::IsNullOrWhiteSpace($imagePath)) { return $null }
    $imagePath = $imagePath.Trim()
    if ($imagePath.StartsWith('"')) {
        $end = $imagePath.IndexOf('"', 1)
        if ($end -gt 1) { $imagePath = $imagePath.Substring(1, $end - 1) }
    }
    elseif ($imagePath -match '^(?<exe>\S+\.exe)') {
        $imagePath = $Matches['exe']
    }
    if (Test-Path $imagePath) { return $imagePath }
    return $null
}

$isAdmin = (
    New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# Re-launch the SCRIPT, not the binary: the ladder below (registry lookup,
# emergency sweeps, BFE) all needs Administrator, and elevating only the
# `cleanup` call would skip every step past the first.
if (-not $isAdmin) {
    Write-Host "Elevating via UAC..." -ForegroundColor Cyan
    $argv = @('-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath, '-Profile', $Profile)
    if ($Reboot) { $argv += '-Reboot' }
    $p = Start-Process -FilePath 'powershell.exe' -ArgumentList $argv -Verb RunAs -Wait -PassThru
    exit $p.ExitCode
}

Write-Host "==> sc stop $serviceName (best-effort)" -ForegroundColor Cyan
$null = sc.exe stop $serviceName 2>&1
Start-Sleep -Seconds 2

# ── Step 1-2: a binary that can run `cleanup` ────────────────────────────────
$exePath = Resolve-RepoBinary -Mode $Profile
if ($exePath) {
    Write-Host "==> using the repo build: $exePath" -ForegroundColor Cyan
}
else {
    $exePath = Resolve-InstalledBinary
    if ($exePath) {
        Write-Host "==> no repo build; using the installed service binary: $exePath" -ForegroundColor Cyan
    }
}

$cleanupOk = $false
if ($exePath) {
    Write-Host "==> $exePath cleanup" -ForegroundColor Cyan
    & $exePath cleanup
    $code = $LASTEXITCODE
    if ($code -eq 0) { $cleanupOk = $true }
    else { Write-Warning "cleanup returned $code — falling back to emergency mode." }
}
else {
    Write-Warning "No NetRuleRouter binary found (no repo build, no installed service)."
}

# ── Step 3-4: emergency mode ─────────────────────────────────────────────────
if (-not $cleanupOk) {
    Write-Host "==> emergency mode: PowerShell only" -ForegroundColor Yellow

    # Marker-scoped, so an admin's or a VPN's own NRPT rules are untouched.
    Write-Host "--> removing our NRPT rule (Mode-B DNS redirect)" -ForegroundColor Cyan
    try {
        $rules = @(Get-DnsClientNrptRule -ErrorAction Stop |
            Where-Object { $_.Comment -eq $nrptMarker })
        foreach ($rule in $rules) {
            Remove-DnsClientNrptRule -Name $rule.Name -Force -ErrorAction Stop
        }
        Write-Host "    NRPT rules removed: $($rules.Count)"
        Clear-DnsClientCache -ErrorAction SilentlyContinue
    }
    catch {
        Write-Warning "NRPT sweep failed: $($_.Exception.Message)"
    }

    # Same signature the binary's offline reset adopts: our metric at /32 (the
    # secondary host routes) or /2 (the mode-A counter-overlay halves).
    Write-Host "--> removing our routes (metric $routeMetric at /32 and /2)" -ForegroundColor Cyan
    try {
        $ours = @(Get-NetRoute -ErrorAction Stop | Where-Object {
                $_.RouteMetric -eq $routeMetric -and
                ($_.DestinationPrefix -like '*/32' -or $_.DestinationPrefix -like '*/2')
            })
        foreach ($route in $ours) {
            Remove-NetRoute -InputObject $route -Confirm:$false -ErrorAction Stop
        }
        Write-Host "    routes removed: $($ours.Count)"
    }
    catch {
        Write-Warning "Route sweep failed: $($_.Exception.Message)"
    }

    # Our WFP filters need the engine, and without a binary the only lever left
    # is the engine's own lifetime: we never set FWPM_FILTER_FLAG_PERSISTENT, so
    # nothing of ours survives a BFE restart. Everyone else's filters go too for
    # those seconds — acceptable here, this path only runs on a machine that is
    # already locked out. `net stop bfe /y` takes the dependent services with
    # it and starting BFE does NOT bring them back, so they are restarted by
    # hand.
    Write-Host "--> restarting the Base Filtering Engine (drops our WFP filters)" -ForegroundColor Cyan
    Write-Warning "Filtering is off for a few seconds, including the Windows firewall."
    try {
        $dependents = @(Get-Service -Name BFE -ErrorAction Stop |
            Select-Object -ExpandProperty DependentServices |
            Where-Object { $_.Status -eq 'Running' } |
            Select-Object -ExpandProperty Name)
        $null = net.exe stop bfe /y 2>&1
        $null = net.exe start bfe 2>&1
        foreach ($dependent in $dependents) {
            try { Start-Service -Name $dependent -ErrorAction Stop }
            catch { Write-Warning "Could not restart dependent service ${dependent}: $($_.Exception.Message)" }
        }
        $bfe = Get-Service -Name BFE
        if ($bfe.Status -ne 'Running') {
            Write-Warning "BFE is $($bfe.Status) — reboot to restore filtering."
        }
        else {
            Write-Host "    BFE running again; dependents restarted: $($dependents.Count)"
        }
    }
    catch {
        Write-Warning "BFE restart failed: $($_.Exception.Message) — a reboot clears our filters."
    }
}

# ── Step 5: reboot, only on an explicit yes ─────────────────────────────────
Write-Host "Network reset complete." -ForegroundColor Green

$doReboot = $Reboot.IsPresent
if (-not $doReboot -and -not [Environment]::UserInteractive) {
    Write-Host "A reboot fully clears any remainder; re-run with -Reboot to have this script do it."
}
elseif (-not $doReboot) {
    $answer = Read-Host "Reboot now to clear any remainder? [y/N]"
    $doReboot = ($answer -match '^(y|yes)$')
}

if ($doReboot) {
    Write-Host "Rebooting..." -ForegroundColor Yellow
    Restart-Computer -Force
}
else {
    Write-Host "Not rebooting. A reboot fully clears any remainder."
}
