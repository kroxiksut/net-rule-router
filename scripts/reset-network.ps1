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
# Needs lib\service-paths.ps1 beside it; the package ships scripts\ whole.
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

. (Join-Path $PSScriptRoot 'lib\service-paths.ps1')

$root = Split-Path -Parent $PSScriptRoot
# Must match `dns_redirect.rs::NRPT_MARKER` and
# `route_codegen.rs::SECONDARY_ROUTE_METRIC` — emergency mode reproduces the
# binary's own sweeps, and a drifted constant here would either miss our state
# or delete somebody else's.
$nrptMarker = 'NetRuleRouter-ModeB-DnsRedirect'
$routeMetric = 5

$targetRoot = Resolve-TargetRoot $root

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
    # One pre-quoted string: Windows PowerShell joins an -ArgumentList array with
    # bare spaces, which splits a script path containing a space.
    $argv = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Profile $Profile"
    if ($Reboot) { $argv += ' -Reboot' }
    $powershell = Get-SystemTool 'WindowsPowerShell\v1.0\powershell.exe'
    $p = Start-Process -FilePath $powershell -ArgumentList $argv -Verb RunAs -Wait -PassThru
    exit $p.ExitCode
}

Write-Host "==> sc stop $NrrServiceName (best-effort)" -ForegroundColor Cyan
$null = Invoke-NativeCommand -FilePath (Get-SystemTool 'sc.exe') -ArgumentList @('stop', $NrrServiceName) -Quiet
Start-Sleep -Seconds 2

# ── Step 1-2: a binary that can run `cleanup` ────────────────────────────────
$exePath = Resolve-RepoServiceBinary -TargetRoot $targetRoot -Mode $Profile
if ($exePath) {
    Write-Host "==> using the repo build: $exePath" -ForegroundColor Cyan
}
else {
    $exePath = Resolve-InstalledServiceBinary
    if ($exePath) {
        Write-Host "==> no repo build; using the installed service binary: $exePath" -ForegroundColor Cyan
    }
}

$cleanupOk = $false
if ($exePath) {
    Write-Host "==> $exePath cleanup" -ForegroundColor Cyan
    $code = Invoke-NativeCommand -FilePath $exePath -ArgumentList @('cleanup')
    if ($code -eq 0) { $cleanupOk = $true }
    else { Write-Warning "cleanup returned $code - falling back to emergency mode." }
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
    $dependents = @()
    try {
        $dependents = @(Get-Service -Name BFE -ErrorAction Stop |
            Select-Object -ExpandProperty DependentServices |
            Where-Object { $_.Status -eq 'Running' } |
            Select-Object -ExpandProperty Name)
    }
    catch {
        Write-Warning "Could not list the services that depend on BFE: $($_.Exception.Message)"
    }

    # Judged by the service's state, never by net.exe's exit code or its
    # localized text: "already stopped" is a stop that succeeded. The start runs
    # whatever the stop said — a BFE left stopped is the lockout itself.
    $net = Get-SystemTool 'net.exe'
    $stopCode = Invoke-NativeCommand -FilePath $net -ArgumentList @('stop', 'bfe', '/y') -Quiet
    if (-not (Wait-ServiceStatus -Name BFE -Status Stopped -Seconds 5)) {
        Write-Warning "BFE did not stop (net.exe exit $stopCode); our filters may still be in place."
    }
    $null = Invoke-NativeCommand -FilePath $net -ArgumentList @('start', 'bfe') -Quiet
    $bfeRunning = Wait-ServiceStatus -Name BFE -Status Running -Seconds 30
    $restarted = 0
    foreach ($dependent in $dependents) {
        try {
            Start-Service -Name $dependent -ErrorAction Stop
            $restarted += 1
        }
        catch { Write-Warning "Could not restart dependent service ${dependent}: $($_.Exception.Message)" }
    }
    if ($bfeRunning) {
        Write-Host "    BFE running again; dependents restarted: $restarted of $($dependents.Count)"
    }
    else {
        Write-Warning "BFE is not running - reboot to restore filtering."
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
