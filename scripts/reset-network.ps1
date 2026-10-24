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
#   1. the INSTALLED service's binary, read from its registry `ImagePath` —
#      the one that made the state being cleaned, and the case that matters on
#      a user's machine, where no repo exists,
#   2. the repo build (`target\{debug,release}\nrr-service.exe`),
#   3. emergency mode, plain PowerShell only: drop our NRPT rule, our routes
#      and our WFP filters by the same signatures `cleanup` uses, and hand back
#      the DNS suffix list and the BFE options the service noted it changed,
#   4. restart the Base Filtering Engine when our filters could not be deleted
#      one by one — our filters do not survive it, but neither does anyone
#      else's, and Windows 11 refuses it,
#   5. reboot — never without an explicit yes, and the default answer is no.
#
# Exits 1 when a step failed, so neither a caller nor the user reads an
# incomplete reset as a working network.
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
# Must match `nrr_platform_api::route_signature::is_owned_route` — emergency
# mode reproduces the binary's own sweep, and a drifted constant here would
# either miss our routes or delete somebody else's. The NRPT constants live in
# lib\service-paths.ps1 beside the sweep that uses them.
$routeMetric = 5          # SECONDARY_ROUTE_METRIC: host routes and overlay halves
$networkRouteMetric = 4   # NETWORK_ROUTE_METRIC: a network rule's routes
$overlayMaxPrefix = 13    # TUNNEL_CATCH_ALL_MAX_PREFIX + 1
$networkMinPrefixV4 = 8   # widest_rule_prefix(v4)
$networkMinPrefixV6 = 16  # widest_rule_prefix(v6)

function Test-NrrOwnedRoute($route) {
    $parts = $route.DestinationPrefix -split '/'
    if ($parts.Count -ne 2) { return $false }
    $length = 0
    if (-not [int]::TryParse($parts[1], [ref]$length)) { return $false }
    $v6 = $parts[0].Contains(':')
    switch ($route.RouteMetric) {
        $routeMetric {
            if ($v6) { return $length -eq 128 }
            return $length -eq 32 -or ($length -ge 1 -and $length -le $overlayMaxPrefix)
        }
        $networkRouteMetric {
            if ($v6) { return $length -ge $networkMinPrefixV6 -and $length -le 128 }
            return $length -ge $networkMinPrefixV4 -and $length -le 32
        }
    }
    return $false
}

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
$null = Stop-NrrServiceDeliberately
Start-Sleep -Seconds 2

# ── Step 1-2: a binary that can run `cleanup` ────────────────────────────────
# The installed binary first: a repo build of another revision may not know the
# state the installed one left behind (the BFE emergency path included).
$exePath = Resolve-InstalledServiceBinary
if ($exePath) {
    Write-Host "==> using the installed service binary: $exePath" -ForegroundColor Cyan
}
else {
    $exePath = Resolve-RepoServiceBinary -TargetRoot $targetRoot -Mode $Profile
    if ($exePath) {
        Write-Host "==> no installed service binary; using the repo build: $exePath" -ForegroundColor Cyan
    }
}

$cleanupOk = $false
if ($exePath) {
    # Stops a service the `sc stop` above did not, ending it if it hangs; a
    # binary that predates the verb answers 2 and gets the plain `cleanup`.
    Write-Host "==> $exePath stop-and-cleanup" -ForegroundColor Cyan
    $code = Invoke-NativeCommand -FilePath $exePath -ArgumentList @('stop-and-cleanup')
    if ($code -eq 2) {
        Write-Host "==> $exePath cleanup" -ForegroundColor Cyan
        $code = Invoke-NativeCommand -FilePath $exePath -ArgumentList @('cleanup')
    }
    if ($code -eq 0) { $cleanupOk = $true }
    else { Write-Warning "cleanup returned $code - falling back to emergency mode." }
}
else {
    Write-Warning "No NetRuleRouter binary found (no repo build, no installed service)."
}

# ── Step 3-4: emergency mode ─────────────────────────────────────────────────
# What could not be undone; any entry makes the reset incomplete.
$failures = New-Object System.Collections.Generic.List[string]
$filtersGone = $false
$bfeRunning = $true
if (-not $cleanupOk) {
    Write-Host "==> emergency mode: PowerShell only" -ForegroundColor Yellow

    # The same marker-scoped sweep the uninstaller falls back to
    # (lib\service-paths.ps1), so the two cannot drift apart.
    if (-not (Remove-NrrDnsRedirect)) { $failures.Add('DNS redirect (NRPT)') }
    if (-not (Restore-NrrDnsSearchList)) { $failures.Add('DNS suffix search list') }

    # Same signature the binary's offline reset adopts: host routes, overlay
    # halves and network-rule routes, each at its own metric. Each route on its
    # own: one refusal must not keep the rest in place.
    Write-Host "--> removing our routes (metrics $routeMetric and $networkRouteMetric)" -ForegroundColor Cyan
    try {
        $ours = @(Get-NetRoute -ErrorAction Stop | Where-Object { Test-NrrOwnedRoute $_ })
        $removed = 0
        $refused = 0
        foreach ($route in $ours) {
            try {
                Remove-NetRoute -InputObject $route -Confirm:$false -ErrorAction Stop
                $removed += 1
            }
            catch {
                $reason = $_.Exception.Message
                # Gone in the meantime (its interface went) is what was wanted.
                $still = @(Get-NetRoute -InterfaceIndex $route.InterfaceIndex `
                        -DestinationPrefix $route.DestinationPrefix -ErrorAction SilentlyContinue |
                    Where-Object { $_.NextHop -eq $route.NextHop -and $_.RouteMetric -eq $route.RouteMetric })
                if ($still.Count -gt 0) {
                    $refused += 1
                    Write-Warning "Route $($route.DestinationPrefix) via $($route.NextHop) stays: $reason"
                }
            }
        }
        Write-Host "    routes removed: $removed of $($ours.Count)"
        if ($refused -gt 0) { $failures.Add("routes ($refused left)") }
    }
    catch {
        Write-Warning "Route sweep failed: $($_.Exception.Message)"
        $failures.Add('routes')
    }

    $filtersGone = Remove-NrrWfpFilters
}

# Only when our filters could not be deleted one by one: we never set
# FWPM_FILTER_FLAG_PERSISTENT, so nothing of ours survives a BFE restart.
# Everyone else's filters go too for those seconds, and Windows 11 refuses it
# outright (the firewall service is protected). `net stop bfe /y` takes the
# dependent services with it and starting BFE does NOT bring them back, so
# they are restarted by hand.
if (-not $cleanupOk -and -not $filtersGone) {
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
        $failures.Add('WFP filters (BFE did not stop)')
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
        $failures.Add('Base Filtering Engine (not running)')
    }
}

# Asked of BFE itself, so only once it runs again.
if (-not $cleanupOk -and $bfeRunning -and -not (Restore-NrrWfpEngineOptions)) {
    $failures.Add('BFE options')
}

# ── Step 5: reboot, only on an explicit yes ─────────────────────────────────
if ($failures.Count -eq 0) {
    Write-Host "Network reset complete." -ForegroundColor Green
}
else {
    Write-Warning "Network reset is incomplete: $($failures -join ', ') could not be undone. Reboot to clear what is left."
}

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

if ($failures.Count -gt 0) { exit 1 }
exit 0
