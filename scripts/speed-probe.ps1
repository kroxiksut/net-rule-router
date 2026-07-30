# Per-adapter reachability and download-speed probe.
#
# NetRuleRouter routes traffic across existing interfaces by source IP
# (e.g. a primary Ethernet NIC plus a secondary VPN tunnel adapter). This
# script answers "how does site X behave over adapter A vs adapter B" by
# shelling out to curl.exe with `--interface <source-ip>` per probe, which
# pins the outbound source address and therefore the egress path — it does
# not touch NetRuleRouter's own routing tables or WFP filters, it just
# measures what the OS routing table + NRR policy currently produce.
#
# Requires curl.exe (bundled with Windows 10 1803+ at
# %SystemRoot%\System32\curl.exe). Read-only: issues plain HTTPS GET/HEAD-ish
# requests, discards response bodies, does not modify network state.
#
# Exit codes:
#   0 - ran to completion (individual probe failures are reported inline,
#       not a script failure — this is a measurement tool)
#   2 - usage error (curl.exe missing, no usable adapters found, bad args)
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File .\scripts\speed-probe.ps1
#   powershell -ExecutionPolicy Bypass -File .\scripts\speed-probe.ps1 -TimeoutSec 10
#   powershell -ExecutionPolicy Bypass -File .\scripts\speed-probe.ps1 `
#       -Urls "https://example.com","https://www.google.com/generate_204"
#   powershell -ExecutionPolicy Bypass -File .\scripts\speed-probe.ps1 `
#       -Adapters "LAN=192.168.0.5","VPN=10.88.0.2"
#   powershell -ExecutionPolicy Bypass -File .\scripts\speed-probe.ps1 `
#       -Adapter "Ethernet","OpenVPN TAP"
#
# Default (no -Adapter / -Adapters): adapters are auto-enumerated via
# Get-NetAdapter, keeping only Status -eq 'Up', dropping Bluetooth adapters
# (InterfaceDescription/Name matching "Bluetooth"), loopback/pseudo
# adapters (InterfaceDescription/Name matching "Loopback"), the product's
# own TUN adapter (InterfaceDescription/Name matching "NetRuleRouter" or with
# an IPv4 in 198.18.0.0/15), and adapters with no IPv4 address. Loopback
# (127.*) and link-local (169.254.*) addresses are always skipped regardless
# of source. Explicit -Adapter selection bypasses the TUN filter.
#
# -Adapter <name[]> bypasses the default filter entirely and probes exactly
# the named adapters (Get-NetAdapter Name/InterfaceAlias), looked up
# regardless of Status or Bluetooth/loopback class; an unknown name or an
# adapter with no IPv4 address is a hard usage error (exit 2).
#
# -Adapters entries are "Alias=SourceIP" (Alias is only a display label) or
# a bare IP (used as its own label) — a manual escape hatch for source IPs
# Windows doesn't expose as a named adapter. -Adapter and -Adapters are
# mutually exclusive.

[CmdletBinding()]
param(
    [Parameter()]
    [string[]] $Urls = @(
        'https://ya.ru',
        'https://www.google.com/generate_204',
        'https://speed.cloudflare.com/__down?bytes=2000000'
    ),

    [Parameter()]
    [string[]] $Adapter = @(),

    [Parameter()]
    [string[]] $Adapters = @(),

    [Parameter()]
    [int] $TimeoutSec = 15,

    [Parameter()]
    [long] $MaxDownloadBytes = 20MB
)

$ErrorActionPreference = 'Continue'

function Test-LoopbackOrLinkLocal {
    param([string] $IpAddress)
    if ($IpAddress -like '127.*') { return $true }
    if ($IpAddress -like '169.254.*') { return $true }
    return $false
}

function Test-BluetoothAdapter {
    param($NetAdapter)
    if ($NetAdapter.InterfaceDescription -match 'Bluetooth') { return $true }
    if ($NetAdapter.Name -match 'Bluetooth') { return $true }
    return $false
}

function Test-LoopbackAdapter {
    param($NetAdapter)
    if ($NetAdapter.InterfaceDescription -match 'Loopback') { return $true }
    if ($NetAdapter.Name -match 'Loopback') { return $true }
    return $false
}

function Test-TunAdapter {
    param($NetAdapter)
    if ($NetAdapter.InterfaceDescription -match 'NetRuleRouter') { return $true }
    if ($NetAdapter.Name -match 'NetRuleRouter') { return $true }
    return $false
}

function Test-VirtualAdapter {
    param($NetAdapter)
    # VirtualBox Host-Only adapter
    if ($NetAdapter.InterfaceDescription -match 'VirtualBox') { return $true }
    if ($NetAdapter.Name -match 'vboxnet') { return $true }
    # Hyper-V virtual adapter
    if ($NetAdapter.InterfaceDescription -match 'Hyper-V') { return $true }
    if ($NetAdapter.Name -match '^vEthernet') { return $true }
    # Docker bridge adapter
    if ($NetAdapter.Name -match '^docker') { return $true }
    if ($NetAdapter.Name -match '^br-') { return $true }
    return $false
}

function Test-FakeIpRange {
    param([string] $IpAddress)
    # 198.18.0.0/15 covers 198.18.x.x and 198.19.x.x
    if ($IpAddress -like '198.18.*') { return $true }
    if ($IpAddress -like '198.19.*') { return $true }
    return $false
}

function Get-AdapterIPv4List {
    param($NetAdapter)
    $ips = New-Object System.Collections.Generic.List[string]
    $ipConfig = Get-NetIPAddress -InterfaceIndex $NetAdapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
    foreach ($addr in $ipConfig) {
        $ip = $addr.IPAddress
        if ([string]::IsNullOrWhiteSpace($ip)) { continue }
        if (Test-LoopbackOrLinkLocal $ip) { continue }
        $ips.Add($ip)
    }
    return $ips
}

function Get-AutoAdapters {
    $found = New-Object System.Collections.Generic.List[object]
    $netAdapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' }
    foreach ($na in $netAdapters) {
        if (Test-BluetoothAdapter $na) { continue }
        if (Test-LoopbackAdapter $na) { continue }
        if (Test-TunAdapter $na) { continue }
        if (Test-VirtualAdapter $na) { continue }
        foreach ($ip in (Get-AdapterIPv4List $na)) {
            if (Test-FakeIpRange $ip) { continue }
            $found.Add([PSCustomObject]@{ Alias = $na.InterfaceAlias; IP = $ip })
        }
    }
    return $found
}

function Get-NamedAdapters {
    param([string[]] $Names)
    $found = New-Object System.Collections.Generic.List[object]
    $allAdapters = Get-NetAdapter -ErrorAction SilentlyContinue
    foreach ($name in $Names) {
        $na = $allAdapters | Where-Object { $_.Name -eq $name -or $_.InterfaceAlias -eq $name } | Select-Object -First 1
        if ($null -eq $na) {
            $available = ($allAdapters | ForEach-Object { $_.Name }) -join ', '
            Write-Error "Adapter not found: '$name'. Available adapters: $available"
            exit 2
        }
        $ips = Get-AdapterIPv4List $na
        if ($ips.Count -eq 0) {
            Write-Error "Adapter '$name' has no usable IPv4 address."
            exit 2
        }
        foreach ($ip in $ips) {
            $found.Add([PSCustomObject]@{ Alias = $na.InterfaceAlias; IP = $ip })
        }
    }
    return $found
}

function ConvertFrom-AdapterSpec {
    param([string] $Spec)
    if ($Spec -match '^(?<alias>.+)=(?<ip>\d{1,3}(\.\d{1,3}){3})$') {
        return [PSCustomObject]@{ Alias = $Matches['alias']; IP = $Matches['ip'] }
    }
    return [PSCustomObject]@{ Alias = $Spec; IP = $Spec }
}

function Format-Speed {
    param([double] $BytesPerSec)
    if ($BytesPerSec -ge 1MB) {
        return "{0:N2} MB/s" -f ($BytesPerSec / 1MB)
    }
    return "{0:N1} KB/s" -f ($BytesPerSec / 1KB)
}

function Get-CurlFailureReason {
    param([int] $ExitCode)
    switch ($ExitCode) {
        6  { return 'could not resolve host' }
        7  { return 'failed to connect' }
        28 { return 'timeout' }
        35 { return 'SSL connect error' }
        52 { return 'empty reply from server' }
        56 { return 'recv failure (connection reset)' }
        63 { return 'exceeded max download size' }
        default { return "curl exit $ExitCode" }
    }
}

$curlCmd = Get-Command curl.exe -ErrorAction SilentlyContinue
if ($null -eq $curlCmd) {
    Write-Error "curl.exe not found on PATH. Windows 10 1803+ ships it at %SystemRoot%\System32\curl.exe."
    exit 2
}

if ($Adapter.Count -gt 0 -and $Adapters.Count -gt 0) {
    Write-Error "Specify only one of -Adapter or -Adapters."
    exit 2
}

if ($Adapter.Count -gt 0) {
    $rawAdapters = Get-NamedAdapters $Adapter
} elseif ($Adapters.Count -gt 0) {
    $rawAdapters = $Adapters | ForEach-Object { ConvertFrom-AdapterSpec $_ }
} else {
    $rawAdapters = Get-AutoAdapters
}

$adapterList = New-Object System.Collections.Generic.List[object]
$seenIps = New-Object System.Collections.Generic.HashSet[string]
foreach ($a in $rawAdapters) {
    if (Test-LoopbackOrLinkLocal $a.IP) { continue }
    if (-not $seenIps.Add($a.IP)) { continue }
    $adapterList.Add($a)
}

if ($adapterList.Count -eq 0) {
    Write-Error "No usable adapters found (all candidates were Bluetooth/loopback, or none are Up with an IPv4 address). Pass -Adapter or -Adapters explicitly."
    exit 2
}

Write-Host "==> Adapters under test" -ForegroundColor Cyan
$adapterList | Format-Table -AutoSize | Out-String | Write-Host
Write-Host ("==> Timeout: {0}s, per-probe max download: {1:N0} bytes" -f $TimeoutSec, $MaxDownloadBytes) -ForegroundColor Cyan

$fmt = '%{http_code}|%{time_starttransfer}|%{time_total}|%{speed_download}|%{size_download}'
$results = New-Object System.Collections.Generic.List[object]

foreach ($url in $Urls) {
    foreach ($ad in $adapterList) {
        $curlArgs = @(
            '-4',
            '-L',
            '-s',
            '-o', 'NUL',
            '--interface', $ad.IP,
            '--max-time', $TimeoutSec,
            '--max-filesize', $MaxDownloadBytes,
            '-w', $fmt,
            $url
        )

        $output = & curl.exe @curlArgs 2>$null
        $exitCode = $LASTEXITCODE

        $row = [PSCustomObject]@{
            Url      = $url
            Adapter  = $ad.Alias
            SourceIP = $ad.IP
            HttpCode = '-'
            TTFB_ms  = '-'
            Total_ms = '-'
            Speed    = '-'
            Note     = ''
        }

        $parts = $null
        if (-not [string]::IsNullOrWhiteSpace($output)) {
            $parts = $output.Trim().Split('|')
        }

        if ($exitCode -eq 0 -and $null -ne $parts -and $parts.Count -eq 5 -and $parts[0] -ne '000') {
            $httpCode = $parts[0]
            $ttfbSec = [double]::Parse($parts[1], [System.Globalization.CultureInfo]::InvariantCulture)
            $totalSec = [double]::Parse($parts[2], [System.Globalization.CultureInfo]::InvariantCulture)
            $speedBps = [double]::Parse($parts[3], [System.Globalization.CultureInfo]::InvariantCulture)

            $row.HttpCode = $httpCode
            $row.TTFB_ms = [string][math]::Round($ttfbSec * 1000)
            $row.Total_ms = [string][math]::Round($totalSec * 1000)
            $row.Speed = Format-Speed $speedBps

            $codeNum = 0
            [int]::TryParse($httpCode, [ref] $codeNum) | Out-Null
            if ($codeNum -ge 400) {
                $row.Note = "HTTP $codeNum"
            }
        } else {
            $row.HttpCode = 'FAIL'
            $row.Note = Get-CurlFailureReason $exitCode
        }

        $results.Add($row)
    }
}

Write-Host ""
Write-Host "==> Results" -ForegroundColor Cyan

foreach ($group in ($results | Group-Object Url)) {
    Write-Host ""
    Write-Host ("URL: {0}" -f $group.Name) -ForegroundColor Yellow
    $group.Group |
        Select-Object Adapter, SourceIP, HttpCode, TTFB_ms, Total_ms, Speed, Note |
        Format-Table -AutoSize |
        Out-String |
        Write-Host
}

exit 0
