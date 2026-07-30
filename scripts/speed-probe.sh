#!/usr/bin/env bash
#
# Per-adapter reachability and download-speed probe (Linux / WSL twin of
# scripts/speed-probe.ps1).
#
# NetRuleRouter routes traffic across existing interfaces by source IP
# (e.g. a primary NIC plus a secondary VPN tunnel adapter). This script
# answers "how does site X behave over adapter A vs adapter B" by shelling
# out to curl with `--interface <source-ip>` per probe, which pins the
# outbound source address and therefore the egress path — it does not touch
# NetRuleRouter's own routing tables, it just measures what the OS routing
# table + NRR policy currently produce.
#
# Requires curl. Read-only: issues plain HTTP(S) GET requests, discards
# response bodies, does not modify network state.
#
# Exit codes:
#   0 - ran to completion (individual probe failures are reported inline,
#       not a script failure — this is a measurement tool)
#   2 - usage error (curl missing, no usable adapters found, bad args)
#
# Usage:
#   ./scripts/speed-probe.sh
#   ./scripts/speed-probe.sh --timeout 10
#   ./scripts/speed-probe.sh --url https://example.com --url https://www.google.com/generate_204
#   ./scripts/speed-probe.sh --no-default-urls --url https://example.com
#   ./scripts/speed-probe.sh --adapter "LAN=192.168.0.5" --adapter "VPN=10.88.0.2"
#   ./scripts/speed-probe.sh -a eth0 -a tun0
#   ./scripts/speed-probe.sh -a eth0,tun0
#
# Default (no -a / --adapter): interfaces are auto-enumerated by walking
# /sys/class/net, keeping only operstate == "up", dropping "lo", dropping the
# product's own TUN adapter (name matching "NetRuleRouter" or with an IPv4 in
# 198.18.0.0/15), and dropping interfaces with no IPv4 address. Loopback
# (127.*) and link-local (169.254.*) addresses are always skipped regardless
# of source. Explicit -a selection bypasses the TUN filter.
#
# -a <name> bypasses the default filter entirely and probes exactly the
# named interface(s) (as reported by `ip link`), repeatable or
# comma-separated, looked up regardless of operstate; an unknown interface
# name or an interface with no IPv4 address is a hard usage error (exit 2).
#
# --adapter entries are "alias=source-ip" (alias is only a display label) or
# a bare IP (used as its own label) — a manual escape hatch for source IPs
# not visible as a named interface. -a and --adapter are mutually exclusive.

set -uo pipefail

TIMEOUT=15
MAX_BYTES=$((20 * 1024 * 1024))
URLS=()
USE_DEFAULT_URLS=1
ADAPTER_SPECS=()
ADAPTER_NAMES=()

DEFAULT_URLS=(
    "https://ya.ru"
    "https://www.google.com/generate_204"
    "https://speed.cloudflare.com/__down?bytes=2000000"
)

usage() {
    cat <<'EOF'
Usage: speed-probe.sh [options]

Options:
  --url URL              Add a URL to probe (repeatable). Replaces the
                          built-in default set unless combined with
                          --keep-default-urls.
  --keep-default-urls    Keep the built-in default URLs in addition to any
                          --url entries.
  --no-default-urls       Alias for the implicit behaviour of --url: do not
                          probe the built-in default URLs.
  --adapter SPEC         Add "alias=source-ip" or a bare source IP
                          (repeatable). Disables auto-enumeration.
  -a, --adapter-name NAME
                          Select an interface by name (as shown by `ip
                          link`), bypassing the default up/IPv4 filter.
                          Repeatable, or a single comma-separated list.
                          Disables auto-enumeration. Mutually exclusive
                          with --adapter.
  --timeout SECONDS      Per-probe max time in seconds (default: 15).
  --max-bytes N          Abort a probe if the response exceeds N bytes
                          (default: 20971520, i.e. 20 MiB).
  -h, --help             Show this help and exit.

Examples:
  ./scripts/speed-probe.sh
  ./scripts/speed-probe.sh --timeout 10
  ./scripts/speed-probe.sh --url https://example.com
  ./scripts/speed-probe.sh --adapter "LAN=192.168.0.5" --adapter "VPN=10.88.0.2"
  ./scripts/speed-probe.sh -a eth0 -a tun0
  ./scripts/speed-probe.sh -a eth0,tun0
EOF
}

KEEP_DEFAULT_URLS=0

while [ $# -gt 0 ]; do
    case "$1" in
        --url)
            [ $# -ge 2 ] || { echo "speed-probe.sh: --url requires an argument" >&2; exit 2; }
            URLS+=("$2")
            USE_DEFAULT_URLS=0
            shift 2
            ;;
        --keep-default-urls)
            KEEP_DEFAULT_URLS=1
            shift
            ;;
        --no-default-urls)
            USE_DEFAULT_URLS=0
            shift
            ;;
        --adapter)
            [ $# -ge 2 ] || { echo "speed-probe.sh: --adapter requires an argument" >&2; exit 2; }
            ADAPTER_SPECS+=("$2")
            shift 2
            ;;
        -a|--adapter-name)
            [ $# -ge 2 ] || { echo "speed-probe.sh: $1 requires an argument" >&2; exit 2; }
            IFS=',' read -r -a _names <<< "$2"
            ADAPTER_NAMES+=("${_names[@]}")
            shift 2
            ;;
        --timeout)
            [ $# -ge 2 ] || { echo "speed-probe.sh: --timeout requires an argument" >&2; exit 2; }
            TIMEOUT="$2"
            shift 2
            ;;
        --max-bytes)
            [ $# -ge 2 ] || { echo "speed-probe.sh: --max-bytes requires an argument" >&2; exit 2; }
            MAX_BYTES="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "speed-probe.sh: unknown argument: $1" >&2
            usage
            exit 2
            ;;
    esac
done

if [ "${#ADAPTER_NAMES[@]}" -gt 0 ] && [ "${#ADAPTER_SPECS[@]}" -gt 0 ]; then
    echo "speed-probe.sh: specify only one of -a/--adapter-name or --adapter" >&2
    exit 2
fi

if [ "$USE_DEFAULT_URLS" -eq 1 ] || [ "$KEEP_DEFAULT_URLS" -eq 1 ]; then
    URLS=("${DEFAULT_URLS[@]}" "${URLS[@]:-}")
fi
if [ "${#URLS[@]}" -eq 0 ]; then
    echo "speed-probe.sh: no URLs to probe" >&2
    exit 2
fi

if ! command -v curl >/dev/null 2>&1; then
    echo "speed-probe.sh: curl not found on PATH" >&2
    exit 2
fi

is_loopback_or_link_local() {
    case "$1" in
        127.*) return 0 ;;
        169.254.*) return 0 ;;
        *) return 1 ;;
    esac
}

is_fake_ip_range() {
    # 198.18.0.0/15 covers 198.18.x.x and 198.19.x.x
    case "$1" in
        198.18.*|198.19.*) return 0 ;;
        *) return 1 ;;
    esac
}

is_tun_adapter() {
    # Check if interface name matches NetRuleRouter (case-insensitive)
    case "${1,,}" in
        *netrulerouter*) return 0 ;;
        *) return 1 ;;
    esac
}

is_virtual_adapter() {
    # Check if interface name matches a virtual adapter pattern.
    # VirtualBox, Docker, bridge, and hypervisor virtual adapters.
    case "$1" in
        vboxnet*|docker*|br-*|veth*|virbr*)
            return 0
            ;;
    esac
    return 1
}

ADAPTER_ALIASES=()
ADAPTER_IPS=()

add_adapter() {
    local alias_name="$1"
    local ip="$2"
    local existing
    if is_loopback_or_link_local "$ip"; then
        return
    fi
    for existing in "${ADAPTER_IPS[@]:-}"; do
        if [ "$existing" = "$ip" ]; then
            return
        fi
    done
    ADAPTER_ALIASES+=("$alias_name")
    ADAPTER_IPS+=("$ip")
}

# Resolve one interface name to its IPv4 address(es), bypassing the
# operstate/loopback/IPv4-presence filter used by auto-enumeration below.
# Errors out (exit 2) if the interface does not exist or has no IPv4
# address — this is the explicit "-a" selection path, so a typo or a
# not-yet-configured interface must fail loudly, not silently drop.
add_named_adapter() {
    local name="$1"
    if [ ! -e "/sys/class/net/$name" ]; then
        local available
        available=$(cd /sys/class/net 2>/dev/null && echo * )
        echo "speed-probe.sh: no such adapter: '$name'. Available adapters: ${available:-<none>}" >&2
        exit 2
    fi
    local addrs
    addrs=$(ip -o -4 addr show dev "$name" 2>/dev/null | awk '{print $4}')
    if [ -z "$addrs" ]; then
        echo "speed-probe.sh: adapter '$name' has no usable IPv4 address" >&2
        exit 2
    fi
    local addr ip_only
    while read -r addr; do
        [ -n "$addr" ] || continue
        ip_only="${addr%%/*}"
        add_adapter "$name" "$ip_only"
    done <<< "$addrs"
}

if [ "${#ADAPTER_NAMES[@]}" -gt 0 ]; then
    for name in "${ADAPTER_NAMES[@]}"; do
        add_named_adapter "$name"
    done
elif [ "${#ADAPTER_SPECS[@]}" -gt 0 ]; then
    for spec in "${ADAPTER_SPECS[@]}"; do
        if [[ "$spec" == *"="* ]]; then
            add_adapter "${spec%%=*}" "${spec#*=}"
        else
            add_adapter "$spec" "$spec"
        fi
    done
else
    # Auto-enumerate: walk /sys/class/net, keep operstate == "up", skip
    # "lo", skip the TUN adapter, skip virtual adapters, and skip interfaces
    # with no IPv4 address.
    for ifpath in /sys/class/net/*; do
        [ -e "$ifpath" ] || continue
        ifname=$(basename "$ifpath")
        [ "$ifname" = "lo" ] && continue
        if is_tun_adapter "$ifname"; then
            continue
        fi
        if is_virtual_adapter "$ifname"; then
            continue
        fi
        operstate=$(cat "$ifpath/operstate" 2>/dev/null || echo "unknown")
        [ "$operstate" = "up" ] || continue
        addr=$(ip -o -4 addr show dev "$ifname" 2>/dev/null | awk '{print $4; exit}')
        [ -n "$addr" ] || continue
        ip_only="${addr%%/*}"
        if is_fake_ip_range "$ip_only"; then
            continue
        fi
        add_adapter "$ifname" "$ip_only"
    done
fi

if [ "${#ADAPTER_IPS[@]}" -eq 0 ]; then
    echo "speed-probe.sh: no usable adapters found (all candidates were loopback/link-local, or none are up with an IPv4 address). Pass -a/--adapter-name or --adapter explicitly." >&2
    exit 2
fi

echo "==> Adapters under test"
for i in "${!ADAPTER_IPS[@]}"; do
    printf '  %-20s %s\n' "${ADAPTER_ALIASES[$i]}" "${ADAPTER_IPS[$i]}"
done
echo "==> Timeout: ${TIMEOUT}s, per-probe max download: ${MAX_BYTES} bytes"

format_speed() {
    # $1 = bytes/sec (curl's %{speed_download}, a decimal string)
    awk -v b="$1" 'BEGIN {
        if (b + 0 >= 1048576) {
            printf "%.2f MB/s", b / 1048576
        } else {
            printf "%.1f KB/s", b / 1024
        }
    }'
}

ms_from_seconds() {
    awk -v s="$1" 'BEGIN { printf "%.0f", s * 1000 }'
}

curl_failure_reason() {
    case "$1" in
        6)  echo "could not resolve host" ;;
        7)  echo "failed to connect" ;;
        28) echo "timeout" ;;
        35) echo "SSL connect error" ;;
        52) echo "empty reply from server" ;;
        56) echo "recv failure (connection reset)" ;;
        63) echo "exceeded max download size" ;;
        *)  echo "curl exit $1" ;;
    esac
}

CURL_FMT='%{http_code}|%{time_starttransfer}|%{time_total}|%{speed_download}|%{size_download}'

echo ""
echo "==> Results"

for url in "${URLS[@]}"; do
    echo ""
    echo "URL: ${url}"
    printf '  %-20s %-15s %-6s %-8s %-8s %-12s %s\n' "ADAPTER" "SOURCE-IP" "HTTP" "TTFB-MS" "TOTAL-MS" "SPEED" "NOTE"

    for i in "${!ADAPTER_IPS[@]}"; do
        alias_name="${ADAPTER_ALIASES[$i]}"
        ip="${ADAPTER_IPS[$i]}"

        output=$(curl -4 -L -s -o /dev/null \
            --interface "$ip" \
            --max-time "$TIMEOUT" \
            --max-filesize "$MAX_BYTES" \
            -w "$CURL_FMT" \
            "$url" 2>/dev/null)
        exit_code=$?

        http_code="-"
        ttfb_ms="-"
        total_ms="-"
        speed="-"
        note=""

        if [ "$exit_code" -eq 0 ] && [ -n "$output" ]; then
            IFS='|' read -r http_code raw_ttfb raw_total raw_speed _ <<< "$output"
            if [ "$http_code" = "000" ] || [ -z "$http_code" ]; then
                http_code="FAIL"
                ttfb_ms="-"
                total_ms="-"
                speed="-"
                note=$(curl_failure_reason "$exit_code")
            else
                ttfb_ms=$(ms_from_seconds "$raw_ttfb")
                total_ms=$(ms_from_seconds "$raw_total")
                speed=$(format_speed "$raw_speed")
                if [ "$http_code" -ge 400 ] 2>/dev/null; then
                    note="HTTP ${http_code}"
                fi
            fi
        else
            http_code="FAIL"
            note=$(curl_failure_reason "$exit_code")
        fi

        printf '  %-20s %-15s %-6s %-8s %-8s %-12s %s\n' \
            "$alias_name" "$ip" "$http_code" "$ttfb_ms" "$total_ms" "$speed" "$note"
    done
done

exit 0
