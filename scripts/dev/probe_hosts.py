#!/usr/bin/env python3
"""Sample hosts from NetRuleRouter rules files and probe TCP reachability.

Rules live inside the NetRuleRouter application database and must be exported
to text files before this script can read them. From the GUI, use Rules export
to create rules_primary.txt and/or rules_secondary.txt.

Reads exported rules_primary.txt / rules_secondary.txt (paths given via
--primary / --secondary, or discovered from current directory), extracts
probeable hostnames per the rules file format (see FORMATS.md section 1),
samples a subset, and reports DNS resolution plus TCP connect latency for
each host. This is a read-only diagnostic helper for hardware testing; it
never writes to the rule files.

Stdlib only. Works on Windows and Linux, Python 3.10+.
"""

from __future__ import annotations

import argparse
import csv
import errno
import ipaddress
import random
import socket
import struct
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

APP_SECTIONS = {"Windows", "Linux", "MacOS"}
DOMAIN_LIKE_SECTIONS = {"Zones", "Domains"}

FAKE_IPV4_NET = ipaddress.ip_network("198.18.0.0/15")
FAKE_IPV6_NET = ipaddress.ip_network("fc00::/18")

# Non-routable ranges a resolver should never legitimately hand out for a
# public hostname. Seeing one of these usually means a parked domain (many
# registrars point dead A records at 127.0.0.1) or local DNS interception,
# not a reachable service - so we skip the TCP probe entirely.
BOGUS_IPV4_NETS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
)
BOGUS_IPV6_NETS = (ipaddress.ip_network("fe80::/10"),)

MAX_WORKERS = 16
PROBE_PORTS = (443, 80)
DEFAULT_VERDICT_WAIT = 2.5

COL_WIDTHS = (38, 9, 30, 5, 11, 9)

# Statuses that reflect a live, reachable destination for the purpose of the
# summary's "reachable" tally. OK = plain success (and, under --verdict-wait,
# an observed peer response with no reset). OPEN = the post-handshake wait
# window elapsed without an RST - TLS servers do not speak first, so silence
# is the expected success signal, not a failure.
REACHABLE_STATUSES = frozenset({"OK", "OPEN"})

# errno / winerror values that mean "the peer reset or aborted the TCP
# connection". ConnectionResetError / ConnectionAbortedError already cover
# the common POSIX and Windows cases (CPython maps WSAECONNRESET /
# WSAECONNABORTED to these exception types), this set is a defensive
# fallback for any OSError that slips through with a matching code instead.
RST_ERRNOS = {
    code
    for code in (
        getattr(errno, "ECONNRESET", None),
        getattr(errno, "ECONNABORTED", None),
        getattr(errno, "WSAECONNRESET", None),
        getattr(errno, "WSAECONNABORTED", None),
        10054,  # WSAECONNRESET
        10053,  # WSAECONNABORTED
    )
    if code is not None
}


@dataclass
class SkipCounts:
    zone: int = 0
    ip: int = 0
    app: int = 0
    other: int = 0

    def total(self) -> int:
        return self.zone + self.ip + self.app + self.other


@dataclass
class HostEntry:
    host: str
    side: str


@dataclass
class ProbeResult:
    host: str
    side: str
    ip_used: str
    fake: bool
    status: str
    latency_ms: Optional[float]


def parse_rules_file(path: Path, side: str, skips: SkipCounts) -> list[HostEntry]:
    """Extract probeable hosts from one rulesrules file, tallying skipped entries."""
    hosts: list[HostEntry] = []
    section: Optional[str] = None

    try:
        raw_text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        print(f"warning: could not read {path}: {exc}", file=sys.stderr)
        return hosts

    for raw_line in raw_text.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        if line.startswith("---"):
            section = line[3:].strip() or None
            continue

        if line.startswith("#"):
            # Disabled rule or free comment; neither is an active entry.
            continue

        if section in APP_SECTIONS:
            # Application rule or a nested "- destination" line under it.
            skips.app += 1
            continue

        value = line.split("#", 1)[0].strip()
        if not value:
            continue

        if section == "IP":
            skips.ip += 1
            continue

        if section not in DOMAIN_LIKE_SECTIONS:
            # Unrecognised/extension section (§1.9) - not applied, skip.
            skips.other += 1
            continue

        if value.startswith("*."):
            base = value[2:]
        elif value.startswith("."):
            base = value[1:]
        else:
            base = value
        base = base.strip().lower()

        if not base:
            skips.other += 1
            continue

        try:
            ipaddress.ip_address(base)
            skips.ip += 1
            continue
        except ValueError:
            pass

        if "." not in base:
            # Single-label suffix - a zone/TLD, not a directly probeable host.
            skips.zone += 1
            continue

        hosts.append(HostEntry(host=base, side=side))

    return hosts


def repo_presets_dir() -> Path:
    """The repository's presets/ directory, located from this script's own
    position (scripts/dev/ -> repo root), so --country works from any cwd."""
    return Path(__file__).resolve().parents[2] / "presets"


def preset_rules_paths(
    country: str, preset: Optional[str]
) -> tuple[Optional[Path], Optional[str]]:
    """Resolve presets/<country>/<preset-dir>/ for --country / --preset.

    Returns (preset_dir, error). Most countries ship exactly one preset
    directory; when there are several, --preset picks one by directory name.
    """
    presets_root = repo_presets_dir()
    country_dir = presets_root / country.lower()
    if not country_dir.is_dir():
        known = ", ".join(
            sorted(
                p.name
                for p in presets_root.iterdir()
                if p.is_dir() and p.name != "examples"
            )
            if presets_root.is_dir()
            else []
        )
        return None, f"unknown country '{country}'. Available: {known or 'none found'}"
    if preset is not None:
        chosen = country_dir / preset
        if not chosen.is_dir():
            available = ", ".join(sorted(p.name for p in country_dir.iterdir() if p.is_dir()))
            return None, (
                f"preset '{preset}' not found under {country_dir}. Available: {available}"
            )
        return chosen, None
    preset_dirs = sorted(p for p in country_dir.iterdir() if p.is_dir())
    if not preset_dirs:
        return None, f"no preset directories under {country_dir}"
    if len(preset_dirs) > 1:
        names = ", ".join(p.name for p in preset_dirs)
        return None, (
            f"country '{country}' has several presets ({names}) — pick one with --preset <name>"
        )
    return preset_dirs[0], None


def default_rules_paths(
    country: str, preset: Optional[str]
) -> tuple[list[Path], list[Path], Optional[str]]:
    """Candidate paths for the rules files, checked in order:
    GUI-exported files in the current directory first, then the bundled
    preset selected by --country / --preset.

    Returns (primary_candidates, secondary_candidates, preset_error).
    """
    primary_candidates = [Path.cwd() / "rules_primary.txt"]
    secondary_candidates = [Path.cwd() / "rules_secondary.txt"]
    preset_dir, error = preset_rules_paths(country, preset)
    if preset_dir is not None:
        primary_candidates.append(preset_dir / "rules_primary.txt")
        secondary_candidates.append(preset_dir / "rules_secondary.txt")
    return primary_candidates, secondary_candidates, error


def sample_hosts(hosts: list[HostEntry], count: int, rng: random.Random) -> list[HostEntry]:
    if count >= len(hosts):
        return list(hosts)
    if count <= 0:
        return []
    return rng.sample(hosts, count)


def is_fake_address(addr: str) -> bool:
    try:
        parsed = ipaddress.ip_address(addr)
    except ValueError:
        return False
    if parsed.version == 4:
        return parsed in FAKE_IPV4_NET
    return parsed in FAKE_IPV6_NET


def is_bogus_address(addr: str) -> bool:
    """True for loopback/unspecified/private/link-local answers.

    A public hostname resolving into one of these ranges is not a reachable
    service; it is almost always a parked domain (dead A record) or some
    form of local DNS interception, so it should not be TCP-probed.
    """
    try:
        parsed = ipaddress.ip_address(addr)
    except ValueError:
        return False
    if parsed.is_loopback or parsed.is_unspecified:
        return True
    nets = BOGUS_IPV4_NETS if parsed.version == 4 else BOGUS_IPV6_NETS
    return any(parsed in net for net in nets)


def classify_gaierror(exc: socket.gaierror) -> str:
    """Best-effort classification of a getaddrinfo() failure.

    Returns "transient" when the OS resolver error code looks like a
    temporary failure (analogous to a DNS SERVFAIL or timeout) and
    "notfound" otherwise (analogous to NXDOMAIN / no such name). The stdlib
    does not expose the actual DNS response code, only an OS resolver errno,
    so this is a heuristic rather than an exact mapping.
    """
    code = getattr(exc, "errno", None)
    transient_codes = {
        getattr(socket, name)
        for name in ("EAI_AGAIN", "EAI_FAIL")
        if hasattr(socket, name)
    }
    if code is not None and code in transient_codes:
        return "transient"
    return "notfound"


def resolve_host(host: str) -> tuple[list[tuple[int, str]], bool, Optional[str]]:
    """Resolve a hostname to (family, address) pairs plus a fake-IP flag.

    Returns (addrs, fake, error_kind). error_kind is None when addrs is
    non-empty, otherwise "transient" or "notfound" per classify_gaierror().
    """
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        return [], False, classify_gaierror(exc)

    seen: set[tuple[int, str]] = set()
    addrs: list[tuple[int, str]] = []
    for family, _socktype, _proto, _canon, sockaddr in infos:
        if family not in (socket.AF_INET, socket.AF_INET6):
            continue
        addr = sockaddr[0]
        key = (family, addr)
        if key in seen:
            continue
        seen.add(key)
        addrs.append((family, addr))

    fake = any(is_fake_address(addr) for _family, addr in addrs)
    return addrs, fake, None


def make_sockaddr(family: int, addr: str, port: int):
    if family == socket.AF_INET6:
        return (addr, port, 0, 0)
    return (addr, port)


def wait_for_post_handshake_rst(sock: socket.socket, wait_seconds: float) -> str:
    """Watch a freshly-connected socket for a post-handshake RST.

    A fake-IP address accepts the TCP handshake immediately and dials the
    real upstream in the background; connect() success therefore proves
    nothing about reachability for those addresses. If the background dial
    is refused or fails, the local stack tears the connection down with a
    RST, usually within a few ms but sometimes only after a multi-second
    upstream connect timeout. This function waits up to wait_seconds for
    that RST before giving up.

    Returns "RST" (the connection was reset/aborted - upstream dial failed),
    "OK" (the peer sent data, or performed an orderly close, before any
    reset was seen), or "OPEN" (nothing arrived within the window; treated
    as a pass, since TLS servers do not speak first and silence is the
    expected success signal).
    """
    sock.settimeout(wait_seconds)
    try:
        # Some stacks only surface an already-pending RST on the next send()
        # or recv() rather than asynchronously. A lone NUL byte is not a
        # valid start of any protocol our probe targets (HTTP, TLS), so it
        # cannot elicit an application-level response - it only exists to
        # give a pending reset a socket operation to surface on.
        sock.send(b"\x00")
        sock.recv(1)
        return "OK"
    except socket.timeout:
        return "OPEN"
    except (ConnectionResetError, ConnectionAbortedError):
        return "RST"
    except OSError as exc:
        if getattr(exc, "errno", None) in RST_ERRNOS or getattr(exc, "winerror", None) in RST_ERRNOS:
            return "RST"
        # Any other post-connect socket error is treated conservatively as a
        # reset, since we already proved the handshake completed and cannot
        # otherwise confirm the destination is still alive.
        return "RST"


def tcp_connect_with_verdict(
    family: int,
    addr: str,
    port: int,
    connect_timeout: float,
    verdict_wait: Optional[float],
) -> tuple[str, float]:
    """Connect, then optionally hold the socket open to watch for a RST.

    When verdict_wait is None, this is a plain TCP connect probe (legacy
    behavior). When verdict_wait is a positive number, a successful connect
    is followed by up to verdict_wait seconds of watching for a
    post-handshake RST via wait_for_post_handshake_rst() - see that
    function for what each resulting status means.
    """
    start = time.perf_counter()
    try:
        sock = socket.socket(family, socket.SOCK_STREAM)
    except OSError:
        return "UNREACHABLE", (time.perf_counter() - start) * 1000.0

    try:
        sock.settimeout(connect_timeout)
        sock.connect(make_sockaddr(family, addr, port))
    except socket.timeout:
        sock.close()
        return "TIMEOUT", (time.perf_counter() - start) * 1000.0
    except ConnectionRefusedError:
        sock.close()
        return "REFUSED", (time.perf_counter() - start) * 1000.0
    except OSError:
        sock.close()
        return "UNREACHABLE", (time.perf_counter() - start) * 1000.0

    try:
        if not verdict_wait:
            return "OK", (time.perf_counter() - start) * 1000.0
        status = wait_for_post_handshake_rst(sock, verdict_wait)
        return status, (time.perf_counter() - start) * 1000.0
    finally:
        sock.close()


def probe_entry(
    entry: HostEntry,
    timeout: float,
    verdict_wait: Optional[float],
    verdict_wait_all: bool,
) -> ProbeResult:
    addrs, fake, err_kind = resolve_host(entry.host)
    display_host = entry.host

    if not addrs:
        if err_kind == "transient":
            # Looks like a real resolver problem (SERVFAIL/timeout-ish), not
            # a bare name that simply has no address - report it as such.
            return ProbeResult(entry.host, entry.side, "-", False, "DNS-FAIL", None)

        # Bare/apex name has no address (NXDOMAIN-like). This is expected
        # for suffix rules such as "jtvnw.net" that only ever route
        # subdomains - try the common "www." alias once before giving up.
        www_host = f"www.{entry.host}"
        addrs, fake, _ = resolve_host(www_host)
        if not addrs:
            return ProbeResult(entry.host, entry.side, "-", False, "NO-APEX", None)
        display_host = www_host

    family, addr = addrs[0]

    if is_bogus_address(addr):
        return ProbeResult(display_host, entry.side, addr, fake, "BOGUS-DNS", None)

    apply_wait = verdict_wait if (fake or verdict_wait_all) else None

    status, elapsed = tcp_connect_with_verdict(family, addr, PROBE_PORTS[0], timeout, apply_wait)
    if status in ("TIMEOUT", "REFUSED", "UNREACHABLE"):
        status, elapsed = tcp_connect_with_verdict(family, addr, PROBE_PORTS[1], timeout, apply_wait)

    return ProbeResult(display_host, entry.side, addr, fake, status, elapsed)


def format_row(cols: tuple) -> str:
    parts = []
    for value, width in zip(cols, COL_WIDTHS):
        text = str(value)
        if len(text) > width:
            text = text[: max(width - 1, 1)] + "~"
        parts.append(text.ljust(width))
    return "  ".join(parts).rstrip()


def _stream_counter_width(total: int) -> int:
    """Digit width of the largest counter value, e.g. 3 for total=300."""
    return len(str(total)) if total > 0 else 1


def _stream_counter_len(total: int) -> int:
    """Full rendered length of a "[ 12/300]" counter for the given total."""
    return 2 * _stream_counter_width(total) + 3


def print_stream_header(total: int) -> None:
    """Print the column header once, before the first streamed result line.

    Left-padded to line up under the "[ 12/300]" progress counter each
    streamed row is prefixed with.
    """
    pad = " " * (_stream_counter_len(total) + 1)
    print(pad + format_row(("HOST", "SIDE", "IP", "FAKE", "STATUS", "MS")))
    print("-" * (len(pad) + sum(COL_WIDTHS) + 2 * (len(COL_WIDTHS) - 1)))


def print_stream_row(
    result: ProbeResult, index: int, total: int, lock: threading.Lock
) -> None:
    """Print one probe result immediately as it completes.

    Uses the same column format as the final table, prefixed with a
    "[ 12/300]" progress counter. Guarded by lock so concurrent completions
    (probes run on a thread pool) cannot interleave partial lines.
    """
    width = _stream_counter_width(total)
    counter = f"[{index:>{width}}/{total}]"
    ms = f"{result.latency_ms:.1f}" if result.latency_ms is not None else "-"
    row = format_row(
        (result.host, result.side, result.ip_used, "YES" if result.fake else "-", result.status, ms)
    )
    with lock:
        print(f"{counter} {row}", flush=True)


def print_summary(
    results: list[ProbeResult],
    pool_by_side: dict[str, list[HostEntry]],
    skips: SkipCounts,
) -> None:
    print()
    print("Summary")
    print("-------")

    overall_status_counts: dict[str, int] = {}
    for side in ("primary", "secondary"):
        side_results = [r for r in results if r.side == side]
        probed = len(side_results)
        reachable = sum(1 for r in side_results if r.status in REACHABLE_STATUSES)
        pool = len(pool_by_side.get(side, []))
        print(f"{side}: reachable {reachable} of {probed} probed (probeable pool: {pool})")

        side_status_counts: dict[str, int] = {}
        for r in side_results:
            side_status_counts[r.status] = side_status_counts.get(r.status, 0) + 1
            overall_status_counts[r.status] = overall_status_counts.get(r.status, 0) + 1

        if side_status_counts:
            counts_str = ", ".join(f"{k}={v}" for k, v in sorted(side_status_counts.items()))
            print(f"  {side} status counts: {counts_str}")

        timeout_count = side_status_counts.get("TIMEOUT", 0)
        if probed > 0 and timeout_count / probed > 0.5:
            print(
                f"  hint: over half of {side} hosts timed out - if this route is a "
                "VPN/tunnel that is currently down, a fail-closed kill switch produces "
                "exactly this pattern; check route status before treating it as a "
                "rules problem"
            )

    if overall_status_counts:
        counts_str = ", ".join(f"{k}={v}" for k, v in sorted(overall_status_counts.items()))
        print(f"Status counts: {counts_str}")
    else:
        print("Status counts: (none probed)")

    fake_count = sum(1 for r in results if r.fake)
    print(f"Fake-resolving hosts: {fake_count}")

    print(
        "Skipped entries: "
        f"zone={skips.zone}, ip={skips.ip}, app={skips.app}, other={skips.other}, "
        f"total={skips.total()}"
    )

    hints = []
    if "NO-APEX" in overall_status_counts:
        hints.append("NO-APEX = suffix rule; apex has no address - expected")
    if "BOGUS-DNS" in overall_status_counts:
        hints.append(
            "BOGUS-DNS = DNS answered a non-routable address (parked domain or DNS interception)"
        )
    if "RST" in overall_status_counts:
        hints.append(
            "RST = handshake succeeded but the connection was reset shortly after - typical of "
            "a fake-IP address whose real upstream refused the connection or failed to dial"
        )
    if "OPEN" in overall_status_counts:
        hints.append(
            "OPEN = handshake succeeded and no reset arrived within --verdict-wait - treated as "
            "reachable (TLS servers do not speak first, so silence is the success signal)"
        )
    if hints:
        print()
        for hint in hints:
            print(f"hint: {hint}")


def write_csv(path: Path, results: list[ProbeResult]) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["host", "side", "ip", "fake", "status", "latency_ms"])
        for r in results:
            latency = "" if r.latency_ms is None else f"{r.latency_ms:.1f}"
            writer.writerow([r.host, r.side, r.ip_used, "yes" if r.fake else "no", r.status, latency])


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Sample and TCP-probe hosts listed in NetRuleRouter rules files.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Rules must be exported from the NetRuleRouter GUI (Rules export) to rules_primary.txt "
            "and/or rules_secondary.txt. Pass paths via --primary / --secondary, or run this script "
            "from the directory containing the exported files.\n"
            "\n"
            "Status meanings:\n"
            "  OK           TCP connect succeeded. Under --verdict-wait, this also covers a\n"
            "               peer response (or orderly close) observed before any reset.\n"
            "  OPEN         Connect succeeded and the --verdict-wait window elapsed with no\n"
            "               RST observed. Treated as reachable: TLS servers do not speak\n"
            "               first, so silence within the window is the expected pass signal.\n"
            "  RST          Connect succeeded but the connection was reset/aborted shortly\n"
            "               after. For a FAKE address this means the local fake-IP stack's\n"
            "               background dial to the real upstream was refused or failed -\n"
            "               the handshake itself proves nothing there, only RST vs OPEN does.\n"
            "               For a real address (only seen with --verdict-wait-all) this means\n"
            "               a middlebox or the server itself reset the connection.\n"
            "  TIMEOUT      connect() did not complete within --timeout.\n"
            "  REFUSED      TCP RST during the handshake itself (nothing listening).\n"
            "  UNREACHABLE  Some other connect-time OS error (e.g. no route to host).\n"
            "  NO-APEX      Suffix-only rule; the bare hostname has no DNS record - expected.\n"
            "  BOGUS-DNS    DNS answered with a non-routable address (parked domain or local\n"
            "               DNS interception) - not TCP-probed.\n"
            "  DNS-FAIL     Resolver returned a transient-looking error (SERVFAIL/timeout-ish),\n"
            "               as opposed to a plain \"no such name\".\n"
        ),
    )
    parser.add_argument("--primary", type=Path, default=None, help="Path to rules_primary.txt")
    parser.add_argument("--secondary", type=Path, default=None, help="Path to rules_secondary.txt")
    parser.add_argument(
        "--country",
        default="ru",
        metavar="CODE",
        help=(
            "Bundled preset country code (presets/<code>/) used when no exported "
            "rules files are found in the current directory (default: ru)"
        ),
    )
    parser.add_argument(
        "--preset",
        default=None,
        metavar="NAME",
        help="Preset directory name under presets/<country>/ (needed only when a country has several)",
    )
    parser.add_argument("--count", type=int, default=25, help="Hosts sampled per side (default: 25)")
    parser.add_argument(
        "--timeout", type=float, default=3.0, help="TCP connect timeout in seconds (default: 3.0)"
    )
    parser.add_argument("--csv", type=Path, default=None, help="Optional CSV output path")
    parser.add_argument(
        "--all", action="store_true", help="Probe every probeable host instead of sampling"
    )
    parser.add_argument("--seed", type=int, default=None, help="Random seed for reproducible sampling")
    parser.add_argument(
        "--verdict-wait",
        type=float,
        default=DEFAULT_VERDICT_WAIT,
        metavar="SECONDS",
        help=(
            "After a successful TCP connect to a FAKE address (198.18.0.0/15 / fc00::/18), keep "
            "the socket open and wait up to this many seconds for a post-handshake RST before "
            "reporting a verdict of OK/OPEN/RST instead of a bare connect-succeeded OK. Set to 0 "
            "to disable and fall back to a plain connect probe (default: "
            f"{DEFAULT_VERDICT_WAIT})"
        ),
    )
    parser.add_argument(
        "--verdict-wait-all",
        action="store_true",
        help=(
            "Apply --verdict-wait to every probed host, not just addresses detected as FAKE. "
            "Slower, but also catches middlebox/server resets on real addresses"
        ),
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help=(
            "Run a local loopback self-test that proves RST detection works on this machine "
            "(spins up a listener that force-resets its connections), then exit without "
            "touching any rules files or the network"
        ),
    )
    return parser


def _pack_linger(onoff: int, linger: int) -> bytes:
    """Pack a SO_LINGER struct for the current platform.

    POSIX's struct linger is two C ints (8 bytes); Winsock's is two
    u_short fields (4 bytes) - using the wrong layout silently corrupts the
    option or fails setsockopt(), so the format must be picked per platform.
    """
    fmt = "hh" if sys.platform == "win32" else "ii"
    return struct.pack(fmt, onoff, linger)


def run_self_test() -> int:
    """Loopback proof that this script's RST detection works on this host.

    Starts a listener on 127.0.0.1 that accepts one connection and closes
    it with SO_LINGER(on, 0) set, which makes the OS send a TCP RST instead
    of the usual graceful FIN. It then runs the exact same connect+verdict
    path used for real probes and checks the result is "RST". This isolates
    the socket-level detection logic from the network and from having a
    live fake-IP stack available, which is useful when adapting this script
    to a new platform.
    """
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def serve_and_reset() -> None:
        try:
            conn, _addr = listener.accept()
        except OSError:
            return
        try:
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, _pack_linger(1, 0))
        except OSError:
            pass
        conn.close()

    server_thread = threading.Thread(target=serve_and_reset, daemon=True)
    server_thread.start()

    print(f"self-test: connecting to 127.0.0.1:{port} (server force-resets on close)")
    status, elapsed = tcp_connect_with_verdict(
        socket.AF_INET, "127.0.0.1", port, connect_timeout=2.0, verdict_wait=2.0
    )
    server_thread.join(timeout=2.0)
    listener.close()

    print(f"self-test: verdict={status} ({elapsed:.1f} ms)")
    if status == "RST":
        print("self-test: PASS - post-handshake RST was correctly detected")
        return 0
    print(f"self-test: FAIL - expected RST, got {status}", file=sys.stderr)
    return 1


def main(argv: Optional[list[str]] = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    args = build_arg_parser().parse_args(argv)

    if args.self_test:
        return run_self_test()

    verdict_wait: Optional[float] = args.verdict_wait if args.verdict_wait > 0 else None

    default_primary_candidates, default_secondary_candidates, preset_error = default_rules_paths(
        args.country, args.preset
    )
    if preset_error is not None and (args.primary is None or args.secondary is None):
        print(f"note: {preset_error}", file=sys.stderr)

    skips = SkipCounts()
    pool_by_side: dict[str, list[HostEntry]] = {"primary": [], "secondary": []}
    files_found = 0
    sides_with_no_hosts: list[str] = []

    # Process primary rules
    if args.primary is not None:
        primary_candidates = [args.primary]
    else:
        primary_candidates = default_primary_candidates

    primary_path = next((p for p in primary_candidates if p.is_file()), None)
    if primary_path is None:
        candidates_str = ", ".join(str(p) for p in primary_candidates)
        print(f"error: primary rules file not found. Checked: {candidates_str}", file=sys.stderr)
    else:
        files_found += 1
        pool_by_side["primary"] = parse_rules_file(primary_path, "primary", skips)
        if not pool_by_side["primary"]:
            sides_with_no_hosts.append("primary")

    # Process secondary rules
    if args.secondary is not None:
        secondary_candidates = [args.secondary]
    else:
        secondary_candidates = default_secondary_candidates

    secondary_path = next((p for p in secondary_candidates if p.is_file()), None)
    if secondary_path is None:
        candidates_str = ", ".join(str(p) for p in secondary_candidates)
        print(f"error: secondary rules file not found. Checked: {candidates_str}", file=sys.stderr)
    else:
        files_found += 1
        pool_by_side["secondary"] = parse_rules_file(secondary_path, "secondary", skips)
        if not pool_by_side["secondary"]:
            sides_with_no_hosts.append("secondary")

    # If no rules files were found at all, print hint and exit with code 2
    if files_found == 0:
        print(
            "\nNo rules files were found. To use this script:\n"
            "  1. Open NetRuleRouter GUI\n"
            "  2. Go to Rules and click 'Export' (for primary and/or secondary)\n"
            "  3. Save the exported rules_primary.txt and/or rules_secondary.txt files\n"
            "  4. Run this script from the directory containing the exported files,\n"
            "     or pass the paths via --primary and/or --secondary",
            file=sys.stderr,
        )
        return 2

    # Warn if files were found but contained no probeable hosts
    for side in sides_with_no_hosts:
        print(f"warning: {side} rules file found but contains no probeable hosts", file=sys.stderr)

    rng = random.Random(args.seed)
    to_probe: list[HostEntry] = []
    for side in ("primary", "secondary"):
        hosts = pool_by_side[side]
        to_probe.extend(hosts if args.all else sample_hosts(hosts, args.count, rng))

    results: list[ProbeResult] = []
    if to_probe:
        total = len(to_probe)
        print_stream_header(total)
        print_lock = threading.Lock()
        with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, total)) as pool:
            futures = [
                pool.submit(probe_entry, entry, args.timeout, verdict_wait, args.verdict_wait_all)
                for entry in to_probe
            ]
            for index, future in enumerate(as_completed(futures), start=1):
                result = future.result()
                results.append(result)
                print_stream_row(result, index, total, print_lock)
        print()
        print("(Per-host results were streamed above as each probe completed.)")
    else:
        print("No hosts probed.")

    results.sort(key=lambda r: (r.side, r.host))

    print_summary(results, pool_by_side, skips)

    if args.csv:
        write_csv(args.csv, results)
        print(f"\nCSV written to {args.csv}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
