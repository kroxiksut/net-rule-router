//! VPN-client discovery port.
//!
//! The kill-switch bootstrap needs to know which executable is the user's
//! VPN client so it can be routed to the primary adapter (and thus exempted
//! from fail-closed — its handshake to its own server must never be blocked,
//! or the tunnel deadlocks). A prior approach silently exempted every
//! process whose name matched a `*vpn*` glob — a security hole (any process
//! named `*vpn*` got a permanent kill-switch exemption with no user consent).
//!
//! This port replaces the silent match with DISCOVERY + user confirmation:
//! the GUI onboarding scans for likely VPN clients (running processes +
//! installed programs) by a case-insensitive keyword mask, shows the
//! candidates, and the user confirms which one is their VPN. The confirmed
//! exe then becomes an ordinary "Application → primary route" rule — the
//! existing, consent-based enforcement path — instead of a blanket glob.
//!
//! Per the policy/mechanism seam: this file holds only the neutral
//! contract (the port, the DTOs, the keyword-matching POLICY, the merge/dedup
//! logic) + the off-platform default. The OS MECHANISM lives in each backend
//! and `impl`s [`VpnDiscoveryPort`]. Two invariant sources per OS — running
//! processes and installed applications — mapped to each platform:
//!
//! - **Windows** (`nrr_platform_windows::WindowsVpnDiscovery`, implemented):
//!   `EnumProcesses` for running images; the `Uninstall` registry keys (HKLM +
//!   `WOW6432Node` + HKCU) for installed programs.
//! - **Linux** (`nrr_platform_linux::vpn_discovery`, designed/stub): `/proc`
//!   for running images; XDG `.desktop` entries (incl. Flatpak/Snap export
//!   dirs) as the distro-agnostic installed-apps source, refined by the native
//!   package DB queried per family — deb → `dpkg-query`, rpm → `rpm -qa`, arch
//!   → `pacman -Qq`, alpine → `apk info` (the low-level DB tools, not the
//!   `apt`/`dnf`/`yum`/`zypper` front-ends, so the query is fast, offline, and
//!   non-interactive).
//! - **macOS** (backend not created yet): `proc_listpids`/`libproc` for running
//!   images; `.app` bundles under `/Applications`, `~/Applications` and
//!   `/System/Applications` (read each bundle's `CFBundleName` /
//!   `CFBundleExecutable` from `Contents/Info.plist`), optionally corroborated
//!   by `mdfind "kMDItemKind == 'Application'"` (Spotlight). System VPN
//!   configurations can additionally be read from the Network preferences, a
//!   macOS-only signal with no Windows/Linux analog.
//!
//! Every backend matches its OS-supplied strings through the same neutral
//! [`looks_like_vpn`] policy and returns [`merge_candidates`] output, so the
//! onboarding UI is identical across platforms.

use serde::Serialize;

/// Where a discovered candidate was found.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum VpnCandidateSource {
    /// A currently-running process whose image name matched.
    RunningProcess,
    /// An entry in the OS installed-programs registry whose display name
    /// matched (may or may not be running right now).
    InstalledProgram,
}

/// A likely VPN client surfaced to the user for confirmation. Never acted on
/// automatically — the user picks which (if any) is their VPN.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VpnCandidate {
    /// Human-friendly name: the installed-program display name
    /// (`"Proton VPN"`) or the process image basename (`"nordvpn.exe"`).
    pub display_name: String,
    /// Concrete on-disk exe path when known. `None` when only an installed
    /// program with no resolvable executable was found — the user can still
    /// pick it and point at the exe manually.
    pub exe_path: Option<String>,
    /// True when a matching process is running right now (a strong signal
    /// this really is an active VPN client).
    pub running: bool,
    /// Provenance, for the GUI to explain why it is listed.
    pub source: VpnCandidateSource,
}

/// Discover likely VPN clients on this machine. Never an error — a backend
/// that cannot enumerate returns an empty list. Runs with the caller's
/// privileges (no elevation needed: process enumeration + HKCU/HKLM reads).
pub trait VpnDiscoveryPort: Send + Sync {
    fn discover_vpn_candidates(&self) -> Vec<VpnCandidate>;
}

/// Off-platform / disabled default: finds nothing.
#[derive(Debug, Default)]
pub struct NoopVpnDiscovery;

impl VpnDiscoveryPort for NoopVpnDiscovery {
    fn discover_vpn_candidates(&self) -> Vec<VpnCandidate> {
        Vec::new()
    }
}

/// Distinctive case-insensitive keywords that identify a VPN client by its
/// executable name OR its installed-program display name. Deliberately
/// curated to be distinctive (a bare `"warp"`/`"hola"` would false-positive
/// on unrelated apps) — the user confirms anyway, so a near miss just means
/// they add it manually, while a false positive is one extra row to ignore.
///
/// Neutral POLICY DATA (matched by [`looks_like_vpn`]); the OS mechanism only
/// supplies the strings to test.
pub const VPN_NAME_KEYWORDS: &[&str] = &[
    "vpn",
    "openvpn",
    "wireguard",
    "mullvad",
    "nordvpn",
    "protonvpn",
    "proton vpn",
    "expressvpn",
    "surfshark",
    "windscribe",
    "tunnelbear",
    "hide.me",
    "hidemy",
    "amnezia",
    "outline",
    "cloudflare warp",
    "warp-svc",
    "tailscale",
    "zerotier",
    "softether",
    "openconnect",
    "anyconnect",
    "psiphon",
    "shadowsocks",
    "sing-box",
    // Paid consumer clients whose name does NOT already contain
    // "vpn" (those match via the "vpn" entry above). Distinctive brand tokens
    // only — bare short/ambiguous ones ("pia", "eddie") are deliberately omitted.
    "cyberghost",
    "private internet access",
    "ipvanish",
    "hotspot shield",
    "hotspotshield",
    "ivacy",
    "torguard",
    "secureline", // Avast/AVG SecureLine
    "netbird",
    "perfect privacy",
    "betternet",
    "speedify",
    "browsec",
    "zenmate",
    // Corporate / enterprise clients. Tokens chosen to match the
    // real DisplayName / exe basename without colliding with non-VPN software:
    // "check point" (spaced, unlike the ML "checkpoint"); "pulse secure" (not
    // bare "pulse"); "bigip" (F5 BIG-IP Edge). "citrix" is intentionally NOT
    // added — Citrix Workspace is overwhelmingly VDI, not VPN.
    "globalprotect", // Palo Alto
    "forticlient",   // Fortinet
    "zscaler",
    "check point",  // Check Point Endpoint Security
    "pulse secure", // Ivanti / Pulse Secure
    "netextender",  // SonicWall
    "sophos connect",
    "watchguard",
    "twingate",
    "barracuda",
    "bigip", // F5 BIG-IP Edge Client
    // Russian/CIS enterprise clients (the project's primary
    // audience). "vipnet" (InfoTeCS ViPNet Client/Coordinator) and "s-terra"
    // (S-Terra Gate/Client) are distinctive Latin product names; "континент"
    // (Continent, Security Code) is a common Russian word so it is left out to
    // avoid false positives — users add it manually if needed.
    "vipnet",
    "s-terra",
];

/// True when `text` (an exe basename or a program display name) contains any
/// [`VPN_NAME_KEYWORDS`] entry, case-insensitively. Empty/whitespace → false.
pub fn looks_like_vpn(text: &str) -> bool {
    let lower = text.trim().to_ascii_lowercase();
    if lower.is_empty() {
        return false;
    }
    VPN_NAME_KEYWORDS.iter().any(|kw| lower.contains(kw))
}

/// Merge candidates from several sources into a stable, deduplicated list.
///
/// Dedup key: the exe path when present (case-insensitive), else the lower-
/// cased display name. When two entries collapse, the merged one keeps
/// `running = true` if EITHER was running and prefers a known `exe_path` and
/// the `RunningProcess` source (the stronger signal). Output is sorted:
/// running candidates first, then by display name — so the GUI shows the most
/// likely active client at the top.
pub fn merge_candidates(candidates: Vec<VpnCandidate>) -> Vec<VpnCandidate> {
    let mut merged: Vec<VpnCandidate> = Vec::new();
    for cand in candidates {
        let key_of = |c: &VpnCandidate| -> String {
            match &c.exe_path {
                Some(p) if !p.is_empty() => format!("path:{}", p.to_ascii_lowercase()),
                _ => format!("name:{}", c.display_name.trim().to_ascii_lowercase()),
            }
        };
        let ck = key_of(&cand);
        if let Some(existing) = merged.iter_mut().find(|e| key_of(e) == ck) {
            existing.running = existing.running || cand.running;
            if existing.exe_path.is_none() && cand.exe_path.is_some() {
                existing.exe_path = cand.exe_path;
            }
            // A running-process sighting is the stronger provenance.
            if cand.source == VpnCandidateSource::RunningProcess {
                existing.source = VpnCandidateSource::RunningProcess;
            }
        } else {
            merged.push(cand);
        }
    }
    merged.sort_by(|a, b| {
        b.running.cmp(&a.running).then_with(|| {
            a.display_name
                .to_ascii_lowercase()
                .cmp(&b.display_name.to_ascii_lowercase())
        })
    });
    merged
}

/// Test double: returns a fixed candidate list. Always compiled (not
/// `#[cfg(test)]`) so dependent crates can use it, per the crate convention.
#[derive(Debug, Default, Clone)]
pub struct MockVpnDiscovery {
    candidates: Vec<VpnCandidate>,
}

impl MockVpnDiscovery {
    pub fn new(candidates: Vec<VpnCandidate>) -> Self {
        Self { candidates }
    }
}

impl VpnDiscoveryPort for MockVpnDiscovery {
    fn discover_vpn_candidates(&self) -> Vec<VpnCandidate> {
        self.candidates.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cand(
        name: &str,
        path: Option<&str>,
        running: bool,
        src: VpnCandidateSource,
    ) -> VpnCandidate {
        VpnCandidate {
            display_name: name.to_string(),
            exe_path: path.map(|s| s.to_string()),
            running,
            source: src,
        }
    }

    #[test]
    fn looks_like_vpn_is_case_insensitive_and_distinctive() {
        assert!(looks_like_vpn("nordvpn.exe"));
        assert!(looks_like_vpn("Proton VPN"));
        assert!(looks_like_vpn("WireGuard"));
        assert!(looks_like_vpn("hidemy.name VPN 3.0.exe"));
        assert!(looks_like_vpn("Cloudflare WARP"));
        // Non-VPN apps must not match.
        assert!(!looks_like_vpn("chrome.exe"));
        assert!(!looks_like_vpn("Microsoft Word"));
        assert!(!looks_like_vpn("svchost.exe"));
        assert!(!looks_like_vpn(""));
        assert!(!looks_like_vpn("   "));
    }

    #[test]
    fn merge_dedups_by_path_and_keeps_running_and_prefers_process_source() {
        let input = vec![
            cand(
                "Proton VPN",
                Some(r"C:\Apps\proton.exe"),
                false,
                VpnCandidateSource::InstalledProgram,
            ),
            cand(
                "proton.exe",
                Some(r"c:\apps\PROTON.EXE"),
                true,
                VpnCandidateSource::RunningProcess,
            ),
            cand("NordVPN", None, false, VpnCandidateSource::InstalledProgram),
        ];
        let out = merge_candidates(input);
        assert_eq!(out.len(), 2, "the two proton entries collapse by path");
        // Running one sorts first.
        assert!(out[0].running);
        assert_eq!(out[0].exe_path.as_deref(), Some(r"C:\Apps\proton.exe"));
        assert_eq!(out[0].source, VpnCandidateSource::RunningProcess);
        assert_eq!(out[1].display_name, "NordVPN");
        assert!(!out[1].running);
    }

    #[test]
    fn merge_dedups_pathless_by_display_name() {
        let input = vec![
            cand("NordVPN", None, false, VpnCandidateSource::InstalledProgram),
            cand("nordvpn", None, true, VpnCandidateSource::RunningProcess),
        ];
        let out = merge_candidates(input);
        assert_eq!(out.len(), 1);
        assert!(out[0].running, "running flag survives the merge");
    }

    #[test]
    fn noop_discovery_finds_nothing() {
        assert!(NoopVpnDiscovery.discover_vpn_candidates().is_empty());
    }

    #[test]
    fn mock_returns_seeded_candidates() {
        let m = MockVpnDiscovery::new(vec![cand(
            "NordVPN",
            Some(r"C:\a\nordvpn.exe"),
            true,
            VpnCandidateSource::RunningProcess,
        )]);
        assert_eq!(m.discover_vpn_candidates().len(), 1);
    }
}
