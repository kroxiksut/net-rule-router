//! The platform capability descriptor emitted into the QML context so the
//! GUI renders **capability-driven**: a section keyed off a feature is
//! shown only when `supports.<feature>` is true, instead of the GUI
//! branching on `Qt.platform.os`. This keeps OS knowledge in Rust (behind
//! the platform policy/mechanism seam) and lets a less-capable OS degrade
//! gracefully by flipping a flag, with no QML logic change.
//!
//! Cross-OS: [`PlatformProfile::current`] is `cfg`-gated so each OS reports its
//! own enforcement/service/elevation backends and feature set. Windows is the
//! fully-featured reference; Linux/macOS values are provisional placeholders
//! until their enforcement backends land, and are intentionally conservative
//! (a capability the port does not implement yet is `false`).

use serde::Serialize;

/// OS-specific capability descriptor for the running platform.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlatformProfile {
    /// `"windows"` | `"linux"` | `"macos"`.
    pub os: &'static str,
    /// The packet-filter mechanism backing enforcement:
    /// `"wfp"` (Windows) | `"nftables"` (Linux) | `"pf"` (macOS).
    pub enforcement_backend: &'static str,
    /// Background-service integration model:
    /// `"scm"` | `"systemd"` | `"launchd"`.
    pub service_model: &'static str,
    /// Privilege-elevation broker:
    /// `"uac"` | `"polkit"` | `"authorization-services"`.
    pub elevation_model: &'static str,
    /// The OS `hosts`-file path for this platform, so the GUI can reveal it (the hosts file redirects/blocks names BEFORE
    /// NRR sees traffic; a user diagnosing "my rule host resolves to loopback"
    /// needs to find it). Mirrors
    /// `nrr_platform_api::hosts_file::default_hosts_path` — a drift-guard test
    /// in `nrr-platform-api` asserts they agree on the running OS. Computed in
    /// Rust so QML never branches on `Qt.platform.os` for the path.
    pub hosts_file_path: String,
    /// Per-feature availability. A GUI section keyed off a feature is hidden
    /// (or shown disabled with an explanation) when its flag is `false`.
    pub supports: PlatformSupports,
}

/// The Windows OS `hosts`-file path. Reads `SystemRoot` at call time (set on
/// every Windows session), falling back to the canonical install path. Kept in
/// sync with `nrr_platform_api::hosts_file::default_hosts_path` by a drift-guard
/// test there. String-built (not `PathBuf`) so the value is identical whether
/// this constructor runs on a Windows or a non-Windows (test) build.
fn windows_hosts_path() -> String {
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| String::from(r"C:\Windows"));
    format!(r"{system_root}\System32\drivers\etc\hosts")
}

/// The Unix (Linux/macOS) OS `hosts`-file path.
fn unix_hosts_path() -> String {
    String::from("/etc/hosts")
}

/// Does a hosts-file CONTENT contain any effective
/// mapping entry (an IP followed by at least one hostname), as opposed to
/// comments and blank lines only? Pure classifier (no I/O — the caller reads
/// the file; on a stock Windows the file is comments-only and the GUI hides
/// the hosts affordances entirely). Loopback/`0.0.0.0` entries COUNT as
/// entries: ad-block style hosts lists are exactly the case the hosts-bypass
/// setting exists for.
pub fn hosts_content_has_entries(content: &str) -> bool {
    content.lines().any(|line| {
        let line = line.split('#').next().unwrap_or("").trim();
        let mut tokens = line.split_whitespace();
        match tokens.next() {
            Some(first) => first.parse::<std::net::IpAddr>().is_ok() && tokens.next().is_some(),
            None => false,
        }
    })
}

/// Per-feature availability flags. Each corresponds to an OS-specific
/// capability the GUI can gate a section on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlatformSupports {
    /// Kill-switch / leak protection (fail-closed packet blocking).
    pub kill_switch: bool,
    /// Per-application routing (steer a process to the additional adapter).
    pub app_routing: bool,
    /// Passive DNS observation (learn a rule host's IPs from system DNS).
    pub dns_observe: bool,
    /// Local DNS resolver (Mode B — enforce-before-connect).
    pub dns_resolver: bool,
    /// Bypass the hosts file when resolving rule hosts to routable IPs.
    pub hosts_pin: bool,
    /// A privileged background service that keeps enforcing while the GUI is
    /// closed.
    pub background_service: bool,
    /// Launch-on-login autostart integration.
    pub autostart: bool,

    // ── Capability INVERSIONS ────────────────────────────────────────────────
    // Unlike the flags above (a Windows superset that other OSes may lack),
    // these are genuine inversions where an OS has something Windows does NOT.
    // They MUST mirror `nrr_platform_api::enforcement::EnforcementCapabilities`
    // — that is the SSOT, but `nrr-shared` sits below `nrr-platform-api` in the
    // dependency graph and cannot import it, so the values are duplicated here
    // and a drift-guard test in `nrr-platform-api` asserts the two agree.
    /// Route traffic per OS user with no kernel driver (Linux `ip rule
    /// uidrange → table`). Windows Free cannot (`false`).
    pub per_user_routing: bool,
    /// A per-application block is leak-proof (Windows `ALE_APP_ID`). Linux is
    /// `false` until the eBPF connect-verdict port ships — its MVP enforces app
    /// rules by observed destination, which is NOT leak-proof and must be
    /// surfaced as such.
    pub per_app_block_leakproof: bool,
    /// Block a user across ALL protocols, including ICMP/ping (Linux
    /// `meta skuid` on every l4proto). Windows cannot: the packet layer forces
    /// `user_sid = None`, widening a per-user block system-wide (`false`).
    pub per_user_all_protocol_scoping: bool,
}

impl PlatformProfile {
    /// The descriptor for the OS this binary is running on.
    pub fn current() -> Self {
        #[cfg(target_os = "windows")]
        {
            Self::windows()
        }
        #[cfg(target_os = "linux")]
        {
            Self::linux()
        }
        #[cfg(target_os = "macos")]
        {
            Self::macos()
        }
        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            Self::windows()
        }
    }

    /// Windows (WFP / SCM / UAC) — the fully-featured reference platform.
    pub fn windows() -> Self {
        Self {
            os: "windows",
            enforcement_backend: "wfp",
            service_model: "scm",
            elevation_model: "uac",
            hosts_file_path: windows_hosts_path(),
            supports: PlatformSupports {
                kill_switch: true,
                app_routing: true,
                dns_observe: true,
                dns_resolver: true,
                hosts_pin: true,
                background_service: true,
                autostart: true,
                // Inversions: Windows blocks apps leak-proof (ALE_APP_ID) but
                // cannot route per-user or scope a per-user block to all
                // protocols (packet layer forces user_sid = None).
                per_user_routing: false,
                per_app_block_leakproof: true,
                per_user_all_protocol_scoping: false,
            },
        }
    }

    /// Linux (nftables / systemd / polkit). Provisional until the Linux
    /// enforcement backend lands; per-process routing and the ETW-style DNS
    /// observer have no analogue wired yet, so they report `false`.
    pub fn linux() -> Self {
        Self {
            os: "linux",
            enforcement_backend: "nftables",
            service_model: "systemd",
            elevation_model: "polkit",
            hosts_file_path: unix_hosts_path(),
            supports: PlatformSupports {
                kill_switch: true,
                app_routing: false,
                dns_observe: false,
                dns_resolver: true,
                hosts_pin: true,
                background_service: true,
                autostart: true,
                // Inversions: Linux routes per-user (ip rule uidrange) and
                // scopes per-user blocks to all protocols (meta skuid), which
                // Windows cannot — but its per-app block is NOT leak-proof
                // until the eBPF connect-verdict port lands (observed-dest MVP).
                per_user_routing: true,
                per_app_block_leakproof: false,
                per_user_all_protocol_scoping: true,
            },
        }
    }

    /// macOS (pf / launchd / Authorization Services). Provisional — the
    /// Network Extension work gates several features behind Apple
    /// entitlements, so the conservative defaults mirror Linux for now.
    pub fn macos() -> Self {
        Self {
            os: "macos",
            enforcement_backend: "pf",
            service_model: "launchd",
            elevation_model: "authorization-services",
            hosts_file_path: unix_hosts_path(),
            supports: PlatformSupports {
                kill_switch: true,
                app_routing: false,
                dns_observe: false,
                dns_resolver: true,
                hosts_pin: true,
                background_service: true,
                autostart: true,
                // Conservative until the macOS Network Extension backend is
                // verified: claim none of the inversions (an unverified
                // capability flag defaults to `false`, never a false promise).
                per_user_routing: false,
                per_app_block_leakproof: false,
                per_user_all_protocol_scoping: false,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    // Test assertions unwrap/expect on infallible fixtures.
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn current_matches_the_compiled_target_os() {
        let p = PlatformProfile::current();
        #[cfg(target_os = "windows")]
        assert_eq!(p.os, "windows");
        #[cfg(target_os = "linux")]
        assert_eq!(p.os, "linux");
        #[cfg(target_os = "macos")]
        assert_eq!(p.os, "macos");
    }

    #[test]
    fn windows_is_fully_featured() {
        let s = PlatformProfile::windows().supports;
        assert!(s.kill_switch && s.app_routing && s.dns_observe && s.dns_resolver);
        assert!(s.hosts_pin && s.background_service && s.autostart);
    }

    #[test]
    fn serialises_to_camel_case_for_the_qml_context() {
        let v = serde_json::to_value(PlatformProfile::windows()).expect("serialise");
        assert_eq!(v["os"], "windows");
        assert_eq!(v["enforcementBackend"], "wfp");
        assert_eq!(v["serviceModel"], "scm");
        assert_eq!(v["elevationModel"], "uac");
        // Hosts path reaches QML under a camelCase key. The `SystemRoot`
        // prefix varies (case, drive), so assert the suffix.
        assert!(v["hostsFilePath"]
            .as_str()
            .expect("hostsFilePath is a string")
            .ends_with(r"\System32\drivers\etc\hosts"));
        assert_eq!(v["supports"]["killSwitch"], true);
        assert_eq!(v["supports"]["appRouting"], true);
        assert_eq!(v["supports"]["dnsResolver"], true);
        // Inversion flags reach QML under camelCase keys too.
        assert_eq!(v["supports"]["perAppBlockLeakproof"], true);
        assert_eq!(v["supports"]["perUserRouting"], false);
        assert_eq!(v["supports"]["perUserAllProtocolScoping"], false);
    }

    #[test]
    fn hosts_content_classifier_ignores_comments_and_counts_any_mapping() {
        // Stock Windows hosts (comments only) → false.
        let stock = "# Copyright (c) 1993-2009 Microsoft Corp.\n#\n# 127.0.0.1  localhost\n\n";
        assert!(!hosts_content_has_entries(stock));
        // A real mapping counts, even to loopback (ad-block style — exactly
        // what the hosts-bypass setting exists for).
        assert!(hosts_content_has_entries("127.0.0.1 ads.example.com\n"));
        assert!(hosts_content_has_entries("0.0.0.0 tracker.example\n"));
        assert!(hosts_content_has_entries(
            "93.184.216.34 example.com # pinned\n"
        ));
        assert!(hosts_content_has_entries("::1 ipv6.local\n"));
        // An IP with no hostname, or junk, is not an entry.
        assert!(!hosts_content_has_entries(
            "127.0.0.1\nnot-an-ip host\n# c\n"
        ));
    }

    #[test]
    fn capability_inversions_flip_between_windows_and_linux() {
        let w = PlatformProfile::windows().supports;
        let l = PlatformProfile::linux().supports;
        // Genuine inversions: each capability is present on exactly one OS.
        assert!(w.per_app_block_leakproof && !l.per_app_block_leakproof);
        assert!(!w.per_user_routing && l.per_user_routing);
        assert!(!w.per_user_all_protocol_scoping && l.per_user_all_protocol_scoping);
    }

    #[test]
    fn macos_claims_no_unverified_inversions() {
        let m = PlatformProfile::macos().supports;
        assert!(!m.per_user_routing);
        assert!(!m.per_app_block_leakproof);
        assert!(!m.per_user_all_protocol_scoping);
    }
}
