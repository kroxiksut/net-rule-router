//! Application-group discovery port.
//!
//! Two user-facing surfaces need to know which installed/running programs
//! belong to a well-known *group* so the onboarding can offer a route for the
//! whole group at once (default: primary):
//!
//! - **Virtual machines & emulators** — a hypervisor's or emulator's guest
//!   traffic egresses as ordinary sockets of the host process (VirtualBox,
//!   VMware, QEMU, DOSBox, Android/console emulators), so an ordinary
//!   application rule routes it. Kernel-NAT stacks (WSL2, Hyper-V, Docker
//!   Desktop) have NO owning process — their traffic cannot be routed by an
//!   application rule — so they are surfaced for DISPLAY only (route fixed to
//!   primary, not user-assignable in this edition).
//! - **Torrents / peer-to-peer** — BitTorrent clients, P2P file-sharing/sync
//!   tools, and blockchain nodes open many outbound connections; a group route
//!   lets the user steer that bulk traffic, and (separately) their peers must
//!   not be learned as rule-hosts by the FCrDNS path.
//!
//! Per the policy/mechanism seam, this file holds ONLY the neutral
//! contract: the group taxonomy, the DTOs, the dictionary (POLICY DATA), the
//! `classify`/merge logic, and the off-platform default. The OS MECHANISM
//! (process enumeration + installed-programs registry + adapter/feature probing
//! for the kernel-NAT stacks) lives in each backend and `impl`s
//! [`AppGroupDiscoveryPort`]. This mirrors [`crate::vpn_discovery`] exactly, so
//! the two onboarding flows share one shape across Windows / Linux / macOS.

use serde::Serialize;

/// The tab a group is shown under. The onboarding presents one window with two
/// tabs; every [`AppGroupKind`] maps to exactly one of these.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AppGroupTab {
    /// Virtual machines and emulators.
    Virtualization,
    /// Torrents and other peer-to-peer software.
    PeerToPeer,
}

/// A recognised group of applications. The subcategory drives both the tab it
/// appears under and whether the user may assign it a route.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AppGroupKind {
    /// Usermode-NAT hypervisor — guest traffic is the host process's sockets,
    /// so an application rule routes it (VirtualBox, VMware, QEMU, DOSBox).
    Hypervisor,
    /// Kernel-NAT virtual network (WSL2, Hyper-V, Docker Desktop). Guest
    /// traffic has no owning user process, so it CANNOT be routed by an
    /// application rule in this edition — surfaced for display, route fixed to
    /// primary.
    KernelVirtualNet,
    /// Android emulator (BlueStacks, Nox, LDPlayer, MEmu, Android Studio AVD).
    AndroidEmulator,
    /// Console/computer emulator with its own network traffic (RetroArch
    /// netplay, Dolphin, PCSX2, RPCS3, …).
    ConsoleEmulator,
    /// BitTorrent client. Explicit rename: kebab-case would emit
    /// `"bit-torrent"`, but the wire slug consumed by the GUI (tab lists,
    /// `app-groups.group.*` locale keys) is `"bittorrent"` — one word, like
    /// the protocol name.
    #[serde(rename = "bittorrent")]
    BitTorrent,
    /// Non-BitTorrent P2P file sharing or sync (eMule, Soulseek, DC++,
    /// Resilio Sync, Syncthing).
    P2pFileSharing,
    /// Blockchain / cryptocurrency full node (Bitcoin, Ethereum, Monero).
    CryptoNode,
}

impl AppGroupKind {
    /// The tab this group is displayed under.
    #[must_use]
    pub fn tab(self) -> AppGroupTab {
        match self {
            Self::Hypervisor
            | Self::KernelVirtualNet
            | Self::AndroidEmulator
            | Self::ConsoleEmulator => AppGroupTab::Virtualization,
            Self::BitTorrent | Self::P2pFileSharing | Self::CryptoNode => AppGroupTab::PeerToPeer,
        }
    }

    /// Whether the user may assign this group a route. False only for
    /// [`Self::KernelVirtualNet`]: its traffic has no owning process, so an
    /// application rule cannot steer it — the GUI shows it read-only, pinned to
    /// the primary route, with an explanation.
    #[must_use]
    pub fn is_route_assignable(self) -> bool {
        !matches!(self, Self::KernelVirtualNet)
    }

    /// Whether this group's connections must be kept OUT of the FCrDNS
    /// rule-host learner. A P2P peer's ISP hostname (`host.corbina.ru`)
    /// forward-confirms and matches a broad zone rule (`.ru`), so learning it
    /// inflates the zone permit cap with junk peers. Only the
    /// peer-to-peer groups carry this flag.
    #[must_use]
    pub fn suppresses_fcrdns_learning(self) -> bool {
        matches!(
            self,
            Self::BitTorrent | Self::P2pFileSharing | Self::CryptoNode
        )
    }

    /// Whether this group must keep REAL addresses when fake-IP is on (Block D).
    /// True for the peer-to-peer groups: they talk to thousands of bare-IP peers
    /// that were never resolved by name, so a per-hostname fake address has
    /// nothing to key on and would only add a relay hop. The mirror image of
    /// [`Self::suppresses_fcrdns_learning`] — same groups, different reason, so
    /// the two stay separately documented and separately changeable.
    #[must_use]
    pub fn excluded_from_fake_ip(self) -> bool {
        matches!(
            self,
            Self::BitTorrent | Self::P2pFileSharing | Self::CryptoNode
        )
    }
}

/// Where a discovered application was found.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AppDiscoverySource {
    /// A currently-running process whose image name matched.
    RunningProcess,
    /// An installed-programs registry entry whose display name matched.
    InstalledProgram,
    /// Inferred from an OS capability/adapter rather than a program — used for
    /// the kernel-NAT stacks (WSL2 feature enabled, `vEthernet` adapter, …)
    /// which may have no discrete installed-program entry.
    SystemFeature,
}

/// A discovered member of a known application group, surfaced to the user for a
/// route choice. Never acted on automatically — the default route is primary
/// until the user (or a rule) says otherwise.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveredApp {
    /// Which group this belongs to.
    pub kind: AppGroupKind,
    /// Human-friendly name: the installed-program display name (`"VirtualBox"`)
    /// or the process image basename (`"qbittorrent.exe"`).
    pub display_name: String,
    /// Concrete on-disk exe path when known; `None` when only an installed
    /// program or a system feature (no resolvable executable) was found.
    pub exe_path: Option<String>,
    /// True when a matching process is running right now.
    pub running: bool,
    /// Provenance, for the GUI to explain why it is listed.
    pub source: AppDiscoverySource,
}

/// Discover known application-group members on this machine. Never an error — a
/// backend that cannot enumerate returns an empty list. Runs with the caller's
/// privileges (process enumeration + HKCU/HKLM reads + feature probing).
pub trait AppGroupDiscoveryPort: Send + Sync {
    fn discover_app_groups(&self) -> Vec<DiscoveredApp>;
}

/// Off-platform / disabled default: finds nothing.
#[derive(Debug, Default)]
pub struct NoopAppGroupDiscovery;

impl AppGroupDiscoveryPort for NoopAppGroupDiscovery {
    fn discover_app_groups(&self) -> Vec<DiscoveredApp> {
        Vec::new()
    }
}

/// One dictionary entry: a group plus the distinctive case-insensitive keywords
/// that identify its members by exe basename OR installed-program display name.
///
/// Neutral POLICY DATA (matched by [`classify_app`]); the OS mechanism only
/// supplies the strings to test. Keywords are lower-case and extension-free so
/// `contains` matches `"qBittorrent"`, `"qbittorrent.exe"`, and a display name
/// alike. Curated to be distinctive — the user confirms the route anyway, so a
/// near miss just means a manual add while a false positive is one row to skip.
#[derive(Clone, Copy, Debug)]
pub struct AppGroupEntry {
    pub kind: AppGroupKind,
    pub keywords: &'static [&'static str],
}

/// The Free-edition application-group dictionary. Deliberately limited; users
/// extend it via feedback channels. The OS backend tests each supplied string
/// against every entry via [`classify_app`].
pub const APP_GROUP_DICTIONARY: &[AppGroupEntry] = &[
    // ── Virtualization: usermode-NAT hypervisors (route-assignable) ──────────
    AppGroupEntry {
        kind: AppGroupKind::Hypervisor,
        keywords: &[
            "virtualbox",
            "vboxheadless",
            "vboxsvc",
            "vmware",
            "vmware-vmx",
            "qemu",
            "dosbox",
        ],
    },
    // ── Virtualization: kernel-NAT stacks (display-only, primary-pinned) ──────
    AppGroupEntry {
        kind: AppGroupKind::KernelVirtualNet,
        keywords: &[
            "wsl",
            "hyper-v",
            "hyperv",
            "vmmem",
            "vmwp",
            "docker desktop",
            "com.docker",
            "dockerd",
        ],
    },
    // ── Virtualization: Android emulators ────────────────────────────────────
    AppGroupEntry {
        kind: AppGroupKind::AndroidEmulator,
        keywords: &[
            "bluestacks",
            "hd-player", // BlueStacks engine process
            "noxplayer",
            "nox_adb",
            "ldplayer",
            "dnplayer", // LDPlayer engine process
            "memu",
            "qemu-system-x86_64", // Android Studio AVD backend
            "emulator",           // Android Studio `emulator` launcher
        ],
    },
    // ── Virtualization: console/computer emulators with network traffic ──────
    AppGroupEntry {
        kind: AppGroupKind::ConsoleEmulator,
        keywords: &["retroarch", "dolphin", "pcsx2", "rpcs3", "cemu", "citra"],
    },
    // ── Peer-to-peer: BitTorrent clients ─────────────────────────────────────
    AppGroupEntry {
        kind: AppGroupKind::BitTorrent,
        keywords: &[
            "qbittorrent",
            "transmission",
            "deluge",
            "utorrent",
            "bittorrent",
            "btweb", // BitTorrent Web (btweb.exe)
            "vuze",
            "tixati",
            "frostwire",
        ],
    },
    // ── Peer-to-peer: non-BitTorrent file sharing & sync ─────────────────────
    AppGroupEntry {
        kind: AppGroupKind::P2pFileSharing,
        keywords: &[
            "emule",
            "amule",
            "soulseek",
            "slskd",
            "airdc",
            "dcplusplus",
            "resilio",
            "btsync",
            "syncthing",
        ],
    },
    // ── Peer-to-peer: blockchain / crypto nodes ──────────────────────────────
    AppGroupEntry {
        kind: AppGroupKind::CryptoNode,
        keywords: &[
            "bitcoin-qt",
            "bitcoind",
            "geth",
            "besu",
            "monerod",
            "monero-wallet",
        ],
    },
];

/// The group `text` (an exe basename or a program display name) belongs to, or
/// `None` when it matches no dictionary entry. Empty/whitespace → `None`.
/// First-match wins in dictionary order.
#[must_use]
pub fn classify_app(text: &str) -> Option<AppGroupKind> {
    let lower = text.trim().to_ascii_lowercase();
    if lower.is_empty() {
        return None;
    }
    APP_GROUP_DICTIONARY
        .iter()
        .find(|entry| entry.keywords.iter().any(|kw| lower.contains(kw)))
        .map(|entry| entry.kind)
}

/// Merge discovered apps from several sources into a stable, deduplicated list.
///
/// Dedup key: the exe path when present (case-insensitive), else the lower-cased
/// `(kind, display_name)` pair — so the same program found as both a running
/// process and an installed entry collapses, while two different groups sharing
/// a name do not. On collapse the merged entry keeps `running = true` if either
/// was running, prefers a known `exe_path`, and prefers the strongest source
/// (`RunningProcess` > `InstalledProgram` > `SystemFeature`). Output is sorted:
/// by tab, then group kind, then running-first, then display name — a stable
/// order the GUI can render into tabbed sections directly.
#[must_use]
pub fn merge_discovered(apps: Vec<DiscoveredApp>) -> Vec<DiscoveredApp> {
    fn source_rank(s: AppDiscoverySource) -> u8 {
        match s {
            AppDiscoverySource::RunningProcess => 0,
            AppDiscoverySource::InstalledProgram => 1,
            AppDiscoverySource::SystemFeature => 2,
        }
    }
    let key_of = |a: &DiscoveredApp| -> String {
        match &a.exe_path {
            Some(p) if !p.is_empty() => format!("path:{}", p.to_ascii_lowercase()),
            _ => format!(
                "kn:{:?}:{}",
                a.kind,
                a.display_name.trim().to_ascii_lowercase()
            ),
        }
    };
    let mut merged: Vec<DiscoveredApp> = Vec::new();
    for app in apps {
        let ak = key_of(&app);
        if let Some(existing) = merged.iter_mut().find(|e| key_of(e) == ak) {
            existing.running = existing.running || app.running;
            if existing.exe_path.is_none() && app.exe_path.is_some() {
                existing.exe_path = app.exe_path.clone();
            }
            if source_rank(app.source) < source_rank(existing.source) {
                existing.source = app.source;
            }
        } else {
            merged.push(app);
        }
    }
    // Explicit taxonomy ranks — the display order the GUI renders, NOT the
    // enum's alphabetical debug string (which would put PeerToPeer before
    // Virtualization).
    fn tab_rank(t: AppGroupTab) -> u8 {
        match t {
            AppGroupTab::Virtualization => 0,
            AppGroupTab::PeerToPeer => 1,
        }
    }
    fn kind_rank(k: AppGroupKind) -> u8 {
        match k {
            AppGroupKind::Hypervisor => 0,
            AppGroupKind::KernelVirtualNet => 1,
            AppGroupKind::AndroidEmulator => 2,
            AppGroupKind::ConsoleEmulator => 3,
            AppGroupKind::BitTorrent => 4,
            AppGroupKind::P2pFileSharing => 5,
            AppGroupKind::CryptoNode => 6,
        }
    }
    merged.sort_by(|a, b| {
        tab_rank(a.kind.tab())
            .cmp(&tab_rank(b.kind.tab()))
            .then_with(|| kind_rank(a.kind).cmp(&kind_rank(b.kind)))
            .then_with(|| b.running.cmp(&a.running))
            .then_with(|| {
                a.display_name
                    .to_ascii_lowercase()
                    .cmp(&b.display_name.to_ascii_lowercase())
            })
    });
    merged
}

/// Test double: returns a fixed list. Always compiled (not `#[cfg(test)]`) so
/// dependent crates can use it, per the crate convention.
#[derive(Debug, Default, Clone)]
pub struct MockAppGroupDiscovery {
    apps: Vec<DiscoveredApp>,
}

impl MockAppGroupDiscovery {
    pub fn new(apps: Vec<DiscoveredApp>) -> Self {
        Self { apps }
    }
}

impl AppGroupDiscoveryPort for MockAppGroupDiscovery {
    fn discover_app_groups(&self) -> Vec<DiscoveredApp> {
        self.apps.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app(
        kind: AppGroupKind,
        name: &str,
        path: Option<&str>,
        running: bool,
        src: AppDiscoverySource,
    ) -> DiscoveredApp {
        DiscoveredApp {
            kind,
            display_name: name.to_string(),
            exe_path: path.map(|s| s.to_string()),
            running,
            source: src,
        }
    }

    /// Wire-contract pin: the serialized `kind` slug of EVERY variant, exactly
    /// as the QML consumer expects it. The second entry point is
    /// `apps/desktop/qml/components/AppGroupRoutingDialog.qml`
    /// (`_virtualizationKinds` / `_peerToPeerKinds`, plus the
    /// `app-groups.group.<slug>` locale keys) — that dialog filters discovered
    /// apps by these strings, so a drifted slug silently hides a whole group
    /// (a BitTorrent client serialized as `"bit-torrent"` never appeared on
    /// the "Torrents and P2P" tab). Change a slug here ONLY together with the
    /// QML lists and both locale files.
    #[test]
    fn kind_wire_slugs_match_the_qml_dialog() {
        let pinned = [
            (AppGroupKind::Hypervisor, "hypervisor"),
            (AppGroupKind::KernelVirtualNet, "kernel-virtual-net"),
            (AppGroupKind::AndroidEmulator, "android-emulator"),
            (AppGroupKind::ConsoleEmulator, "console-emulator"),
            (AppGroupKind::BitTorrent, "bittorrent"),
            (AppGroupKind::P2pFileSharing, "p2p-file-sharing"),
            (AppGroupKind::CryptoNode, "crypto-node"),
        ];
        for (kind, slug) in pinned {
            let value = serde_json::to_value(kind).unwrap_or_default();
            assert_eq!(
                value,
                serde_json::Value::String(slug.to_string()),
                "{kind:?} must serialize as {slug:?} — see AppGroupRoutingDialog.qml"
            );
        }
    }

    /// Same pin for `source`: `AppGroupRoutingDialog.qml::_badgeTextFor`
    /// matches these strings to pick the row badge.
    #[test]
    fn source_wire_slugs_match_the_qml_dialog() {
        let pinned = [
            (AppDiscoverySource::RunningProcess, "running-process"),
            (AppDiscoverySource::InstalledProgram, "installed-program"),
            (AppDiscoverySource::SystemFeature, "system-feature"),
        ];
        for (source, slug) in pinned {
            let value = serde_json::to_value(source).unwrap_or_default();
            assert_eq!(
                value,
                serde_json::Value::String(slug.to_string()),
                "{source:?} must serialize as {slug:?} — see AppGroupRoutingDialog.qml"
            );
        }
    }

    #[test]
    fn classify_maps_known_apps_to_their_group() {
        assert_eq!(
            classify_app("qBittorrent.exe"),
            Some(AppGroupKind::BitTorrent)
        );
        assert_eq!(classify_app("btweb.exe"), Some(AppGroupKind::BitTorrent));
        assert_eq!(
            classify_app("VirtualBox VM"),
            Some(AppGroupKind::Hypervisor)
        );
        assert_eq!(
            classify_app("Docker Desktop"),
            Some(AppGroupKind::KernelVirtualNet)
        );
        assert_eq!(
            classify_app("BlueStacks"),
            Some(AppGroupKind::AndroidEmulator)
        );
        assert_eq!(classify_app("RPCS3"), Some(AppGroupKind::ConsoleEmulator));
        assert_eq!(
            classify_app("syncthing"),
            Some(AppGroupKind::P2pFileSharing)
        );
        assert_eq!(classify_app("bitcoind"), Some(AppGroupKind::CryptoNode));
    }

    #[test]
    fn classify_rejects_unknown_and_empty() {
        assert_eq!(classify_app("chrome.exe"), None);
        assert_eq!(classify_app("Microsoft Word"), None);
        assert_eq!(classify_app(""), None);
        assert_eq!(classify_app("   "), None);
    }

    #[test]
    fn tab_and_route_assignability_match_the_taxonomy() {
        assert_eq!(AppGroupKind::Hypervisor.tab(), AppGroupTab::Virtualization);
        assert_eq!(AppGroupKind::BitTorrent.tab(), AppGroupTab::PeerToPeer);
        // Kernel-NAT is the only non-assignable group.
        assert!(AppGroupKind::Hypervisor.is_route_assignable());
        assert!(!AppGroupKind::KernelVirtualNet.is_route_assignable());
        assert!(AppGroupKind::BitTorrent.is_route_assignable());
    }

    #[test]
    fn only_p2p_groups_suppress_fcrdns_learning() {
        assert!(AppGroupKind::BitTorrent.suppresses_fcrdns_learning());
        assert!(AppGroupKind::P2pFileSharing.suppresses_fcrdns_learning());
        assert!(AppGroupKind::CryptoNode.suppresses_fcrdns_learning());
        assert!(!AppGroupKind::Hypervisor.suppresses_fcrdns_learning());
        assert!(!AppGroupKind::KernelVirtualNet.suppresses_fcrdns_learning());
    }

    #[test]
    fn merge_dedups_by_path_keeps_running_and_prefers_process_source() {
        let input = vec![
            app(
                AppGroupKind::Hypervisor,
                "VirtualBox",
                Some(r"C:\Prog\VBoxSVC.exe"),
                false,
                AppDiscoverySource::InstalledProgram,
            ),
            app(
                AppGroupKind::Hypervisor,
                "VBoxSVC.exe",
                Some(r"c:\prog\vboxsvc.exe"),
                true,
                AppDiscoverySource::RunningProcess,
            ),
        ];
        let out = merge_discovered(input);
        assert_eq!(out.len(), 1, "same path collapses regardless of case");
        assert!(out[0].running, "running survives the merge");
        assert_eq!(out[0].source, AppDiscoverySource::RunningProcess);
    }

    #[test]
    fn merge_keeps_distinct_groups_that_share_a_name() {
        // Contrived: same pathless display name under two different groups must
        // NOT collapse (the dedup key includes the kind for pathless entries).
        let input = vec![
            app(
                AppGroupKind::BitTorrent,
                "node",
                None,
                false,
                AppDiscoverySource::InstalledProgram,
            ),
            app(
                AppGroupKind::CryptoNode,
                "node",
                None,
                true,
                AppDiscoverySource::RunningProcess,
            ),
        ];
        let out = merge_discovered(input);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn merge_sorts_by_tab_then_group() {
        let input = vec![
            app(
                AppGroupKind::BitTorrent,
                "qBittorrent",
                None,
                false,
                AppDiscoverySource::InstalledProgram,
            ),
            app(
                AppGroupKind::Hypervisor,
                "VirtualBox",
                None,
                false,
                AppDiscoverySource::InstalledProgram,
            ),
        ];
        let out = merge_discovered(input);
        // Virtualization tab sorts before PeerToPeer.
        assert_eq!(out[0].kind, AppGroupKind::Hypervisor);
        assert_eq!(out[1].kind, AppGroupKind::BitTorrent);
    }

    #[test]
    fn noop_finds_nothing_and_mock_returns_seeded() {
        assert!(NoopAppGroupDiscovery.discover_app_groups().is_empty());
        let m = MockAppGroupDiscovery::new(vec![app(
            AppGroupKind::BitTorrent,
            "qBittorrent",
            Some(r"C:\a\qbittorrent.exe"),
            true,
            AppDiscoverySource::RunningProcess,
        )]);
        assert_eq!(m.discover_app_groups().len(), 1);
    }
}
