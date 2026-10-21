//! What this machine's kernel can actually do, as found at start-up and
//! corrected when a later attempt shows otherwise. The static profile says what
//! the platform could do; this says what it does here.
//!
//! Every probe is read-only: it never touches traffic or installs anything.

use std::sync::atomic::{AtomicBool, Ordering};

/// A capability the profile claims for Linux that a kernel or distribution may
/// not give.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KernelCapability {
    /// `SOCK_DESTROY`: closing established connections after a rule change.
    ConnectionReset,
    /// `ip rule uidrange`: routes that differ per user.
    UserRoutes,
    /// NFLOG: reports of blocked connections.
    BlockReports,
    /// `rt ipsec` (Linux 4.20, nftables 0.9.1): a policy-based IPsec VPN's
    /// networks spared from the blanket block. Learnt from a refused apply.
    IpsecNetworks,
}

impl KernelCapability {
    pub const ALL: [Self; 4] = [
        Self::ConnectionReset,
        Self::UserRoutes,
        Self::BlockReports,
        Self::IpsecNetworks,
    ];

    /// Stable id the clients map to `platform.missing.<slug>.*` locale keys.
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::ConnectionReset => "connection-reset",
            Self::UserRoutes => "user-routes",
            Self::BlockReports => "block-reports",
            Self::IpsecNetworks => "ipsec-networks",
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::ConnectionReset => 0,
            Self::UserRoutes => 1,
            Self::BlockReports => 2,
            Self::IpsecNetworks => 3,
        }
    }
}

/// One answer per capability, each `true` until a probe or a failed attempt
/// says no: a machine we could not test keeps the benefit of the doubt.
static AVAILABLE: [AtomicBool; KernelCapability::ALL.len()] = [
    AtomicBool::new(true),
    AtomicBool::new(true),
    AtomicBool::new(true),
    AtomicBool::new(true),
];

/// Record what was found. Logged once per change, not per call.
pub fn record(capability: KernelCapability, available: bool) {
    let before = AVAILABLE[capability.index()].swap(available, Ordering::Relaxed);
    if before != available {
        tracing::warn!(
            target: "nrr::capabilities",
            msg_key = "linux-capability-changed",
            capability = capability.slug(),
            available,
            "a kernel capability became available or went missing on this machine",
        );
    }
}

/// Held by every test that moves the process-wide answers: tests run in
/// parallel within one process.
#[cfg(test)]
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[must_use]
pub fn is_available(capability: KernelCapability) -> bool {
    AVAILABLE[capability.index()].load(Ordering::Relaxed)
}

/// Whether the kernel closes UDP (QUIC) sockets on request. Not a client-visible
/// capability: TCP reset still works without it, so it only gates the extra dump.
static UDP_RESET: AtomicBool = AtomicBool::new(true);

pub fn record_udp_reset(available: bool) {
    if UDP_RESET.swap(available, Ordering::Relaxed) != available {
        tracing::warn!(
            target: "nrr::capabilities",
            available,
            "closing UDP sockets on request is {} on this machine",
            if available { "available" } else { "missing" },
        );
    }
}

#[must_use]
pub fn udp_reset_available() -> bool {
    UDP_RESET.load(Ordering::Relaxed)
}

/// A catch-all routing rule of another program sits far ahead of ours.
static FOREIGN_RULE_AHEAD: AtomicBool = AtomicBool::new(false);

/// Slug of the foreign-rule notice, beside the capability slugs.
pub const FOREIGN_RULE_AHEAD_SLUG: &str = "foreign-rule-ahead";

pub fn set_foreign_rule_ahead(present: bool) {
    FOREIGN_RULE_AHEAD.store(present, Ordering::Relaxed);
}

/// What the clients show: missing capabilities, then the foreign-rule notice.
#[must_use]
pub fn reported_slugs() -> Vec<String> {
    let mut slugs: Vec<String> = missing().into_iter().map(|c| c.slug().to_owned()).collect();
    if FOREIGN_RULE_AHEAD.load(Ordering::Relaxed) {
        slugs.push(FOREIGN_RULE_AHEAD_SLUG.to_owned());
    }
    slugs
}

/// What this machine lacks, in a stable order.
#[must_use]
pub fn missing() -> Vec<KernelCapability> {
    KernelCapability::ALL
        .into_iter()
        .filter(|c| !is_available(*c))
        .collect()
}

/// What a refused `SOCK_DESTROY` for a socket that cannot exist says about the
/// kernel; `None` when the answer says nothing either way.
#[must_use]
pub fn destroy_support_from_errno(errno: i32) -> Option<bool> {
    const ENOENT: i32 = 2;
    const EOPNOTSUPP: i32 = 95;
    match errno {
        // Looked the socket up and found none: the request is understood.
        0 | ENOENT => Some(true),
        EOPNOTSUPP => Some(false),
        // A missing privilege (EPERM) and anything else prove nothing.
        _ => None,
    }
}

/// The reverse-path filter mode in force for an interface: the kernel takes
/// the larger of the machine-wide and the interface's own value (`0` off,
/// `1` strict, `2` loose).
#[must_use]
pub fn effective_rp_filter(all: u8, interface: u8) -> u8 {
    all.max(interface)
}

/// A strict filter drops a reply that returns on a different interface than the
/// one the system would use to reach its sender, which per-user routes cause
/// for every user but the one the main table was built for.
#[must_use]
pub fn rp_filter_is_strict(all: &str, default: &str) -> bool {
    let read = |text: &str| text.trim().parse::<u8>().unwrap_or(0);
    effective_rp_filter(read(all), read(default)) == 1
}

/// Run the start-up probes and record their answers. Block reports are
/// recorded by the NFLOG start itself, which is the probe.
pub fn probe_at_start() {
    #[cfg(target_os = "linux")]
    {
        if let Some(supported) = crate::stale_flows::probe_destroy_support() {
            record(KernelCapability::ConnectionReset, supported);
        }
        let release = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
        record(
            KernelCapability::UserRoutes,
            crate::policy_routing::release_selects_by_uid(&release),
        );
        let read = |name: &str| {
            std::fs::read_to_string(format!("/proc/sys/net/ipv4/conf/{name}/rp_filter"))
                .unwrap_or_default()
        };
        if rp_filter_is_strict(&read("all"), &read("default")) {
            tracing::warn!(
                target: "nrr::capabilities",
                msg_key = "linux-rp-filter-strict",
                "strict reverse-path filtering is on: a second signed-in user may get no replies from hosts routed through the additional connection",
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_kernel_built_without_destroy_is_told_apart_from_a_missing_privilege() {
        assert_eq!(destroy_support_from_errno(95), Some(false));
        assert_eq!(destroy_support_from_errno(2), Some(true));
        assert_eq!(destroy_support_from_errno(0), Some(true));
        assert_eq!(destroy_support_from_errno(1), None, "EPERM proves nothing");
        assert_eq!(destroy_support_from_errno(22), None);
    }

    #[test]
    fn strict_filtering_is_found_in_either_setting() {
        assert!(rp_filter_is_strict("1\n", "0\n"));
        assert!(rp_filter_is_strict("0", "1"));
        assert!(!rp_filter_is_strict("0", "0"));
        assert!(!rp_filter_is_strict("2", "2"), "loose lets replies in");
        assert!(!rp_filter_is_strict("1", "2"), "the larger value wins");
        assert!(
            !rp_filter_is_strict("", "garbage"),
            "unreadable counts as off"
        );
    }

    #[test]
    fn slugs_are_distinct_and_stable() {
        let slugs: Vec<_> = KernelCapability::ALL.iter().map(|c| c.slug()).collect();
        assert_eq!(
            slugs,
            [
                "connection-reset",
                "user-routes",
                "block-reports",
                "ipsec-networks"
            ]
        );
    }

    /// UDP reset has a flag of its own: losing it is not a missing client-visible
    /// capability, since TCP closing still works.
    #[test]
    fn a_kernel_that_cannot_close_udp_is_not_a_missing_capability() {
        record_udp_reset(false);
        assert!(!udp_reset_available());
        record_udp_reset(true);
        assert!(udp_reset_available());
    }

    /// Process-wide state: one test owns the whole sequence.
    #[test]
    fn a_missing_capability_is_listed_until_it_is_seen_again() {
        let _held = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        for c in KernelCapability::ALL {
            record(c, true);
        }
        assert!(missing().is_empty());
        record(KernelCapability::BlockReports, false);
        record(KernelCapability::ConnectionReset, false);
        assert_eq!(
            missing(),
            [
                KernelCapability::ConnectionReset,
                KernelCapability::BlockReports
            ]
        );
        assert!(is_available(KernelCapability::UserRoutes));
        for c in KernelCapability::ALL {
            record(c, true);
        }
        assert!(missing().is_empty());
        record(KernelCapability::UserRoutes, false);
        set_foreign_rule_ahead(true);
        assert_eq!(reported_slugs(), ["user-routes", FOREIGN_RULE_AHEAD_SLUG]);
        set_foreign_rule_ahead(false);
        record(KernelCapability::UserRoutes, true);
        assert!(reported_slugs().is_empty());
    }
}
