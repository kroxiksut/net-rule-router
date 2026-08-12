//! Which hostnames get a fake address — the neutral policy half of fake-IP.
//!
//! The shape is deliberately "broad by default, with named exclusions" (scope
//! decision 0720): once the user turns fake-IP on, ordinary applications and
//! virtual machines are all steered through fake addresses, because that is what
//! makes routing per-hostname. Two classes stay on real addresses:
//!
//! - **Peer-to-peer / crypto groups** — a torrent client or a full node talks to
//!   thousands of bare IP peers that were never resolved by name, so a fake
//!   address would only add a relay hop it cannot benefit from (and the same
//!   groups are already kept out of the FCrDNS learner for the mirror-image
//!   reason). See [`AppGroupKind::excluded_from_fake_ip`].
//! - **Names that are not public destinations** — literals, single-label
//!   intranet names, `localhost`, mDNS/reverse zones. Handing those a fake
//!   address would break local discovery for no routing benefit.
//!
//! The verdict carries its reason so the GUI's explain surface can answer "why
//! did this host NOT get a virtual address?" without re-deriving the policy.

use std::net::IpAddr;

use serde::Serialize;

use crate::app_group_discovery::AppGroupKind;
use crate::hosts_file::normalize_hostname;

/// Suffixes that are never given a fake address: local/discovery/reverse zones.
/// Matched on the normalized hostname, either exactly (`localhost`) or as a
/// dot-suffix (`printer.local`).
const NON_ROUTABLE_SUFFIXES: &[&str] = &[
    "localhost",
    "local",
    "localdomain",
    "home.arpa",
    "internal",
    "intranet",
    "lan",
    "onion",
    "in-addr.arpa",
    "ip6.arpa",
];

/// Why a hostname keeps its real address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RealIpReason {
    /// The user has not enabled fake-IP (the default).
    FeatureDisabled,
    /// The traffic belongs to an application group excluded by design
    /// (peer-to-peer / crypto).
    ExcludedAppGroup,
    /// The user listed this host as an exclusion.
    ExcludedHost,
    /// The query is for an address literal, not a name.
    LiteralAddress,
    /// A local/discovery/reverse name that has no public destination.
    NonRoutableName,
}

/// Outcome of the scope decision for one hostname.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case", tag = "verdict", content = "reason")]
pub enum FakeIpVerdict {
    /// Answer with a fake address from the pool.
    FakeIp,
    /// Answer with the real address; the reason is user-facing.
    RealIp(RealIpReason),
}

impl FakeIpVerdict {
    #[must_use]
    pub fn is_fake_ip(self) -> bool {
        matches!(self, Self::FakeIp)
    }

    /// The reason a real address is used, or `None` when the verdict is fake-IP.
    #[must_use]
    pub fn real_ip_reason(self) -> Option<RealIpReason> {
        match self {
            Self::FakeIp => None,
            Self::RealIp(reason) => Some(reason),
        }
    }
}

/// The fake-IP scope: the feature toggle plus the user's host exclusions.
///
/// Default is **disabled** — fake-IP changes how names resolve, so it is opt-in
/// (the kill-switch checkbox), matching the product decision that Modes A and B
/// both work with and without it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FakeIpScope {
    enabled: bool,
    excluded_hosts: Vec<String>,
}

impl FakeIpScope {
    /// Fake-IP off — every hostname keeps its real address.
    #[must_use]
    pub fn disabled() -> Self {
        Self::default()
    }

    /// Fake-IP on, with the user's host exclusions. Each exclusion matches the
    /// host itself and everything under it (`example.com` also excludes
    /// `api.example.com`); empty entries are dropped.
    pub fn enabled<I, S>(excluded_hosts: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut hosts: Vec<String> = excluded_hosts
            .into_iter()
            .map(|h| normalize_hostname(h.as_ref()))
            .filter(|h| !h.is_empty())
            .collect();
        hosts.sort();
        hosts.dedup();
        Self {
            enabled: true,
            excluded_hosts: hosts,
        }
    }

    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    #[must_use]
    pub fn excluded_hosts(&self) -> &[String] {
        &self.excluded_hosts
    }

    /// Decide whether `host` gets a fake address. `app_group` is the application
    /// group the requesting process belongs to when it is known (`None` for a
    /// plain DNS query with no attributable process).
    #[must_use]
    pub fn decide(&self, host: &str, app_group: Option<AppGroupKind>) -> FakeIpVerdict {
        if !self.enabled {
            return FakeIpVerdict::RealIp(RealIpReason::FeatureDisabled);
        }
        if app_group.is_some_and(AppGroupKind::excluded_from_fake_ip) {
            return FakeIpVerdict::RealIp(RealIpReason::ExcludedAppGroup);
        }
        let key = normalize_hostname(host);
        if key.parse::<IpAddr>().is_ok() {
            return FakeIpVerdict::RealIp(RealIpReason::LiteralAddress);
        }
        if is_non_routable_name(&key) {
            return FakeIpVerdict::RealIp(RealIpReason::NonRoutableName);
        }
        if self
            .excluded_hosts
            .iter()
            .any(|pattern| host_matches(pattern, &key))
        {
            return FakeIpVerdict::RealIp(RealIpReason::ExcludedHost);
        }
        FakeIpVerdict::FakeIp
    }
}

/// True when `host` is `pattern` or a subdomain of it. Both sides are expected
/// to be normalized already.
#[must_use]
pub fn host_matches(pattern: &str, host: &str) -> bool {
    if pattern.is_empty() || host.is_empty() {
        return false;
    }
    host == pattern || host.ends_with(&format!(".{pattern}"))
}

/// True for names with no public destination: empty, single-label (intranet
/// short names), and the local/discovery/reverse zones.
#[must_use]
pub fn is_non_routable_name(host: &str) -> bool {
    let key = normalize_hostname(host);
    if key.is_empty() {
        return true;
    }
    if NON_ROUTABLE_SUFFIXES
        .iter()
        .any(|suffix| host_matches(suffix, &key))
    {
        return true;
    }
    // A single label ("printserver", "wpad") is resolved by the local network,
    // never by a public authority — routing it per-hostname buys nothing.
    !key.contains('.')
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn disabled_by_default_and_every_host_keeps_its_real_address() {
        let scope = FakeIpScope::default();
        assert!(!scope.is_enabled());
        assert_eq!(
            scope.decide("chatgpt.com", None),
            FakeIpVerdict::RealIp(RealIpReason::FeatureDisabled)
        );
        assert_eq!(FakeIpScope::disabled(), FakeIpScope::default());
    }

    #[test]
    fn enabled_scope_covers_ordinary_hosts() {
        let scope = FakeIpScope::enabled(Vec::<String>::new());
        assert_eq!(scope.decide("chatgpt.com", None), FakeIpVerdict::FakeIp);
        assert!(scope.decide("Www.Google.com.", None).is_fake_ip());
        // A hypervisor's guest traffic is explicitly in scope.
        assert!(scope
            .decide("example.com", Some(AppGroupKind::Hypervisor))
            .is_fake_ip());
    }

    #[test]
    fn peer_to_peer_groups_keep_real_addresses() {
        let scope = FakeIpScope::enabled(Vec::<String>::new());
        for kind in [
            AppGroupKind::BitTorrent,
            AppGroupKind::P2pFileSharing,
            AppGroupKind::CryptoNode,
        ] {
            assert_eq!(
                scope.decide("tracker.example.com", Some(kind)),
                FakeIpVerdict::RealIp(RealIpReason::ExcludedAppGroup),
                "{kind:?} must not be steered through fake addresses"
            );
        }
    }

    #[test]
    fn user_exclusions_cover_subdomains_and_normalize() {
        let scope = FakeIpScope::enabled(["Example.COM.", "  ", "example.com"]);
        assert_eq!(scope.excluded_hosts(), &["example.com".to_string()]);
        assert_eq!(
            scope.decide("api.example.com", None),
            FakeIpVerdict::RealIp(RealIpReason::ExcludedHost)
        );
        assert_eq!(
            scope.decide("example.com", None),
            FakeIpVerdict::RealIp(RealIpReason::ExcludedHost)
        );
        // A different host that merely ends with the same letters is unaffected.
        assert!(scope.decide("notexample.com", None).is_fake_ip());
    }

    #[test]
    fn literals_and_local_names_keep_real_addresses() {
        let scope = FakeIpScope::enabled(Vec::<String>::new());
        assert_eq!(
            scope.decide("142.250.74.78", None),
            FakeIpVerdict::RealIp(RealIpReason::LiteralAddress)
        );
        assert_eq!(
            scope.decide("2606:4700::1111", None),
            FakeIpVerdict::RealIp(RealIpReason::LiteralAddress)
        );
        for host in [
            "localhost",
            "printer.local",
            "wpad",
            "nas.lan",
            "1.0.168.192.in-addr.arpa",
            "router.home.arpa",
        ] {
            assert_eq!(
                scope.decide(host, None),
                FakeIpVerdict::RealIp(RealIpReason::NonRoutableName),
                "{host} must not get a fake address"
            );
        }
    }

    #[test]
    fn verdict_serializes_with_its_reason() {
        let json = serde_json::to_string(&FakeIpVerdict::RealIp(RealIpReason::ExcludedAppGroup))
            .expect("serialize verdict");
        assert_eq!(
            json,
            r#"{"verdict":"real-ip","reason":"excluded-app-group"}"#
        );
        let json = serde_json::to_string(&FakeIpVerdict::FakeIp).expect("serialize verdict");
        assert_eq!(json, r#"{"verdict":"fake-ip"}"#);
    }
}
