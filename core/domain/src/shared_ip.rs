//! Shared-IP policy.
//!
//! How NetRuleRouter treats an IPv4 address that a **secondary** (VPN) rule
//! routes but that is SHARED with other, non-secondary hostnames (the classic
//! shared-CDN case: `chatgpt.com` and `www.whatismyip.com` both on
//! `8.6.112.0`). IP-level routing cannot separate two hostnames on one address,
//! so committing a shared IP to the secondary link drags the innocent
//! co-tenants onto the secondary link (collateral), while NOT committing it leaks the
//! ruled host onto the primary. This enum lets the user pick the trade-off.
//!
//! Pure and deterministic. The census counts are injected by the caller:
//! service-runtime derives `rule_on_ip` / `total_rule` from the secondary rules
//! × FQDN cache, and `direct_on_ip` from the observed shared-IP census. A
//! separating solution (per-hostname routing on a shared IP) needs SNI/L7
//! inspection and is a Pro feature.

use std::fmt;

/// User-selectable policy for committing a SHARED secondary IP to the secondary
/// (VPN) link. Ordered aggressive→conservative is *not* the discriminant order;
/// see [`SharedIpPolicy::as_code`] for the stable storage mapping.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SharedIpPolicy {
    /// б1 (default) — commit a shared IP only when the secondary-rule hostnames
    /// are the majority of the hostnames observed on it (`rule_on_ip >
    /// direct_on_ip`). Balanced: protects the innocent majority, still covers
    /// an IP that is mostly "ours".
    #[default]
    MajorityOfIp,
    /// б2 — commit a shared IP only when it carries the majority of ALL your
    /// secondary-rule hostnames (`rule_on_ip * 2 > total_rule`). Conservative:
    /// only takes a shared IP that is central to your whole rule set.
    MajorityOfRules,
    /// б3 — commit a shared IP whenever ANY secondary-rule hostname resolves to
    /// it. Aggressive: guarantees the ruled host is covered, accepts all
    /// collateral. This is the historic behaviour from before the setting
    /// existed.
    AnyRuleDomain,
}

impl SharedIpPolicy {
    /// Wire/locale slug (kebab-case, stable). Used by the IPC DTO and GUI combo.
    pub const fn as_slug(self) -> &'static str {
        match self {
            Self::MajorityOfIp => "majority-of-ip",
            Self::MajorityOfRules => "majority-of-rules",
            Self::AnyRuleDomain => "any-rule-domain",
        }
    }

    /// Parse a wire slug. Unknown → `None` (caller falls back to the default).
    pub fn from_slug(slug: &str) -> Option<Self> {
        match slug {
            "majority-of-ip" => Some(Self::MajorityOfIp),
            "majority-of-rules" => Some(Self::MajorityOfRules),
            "any-rule-domain" => Some(Self::AnyRuleDomain),
            _ => None,
        }
    }

    /// Stable small-int for compact SQLite storage. APPEND-ONLY: a new variant
    /// gets the next code, existing codes never change (keeps stored rows valid
    /// across releases). Kept in sync with [`SharedIpPolicy::from_code`].
    pub const fn as_code(self) -> i64 {
        match self {
            Self::MajorityOfIp => 0,
            Self::MajorityOfRules => 1,
            Self::AnyRuleDomain => 2,
        }
    }

    /// Inverse of [`SharedIpPolicy::as_code`]. Unknown → `None`.
    pub fn from_code(code: i64) -> Option<Self> {
        match code {
            0 => Some(Self::MajorityOfIp),
            1 => Some(Self::MajorityOfRules),
            2 => Some(Self::AnyRuleDomain),
            _ => None,
        }
    }
}

impl fmt::Display for SharedIpPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_slug())
    }
}

/// Decide whether a secondary IP should be committed to the secondary (VPN)
/// link under `policy`.
///
/// - `rule_on_ip`: distinct secondary-rule hostnames resolving to this IP (≥ 1
///   by construction — the IP is only a candidate because a secondary rule
///   resolved to it).
/// - `direct_on_ip`: distinct NON-secondary (innocent / primary-rule) hostnames
///   observed sharing this IP. `0` ⇒ the IP is not actually shared.
/// - `total_rule`: distinct secondary-rule hostnames across ALL IPs.
///
/// A non-shared IP (`direct_on_ip == 0`) is ALWAYS committed — the policy only
/// governs genuinely shared addresses, so normal single-tenant routing is
/// unaffected by every policy (including the conservative ones).
pub fn commit_shared_ip(
    policy: SharedIpPolicy,
    rule_on_ip: u32,
    direct_on_ip: u32,
    total_rule: u32,
) -> bool {
    if direct_on_ip == 0 {
        // Not shared → normal routing; every policy commits.
        return true;
    }
    match policy {
        SharedIpPolicy::AnyRuleDomain => true,
        SharedIpPolicy::MajorityOfIp => rule_on_ip > direct_on_ip,
        SharedIpPolicy::MajorityOfRules => rule_on_ip.saturating_mul(2) > total_rule,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slug_and_code_round_trip() {
        for p in [
            SharedIpPolicy::MajorityOfIp,
            SharedIpPolicy::MajorityOfRules,
            SharedIpPolicy::AnyRuleDomain,
        ] {
            assert_eq!(SharedIpPolicy::from_slug(p.as_slug()), Some(p));
            assert_eq!(SharedIpPolicy::from_code(p.as_code()), Some(p));
        }
        assert_eq!(SharedIpPolicy::from_slug("nope"), None);
        assert_eq!(SharedIpPolicy::from_code(99), None);
    }

    #[test]
    fn default_is_majority_of_ip() {
        assert_eq!(SharedIpPolicy::default(), SharedIpPolicy::MajorityOfIp);
    }

    #[test]
    fn non_shared_ip_always_committed() {
        // direct_on_ip == 0 → committed regardless of policy or rule counts.
        for p in [
            SharedIpPolicy::MajorityOfIp,
            SharedIpPolicy::MajorityOfRules,
            SharedIpPolicy::AnyRuleDomain,
        ] {
            assert!(commit_shared_ip(p, 1, 0, 100));
        }
    }

    #[test]
    fn any_rule_domain_commits_even_when_shared() {
        // б3: 1 rule host, 9 innocents on the IP → still committed.
        assert!(commit_shared_ip(SharedIpPolicy::AnyRuleDomain, 1, 9, 1));
    }

    #[test]
    fn majority_of_ip_needs_rule_hosts_to_dominate_the_ip() {
        // б1: commit only when rule hosts strictly outnumber the innocents.
        assert!(commit_shared_ip(SharedIpPolicy::MajorityOfIp, 3, 2, 3));
        assert!(!commit_shared_ip(SharedIpPolicy::MajorityOfIp, 2, 2, 5)); // tie → not majority
        assert!(!commit_shared_ip(SharedIpPolicy::MajorityOfIp, 1, 9, 1));
    }

    #[test]
    fn majority_of_rules_needs_the_ip_to_hold_most_of_the_rule_set() {
        // б2: on a SHARED ip, commit only if this IP carries > half of all
        // secondary-rule hosts.
        assert!(commit_shared_ip(SharedIpPolicy::MajorityOfRules, 3, 1, 4)); // 3*2=6 > 4
        assert!(!commit_shared_ip(SharedIpPolicy::MajorityOfRules, 1, 1, 10)); // 2 > 10 false
                                                                               // Edge: the IP holds exactly half → not a strict majority.
        assert!(!commit_shared_ip(SharedIpPolicy::MajorityOfRules, 2, 1, 4)); // 4 > 4 false
    }
}
