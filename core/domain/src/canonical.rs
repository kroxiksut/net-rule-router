//! Canonical internal representation of a validated routing configuration.
//!
//! A [`CanonicalProfile`] is the normalized, validated form of an
//! [`ActiveConfiguration`]. It is produced by the validation pipeline in
//! [`crate::validation`] and consumed by the revision system as input to
//! `PolicyRevision`.
//!
//! # Canonical ordering
//!
//! Rules within a [`CanonicalRuleSet`] are stored in a fixed canonical order:
//! `ExactFqdn` first (sorted lexicographically), then `SuffixDomain` (sorted
//! lexicographically), then `Zone` (sorted lexicographically), then `ExactIp`
//! (sorted numerically by 32-bit value), then `Application` (sorted
//! lexicographically by process name). This ensures that two logically
//! equivalent configurations produce the same byte sequence when serialized,
//! and therefore the same SHA-256 content hash.
//!
//! Note: this canonical storage order is fixed for hashing purposes and does
//! **not** reflect the runtime evaluation priority, which is configurable for
//! the Zone vs ExactIp ordering (see `ZonePriorityPolicy`).
//!
//! The rule file on disk stores rules in user-defined display order — canonical
//! ordering is applied only to the internal representation used for hashing and
//! the operational SQLite store.

use core::fmt;
use std::net::Ipv4Addr;

use nrr_shared::RouteRole;

use crate::{RouteBehaviorMode, RouteBinding};

/// Normalized application match pattern.
///
/// `Exact` — lowercase filename, `.exe` suffix guaranteed, path stripped.
/// `Glob`  — lowercase glob pattern, bare `*` rejected at validation time.
///           Runtime matching uses `*` as zero-or-more-chars.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum CanonicalAppPattern {
    /// Exact process filename (e.g. `chrome.exe`).
    Exact(String),
    /// Glob pattern (e.g. `*vpn*.exe`).
    Glob(String),
}

impl CanonicalAppPattern {
    /// Returns the pattern string for display and deduplication.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Exact(s) | Self::Glob(s) => s.as_str(),
        }
    }
}

/// Per-rule enforcement action.
///
/// `Route` (the default) sends matching traffic through the rule's route role
/// (the primary or secondary adapter). `Block` drops matching traffic entirely
/// via a hard WFP `FWP_ACTION_BLOCK` filter and installs no route — for a
/// blocked rule the primary/secondary set membership becomes
/// enforcement-irrelevant.
///
/// This is modeled as a per-rule attribute rather than a [`RouteRole`] variant
/// because a block has no adapter binding and no reachability to probe. The
/// action is intentionally NOT part of the canonical sort key: block and route
/// rules interleave by address so a route rule's canonical bytes stay stable
/// when a sibling rule toggles block.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub enum RuleAction {
    /// Route matching traffic via the rule's route role. Default action.
    #[default]
    Route,
    /// Drop matching traffic with a hard WFP block; install no route.
    Block,
}

impl RuleAction {
    /// Returns `true` for the default [`RuleAction::Route`] action.
    ///
    /// Used by serde `skip_serializing_if` on the wire DTO so route rules
    /// serialize byte-identically to the pre-block format.
    pub fn is_route(&self) -> bool {
        matches!(self, Self::Route)
    }
}

/// Normalized application match condition.
///
/// Produced by the validation pipeline from [`crate::AppMatch`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CanonicalAppMatch {
    /// Normalized match pattern (exact name or glob).
    pub pattern: CanonicalAppPattern,
    /// When `true`, direct child processes are also matched.
    pub include_child_processes: bool,
}

/// Normalized address match condition.
///
/// All domain labels are lowercase, have no trailing dot, and are ASCII
/// (punycode-encoded per IDNA2008 for internationalized names).
/// IPv6 addresses are never present — the Free edition accepts only IPv4.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum CanonicalAddressMatch {
    /// Matches the exact FQDN only (runtime priority tier 1 — highest).
    /// Normalized: lowercase, no trailing dot, punycode for IDN.
    ExactFqdn(String),
    /// Matches the apex `label` itself and any subdomain of it at any depth
    /// (runtime priority tier 2). Stored without `*.` prefix; display renders
    /// as `*.label`.
    ///
    /// Apex coverage costs no expressiveness: `ExactFqdn` is a strictly
    /// higher tier, so "subdomains here, apex elsewhere" is still
    /// expressible by adding an exact rule for the apex. See
    /// [`match_suffix_domain`](crate::decision_matching::match_suffix_domain).
    SuffixDomain(String),
    /// Matches all hosts in a TLD or internal domain zone (runtime priority tier 3).
    ///
    /// Zone name is the suffix label — e.g. `ru`, `com`, `intra`, `corp`. Normalized:
    /// lowercase, `*.` prefix stripped if present, punycode for IDN zones
    /// (`рф` is stored as `xn--p1ai`, matching both the GUI's `QUrl::toAce`
    /// output and the punycode hostnames seen at decision time).
    /// A hostname matches if it ends with `.{zone_name}`. Zone applies only
    /// when a hostname is available; IP-only traffic bypasses Zone in Free.
    ///
    /// Runtime priority vs [`CanonicalAddressMatch::ExactIp`] is user-configurable
    /// (default: ExactIp wins). IP subnet zones are a Pro edition feature; Free
    /// supports domain-suffix zones only.
    Zone(String),
    /// Matches exactly one IPv4 address (runtime priority tier 3 by default;
    /// configurable vs [`CanonicalAddressMatch::Zone`]).
    ExactIp(Ipv4Addr),
}

impl CanonicalAddressMatch {
    /// Returns the address as a user-facing string.
    ///
    /// `SuffixDomain` is rendered with `*.` prefix restored.
    pub fn to_display_string(&self) -> String {
        match self {
            Self::ExactFqdn(label) => label.clone(),
            Self::SuffixDomain(label) => format!("*.{label}"),
            Self::Zone(name) => name.clone(),
            Self::ExactIp(addr) => addr.to_string(),
        }
    }

    /// Canonical sort key string used to order rules within the same type group.
    pub(crate) fn sort_key_str(&self) -> String {
        match self {
            Self::ExactFqdn(label) => label.clone(),
            Self::SuffixDomain(label) => label.clone(),
            Self::Zone(name) => name.clone(),
            Self::ExactIp(addr) => format!("{:010}", u32::from(*addr)),
        }
    }
}

impl fmt::Display for CanonicalAddressMatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_display_string())
    }
}

/// A normalized, validated routing rule.
///
/// Guaranteed invariants enforced by the validation pipeline:
/// - At least one of `address_match` or `app_match` is `Some`.
/// - `comment` is trimmed.
/// - All match values are normalized per the rules in [`crate::validation`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalRule {
    /// Stable rule identifier. Preserved unchanged from the source rule.
    pub id: crate::RuleId,
    /// Whether this rule participates in route evaluation.
    pub enabled: bool,
    /// Normalized address condition, if present.
    pub address_match: Option<CanonicalAddressMatch>,
    /// Normalized application condition, if present.
    pub app_match: Option<CanonicalAppMatch>,
    /// Trimmed user comment.
    pub comment: String,
    /// Per-rule enforcement action (route vs. hard block). Defaults to
    /// [`RuleAction::Route`]; not part of the canonical sort key.
    pub action: RuleAction,
    /// Who authored the rule; `None` means the user did. Carried through
    /// validation unchanged and **not** part of the canonical sort key —
    /// provenance must never move a rule within the deterministic order, or
    /// annotating a rule would reshuffle the content hash of its neighbours.
    pub origin: Option<crate::RuleOrigin>,
}

impl CanonicalRule {
    /// Returns the canonical sort key for ordering within a [`CanonicalRuleSet`].
    ///
    /// This is the **canonical storage order** used for deterministic hashing — it
    /// does **not** reflect runtime evaluation priority, which is configurable for
    /// Zone vs ExactIp (see `ZonePriorityPolicy`):
    /// `ExactFqdn(0) < SuffixDomain(1) < Zone(2) < ExactIp(3) < Application(4)`.
    /// Within each group, the match value string is used for lexicographic ordering.
    pub(crate) fn sort_key(&self) -> (u8, String) {
        match &self.address_match {
            Some(m) => {
                let group = match m {
                    CanonicalAddressMatch::ExactFqdn(_) => 0u8,
                    CanonicalAddressMatch::SuffixDomain(_) => 1u8,
                    CanonicalAddressMatch::Zone(_) => 2u8,
                    CanonicalAddressMatch::ExactIp(_) => 3u8,
                };
                (group, m.sort_key_str())
            }
            None => {
                let pattern_str = self
                    .app_match
                    .as_ref()
                    .map(|a| a.pattern.as_str().to_string())
                    .unwrap_or_default();
                (4u8, pattern_str)
            }
        }
    }
}

/// Canonically ordered collection of routing rules for one route role.
///
/// Rules are stored in the fixed canonical order described in the module
/// documentation: ExactFqdn → SuffixDomain → Zone → ExactIp → Application,
/// then lexicographically by value within each group.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CanonicalRuleSet {
    rules: Vec<CanonicalRule>,
}

impl CanonicalRuleSet {
    /// Creates a canonical rule set from an unordered list of validated rules.
    ///
    /// Rules are sorted into canonical order. The input order is not preserved.
    ///
    /// `pub` so `nrr-service-runtime`'s `rules_json_codec::decode` and
    /// `wfp_codegen::generate_filters` can call it, but it remains the only
    /// sanctioned path: rules MUST go through `from_rules` so the
    /// canonical-order invariant cannot be broken by hand-crafting a
    /// `CanonicalRuleSet { rules: ... }` from outside the crate.
    pub fn from_rules(mut rules: Vec<CanonicalRule>) -> Self {
        rules.sort_by_key(|r| r.sort_key());
        Self { rules }
    }

    /// All rules in canonical order.
    pub fn rules(&self) -> &[CanonicalRule] {
        &self.rules
    }

    /// Number of rules in this set.
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// `true` when this set contains no rules.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Expand each `ExactFqdn(d)` rule with a sibling
    /// `SuffixDomain(d)` rule so a bare-domain rule also covers every subdomain,
    /// WITHOUT losing the apex (the `ExactFqdn` rule stays). The sibling copies
    /// the same `app_match`, `action` and `enabled` state (route role is implied
    /// by the set). Idempotent: a domain that already has a `SuffixDomain(d)`
    /// with the same `app_match` is skipped, so it is safe to apply repeatedly.
    ///
    /// Enforcement-only: apply this to the rule book that drives codegen and
    /// seeding, NEVER to the stored / hashed rule book — the canonical hash must
    /// stay computed over the bare rules or the drift detector would diverge.
    fn with_subdomain_coverage(&self) -> CanonicalRuleSet {
        let existing_suffix: std::collections::HashSet<(String, Option<CanonicalAppMatch>)> = self
            .rules
            .iter()
            .filter_map(|r| match &r.address_match {
                Some(CanonicalAddressMatch::SuffixDomain(d)) => {
                    Some((d.clone(), r.app_match.clone()))
                }
                _ => None,
            })
            .collect();
        let mut out = self.rules.clone();
        for r in &self.rules {
            if let Some(CanonicalAddressMatch::ExactFqdn(d)) = &r.address_match {
                if existing_suffix.contains(&(d.clone(), r.app_match.clone())) {
                    continue;
                }
                out.push(CanonicalRule {
                    // Synthetic enforcement-only id; distinct from the apex rule
                    // so the codegen treats them as separate filters/routes.
                    id: crate::RuleId(format!("{}+sub", r.id.0)),
                    enabled: r.enabled,
                    address_match: Some(CanonicalAddressMatch::SuffixDomain(d.clone())),
                    app_match: r.app_match.clone(),
                    comment: r.comment.clone(),
                    action: r.action,
                    origin: None,
                });
            }
        }
        CanonicalRuleSet::from_rules(out)
    }

    /// Number of currently enabled rules.
    pub fn enabled_count(&self) -> usize {
        self.rules.iter().filter(|r| r.enabled).count()
    }
}

/// Canonically ordered rule book covering primary and secondary routes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CanonicalRuleBook {
    /// Rules bound to the primary route, in canonical order.
    pub primary: CanonicalRuleSet,
    /// Rules bound to the secondary route, in canonical order.
    pub secondary: CanonicalRuleSet,
}

impl CanonicalRuleBook {
    /// Returns the canonical rule set for the given route role.
    pub fn set_for(&self, role: RouteRole) -> &CanonicalRuleSet {
        match role {
            RouteRole::Primary => &self.primary,
            RouteRole::Secondary => &self.secondary,
        }
    }

    /// Total rule count across both sets.
    pub fn total_rule_count(&self) -> usize {
        self.primary.len() + self.secondary.len()
    }

    /// Total enabled rule count across both sets.
    pub fn total_enabled_count(&self) -> usize {
        self.primary.enabled_count() + self.secondary.enabled_count()
    }

    /// Return a copy of this book where every bare-domain
    /// (`ExactFqdn`) rule ALSO covers its subdomains (`SuffixDomain`), on both
    /// route sets, keeping the apex. Backs the opt-in "treat a domain as
    /// `domain` + `*.domain`" setting. Enforcement-only (see
    /// [`CanonicalRuleSet::with_subdomain_coverage`]); never feed the result to
    /// the canonical hash. A no-op-ish identity when there are no `ExactFqdn`
    /// rules to expand.
    pub fn with_subdomain_coverage(&self) -> CanonicalRuleBook {
        CanonicalRuleBook {
            primary: self.primary.with_subdomain_coverage(),
            secondary: self.secondary.with_subdomain_coverage(),
        }
    }
}

/// The normalized, validated internal representation of a routing configuration.
///
/// `CanonicalProfile` is the output of the validation pipeline
/// and the input to the revision system. It carries all
/// policy-relevant content in a deterministic, normalized form.
///
/// # Included fields
///
/// - `primary` — confirmed primary route binding (always present; missing
///   primary is a blocking validation error).
/// - `secondary` — optional secondary binding; absent when only the primary
///   route is configured.
/// - `behavior_mode` — default routing behaviour when no rule matches.
/// - `rule_book` — all rules in canonical order with normalized values.
///
/// # Excluded from `CanonicalProfile`
///
/// - **Route display labels** (`route_primary_label`, `route_secondary_label`)
///   are UI preferences stored in `UiPreferences`, not routing policy.
/// - **Rule insertion order** — `CanonicalRuleBook` uses deterministic ordering
///   regardless of the file's display order.
/// - **Import metadata** (source path, import timestamp) — tracked separately
///   by `ImportedArtifact`.
///
/// # SHA-256 content hash
///
/// The hash in `PolicyRevision` is computed over the canonical serialized form:
/// `primary + secondary + behavior_mode + rule_book`. Display labels and import
/// metadata are excluded from the hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalProfile {
    /// Confirmed binding for the primary route. Always present.
    pub primary: RouteBinding,
    /// Binding for the secondary route. `None` when only primary is configured.
    pub secondary: Option<RouteBinding>,
    /// Default routing behaviour when no rule matches.
    pub behavior_mode: RouteBehaviorMode,
    /// All routing rules in canonical order, split by route.
    pub rule_book: CanonicalRuleBook,
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn exact_fqdn_rule(id: &str, label: &str) -> CanonicalRule {
        CanonicalRule {
            id: crate::RuleId(id.to_string()),
            enabled: true,
            address_match: Some(CanonicalAddressMatch::ExactFqdn(label.to_string())),
            app_match: None,
            comment: String::new(),
            action: crate::canonical::RuleAction::Route,
            origin: None,
        }
    }

    fn suffix_rule(id: &str, label: &str) -> CanonicalRule {
        CanonicalRule {
            id: crate::RuleId(id.to_string()),
            enabled: true,
            address_match: Some(CanonicalAddressMatch::SuffixDomain(label.to_string())),
            app_match: None,
            comment: String::new(),
            action: crate::canonical::RuleAction::Route,
            origin: None,
        }
    }

    fn ip_rule(id: &str, addr: Ipv4Addr) -> CanonicalRule {
        CanonicalRule {
            id: crate::RuleId(id.to_string()),
            enabled: true,
            address_match: Some(CanonicalAddressMatch::ExactIp(addr)),
            app_match: None,
            comment: String::new(),
            action: crate::canonical::RuleAction::Route,
            origin: None,
        }
    }

    fn zone_rule(id: &str, zone: &str) -> CanonicalRule {
        CanonicalRule {
            id: crate::RuleId(id.to_string()),
            enabled: true,
            address_match: Some(CanonicalAddressMatch::Zone(zone.to_string())),
            app_match: None,
            comment: String::new(),
            action: crate::canonical::RuleAction::Route,
            origin: None,
        }
    }

    fn app_rule(id: &str, process: &str) -> CanonicalRule {
        CanonicalRule {
            id: crate::RuleId(id.to_string()),
            enabled: true,
            address_match: None,
            app_match: Some(CanonicalAppMatch {
                pattern: CanonicalAppPattern::Exact(process.to_string()),
                include_child_processes: false,
            }),
            comment: String::new(),
            action: crate::canonical::RuleAction::Route,
            origin: None,
        }
    }

    #[test]
    fn canonical_rule_set_ordering_zone_between_suffix_and_ip() {
        let rules = vec![
            ip_rule("r-4", Ipv4Addr::new(10, 0, 0, 1)),
            zone_rule("r-3", "intra"),
            suffix_rule("r-2", "example.com"),
            exact_fqdn_rule("r-1", "example.com"),
        ];
        let set = CanonicalRuleSet::from_rules(rules);
        let order: Vec<&str> = set.rules().iter().map(|r| r.id.as_str()).collect();
        assert_eq!(order, ["r-1", "r-2", "r-3", "r-4"]);
    }

    #[test]
    fn canonical_rule_set_ordering_exact_fqdn_before_suffix_before_ip_before_app() {
        let rules = vec![
            app_rule("r-4", "chrome.exe"),
            ip_rule("r-3", Ipv4Addr::new(10, 0, 0, 1)),
            suffix_rule("r-2", "example.com"),
            exact_fqdn_rule("r-1", "example.com"),
        ];
        let set = CanonicalRuleSet::from_rules(rules);
        let order: Vec<&str> = set.rules().iter().map(|r| r.id.as_str()).collect();
        assert_eq!(order, ["r-1", "r-2", "r-3", "r-4"]);
    }

    #[test]
    fn canonical_rule_set_ordering_exact_fqdns_alphabetical() {
        let rules = vec![
            exact_fqdn_rule("r-z", "z.example.com"),
            exact_fqdn_rule("r-a", "a.example.com"),
            exact_fqdn_rule("r-m", "example.com"),
        ];
        let set = CanonicalRuleSet::from_rules(rules);
        let labels: Vec<String> = set
            .rules()
            .iter()
            .map(|r| match r.address_match.as_ref() {
                Some(CanonicalAddressMatch::ExactFqdn(l)) => l.clone(),
                _ => String::new(),
            })
            .collect();
        assert_eq!(labels, ["a.example.com", "example.com", "z.example.com"]);
    }

    #[test]
    fn canonical_rule_set_ordering_ips_numeric() {
        let rules = vec![
            ip_rule("r-3", Ipv4Addr::new(192, 168, 1, 1)),
            ip_rule("r-1", Ipv4Addr::new(10, 0, 0, 1)),
            ip_rule("r-2", Ipv4Addr::new(172, 16, 0, 1)),
        ];
        let set = CanonicalRuleSet::from_rules(rules);
        let addrs: Vec<String> = set
            .rules()
            .iter()
            .map(|r| match r.address_match.as_ref() {
                Some(CanonicalAddressMatch::ExactIp(a)) => a.to_string(),
                _ => String::new(),
            })
            .collect();
        assert_eq!(addrs, ["10.0.0.1", "172.16.0.1", "192.168.1.1"]);
    }

    #[test]
    fn canonical_rule_set_different_insertion_order_same_result() {
        let rules_a = vec![
            exact_fqdn_rule("r-1", "example.com"),
            exact_fqdn_rule("r-2", "api.example.com"),
            ip_rule("r-3", Ipv4Addr::new(1, 1, 1, 1)),
        ];
        let rules_b = vec![
            ip_rule("r-3", Ipv4Addr::new(1, 1, 1, 1)),
            exact_fqdn_rule("r-2", "api.example.com"),
            exact_fqdn_rule("r-1", "example.com"),
        ];
        assert_eq!(
            CanonicalRuleSet::from_rules(rules_a),
            CanonicalRuleSet::from_rules(rules_b),
        );
    }

    #[test]
    fn canonical_rule_set_len_and_enabled_count() {
        let rules = vec![
            CanonicalRule {
                id: crate::RuleId("r-1".to_string()),
                enabled: true,
                address_match: Some(CanonicalAddressMatch::ExactFqdn("a.com".to_string())),
                app_match: None,
                comment: String::new(),
                action: crate::canonical::RuleAction::Route,
                origin: None,
            },
            CanonicalRule {
                id: crate::RuleId("r-2".to_string()),
                enabled: false,
                address_match: Some(CanonicalAddressMatch::ExactFqdn("b.com".to_string())),
                app_match: None,
                comment: String::new(),
                action: crate::canonical::RuleAction::Route,
                origin: None,
            },
        ];
        let set = CanonicalRuleSet::from_rules(rules);
        assert_eq!(set.len(), 2);
        assert_eq!(set.enabled_count(), 1);
        assert!(!set.is_empty());
    }

    #[test]
    fn canonical_address_match_display() {
        let exact = CanonicalAddressMatch::ExactFqdn("example.com".to_string());
        assert_eq!(exact.to_display_string(), "example.com");

        let suffix = CanonicalAddressMatch::SuffixDomain("example.com".to_string());
        assert_eq!(suffix.to_display_string(), "*.example.com");

        let ip = CanonicalAddressMatch::ExactIp(Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(ip.to_display_string(), "1.2.3.4");
    }

    // ── subdomain-coverage expansion ──────────────────────────────────────────

    #[test]
    fn subdomain_coverage_adds_suffix_and_keeps_apex() {
        let book = CanonicalRuleBook {
            primary: CanonicalRuleSet::default(),
            secondary: CanonicalRuleSet::from_rules(vec![exact_fqdn_rule("r1", "whatismyip.com")]),
        };
        let expanded = book.with_subdomain_coverage();
        let sec = expanded.secondary.rules();
        assert!(
            sec.iter().any(|r| matches!(
                &r.address_match,
                Some(CanonicalAddressMatch::ExactFqdn(d)) if d == "whatismyip.com"
            )),
            "apex ExactFqdn must be preserved",
        );
        assert!(
            sec.iter().any(|r| matches!(
                &r.address_match,
                Some(CanonicalAddressMatch::SuffixDomain(d)) if d == "whatismyip.com"
            )),
            "a SuffixDomain sibling must be added",
        );
        assert_eq!(sec.len(), 2, "exactly apex + one subdomain sibling");
    }

    #[test]
    fn subdomain_coverage_is_idempotent_and_skips_existing_suffix() {
        let set = CanonicalRuleSet::from_rules(vec![
            exact_fqdn_rule("r1", "example.com"),
            suffix_rule("r2", "example.com"),
        ]);
        let book = CanonicalRuleBook {
            primary: CanonicalRuleSet::default(),
            secondary: set,
        };
        let once = book.with_subdomain_coverage();
        assert_eq!(
            once.secondary.rules().len(),
            2,
            "already-covered domain gains no duplicate",
        );
        let twice = once.with_subdomain_coverage();
        assert_eq!(twice.secondary.rules().len(), 2, "idempotent");
    }

    #[test]
    fn subdomain_coverage_leaves_non_fqdn_rules_untouched() {
        let set = CanonicalRuleSet::from_rules(vec![
            zone_rule("z", "ru"),
            ip_rule("i", Ipv4Addr::new(1, 2, 3, 4)),
            app_rule("a", "chrome.exe"),
        ]);
        let book = CanonicalRuleBook {
            primary: set,
            secondary: CanonicalRuleSet::default(),
        };
        let expanded = book.with_subdomain_coverage();
        assert_eq!(
            expanded.primary.rules().len(),
            3,
            "zone / ip / app rules gain no subdomain sibling",
        );
    }

    #[test]
    fn subdomain_coverage_preserves_app_match_and_action() {
        let mut r = exact_fqdn_rule("r1", "example.com");
        r.action = crate::canonical::RuleAction::Block;
        r.app_match = Some(CanonicalAppMatch {
            pattern: CanonicalAppPattern::Exact("chrome.exe".to_string()),
            include_child_processes: false,
        });
        let book = CanonicalRuleBook {
            primary: CanonicalRuleSet::default(),
            secondary: CanonicalRuleSet::from_rules(vec![r]),
        };
        let expanded = book.with_subdomain_coverage();
        let sibling = expanded
            .secondary
            .rules()
            .iter()
            .find(|r| {
                matches!(
                    &r.address_match,
                    Some(CanonicalAddressMatch::SuffixDomain(_))
                )
            })
            .expect("suffix sibling exists");
        assert_eq!(
            sibling.action,
            crate::canonical::RuleAction::Block,
            "action copied to the sibling",
        );
        assert!(
            sibling.app_match.is_some(),
            "app_match copied to the sibling"
        );
    }
}
