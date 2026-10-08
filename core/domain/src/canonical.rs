//! Canonical internal representation of a validated routing configuration.
//!
//! A [`CanonicalProfile`] is the normalized, validated form of an
//! [`ActiveConfiguration`]. It is produced by the validation pipeline in
//! [`crate::validation`] and consumed by the review diff
//! ([`crate::review::compute_diff`]).
//!
//! # Canonical ordering
//!
//! Rules within a [`CanonicalRuleSet`] are stored in a fixed canonical order:
//! `ExactFqdn` first (sorted lexicographically), then `SuffixDomain` (sorted
//! lexicographically), then `Zone` (sorted lexicographically), then `ExactIp`
//! (sorted numerically), then `Application` (sorted lexicographically by
//! process name), then `Subnet` and `IpRange` (sorted numerically; they sort
//! after the older kinds so no stored ordering moves). Rules sharing a match value are then
//! ordered by every remaining field, so the order is total: two equal books
//! produce the same byte sequence when serialized, and therefore the same
//! SHA-256 content hash, whatever order they arrived in.
//!
//! Note: this canonical storage order is fixed for hashing purposes and does
//! **not** reflect the runtime evaluation priority, which is configurable for
//! the Zone vs ExactIp ordering (see `ZonePriorityPolicy`).
//!
//! The rule file on disk stores rules in user-defined display order — canonical
//! ordering is applied only to the internal representation used for hashing and
//! the operational SQLite store.

use core::fmt;
use std::net::IpAddr;

use nrr_shared::ip_block::{IpBlock, IpRange};
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
/// action only breaks ties between rules with the same match: block and route
/// rules still interleave by address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub enum RuleAction {
    /// Route matching traffic via the rule's route role. Default action.
    #[default]
    Route,
    /// Drop matching traffic with a hard WFP block; install no route.
    Block,
    /// Written in the secondary set as `?host`: routed via the PRIMARY route
    /// until the service confirms the primary cannot reach the host, then
    /// rewritten to [`Self::Route`]. Enforcement sees it only as a primary
    /// `Route` (see `CanonicalRuleBook::with_verify_primary_effective`).
    VerifyPrimary,
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
    /// (default: ExactIp wins). IP subnet zones are not supported; Free
    /// supports domain-suffix zones only.
    Zone(String),
    /// Matches exactly one address of either family (runtime priority tier 3 by default;
    /// configurable vs [`CanonicalAddressMatch::Zone`]).
    ExactIp(IpAddr),
    /// Matches every address of one network. Within the address tier a longer
    /// prefix beats a shorter one, and an exact address beats any network.
    Subnet(IpBlock),
    /// Matches an inclusive address range. Kept as written for display and the
    /// rules file; every consumer reads its [`IpRange::blocks`]. Boxed: ranges
    /// are rare, and inline they would grow every rule in memory.
    IpRange(Box<IpRange>),
}

impl CanonicalAddressMatch {
    pub fn ip_range(range: IpRange) -> Self {
        Self::IpRange(Box::new(range))
    }

    /// Returns the address as a user-facing string.
    ///
    /// `SuffixDomain` is rendered with `*.` prefix restored.
    pub fn to_display_string(&self) -> String {
        match self {
            Self::ExactFqdn(label) => label.clone(),
            Self::SuffixDomain(label) => format!("*.{label}"),
            Self::Zone(name) => name.clone(),
            Self::ExactIp(addr) => addr.to_string(),
            Self::Subnet(block) => block.to_string(),
            Self::IpRange(range) => range.to_string(),
        }
    }

    /// The networks the rule names, when it names addresses by network: one
    /// for a subnet, the decomposition for a range.
    pub fn ip_blocks(&self) -> Option<&[IpBlock]> {
        match self {
            Self::Subnet(block) => Some(std::slice::from_ref(block)),
            Self::IpRange(range) => Some(range.blocks()),
            _ => None,
        }
    }

    /// Canonical sort key string used to order rules within the same type group.
    pub(crate) fn sort_key_str(&self) -> String {
        match self {
            Self::ExactFqdn(label) => label.clone(),
            Self::SuffixDomain(label) => label.clone(),
            Self::Zone(name) => name.clone(),
            // v4 keys keep their historic form, so stored orderings do not
            // move; a v6 key sorts after every v4 one.
            Self::ExactIp(IpAddr::V4(addr)) => format!("{:010}", u32::from(*addr)),
            Self::ExactIp(IpAddr::V6(addr)) => format!("v6:{:032x}", u128::from(*addr)),
            Self::Subnet(block) => {
                format!("{}/{:03}", ip_sort_key(block.network()), block.prefix_len())
            }
            Self::IpRange(range) => {
                format!(
                    "{}-{}",
                    ip_sort_key(range.first()),
                    ip_sort_key(range.last())
                )
            }
        }
    }
}

fn ip_sort_key(addr: IpAddr) -> String {
    match addr {
        IpAddr::V4(v4) => format!("{:010}", u32::from(v4)),
        IpAddr::V6(v6) => format!("v6:{:032x}", u128::from(v6)),
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
    /// [`RuleAction::Route`].
    pub action: RuleAction,
    /// Who authored the rule; `None` means the user did. Carried through
    /// validation unchanged, and the last tie-breaker of the canonical order:
    /// it only decides between rules identical in everything else.
    pub origin: Option<crate::RuleOrigin>,
}

impl CanonicalRule {
    /// Returns the canonical sort key for ordering within a [`CanonicalRuleSet`].
    ///
    /// This is the **canonical storage order** used for deterministic hashing — it
    /// does **not** reflect runtime evaluation priority, which is configurable for
    /// Zone vs ExactIp (see `ZonePriorityPolicy`):
    /// `ExactFqdn(0) < SuffixDomain(1) < Zone(2) < ExactIp(3) < Application(4)
    /// < Subnet(5) < IpRange(6)`.
    /// Within each group, the match value string is used for lexicographic
    /// ordering. Not total on its own — [`CanonicalRuleSet::from_rules`] adds
    /// the tie-breaker.
    pub(crate) fn sort_key(&self) -> (u8, String) {
        match &self.address_match {
            Some(m) => {
                let group = match m {
                    CanonicalAddressMatch::ExactFqdn(_) => 0u8,
                    CanonicalAddressMatch::SuffixDomain(_) => 1u8,
                    CanonicalAddressMatch::Zone(_) => 2u8,
                    CanonicalAddressMatch::ExactIp(_) => 3u8,
                    CanonicalAddressMatch::Subnet(_) => 5u8,
                    CanonicalAddressMatch::IpRange(_) => 6u8,
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

    /// Orders two rules [`sort_key`](Self::sort_key) cannot tell apart.
    ///
    /// Total over every field the canonical bytes carry: rules equal here
    /// serialize identically, so no tie is left to input order — which is what
    /// made the same book, re-sorted in the GUI table, hash as a new revision.
    fn tie_break(&self, other: &Self) -> core::cmp::Ordering {
        fn app(rule: &CanonicalRule) -> Option<(u8, &str, bool)> {
            rule.app_match.as_ref().map(|m| {
                let kind = match m.pattern {
                    CanonicalAppPattern::Exact(_) => 0u8,
                    CanonicalAppPattern::Glob(_) => 1u8,
                };
                (kind, m.pattern.as_str(), m.include_child_processes)
            })
        }
        fn action(rule: &CanonicalRule) -> u8 {
            match rule.action {
                RuleAction::Route => 0,
                RuleAction::Block => 1,
                RuleAction::VerifyPrimary => 2,
            }
        }
        fn origin(rule: &CanonicalRule) -> Option<(&str, &str, &str)> {
            rule.origin.as_ref().map(|o| match o {
                crate::RuleOrigin::Auto {
                    reason,
                    anchor,
                    added,
                } => (reason.as_slug(), anchor.as_str(), added.as_str()),
            })
        }
        app(self)
            .cmp(&app(other))
            .then_with(|| action(self).cmp(&action(other)))
            .then_with(|| self.enabled.cmp(&other.enabled))
            .then_with(|| self.id.0.cmp(&other.id.0))
            .then_with(|| self.comment.cmp(&other.comment))
            .then_with(|| origin(self).cmp(&origin(other)))
    }
}

/// Canonically ordered collection of routing rules for one route role.
///
/// Rules are stored in the fixed canonical order described in the module
/// documentation: ExactFqdn → SuffixDomain → Zone → ExactIp → Application →
/// Subnet → IpRange,
/// then lexicographically by value within each group, then by the remaining
/// fields.
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
    pub fn from_rules(rules: Vec<CanonicalRule>) -> Self {
        // The primary key allocates, so it is built once per rule rather than
        // once per comparison.
        let mut keyed: Vec<((u8, String), CanonicalRule)> =
            rules.into_iter().map(|r| (r.sort_key(), r)).collect();
        // Total order, so stability buys nothing: equal rules are identical.
        keyed.sort_unstable_by(|(ka, a), (kb, b)| ka.cmp(kb).then_with(|| a.tie_break(b)));
        Self {
            rules: keyed.into_iter().map(|(_, r)| r).collect(),
        }
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

    /// The inverse of [`Self::with_subdomain_coverage`]: drops the synthetic
    /// `<id>+sub` twins of exact rules. `None` when there is none. A twin that
    /// differs from what its apex derives was edited as a rule in the list, so
    /// it is the user's and stays.
    fn without_subdomain_twins(&self) -> Option<CanonicalRuleSet> {
        let is_twin = |r: &CanonicalRule| {
            let (Some(apex_id), Some(CanonicalAddressMatch::SuffixDomain(d))) =
                (r.id.0.strip_suffix("+sub"), &r.address_match)
            else {
                return false;
            };
            self.rules.iter().any(|apex| {
                apex.id.0 == apex_id
                    && matches!(&apex.address_match, Some(CanonicalAddressMatch::ExactFqdn(a)) if a == d)
                    && apex.app_match == r.app_match
                    && apex.enabled == r.enabled
                    && apex.action == r.action
                    && apex.comment == r.comment
                    && r.origin.is_none()
            })
        };
        if !self.rules.iter().any(is_twin) {
            return None;
        }
        let kept = self.rules.iter().filter(|r| !is_twin(r)).cloned().collect();
        Some(CanonicalRuleSet::from_rules(kept))
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

    /// The book as enforcement must see it: a `?host` rule is "primary until
    /// proven otherwise", so every [`RuleAction::VerifyPrimary`] rule becomes a
    /// primary `Route`. Enforcement-only, like [`Self::with_subdomain_coverage`]
    /// and applied before it; never stored, hashed or written back.
    pub fn with_verify_primary_effective(&self) -> CanonicalRuleBook {
        let is_verify = |r: &CanonicalRule| r.action == RuleAction::VerifyPrimary;
        if !self
            .primary
            .rules
            .iter()
            .chain(&self.secondary.rules)
            .any(is_verify)
        {
            return self.clone();
        }
        let as_route = |r: &CanonicalRule| {
            if is_verify(r) {
                CanonicalRule {
                    action: RuleAction::Route,
                    ..r.clone()
                }
            } else {
                r.clone()
            }
        };
        let primary = self
            .primary
            .rules
            .iter()
            .chain(self.secondary.rules.iter().filter(|r| is_verify(r)))
            .map(as_route)
            .collect();
        let secondary = self
            .secondary
            .rules
            .iter()
            .filter(|r| !is_verify(r))
            .cloned()
            .collect();
        CanonicalRuleBook {
            primary: CanonicalRuleSet::from_rules(primary),
            secondary: CanonicalRuleSet::from_rules(secondary),
        }
    }

    /// This book without the twins [`Self::with_subdomain_coverage`] adds, for
    /// a stored book a writer once saved widened. `None` when it is clean.
    pub fn without_subdomain_twins(&self) -> Option<CanonicalRuleBook> {
        let primary = self.primary.without_subdomain_twins();
        let secondary = self.secondary.without_subdomain_twins();
        if primary.is_none() && secondary.is_none() {
            return None;
        }
        Some(CanonicalRuleBook {
            primary: primary.unwrap_or_else(|| self.primary.clone()),
            secondary: secondary.unwrap_or_else(|| self.secondary.clone()),
        })
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
/// - **Import metadata** (source path, import timestamp) — provenance, not policy.
///
/// # SHA-256 content hash
///
/// A revision's content hash is computed over the canonical serialized form:
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
            address_match: Some(CanonicalAddressMatch::ExactIp(IpAddr::V4(addr))),
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

    /// An IPv6 rule sorts after every IPv4 one, and an IPv4 key keeps the form
    /// stored orderings were built from.
    #[test]
    fn ipv6_rules_sort_after_ipv4_and_the_ipv4_key_does_not_move() {
        let mut v6 = ip_rule("r-6", Ipv4Addr::new(10, 0, 0, 1));
        v6.address_match = Some(CanonicalAddressMatch::ExactIp(
            "2001:db8::1".parse().unwrap(),
        ));
        let set = CanonicalRuleSet::from_rules(vec![v6, ip_rule("r-4", Ipv4Addr::BROADCAST)]);
        let ids: Vec<&str> = set.rules().iter().map(|r| r.id.0.as_str()).collect();
        assert_eq!(ids, ["r-4", "r-6"]);
        assert_eq!(
            CanonicalAddressMatch::ExactIp(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))).sort_key_str(),
            "0167772161"
        );
    }

    #[test]
    fn canonical_rule_set_different_insertion_order_same_result() {
        let rules_a = vec![
            exact_fqdn_rule("r-1", "example.com"),
            exact_fqdn_rule("r-2", "api.example.com"),
            ip_rule("r-3", Ipv4Addr::new(192, 0, 2, 1)),
        ];
        let rules_b = vec![
            ip_rule("r-3", Ipv4Addr::new(192, 0, 2, 1)),
            exact_fqdn_rule("r-2", "api.example.com"),
            exact_fqdn_rule("r-1", "example.com"),
        ];
        assert_eq!(
            CanonicalRuleSet::from_rules(rules_a),
            CanonicalRuleSet::from_rules(rules_b),
        );
    }

    /// Rules sharing one match value used to keep their arrival order, so the
    /// same book re-sorted in the GUI serialized — and hashed — differently.
    #[test]
    fn rules_sharing_a_match_value_order_the_same_from_any_arrival_order() {
        let with_app = |id: &str, app: &str, children: bool| CanonicalRule {
            app_match: Some(CanonicalAppMatch {
                pattern: CanonicalAppPattern::Exact(app.to_string()),
                include_child_processes: children,
            }),
            ..exact_fqdn_rule(id, "example.com")
        };
        let mut glob = with_app("r-g", "chrome.exe", false);
        glob.app_match = Some(CanonicalAppMatch {
            pattern: CanonicalAppPattern::Glob("chrome.exe".to_string()),
            include_child_processes: false,
        });
        let mut blocked = exact_fqdn_rule("r-b", "example.com");
        blocked.action = RuleAction::Block;
        let mut disabled = exact_fqdn_rule("r-d", "example.com");
        disabled.enabled = false;
        let mut commented = exact_fqdn_rule("r-1", "example.com");
        commented.comment = "note".to_string();
        let mut authored = exact_fqdn_rule("r-1", "example.com");
        authored.origin = Some(crate::RuleOrigin::auto(
            nrr_shared::AutoRuleReason::SiteCompanion,
            "anchor.example",
            "2026-09-01",
        ));
        let rules = vec![
            exact_fqdn_rule("r-1", "example.com"),
            exact_fqdn_rule("r-2", "example.com"),
            with_app("r-a", "chrome.exe", false),
            with_app("r-c", "chrome.exe", true),
            glob,
            blocked,
            disabled,
            commented,
            authored,
        ];
        let expected = CanonicalRuleSet::from_rules(rules.clone());
        // Every rotation and its reverse: enough to move each rule to every
        // position without the factorial.
        for shift in 0..rules.len() {
            let mut rotated = rules.clone();
            rotated.rotate_left(shift);
            assert_eq!(CanonicalRuleSet::from_rules(rotated.clone()), expected);
            rotated.reverse();
            assert_eq!(CanonicalRuleSet::from_rules(rotated), expected);
        }
        // Address order still leads; the tie-breaker never reaches across it.
        let set = CanonicalRuleSet::from_rules(vec![
            exact_fqdn_rule("r-z", "b.example"),
            blocked_fqdn("r-a", "a.example"),
        ]);
        let ids: Vec<&str> = set.rules().iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, ["r-a", "r-z"]);
    }

    fn blocked_fqdn(id: &str, label: &str) -> CanonicalRule {
        CanonicalRule {
            action: RuleAction::Block,
            ..exact_fqdn_rule(id, label)
        }
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

        let ip = CanonicalAddressMatch::ExactIp(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 4)));
        assert_eq!(ip.to_display_string(), "192.0.2.4");
    }

    // ── subdomain-coverage expansion ──────────────────────────────────────────

    #[test]
    fn a_verify_primary_rule_is_enforced_as_a_primary_route_and_nothing_else_moves() {
        let verify = CanonicalRule {
            action: RuleAction::VerifyPrimary,
            ..suffix_rule("s-verify", "proton.example")
        };
        let block = CanonicalRule {
            action: RuleAction::Block,
            ..exact_fqdn_rule("p-block", "ads.example")
        };
        let book = CanonicalRuleBook {
            primary: CanonicalRuleSet::from_rules(vec![block.clone()]),
            secondary: CanonicalRuleSet::from_rules(vec![
                exact_fqdn_rule("s-route", "chat.example"),
                verify.clone(),
            ]),
        };
        let effective = book.with_verify_primary_effective();
        assert_eq!(
            effective.primary,
            CanonicalRuleSet::from_rules(vec![
                block,
                CanonicalRule {
                    action: RuleAction::Route,
                    ..verify
                },
            ])
        );
        assert_eq!(
            effective.secondary,
            CanonicalRuleSet::from_rules(vec![exact_fqdn_rule("s-route", "chat.example")])
        );
        let plain = effective.clone();
        assert_eq!(
            plain.with_verify_primary_effective(),
            effective,
            "nothing left to move"
        );
    }

    #[test]
    fn a_widened_book_written_back_is_restored_and_user_suffix_rules_stay() {
        let book = CanonicalRuleBook {
            primary: CanonicalRuleSet::from_rules(vec![exact_fqdn_rule("p1", "main.example")]),
            secondary: CanonicalRuleSet::from_rules(vec![
                exact_fqdn_rule("r1", "site.example"),
                // The user's own suffix rule, even one whose id looks synthetic.
                suffix_rule("r9+sub", "other.example"),
            ]),
        };
        assert_eq!(
            book.without_subdomain_twins(),
            None,
            "a clean book stays as is"
        );
        let widened = book.with_subdomain_coverage();
        assert_eq!(widened.total_rule_count(), 5);
        assert_eq!(widened.without_subdomain_twins(), Some(book));
    }

    #[test]
    fn a_twin_edited_apart_from_its_apex_is_the_users_rule() {
        let apex = exact_fqdn_rule("r1", "site.example");
        let widened = CanonicalRuleBook {
            primary: CanonicalRuleSet::default(),
            secondary: CanonicalRuleSet::from_rules(vec![apex.clone()]),
        }
        .with_subdomain_coverage();
        let twin = widened
            .secondary
            .rules()
            .iter()
            .find(|r| r.id.0 == "r1+sub")
            .cloned()
            .expect("twin");
        // Positive control: the twin as derived is dropped.
        assert!(widened.without_subdomain_twins().is_some());

        // The apex switched off, the twin left on: the user kept subdomains.
        let apex_off = CanonicalRule {
            enabled: false,
            ..apex.clone()
        };
        let kept = CanonicalRuleBook {
            primary: CanonicalRuleSet::default(),
            secondary: CanonicalRuleSet::from_rules(vec![apex_off, twin.clone()]),
        };
        assert_eq!(kept.without_subdomain_twins(), None);

        // A twin with its own comment is no longer the derived one either.
        let commented = CanonicalRuleBook {
            primary: CanonicalRuleSet::default(),
            secondary: CanonicalRuleSet::from_rules(vec![
                apex,
                CanonicalRule {
                    comment: "kept on purpose".into(),
                    ..twin
                },
            ]),
        };
        assert_eq!(commented.without_subdomain_twins(), None);
    }

    #[test]
    fn subdomain_coverage_adds_suffix_and_keeps_apex() {
        let book = CanonicalRuleBook {
            primary: CanonicalRuleSet::default(),
            secondary: CanonicalRuleSet::from_rules(vec![exact_fqdn_rule("r1", "site.example")]),
        };
        let expanded = book.with_subdomain_coverage();
        let sec = expanded.secondary.rules();
        assert!(
            sec.iter().any(|r| matches!(
                &r.address_match,
                Some(CanonicalAddressMatch::ExactFqdn(d)) if d == "site.example"
            )),
            "apex ExactFqdn must be preserved",
        );
        assert!(
            sec.iter().any(|r| matches!(
                &r.address_match,
                Some(CanonicalAddressMatch::SuffixDomain(d)) if d == "site.example"
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
            ip_rule("i", Ipv4Addr::new(192, 0, 2, 4)),
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
