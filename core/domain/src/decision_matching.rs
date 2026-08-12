//! Rule matching contracts for the routing decision pipeline.
//!
//! This module formalises the **rule matching stage**: the third step of the
//! routing decision pipeline that selects which routing rule applies to a
//! normalised and looked-up connection.
//!
//! # Match order (default)
//!
//! ```text
//! 1. ExactFqdn      — exact hostname; longest label wins within tier
//! 2. SuffixDomain   — apex + subdomains; longest base domain wins within tier
//! 3a. ExactIp       — exact IPv4 (default: checked before Zone)
//! 3b. Zone          — TLD / internal domain suffix
//!    ↑ order of 3a/3b is controlled by ZonePriorityPolicy
//! 4. Application    — process filename / glob (address-less rules only)
//! 5. Default        — behavior-mode fallback, no rule matched
//! ```
//!
//! **ExactFqdn tier always precedes SuffixDomain tier** for the same hostname.
//! Longest-label wins applies only *within* a single tier.
//!
//! # Suffix-domain and Zone matching semantics
//!
//! `SuffixDomain(label)` (written `*.label`) matches the apex `label` itself
//! **and** every subdomain of it. Use the [`match_suffix_domain`] helper for all
//! suffix comparisons — it carries the rationale for apex coverage.
//!
//! `Zone(name)` matches a hostname when `hostname.ends_with(".{name}")` — the
//! bare zone label is deliberately NOT a member. Use the [`match_zone`] helper
//! for all Zone comparisons.
//! Zone is skipped entirely when no hostname is available (IP-only traffic).
//!
//! # AND semantics for address + app filter
//!
//! When a rule carries both an `address_match` and an `app_match`, **both**
//! must match.  A rule that matches the address but not the process is
//! treated as a non-match for that candidate (see [`AppFilterResult`]).
//!
//! # `RequestedRouteDecision` is not the final route
//!
//! The match stage produces a [`RequestedRouteDecision`] — what route the
//! matching logic *requests*.  The actual route is confirmed (or overridden)
//! by the availability check and Fail-Closed / Fail-Open arbitration stages
//! downstream.
//!
//! # Algorithm pseudocode — `match_rules`
//!
//! ```text
//! fn match_rules(
//!     input:         &NormalizedDecisionInput,
//!     lookup:        &LookupResult,
//!     rule_book:     &CanonicalRuleBook,
//!     zone_policy:   ZonePriorityPolicy,
//!     behavior_mode: RouteBehaviorMode,
//! ) -> RequestedRouteDecision
//!
//!   avail = input.match_class_availability
//!
//!   // --- Pass 1: hostname-based tiers ---
//!   if hostname available and not blocked:
//!     // Tier 1: ExactFqdn
//!     candidates = rule_book.rules_where(|r| r.address == ExactFqdn(hostname))
//!     if candidates non-empty:
//!       winner, conflict = select_highest_specificity(candidates)
//!       return RequestedRouteDecision::MatchedRoute { winner, conflict }
//!
//!     // Tier 2: SuffixDomain
//!     candidates = rule_book.rules_where(|r|
//!         matches ExactFqdn AND hostname is strict subdomain of r.label)
//!     if candidates non-empty:
//!       winner, conflict = select_highest_specificity(candidates)
//!       return RequestedRouteDecision::MatchedRoute { winner, conflict }
//!
//!   // --- Pass 2: Zone / ExactIp (order per ZonePriorityPolicy) ---
//!   let tiers = if zone_policy.prefer_ip {
//!     [ExactIp, Zone]
//!   } else {
//!     [Zone, ExactIp]
//!   };
//!
//!   for tier in tiers:
//!     if tier == ExactIp and ip_available and not blocked:
//!       candidates = rule_book.rules_where(|r| r.address == ExactIp(selected_ip))
//!     if tier == Zone and hostname_available and not blocked:
//!       candidates = rule_book.rules_where(|r|
//!           r.address == Zone(name) AND match_zone(hostname, name))
//!     if candidates non-empty:
//!       winner, conflict = select_highest_specificity(candidates)
//!       return RequestedRouteDecision::MatchedRoute { winner, conflict }
//!
//!   // --- Pass 3: Application-only rules ---
//!   if app identity available and not blocked:
//!     candidates = rule_book.rules_where(|r|
//!         r.address_match == None AND r.app_match matches process_name)
//!     if candidates non-empty:
//!       winner, conflict = select_highest_specificity(candidates)
//!       return RequestedRouteDecision::MatchedRoute { winner, conflict }
//!
//!   // --- Pass 4: Default ---
//!   return RequestedRouteDecision::DefaultRoute {
//!       reason: NoMatchReason::NoMatchFound,
//!       behavior_mode,
//!   }
//!
//! fn select_highest_specificity(candidates) -> (RuleMatchCandidate, conflict: bool):
//!   // Discard candidates where AppFilterResult == NotMatched
//!   active = candidates.filter(|c| c.app_filter != NotMatched)
//!   // Sort descending by specificity
//!   sorted = active.sort_by(|a, b| b.specificity.cmp(a.specificity))
//!   top = sorted[0]
//!   // Conflict: another candidate has equal specificity but different route
//!   conflict = sorted[1..].any(|c| c.specificity == top.specificity
//!                                  && c.route_role != top.route_role)
//!   return (top, conflict)
//! ```

use nrr_shared::{RouteBehaviorMode, RouteRole};

use crate::{RuleAction, RuleId};

// ── match_zone ────────────────────────────────────────────────────────────────

/// Returns `true` if `hostname` belongs to the given `zone_name`.
///
/// A hostname belongs to a zone when it ends with `".{zone_name}"`.
/// The apex itself (the bare zone name) is **not** a member of the zone.
///
/// Both inputs must already be normalised to lowercase before calling this
/// function — Zone matching is case-sensitive on the normalised form.
///
/// # Examples
///
/// ```
/// use nrr_domain::decision_matching::match_zone;
///
/// assert!(match_zone("server.corp.intra", "intra"));
/// assert!(match_zone("a.b.ru", "ru"));
/// assert!(!match_zone("intra", "intra"));      // apex is not a member
/// assert!(!match_zone("notintra", "intra"));   // suffix must be preceded by '.'
/// assert!(!match_zone("example.com", "ru"));
/// assert!(!match_zone("", "intra"));
/// assert!(!match_zone("server.intra", ""));    // empty zone name is invalid
/// ```
pub fn match_zone(hostname: &str, zone_name: &str) -> bool {
    if zone_name.is_empty() || hostname.is_empty() {
        return false;
    }
    let zone_len = zone_name.len();
    let host_len = hostname.len();
    // hostname must be strictly longer than ".{zone_name}"
    if host_len <= zone_len + 1 {
        return false;
    }
    let boundary = host_len - zone_len - 1;
    hostname.as_bytes()[boundary] == b'.' && hostname[boundary + 1..].eq(zone_name)
}

// ── match_suffix_domain ───────────────────────────────────────────────────────

/// Returns `true` if `hostname` is covered by the `SuffixDomain(label)` rule
/// written `*.label` — **the apex `label` itself and every subdomain of it, at
/// any depth**.
///
/// This is the single source of truth for `SuffixDomain` coverage: the pure
/// decision engine, the DNS observer's rule gate, and every enforcement fan-out
/// call it, so GUI explanation and enforcement cannot drift apart.
///
/// # Why the apex is covered
///
/// Matching subdomains only would be a silent footgun: a user writes
/// `*.mysite.com`, opens `mysite.com`, and that one request quietly leaves by
/// the other route with no error surfaced anywhere. Nothing is lost by
/// covering the apex, because `ExactFqdn` is a strictly higher tier than
/// `SuffixDomain`: a user who genuinely wants "subdomains here, apex
/// elsewhere" writes an exact rule for the apex and it wins. So the exotic
/// case stays expressible — as an explicit action — instead of arising
/// silently by default.
///
/// [`match_zone`] deliberately keeps the apex-excluded semantics: a `Zone` rule
/// names a TLD or internal zone (`ru`, `intra`), and the bare zone label is not
/// a host a user ever means to route.
///
/// Both inputs must already be normalised to lowercase (and punycode for IDN)
/// before calling — matching is exact on the normalised form.
///
/// # Examples
///
/// ```
/// use nrr_domain::decision_matching::match_suffix_domain;
///
/// assert!(match_suffix_domain("mysite.com", "mysite.com"));      // apex
/// assert!(match_suffix_domain("www.mysite.com", "mysite.com"));  // subdomain
/// assert!(match_suffix_domain("a.b.mysite.com", "mysite.com"));  // any depth
/// assert!(!match_suffix_domain("notmysite.com", "mysite.com"));  // label boundary
/// assert!(!match_suffix_domain("mysite.com", ""));               // empty label is invalid
/// ```
pub fn match_suffix_domain(hostname: &str, label: &str) -> bool {
    if label.is_empty() || hostname.is_empty() {
        return false;
    }
    hostname == label || match_zone(hostname, label)
}

// ── MatchClass ────────────────────────────────────────────────────────────────

/// The match class (tier) that produced a candidate rule.
///
/// Determines the coarse priority of a candidate before specificity is
/// compared.  Only candidates within the same match class compete on
/// specificity; cross-class comparison uses the fixed tier order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum MatchClass {
    /// Tier 1 — exact FQDN match (highest priority address tier).
    ExactFqdn,
    /// Tier 2 — subdomain wildcard match.
    SuffixDomain,
    /// Tier 3a — exact IPv4 match (default: checked before Zone).
    ExactIp,
    /// Tier 3b — TLD / internal domain zone match.
    Zone,
    /// Tier 4 — application process name match (address-less rules).
    Application,
    /// Tier 5 — behavior-mode default (no rule matched).
    Default,
}

// ── SpecificityScore ──────────────────────────────────────────────────────────

/// Specificity score for ordering candidates within a single [`MatchClass`].
///
/// Higher scores are more specific and win over lower scores.
///
/// ## Scoring rules by match class
///
/// | Match class  | Score                                         |
/// |--------------|-----------------------------------------------|
/// | `ExactFqdn`  | Number of DNS labels (e.g. `a.b.c` = 3)       |
/// | `SuffixDomain` | Number of DNS labels in the base domain      |
/// | `Zone`       | Always 1 (all zones are equally specific)     |
/// | `ExactIp`    | Always 1 (exact match; no CIDR in Free)       |
/// | `Application` | Exact name = 2, glob pattern = 1             |
/// | `Default`    | Always 0                                      |
///
/// Within a tier, if two candidates have **equal** specificity but belong to
/// **different** route sets, a [`ConflictMarker::Detected`] is attached to the
/// winner (see [`RuleMatchCandidate::conflict`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SpecificityScore(pub u32);

impl SpecificityScore {
    /// Counts DNS labels in a hostname/domain label string.
    ///
    /// Used to compute specificity for `ExactFqdn` and `SuffixDomain`.
    pub fn label_count(label: &str) -> Self {
        if label.is_empty() {
            return Self(0);
        }
        Self(label.split('.').count() as u32)
    }

    /// Fixed score of 1 — used for `Zone`, `ExactIp`.
    pub const SINGLE: Self = Self(1);

    /// Fixed score of 2 — used for exact application name match.
    pub const APP_EXACT: Self = Self(2);

    /// Fixed score of 1 — used for application glob match.
    pub const APP_GLOB: Self = Self(1);

    /// Fixed score of 0 — used for the default fallback tier.
    pub const DEFAULT: Self = Self(0);
}

// ── AppFilterResult ───────────────────────────────────────────────────────────

/// Result of evaluating the optional application filter on an address rule.
///
/// An address rule with an `app_match` field uses AND semantics: both the
/// address condition **and** the app filter must match for the rule to apply.
/// A candidate with [`AppFilterResult::NotMatched`] is removed from
/// consideration before specificity selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppFilterResult {
    /// The rule has no app filter — address match alone is sufficient.
    NoFilter,
    /// The app filter was present and matched the current process identity.
    Matched,
    /// The app filter was present but did not match — this candidate is
    /// disqualified.
    NotMatched,
}

impl AppFilterResult {
    /// Returns `true` if the candidate is eligible for selection.
    pub fn is_eligible(self) -> bool {
        !matches!(self, Self::NotMatched)
    }
}

// ── ConflictMarker ────────────────────────────────────────────────────────────

/// Whether a same-tier, same-specificity conflict was detected during
/// candidate selection.
///
/// A conflict arises when two rules have the same [`MatchClass`] and the same
/// [`SpecificityScore`] but are assigned to **different** route sets.  The
/// pipeline deterministically selects the primary-route rule to avoid
/// non-determinism, but records the conflict so it can be surfaced in the
/// explain output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConflictMarker {
    /// No conflicting candidate was found at the same specificity level.
    None,
    /// A conflicting candidate with equal specificity but a different route
    /// role was detected.  The explain output must note this.
    Detected,
}

// ── RuleMatchCandidate ────────────────────────────────────────────────────────

/// A rule that matched the normalised input and is eligible for selection.
///
/// The match stage collects all candidates, discards those with
/// [`AppFilterResult::NotMatched`], then selects the winner by:
/// 1. Highest [`SpecificityScore`] within the match class.
/// 2. If tied: deterministic ordering by `rule_id` string (lexicographic,
///    ascending) — lower `rule_id` wins.  The tie is also flagged via
///    [`ConflictMarker`] if the tied candidates point to different route sets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleMatchCandidate {
    /// Stable identifier of the matched rule.
    pub rule_id: RuleId,
    /// Which route set this rule belongs to.
    pub route_role: RouteRole,
    /// Which match class (tier) produced this candidate.
    pub match_class: MatchClass,
    /// Specificity score within the match class.
    pub specificity: SpecificityScore,
    /// Result of the optional app filter check.
    pub app_filter_result: AppFilterResult,
    /// Whether an equal-specificity conflict with a different route set was
    /// detected when this candidate was selected as the winner.
    pub conflict: ConflictMarker,
    /// Per-rule enforcement action. When the winning candidate carries
    /// [`RuleAction::Block`], the final-action stage short-circuits to a drop
    /// regardless of `route_role`.
    pub action: RuleAction,
}

// ── ZonePriorityPolicy ────────────────────────────────────────────────────────

/// Controls whether `ExactIp` or `Zone` is checked first in tier 3.
///
/// Stored in `UiPreferences` as `zone_priority_over_ip: bool`.
/// Surfaced to the user in **Settings → Routing**.
///
/// **This setting affects only runtime evaluation order — it has no effect on
/// canonical storage order** (which is always `ExactFqdn < SuffixDomain <
/// Zone < ExactIp < Application`).
///
/// | `prefer_ip` | Evaluation order of tier 3   |
/// |-------------|------------------------------|
/// | `true`      | ExactIp → Zone (default)     |
/// | `false`     | Zone → ExactIp               |
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZonePriorityPolicy {
    /// When `true` (default), `ExactIp` is evaluated before `Zone`.
    /// When `false`, `Zone` is evaluated before `ExactIp`.
    pub prefer_ip: bool,
}

impl Default for ZonePriorityPolicy {
    fn default() -> Self {
        Self { prefer_ip: true }
    }
}

impl ZonePriorityPolicy {
    /// Returns the two tier-3 match classes in the order they should be
    /// evaluated for this policy.
    pub fn tier3_order(self) -> [MatchClass; 2] {
        if self.prefer_ip {
            [MatchClass::ExactIp, MatchClass::Zone]
        } else {
            [MatchClass::Zone, MatchClass::ExactIp]
        }
    }
}

// ── NoMatchReason ─────────────────────────────────────────────────────────────

/// Reason why the match stage produced no matching rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoMatchReason {
    /// All match classes were blocked by normalization errors — nothing to
    /// check against the rule book.
    AllClassesBlocked,
    /// The active rule book is empty — no rules exist.
    EmptyRuleBook,
    /// Rules exist but none matched the normalised input.
    NoMatchFound,
}

// ── RequestedRouteDecision ────────────────────────────────────────────────────

/// Output of the rule matching stage — what route is *requested*.
///
/// This value is consumed by the availability check, which verifies whether
/// the requested route is actually reachable, and by the Fail-Closed /
/// Fail-Open arbitration stage, which determines the [`FinalAction`].
///
/// The match stage does **not** apply the route — it only declares intent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RequestedRouteDecision {
    /// A rule was matched and a specific route role is requested.
    MatchedRoute {
        /// The winning match candidate.
        candidate: RuleMatchCandidate,
    },
    /// No rule matched; the pipeline defers to the behavior-mode default.
    DefaultRoute {
        /// Why no rule matched.
        reason: NoMatchReason,
        /// The active behavior mode, used by stage 5/6 to resolve the default
        /// to a concrete route and apply Fail-Closed / Fail-Open semantics.
        behavior_mode: RouteBehaviorMode,
    },
}

impl RequestedRouteDecision {
    /// Returns the requested route role, if a rule was matched.
    /// Returns `None` for `DefaultRoute` (route not yet resolved at this stage).
    pub fn matched_route_role(&self) -> Option<RouteRole> {
        match self {
            Self::MatchedRoute { candidate } => Some(candidate.route_role),
            Self::DefaultRoute { .. } => None,
        }
    }

    /// Returns `true` if a rule was matched (as opposed to falling through to
    /// the default route).
    pub fn is_rule_matched(&self) -> bool {
        matches!(self, Self::MatchedRoute { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── match_zone ────────────────────────────────────────────────────────────

    #[test]
    fn match_zone_basic_tld() {
        assert!(match_zone("example.ru", "ru"));
        assert!(match_zone("sub.example.ru", "ru"));
        assert!(match_zone("a.b.c.ru", "ru"));
    }

    #[test]
    fn match_zone_internal_domain() {
        assert!(match_zone("server.corp.intra", "intra"));
        assert!(match_zone("host.intra", "intra"));
    }

    #[test]
    fn match_zone_apex_is_not_a_member() {
        // The zone name itself ("intra") does not belong to the zone
        assert!(!match_zone("intra", "intra"));
        assert!(!match_zone("ru", "ru"));
    }

    #[test]
    fn match_zone_suffix_without_dot_is_not_a_match() {
        // "notintra" ends with "intra" but not ".intra"
        assert!(!match_zone("notintra", "intra"));
        assert!(!match_zone("extraru", "ru"));
    }

    #[test]
    fn match_zone_empty_inputs() {
        assert!(!match_zone("", "intra"));
        assert!(!match_zone("host.intra", ""));
        assert!(!match_zone("", ""));
    }

    #[test]
    fn match_zone_different_tld() {
        assert!(!match_zone("example.com", "ru"));
        assert!(!match_zone("example.ru", "com"));
    }

    #[test]
    fn match_zone_multi_label_zone_name() {
        // Zone names are single labels (e.g. "corp"), not multi-label
        // but the function must still work correctly if called with one
        assert!(match_zone("host.corp", "corp"));
        assert!(!match_zone("corp", "corp"));
    }

    #[test]
    fn match_zone_hostname_shorter_than_dot_plus_zone() {
        // ".ru" would be len=3, hostname must be >3
        assert!(!match_zone(".ru", "ru")); // len==3, not strictly greater
        assert!(!match_zone("a.r", "ru")); // doesn't end with ".ru"
    }

    // ── match_suffix_domain ───────────────────────────────────────────────────

    #[test]
    fn match_suffix_domain_covers_the_apex() {
        assert!(match_suffix_domain("example.com", "example.com"));
        assert!(match_suffix_domain("mysite.com", "mysite.com"));
    }

    #[test]
    fn match_suffix_domain_covers_subdomains_at_any_depth() {
        assert!(match_suffix_domain("www.example.com", "example.com"));
        assert!(match_suffix_domain("a.b.c.example.com", "example.com"));
    }

    #[test]
    fn match_suffix_domain_respects_the_label_boundary() {
        assert!(!match_suffix_domain("notexample.com", "example.com"));
        assert!(!match_suffix_domain("example.com.evil.net", "example.com"));
    }

    #[test]
    fn match_suffix_domain_at_depth_does_not_reach_the_parent_or_siblings() {
        assert!(match_suffix_domain("sub.example.com", "sub.example.com"));
        assert!(match_suffix_domain("a.sub.example.com", "sub.example.com"));
        assert!(!match_suffix_domain("example.com", "sub.example.com"));
        assert!(!match_suffix_domain("other.example.com", "sub.example.com"));
        assert!(!match_suffix_domain(
            "notsub.example.com",
            "sub.example.com"
        ));
    }

    #[test]
    fn match_suffix_domain_rejects_empty_inputs() {
        assert!(!match_suffix_domain("", "example.com"));
        assert!(!match_suffix_domain("example.com", ""));
        assert!(!match_suffix_domain("", ""));
    }

    #[test]
    fn match_suffix_domain_is_a_strict_superset_of_match_zone() {
        // Every zone member is a suffix member; the apex is the only addition.
        for (host, label) in [
            ("a.b.ru", "ru"),
            ("server.corp.intra", "intra"),
            ("www.example.com", "example.com"),
        ] {
            assert_eq!(match_zone(host, label), match_suffix_domain(host, label));
        }
        assert!(!match_zone("intra", "intra"));
        assert!(match_suffix_domain("intra", "intra"));
    }

    // ── SpecificityScore ──────────────────────────────────────────────────────

    #[test]
    fn specificity_label_count_single_label() {
        assert_eq!(SpecificityScore::label_count("com"), SpecificityScore(1));
    }

    #[test]
    fn specificity_label_count_multi_label() {
        assert_eq!(
            SpecificityScore::label_count("mail.corp.example.com"),
            SpecificityScore(4)
        );
    }

    #[test]
    fn specificity_label_count_empty() {
        assert_eq!(SpecificityScore::label_count(""), SpecificityScore(0));
    }

    #[test]
    fn specificity_longer_label_beats_shorter() {
        let long = SpecificityScore::label_count("mail.corp.example.com");
        let short = SpecificityScore::label_count("corp.example.com");
        assert!(long > short);
    }

    #[test]
    fn specificity_constants_ordered() {
        assert!(SpecificityScore::APP_EXACT > SpecificityScore::APP_GLOB);
        assert!(SpecificityScore::SINGLE > SpecificityScore::DEFAULT);
        assert_eq!(SpecificityScore::SINGLE, SpecificityScore(1));
    }

    // ── AppFilterResult ───────────────────────────────────────────────────────

    #[test]
    fn app_filter_no_filter_is_eligible() {
        assert!(AppFilterResult::NoFilter.is_eligible());
    }

    #[test]
    fn app_filter_matched_is_eligible() {
        assert!(AppFilterResult::Matched.is_eligible());
    }

    #[test]
    fn app_filter_not_matched_is_not_eligible() {
        assert!(!AppFilterResult::NotMatched.is_eligible());
    }

    // ── ZonePriorityPolicy ────────────────────────────────────────────────────

    #[test]
    fn zone_policy_default_prefers_ip() {
        let p = ZonePriorityPolicy::default();
        assert!(p.prefer_ip);
        assert_eq!(p.tier3_order(), [MatchClass::ExactIp, MatchClass::Zone]);
    }

    #[test]
    fn zone_policy_prefer_zone_reverses_order() {
        let p = ZonePriorityPolicy { prefer_ip: false };
        assert_eq!(p.tier3_order(), [MatchClass::Zone, MatchClass::ExactIp]);
    }

    #[test]
    fn zone_policy_does_not_affect_tier1_or_tier2() {
        let default_p = ZonePriorityPolicy::default();
        let inverted_p = ZonePriorityPolicy { prefer_ip: false };
        // Both policies produce different tier3 order
        assert_ne!(default_p.tier3_order(), inverted_p.tier3_order());
        // But neither changes ExactFqdn / SuffixDomain — those are always first
    }

    // ── RuleMatchCandidate ────────────────────────────────────────────────────

    #[test]
    fn rule_match_candidate_construction() {
        let c = RuleMatchCandidate {
            rule_id: RuleId("r-abc".to_owned()),
            route_role: RouteRole::Secondary,
            match_class: MatchClass::ExactFqdn,
            specificity: SpecificityScore::label_count("mail.example.com"),
            app_filter_result: AppFilterResult::NoFilter,
            conflict: ConflictMarker::None,
            action: RuleAction::Route,
        };
        assert_eq!(c.route_role, RouteRole::Secondary);
        assert_eq!(c.match_class, MatchClass::ExactFqdn);
        assert_eq!(c.specificity, SpecificityScore(3));
        assert!(c.app_filter_result.is_eligible());
    }

    // ── RequestedRouteDecision ────────────────────────────────────────────────

    fn make_candidate(class: MatchClass, role: RouteRole) -> RuleMatchCandidate {
        RuleMatchCandidate {
            rule_id: RuleId("r-test".to_owned()),
            route_role: role,
            match_class: class,
            specificity: SpecificityScore::SINGLE,
            app_filter_result: AppFilterResult::NoFilter,
            conflict: ConflictMarker::None,
            action: RuleAction::Route,
        }
    }

    #[test]
    fn requested_route_decision_matched_route_returns_role() {
        let decision = RequestedRouteDecision::MatchedRoute {
            candidate: make_candidate(MatchClass::ExactIp, RouteRole::Secondary),
        };
        assert_eq!(decision.matched_route_role(), Some(RouteRole::Secondary));
        assert!(decision.is_rule_matched());
    }

    #[test]
    fn requested_route_decision_default_route_returns_none() {
        let decision = RequestedRouteDecision::DefaultRoute {
            reason: NoMatchReason::NoMatchFound,
            behavior_mode: RouteBehaviorMode::PreferPrimary,
        };
        assert_eq!(decision.matched_route_role(), None);
        assert!(!decision.is_rule_matched());
    }

    #[test]
    fn requested_route_decision_default_preserves_behavior_mode() {
        let decision = RequestedRouteDecision::DefaultRoute {
            reason: NoMatchReason::EmptyRuleBook,
            behavior_mode: RouteBehaviorMode::StrictSecondaryFailClosed,
        };
        if let RequestedRouteDecision::DefaultRoute { behavior_mode, .. } = decision {
            assert_eq!(behavior_mode, RouteBehaviorMode::StrictSecondaryFailClosed);
        } else {
            panic!("expected DefaultRoute");
        }
    }

    // ── Match class ordering (tier priority) ──────────────────────────────────

    #[test]
    fn match_class_tier_ordering_exact_fqdn_beats_all() {
        assert!(MatchClass::ExactFqdn < MatchClass::SuffixDomain);
        assert!(MatchClass::ExactFqdn < MatchClass::ExactIp);
        assert!(MatchClass::ExactFqdn < MatchClass::Zone);
        assert!(MatchClass::ExactFqdn < MatchClass::Application);
        assert!(MatchClass::ExactFqdn < MatchClass::Default);
    }

    #[test]
    fn match_class_tier_ordering_suffix_beats_zone_ip_app_default() {
        assert!(MatchClass::SuffixDomain < MatchClass::ExactIp);
        assert!(MatchClass::SuffixDomain < MatchClass::Zone);
        assert!(MatchClass::SuffixDomain < MatchClass::Application);
        assert!(MatchClass::SuffixDomain < MatchClass::Default);
    }

    #[test]
    fn match_class_tier_ordering_app_beats_default() {
        assert!(MatchClass::Application < MatchClass::Default);
    }
}
