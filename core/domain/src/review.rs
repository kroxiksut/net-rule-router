//! Review flow and diff engine for candidate policy revisions.
//!
//! # Data flow
//!
//! 1. [`compute_diff`]`(prev, candidate)` → [`StructuralDiff`]
//! 2. [`StructuralDiff::to_review_summary`] → [`ReviewSummary`] (shown in the review UI)
//! 3. [`check_confirmation`]`(token, ...)` → [`ConfirmationResult`]
//!
//! [`StructuralDiff`] is the machine-level representation: every per-rule change
//! is enumerated and preserved for audit/debug purposes. [`ReviewSummary`] is the
//! user-facing layer: the same data aggregated into human-readable categories.
//!
//! Rule-order changes are invisible after canonicalization. Only semantic
//! changes — match value, enabled state, comment, or target route — are reported.
//!
//! # Staleness and supersession
//!
//! A [`ConfirmationToken`] captures the service state at the moment the review UI
//! was opened. [`check_confirmation`] verifies that neither the active revision
//! nor the pending candidate changed while the review was open:
//! - Active changed → [`ConfirmationResult::Stale`]: user must re-review against
//!   the new baseline.
//! - A different candidate is now pending → [`ConfirmationResult::Superseded`]:
//!   the reviewed candidate was displaced and cannot be confirmed.

use std::collections::BTreeMap;

use crate::{
    canonical::{CanonicalAddressMatch, CanonicalProfile, CanonicalRule},
    revision::{ContentHash, RevisionId, UnixTimestamp},
    RouteBehaviorMode, RouteRole, RuleId,
};

// ── RuleChange ────────────────────────────────────────────────────────────────

/// A single rule-level change between the previous active profile and a candidate.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuleChange {
    /// Rule is present in the candidate but absent from the previous profile.
    Added {
        rule: CanonicalRule,
        route: RouteRole,
    },
    /// Rule is absent from the candidate but present in the previous profile.
    Removed {
        rule: CanonicalRule,
        route: RouteRole,
    },
    /// Rule exists in both with the same target route but different content
    /// (match value, enabled state, or comment changed).
    Modified {
        prev: CanonicalRule,
        next: CanonicalRule,
        route: RouteRole,
    },
    /// Rule exists in both but was moved to a different target route.
    ///
    /// Content differences are absorbed — retarget supersedes modify as the
    /// more semantically significant change.
    Retargeted {
        rule: CanonicalRule,
        from: RouteRole,
        to: RouteRole,
    },
}

impl RuleChange {
    #[cfg(test)]
    fn is_added(&self) -> bool {
        matches!(self, Self::Added { .. })
    }
    #[cfg(test)]
    fn is_removed(&self) -> bool {
        matches!(self, Self::Removed { .. })
    }
    #[cfg(test)]
    fn is_modified_or_retargeted(&self) -> bool {
        matches!(self, Self::Modified { .. } | Self::Retargeted { .. })
    }

    fn rule_id(&self) -> &RuleId {
        match self {
            Self::Added { rule, .. }
            | Self::Removed { rule, .. }
            | Self::Retargeted { rule, .. } => &rule.id,
            Self::Modified { next, .. } => &next.id,
        }
    }

    /// Content sort key (canonical group + match value) used as the
    /// primary tiebreaker within a change kind. Independent of the
    /// synthetic `r-NNNN` id so the diff order stays stable even when ids
    /// are regenerated (preset re-import) or collide across routes.
    fn content_sort_key(&self) -> (u8, String) {
        match self {
            Self::Added { rule, .. }
            | Self::Removed { rule, .. }
            | Self::Retargeted { rule, .. } => rule.sort_key(),
            Self::Modified { next, .. } => next.sort_key(),
        }
    }

    fn kind_order(&self) -> u8 {
        match self {
            Self::Added { .. } => 0,
            Self::Removed { .. } => 1,
            Self::Modified { .. } => 2,
            Self::Retargeted { .. } => 3,
        }
    }
}

// ── StructuralDiff ────────────────────────────────────────────────────────────

/// Machine-level diff between a previous active profile and a candidate revision.
///
/// All per-rule changes are enumerated in [`rule_changes`](Self::rule_changes)
/// and preserved for audit and debug. The list is sorted in a stable order:
/// Added → Removed → Modified → Retargeted, then lexicographically by rule ID
/// within each group.
///
/// Produce with [`compute_diff`]. Convert to the presentation layer with
/// [`to_review_summary`](Self::to_review_summary).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StructuralDiff {
    /// At least one route adapter binding (primary or secondary) changed.
    pub binding_changed: bool,
    /// The default routing behavior mode changed.
    pub behavior_mode_changed: bool,
    /// Behavior mode of the previous active profile.
    /// `None` when there was no previous profile (first revision).
    pub prev_behavior_mode: Option<RouteBehaviorMode>,
    /// Behavior mode of the candidate revision.
    pub next_behavior_mode: RouteBehaviorMode,
    /// All rule-level changes in deterministic order.
    pub rule_changes: Vec<RuleChange>,
    /// Total rule count in the previous active
    /// profile (sum of primary + secondary rule sets). `0` when there
    /// was no previous profile (first revision). Used by
    /// [`risk::score_candidate`](crate::risk::score_candidate) to
    /// detect rule-set-emptied / high-removal-ratio signals without
    /// re-walking the rule book.
    pub prev_total_rules: u32,
    /// Total rule count in the candidate revision.
    pub next_total_rules: u32,
    /// Apex labels of `SuffixDomain` rules in the
    /// candidate that also have a matching `ExactFqdn` rule (in
    /// either route set) whose hostname ends with `.{apex}` or equals
    /// `{apex}`. Deterministic order (lexicographic by apex). Empty
    /// when no overlap is detected. Used by
    /// [`risk::score_candidate`](crate::risk::score_candidate) to
    /// emit [`RiskSignal::OverlappingRules`](crate::risk::RiskSignal::OverlappingRules).
    pub overlapping_apexes: Vec<String>,
}

impl StructuralDiff {
    /// Returns `true` when this diff records no changes at all.
    ///
    /// An empty diff means the candidate is semantically identical to the active
    /// revision. [`process_import`](crate::import::process_import) prevents this
    /// via content-hash comparison, but this helper guards against accidents.
    pub fn is_empty(&self) -> bool {
        !self.binding_changed && !self.behavior_mode_changed && self.rule_changes.is_empty()
    }

    /// Converts this diff to the user-facing [`ReviewSummary`] for the review UI.
    pub fn to_review_summary(&self) -> ReviewSummary {
        let mut added = Vec::new();
        let mut removed = Vec::new();
        let mut modified = Vec::new();
        let mut retargeted = Vec::new();

        for change in &self.rule_changes {
            match change {
                RuleChange::Added { rule, route } => {
                    added.push(RuleSummaryEntry::from_rule(rule, *route));
                }
                RuleChange::Removed { rule, route } => {
                    removed.push(RuleSummaryEntry::from_rule(rule, *route));
                }
                RuleChange::Modified { next, route, .. } => {
                    modified.push(RuleSummaryEntry::from_rule(next, *route));
                }
                RuleChange::Retargeted { rule, from, to } => {
                    retargeted.push(RuleSummaryEntry::retargeted(rule, *from, *to));
                }
            }
        }

        ReviewSummary {
            binding_changed: self.binding_changed,
            behavior_mode_changed: self.behavior_mode_changed,
            prev_behavior_mode: self.prev_behavior_mode,
            next_behavior_mode: self.next_behavior_mode,
            rules_added: added,
            rules_removed: removed,
            rules_modified: modified,
            rules_retargeted: retargeted,
        }
    }
}

// ── RuleSummaryEntry ──────────────────────────────────────────────────────────

/// A compact, human-readable entry for one changed rule in the review UI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleSummaryEntry {
    /// Stable rule identifier.
    pub id: String,
    /// Display string for the rule, suitable for the review change list.
    pub display: String,
    /// Route the rule is bound to in the candidate (destination for retargets).
    pub route: RouteRole,
    /// Whether the rule participates in route evaluation. A disabled rule is
    /// still a real diff entry — it is stored and travels to the service — but
    /// it changes nothing about routing, so the review UI has to say so rather
    /// than list it next to rules that actually take effect.
    pub enabled: bool,
}

impl RuleSummaryEntry {
    fn from_rule(rule: &CanonicalRule, route: RouteRole) -> Self {
        Self {
            id: rule.id.0.clone(),
            display: rule_display(rule),
            route,
            enabled: rule.enabled,
        }
    }

    fn retargeted(rule: &CanonicalRule, from: RouteRole, to: RouteRole) -> Self {
        let base = rule_display(rule);
        Self {
            id: rule.id.0.clone(),
            display: format!("{base} ({} → {})", route_label(from), route_label(to)),
            route: to,
            enabled: rule.enabled,
        }
    }
}

fn rule_display(rule: &CanonicalRule) -> String {
    match (&rule.address_match, &rule.app_match) {
        (Some(addr), None) => addr.to_display_string(),
        (None, Some(app)) => format!("{} (app)", app.pattern.as_str()),
        (Some(addr), Some(app)) => {
            format!(
                "{} + {} (app)",
                addr.to_display_string(),
                app.pattern.as_str()
            )
        }
        (None, None) => String::from("(no match — invalid rule)"),
    }
}

fn route_label(role: RouteRole) -> &'static str {
    match role {
        RouteRole::Primary => "primary",
        RouteRole::Secondary => "secondary",
    }
}

// ── ReviewSummary ─────────────────────────────────────────────────────────────

/// User-facing summary of what changed between the active profile and a candidate.
///
/// Produced from [`StructuralDiff::to_review_summary`]. The four rule-change
/// lists follow the order of the parent [`StructuralDiff::rule_changes`] (sorted
/// by kind, then rule ID).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReviewSummary {
    /// At least one route adapter binding changed.
    pub binding_changed: bool,
    /// The default routing behavior mode changed.
    pub behavior_mode_changed: bool,
    /// Previous behavior mode (`None` for the first revision).
    pub prev_behavior_mode: Option<RouteBehaviorMode>,
    /// Behavior mode of the candidate revision.
    pub next_behavior_mode: RouteBehaviorMode,
    /// Rules present in the candidate but absent in the previous profile.
    pub rules_added: Vec<RuleSummaryEntry>,
    /// Rules absent from the candidate but present in the previous profile.
    pub rules_removed: Vec<RuleSummaryEntry>,
    /// Rules present in both with modified content (same route).
    pub rules_modified: Vec<RuleSummaryEntry>,
    /// Rules present in both but moved to a different target route.
    pub rules_retargeted: Vec<RuleSummaryEntry>,
}

impl ReviewSummary {
    /// Returns `true` when this summary records no user-visible changes.
    pub fn is_empty(&self) -> bool {
        !self.binding_changed
            && !self.behavior_mode_changed
            && self.rules_added.is_empty()
            && self.rules_removed.is_empty()
            && self.rules_modified.is_empty()
            && self.rules_retargeted.is_empty()
    }

    /// Total number of rule-level changes across all four categories.
    pub fn total_rule_changes(&self) -> usize {
        self.rules_added.len()
            + self.rules_removed.len()
            + self.rules_modified.len()
            + self.rules_retargeted.len()
    }
}

// ── ConfirmationToken ─────────────────────────────────────────────────────────

/// State captured when the review UI was opened.
///
/// The caller creates a token at the moment the review screen is shown. Pass it
/// to [`check_confirmation`] when the user clicks "Approve" to verify that
/// nothing changed while the review was open.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfirmationToken {
    /// ID of the candidate revision being reviewed.
    pub candidate_id: RevisionId,
    /// Content hash of the active revision at the moment the review opened.
    /// `None` when no active revision existed at that time.
    pub active_hash_at_open: Option<ContentHash>,
    /// UTC timestamp when the review was opened (recorded for audit).
    pub opened_at: UnixTimestamp,
}

// ── ConfirmationResult ────────────────────────────────────────────────────────

/// Outcome of [`check_confirmation`].
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfirmationResult {
    /// The candidate is still pending and the active revision has not changed.
    /// The service may proceed to activate the candidate revision.
    Confirmed { candidate_id: RevisionId },
    /// The active revision changed while the review was open.
    ///
    /// The user must re-open the review: the diff shown was relative to a
    /// previous baseline that no longer reflects the current active policy.
    Stale { candidate_id: RevisionId },
    /// The candidate being reviewed is no longer the current pending revision.
    ///
    /// It was displaced by a newer import (variant-A supersession) or otherwise
    /// consumed. The token is invalid and cannot be used to activate any revision.
    Superseded,
}

/// Checks whether the user's approval of a candidate revision is still valid.
///
/// # Arguments
///
/// - `token` — snapshot captured when the review UI was opened.
/// - `current_active_hash` — content hash of the currently active revision.
///   `None` if no revision is currently active.
/// - `current_pending_id` — ID of the revision currently in the pending slot.
///   `None` if no revision is pending (already consumed or never created).
///
/// # Decision logic
///
/// Supersession is checked first: if the pending slot no longer holds the
/// reviewed candidate, no further checks are meaningful. Staleness is checked
/// second: the active baseline the user reviewed against must still be current.
pub fn check_confirmation(
    token: &ConfirmationToken,
    current_active_hash: Option<&ContentHash>,
    current_pending_id: Option<&RevisionId>,
) -> ConfirmationResult {
    if current_pending_id != Some(&token.candidate_id) {
        return ConfirmationResult::Superseded;
    }
    if current_active_hash != token.active_hash_at_open.as_ref() {
        return ConfirmationResult::Stale {
            candidate_id: token.candidate_id.clone(),
        };
    }
    ConfirmationResult::Confirmed {
        candidate_id: token.candidate_id.clone(),
    }
}

// ── compute_diff ──────────────────────────────────────────────────────────────

/// Computes the structural diff between a previous active profile and a candidate.
///
/// Pass `prev = None` for the very first revision: all candidate rules will be
/// reported as [`RuleChange::Added`] and binding/behavior fields will show no
/// change (there is no baseline to compare against).
///
/// Rule-order changes are invisible after canonicalization. Two profiles with the
/// same rules in different insertion order produce the same [`CanonicalProfile`]
/// and therefore an empty diff.
///
/// [`StructuralDiff::rule_changes`] is sorted deterministically: Added first,
/// then Removed, then Modified, then Retargeted; lexicographically by rule ID
/// within each group.
pub fn compute_diff(
    prev: Option<&CanonicalProfile>,
    candidate: &CanonicalProfile,
) -> StructuralDiff {
    let binding_changed = prev.is_some_and(|p| {
        p.primary.adapter.stable_id != candidate.primary.adapter.stable_id
            || p.secondary.as_ref().map(|s| &s.adapter.stable_id)
                != candidate.secondary.as_ref().map(|s| &s.adapter.stable_id)
    });

    let behavior_mode_changed = prev.is_some_and(|p| p.behavior_mode != candidate.behavior_mode);
    let prev_behavior_mode = prev.map(|p| p.behavior_mode);

    let RuleChanges {
        mut changes,
        prev_rules,
        next_rules,
    } = compute_rule_changes(prev, candidate);
    let rule_changes = &mut changes;
    rule_changes.sort_by(|a, b| {
        a.kind_order()
            .cmp(&b.kind_order())
            .then_with(|| a.content_sort_key().cmp(&b.content_sort_key()))
            .then_with(|| a.rule_id().0.as_str().cmp(b.rule_id().0.as_str()))
    });

    // Counted the way `rule_changes` is — every rule accounts for itself — so
    // the risk scorer's removal ratio divides like by like.
    let prev_total_rules = prev_rules as u32;
    let next_total_rules = next_rules as u32;

    let overlapping_apexes = collect_overlapping_apexes(candidate, rule_changes);
    let rule_changes = changes;

    StructuralDiff {
        binding_changed,
        behavior_mode_changed,
        prev_behavior_mode,
        next_behavior_mode: candidate.behavior_mode,
        rule_changes,
        prev_total_rules,
        next_total_rules,
        overlapping_apexes,
    }
}

/// Finds every apex label that has a `SuffixDomain`
/// rule (in either route set) AND at least one `ExactFqdn` rule whose
/// hostname is `apex` or ends with `.apex` (in either route set). The
/// overlap matters because the user is likely confused — the
/// SuffixDomain "wildcards everything under apex" would seem to
/// subsume the ExactFqdn, but the engine evaluates ExactFqdn first
/// (tier 1) and the two may route different ways if they live in
/// different sets.
///
/// Only overlaps THIS change touches are reported. Scoring the whole
/// candidate meant a set that already carried an overlap raised the same
/// signal on every later apply — including applies whose diff was empty —
/// so the review screen warned about something the user was not doing.
/// A standing overlap belongs to the rules screen's cleanup, not to the
/// path of an unrelated edit.
fn collect_overlapping_apexes(candidate: &CanonicalProfile, changes: &[RuleChange]) -> Vec<String> {
    use crate::canonical::CanonicalAddressMatch;
    use std::collections::BTreeSet;

    let mut suffix_apexes: BTreeSet<String> = BTreeSet::new();
    let mut exact_fqdns: Vec<String> = Vec::new();
    for set in [&candidate.rule_book.primary, &candidate.rule_book.secondary] {
        for rule in set.rules() {
            match rule.address_match.as_ref() {
                Some(CanonicalAddressMatch::SuffixDomain(label)) => {
                    suffix_apexes.insert(label.clone());
                }
                Some(CanonicalAddressMatch::ExactFqdn(host)) => {
                    exact_fqdns.push(host.clone());
                }
                _ => {}
            }
        }
    }

    // Hostnames the candidate side of this change carries. `Removed` is absent
    // on purpose: dropping one half of a pair ends an overlap, it never opens
    // one.
    let mut touched: BTreeSet<&str> = BTreeSet::new();
    for change in changes {
        let rule = match change {
            RuleChange::Added { rule, .. } | RuleChange::Retargeted { rule, .. } => rule,
            RuleChange::Modified { next, .. } => next,
            RuleChange::Removed { .. } => continue,
        };
        match rule.address_match.as_ref() {
            Some(CanonicalAddressMatch::SuffixDomain(label)) => {
                touched.insert(label.as_str());
            }
            Some(CanonicalAddressMatch::ExactFqdn(host)) => {
                touched.insert(host.as_str());
            }
            _ => {}
        }
    }

    let mut overlapping: BTreeSet<String> = BTreeSet::new();
    for apex in &suffix_apexes {
        let dotted_suffix = format!(".{apex}");
        for host in &exact_fqdns {
            let pairs = host == apex || host.ends_with(&dotted_suffix);
            if pairs && (touched.contains(apex.as_str()) || touched.contains(host.as_str())) {
                overlapping.insert(apex.clone());
                break;
            }
        }
    }
    overlapping.into_iter().collect()
}

/// Content-derived identity of a rule for diffing, deliberately
/// **excluding** the synthetic `r-NNNN` id, `enabled`, and `comment`.
///
/// Two rules are "the same rule" iff they match the same traffic — i.e.
/// they share an `address_match` and `app_match`. The synthetic id is NOT
/// part of the identity: it is regenerated on every import (the
/// preset-import path numbers `r-NNNN` independently per route, while the
/// rules-update path carries the GUI model's ids), so keying the diff on
/// the id makes re-importing an already-active preset report a full
/// add/remove churn even though the routing set is byte-identical. The
/// route role is *not* part of the key so that moving a rule between
/// routes surfaces as `Retargeted` rather than Removed+Added.
///
/// It names a group, not a rule: `x` and `x +block` share it, and
/// [`pair_identity_group`] decides which rule of the group is which.
///
/// `{:?}` over the two match `Option`s is a faithful, deterministic
/// content key: `CanonicalAddressMatch` / `CanonicalAppMatch` derive
/// `Eq`, so equal debug output ⟺ equal value within this crate.
pub fn rule_identity_key(rule: &CanonicalRule) -> String {
    rule_identity_key_under(rule, SubdomainCoverage::Off)
}

/// Whether the reader's subdomain-coverage setting ("a domain rule also covers
/// its subdomains") is on. It changes what "the same rule" means, so it is
/// named at every call site rather than passed as a bare `bool`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubdomainCoverage {
    /// A domain rule covers the apex only; `x` and `*.x` are two rules.
    Off,
    /// A domain rule covers the apex and every subdomain; `x` and `*.x` name
    /// one rule.
    On,
}

/// [`rule_identity_key`], with `x` and `*.x` folded into one identity when the
/// caller's subdomain coverage is on.
///
/// Under coverage an `ExactFqdn(d)` rule is enforced as `{ExactFqdn(d),
/// SuffixDomain(d)}`, and `SuffixDomain(d)` already covers the apex on both the
/// decision and the enforcement side, so the two forms match exactly the same
/// traffic — one rule wearing two spellings. Pairing them as one is what keeps
/// a file that says `*.x` from reading as a rule the service does not have.
pub fn rule_identity_key_under(rule: &CanonicalRule, coverage: SubdomainCoverage) -> String {
    let address = match (coverage, &rule.address_match) {
        (SubdomainCoverage::On, Some(CanonicalAddressMatch::ExactFqdn(d))) => {
            Some(CanonicalAddressMatch::SuffixDomain(d.clone()))
        }
        (_, other) => other.clone(),
    };
    format!("{:?}\u{1}{:?}", address, rule.app_match)
}

/// True when two rules with the same [`rule_identity_key`] and route differ
/// in any user-visible attribute (`enabled` / `comment` / `action`). The match
/// conditions are equal by construction (same identity key), so this only
/// inspects the mutable attributes — a change here is a `Modified`. Including
/// `action` here makes both review Modified-detection and merge
/// conflict-detection block-aware: toggling a rule between route and block is
/// a `Modified`, not an Add/Remove (identity stays match-only).
pub(crate) fn rule_attributes_differ(prev: &CanonicalRule, next: &CanonicalRule) -> bool {
    prev.enabled != next.enabled || prev.comment != next.comment || prev.action != next.action
}

/// Pairs the rules of one identity group (same [`rule_identity_key`]) across
/// two books; returns `(left, right)` indexes, `None` where a rule has no
/// counterpart.
///
/// A group can hold several rules — `x` next to `x +block`, or `x` next to
/// `*.x` under coverage — and each must survive as itself. The closest pair is
/// taken first: the same [`MatchKey`](crate::validation::MatchKey), then the
/// same route, action and enabled state, in that order. A group of one on each
/// side always pairs, which is what keeps a toggle a `Modified` rather than an
/// `Added` plus a `Removed`.
pub(crate) fn pair_identity_group(
    left: &[(&CanonicalRule, RouteRole)],
    right: &[(&CanonicalRule, RouteRole)],
) -> Vec<(Option<usize>, Option<usize>)> {
    use crate::validation::MatchKey;
    let affinity = |(l, lr): (&CanonicalRule, RouteRole), (r, rr): (&CanonicalRule, RouteRole)| {
        (u8::from(MatchKey::from_rule(l) == MatchKey::from_rule(r)) << 3)
            | (u8::from(lr == rr) << 2)
            | (u8::from(l.action == r.action) << 1)
            | u8::from(l.enabled == r.enabled)
    };

    let mut left_free = vec![true; left.len()];
    let mut right_free = vec![true; right.len()];
    let mut pairs = Vec::with_capacity(left.len().max(right.len()));
    loop {
        let mut best: Option<(u8, usize, usize)> = None;
        for (i, l) in left.iter().enumerate().filter(|(i, _)| left_free[*i]) {
            for (j, r) in right.iter().enumerate().filter(|(j, _)| right_free[*j]) {
                let score = affinity(*l, *r);
                if best.is_none_or(|(top, _, _)| score > top) {
                    best = Some((score, i, j));
                }
            }
        }
        let Some((_, i, j)) = best else { break };
        left_free[i] = false;
        right_free[j] = false;
        pairs.push((Some(i), Some(j)));
    }
    pairs.sort_unstable();
    pairs.extend(
        (0..left.len())
            .filter(|i| left_free[*i])
            .map(|i| (Some(i), None)),
    );
    pairs.extend(
        (0..right.len())
            .filter(|j| right_free[*j])
            .map(|j| (None, Some(j))),
    );
    pairs
}

/// Every rule of a profile grouped by [`rule_identity_key`], in canonical
/// order within each group.
fn identity_groups(
    profile: Option<&CanonicalProfile>,
) -> BTreeMap<String, Vec<(&CanonicalRule, RouteRole)>> {
    let mut groups: BTreeMap<String, Vec<(&CanonicalRule, RouteRole)>> = BTreeMap::new();
    if let Some(p) = profile {
        for (set, route) in [
            (&p.rule_book.primary, RouteRole::Primary),
            (&p.rule_book.secondary, RouteRole::Secondary),
        ] {
            for rule in set.rules() {
                groups
                    .entry(rule_identity_key(rule))
                    .or_default()
                    .push((rule, route));
            }
        }
    }
    groups
}

/// The diff, plus the two rule counts it was computed over. They travel
/// together because the risk scorer forms a ratio out of them: taken from
/// anywhere else the numerator and the denominator count different things.
struct RuleChanges {
    changes: Vec<RuleChange>,
    prev_rules: usize,
    next_rules: usize,
}

fn compute_rule_changes(
    prev: Option<&CanonicalProfile>,
    candidate: &CanonicalProfile,
) -> RuleChanges {
    let prev_groups = identity_groups(prev);
    let next_groups = identity_groups(Some(candidate));
    let count = |groups: &BTreeMap<String, Vec<_>>| groups.values().map(Vec::len).sum();
    let (prev_rules, next_rules) = (count(&prev_groups), count(&next_groups));

    let mut keys: Vec<&String> = prev_groups.keys().chain(next_groups.keys()).collect();
    keys.sort();
    keys.dedup();

    let mut changes = Vec::new();
    for key in keys {
        let before = prev_groups.get(key).map(Vec::as_slice).unwrap_or_default();
        let after = next_groups.get(key).map(Vec::as_slice).unwrap_or_default();
        for pair in pair_identity_group(before, after) {
            match pair {
                (Some(i), Some(j)) => {
                    let ((prev_rule, prev_route), (next_rule, next_route)) = (before[i], after[j]);
                    if prev_route != next_route {
                        changes.push(RuleChange::Retargeted {
                            rule: next_rule.clone(),
                            from: prev_route,
                            to: next_route,
                        });
                    } else if rule_attributes_differ(prev_rule, next_rule) {
                        changes.push(RuleChange::Modified {
                            prev: prev_rule.clone(),
                            next: next_rule.clone(),
                            route: next_route,
                        });
                    }
                }
                (Some(i), None) => changes.push(RuleChange::Removed {
                    rule: before[i].0.clone(),
                    route: before[i].1,
                }),
                (None, Some(j)) => changes.push(RuleChange::Added {
                    rule: after[j].0.clone(),
                    route: after[j].1,
                }),
                (None, None) => {}
            }
        }
    }

    RuleChanges {
        changes,
        prev_rules,
        next_rules,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::{
        canonical::{CanonicalAddressMatch, CanonicalRule, CanonicalRuleBook, CanonicalRuleSet},
        revision::{ContentHash, RevisionId, UnixTimestamp},
        AdapterIdentity, BindingSource, RouteBinding,
    };

    // ── helpers ──────────────────────────────────────────────────────────────

    /// Added, removed, and modified-or-retargeted changes.
    fn counts(diff: &StructuralDiff) -> (usize, usize, usize) {
        let count = |f: fn(&RuleChange) -> bool| diff.rule_changes.iter().filter(|c| f(c)).count();
        (
            count(RuleChange::is_added),
            count(RuleChange::is_removed),
            count(RuleChange::is_modified_or_retargeted),
        )
    }

    fn fqdn_rule(id: &str, fqdn: &str) -> CanonicalRule {
        CanonicalRule {
            id: RuleId(id.to_string()),
            enabled: true,
            address_match: Some(CanonicalAddressMatch::ExactFqdn(fqdn.to_string())),
            app_match: None,
            comment: String::new(),
            action: crate::canonical::RuleAction::Route,
            origin: None,
        }
    }

    fn suffix_rule(id: &str, label: &str) -> CanonicalRule {
        CanonicalRule {
            id: RuleId(id.to_string()),
            enabled: true,
            address_match: Some(CanonicalAddressMatch::SuffixDomain(label.to_string())),
            app_match: None,
            comment: String::new(),
            action: crate::canonical::RuleAction::Route,
            origin: None,
        }
    }

    fn make_profile(
        primary_rules: Vec<CanonicalRule>,
        secondary_rules: Vec<CanonicalRule>,
    ) -> CanonicalProfile {
        CanonicalProfile {
            primary: RouteBinding {
                role: RouteRole::Primary,
                adapter: AdapterIdentity {
                    stable_id: "adapter-primary-001".to_string(),
                    display_name: "Primary".to_string(),
                },
                source: BindingSource::UserAssigned,
            },
            secondary: Some(RouteBinding {
                role: RouteRole::Secondary,
                adapter: AdapterIdentity {
                    stable_id: "adapter-secondary-001".to_string(),
                    display_name: "Secondary".to_string(),
                },
                source: BindingSource::UserAssigned,
            }),
            behavior_mode: RouteBehaviorMode::StrictSecondaryFailClosed,
            rule_book: CanonicalRuleBook {
                primary: CanonicalRuleSet::from_rules(primary_rules),
                secondary: CanonicalRuleSet::from_rules(secondary_rules),
            },
        }
    }

    fn make_token(candidate_id: &str, active_hash_byte: Option<u8>) -> ConfirmationToken {
        ConfirmationToken {
            candidate_id: RevisionId::from_prefixed_string(candidate_id.to_string())
                .expect("valid id"),
            active_hash_at_open: active_hash_byte.map(|b| ContentHash::from_bytes([b; 32])),
            opened_at: UnixTimestamp::from_secs(1_700_000_000),
        }
    }

    fn rev_id(s: &str) -> RevisionId {
        RevisionId::from_prefixed_string(s.to_string()).expect("valid id")
    }

    // ── compute_diff ─────────────────────────────────────────────────────────

    /// The risk scorer divides removed entries by `prev_total_rules`, so both
    /// count the same thing: rules. A copy named on the other route is a rule
    /// of its own, and removing it is a removal.
    #[test]
    fn the_rule_totals_are_counted_the_way_the_changes_are() {
        let shared = fqdn_rule("r-1", "corp.example.com");
        let prev = make_profile(
            vec![shared.clone(), fqdn_rule("r-2", "other.example.com")],
            vec![shared],
        );
        let candidate = make_profile(vec![fqdn_rule("r-1", "corp.example.com")], vec![]);
        let diff = compute_diff(Some(&prev), &candidate);
        assert_eq!(diff.prev_total_rules, 3);
        assert_eq!(diff.next_total_rules, 1);

        let removed = diff
            .rule_changes
            .iter()
            .filter(|c| matches!(c, RuleChange::Removed { .. }))
            .count();
        assert_eq!(removed, 2, "the other host and the secondary copy");
        assert_eq!(diff.rule_changes.len(), 2, "the primary copy is unchanged");
        assert!(removed as u32 * 100 / diff.prev_total_rules >= 50);
    }

    /// `x` and `x +block` are two rules; the diff used to key both on the
    /// address and lose one of them.
    #[test]
    fn adding_a_block_rule_beside_a_route_rule_for_the_same_host_is_one_addition() {
        let prev = make_profile(vec![fqdn_rule("r-1", "shop.test")], vec![]);
        let mut block = fqdn_rule("r-2", "shop.test");
        block.action = crate::canonical::RuleAction::Block;
        let next = make_profile(vec![fqdn_rule("r-1", "shop.test"), block], vec![]);

        let diff = compute_diff(Some(&prev), &next);
        assert_eq!(diff.rule_changes.len(), 1, "{:?}", diff.rule_changes);
        assert!(matches!(
            &diff.rule_changes[0],
            RuleChange::Added { rule, .. } if rule.action == crate::canonical::RuleAction::Block
        ));

        let back = compute_diff(Some(&next), &prev);
        assert_eq!(back.rule_changes.len(), 1);
        assert!(back.rule_changes[0].is_removed());
    }

    /// With two rules under one address each change lands on its own rule: a
    /// toggled block rule is a `Modified`, and its route twin is untouched.
    #[test]
    fn toggling_one_of_two_rules_for_a_host_modifies_only_that_rule() {
        let mut block = fqdn_rule("r-2", "shop.test");
        block.action = crate::canonical::RuleAction::Block;
        let prev = make_profile(vec![fqdn_rule("r-1", "shop.test"), block.clone()], vec![]);
        block.enabled = false;
        let next = make_profile(vec![fqdn_rule("r-1", "shop.test"), block], vec![]);

        let diff = compute_diff(Some(&prev), &next);
        assert_eq!(diff.rule_changes.len(), 1, "{:?}", diff.rule_changes);
        assert!(matches!(
            &diff.rule_changes[0],
            RuleChange::Modified { next, .. }
                if next.action == crate::canonical::RuleAction::Block && !next.enabled
        ));
    }

    /// A single rule toggled between route and block is still one `Modified`,
    /// never an `Added` plus a `Removed`.
    #[test]
    fn a_route_to_block_toggle_stays_a_modification() {
        let prev = make_profile(vec![fqdn_rule("r-1", "shop.test")], vec![]);
        let mut block = fqdn_rule("r-1", "shop.test");
        block.action = crate::canonical::RuleAction::Block;
        let next = make_profile(vec![block], vec![]);
        assert_eq!(counts(&compute_diff(Some(&prev), &next)), (0, 0, 1));
    }

    /// The diff reads spellings literally: adding `*.x` next to `x` is one
    /// addition and leaves `x` alone.
    #[test]
    fn adding_the_wildcard_beside_the_apex_is_one_addition() {
        let prev = make_profile(vec![fqdn_rule("r-1", "proflcdn.test")], vec![]);
        let next = make_profile(
            vec![
                fqdn_rule("r-1", "proflcdn.test"),
                suffix_rule("r-2", "proflcdn.test"),
            ],
            vec![],
        );
        let diff = compute_diff(Some(&prev), &next);
        assert_eq!(diff.rule_changes.len(), 1);
        assert!(diff.rule_changes[0].is_added());
    }

    #[test]
    fn diff_identical_profiles_is_empty() {
        let profile = make_profile(vec![fqdn_rule("r-1", "corp.example.com")], vec![]);
        let diff = compute_diff(Some(&profile), &profile);
        assert!(diff.is_empty());
    }

    #[test]
    fn diff_identical_content_with_different_ids_is_empty() {
        // Re-importing an already-active preset
        // must report NO changes even though the import path regenerates
        // synthetic `r-NNNN` ids. The diff keys on content, not id.
        let prev = make_profile(
            vec![
                fqdn_rule("r-0000", "a.com"),
                suffix_rule("r-0001", "example.com"),
            ],
            vec![fqdn_rule("r-0000", "z.org")],
        );
        // Same rules, same routes, *different* ids (as a fresh parse / a
        // rules-update round-trip would assign).
        let next = make_profile(
            vec![
                fqdn_rule("r-42", "a.com"),
                suffix_rule("r-99", "example.com"),
            ],
            vec![fqdn_rule("svc-7", "z.org")],
        );
        let diff = compute_diff(Some(&prev), &next);
        assert!(
            diff.rule_changes.is_empty(),
            "identical content with renumbered ids must produce no rule changes, got {:?}",
            diff.rule_changes
        );
        assert!(diff.is_empty());
    }

    #[test]
    fn diff_retarget_survives_id_renumbering() {
        // A rule moved primary→secondary is a Retarget even when its id
        // also changed across the import.
        let prev = make_profile(vec![fqdn_rule("r-0000", "corp.net")], vec![]);
        let next = make_profile(vec![], vec![fqdn_rule("r-9", "corp.net")]);
        let diff = compute_diff(Some(&prev), &next);
        assert_eq!(diff.rule_changes.len(), 1);
        assert!(matches!(
            diff.rule_changes.first(),
            Some(RuleChange::Retargeted {
                from: RouteRole::Primary,
                to: RouteRole::Secondary,
                ..
            })
        ));
    }

    #[test]
    fn diff_modified_detected_despite_id_change() {
        // Same target + route, `enabled` toggled, id renumbered → Modified.
        let prev = make_profile(vec![fqdn_rule("r-0000", "a.com")], vec![]);
        let mut modified = fqdn_rule("r-77", "a.com");
        modified.enabled = false;
        let next = make_profile(vec![modified], vec![]);
        assert_eq!(counts(&compute_diff(Some(&prev), &next)), (0, 0, 1));
    }

    #[test]
    fn diff_no_prev_reports_all_rules_as_added() {
        let candidate = make_profile(
            vec![fqdn_rule("r-1", "corp.example.com")],
            vec![fqdn_rule("r-2", "updates.example.org")],
        );
        let diff = compute_diff(None, &candidate);
        assert!(
            !diff.binding_changed,
            "no prev → no binding change reported"
        );
        assert!(
            !diff.behavior_mode_changed,
            "no prev → no behavior change reported"
        );
        assert_eq!(diff.rule_changes.len(), 2);
        assert!(diff.rule_changes.iter().all(|c| c.is_added()));
        assert!(diff.prev_behavior_mode.is_none());
    }

    #[test]
    fn diff_added_rule_detected() {
        let prev = make_profile(vec![fqdn_rule("r-1", "a.com")], vec![]);
        let next = make_profile(
            vec![fqdn_rule("r-1", "a.com"), fqdn_rule("r-2", "b.com")],
            vec![],
        );
        assert_eq!(counts(&compute_diff(Some(&prev), &next)), (1, 0, 0));
    }

    #[test]
    fn diff_removed_rule_detected() {
        let prev = make_profile(
            vec![fqdn_rule("r-1", "a.com"), fqdn_rule("r-2", "b.com")],
            vec![],
        );
        let next = make_profile(vec![fqdn_rule("r-1", "a.com")], vec![]);
        assert_eq!(counts(&compute_diff(Some(&prev), &next)), (0, 1, 0));
    }

    #[test]
    fn diff_modified_rule_detected() {
        let prev = make_profile(vec![fqdn_rule("r-1", "a.com")], vec![]);
        let mut modified = fqdn_rule("r-1", "a.com");
        modified.enabled = false; // toggle enabled state
        let next = make_profile(vec![modified], vec![]);
        assert_eq!(counts(&compute_diff(Some(&prev), &next)), (0, 0, 1));
    }

    #[test]
    fn diff_retargeted_rule_detected() {
        let prev = make_profile(vec![fqdn_rule("r-1", "corp.example.net")], vec![]);
        let next = make_profile(vec![], vec![fqdn_rule("r-1", "corp.example.net")]);
        let diff = compute_diff(Some(&prev), &next);
        assert_eq!(counts(&diff), (0, 0, 1));
        assert!(matches!(
            diff.rule_changes.first(),
            Some(RuleChange::Retargeted {
                from: RouteRole::Primary,
                to: RouteRole::Secondary,
                ..
            })
        ));
    }

    #[test]
    fn diff_behavior_mode_change_detected() {
        let prev = make_profile(vec![], vec![]);
        let mut next = make_profile(vec![], vec![]);
        next.behavior_mode = RouteBehaviorMode::PreferPrimary;
        let diff = compute_diff(Some(&prev), &next);
        assert!(diff.behavior_mode_changed);
        assert_eq!(
            diff.prev_behavior_mode,
            Some(RouteBehaviorMode::StrictSecondaryFailClosed)
        );
        assert_eq!(diff.next_behavior_mode, RouteBehaviorMode::PreferPrimary);
    }

    #[test]
    fn diff_binding_change_detected() {
        let prev = make_profile(vec![], vec![]);
        let mut next = make_profile(vec![], vec![]);
        next.primary.adapter.stable_id = "adapter-different-999".to_string();
        let diff = compute_diff(Some(&prev), &next);
        assert!(diff.binding_changed);
    }

    #[test]
    fn diff_rule_changes_sorted_added_before_removed_before_modified() {
        let prev = make_profile(
            vec![
                fqdn_rule("r-remove", "remove.com"),
                fqdn_rule("r-mod", "mod.com"),
            ],
            vec![],
        );
        let mut modified_rule = fqdn_rule("r-mod", "mod.com");
        modified_rule.enabled = false;
        let next = make_profile(vec![fqdn_rule("r-new", "new.com"), modified_rule], vec![]);
        let diff = compute_diff(Some(&prev), &next);
        // Expected order: Added(r-new), Removed(r-remove), Modified(r-mod)
        assert_eq!(diff.rule_changes.len(), 3);
        assert!(diff.rule_changes[0].is_added());
        assert!(diff.rule_changes[1].is_removed());
        assert!(diff.rule_changes[2].is_modified_or_retargeted());
    }

    #[test]
    fn diff_broad_suffix_domain_appears_in_review_summary() {
        let prev = make_profile(vec![], vec![]);
        let next = make_profile(vec![suffix_rule("r-1", "com")], vec![]);
        let diff = compute_diff(Some(&prev), &next);
        let review = diff.to_review_summary();
        assert_eq!(review.rules_added.len(), 1);
        // suffix domain display uses *.prefix
        assert!(review.rules_added[0].display.contains("*.com"));
    }

    /// The review list has to distinguish "added and enforced" from "added and
    /// inert" — a disabled rule reaches the service and shows up in the diff
    /// exactly like an enabled one, but routes nothing.
    #[test]
    fn diff_review_summary_carries_the_enabled_state_of_each_entry() {
        let prev = make_profile(vec![], vec![]);
        let mut disabled = fqdn_rule("r-off", "off.example");
        disabled.enabled = false;
        let next = make_profile(vec![fqdn_rule("r-on", "on.example"), disabled], vec![]);
        let review = compute_diff(Some(&prev), &next).to_review_summary();
        assert_eq!(review.rules_added.len(), 2);
        let entry = |id: &str| {
            review
                .rules_added
                .iter()
                .find(|e| e.id == id)
                .expect("entry present")
        };
        assert!(entry("r-on").enabled);
        assert!(!entry("r-off").enabled);
    }

    #[test]
    fn diff_to_review_summary_empty_when_no_changes() {
        let profile = make_profile(vec![fqdn_rule("r-1", "a.com")], vec![]);
        let diff = compute_diff(Some(&profile), &profile);
        let review = diff.to_review_summary();
        assert!(review.is_empty());
        assert_eq!(review.total_rule_changes(), 0);
    }

    #[test]
    fn diff_retargeted_display_shows_route_direction() {
        let prev = make_profile(vec![fqdn_rule("r-1", "corp.net")], vec![]);
        let next = make_profile(vec![], vec![fqdn_rule("r-1", "corp.net")]);
        let diff = compute_diff(Some(&prev), &next);
        let review = diff.to_review_summary();
        assert_eq!(review.rules_retargeted.len(), 1);
        assert!(review.rules_retargeted[0].display.contains("primary"));
        assert!(review.rules_retargeted[0].display.contains("secondary"));
    }

    // ── check_confirmation ────────────────────────────────────────────────────

    #[test]
    fn confirmation_ok_when_pending_matches_and_active_unchanged() {
        let token = make_token("rev-candidate-001", Some(0xAA));
        let active_hash = ContentHash::from_bytes([0xAA; 32]);
        let pending_id = rev_id("rev-candidate-001");
        let result = check_confirmation(&token, Some(&active_hash), Some(&pending_id));
        assert!(matches!(result, ConfirmationResult::Confirmed { .. }));
    }

    #[test]
    fn confirmation_stale_when_active_hash_changed() {
        let token = make_token("rev-candidate-001", Some(0xAA));
        let new_active_hash = ContentHash::from_bytes([0xBB; 32]); // different from token
        let pending_id = rev_id("rev-candidate-001");
        let result = check_confirmation(&token, Some(&new_active_hash), Some(&pending_id));
        assert!(matches!(result, ConfirmationResult::Stale { .. }));
    }

    #[test]
    fn confirmation_stale_when_active_appeared_after_review_opened_with_no_active() {
        let token = make_token("rev-candidate-001", None); // no active when opened
        let active_hash = ContentHash::from_bytes([0xCC; 32]);
        let pending_id = rev_id("rev-candidate-001");
        let result = check_confirmation(&token, Some(&active_hash), Some(&pending_id));
        assert!(matches!(result, ConfirmationResult::Stale { .. }));
    }

    #[test]
    fn confirmation_superseded_when_different_pending_id() {
        let token = make_token("rev-candidate-001", Some(0xAA));
        let active_hash = ContentHash::from_bytes([0xAA; 32]);
        let different_pending = rev_id("rev-candidate-002"); // different candidate now pending
        let result = check_confirmation(&token, Some(&active_hash), Some(&different_pending));
        assert!(matches!(result, ConfirmationResult::Superseded));
    }

    #[test]
    fn confirmation_superseded_when_no_pending() {
        let token = make_token("rev-candidate-001", Some(0xAA));
        let active_hash = ContentHash::from_bytes([0xAA; 32]);
        let result = check_confirmation(&token, Some(&active_hash), None);
        assert!(matches!(result, ConfirmationResult::Superseded));
    }

    #[test]
    fn confirmation_superseded_checked_before_staleness() {
        // Both pending ID mismatch AND active hash changed → Superseded wins
        let token = make_token("rev-candidate-001", Some(0xAA));
        let different_active = ContentHash::from_bytes([0xBB; 32]);
        let different_pending = rev_id("rev-candidate-002");
        let result = check_confirmation(&token, Some(&different_active), Some(&different_pending));
        assert!(matches!(result, ConfirmationResult::Superseded));
    }

    #[test]
    fn confirmation_confirmed_candidate_id_matches_token() {
        let token = make_token("rev-candidate-042", Some(0x11));
        let active_hash = ContentHash::from_bytes([0x11; 32]);
        let pending_id = rev_id("rev-candidate-042");
        let result = check_confirmation(&token, Some(&active_hash), Some(&pending_id));
        if let ConfirmationResult::Confirmed { candidate_id } = result {
            assert_eq!(candidate_id.as_str(), "rev-candidate-042");
        } else {
            panic!("expected Confirmed");
        }
    }
}
