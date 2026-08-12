//! Review flow and diff engine for candidate policy revisions.
//!
//! # Data flow
//!
//! 1. [`compute_diff`]`(prev, candidate)` → [`StructuralDiff`]
//! 2. [`StructuralDiff::to_revision_summary`] → [`RevisionDiffSummary`] (stored on [`PolicyRevision`])
//! 3. [`StructuralDiff::to_review_summary`] → [`ReviewSummary`] (shown in the review UI)
//! 4. [`check_confirmation`]`(token, ...)` → [`ConfirmationResult`]
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

use std::collections::HashMap;

use crate::{
    canonical::{CanonicalProfile, CanonicalRule},
    revision::{ContentHash, RevisionDiffSummary, RevisionId, UnixTimestamp},
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
    fn is_added(&self) -> bool {
        matches!(self, Self::Added { .. })
    }
    fn is_removed(&self) -> bool {
        matches!(self, Self::Removed { .. })
    }
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
/// [`to_review_summary`](Self::to_review_summary) or to the compact revision
/// metadata with [`to_revision_summary`](Self::to_revision_summary).
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

    /// Converts this diff to the compact [`RevisionDiffSummary`] stored on
    /// [`PolicyRevision`](crate::revision::PolicyRevision).
    pub fn to_revision_summary(&self) -> RevisionDiffSummary {
        RevisionDiffSummary {
            changed_interface_bindings: self.binding_changed,
            changed_default_behavior: self.behavior_mode_changed,
            changed_rules: !self.rule_changes.is_empty(),
            rules_added: self.rule_changes.iter().filter(|c| c.is_added()).count() as u32,
            rules_removed: self.rule_changes.iter().filter(|c| c.is_removed()).count() as u32,
            rules_modified: self
                .rule_changes
                .iter()
                .filter(|c| c.is_modified_or_retargeted())
                .count() as u32,
        }
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

    let mut rule_changes = compute_rule_changes(prev, candidate);
    rule_changes.sort_by(|a, b| {
        a.kind_order()
            .cmp(&b.kind_order())
            .then_with(|| a.content_sort_key().cmp(&b.content_sort_key()))
            .then_with(|| a.rule_id().0.as_str().cmp(b.rule_id().0.as_str()))
    });

    let prev_total_rules = prev
        .map(|p| (p.rule_book.primary.len() + p.rule_book.secondary.len()) as u32)
        .unwrap_or(0);
    let next_total_rules =
        (candidate.rule_book.primary.len() + candidate.rule_book.secondary.len()) as u32;

    let overlapping_apexes = collect_overlapping_apexes(candidate);

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
fn collect_overlapping_apexes(candidate: &CanonicalProfile) -> Vec<String> {
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

    let mut overlapping: BTreeSet<String> = BTreeSet::new();
    for apex in &suffix_apexes {
        let dotted_suffix = format!(".{apex}");
        for host in &exact_fqdns {
            if host == apex || host.ends_with(&dotted_suffix) {
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
/// `{:?}` over the two match `Option`s is a faithful, deterministic
/// content key: `CanonicalAddressMatch` / `CanonicalAppMatch` derive
/// `Eq`, so equal debug output ⟺ equal value within this crate.
pub(crate) fn rule_identity_key(rule: &CanonicalRule) -> String {
    format!("{:?}\u{1}{:?}", rule.address_match, rule.app_match)
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

fn build_identity_map(
    profile: Option<&CanonicalProfile>,
) -> HashMap<String, (CanonicalRule, RouteRole)> {
    profile
        .map(|p| {
            p.rule_book
                .primary
                .rules()
                .iter()
                .map(|r| (rule_identity_key(r), (r.clone(), RouteRole::Primary)))
                .chain(
                    p.rule_book
                        .secondary
                        .rules()
                        .iter()
                        .map(|r| (rule_identity_key(r), (r.clone(), RouteRole::Secondary))),
                )
                .collect()
        })
        .unwrap_or_default()
}

fn compute_rule_changes(
    prev: Option<&CanonicalProfile>,
    candidate: &CanonicalProfile,
) -> Vec<RuleChange> {
    let prev_map = build_identity_map(prev);
    let next_map = build_identity_map(Some(candidate));

    let mut changes = Vec::new();

    for (key, (next_rule, next_route)) in &next_map {
        match prev_map.get(key) {
            None => changes.push(RuleChange::Added {
                rule: next_rule.clone(),
                route: *next_route,
            }),
            Some((_prev_rule, prev_route)) if prev_route != next_route => {
                changes.push(RuleChange::Retargeted {
                    rule: next_rule.clone(),
                    from: *prev_route,
                    to: *next_route,
                });
            }
            Some((prev_rule, _)) if rule_attributes_differ(prev_rule, next_rule) => {
                changes.push(RuleChange::Modified {
                    prev: prev_rule.clone(),
                    next: next_rule.clone(),
                    route: *next_route,
                });
            }
            Some(_) => {} // identical content + route — no change
        }
    }

    for (key, (rule, route)) in &prev_map {
        if !next_map.contains_key(key) {
            changes.push(RuleChange::Removed {
                rule: rule.clone(),
                route: *route,
            });
        }
    }

    changes
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
        let summary = compute_diff(Some(&prev), &next).to_revision_summary();
        assert_eq!(summary.rules_modified, 1);
        assert_eq!(summary.rules_added, 0);
        assert_eq!(summary.rules_removed, 0);
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
        let diff = compute_diff(Some(&prev), &next);
        let summary = diff.to_revision_summary();
        assert_eq!(summary.rules_added, 1);
        assert_eq!(summary.rules_removed, 0);
        assert_eq!(summary.rules_modified, 0);
    }

    #[test]
    fn diff_removed_rule_detected() {
        let prev = make_profile(
            vec![fqdn_rule("r-1", "a.com"), fqdn_rule("r-2", "b.com")],
            vec![],
        );
        let next = make_profile(vec![fqdn_rule("r-1", "a.com")], vec![]);
        let diff = compute_diff(Some(&prev), &next);
        let summary = diff.to_revision_summary();
        assert_eq!(summary.rules_added, 0);
        assert_eq!(summary.rules_removed, 1);
        assert_eq!(summary.rules_modified, 0);
    }

    #[test]
    fn diff_modified_rule_detected() {
        let prev = make_profile(vec![fqdn_rule("r-1", "a.com")], vec![]);
        let mut modified = fqdn_rule("r-1", "a.com");
        modified.enabled = false; // toggle enabled state
        let next = make_profile(vec![modified], vec![]);
        let diff = compute_diff(Some(&prev), &next);
        let summary = diff.to_revision_summary();
        assert_eq!(summary.rules_modified, 1);
        assert_eq!(summary.rules_added, 0);
        assert_eq!(summary.rules_removed, 0);
    }

    #[test]
    fn diff_retargeted_rule_detected() {
        let prev = make_profile(vec![fqdn_rule("r-1", "corp.example.net")], vec![]);
        let next = make_profile(vec![], vec![fqdn_rule("r-1", "corp.example.net")]);
        let diff = compute_diff(Some(&prev), &next);
        let summary = diff.to_revision_summary();
        // retargeted counts as modified
        assert_eq!(summary.rules_modified, 1);
        assert_eq!(summary.rules_added, 0);
        assert_eq!(summary.rules_removed, 0);
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
    fn diff_to_revision_summary_changed_rules_flag() {
        let prev = make_profile(vec![], vec![]);
        let next = make_profile(vec![fqdn_rule("r-1", "a.com")], vec![]);
        let diff = compute_diff(Some(&prev), &next);
        let summary = diff.to_revision_summary();
        assert!(summary.changed_rules);
        assert!(summary.changed_interface_bindings == diff.binding_changed);
        assert!(summary.changed_default_behavior == diff.behavior_mode_changed);
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
