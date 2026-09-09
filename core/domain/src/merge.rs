//! Two-way rule-set merge — reconcile a linked rules file with the active
//! service revision.
//!
//! # Why
//!
//! A user can edit the linked `.txt` files (`rules_primary.txt` /
//! `rules_secondary.txt`) *or* apply changes in the app, so the file and the
//! active service revision diverge. [`merge_rule_books`] reconciles the two
//! into one [`MergeResult`] whose [`merged`](MergeResult::merged) book feeds
//! straight into the normal rules-review + apply flow — the service stays the
//! single writer.
//!
//! # Identity and safety model
//!
//! Rules are paired by [`rule_identity_key`](crate::review::rule_identity_key)
//! — the traffic they match (`address_match` + `app_match`), **not** the
//! synthetic `r-NNNN` id (which is regenerated on every import). The route
//! role is tracked separately, so the *same* rule assigned to a *different*
//! route surfaces as a conflict rather than an add/remove churn.
//!
//! Pairing follows the reader's subdomain coverage
//! ([`SubdomainCoverage`](crate::review::SubdomainCoverage)): with it on, `x`
//! and `*.x` enforce the same traffic and therefore pair as one rule, and the
//! side that only differs in spelling keeps the service's.
//!
//! **Presence is always a union.** A rule present on only one side is always
//! kept, under every policy. Without a common ancestor we cannot distinguish
//! "the file deleted this rule" from "the service added it", so we never drop
//! — the safe default. Deletion-aware three-way merge (using a persisted
//! last-reconciled base) is a deliberate future extension.
//!
//! Policies therefore differ **only** in how they resolve a *conflict* (a rule
//! present on both sides but with a different route, enabled state, or
//! comment):
//! - [`MergePolicy::Union`] keeps the file side provisionally and flags the
//!   conflict as [`ConflictSide::Unresolved`] for the user to decide. This is
//!   the safe interactive default.
//! - [`MergePolicy::FileWins`] takes the file side and marks it resolved.
//! - [`MergePolicy::ServiceWins`] takes the service side and marks it resolved.
//!
//! The function is pure and deterministic: identical inputs yield identical
//! output and ordering (keys are processed in sorted order).

use std::collections::{BTreeMap, BTreeSet};

use crate::canonical::{CanonicalRule, CanonicalRuleBook, CanonicalRuleSet, RuleAction};
use crate::review::{rule_attributes_differ, rule_identity_key_under, SubdomainCoverage};
use crate::RouteRole;

/// How a merge resolves rules that exist on both sides but differ.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MergePolicy {
    /// Keep every rule; flag each both-sides-differ case as an unresolved
    /// conflict for the user to pick. The safe interactive default.
    Union,
    /// The linked file is authoritative for conflicts.
    FileWins,
    /// The active service revision is authoritative for conflicts.
    ServiceWins,
}

impl MergePolicy {
    /// Parse a wire/preference slug (`union` / `file-wins` / `service-wins`).
    /// Unknown input falls back to the safe [`MergePolicy::Union`] default.
    pub fn from_slug(slug: &str) -> Self {
        match slug {
            "file-wins" => Self::FileWins,
            "service-wins" => Self::ServiceWins,
            _ => Self::Union,
        }
    }

    /// Stable slug for storage / the wire.
    pub fn slug(self) -> &'static str {
        match self {
            Self::Union => "union",
            Self::FileWins => "file-wins",
            Self::ServiceWins => "service-wins",
        }
    }
}

/// Which side(s) a merged rule came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MergeOrigin {
    /// Present only in the linked file.
    FileOnly,
    /// Present only in the service revision.
    ServiceOnly,
    /// Present on both sides (identical, or a resolved conflict).
    Both,
}

/// Which side a conflict was resolved in favour of.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConflictSide {
    /// The linked file's version was chosen.
    File,
    /// The service revision's version was chosen.
    Service,
    /// Not auto-resolved (Union policy) — awaiting a user choice.
    Unresolved,
}

/// One side of a conflict, in a form suitable for a review UI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConflictRule {
    /// Route this side binds the rule to.
    pub route: RouteRole,
    /// Enabled state on this side.
    pub enabled: bool,
    /// Enforcement action on this side (route vs. hard block). A route↔block
    /// toggle is a conflict whose two sides are otherwise identical, so the
    /// action must be carried per side or the UI shows a "difference" with no
    /// visible distinction.
    pub action: RuleAction,
    /// Comment on this side.
    pub comment: String,
}

impl ConflictRule {
    fn of(rule: &CanonicalRule, route: RouteRole) -> Self {
        Self {
            route,
            enabled: rule.enabled,
            action: rule.action,
            comment: rule.comment.clone(),
        }
    }
}

/// A rule present on both sides but with a different route, enabled state, or
/// comment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MergeConflict {
    /// Content identity of the rule (stable across id regeneration).
    pub identity_key: String,
    /// A representative rule (the file side) carrying the match conditions so
    /// the review UI can render the rule's type and value. The match is equal
    /// on both sides by construction (they share an [`identity_key`]); only the
    /// mutable attributes (route / enabled / action / comment) differ.
    ///
    /// [`identity_key`]: MergeConflict::identity_key
    pub rule: CanonicalRule,
    /// The file-side version.
    pub file: ConflictRule,
    /// The service-side version.
    pub service: ConflictRule,
    /// Which side the merge chose (or [`ConflictSide::Unresolved`] under Union).
    pub resolved: ConflictSide,
}

/// Provenance for one rule in the merged output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MergedRuleEntry {
    /// Content identity of the rule.
    pub identity_key: String,
    /// The full merged rule as it lands in the output book — carries the match
    /// conditions, action, enabled state and comment so a review UI can render
    /// the bucket row without re-indexing the source books.
    pub rule: CanonicalRule,
    /// Route the merged rule is bound to.
    pub route: RouteRole,
    /// Which side(s) the rule came from.
    pub origin: MergeOrigin,
    /// `true` when this entry came from a both-sides-differ conflict.
    pub was_conflict: bool,
}

/// Outcome of [`merge_rule_books`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MergeResult {
    /// The reconciled rule book, ready for the rules-review + apply flow.
    pub merged: CanonicalRuleBook,
    /// Per-rule provenance, in deterministic order (by identity key).
    pub entries: Vec<MergedRuleEntry>,
    /// The subset of `entries` that were both-sides-differ conflicts.
    pub conflicts: Vec<MergeConflict>,
    /// Matches that were named in both route sets of one of the two input
    /// books, with the secondary-route copy switched off so the book had one
    /// answer. Reported, never hidden: the merge flow does not stop to ask
    /// (the person merging is busy with something else and often did not write
    /// the file), so the choice is made and then shown, one click from being
    /// changed.
    pub normalized_duplicates: Vec<NormalizedCrossSetRule>,
}

impl MergeResult {
    /// `true` when the two books were already identical (nothing to reconcile).
    ///
    /// A normalised duplicate counts as something to reconcile even when every
    /// entry came from both sides: the merged book has a rule switched off that
    /// neither input had switched off, and reporting that as "nothing to do"
    /// would hide the one change the user is meant to be shown.
    pub fn is_noop(&self) -> bool {
        self.conflicts.is_empty()
            && self.normalized_duplicates.is_empty()
            && self.entries.iter().all(|e| e.origin == MergeOrigin::Both)
    }

    /// Conflicts still awaiting a user decision (Union policy only).
    pub fn unresolved_conflicts(&self) -> usize {
        self.conflicts
            .iter()
            .filter(|c| c.resolved == ConflictSide::Unresolved)
            .count()
    }
}

/// Per-side view of a rule, keyed by content identity.
struct Side {
    rule: CanonicalRule,
    route: RouteRole,
}

/// Index a rule book by content identity. Both route sets are walked; the
/// route role is carried alongside so a retarget can be detected.
///
/// One identity gets one entry — that is what makes "the same rule moved to the
/// other route" expressible at all, and it is why the key cannot also carry the
/// route. A book CAN name the same match in both sets (validation reports that,
/// it does not reject it), so the choice is made here rather than left to
/// whichever copy happened to be met first: **an enabled copy always wins**.
/// [`normalize_cross_set_duplicates`] has already ensured at most one copy is
/// enabled, so the rule that is actually enforced is the one that survives, and
/// the merge cannot drop an enforced rule. Two disabled copies enforce nothing
/// either way; the first in canonical order wins, deterministically.
fn index(book: &CanonicalRuleBook, coverage: SubdomainCoverage) -> BTreeMap<String, Side> {
    let mut map: BTreeMap<String, Side> = BTreeMap::new();
    for (set, route) in [
        (&book.primary, RouteRole::Primary),
        (&book.secondary, RouteRole::Secondary),
    ] {
        for rule in set.rules() {
            let key = rule_identity_key_under(rule, coverage);
            match map.get(&key) {
                Some(held) if held.rule.enabled || !rule.enabled => continue,
                _ => {
                    map.insert(
                        key,
                        Side {
                            rule: rule.clone(),
                            route,
                        },
                    );
                }
            }
        }
    }
    map
}

/// One match that was named in BOTH route sets of a single book, with both
/// copies enabled, and the copy that was switched off to give the book one
/// answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NormalizedCrossSetRule {
    /// Content identity of the pair.
    pub identity_key: String,
    /// The copy left enabled: the one on the primary route.
    pub kept: CanonicalRule,
    /// The secondary-route copy, as it stood BEFORE being switched off, so a
    /// UI can offer the opposite choice with the user's own wording intact.
    pub disabled: CanonicalRule,
}

/// Give a book one enabled copy per match: where the same match is enabled in
/// both route sets, the secondary-route copy is switched off.
///
/// Two enabled copies of one match are not a merge problem — they are a problem
/// the book already had, and the merge only exposes it. Resolving it HERE, on
/// each side separately, keeps [`merge_rule_books`] about "file versus service"
/// and leaves "this rule moved to the other route" meaning what it says.
///
/// The primary copy is the one kept by DEFAULT. That is what the code did
/// before, silently, and it is the safer half: a rule left enabled on the
/// additional route turns into a block or a leak, depending on the behaviour
/// mode, every time the tunnel is down — whereas the primary route is the one
/// that works when nothing else does.
///
/// `keep_secondary` names the identity keys where the user said otherwise, and
/// there the roles swap: the secondary copy stays enabled and the primary one
/// is switched off. It is a default being overridden, not a policy — which is
/// why it arrives as a set of keys rather than a flag.
///
/// Nothing is deleted: the loser is disabled, which is exactly the state the
/// user is offered as the resolution, so a second pass reports nothing and the
/// user's row is still there to switch back.
pub fn normalize_cross_set_duplicates(
    book: &CanonicalRuleBook,
    keep_secondary: &BTreeSet<String>,
    coverage: SubdomainCoverage,
) -> (CanonicalRuleBook, Vec<NormalizedCrossSetRule>) {
    let enabled_primary: BTreeMap<String, &CanonicalRule> = book
        .primary
        .rules()
        .iter()
        .filter(|rule| rule.enabled)
        .map(|rule| (rule_identity_key_under(rule, coverage), rule))
        .collect();
    if enabled_primary.is_empty() {
        return (book.clone(), Vec::new());
    }

    let mut normalized = Vec::new();
    let mut disable_primary: BTreeSet<String> = BTreeSet::new();
    let mut secondary = Vec::with_capacity(book.secondary.len());
    for rule in book.secondary.rules() {
        let key = rule_identity_key_under(rule, coverage);
        match enabled_primary.get(&key) {
            Some(primary_copy) if rule.enabled => {
                let user_keeps_secondary = keep_secondary.contains(&key);
                let (kept, disabled) = if user_keeps_secondary {
                    disable_primary.insert(key.clone());
                    (rule.clone(), (*primary_copy).clone())
                } else {
                    ((*primary_copy).clone(), rule.clone())
                };
                normalized.push(NormalizedCrossSetRule {
                    identity_key: key,
                    kept,
                    disabled,
                });
                let mut copy = rule.clone();
                copy.enabled = user_keeps_secondary;
                secondary.push(copy);
            }
            _ => secondary.push(rule.clone()),
        }
    }

    let primary = if disable_primary.is_empty() {
        book.primary.clone()
    } else {
        CanonicalRuleSet::from_rules(
            book.primary
                .rules()
                .iter()
                .map(|rule| {
                    let mut copy = rule.clone();
                    if disable_primary.contains(&rule_identity_key_under(rule, coverage)) {
                        copy.enabled = false;
                    }
                    copy
                })
                .collect::<Vec<_>>(),
        )
    };

    (
        CanonicalRuleBook {
            primary,
            secondary: CanonicalRuleSet::from_rules(secondary),
        },
        normalized,
    )
}

/// Place a rule into the primary or secondary accumulator by route.
fn place(
    rule: &CanonicalRule,
    route: RouteRole,
    primary: &mut Vec<CanonicalRule>,
    secondary: &mut Vec<CanonicalRule>,
) {
    match route {
        RouteRole::Primary => primary.push(rule.clone()),
        RouteRole::Secondary => secondary.push(rule.clone()),
    }
}

/// Reconcile a linked-file rule book with the service rule book.
///
/// See the [module docs](self) for the identity and safety model. Pure and
/// deterministic. Conflicts are resolved solely by `policy`; for the
/// interactive flow where the user picks a side per conflict use
/// [`merge_rule_books_with_resolutions`].
pub fn merge_rule_books(
    file: &CanonicalRuleBook,
    service: &CanonicalRuleBook,
    policy: MergePolicy,
    coverage: SubdomainCoverage,
) -> MergeResult {
    merge_rule_books_with_resolutions(
        file,
        service,
        policy,
        &BTreeMap::new(),
        &BTreeSet::new(),
        coverage,
    )
}

/// Reconcile a linked-file rule book with the service rule book, honouring
/// explicit per-conflict user picks.
///
/// Behaves exactly like [`merge_rule_books`] except that any conflict whose
/// [`identity_key`](MergeConflict::identity_key) appears in `resolutions` is
/// resolved to the mapped [`ConflictSide`] ([`ConflictSide::File`] keeps the
/// file rule, [`ConflictSide::Service`] keeps the service rule) in both the
/// `merged` book and the conflict's `resolved` marker; a mapped
/// [`ConflictSide::Unresolved`] (or any conflict absent from the map) falls
/// back to `policy`.
///
/// `keep_secondary` carries the other kind of pick made in the same dialog:
/// identity keys where a match named in BOTH route sets of one book should keep
/// its additional-route copy rather than the primary one (see
/// [`normalize_cross_set_duplicates`]). Both maps travel together because both
/// are answers to the same screen, replayed on the second call.
///
/// This is the second pass of the two-call merge-preview flow: the first call
/// runs under [`MergePolicy::Union`] with empty picks (every conflict comes
/// back [`ConflictSide::Unresolved`]); the second call replays the same inputs
/// with the user's picks to produce the final book. Pure and deterministic.
pub fn merge_rule_books_with_resolutions(
    file: &CanonicalRuleBook,
    service: &CanonicalRuleBook,
    policy: MergePolicy,
    resolutions: &BTreeMap<String, ConflictSide>,
    keep_secondary: &BTreeSet<String>,
    coverage: SubdomainCoverage,
) -> MergeResult {
    // Each side is given one enabled copy per match BEFORE anything is paired.
    // Two enabled copies in one book are that book's problem, not a
    // file-versus-service disagreement, and letting them reach the pairing is
    // what made it drop one silently.
    let (file, file_normalized) = normalize_cross_set_duplicates(file, keep_secondary, coverage);
    let (service, service_normalized) =
        normalize_cross_set_duplicates(service, keep_secondary, coverage);
    let normalized_duplicates = merge_normalized(file_normalized, service_normalized);

    let file_idx = index(&file, coverage);
    let service_idx = index(&service, coverage);

    // Union of identity keys in deterministic (sorted) order.
    let mut keys: Vec<&String> = file_idx.keys().chain(service_idx.keys()).collect();
    keys.sort();
    keys.dedup();

    let mut primary_rules: Vec<CanonicalRule> = Vec::new();
    let mut secondary_rules: Vec<CanonicalRule> = Vec::new();
    let mut entries: Vec<MergedRuleEntry> = Vec::new();
    let mut conflicts: Vec<MergeConflict> = Vec::new();

    for key in keys {
        match (file_idx.get(key), service_idx.get(key)) {
            // Present only in the file — always kept (never drop).
            (Some(f), None) => {
                place(&f.rule, f.route, &mut primary_rules, &mut secondary_rules);
                entries.push(MergedRuleEntry {
                    identity_key: key.clone(),
                    rule: f.rule.clone(),
                    route: f.route,
                    origin: MergeOrigin::FileOnly,
                    was_conflict: false,
                });
            }
            // Present only in the service — always kept (never drop).
            (None, Some(s)) => {
                place(&s.rule, s.route, &mut primary_rules, &mut secondary_rules);
                entries.push(MergedRuleEntry {
                    identity_key: key.clone(),
                    rule: s.rule.clone(),
                    route: s.route,
                    origin: MergeOrigin::ServiceOnly,
                    was_conflict: false,
                });
            }
            // Present on both sides.
            (Some(f), Some(s)) => {
                let differs = f.route != s.route || rule_attributes_differ(&f.rule, &s.rule);
                if !differs {
                    // The service spelling wins when the two sides agree on
                    // everything but the spelling (`x` versus `*.x`, paired
                    // only under subdomain coverage). They enforce the same
                    // traffic, so rewriting the active revision to the file's
                    // spelling would turn a no-op merge into a rules change the
                    // user then has to review for nothing.
                    let same_spelling = f.rule.address_match == s.rule.address_match;
                    let kept = if same_spelling { &f.rule } else { &s.rule };
                    place(kept, f.route, &mut primary_rules, &mut secondary_rules);
                    entries.push(MergedRuleEntry {
                        identity_key: key.clone(),
                        rule: kept.clone(),
                        route: f.route,
                        origin: MergeOrigin::Both,
                        was_conflict: false,
                    });
                } else {
                    // A per-conflict user pick (File/Service) overrides the
                    // policy; an explicit Unresolved or an absent key falls
                    // back to the policy.
                    let picked = match resolutions.get(key) {
                        Some(ConflictSide::File) => Some(ConflictSide::File),
                        Some(ConflictSide::Service) => Some(ConflictSide::Service),
                        _ => None,
                    };
                    let (chosen, chosen_route, resolved) = match picked {
                        Some(ConflictSide::File) => (&f.rule, f.route, ConflictSide::File),
                        Some(ConflictSide::Service) => (&s.rule, s.route, ConflictSide::Service),
                        // `picked` is only ever File/Service or None.
                        _ => match policy {
                            MergePolicy::ServiceWins => (&s.rule, s.route, ConflictSide::Service),
                            MergePolicy::FileWins => (&f.rule, f.route, ConflictSide::File),
                            MergePolicy::Union => (&f.rule, f.route, ConflictSide::Unresolved),
                        },
                    };
                    place(
                        chosen,
                        chosen_route,
                        &mut primary_rules,
                        &mut secondary_rules,
                    );
                    entries.push(MergedRuleEntry {
                        identity_key: key.clone(),
                        rule: chosen.clone(),
                        route: chosen_route,
                        origin: MergeOrigin::Both,
                        was_conflict: true,
                    });
                    conflicts.push(MergeConflict {
                        identity_key: key.clone(),
                        rule: f.rule.clone(),
                        file: ConflictRule::of(&f.rule, f.route),
                        service: ConflictRule::of(&s.rule, s.route),
                        resolved,
                    });
                }
            }
            (None, None) => {
                // A key came from one of the two maps, so at least one side
                // must be present. Unreachable by construction.
                debug_assert!(false, "merge key present in neither side");
            }
        }
    }

    MergeResult {
        merged: CanonicalRuleBook {
            primary: CanonicalRuleSet::from_rules(primary_rules),
            secondary: CanonicalRuleSet::from_rules(secondary_rules),
        },
        entries,
        conflicts,
        normalized_duplicates,
    }
}

/// One report per match across both sides. A match named in both sets of BOTH
/// books is one thing to tell the user about, not two; the file side is kept
/// because its rule carries the wording the user typed.
fn merge_normalized(
    file: Vec<NormalizedCrossSetRule>,
    service: Vec<NormalizedCrossSetRule>,
) -> Vec<NormalizedCrossSetRule> {
    let mut by_key: BTreeMap<String, NormalizedCrossSetRule> = service
        .into_iter()
        .map(|n| (n.identity_key.clone(), n))
        .collect();
    for n in file {
        by_key.insert(n.identity_key.clone(), n);
    }
    by_key.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::CanonicalAddressMatch;
    use crate::RuleId;
    use std::net::Ipv4Addr;

    fn ip_rule(id: &str, enabled: bool, ip: [u8; 4], comment: &str) -> CanonicalRule {
        CanonicalRule {
            id: RuleId(id.to_string()),
            enabled,
            address_match: Some(CanonicalAddressMatch::ExactIp(Ipv4Addr::new(
                ip[0], ip[1], ip[2], ip[3],
            ))),
            app_match: None,
            comment: comment.to_string(),
            action: crate::canonical::RuleAction::Route,
            origin: None,
        }
    }

    fn book(primary: Vec<CanonicalRule>, secondary: Vec<CanonicalRule>) -> CanonicalRuleBook {
        CanonicalRuleBook {
            primary: CanonicalRuleSet::from_rules(primary),
            secondary: CanonicalRuleSet::from_rules(secondary),
        }
    }

    // ── cross-set duplicates inside ONE book ────────────────────────────────

    /// The pairing keys on what a rule matches, so a book naming one match in
    /// both of its own route sets has no single answer — and used to lose one
    /// copy without saying so. The book is normalised first instead.
    #[test]
    fn one_match_enabled_in_both_sets_of_a_book_keeps_the_primary_copy() {
        let file = book(
            vec![ip_rule("r-1", true, [1, 1, 1, 1], "on primary")],
            vec![ip_rule("r-2", true, [1, 1, 1, 1], "and on secondary")],
        );
        let (normalized, reported) =
            normalize_cross_set_duplicates(&file, &BTreeSet::new(), SubdomainCoverage::Off);

        assert_eq!(reported.len(), 1, "the pair must be reported, not hidden");
        assert_eq!(reported[0].kept.id.as_str(), "r-1");
        assert_eq!(reported[0].disabled.id.as_str(), "r-2");
        assert!(
            reported[0].disabled.enabled,
            "the report carries the copy AS IT WAS, so the choice can be reversed",
        );

        // Nothing is deleted: the losing row is still there, switched off.
        assert!(normalized.primary.rules()[0].enabled);
        assert_eq!(normalized.secondary.rules().len(), 1);
        assert!(!normalized.secondary.rules()[0].enabled);
        assert_eq!(normalized.secondary.rules()[0].id.as_str(), "r-2");
    }

    /// A disabled copy IS the resolution the user is offered, so reporting it
    /// again would ask the same question for ever.
    #[test]
    fn a_copy_that_is_already_disabled_is_not_reported_again() {
        let file = book(
            vec![ip_rule("r-1", true, [1, 1, 1, 1], "")],
            vec![ip_rule("r-2", false, [1, 1, 1, 1], "")],
        );
        let (normalized, reported) =
            normalize_cross_set_duplicates(&file, &BTreeSet::new(), SubdomainCoverage::Off);
        assert!(reported.is_empty());
        assert_eq!(normalized, file, "an already-settled book is left alone");
    }

    /// The default is a default, not a verdict. When the user says the
    /// additional route is the one they meant, the roles swap: the secondary
    /// copy stays enabled and the primary one is switched off — and the report
    /// says so, so the band the choice was made in still reads correctly.
    #[test]
    fn the_user_can_keep_the_additional_routes_copy_instead() {
        let file = book(
            vec![ip_rule("r-1", true, [1, 1, 1, 1], "")],
            vec![ip_rule("r-2", true, [1, 1, 1, 1], "")],
        );
        let key = {
            let (_, reported) =
                normalize_cross_set_duplicates(&file, &BTreeSet::new(), SubdomainCoverage::Off);
            assert_eq!(reported.len(), 1);
            assert_eq!(reported[0].kept.id.as_str(), "r-1", "primary by default");
            reported[0].identity_key.clone()
        };

        let mut keep_secondary = BTreeSet::new();
        keep_secondary.insert(key);
        let (normalized, reported) =
            normalize_cross_set_duplicates(&file, &keep_secondary, SubdomainCoverage::Off);

        assert_eq!(reported.len(), 1);
        assert_eq!(reported[0].kept.id.as_str(), "r-2");
        assert_eq!(reported[0].disabled.id.as_str(), "r-1");
        // Nothing is deleted on either choice: both rows survive, one switched off.
        assert_eq!(normalized.primary.len(), 1);
        assert_eq!(normalized.secondary.len(), 1);
        assert!(!normalized.primary.rules()[0].enabled);
        assert!(normalized.secondary.rules()[0].enabled);
    }

    /// A key nobody named leaves the default alone — the set is an override
    /// list, so an unrelated entry must not move anything.
    #[test]
    fn a_key_that_names_nothing_changes_nothing() {
        let file = book(
            vec![ip_rule("r-1", true, [1, 1, 1, 1], "")],
            vec![ip_rule("r-2", true, [1, 1, 1, 1], "")],
        );
        let mut keep_secondary = BTreeSet::new();
        keep_secondary.insert("not-a-key-in-this-book".to_string());
        let (normalized, reported) =
            normalize_cross_set_duplicates(&file, &keep_secondary, SubdomainCoverage::Off);

        assert_eq!(reported[0].kept.id.as_str(), "r-1");
        assert!(normalized.primary.rules()[0].enabled);
        assert!(!normalized.secondary.rules()[0].enabled);
    }

    /// The whole point: the copy that is actually enforced must survive the
    /// pairing. Before normalisation the primary copy won only because it was
    /// walked first — which meant an enabled secondary copy could be dropped in
    /// favour of a disabled primary one.
    #[test]
    fn the_enabled_copy_survives_the_pairing_even_when_the_primary_one_is_off() {
        let file = book(
            vec![ip_rule("r-1", false, [1, 1, 1, 1], "")],
            vec![ip_rule("r-2", true, [1, 1, 1, 1], "")],
        );
        let service = book(vec![], vec![]);
        let result = merge_rule_books(&file, &service, MergePolicy::Union, SubdomainCoverage::Off);

        assert!(
            result.normalized_duplicates.is_empty(),
            "only one copy is enabled, so there is nothing to normalise",
        );
        assert_eq!(result.entries.len(), 1);
        assert_eq!(result.entries[0].route, RouteRole::Secondary);
        assert!(result.entries[0].rule.enabled);
        assert_eq!(result.merged.primary.len(), 0);
        assert_eq!(result.merged.secondary.len(), 1);
    }

    /// A book that needed normalising has something to show the user, even when
    /// the two sides agreed about everything else.
    #[test]
    fn a_normalised_book_is_not_a_no_op_merge() {
        let both = book(
            vec![ip_rule("r-1", true, [1, 1, 1, 1], "")],
            vec![ip_rule("r-2", true, [1, 1, 1, 1], "")],
        );
        let result = merge_rule_books(&both, &both, MergePolicy::Union, SubdomainCoverage::Off);
        assert!(!result.normalized_duplicates.is_empty());
        assert!(
            !result.is_noop(),
            "the merged book switched a rule off that neither input had off",
        );
    }

    /// One match, both books — one thing to tell the user about.
    #[test]
    fn the_same_pair_on_both_sides_is_reported_once() {
        let file = book(
            vec![ip_rule("r-1", true, [1, 1, 1, 1], "file wording")],
            vec![ip_rule("r-2", true, [1, 1, 1, 1], "")],
        );
        let service = book(
            vec![ip_rule("s-1", true, [1, 1, 1, 1], "file wording")],
            vec![ip_rule("s-2", true, [1, 1, 1, 1], "")],
        );
        let result = merge_rule_books(&file, &service, MergePolicy::Union, SubdomainCoverage::Off);
        assert_eq!(result.normalized_duplicates.len(), 1);
        assert_eq!(
            result.normalized_duplicates[0].kept.id.as_str(),
            "r-1",
            "the file side is reported: it carries the wording the user typed",
        );
    }

    /// A rule appearing on only one side is always kept (never dropped).
    #[test]
    fn presence_is_always_union_for_every_policy() {
        // File has A on secondary; service has B on secondary. Union of both.
        let file = book(vec![], vec![ip_rule("r-1", true, [1, 1, 1, 1], "")]);
        let service = book(vec![], vec![ip_rule("r-9", true, [2, 2, 2, 2], "")]);
        for policy in [
            MergePolicy::Union,
            MergePolicy::FileWins,
            MergePolicy::ServiceWins,
        ] {
            let r = merge_rule_books(&file, &service, policy, SubdomainCoverage::Off);
            assert_eq!(
                r.merged.secondary.len(),
                2,
                "both file-only and service-only rules must survive under {policy:?}"
            );
            assert!(r.conflicts.is_empty(), "no conflicts for disjoint rules");
            let origins: Vec<_> = r.entries.iter().map(|e| e.origin).collect();
            assert!(origins.contains(&MergeOrigin::FileOnly));
            assert!(origins.contains(&MergeOrigin::ServiceOnly));
        }
    }

    /// Identical rule on both sides → kept once, `Both`, no conflict.
    #[test]
    fn identical_rule_is_not_a_conflict() {
        let rule = ip_rule("r-1", true, [1, 1, 1, 1], "hi");
        // Different ids (regenerated on import) but same content + route.
        let file = book(vec![], vec![rule.clone()]);
        let service = book(vec![], vec![ip_rule("r-77", true, [1, 1, 1, 1], "hi")]);
        let r = merge_rule_books(&file, &service, MergePolicy::Union, SubdomainCoverage::Off);
        assert_eq!(r.merged.secondary.len(), 1);
        assert!(r.conflicts.is_empty());
        assert!(r.is_noop());
    }

    /// Same match, different enabled state → conflict; policy decides winner.
    #[test]
    fn enabled_conflict_resolves_per_policy() {
        let file = book(vec![], vec![ip_rule("r-1", true, [1, 1, 1, 1], "")]);
        let service = book(vec![], vec![ip_rule("r-1", false, [1, 1, 1, 1], "")]);

        let union = merge_rule_books(&file, &service, MergePolicy::Union, SubdomainCoverage::Off);
        assert_eq!(union.conflicts.len(), 1);
        assert_eq!(union.conflicts[0].resolved, ConflictSide::Unresolved);
        // Union keeps the file side provisionally.
        assert!(union.merged.secondary.rules()[0].enabled);
        assert_eq!(union.unresolved_conflicts(), 1);

        let fw = merge_rule_books(
            &file,
            &service,
            MergePolicy::FileWins,
            SubdomainCoverage::Off,
        );
        assert_eq!(fw.conflicts[0].resolved, ConflictSide::File);
        assert!(fw.merged.secondary.rules()[0].enabled);

        let sw = merge_rule_books(
            &file,
            &service,
            MergePolicy::ServiceWins,
            SubdomainCoverage::Off,
        );
        assert_eq!(sw.conflicts[0].resolved, ConflictSide::Service);
        assert!(!sw.merged.secondary.rules()[0].enabled);
    }

    /// Same match, one side routes and the other blocks → conflict; the block
    /// toggle is a mutable attribute (identity stays match-only) so it merges as
    /// a `Modified`-style conflict, never Add+Remove.
    #[test]
    fn block_vs_route_toggle_is_a_conflict() {
        let routed = ip_rule("r-1", true, [1, 1, 1, 1], "");
        let mut blocked = ip_rule("r-1", true, [1, 1, 1, 1], "");
        blocked.action = crate::canonical::RuleAction::Block;

        let file = book(vec![], vec![routed]);
        let service = book(vec![], vec![blocked]);

        let union = merge_rule_books(&file, &service, MergePolicy::Union, SubdomainCoverage::Off);
        assert_eq!(
            union.conflicts.len(),
            1,
            "toggling block vs route must surface as a single conflict"
        );
        assert_eq!(union.conflicts[0].resolved, ConflictSide::Unresolved);
        // Exactly one rule survives — never duplicated into Add+Remove.
        assert_eq!(union.merged.secondary.len(), 1);

        // ServiceWins picks the blocking side.
        let sw = merge_rule_books(
            &file,
            &service,
            MergePolicy::ServiceWins,
            SubdomainCoverage::Off,
        );
        assert_eq!(sw.conflicts[0].resolved, ConflictSide::Service);
        assert_eq!(
            sw.merged.secondary.rules()[0].action,
            crate::canonical::RuleAction::Block
        );
    }

    /// Same match on different routes → conflict (a retarget); winner's route
    /// is used and the rule appears in exactly one route set.
    #[test]
    fn route_conflict_uses_winner_route_and_never_duplicates() {
        // File routes 1.1.1.1 via primary; service routes it via secondary.
        let file = book(vec![ip_rule("r-1", true, [1, 1, 1, 1], "")], vec![]);
        let service = book(vec![], vec![ip_rule("r-1", true, [1, 1, 1, 1], "")]);

        let fw = merge_rule_books(
            &file,
            &service,
            MergePolicy::FileWins,
            SubdomainCoverage::Off,
        );
        assert_eq!(fw.conflicts.len(), 1);
        assert_eq!(fw.merged.primary.len(), 1, "file wins → primary");
        assert_eq!(fw.merged.secondary.len(), 0);

        let sw = merge_rule_books(
            &file,
            &service,
            MergePolicy::ServiceWins,
            SubdomainCoverage::Off,
        );
        assert_eq!(sw.merged.primary.len(), 0);
        assert_eq!(sw.merged.secondary.len(), 1, "service wins → secondary");

        // Never both — the rule lands in exactly one route set.
        assert_eq!(fw.merged.total_rule_count(), 1);
        assert_eq!(sw.merged.total_rule_count(), 1);
    }

    /// Comment-only difference is a conflict (attributes differ).
    #[test]
    fn comment_difference_is_a_conflict() {
        let file = book(
            vec![],
            vec![ip_rule("r-1", true, [1, 1, 1, 1], "from file")],
        );
        let service = book(
            vec![],
            vec![ip_rule("r-1", true, [1, 1, 1, 1], "from service")],
        );
        let r = merge_rule_books(&file, &service, MergePolicy::Union, SubdomainCoverage::Off);
        assert_eq!(r.conflicts.len(), 1);
        assert_eq!(r.conflicts[0].file.comment, "from file");
        assert_eq!(r.conflicts[0].service.comment, "from service");
    }

    /// Two identical books merge to a no-op with all `Both` origins.
    #[test]
    fn identical_books_are_noop() {
        let mk = || {
            book(
                vec![ip_rule("r-1", true, [10, 0, 0, 1], "")],
                vec![ip_rule("r-2", true, [10, 0, 0, 2], "")],
            )
        };
        let r = merge_rule_books(&mk(), &mk(), MergePolicy::Union, SubdomainCoverage::Off);
        assert!(r.is_noop());
        assert_eq!(r.merged.total_rule_count(), 2);
    }

    /// Output is deterministic regardless of input rule ordering (the same
    /// rules in a different order produce byte-identical output, because
    /// `CanonicalRuleSet::from_rules` imposes canonical order and the entry
    /// list is keyed by sorted identity).
    #[test]
    fn merge_is_deterministic() {
        let file_a = book(
            vec![],
            vec![
                ip_rule("r-1", true, [1, 1, 1, 1], ""),
                ip_rule("r-2", true, [2, 2, 2, 2], ""),
            ],
        );
        // Same rules (same ids), reversed input order.
        let file_b = book(
            vec![],
            vec![
                ip_rule("r-2", true, [2, 2, 2, 2], ""),
                ip_rule("r-1", true, [1, 1, 1, 1], ""),
            ],
        );
        let service = book(vec![], vec![ip_rule("r-3", true, [3, 3, 3, 3], "")]);
        let ra = merge_rule_books(
            &file_a,
            &service,
            MergePolicy::Union,
            SubdomainCoverage::Off,
        );
        let rb = merge_rule_books(
            &file_b,
            &service,
            MergePolicy::Union,
            SubdomainCoverage::Off,
        );
        assert_eq!(ra.merged, rb.merged);
        let keys_a: Vec<_> = ra.entries.iter().map(|e| e.identity_key.clone()).collect();
        let keys_b: Vec<_> = rb.entries.iter().map(|e| e.identity_key.clone()).collect();
        assert_eq!(keys_a, keys_b, "entry order must be identity-key stable");
    }

    /// A conflict carries the action per side, so a route↔block toggle has a
    /// visible distinction (both sides otherwise share every field), and each
    /// merged entry carries its full rule for bucket rendering.
    #[test]
    fn conflict_carries_action_per_side_and_entry_carries_rule() {
        let routed = ip_rule("r-1", true, [1, 1, 1, 1], "");
        let mut blocked = ip_rule("r-1", true, [1, 1, 1, 1], "");
        blocked.action = crate::canonical::RuleAction::Block;

        let file = book(vec![], vec![routed.clone()]);
        let service = book(vec![], vec![blocked]);

        let union = merge_rule_books(&file, &service, MergePolicy::Union, SubdomainCoverage::Off);
        assert_eq!(union.conflicts.len(), 1);
        assert_eq!(union.conflicts[0].file.action, RuleAction::Route);
        assert_eq!(union.conflicts[0].service.action, RuleAction::Block);
        // The representative rule carries the match so the UI can render type/value.
        assert_eq!(union.conflicts[0].rule.address_match, routed.address_match);
        // Every merged entry carries its full rule.
        assert!(union.entries.iter().all(|e| e.rule.address_match.is_some()));
        // Union keeps the file (routed) side provisionally in the entry.
        assert_eq!(union.entries[0].rule.action, RuleAction::Route);
    }

    /// Per-conflict resolutions override the policy: each key resolves to its
    /// picked side, keys absent from the map follow the policy.
    #[test]
    fn resolutions_apply_per_conflict() {
        // Two conflicts: 1.1.1.1 (enabled differs) and 2.2.2.2 (comment differs).
        let file = book(
            vec![],
            vec![
                ip_rule("r-1", true, [1, 1, 1, 1], ""),
                ip_rule("r-2", true, [2, 2, 2, 2], "file"),
            ],
        );
        let service = book(
            vec![],
            vec![
                ip_rule("r-1", false, [1, 1, 1, 1], ""),
                ip_rule("r-2", true, [2, 2, 2, 2], "service"),
            ],
        );

        let base = merge_rule_books(&file, &service, MergePolicy::Union, SubdomainCoverage::Off);
        assert_eq!(base.conflicts.len(), 2);
        // Pick Service for 1.1.1.1, File for 2.2.2.2; leave nothing to policy.
        let key_1 = base
            .conflicts
            .iter()
            .find(|c| {
                matches!(&c.rule.address_match,
                Some(CanonicalAddressMatch::ExactIp(a)) if *a == Ipv4Addr::new(1, 1, 1, 1))
            })
            .map(|c| c.identity_key.clone())
            .expect("conflict for 1.1.1.1");
        let key_2 = base
            .conflicts
            .iter()
            .find(|c| {
                matches!(&c.rule.address_match,
                Some(CanonicalAddressMatch::ExactIp(a)) if *a == Ipv4Addr::new(2, 2, 2, 2))
            })
            .map(|c| c.identity_key.clone())
            .expect("conflict for 2.2.2.2");

        let mut resolutions = BTreeMap::new();
        resolutions.insert(key_1, ConflictSide::Service);
        resolutions.insert(key_2, ConflictSide::File);
        let resolved = merge_rule_books_with_resolutions(
            &file,
            &service,
            MergePolicy::Union,
            &resolutions,
            &BTreeSet::new(),
            SubdomainCoverage::Off,
        );

        assert_eq!(resolved.unresolved_conflicts(), 0, "all picks applied");
        for c in &resolved.conflicts {
            match &c.rule.address_match {
                Some(CanonicalAddressMatch::ExactIp(a)) if *a == Ipv4Addr::new(1, 1, 1, 1) => {
                    assert_eq!(c.resolved, ConflictSide::Service);
                }
                Some(CanonicalAddressMatch::ExactIp(a)) if *a == Ipv4Addr::new(2, 2, 2, 2) => {
                    assert_eq!(c.resolved, ConflictSide::File);
                }
                other => panic!("unexpected conflict rule {other:?}"),
            }
        }
        // Service pick for 1.1.1.1 → disabled; File pick for 2.2.2.2 → "file".
        let rules = resolved.merged.secondary.rules();
        let r1 = rules
            .iter()
            .find(|r| {
                matches!(&r.address_match,
                Some(CanonicalAddressMatch::ExactIp(a)) if *a == Ipv4Addr::new(1, 1, 1, 1))
            })
            .expect("merged 1.1.1.1");
        assert!(!r1.enabled, "service side (disabled) chosen for 1.1.1.1");
        let r2 = rules
            .iter()
            .find(|r| {
                matches!(&r.address_match,
                Some(CanonicalAddressMatch::ExactIp(a)) if *a == Ipv4Addr::new(2, 2, 2, 2))
            })
            .expect("merged 2.2.2.2");
        assert_eq!(r2.comment, "file", "file side chosen for 2.2.2.2");
    }

    /// A conflict absent from the resolutions map falls back to the base policy.
    #[test]
    fn unresolved_key_falls_back_to_policy() {
        let file = book(vec![], vec![ip_rule("r-1", true, [1, 1, 1, 1], "")]);
        let service = book(vec![], vec![ip_rule("r-1", false, [1, 1, 1, 1], "")]);
        let empty = BTreeMap::new();
        let sw = merge_rule_books_with_resolutions(
            &file,
            &service,
            MergePolicy::ServiceWins,
            &empty,
            &BTreeSet::new(),
            SubdomainCoverage::Off,
        );
        assert_eq!(sw.conflicts[0].resolved, ConflictSide::Service);
        assert!(!sw.merged.secondary.rules()[0].enabled);
    }

    // ── `x` versus `*.x` under subdomain coverage ───────────────────────────

    fn domain_rule(id: &str, m: CanonicalAddressMatch) -> CanonicalRule {
        CanonicalRule {
            id: RuleId(id.to_string()),
            enabled: true,
            address_match: Some(m),
            app_match: None,
            comment: String::new(),
            action: crate::canonical::RuleAction::Route,
            origin: None,
        }
    }

    fn exact(host: &str) -> CanonicalAddressMatch {
        CanonicalAddressMatch::ExactFqdn(host.to_string())
    }

    fn suffix(host: &str) -> CanonicalAddressMatch {
        CanonicalAddressMatch::SuffixDomain(host.to_string())
    }

    /// The file says `*.proflcdn.test`, the service revision says `proflcdn.test`.
    /// With coverage on the two enforce the same traffic, so the merge must see
    /// one rule present on both sides — not one rule missing from each.
    #[test]
    fn the_two_spellings_of_one_domain_pair_as_one_rule_under_coverage() {
        let file = book(vec![domain_rule("r-1", suffix("proflcdn.test"))], vec![]);
        let service = book(vec![domain_rule("r-9", exact("proflcdn.test"))], vec![]);

        let r = merge_rule_books(&file, &service, MergePolicy::Union, SubdomainCoverage::On);

        assert_eq!(r.entries.len(), 1);
        assert_eq!(r.entries[0].origin, MergeOrigin::Both);
        assert!(r.conflicts.is_empty(), "same traffic is not a disagreement");
        assert!(r.is_noop(), "nothing to reconcile");
        assert_eq!(
            r.merged.primary.rules()[0].address_match,
            Some(exact("proflcdn.test")),
            "a spelling-only match keeps the service's, so the revision is left alone",
        );
    }

    /// Positive control for the fold: with coverage OFF the same two books are
    /// two separate rules, one per side — the honest reading when a bare domain
    /// rule covers only its apex.
    #[test]
    fn the_two_spellings_stay_separate_rules_without_coverage() {
        let file = book(vec![domain_rule("r-1", suffix("proflcdn.test"))], vec![]);
        let service = book(vec![domain_rule("r-9", exact("proflcdn.test"))], vec![]);

        let r = merge_rule_books(&file, &service, MergePolicy::Union, SubdomainCoverage::Off);

        assert_eq!(r.entries.len(), 2);
        assert!(r.entries.iter().any(|e| e.origin == MergeOrigin::FileOnly));
        assert!(r
            .entries
            .iter()
            .any(|e| e.origin == MergeOrigin::ServiceOnly));
    }

    /// Folding the two spellings must not fold anything else: a different host
    /// under the same suffix is still its own rule.
    #[test]
    fn coverage_folds_only_the_apex_spelling_not_a_subdomain_of_it() {
        let file = book(vec![domain_rule("r-1", exact("www.proflcdn.test"))], vec![]);
        let service = book(vec![domain_rule("r-9", suffix("proflcdn.test"))], vec![]);

        let r = merge_rule_books(&file, &service, MergePolicy::Union, SubdomainCoverage::On);

        assert_eq!(r.entries.len(), 2, "www.x is not the same rule as *.x");
    }

    /// The two spellings on OPPOSITE routes are a real disagreement: they name
    /// one rule and the two sides send it to different places.
    #[test]
    fn the_two_spellings_on_different_routes_are_a_conflict_under_coverage() {
        let file = book(vec![], vec![domain_rule("r-1", suffix("proflcdn.test"))]);
        let service = book(vec![domain_rule("r-9", exact("proflcdn.test"))], vec![]);

        let r = merge_rule_books(&file, &service, MergePolicy::Union, SubdomainCoverage::On);

        assert_eq!(r.conflicts.len(), 1);
        assert_eq!(r.conflicts[0].resolved, ConflictSide::Unresolved);
    }

    /// One book naming both spellings across its own two route sets is the
    /// cross-set duplicate case, and under coverage it must be recognised as
    /// one — otherwise the pairing would silently drop the copy it did not
    /// keep.
    #[test]
    fn both_spellings_across_one_books_route_sets_normalize_under_coverage() {
        let file = book(
            vec![domain_rule("r-1", exact("proflcdn.test"))],
            vec![domain_rule("r-2", suffix("proflcdn.test"))],
        );
        let (normalized, reported) =
            normalize_cross_set_duplicates(&file, &BTreeSet::new(), SubdomainCoverage::On);

        assert_eq!(reported.len(), 1);
        assert_eq!(reported[0].kept.id.as_str(), "r-1");
        assert!(!normalized.secondary.rules()[0].enabled);
    }

    #[test]
    fn policy_slug_round_trips() {
        for p in [
            MergePolicy::Union,
            MergePolicy::FileWins,
            MergePolicy::ServiceWins,
        ] {
            assert_eq!(MergePolicy::from_slug(p.slug()), p);
        }
        assert_eq!(MergePolicy::from_slug("nonsense"), MergePolicy::Union);
    }
}
