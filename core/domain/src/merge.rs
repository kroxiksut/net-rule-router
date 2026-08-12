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

use std::collections::BTreeMap;

use crate::canonical::{CanonicalRule, CanonicalRuleBook, CanonicalRuleSet, RuleAction};
use crate::review::{rule_attributes_differ, rule_identity_key};
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
}

impl MergeResult {
    /// `true` when the two books were already identical (nothing to reconcile).
    pub fn is_noop(&self) -> bool {
        self.conflicts.is_empty() && self.entries.iter().all(|e| e.origin == MergeOrigin::Both)
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
/// route role is carried alongside so a retarget can be detected. Canonical
/// sets cannot contain the same identity twice, but if they somehow did, the
/// first (canonical-order) wins deterministically.
fn index(book: &CanonicalRuleBook) -> BTreeMap<String, Side> {
    let mut map = BTreeMap::new();
    for (set, route) in [
        (&book.primary, RouteRole::Primary),
        (&book.secondary, RouteRole::Secondary),
    ] {
        for rule in set.rules() {
            map.entry(rule_identity_key(rule)).or_insert_with(|| Side {
                rule: rule.clone(),
                route,
            });
        }
    }
    map
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
) -> MergeResult {
    merge_rule_books_with_resolutions(file, service, policy, &BTreeMap::new())
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
/// This is the second pass of the two-call merge-preview flow: the first call
/// runs under [`MergePolicy::Union`] with an empty map (every conflict comes
/// back [`ConflictSide::Unresolved`]); the second call replays the same inputs
/// with the user's picks to produce the final book. Pure and deterministic.
pub fn merge_rule_books_with_resolutions(
    file: &CanonicalRuleBook,
    service: &CanonicalRuleBook,
    policy: MergePolicy,
    resolutions: &BTreeMap<String, ConflictSide>,
) -> MergeResult {
    let file_idx = index(file);
    let service_idx = index(service);

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
                    place(&f.rule, f.route, &mut primary_rules, &mut secondary_rules);
                    entries.push(MergedRuleEntry {
                        identity_key: key.clone(),
                        rule: f.rule.clone(),
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
    }
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
            let r = merge_rule_books(&file, &service, policy);
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
        let r = merge_rule_books(&file, &service, MergePolicy::Union);
        assert_eq!(r.merged.secondary.len(), 1);
        assert!(r.conflicts.is_empty());
        assert!(r.is_noop());
    }

    /// Same match, different enabled state → conflict; policy decides winner.
    #[test]
    fn enabled_conflict_resolves_per_policy() {
        let file = book(vec![], vec![ip_rule("r-1", true, [1, 1, 1, 1], "")]);
        let service = book(vec![], vec![ip_rule("r-1", false, [1, 1, 1, 1], "")]);

        let union = merge_rule_books(&file, &service, MergePolicy::Union);
        assert_eq!(union.conflicts.len(), 1);
        assert_eq!(union.conflicts[0].resolved, ConflictSide::Unresolved);
        // Union keeps the file side provisionally.
        assert!(union.merged.secondary.rules()[0].enabled);
        assert_eq!(union.unresolved_conflicts(), 1);

        let fw = merge_rule_books(&file, &service, MergePolicy::FileWins);
        assert_eq!(fw.conflicts[0].resolved, ConflictSide::File);
        assert!(fw.merged.secondary.rules()[0].enabled);

        let sw = merge_rule_books(&file, &service, MergePolicy::ServiceWins);
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

        let union = merge_rule_books(&file, &service, MergePolicy::Union);
        assert_eq!(
            union.conflicts.len(),
            1,
            "toggling block vs route must surface as a single conflict"
        );
        assert_eq!(union.conflicts[0].resolved, ConflictSide::Unresolved);
        // Exactly one rule survives — never duplicated into Add+Remove.
        assert_eq!(union.merged.secondary.len(), 1);

        // ServiceWins picks the blocking side.
        let sw = merge_rule_books(&file, &service, MergePolicy::ServiceWins);
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

        let fw = merge_rule_books(&file, &service, MergePolicy::FileWins);
        assert_eq!(fw.conflicts.len(), 1);
        assert_eq!(fw.merged.primary.len(), 1, "file wins → primary");
        assert_eq!(fw.merged.secondary.len(), 0);

        let sw = merge_rule_books(&file, &service, MergePolicy::ServiceWins);
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
        let r = merge_rule_books(&file, &service, MergePolicy::Union);
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
        let r = merge_rule_books(&mk(), &mk(), MergePolicy::Union);
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
        let ra = merge_rule_books(&file_a, &service, MergePolicy::Union);
        let rb = merge_rule_books(&file_b, &service, MergePolicy::Union);
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

        let union = merge_rule_books(&file, &service, MergePolicy::Union);
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

        let base = merge_rule_books(&file, &service, MergePolicy::Union);
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
        let resolved =
            merge_rule_books_with_resolutions(&file, &service, MergePolicy::Union, &resolutions);

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
        let sw =
            merge_rule_books_with_resolutions(&file, &service, MergePolicy::ServiceWins, &empty);
        assert_eq!(sw.conflicts[0].resolved, ConflictSide::Service);
        assert!(!sw.merged.secondary.rules()[0].enabled);
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
