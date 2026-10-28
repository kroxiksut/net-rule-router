//! The user's unsaved edits laid over rules that changed elsewhere meanwhile
//! (`rebaseEdits` in `rules.js`).
//!
//! Three lists meet: the `base` the edits were made against, the `edited`
//! table the user has now, and the `fresh` rules in force. Rules are named by
//! [`RuleRow::merge_key`]. What the user did to `base` — added, changed or
//! deleted a rule — is done to `fresh` as well, deletions included. A rule
//! nobody touched, or only someone else did, stays as `fresh` has it.
//!
//! Where both sides touched one rule the user's version wins and the case is
//! listed as a [`Conflict`]; a key in `keep_theirs` turns that one round and
//! leaves the fresh side as it is.

use std::collections::{HashMap, HashSet};

use crate::rules_table::RuleRow;

/// How the two sides disagree about one rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConflictKind {
    /// Changed by the user and changed otherwise elsewhere.
    ChangedBoth,
    /// Changed by the user, deleted elsewhere.
    EditedButDeletedElsewhere,
    /// Deleted by the user, changed elsewhere.
    DeletedButChangedElsewhere,
    /// Added by the user, added otherwise elsewhere.
    AddedBoth,
}

impl ConflictKind {
    /// The wire / vector slug.
    pub fn slug(self) -> &'static str {
        match self {
            Self::ChangedBoth => "changed-both",
            Self::EditedButDeletedElsewhere => "edited-but-deleted-elsewhere",
            Self::DeletedButChangedElsewhere => "deleted-but-changed-elsewhere",
            Self::AddedBoth => "added-both",
        }
    }
}

/// One rule both sides touched.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Conflict {
    pub key: String,
    pub kind: ConflictKind,
    /// The user's version; `None` when the user deleted it.
    pub mine: Option<RuleRow>,
    /// The version in force; `None` when it was deleted elsewhere.
    pub theirs: Option<RuleRow>,
}

/// The edits laid over the fresh rules.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Rebase {
    /// The result: `fresh` in its order, deletions gone, changed rules in
    /// place, added ones last with an empty id for the caller to number.
    pub rows: Vec<RuleRow>,
    /// Rules put in that `fresh` lacks.
    pub added: Vec<RuleRow>,
    /// Rules of `fresh` the user's version replaced.
    pub changed: Vec<RuleRow>,
    /// Rules of `fresh` the user's deletions took out.
    pub removed: Vec<RuleRow>,
    pub conflicts: Vec<Conflict>,
}

/// Whether two rows are the same rule with the same settings; the id is
/// no part of it, and neither is the spelling of the type or the case of the
/// value, which `merge_key` folds too: a recased value is not a change.
pub fn same_content(a: &RuleRow, b: &RuleRow) -> bool {
    fn origin(r: &RuleRow) -> (&str, &str, &str) {
        r.origin
            .as_ref()
            .map_or(("", "", ""), |o| (&*o.reason, &*o.anchor, &*o.added))
    }
    a.enabled == b.enabled
        && a.rule_type.canonical_slug() == b.rule_type.canonical_slug()
        && crate::js::key_lower(&a.match_value) == crate::js::key_lower(&b.match_value)
        && a.target_route.as_str() == b.target_route.as_str()
        && a.verify == b.verify
        && a.comment == b.comment
        && origin(a) == origin(b)
}

fn first_by_key(rows: &[RuleRow]) -> HashMap<String, &RuleRow> {
    let mut map = HashMap::new();
    for row in rows {
        map.entry(row.merge_key()).or_insert(row);
    }
    map
}

/// `edited` laid over `fresh`, relative to the `base` it was made against.
pub fn rebase_edits(
    base: &[RuleRow],
    edited: &[RuleRow],
    fresh: &[RuleRow],
    keep_theirs: &[String],
) -> Rebase {
    let keep: HashSet<&str> = keep_theirs.iter().map(String::as_str).collect();
    let base_by_key = first_by_key(base);
    let edited_by_key = first_by_key(edited);
    let fresh_by_key = first_by_key(fresh);
    let mut out = Rebase::default();
    let mut dropped: HashSet<String> = HashSet::new();

    let mut seen = HashSet::new();
    for row in base {
        let key = row.merge_key();
        if edited_by_key.contains_key(&key) || !seen.insert(key.clone()) {
            continue;
        }
        let Some(theirs) = fresh_by_key.get(&key) else {
            continue;
        };
        if !same_content(theirs, row) {
            out.conflicts.push(Conflict {
                key: key.clone(),
                kind: ConflictKind::DeletedButChangedElsewhere,
                mine: None,
                theirs: Some((*theirs).clone()),
            });
            if keep.contains(key.as_str()) {
                continue;
            }
        }
        out.removed.push((*theirs).clone());
        dropped.insert(key);
    }

    out.rows = fresh
        .iter()
        .filter(|row| !dropped.contains(&row.merge_key()))
        .cloned()
        .collect();
    let mut at: HashMap<String, usize> = HashMap::new();
    for (i, row) in out.rows.iter().enumerate() {
        at.entry(row.merge_key()).or_insert(i);
    }

    let mut done = HashSet::new();
    for mine in edited {
        let key = mine.merge_key();
        let before = base_by_key.get(&key);
        if before.is_some_and(|b| same_content(b, mine)) || !done.insert(key.clone()) {
            continue;
        }
        match at.get(&key).copied() {
            Some(i) => {
                let theirs = out.rows[i].clone();
                if same_content(&theirs, mine) {
                    continue;
                }
                let clash = match before {
                    Some(b) => (!same_content(&theirs, b)).then_some(ConflictKind::ChangedBoth),
                    None => Some(ConflictKind::AddedBoth),
                };
                if let Some(kind) = clash {
                    out.conflicts.push(Conflict {
                        key: key.clone(),
                        kind,
                        mine: Some(mine.clone()),
                        theirs: Some(theirs),
                    });
                    if keep.contains(key.as_str()) {
                        continue;
                    }
                }
                let placed = RuleRow {
                    id: out.rows[i].id.clone(),
                    ..mine.clone()
                };
                out.rows[i] = placed.clone();
                out.changed.push(placed);
            }
            None => {
                if before.is_some() {
                    out.conflicts.push(Conflict {
                        key: key.clone(),
                        kind: ConflictKind::EditedButDeletedElsewhere,
                        mine: Some(mine.clone()),
                        theirs: None,
                    });
                    if keep.contains(key.as_str()) {
                        continue;
                    }
                }
                let placed = RuleRow {
                    id: String::new(),
                    ..mine.clone()
                };
                at.insert(key, out.rows.len());
                out.rows.push(placed.clone());
                out.added.push(placed);
            }
        }
    }
    out
}

/// A [`Rebase`] as the merge review lists it (`rebaseMergeView` in `rules.js`):
/// what the user added, changed and deleted, and the rules both sides touched
/// as conflicts. A rule that is a conflict is listed there only.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MergeView {
    /// Rules only the user has: added on top of the rules in force.
    pub added: Vec<RuleRow>,
    pub changed: Vec<RuleRow>,
    pub removed: Vec<RuleRow>,
    pub conflicts: Vec<Conflict>,
}

impl MergeView {
    /// The edits already match the rules in force: nothing to review.
    pub fn is_noop(&self) -> bool {
        self.added.is_empty()
            && self.changed.is_empty()
            && self.removed.is_empty()
            && self.conflicts.is_empty()
    }
}

pub fn merge_view(rebase: &Rebase) -> MergeView {
    let in_conflict: HashSet<&str> = rebase.conflicts.iter().map(|c| c.key.as_str()).collect();
    let outside = |rows: &[RuleRow]| -> Vec<RuleRow> {
        rows.iter()
            .filter(|row| !in_conflict.contains(row.merge_key().as_str()))
            .cloned()
            .collect()
    };
    MergeView {
        added: outside(&rebase.added),
        changed: outside(&rebase.changed),
        removed: outside(&rebase.removed),
        conflicts: rebase.conflicts.clone(),
    }
}

/// The keys to pass to [`rebase_edits`] as `keep_theirs`: every conflict whose
/// pick is the rules in force (`true`).
pub fn keep_theirs_from_picks(picks: &[(String, bool)]) -> Vec<String> {
    picks
        .iter()
        .filter(|(_, theirs)| *theirs)
        .map(|(key, _)| key.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules_table::{RuleType, TargetRoute};

    fn rule(id: &str, value: &str) -> RuleRow {
        RuleRow {
            id: id.into(),
            enabled: true,
            rule_type: RuleType::Domain,
            match_value: value.into(),
            target_route: TargetRoute::Secondary,
            verify: false,
            comment: String::new(),
            origin: None,
        }
    }

    fn off(mut row: RuleRow) -> RuleRow {
        row.enabled = false;
        row
    }

    fn values(rows: &[RuleRow]) -> Vec<&str> {
        rows.iter().map(|r| r.match_value.as_str()).collect()
    }

    #[test]
    fn nothing_edited_leaves_fresh_alone() {
        let base = [rule("R-0001", "a.example")];
        let fresh = [rule("R-0001", "a.example"), rule("R-0002", "b.example")];
        let out = rebase_edits(&base, &base, &fresh, &[]);
        assert_eq!(out.rows, fresh);
        assert!(out.conflicts.is_empty() && out.added.is_empty() && out.removed.is_empty());
    }

    #[test]
    fn a_deleted_rule_stays_deleted_and_a_foreign_one_stays() {
        let base = [rule("R-0001", "a.example"), rule("R-0002", "b.example")];
        let edited = [rule("R-0001", "a.example")];
        let fresh = [
            rule("R-0001", "a.example"),
            rule("R-0002", "b.example"),
            rule("R-0003", "theirs.example"),
        ];
        let out = rebase_edits(&base, &edited, &fresh, &[]);
        assert_eq!(values(&out.rows), ["a.example", "theirs.example"]);
        assert_eq!(values(&out.removed), ["b.example"]);
        assert!(out.conflicts.is_empty());
    }

    #[test]
    fn a_deletion_of_a_rule_already_gone_is_nothing() {
        let base = [rule("R-0001", "a.example"), rule("R-0002", "b.example")];
        let edited = [rule("R-0001", "a.example")];
        let fresh = [rule("R-0001", "a.example")];
        let out = rebase_edits(&base, &edited, &fresh, &[]);
        assert_eq!(out.rows, fresh);
        assert!(out.removed.is_empty() && out.conflicts.is_empty());
    }

    #[test]
    fn a_change_and_an_addition_go_on_top() {
        let base = [rule("R-0001", "a.example")];
        let edited = [
            off(rule("R-0001", "a.example")),
            rule("R-0002", "mine.example"),
        ];
        let fresh = [
            rule("R-0007", "a.example"),
            rule("R-0008", "theirs.example"),
        ];
        let out = rebase_edits(&base, &edited, &fresh, &[]);
        assert_eq!(
            values(&out.rows),
            ["a.example", "theirs.example", "mine.example"]
        );
        assert!(!out.rows[0].enabled);
        assert_eq!(out.rows[0].id, "R-0007");
        assert_eq!(out.rows[2].id, "");
        assert_eq!(values(&out.added), ["mine.example"]);
        assert_eq!(values(&out.changed), ["a.example"]);
    }

    #[test]
    fn both_changing_one_rule_is_listed_and_the_user_wins() {
        let base = [rule("R-0001", "a.example")];
        let edited = [off(rule("R-0001", "a.example"))];
        let mut theirs = rule("R-0001", "a.example");
        theirs.comment = "theirs".into();
        let out = rebase_edits(&base, &edited, &[theirs], &[]);
        assert!(!out.rows[0].enabled);
        assert_eq!(out.conflicts.len(), 1);
        assert_eq!(out.conflicts[0].kind, ConflictKind::ChangedBoth);
    }

    #[test]
    fn keeping_theirs_turns_a_conflict_round() {
        let base = [rule("R-0001", "a.example")];
        let edited = [off(rule("R-0001", "a.example"))];
        let mut theirs = rule("R-0001", "a.example");
        theirs.comment = "theirs".into();
        let key = theirs.merge_key();
        let out = rebase_edits(&base, &edited, &[theirs.clone()], &[key]);
        assert_eq!(out.rows, [theirs]);
        assert_eq!(out.conflicts.len(), 1);
        assert!(out.changed.is_empty());
    }

    #[test]
    fn an_edit_of_a_rule_deleted_elsewhere_brings_it_back_unless_declined() {
        let base = [rule("R-0001", "a.example")];
        let edited = [off(rule("R-0001", "a.example"))];
        let out = rebase_edits(&base, &edited, &[], &[]);
        assert_eq!(values(&out.rows), ["a.example"]);
        assert_eq!(
            out.conflicts[0].kind,
            ConflictKind::EditedButDeletedElsewhere
        );
        let key = edited[0].merge_key();
        let out = rebase_edits(&base, &edited, &[], &[key]);
        assert!(out.rows.is_empty());
    }

    #[test]
    fn a_deletion_of_a_rule_changed_elsewhere_is_listed() {
        let base = [rule("R-0001", "a.example")];
        let fresh = [off(rule("R-0001", "a.example"))];
        let out = rebase_edits(&base, &[], &fresh, &[]);
        assert!(out.rows.is_empty());
        assert_eq!(
            out.conflicts[0].kind,
            ConflictKind::DeletedButChangedElsewhere
        );
        let key = fresh[0].merge_key();
        let out = rebase_edits(&base, &[], &fresh, &[key]);
        assert_eq!(out.rows, fresh);
    }

    #[test]
    fn the_review_lists_a_conflicting_rule_once_as_a_conflict() {
        let base = [rule("R-0001", "a.example"), rule("R-0002", "gone.example")];
        let edited = [
            off(rule("R-0001", "a.example")),
            rule("R-0009", "mine.example"),
        ];
        let mut theirs = rule("R-0001", "a.example");
        theirs.comment = "theirs".into();
        let out = rebase_edits(
            &base,
            &edited,
            &[theirs, rule("R-0002", "gone.example")],
            &[],
        );
        let view = merge_view(&out);
        assert_eq!(view.conflicts.len(), 1);
        assert!(view.changed.is_empty(), "the conflict is not also a change");
        assert_eq!(values(&view.added), ["mine.example"]);
        assert_eq!(values(&view.removed), ["gone.example"]);
        assert!(!view.is_noop());
    }

    #[test]
    fn edits_that_match_what_is_in_force_are_a_noop() {
        let base = [rule("R-0001", "a.example")];
        let fresh = [
            rule("R-0001", "a.example"),
            rule("R-0002", "theirs.example"),
        ];
        assert!(merge_view(&rebase_edits(&base, &base, &fresh, &[])).is_noop());
    }

    #[test]
    fn only_the_picks_for_the_rules_in_force_are_kept() {
        let picks = [
            ("a".to_string(), true),
            ("b".to_string(), false),
            ("c".to_string(), true),
        ];
        assert_eq!(keep_theirs_from_picks(&picks), ["a", "c"]);
    }

    #[test]
    fn the_same_rule_added_on_both_sides_is_one_rule() {
        let edited = [rule("R-0001", "a.example")];
        let fresh = [rule("R-0004", "a.example")];
        let out = rebase_edits(&[], &edited, &fresh, &[]);
        assert_eq!(out.rows, fresh);
        assert!(out.conflicts.is_empty());
    }
}
