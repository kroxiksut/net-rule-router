//! What a user changed in their own rules lately, told from adjacent revisions
//! of their rule set. Nothing is recorded for it: the revisions already hold
//! the history, and this runs only when a client asks.
//!
//! A rule's id is its position in the set, so rules are matched across
//! revisions by type and value. An import replaces the set as one event.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

use nrr_domain::rules_revision::RulesRevisionSource;
use nrr_shared::ipc_payloads::{
    RecentRuleChangeDto, RecentRuleChangeKind, RecentRulePreviousDto, RuleRowEntry,
    RulesRecentChangesResponse, MAX_RECENT_REPLACED_MEMBERS, MAX_RECENT_RULE_CHANGES,
    RECENT_RULE_CHANGES_TEXT_BUDGET,
};
use nrr_shared::rules_json::{CanonicalRulesJsonV1, RuleAction, RuleDto};
use nrr_storage::revisions::{EnforcedRevisionStamp, RevisionsRepository};
use nrr_storage::BASELINE_PRINCIPAL;
use rusqlite::Connection;

/// Most revisions one answer compares. The default retention keeps no more.
pub const MAX_COMPARED_REVISIONS: usize = 100;

/// The lowest count cap revision retention accepts: below it, nothing of a
/// period this short has been pruned.
const RETENTION_MIN_SUPERSEDED_CAP: usize = 20;

/// One stored set, as it came into force.
pub struct ChainStep {
    pub at: i64,
    /// An import: one event for the whole set.
    pub replaces: bool,
    pub book: CanonicalRulesJsonV1,
}

/// The sets a period went through, oldest first.
pub struct Chain {
    /// The set in force when the period began.
    pub base: CanonicalRulesJsonV1,
    pub steps: Vec<ChainStep>,
    /// The history begins inside the period, at this moment.
    pub history_starts_at: Option<i64>,
    /// More revisions fell in the period than one answer compares.
    pub truncated: bool,
}

type RuleKey = (&'static str, String);

#[derive(Clone, Copy)]
struct Held<'a> {
    dto: &'a RuleDto,
    bucket: &'static str,
}

impl Held<'_> {
    fn route(&self) -> &str {
        match self.dto.action {
            RuleAction::Block => "block",
            _ => self.bucket,
        }
    }

    fn verify(&self) -> bool {
        self.dto.action == RuleAction::VerifyPrimary
    }

    /// What the user sees change: the route, the `?` and the switch. A note
    /// edited alone is not a change of the rule.
    fn same_effect(&self, other: &Held<'_>) -> bool {
        self.route() == other.route()
            && self.verify() == other.verify()
            && self.dto.enabled == other.dto.enabled
    }

    fn row(&self) -> RuleRowEntry {
        let mut row = crate::production_handlers_misc::rule_dto_to_row(self.dto, self.bucket);
        row.id.clear();
        row
    }
}

fn key_of(dto: &RuleDto) -> Option<RuleKey> {
    nrr_domain::rule_value_validation::wire_rule_values(dto)
        .next()
        .map(|(kind, value)| (kind, value.to_lowercase()))
}

/// The rules of `book` by key; a key held twice keeps its first rule.
fn index(book: &CanonicalRulesJsonV1) -> HashMap<RuleKey, Held<'_>> {
    let mut out = HashMap::new();
    let buckets = [("primary", &book.primary), ("secondary", &book.secondary)];
    for (bucket, rules) in buckets {
        for dto in rules.iter().filter(|d| !d.is_unrecognized()) {
            if let Some(key) = key_of(dto) {
                out.entry(key).or_insert(Held { dto, bucket });
            }
        }
    }
    out
}

struct Touched<'a> {
    /// At the start of the period (or after the last replace).
    before: Option<Held<'a>>,
    /// The last state while the rule was in the set.
    last_present: Option<Held<'a>>,
    at: i64,
}

fn touch<'a>(
    touched: &mut HashMap<RuleKey, Touched<'a>>,
    key: &RuleKey,
    before: Option<Held<'a>>,
    after: Option<Held<'a>>,
    at: i64,
) {
    let entry = touched.entry(key.clone()).or_insert(Touched {
        before,
        last_present: before,
        at,
    });
    entry.at = at;
    entry.last_present = after.or(before);
}

/// The changes `chain` went through, newest first. `in_force` is the set the
/// user is under now; it says whether a deleted rule is back.
pub fn changes_of(
    chain: &Chain,
    in_force: Option<&CanonicalRulesJsonV1>,
) -> RulesRecentChangesResponse {
    let mut prev = index(&chain.base);
    let mut touched: HashMap<RuleKey, Touched<'_>> = HashMap::new();
    let mut replaced: Vec<(i64, &CanonicalRulesJsonV1)> = Vec::new();
    for step in &chain.steps {
        let next = index(&step.book);
        if step.replaces {
            // What the replace swept away is not told rule by rule.
            replaced.push((step.at, &step.book));
            touched.clear();
            prev = next;
            continue;
        }
        for (key, before) in &prev {
            match next.get(key) {
                None => touch(&mut touched, key, Some(*before), None, step.at),
                Some(after) if !before.same_effect(after) => {
                    touch(&mut touched, key, Some(*before), Some(*after), step.at);
                }
                Some(_) => {}
            }
        }
        for (key, after) in &next {
            if !prev.contains_key(key) {
                touch(&mut touched, key, None, Some(*after), step.at);
            }
        }
        prev = next;
    }

    let held_now = in_force.map(index).unwrap_or_default();
    let mut changes: Vec<RecentRuleChangeDto> = Vec::new();
    for (key, t) in &touched {
        let change = match (t.before, prev.get(key)) {
            (None, Some(now)) => entry(RecentRuleChangeKind::Added, t.at, now.row()),
            (Some(before), Some(now)) if !before.same_effect(now) => RecentRuleChangeDto {
                previous: Some(RecentRulePreviousDto {
                    target_route: before.route().to_owned(),
                    enabled: before.dto.enabled,
                    verify: before.verify(),
                }),
                ..entry(RecentRuleChangeKind::Changed, t.at, now.row())
            },
            (_, None) => match t.last_present {
                Some(last) => RecentRuleChangeDto {
                    exists_now: held_now.contains_key(key),
                    ..entry(RecentRuleChangeKind::Deleted, t.at, last.row())
                },
                None => continue,
            },
            (Some(_), Some(_)) => continue,
        };
        changes.push(change);
    }
    for (at, book) in replaced {
        let rules = index(book);
        let mut members: Vec<(&RuleKey, &Held<'_>)> = rules.iter().collect();
        members.sort_by(|a, b| a.0.cmp(b.0));
        changes.push(RecentRuleChangeDto {
            kind: RecentRuleChangeKind::Replaced,
            at,
            rule: None,
            previous: None,
            exists_now: false,
            count: u32::try_from(rules.len()).unwrap_or(u32::MAX),
            members: members
                .into_iter()
                .take(MAX_RECENT_REPLACED_MEMBERS)
                .map(|(_, held)| held.row())
                .collect(),
        });
    }
    changes.sort_by(|a, b| {
        b.at.cmp(&a.at)
            .then_with(|| kind_rank(a.kind).cmp(&kind_rank(b.kind)))
            .then_with(|| sort_key(a).cmp(&sort_key(b)))
    });

    let mut response = RulesRecentChangesResponse {
        changes: Vec::new(),
        history_starts_at: chain.history_starts_at,
        truncated: chain.truncated,
    };
    let mut budget = RECENT_RULE_CHANGES_TEXT_BUDGET;
    for change in changes {
        let cost = text_cost(&change);
        if response.changes.len() >= MAX_RECENT_RULE_CHANGES || cost > budget {
            response.truncated = true;
            break;
        }
        budget -= cost;
        response.changes.push(change);
    }
    response
}

fn entry(kind: RecentRuleChangeKind, at: i64, rule: RuleRowEntry) -> RecentRuleChangeDto {
    RecentRuleChangeDto {
        kind,
        at,
        rule: Some(rule),
        previous: None,
        exists_now: false,
        count: 0,
        members: Vec::new(),
    }
}

fn kind_rank(kind: RecentRuleChangeKind) -> u8 {
    match kind {
        RecentRuleChangeKind::Added => 0,
        RecentRuleChangeKind::Changed => 1,
        RecentRuleChangeKind::Deleted => 2,
        RecentRuleChangeKind::Replaced => 3,
    }
}

fn sort_key(change: &RecentRuleChangeDto) -> (&str, &str) {
    change
        .rule
        .as_ref()
        .map_or(("", ""), |r| (r.rule_type.as_str(), r.match_value.as_str()))
}

fn row_cost(row: &RuleRowEntry) -> usize {
    row.match_value.len() + row.comment.as_ref().map_or(0, String::len)
}

fn text_cost(change: &RecentRuleChangeDto) -> usize {
    change.rule.as_ref().map_or(0, row_cost) + change.members.iter().map(row_cost).sum::<usize>()
}

// ── Reading the chain ────────────────────────────────────────────────────────

fn lock(conn: &Mutex<Connection>) -> std::sync::MutexGuard<'_, Connection> {
    conn.lock().unwrap_or_else(PoisonError::into_inner)
}

/// One revision's rules, read under a lock of its own: the blobs are read one
/// at a time so the state database is never held for the whole walk.
fn book_of(
    conn: &Mutex<Connection>,
    principal: &str,
    stamp: &EnforcedRevisionStamp,
) -> Result<Option<CanonicalRulesJsonV1>, String> {
    let record = {
        let guard = lock(conn);
        RevisionsRepository::new(&guard)
            .get_by_id_for(principal, &stamp.revision_id)
            .map_err(|e| e.to_string())?
    };
    Ok(record.and_then(|r| {
        crate::production_rules_provider::read_stored_rules(&r.rules_json, &r.revision_id).ok()
    }))
}

/// The set the user's first own revision was made from: the baseline in force
/// at that moment, or no rules when there has never been a baseline. `None`
/// when history no longer holds it.
fn baseline_at(conn: &Mutex<Connection>, at: i64) -> Result<Option<CanonicalRulesJsonV1>, String> {
    let (then, ever) = {
        let guard = lock(conn);
        let repo = RevisionsRepository::new(&guard);
        let then = repo
            .last_enforced_before_for(BASELINE_PRINCIPAL, at.saturating_add(1))
            .map_err(|e| e.to_string())?;
        let ever = repo
            .last_enforced_before_for(BASELINE_PRINCIPAL, i64::MAX)
            .map_err(|e| e.to_string())?;
        (then, ever)
    };
    match (then, ever) {
        (Some(stamp), _) => book_of(conn, BASELINE_PRINCIPAL, &stamp),
        (None, None) => Ok(Some(empty_book())),
        (None, Some(_)) => Ok(None),
    }
}

fn empty_book() -> CanonicalRulesJsonV1 {
    CanonicalRulesJsonV1 {
        schema_version: 1,
        primary: Vec::new(),
        secondary: Vec::new(),
    }
}

/// The chain `principal`'s own revisions went through from `since`.
pub fn read_chain(
    conn: &Mutex<Connection>,
    principal: &str,
    since: i64,
) -> Result<Option<Chain>, String> {
    let (mut stamps, before, superseded) = {
        let guard = lock(conn);
        let repo = RevisionsRepository::new(&guard);
        let stamps = repo
            .enforced_since_for(principal, since, MAX_COMPARED_REVISIONS + 1)
            .map_err(|e| e.to_string())?;
        let before = repo
            .last_enforced_before_for(principal, since)
            .map_err(|e| e.to_string())?;
        let superseded = repo
            .superseded_count_since_for(principal, since)
            .map_err(|e| e.to_string())?;
        (stamps, before, superseded)
    };
    if stamps.is_empty() {
        return Ok(None);
    }
    stamps.reverse();
    let mut truncated = false;
    let mut history_starts_at = None;
    // The set the period starts from, and the stamps after it.
    let (base_stamp, rest): (Option<EnforcedRevisionStamp>, Vec<EnforcedRevisionStamp>) =
        if stamps.len() > MAX_COMPARED_REVISIONS {
            truncated = true;
            let base = stamps.remove(0);
            history_starts_at = Some(base.activated_at);
            (Some(base), stamps)
        } else {
            (before, stamps)
        };
    let mut rest = rest.into_iter().peekable();
    let mut base_hash = base_stamp.as_ref().map(|s| s.content_hash.clone());
    let base = match base_stamp {
        Some(stamp) => book_of(conn, principal, &stamp)?,
        None => {
            // The user's first own revision is made from the baseline. Only
            // when nothing older can have been pruned: a rollback re-enters
            // history, and a full count cap means older rows went.
            let first = rest.peek().map(|s| (s.activated_at, s.source));
            match first {
                Some((
                    at,
                    RulesRevisionSource::GuiRulesEdit | RulesRevisionSource::PresetImport,
                )) if superseded < RETENTION_MIN_SUPERSEDED_CAP => baseline_at(conn, at)?,
                _ => None,
            }
        }
    };
    let base = match base {
        Some(book) => book,
        None => {
            // The history begins inside the period: its first set is where
            // the telling starts.
            let Some(first) = rest.next() else {
                return Ok(None);
            };
            history_starts_at = Some(first.activated_at);
            base_hash = Some(first.content_hash.clone());
            book_of(conn, principal, &first)?.unwrap_or_else(empty_book)
        }
    };
    let mut steps: Vec<ChainStep> = Vec::new();
    for stamp in rest {
        if base_hash.as_deref() == Some(stamp.content_hash.as_str()) {
            continue;
        }
        // A revision that no longer reads is skipped: the next one is
        // compared with the last that did.
        let Some(book) = book_of(conn, principal, &stamp)? else {
            continue;
        };
        base_hash = Some(stamp.content_hash.clone());
        steps.push(ChainStep {
            at: stamp.activated_at,
            replaces: stamp.source == RulesRevisionSource::PresetImport,
            book,
        });
    }
    Ok(Some(Chain {
        base,
        steps,
        history_starts_at,
        truncated,
    }))
}

/// `rules.recent-changes.list` for `principal`, from `since` (already held to
/// the period the service allows) to `now`.
pub fn read_for(
    conn: &Mutex<Connection>,
    principal: &str,
    since: i64,
    _now: i64,
) -> Result<RulesRecentChangesResponse, String> {
    let Some(chain) = read_chain(conn, principal, since)? else {
        return Ok(RulesRecentChangesResponse::default());
    };
    let in_force = {
        let guard = lock(conn);
        crate::production_rules_provider::stored_book_in_force_for(&guard, principal)
    };
    Ok(changes_of(&chain, in_force.as_ref()))
}

#[cfg(test)]
mod tests;
