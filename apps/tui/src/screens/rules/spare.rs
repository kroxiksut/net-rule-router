//! `C`: exact rules a wildcard rule of the same route already covers. Removing
//! one changes nothing about where traffic goes; `rules_overlap::find_overlaps`
//! decides which they are, as for the GUI's cleanup. The removal is an edit
//! like any other and reaches the service with the next apply.

use nrr_client_logic::Route;
use nrr_shared::display_text::display_text;
use nrr_shared::rules_overlap::find_overlaps;

use super::{ace, apply, ask, locked, text, ChoicePurpose, Note};
use crate::i18n::Texts;
use crate::state::AppState;

/// Covered rules listed in the question before the rest are counted.
const LISTED: usize = 8;

/// One spare rule and the wildcard that covers it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Spare {
    bucket: Route,
    rule_id: String,
    host: String,
    apex: String,
}

/// The spare rules on screen, one entry per rule; none when the list is one
/// the wire refuses, so there is nothing to compare.
pub fn spare_rules(app: &AppState) -> Vec<Spare> {
    let Ok(book) = apply::book_of(app.rules.table.rules()) else {
        return Vec::new();
    };
    let mut out: Vec<Spare> = Vec::new();
    for pair in find_overlaps(&book).into_iter().filter(|p| p.redundant) {
        let Some(bucket) = Route::from_slug(&pair.covered_route) else {
            continue;
        };
        // A host under two wildcards is one rule to remove, not two.
        if out
            .iter()
            .any(|s| s.bucket == bucket && s.rule_id == pair.covered_rule_id)
        {
            continue;
        }
        out.push(Spare {
            bucket,
            rule_id: pair.covered_rule_id,
            host: pair.covered_host,
            apex: pair.apex,
        });
    }
    out
}

/// `C`: ask before removing; nothing to remove is said, not silently ignored.
pub fn start(app: &mut AppState) -> bool {
    if locked(app) {
        return true;
    }
    let spare = spare_rules(app);
    if spare.is_empty() {
        app.rules.note = Some(Note::new(text::SPARE_NONE));
    } else {
        ask(app, ChoicePurpose::RemoveSpare(spare));
    }
    true
}

/// The answer "remove": every listed rule still in the list goes.
pub fn remove(app: &mut AppState, spare: &[Spare]) {
    let table = &mut app.rules.table;
    let mut at: Vec<usize> = spare
        .iter()
        .filter_map(|s| table.find(s.bucket, &s.rule_id))
        .collect();
    at.sort_unstable();
    at.dedup();
    for i in at.iter().rev() {
        table.rows.remove(*i);
    }
    table.clamp_cursor();
    if !at.is_empty() {
        app.rules.note = Some(Note::counted(text::SPARE_REMOVED, at.len()));
    }
}

/// The question's details: why removing is safe, then the rules it removes.
pub fn details(spare: &[Spare], texts: &Texts) -> Vec<String> {
    let mut lines = vec![texts.get(text::SPARE_BODY)];
    for s in spare.iter().take(LISTED) {
        lines.push(texts.fill(
            text::SPARE_ITEM,
            &[
                ("host", display_text(&ace::decode(&s.host)).into_owned()),
                ("apex", display_text(&ace::decode(&s.apex)).into_owned()),
            ],
        ));
    }
    let more = spare.len().saturating_sub(LISTED);
    if more > 0 {
        lines.push(texts.fill(text::OVERLAPS_MORE, &[("count", more.to_string())]));
    }
    lines
}

/// The line on the rules screen while there is something to remove.
pub fn offer(spare: usize, texts: &Texts) -> String {
    format!(
        "C: {}",
        texts.fill(text::SPARE_ACTION, &[("n", spare.to_string())])
    )
}
