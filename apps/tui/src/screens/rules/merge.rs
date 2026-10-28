//! Two versions of the rules laid over each other, shown before anything is
//! replaced, one pick for each rule both sides touched. Either your edits over
//! rules that changed elsewhere (what only your edits hold, what you changed
//! or deleted) or the bound rules files against the rules the service
//! enforces (what only the files hold, what only the service has). The
//! window's merge dialog says the same; the confirmed result goes to the
//! ordinary review, as there.

use crossterm::event::{KeyCode, KeyEvent};
use nrr_client_logic::rebase::{keep_theirs_from_picks, Conflict, MergeView};
use nrr_client_logic::rules_table::{RuleRow, TargetRoute};
use nrr_shared::display_text::display_text;
use nrr_shared::ipc_payloads::RuleRowEntry;

use super::render::{route_text, type_label};
use super::table::Edits;
use super::{file_merge, overlaps, start_apply, text, Mode, Note};
use crate::i18n::{Key, Texts};
use crate::state::{AppState, Focus};
use crate::view::{Segment, ViewLine};

/// The edits and the rules in force they would go over.
#[derive(Debug)]
struct EditsSide {
    edits: Edits,
    /// The rules in force as the service listed them; they replace the list
    /// only when the merge is confirmed.
    rows: Vec<RuleRowEntry>,
    base_revision: Option<String>,
    unrecognized: u32,
}

/// What is merged, until the user picks.
#[derive(Debug)]
enum Source {
    Edits(EditsSide),
    /// The bound files' text, to ask the service again with the picks.
    Files([String; 2]),
}

/// A rule one of the books names in both sets with both copies on; the merge
/// keeps the main route's copy unless the user picks the other.
#[derive(Debug)]
pub struct Duplicate {
    pub key: String,
    /// What both copies match, as written.
    pub summary: String,
}

#[derive(Debug)]
pub struct Merge {
    source: Source,
    view: MergeView,
    /// Per conflict: `true` keeps the rules in force, `false` your version.
    theirs: Vec<bool>,
    duplicates: Vec<Duplicate>,
    /// Per duplicate: `true` keeps the additional route's copy.
    keep_secondary: Vec<bool>,
    /// Over the conflicts, then the duplicates.
    cursor: usize,
}

impl Merge {
    pub fn new(
        edits: Edits,
        rows: Vec<RuleRowEntry>,
        base_revision: Option<String>,
        unrecognized: u32,
        view: MergeView,
    ) -> Self {
        let side = EditsSide {
            edits,
            rows,
            base_revision,
            unrecognized,
        };
        Self::of(Source::Edits(side), view, Vec::new())
    }

    /// The bound files' text (primary, secondary) against the rules the
    /// service enforces.
    pub fn files(texts: [String; 2], view: MergeView, duplicates: Vec<Duplicate>) -> Self {
        Self::of(Source::Files(texts), view, duplicates)
    }

    fn of(source: Source, view: MergeView, duplicates: Vec<Duplicate>) -> Self {
        Self {
            theirs: vec![false; view.conflicts.len()],
            keep_secondary: vec![false; duplicates.len()],
            duplicates,
            source,
            view,
            cursor: 0,
        }
    }

    /// The duplicates whose additional route's copy stays, for the service.
    fn keep_secondary_keys(&self) -> Vec<String> {
        self.duplicates
            .iter()
            .zip(&self.keep_secondary)
            .filter(|(_, keep)| **keep)
            .map(|(d, _)| d.key.clone())
            .collect()
    }

    fn picks_len(&self) -> usize {
        self.theirs.len() + self.keep_secondary.len()
    }

    fn wording(&self) -> Wording {
        match self.source {
            Source::Edits(_) => Wording {
                title: text::MERGE_TITLE,
                body: text::MERGE_BODY,
                added: text::MERGE_BUCKET_ADDED,
                removed: text::MERGE_BUCKET_DELETED,
                mine: text::MERGE_PICK_MINE,
                theirs: text::MERGE_PICK_THEIRS,
            },
            Source::Files(_) => Wording {
                title: text::FILES_MERGE_TITLE,
                body: text::FILES_MERGE_BODY,
                added: text::FILES_MERGE_BUCKET_FILE,
                removed: text::FILES_MERGE_BUCKET_SERVICE,
                mine: text::FILES_MERGE_PICK_FILE,
                theirs: text::FILES_MERGE_PICK_SERVICE,
            },
        }
    }

    fn toggle(&mut self, at: usize) {
        let conflicts = self.theirs.len();
        let pick = match at.checked_sub(conflicts) {
            None => self.theirs.get_mut(at),
            Some(dup) => self.keep_secondary.get_mut(dup),
        };
        if let Some(pick) = pick {
            *pick = !*pick;
            self.cursor = at;
        }
    }

    /// The conflicts to turn round, for `rebase_edits`.
    fn keep_theirs(&self) -> Vec<String> {
        keep_theirs_from_picks(&self.picks())
    }

    fn picks(&self) -> Vec<(String, bool)> {
        self.view
            .conflicts
            .iter()
            .zip(&self.theirs)
            .map(|(conflict, theirs)| (conflict.key.clone(), *theirs))
            .collect()
    }
}

/// The words of one kind of merge.
struct Wording {
    title: Key,
    body: Key,
    added: Key,
    removed: Key,
    mine: Key,
    theirs: Key,
}

pub fn title(merge: &Merge) -> Key {
    merge.wording().title
}

/// The rule as the lists show it, in one line.
fn item(rule: &RuleRow, texts: &Texts) -> String {
    let mut line = format!(
        "{} {} \u{2192} {}",
        type_label(&rule.rule_type, texts),
        display_text(&rule.match_value),
        route_text(&rule.target_route, texts)
    );
    if rule.verify {
        line.push_str(" ?");
    }
    if !rule.enabled {
        line.push_str(&format!(" ({})", texts.get(text::DISABLED)));
    }
    line
}

fn side(rule: Option<&RuleRow>, texts: &Texts) -> String {
    rule.map_or_else(|| texts.get(text::MERGE_SIDE_DELETED), |r| item(r, texts))
}

fn bucket(lines: &mut Vec<ViewLine>, title: String, rules: &[RuleRow], texts: &Texts) {
    if rules.is_empty() {
        return;
    }
    lines.push(ViewLine::new(vec![Segment::strong(format!(
        "{title} ({})",
        rules.len()
    ))]));
    for rule in rules {
        lines.push(ViewLine::text(format!("  {}", item(rule, texts))));
    }
}

pub fn lines(app: &AppState, merge: &Merge, texts: &Texts) -> Vec<ViewLine> {
    let words = merge.wording();
    let mut lines = vec![ViewLine::text(texts.get(words.body))];
    let view = &merge.view;
    bucket(&mut lines, texts.get(words.added), &view.added, texts);
    bucket(
        &mut lines,
        texts.get(text::MERGE_BUCKET_CHANGED),
        &view.changed,
        texts,
    );
    bucket(&mut lines, texts.get(words.removed), &view.removed, texts);
    if !view.conflicts.is_empty() {
        lines.push(ViewLine::new(vec![Segment::strong(format!(
            "{} ({})",
            texts.get(text::MERGE_BUCKET_CONFLICTS),
            view.conflicts.len()
        ))]));
        for (at, conflict) in view.conflicts.iter().enumerate() {
            lines.extend(conflict_lines(app, merge, at, conflict, texts));
        }
    }
    duplicate_lines(&mut lines, app, merge, texts);
    lines.push(ViewLine::text(texts.get(text::MERGE_KEYS)));
    lines
}

/// The rules a book names in both sets, numbered on after the conflicts,
/// each with the route whose copy stays.
fn duplicate_lines(lines: &mut Vec<ViewLine>, app: &AppState, merge: &Merge, texts: &Texts) {
    if merge.duplicates.is_empty() {
        return;
    }
    lines.push(ViewLine::new(vec![Segment::strong(format!(
        "{} ({})",
        texts.get(text::FILES_MERGE_DUPLICATES),
        merge.duplicates.len()
    ))]));
    lines.push(ViewLine::text(texts.get(text::FILES_MERGE_DUPLICATES_HINT)));
    let first = merge.theirs.len();
    for (i, duplicate) in merge.duplicates.iter().enumerate() {
        let at = first + i;
        let route = if merge.keep_secondary.get(i).copied().unwrap_or(false) {
            TargetRoute::Secondary
        } else {
            TargetRoute::Primary
        };
        let head = format!(
            "{}. {} \u{2014} {}",
            at + 1,
            display_text(&duplicate.summary),
            texts.fill(text::MERGE_STAYS, &[("side", route_text(&route, texts))])
        );
        lines.push(if at == merge.cursor && app.focus == Focus::Feed {
            ViewLine::new(vec![Segment::selected(format!("> {head}"))])
        } else {
            ViewLine::text(format!("  {head}"))
        });
    }
}

fn conflict_lines(
    app: &AppState,
    merge: &Merge,
    at: usize,
    conflict: &Conflict,
    texts: &Texts,
) -> Vec<ViewLine> {
    let words = merge.wording();
    let theirs = merge.theirs.get(at).copied().unwrap_or(false);
    let stays = texts.get(if theirs { words.theirs } else { words.mine });
    let any = conflict.mine.as_ref().or(conflict.theirs.as_ref());
    let name = any.map_or_else(String::new, |rule| {
        format!(
            "{} {}",
            type_label(&rule.rule_type, texts),
            display_text(&rule.match_value)
        )
    });
    let head = format!(
        "{}. {name} \u{2014} {}",
        at + 1,
        texts.fill(text::MERGE_STAYS, &[("side", stays)])
    );
    let chosen = at == merge.cursor && app.focus == Focus::Feed;
    let head = if chosen {
        ViewLine::new(vec![Segment::selected(format!("> {head}"))])
    } else {
        ViewLine::text(format!("  {head}"))
    };
    vec![
        head,
        ViewLine::text(format!(
            "     {}: {}",
            texts.get(words.mine),
            side(conflict.mine.as_ref(), texts)
        )),
        ViewLine::text(format!(
            "     {}: {}",
            texts.get(words.theirs),
            side(conflict.theirs.as_ref(), texts)
        )),
    ]
}

pub fn on_key(app: &mut AppState, mut merge: Box<Merge>, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Esc | KeyCode::Char('n') => {
            leave(app);
            return true;
        }
        KeyCode::Enter | KeyCode::Char('y') => {
            confirm(app, merge);
            return true;
        }
        KeyCode::Up => merge.cursor = merge.cursor.saturating_sub(1),
        KeyCode::Down => {
            merge.cursor = (merge.cursor + 1).min(merge.picks_len().saturating_sub(1));
        }
        KeyCode::Char(' ') | KeyCode::Left | KeyCode::Right => {
            let at = merge.cursor;
            merge.toggle(at);
        }
        KeyCode::Char(c) => {
            if let Some(n) = c.to_digit(10).map(|n| n as usize) {
                if n >= 1 {
                    merge.toggle(n - 1);
                }
            }
        }
        KeyCode::F(1) => {
            app.rules.mode = Mode::Merge(merge);
            return false;
        }
        _ => {}
    }
    app.rules.mode = Mode::Merge(merge);
    true
}

/// A line while the merge is shown (`--plain`): a number switches that
/// conflict's side, `y` merges, `n` leaves.
pub fn on_line(app: &mut AppState, mut merge: Box<Merge>, line: &str) {
    match line.trim() {
        "y" | "Y" => confirm(app, merge),
        "n" | "N" => leave(app),
        other => {
            if let Ok(n) = other.parse::<usize>() {
                if n >= 1 {
                    merge.toggle(n - 1);
                }
            }
            app.rules.mode = Mode::Merge(merge);
        }
    }
}

/// Nothing is merged: the list, the rules' revision it stands on and the edits
/// are exactly as they were.
fn leave(app: &mut AppState) {
    app.rules.note = Some(Note::new(text::MERGE_CANCELLED));
}

/// The edits go over the rules in force with the picks, and the result is
/// reviewed like any apply.
fn confirm(app: &mut AppState, merge: Box<Merge>) {
    let keep = merge.keep_theirs();
    let picks = merge.picks();
    let keep_secondary = merge.keep_secondary_keys();
    let side = match merge.source {
        Source::Edits(side) => side,
        Source::Files(texts) => {
            file_merge::confirm(app, texts, &picks, keep_secondary);
            return;
        }
    };
    let EditsSide {
        edits,
        rows,
        base_revision,
        unrecognized,
    } = side;
    let rules = &mut app.rules;
    rules.base_revision = base_revision;
    rules.unrecognized = unrecognized;
    rules.table.load(&rows);
    rules.table.apply_edits(edits, &keep);
    rules.note = Some(Note::new(text::REBASED));
    overlaps::refresh(app);
    start_apply(app);
}
