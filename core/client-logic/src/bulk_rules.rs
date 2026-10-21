//! Many rules typed or pasted at once in the rules-file syntax, read line by
//! line into what the Add form would do with each — `planBulkRules` in
//! `rules.js`, held to it by `tests/vectors/bulk_rules.json`.
//!
//! A line under a section header means what an import makes of it: the
//! reading is `nrr_shared::preset_parser`'s own (comment, `#` turned off, `!`,
//! `?`, flags, provenance). Only what a file has no answer for is decided here:
//! the type of a line under no header (by `rule_value_class`, or asked when the
//! word is ambiguous), duplicates, the rule on another route, and the bounds.
//!
//! The text is somebody's clipboard. It is read in one pass and bounded in
//! lines and size; whatever lies past the bound stays in the field with the
//! reason rather than being cut. Any input costs time linear in its length and
//! nothing here panics. The service's validation keeps the last word: the
//! caller judges each row's [`BulkRow::verdict_key`] and passes the answer in,
//! and a row without one waits.

use std::collections::{BTreeMap, HashMap};

use nrr_shared::auto_rule::{parse_provenance_comment, AUTO_SECTION_NAME};
use nrr_shared::preset_parser::{
    carries_retired_block_flag, is_disabled_rule_value, is_syntax_hint_line, parse_section_header,
    split_deny, split_rule_flags, split_rule_markers, split_verify_primary, stored_rule_value,
    unquote_program_value, without_retired_block_flag, RuleFlags,
};
use nrr_shared::rule_value_class::{classify_rule_value, rule_type_from_slug, RuleValueClass};

use crate::rule_value_class::misplaced_target_type;
use crate::rules_table::RuleType;

/// Lines read; the rest stay in the field.
pub const MAX_LINES: usize = 1000;
/// UTF-16 units of the lines read, newlines included: what the GUI's field
/// counts, so both clients cut at the same line.
pub const MAX_UNITS: usize = 262_144;
/// A longer line is refused on its own.
pub const MAX_LINE_UNITS: usize = 1024;
/// `nrr_domain::preset_validation::MAX_INLINE_COMMENT_CHARS`, which an import
/// enforces; client-logic cannot read it, so the TUI's tests hold the two equal.
pub const COMMENT_MAX_CHARS: usize = 200;

/// Where a row stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RowStatus {
    Ok,
    /// Added, with something to know.
    Warning,
    /// Cannot be added as written.
    Error,
    /// One word: a zone or a program, the user says which.
    NeedsType,
    /// The service's verdict has not come in.
    Pending,
    /// Already in the rules or earlier in the text.
    Duplicate,
    /// The same rule already stands on another route.
    Elsewhere,
}

impl RowStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::NeedsType => "needs-type",
            Self::Pending => "pending",
            Self::Duplicate => "duplicate",
            Self::Elsewhere => "elsewhere",
        }
    }
}

/// What an apply does with a row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RowAction {
    Add,
    /// The existing rule moves to this row's route.
    Move,
    /// Nothing; the line stays in the field.
    Keep,
    /// Nothing; the rule is already there.
    Drop,
}

impl RowAction {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Add => "add",
            Self::Move => "move",
            Self::Keep => "keep",
            Self::Drop => "drop",
        }
    }
}

/// Which bound stopped the reading.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bound {
    Lines,
    Size,
}

impl Bound {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Lines => "lines",
            Self::Size => "size",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerdictLevel {
    Valid,
    Warning,
    Error,
}

impl VerdictLevel {
    /// `"error"`, `"warning"`, anything else valid.
    #[must_use]
    pub fn from_slug(slug: &str) -> Self {
        match slug {
            "error" => Self::Error,
            "warning" => Self::Warning,
            _ => Self::Valid,
        }
    }
}

/// The service's word on one `type|value`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LineVerdict {
    pub level: VerdictLevel,
    pub message_key: String,
    pub args: BTreeMap<String, String>,
}

/// What the user decided on one line's preview row.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LineChoice {
    /// The type picked for a value that does not name its own.
    pub rule_type: Option<String>,
    /// Move the rule that stands on another route.
    pub move_elsewhere: bool,
}

/// A rule already in the list, by any spelling of its type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExistingRule<'a> {
    pub rule_type: &'a str,
    pub value: &'a str,
    pub route: &'a str,
}

pub struct BulkInput<'a> {
    pub text: &'a str,
    /// The route chosen above the field: `primary`, `secondary` or `block`.
    pub route: &'a str,
    /// `PlatformProfile.os`.
    pub os: &'a str,
    /// Application rules work on this system.
    pub apps: bool,
    pub existing: &'a [ExistingRule<'a>],
    /// By 1-based line number.
    pub choices: &'a HashMap<usize, LineChoice>,
    /// By [`BulkRow::verdict_key`].
    pub verdicts: &'a HashMap<String, LineVerdict>,
    /// Rules that may still be added; `None` for no limit.
    pub room: Option<usize>,
}

/// One rule line and what becomes of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BulkRow {
    /// 1-based line number in the text.
    pub line: usize,
    /// The line as written, trimmed.
    pub text: String,
    /// The section header the line stands under, `""` for none.
    pub section: String,
    /// A rule-type slug; `""` while not known.
    pub rule_type: &'static str,
    /// The types the user may pick for this row.
    pub options: Vec<&'static str>,
    /// The match value as a table stores it: `+children` and `+override` kept
    /// on a program.
    pub value: String,
    pub enabled: bool,
    /// `block` for a deny.
    pub route: String,
    pub verify: bool,
    pub comment: String,
    pub status: RowStatus,
    pub message_key: String,
    pub args: BTreeMap<String, String>,
    /// The existing rule it duplicates or that stands elsewhere.
    pub existing: Option<usize>,
    /// That rule's route, for [`RowStatus::Elsewhere`].
    pub other_route: String,
    /// The earlier line it repeats.
    pub same_line: Option<usize>,
    pub move_elsewhere: bool,
    pub action: RowAction,
    /// `type|value`, the verdict this row needs; `""` when it needs none.
    pub verdict_key: String,
    /// Provenance read from an `--- Auto` line, as an import lifts it; empty
    /// for a rule of the user's own.
    pub origin_reason: String,
    pub origin_anchor: String,
    pub origin_added: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BulkPlan {
    pub rows: Vec<BulkRow>,
    /// Lines read.
    pub lines: usize,
    /// Lines past the bound, left unread.
    pub excess: usize,
    pub bound: Option<Bound>,
    /// What the field keeps after an apply: every kept line, under its
    /// section header, then whatever lay past the bound.
    pub remaining: String,
}

impl BulkPlan {
    #[must_use]
    pub fn count(&self, action: RowAction) -> usize {
        self.rows.iter().filter(|r| r.action == action).count()
    }
}

/// What pasting `input.text` into the Add form amounts to.
#[must_use]
pub fn plan_bulk_rules(input: &BulkInput<'_>) -> BulkPlan {
    let text = input.text.strip_prefix('\u{feff}').unwrap_or(input.text);
    let mut planner = Planner::new(input);
    let mut lines = 0usize;
    let mut units = 0usize;
    let mut bound = None;
    let mut cut = None;
    let mut pos = 0usize;
    while pos < text.len() {
        let rest = &text[pos..];
        let (raw, next) = match rest.find('\n') {
            Some(i) => (&rest[..i], Some(pos + i + 1)),
            None => (rest, None),
        };
        if lines == MAX_LINES {
            bound = Some(Bound::Lines);
            cut = Some(pos);
            break;
        }
        let taken = units.saturating_add(utf16_len(raw)).saturating_add(1);
        if taken > MAX_UNITS {
            bound = Some(Bound::Size);
            cut = Some(pos);
            break;
        }
        units = taken;
        lines += 1;
        if let Some(row) = planner.line(raw, lines) {
            planner.rows.push(row);
        }
        match next {
            Some(n) => pos = n,
            None => break,
        }
    }
    let excess = cut.map_or(0, |at| line_count(&text[at..]));
    let remaining = remaining_text(
        &planner.rows,
        cut.map(|at| &text[at..]),
        &planner.section.name,
    );
    let rows = planner.rows;
    BulkPlan {
        rows,
        lines,
        excess,
        bound,
        remaining,
    }
}

/// Kept lines first without a section, then under their headers; the unread
/// tail last, under the section it was cut in.
fn remaining_text(rows: &[BulkRow], tail: Option<&str>, open_section: &str) -> String {
    let mut top: Vec<&str> = Vec::new();
    let mut below: Vec<String> = Vec::new();
    let mut last = String::new();
    for row in rows.iter().filter(|r| r.action == RowAction::Keep) {
        if row.section.is_empty() {
            top.push(&row.text);
            continue;
        }
        let head = format!("--- {}", row.section);
        if head != last {
            below.push(head.clone());
        }
        last = head;
        below.push(row.text.clone());
    }
    if let Some(rest) = tail {
        let rest = rest.strip_suffix('\n').unwrap_or(rest);
        let first = rest.split('\n').next().unwrap_or_default();
        let first = first.strip_suffix('\r').unwrap_or(first);
        let open = if open_section.is_empty() {
            String::new()
        } else {
            format!("--- {open_section}")
        };
        if !open.is_empty() && open != last && parse_section_header(first).is_none() {
            below.push(open);
        }
        below.push(rest.to_owned());
    }
    let mut out: Vec<&str> = top;
    out.extend(below.iter().map(String::as_str));
    out.join("\n")
}

fn utf16_len(s: &str) -> usize {
    s.chars().map(char::len_utf16).sum()
}

fn line_count(s: &str) -> usize {
    if s.is_empty() {
        0
    } else {
        s.matches('\n').count() + usize::from(!s.ends_with('\n'))
    }
}

/// The rule type of a section on `os`; `""` for one not applied here. Names
/// match in any ASCII case, as the rules-file parser reads them.
fn section_type(name: &str, os: &str) -> &'static str {
    let name = name.to_ascii_lowercase();
    let app_section = match os {
        "linux" => "linux",
        "macos" => "macos",
        _ => "windows",
    };
    match name.as_str() {
        "zones" => "zone",
        "domains" | "auto" => "domain",
        "ip" => "exact-ip",
        "cidr" => "subnet",
        "ranges" => "ip-range",
        other if other == app_section => "application",
        _ => "",
    }
}

#[derive(Default)]
struct Section {
    name: String,
    rule_type: &'static str,
}

/// What a header-less value is judged as: the line without its marks and
/// flags. The reading itself is still the file's, once the type is known.
fn classified_core(collapsed: &str) -> String {
    let (after_deny, _) = split_deny(collapsed);
    let (after_verify, _) = split_verify_primary(after_deny);
    if carries_retired_block_flag(after_verify) {
        without_retired_block_flag(after_verify)
    } else {
        after_verify.to_owned()
    }
}

/// [`stored_rule_value`] by type slug; `""` and unknown slugs keep no flag.
fn stored_value(rule_type: &str, value: &str, flags: RuleFlags) -> String {
    match rule_type_from_slug(rule_type) {
        Some(parsed) => stored_rule_value(parsed, value, flags),
        None => value.to_owned(),
    }
}

struct Planner<'a> {
    input: &'a BulkInput<'a>,
    section: Section,
    rows: Vec<BulkRow>,
    /// `type|value|route` of the rows taken so far, by index in `rows`.
    seen: HashMap<String, usize>,
    /// `type|value` of the rows taken so far, by index in `rows`.
    seen_value: HashMap<String, usize>,
    existing_key: HashMap<String, usize>,
    existing_value: HashMap<String, usize>,
    adding: usize,
}

impl<'a> Planner<'a> {
    fn new(input: &'a BulkInput<'a>) -> Self {
        let mut existing_key = HashMap::new();
        let mut existing_value = HashMap::new();
        for (i, rule) in input.existing.iter().enumerate() {
            let same = format!(
                "{}|{}",
                RuleType::from_slug(rule.rule_type).canonical_slug(),
                rule.value.to_lowercase()
            );
            existing_key
                .entry(format!("{same}|{}", rule.route))
                .or_insert(i);
            existing_value.entry(same).or_insert(i);
        }
        Self {
            input,
            section: Section::default(),
            rows: Vec::new(),
            seen: HashMap::new(),
            seen_value: HashMap::new(),
            existing_key,
            existing_value,
            adding: 0,
        }
    }

    fn line(&mut self, raw: &str, line_no: usize) -> Option<BulkRow> {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        if is_syntax_hint_line(line) {
            return None;
        }
        if let Some(name) = parse_section_header(line) {
            self.section = Section {
                name: name.to_owned(),
                rule_type: section_type(name, self.input.os),
            };
            return None;
        }
        let t = line.trim();
        if t.is_empty() || t.starts_with("##") {
            return None;
        }
        let input = self.input;
        let sec_name = self.section.name.clone();
        let sec_type = self.section.rule_type;
        let mut row = new_row(line_no, t, &sec_name, input.route);
        if utf16_len(t) > MAX_LINE_UNITS {
            let args = BTreeMap::from([("max".to_owned(), MAX_LINE_UNITS.to_string())]);
            return Some(fail(row, "rules.paste.too-long", args));
        }
        if t.chars().any(|c| c.is_control() && c != '\t') {
            return Some(fail(row, "rules.paste.control-character", BTreeMap::new()));
        }
        // The file's reading of a rule line, step for step.
        let (body, hashed) = match (t.strip_prefix("# "), t.strip_prefix('#')) {
            (Some(rest), _) => (rest, true),
            (None, Some("")) => return None,
            (None, Some(rest)) => (rest, true),
            (None, None) => (t, false),
        };
        let (value_part, comment) = match body.find('#') {
            Some(at) => (&body[..at], body[at + 1..].trim()),
            None => (body, ""),
        };
        let collapsed = value_part.split_whitespace().collect::<Vec<_>>().join(" ");
        if collapsed.is_empty() {
            return None;
        }
        if !sec_name.is_empty() && sec_type.is_empty() {
            // An import keeps such a section aside and applies none of it.
            if hashed {
                return None;
            }
            row.value = collapsed;
            let args = BTreeMap::from([("section".to_owned(), sec_name)]);
            return Some(fail(row, "rules.paste.section-not-applied", args));
        }
        // Off before the type and the `#` are judged, as the file reader does.
        let (collapsed, flags) = split_rule_flags(&collapsed);
        let choice = input.choices.get(&line_no);
        let chosen = choice
            .and_then(|c| c.rule_type.as_deref())
            .unwrap_or_default();
        // Under no header a file has no type for the line: its value names one,
        // or the user does. A `#` line that names none is a note.
        let rule_type: &'static str = if sec_type.is_empty() {
            let class = classify_rule_value(&classified_core(&collapsed));
            match class.rule_type() {
                Some(t) => t.slug(),
                None if hashed => return None,
                None if class == RuleValueClass::Ambiguous => {
                    row.options = if input.apps {
                        vec!["zone", "application"]
                    } else {
                        vec!["zone"]
                    };
                    row.options
                        .iter()
                        .copied()
                        .find(|o| *o == chosen)
                        .unwrap_or_default()
                }
                None => {
                    row.value = collapsed;
                    return Some(fail(row, "rules.paste.unrecognized", BTreeMap::new()));
                }
            }
        } else {
            sec_type
        };
        let reads_verify = matches!(rule_type, "domain" | "exact-ip");
        let (value, marks) = split_rule_markers(&collapsed, reads_verify);
        if value.is_empty() {
            return None;
        }
        let quoted = if rule_type == "application" {
            unquote_program_value(value)
        } else {
            None
        };
        let value = quoted.unwrap_or(value);
        if hashed && quoted.is_none() {
            let parsed = rule_type_from_slug(rule_type)?;
            if !is_disabled_rule_value(parsed, value) {
                return None;
            }
        }
        row.value = stored_value(rule_type, value, flags);
        row.enabled = !hashed;
        if marks.deny {
            row.route = "block".to_owned();
        }
        row.comment = comment.to_owned();
        // An app-authored program rule keeps its section and its provenance.
        if rule_type == "application" || sec_name.eq_ignore_ascii_case(AUTO_SECTION_NAME) {
            if let Some(provenance) = parse_provenance_comment(comment) {
                row.comment = provenance.note.unwrap_or_default();
                row.origin_reason = provenance.origin.reason().as_slug().to_owned();
                row.origin_anchor = provenance.origin.anchor().to_owned();
                row.origin_added = provenance.origin.added().to_owned();
            }
        }
        if rule_type.is_empty() {
            row.status = RowStatus::NeedsType;
            row.message_key = "rules.paste.needs-type".to_owned();
            row.action = RowAction::Keep;
            return Some(row);
        }
        row.rule_type = rule_type;
        if sec_type.is_empty() && rule_type == "application" && !input.apps {
            return Some(fail(row, "rules.paste.apps-unsupported", BTreeMap::new()));
        }
        if row.comment.chars().count() > COMMENT_MAX_CHARS {
            let args = BTreeMap::from([("max".to_owned(), COMMENT_MAX_CHARS.to_string())]);
            return Some(fail(row, "rules.paste.comment-too-long", args));
        }
        let denied = row.route == "block";
        row.verify = marks.verify && !denied;
        let Some(mut verdict) = self.verdict(&mut row) else {
            return Some(row);
        };
        // A value the verdict names another type for: that type, once picked.
        if verdict.level == VerdictLevel::Error {
            if let Some(target) = misplaced_target_type(&verdict.message_key) {
                if input.apps || target != "application" {
                    row.options = vec![target];
                    if chosen == target {
                        row.rule_type = target;
                        row.value = stored_value(target, value, flags);
                        row.verify = row.verify && matches!(target, "domain" | "exact-ip");
                        match self.verdict(&mut row) {
                            Some(again) => verdict = again,
                            None => return Some(row),
                        }
                    }
                }
            }
        }
        match verdict.level {
            VerdictLevel::Error => {
                return Some(fail(row, &verdict.message_key, verdict.args));
            }
            VerdictLevel::Warning => {
                row.status = RowStatus::Warning;
                row.message_key = verdict.message_key;
                row.args = verdict.args;
            }
            // A deny takes no check: the `?` is dropped, as the form drops it.
            VerdictLevel::Valid if marks.verify && denied => {
                row.status = RowStatus::Warning;
                row.message_key = "dialog.rule.verify-deny".to_owned();
            }
            VerdictLevel::Valid => row.status = RowStatus::Ok,
        }
        Some(self.place(row, choice))
    }

    /// The verdict for the row's type and value; `None`, with the row left
    /// waiting, while the caller has not judged it yet.
    fn verdict(&self, row: &mut BulkRow) -> Option<LineVerdict> {
        row.verdict_key = format!("{}|{}", row.rule_type, row.value);
        let found = self.input.verdicts.get(&row.verdict_key).cloned();
        if found.is_none() {
            row.status = RowStatus::Pending;
            row.message_key = "rules.paste.pending".to_owned();
            row.args = BTreeMap::new();
            row.action = RowAction::Keep;
        }
        found
    }

    /// Where a judged row lands against the text so far and the rules there.
    fn place(&mut self, mut row: BulkRow, choice: Option<&LineChoice>) -> BulkRow {
        let same = format!("{}|{}", row.rule_type, row.value.to_lowercase());
        let key = format!("{same}|{}", row.route);
        if let Some(&at) = self.seen.get(&key) {
            // `?x` and `x` on one route are one rule, and the plain one wins,
            // as an import has it.
            if !row.verify {
                self.rows[at].verify = false;
            }
            let first = self.rows[at].line;
            row.status = RowStatus::Duplicate;
            row.message_key = "rules.paste.same-as-line".to_owned();
            row.args = BTreeMap::from([("line".to_owned(), first.to_string())]);
            row.same_line = Some(first);
            row.action = RowAction::Drop;
            return row;
        }
        if let Some(&at) = self.seen_value.get(&same) {
            let first = self.rows[at].line;
            let args = BTreeMap::from([("line".to_owned(), first.to_string())]);
            return fail(row, "rules.paste.conflicts-with-line", args);
        }
        if let Some(&at) = self.existing_key.get(&key) {
            row.status = RowStatus::Duplicate;
            row.message_key = "rules.paste.already-present".to_owned();
            row.args = BTreeMap::new();
            row.existing = Some(at);
            row.action = RowAction::Drop;
        } else if let Some(&at) = self.existing_value.get(&same) {
            let other = self
                .input
                .existing
                .get(at)
                .map_or_else(String::new, |r| r.route.to_owned());
            row.status = RowStatus::Elsewhere;
            row.existing = Some(at);
            if other == "block" {
                row.message_key = "rules.paste.already-denied".to_owned();
                row.args = BTreeMap::new();
            } else {
                row.message_key = "rules.paste.on-other-route".to_owned();
                row.args = BTreeMap::from([("route".to_owned(), other.clone())]);
            }
            row.other_route = other;
            row.move_elsewhere = choice.is_some_and(|c| c.move_elsewhere);
            row.action = if row.move_elsewhere {
                RowAction::Move
            } else {
                RowAction::Keep
            };
        } else if row.origin_reason.is_empty()
            && self.input.room.is_some_and(|room| self.adding >= room)
        {
            return fail(row, "rules.paste.over-limit", BTreeMap::new());
        } else {
            // App-authored rules have a budget of their own.
            if row.origin_reason.is_empty() {
                self.adding += 1;
            }
            row.action = RowAction::Add;
        }
        let at = self.rows.len();
        self.seen.insert(key, at);
        self.seen_value.insert(same, at);
        row
    }
}

fn new_row(line: usize, text: &str, section: &str, route: &str) -> BulkRow {
    BulkRow {
        line,
        text: text.to_owned(),
        section: section.to_owned(),
        rule_type: "",
        options: Vec::new(),
        value: String::new(),
        enabled: true,
        route: route.to_owned(),
        verify: false,
        comment: String::new(),
        status: RowStatus::Ok,
        message_key: String::new(),
        args: BTreeMap::new(),
        existing: None,
        other_route: String::new(),
        same_line: None,
        move_elsewhere: false,
        action: RowAction::Keep,
        verdict_key: String::new(),
        origin_reason: String::new(),
        origin_anchor: String::new(),
        origin_added: String::new(),
    }
}

fn fail(mut row: BulkRow, key: &str, args: BTreeMap<String, String>) -> BulkRow {
    row.status = RowStatus::Error;
    key.clone_into(&mut row.message_key);
    row.args = args;
    row.action = RowAction::Keep;
    row
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(text: &str, route: &str) -> BulkPlan {
        let choices = HashMap::new();
        let verdicts = HashMap::new();
        plan_bulk_rules(&BulkInput {
            text,
            route,
            os: "windows",
            apps: true,
            existing: &[],
            choices: &choices,
            verdicts: &verdicts,
            room: None,
        })
    }

    #[test]
    fn past_the_line_bound_nothing_is_read_and_nothing_is_lost() {
        let text: String = (0..MAX_LINES + 5)
            .map(|i| format!("host{i}.example\n"))
            .collect();
        let planned = plan(&text, "primary");
        assert_eq!(planned.lines, MAX_LINES);
        assert_eq!(planned.excess, 5);
        assert_eq!(planned.bound, Some(Bound::Lines));
        assert_eq!(planned.rows.len(), MAX_LINES);
        // Every row waits for its verdict, so it is kept along with the tail.
        assert_eq!(planned.remaining.lines().count(), MAX_LINES + 5);
    }

    #[test]
    fn one_huge_line_is_left_whole_in_the_field() {
        let text = "a".repeat(MAX_UNITS + 10);
        let planned = plan(&text, "primary");
        assert_eq!(planned.lines, 0);
        assert_eq!(planned.bound, Some(Bound::Size));
        assert_eq!(planned.excess, 1);
        assert_eq!(planned.remaining, text);
    }

    #[test]
    fn hostile_bytes_end_as_row_errors_not_panics() {
        for text in [
            "\u{0}\u{1b}[2J\n",
            "!?\n?!x\n!\n?\n#\n# #\n--- \n---  Domains\n",
            "\u{feff}\u{feff}x\r\r\n",
            "*.\n.\n..\n*\n**\n/\n\\\n:\n::\n",
            "\u{10ffff}\u{d7ff}.\u{3000}\n",
        ] {
            let planned = plan(text, "secondary");
            assert!(planned.rows.len() <= planned.lines);
        }
    }
}
