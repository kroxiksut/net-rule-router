//! Screen 6, suggested addresses: what the sites you route turned out to
//! need, grouped by domain, with the main route's verdict where it is known.
//! The answers are the GUI's: add, don't suggest again, allow again, add and
//! switch to automatic mode, and the main-route check. Grouping, filters and
//! order come from `nrr-client-logic`, the port of the GUI's own helpers.
//!
//! The list is re-read on every visit and on every `auto-rule-candidates-changed`
//! push, never patched locally: the service re-derives its pending set.

mod keys;
#[cfg(test)]
pub(crate) mod tests;

use crossterm::event::{KeyCode, KeyEvent};
use nrr_client_logic::auto_rules::{
    count_dismissed_hosts, count_served_by_main_link, filter_by_status, filter_served_by_main_link,
    group_rows, sort_groups, HostStatus, SortMode, SuggestionGroup, SuggestionHost,
};
use nrr_client_logic::route_policy::build_full_update_request;
use nrr_ipc_client::{ipc_error_to_wire, ipc_operation_timeout, IpcClient};
use nrr_shared::ipc::IpcOperationName;
use nrr_shared::ipc_payloads::{
    AutoRuleCandidateDto, AutoRuleCandidatesActionRequest, AutoRuleCandidatesActionResponse,
    AutoRuleCandidatesListResponse, AutoRuleCandidatesProbeRequest,
    AutoRuleCandidatesProbeResponse, AutoRuleDismissedEntryDto, AutoRuleDismissedListResponse,
    AutoRuleDismissedRestoreRequest, AutoRuleDismissedRestoreResponse,
};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{json, Map, Value};

use super::{Screen, ScreenId};
use crate::backend::{Job, Reply};
use crate::i18n::{Key, Texts};
use crate::keys as common;
use crate::state::{AppState, Focus};
use crate::view::{Panel, ScreenView, Segment, ViewLine};

/// Sites named in a group's "needed by" line before the rest are counted.
const CONSUMERS_SHOWN: usize = 3;
/// Observed names spelled out in the reach line before the rest are counted.
const MEMBERS_SHOWN: usize = 4;
const AUTO_MODE: &str = "auto";

/// A failed call, as the client words it: the slug picks the localized text,
/// the message stands in when this build has none for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallError {
    pub code: String,
    pub message: String,
}

impl CallError {
    pub fn text(&self, texts: &Texts) -> String {
        let fallback = if self.message.is_empty() {
            self.code.as_str()
        } else {
            self.message.as_str()
        };
        texts.dynamic(&format!("errors.{}", self.code), fallback)
    }
}

/// One call with a typed request and answer, on the jobs thread.
pub fn call<T: DeserializeOwned>(
    client: &dyn IpcClient,
    op: IpcOperationName,
    request: &impl Serialize,
) -> Result<T, CallError> {
    let payload = serde_json::to_value(request).map_err(|e| CallError {
        code: "serialization-failed".into(),
        message: e.to_string(),
    })?;
    let answer = client
        .call(op, payload, ipc_operation_timeout(op))
        .map_err(|e| {
            let (code, message) = ipc_error_to_wire(&e);
            CallError {
                code: code.to_owned(),
                message,
            }
        })?;
    serde_json::from_value(answer).map_err(|e| CallError {
        code: "bad-response".into(),
        message: e.to_string(),
    })
}

/// What the last answer did, worded when drawn.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Note {
    Added(u32),
    Declined(u32),
    Restored(u32),
    AutoOn,
    CheckStarted(u32),
    CheckNothing,
    Failed(CallError),
    NoItem(usize),
    NothingToDo(usize),
    Cancelled,
    Offline,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Action {
    Add,
    Never,
    Restore,
    /// Add, and from now on add without asking — after a yes.
    Always,
}

#[derive(Debug, Default)]
pub struct Suggestions {
    candidates: Vec<AutoRuleCandidateDto>,
    dismissed: Vec<AutoRuleDismissedEntryDto>,
    inert_dropped: u64,
    inert_sample: Vec<String>,
    /// Offers shown by default, as the service last counted them.
    pending_count: u64,
    loaded: bool,
    loading: bool,
    /// A re-read asked for while one was in flight.
    reload_owed: bool,
    /// Index into the shown groups.
    selected: usize,
    show_dismissed: bool,
    show_served: bool,
    sort: SortMode,
    /// The domain whose "add automatically from now on" waits for a yes.
    confirm: Option<String>,
    probing: bool,
    note: Option<Note>,
    reload_hint: bool,
}

impl Suggestions {
    /// The groups as listed, in the GUI's filter order.
    fn shown(&self) -> Vec<SuggestionGroup> {
        let merged = group_rows(&self.candidates, &self.dismissed);
        let by_status = filter_by_status(&merged, self.show_dismissed);
        sort_groups(
            &filter_served_by_main_link(&by_status, self.show_served),
            self.sort,
        )
    }

    fn select(&mut self, index: usize, count: usize) {
        self.selected = index.min(count.saturating_sub(1));
    }
}

pub struct SuggestionsScreen;

impl Screen for SuggestionsScreen {
    fn view(&self, app: &AppState, texts: &Texts) -> ScreenView {
        ScreenView {
            title: texts.get(ScreenId::Suggestions.title()),
            panels: vec![
                Panel {
                    title: texts.get(keys::TITLE),
                    lines: head_lines(app, texts),
                    feed: false,
                },
                Panel {
                    title: texts.get(keys::LIST_TITLE),
                    lines: list_lines(app, texts),
                    feed: true,
                },
            ],
        }
    }

    fn help(&self) -> &'static [Key] {
        keys::HELP_KEYS
    }

    fn plain_help(&self) -> &'static [Key] {
        keys::PLAIN_KEYS
    }

    fn on_show(&self, app: &mut AppState) {
        if app.link.is_connected() {
            load(app);
        }
    }

    fn takes_focus(&self) -> bool {
        true
    }

    fn captures_keys(&self, app: &AppState) -> bool {
        app.suggestions.confirm.is_some()
    }

    fn on_key(&self, app: &mut AppState, key: KeyEvent) -> bool {
        if app.suggestions.confirm.is_some() {
            return match key.code {
                KeyCode::Enter | KeyCode::Char('y') => {
                    confirm_always(app);
                    true
                }
                KeyCode::Esc | KeyCode::Char('n') => {
                    cancel_always(app);
                    true
                }
                _ => false,
            };
        }
        let count = app.suggestions.shown().len();
        let selected = app.suggestions.selected;
        match key.code {
            KeyCode::Up => move_to(app, selected.saturating_sub(1), count),
            KeyCode::Down => move_to(app, selected + 1, count),
            KeyCode::Home => move_to(app, 0, count),
            KeyCode::End => move_to(app, count.saturating_sub(1), count),
            KeyCode::Char(c) => return command(app, c, selected),
            _ => return false,
        }
        true
    }

    fn on_line(&self, app: &mut AppState, line: &str) -> bool {
        if app.suggestions.confirm.is_some() {
            match line.trim() {
                "y" => confirm_always(app),
                "n" => cancel_always(app),
                _ => return false,
            }
            return true;
        }
        let mut chars = line.trim().chars();
        let Some(letter) = chars.next() else {
            return false;
        };
        let rest = chars.as_str().trim();
        if rest.is_empty() {
            return matches!(letter, 'c' | 's' | 'v' | 'o') && command(app, letter, 0);
        }
        if !matches!(letter, 'a' | 'n' | 'r' | 'm') {
            return false;
        }
        let Ok(number) = rest.parse::<usize>() else {
            return false;
        };
        let count = app.suggestions.shown().len();
        if number == 0 || number > count {
            app.suggestions.note = Some(Note::NoItem(number));
            return true;
        }
        app.suggestions.select(number - 1, count);
        command(app, letter, number - 1)
    }

    fn plain_prompt(&self, app: &AppState) -> Option<Key> {
        app.suggestions
            .confirm
            .as_ref()
            .map(|_| keys::CONFIRM_PROMPT)
    }
}

fn move_to(app: &mut AppState, index: usize, count: usize) {
    app.suggestions.select(index, count);
    app.scroll = scroll_for(&app.suggestions);
}

/// The list's first row of the chosen item, so moving keeps it in view.
fn scroll_for(state: &Suggestions) -> u16 {
    let rows: usize = state
        .shown()
        .iter()
        .take(state.selected)
        .map(group_line_count)
        .sum();
    u16::try_from(rows).unwrap_or(u16::MAX)
}

/// A screen letter; `index` is the item it acts on. `false` for a letter the
/// screen does not use.
fn command(app: &mut AppState, letter: char, index: usize) -> bool {
    let action = match letter {
        'a' => Action::Add,
        'n' => Action::Never,
        'r' => Action::Restore,
        'm' => Action::Always,
        'c' => {
            probe(app);
            return true;
        }
        's' => {
            app.suggestions.show_dismissed = !app.suggestions.show_dismissed;
            reselect(app);
            return true;
        }
        'v' => {
            app.suggestions.show_served = !app.suggestions.show_served;
            reselect(app);
            return true;
        }
        'o' => {
            app.suggestions.sort = app.suggestions.sort.next();
            reselect(app);
            return true;
        }
        _ => return false,
    };
    act(app, action, index);
    true
}

/// After the list changed shape: the first item, at the top.
fn reselect(app: &mut AppState) {
    app.suggestions.selected = 0;
    app.scroll = 0;
}

fn act(app: &mut AppState, action: Action, index: usize) {
    if !app.link.is_connected() {
        app.suggestions.note = Some(Note::Offline);
        return;
    }
    let Some(group) = app.suggestions.shown().into_iter().nth(index) else {
        app.suggestions.note = Some(Note::NoItem(index + 1));
        return;
    };
    let ids = match action {
        Action::Restore => group.dismissed_ids.clone(),
        _ => group.pending_ids.clone(),
    };
    if ids.is_empty() {
        app.suggestions.note = Some(Note::NothingToDo(index + 1));
        return;
    }
    match action {
        // Unattended writes are worth a real yes; nothing changes before it.
        Action::Always => {
            app.suggestions.confirm = Some(group.domain);
            app.suggestions.note = None;
        }
        Action::Add => app.outbox.push(accept_job(ids)),
        Action::Never => app.outbox.push(dismiss_job(ids)),
        Action::Restore => app.outbox.push(restore_job(ids)),
    }
}

fn confirm_always(app: &mut AppState) {
    let Some(domain) = app.suggestions.confirm.take() else {
        return;
    };
    let ids = app
        .suggestions
        .shown()
        .into_iter()
        .find(|g| g.domain == domain)
        .map(|g| g.pending_ids)
        .unwrap_or_default();
    if !app.link.is_connected() {
        app.suggestions.note = Some(Note::Offline);
        return;
    }
    app.outbox.push(always_job(ids));
}

fn cancel_always(app: &mut AppState) {
    app.suggestions.confirm = None;
    app.suggestions.note = Some(Note::Cancelled);
}

// ── Service calls ────────────────────────────────────────────────────────────

/// Re-read both lists; a request while one is in flight is owed, not dropped.
pub fn load(app: &mut AppState) {
    let state = &mut app.suggestions;
    if state.loading {
        state.reload_owed = true;
        return;
    }
    state.loading = true;
    app.outbox.push(Box::new(|client: &dyn IpcClient| {
        let empty = Map::new();
        let pending: Result<AutoRuleCandidatesListResponse, _> =
            call(client, IpcOperationName::AutoRuleCandidatesList, &empty);
        let answered: Result<AutoRuleDismissedListResponse, _> =
            call(client, IpcOperationName::AutoRuleDismissedList, &empty);
        Reply::new(move |app| loaded(app, pending, answered))
    }));
}

fn loaded(
    app: &mut AppState,
    pending: Result<AutoRuleCandidatesListResponse, CallError>,
    answered: Result<AutoRuleDismissedListResponse, CallError>,
) {
    let state = &mut app.suggestions;
    state.loading = false;
    match (pending, answered) {
        (Ok(pending), Ok(answered)) => {
            state.candidates = pending.candidates;
            state.pending_count = pending.pending_count;
            state.inert_dropped = pending.inert_dropped;
            state.inert_sample = pending.inert_sample;
            state.dismissed = answered.dismissed;
            state.loaded = true;
            let count = state.shown().len();
            state.select(state.selected, count);
        }
        (Err(error), _) | (_, Err(error)) => state.note = Some(Note::Failed(error)),
    }
    if std::mem::take(&mut state.reload_owed) {
        load(app);
    }
}

/// The answer's own outcome, then a fresh list.
fn finish(app: &mut AppState, note: Result<Note, CallError>) {
    app.suggestions.note = Some(note.unwrap_or_else(Note::Failed));
    load(app);
}

fn accept_job(ids: Vec<String>) -> Job {
    Box::new(move |client: &dyn IpcClient| {
        let answer = accept(client, ids);
        Reply::new(move |app| {
            if let Ok(answer) = &answer {
                app.suggestions.pending_count = answer.pending;
                app.suggestions.reload_hint = answer.anchor_skipped;
            }
            finish(app, answer.map(|a| Note::Added(a.applied)));
        })
    })
}

fn accept(
    client: &dyn IpcClient,
    ids: Vec<String>,
) -> Result<AutoRuleCandidatesActionResponse, CallError> {
    call(
        client,
        IpcOperationName::AutoRuleCandidatesAccept,
        &AutoRuleCandidatesActionRequest { ids },
    )
}

fn dismiss_job(ids: Vec<String>) -> Job {
    Box::new(move |client: &dyn IpcClient| {
        let answer: Result<AutoRuleCandidatesActionResponse, _> = call(
            client,
            IpcOperationName::AutoRuleCandidatesDismiss,
            &AutoRuleCandidatesActionRequest { ids },
        );
        Reply::new(move |app| {
            if let Ok(answer) = &answer {
                app.suggestions.pending_count = answer.pending;
            }
            finish(app, answer.map(|a| Note::Declined(a.applied)));
        })
    })
}

fn restore_job(ids: Vec<String>) -> Job {
    Box::new(move |client: &dyn IpcClient| {
        let answer: Result<AutoRuleDismissedRestoreResponse, _> = call(
            client,
            IpcOperationName::AutoRuleDismissedRestore,
            &AutoRuleDismissedRestoreRequest { ids },
        );
        Reply::new(move |app| finish(app, answer.map(|a| Note::Restored(a.restored))))
    })
}

/// The tray's "add automatically from now on": the policy write is a full
/// replacement, so it starts from the live snapshot, then the items on screen
/// are accepted so the one answer covers both the future and the present.
fn always_job(ids: Vec<String>) -> Job {
    Box::new(move |client: &dyn IpcClient| {
        let switched = switch_to_auto(client);
        let did_switch = switched.is_ok();
        let outcome = switched.and_then(|()| accept(client, ids));
        Reply::new(move |app| {
            if did_switch {
                let named =
                    json!({ "auto-rules-mode": AUTO_MODE, "apply-only": ["auto-rules-mode"] });
                if let Value::Object(named) = named {
                    crate::restore::record_route_policy(app, &named);
                }
            }
            if let Ok(answer) = &outcome {
                app.suggestions.pending_count = answer.pending;
                app.suggestions.reload_hint = answer.anchor_skipped;
                if let Some(policy) = app.snapshot.as_mut().and_then(|s| s.route_policy.as_mut()) {
                    policy.auto_rules_mode = AUTO_MODE.to_owned();
                }
            }
            finish(app, outcome.map(|_| Note::AutoOn));
        })
    })
}

fn switch_to_auto(client: &dyn IpcClient) -> Result<(), CallError> {
    let snapshot: Value = call(client, IpcOperationName::SnapshotInitialGet, &Map::new())?;
    let current = snapshot
        .get("route-policy")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let mut request = build_full_update_request(&current, "");
    request.insert("auto-rules-mode".into(), Value::from(AUTO_MODE));
    // The window may be writing other fields meanwhile; name ours.
    request.insert("apply-only".into(), json!(["auto-rules-mode"]));
    call::<Value>(client, IpcOperationName::RoutePolicyUpdate, &request).map(|_| ())
}

/// The verdicts arrive later with a change push; the answer only says how
/// many addresses the pass took.
fn probe(app: &mut AppState) {
    if !app.link.is_connected() {
        app.suggestions.note = Some(Note::Offline);
        return;
    }
    if app.suggestions.probing {
        return;
    }
    app.suggestions.probing = true;
    app.outbox.push(Box::new(|client: &dyn IpcClient| {
        let answer: Result<AutoRuleCandidatesProbeResponse, _> = call(
            client,
            IpcOperationName::AutoRuleCandidatesProbe,
            &AutoRuleCandidatesProbeRequest::default(),
        );
        Reply::new(move |app| {
            app.suggestions.probing = false;
            app.suggestions.note = Some(match answer {
                Ok(a) if a.accepted > 0 => Note::CheckStarted(a.accepted),
                Ok(_) => Note::CheckNothing,
                Err(error) => Note::Failed(error),
            });
        })
    }));
}

/// The service's `auto-rule-candidates-changed`: re-read the list when it is
/// in use, and a notice when more offers wait than before. The notice is a
/// pointer, never a question asked over the user's work.
pub fn changed(
    app: &mut AppState,
    pending_count: u64,
    top_anchor: &str,
    texts: &Texts,
) -> Option<(String, String)> {
    let grew = pending_count > app.suggestions.pending_count;
    app.suggestions.pending_count = pending_count;
    if app.link.is_connected() && (app.suggestions.loaded || app.screen == ScreenId::Suggestions) {
        load(app);
    }
    if !grew {
        return None;
    }
    let site = if top_anchor.is_empty() {
        texts.get(keys::NOTICE_SITE_FALLBACK)
    } else {
        top_anchor.to_owned()
    };
    let screen = ScreenId::Suggestions;
    let body = format!(
        "{} {}",
        texts.fill(keys::NOTICE_BODY, &[("name", site.as_str())]),
        texts.fill(
            keys::NOTICE_OPEN,
            &[
                ("key", screen.hotkey().map(String::from).unwrap_or_default()),
                ("screen", texts.get(screen.title())),
            ],
        )
    );
    Some((texts.get(keys::NOTICE_TITLE), body))
}

// ── Picture ──────────────────────────────────────────────────────────────────

fn head_lines(app: &AppState, texts: &Texts) -> Vec<ViewLine> {
    let state = &app.suggestions;
    let mut lines = vec![ViewLine::text(texts.get(keys::INTRO))];
    if let Some(mode) = app
        .snapshot
        .as_ref()
        .and_then(|s| s.route_policy.as_ref())
        .map(|p| p.auto_rules_mode.as_str())
    {
        let word = match mode {
            "off" => keys::MODE_OFF,
            AUTO_MODE => keys::MODE_AUTO,
            _ => keys::MODE_SUGGEST,
        };
        lines.push(labelled(texts.get(keys::MODE), texts.get(word)));
    }
    lines.push(labelled(
        texts.get(keys::SORT),
        texts.get(sort_label(state.sort)),
    ));
    let merged = group_rows(&state.candidates, &state.dismissed);
    let by_status = filter_by_status(&merged, state.show_dismissed);
    let yes_no = |on: bool| texts.get(if on { keys::YES } else { keys::NO });
    lines.push(labelled(
        texts.fill(
            keys::SHOW_DISMISSED,
            &[("n", count_dismissed_hosts(&merged).to_string())],
        ),
        yes_no(state.show_dismissed),
    ));
    lines.push(labelled(
        texts.fill(
            keys::SHOW_SERVED,
            &[("n", count_served_by_main_link(&by_status).to_string())],
        ),
        yes_no(state.show_served),
    ));
    if !app.link.is_connected() {
        lines.push(ViewLine::text(texts.get(if state.loaded {
            common::STALE
        } else {
            common::NO_DATA
        })));
    } else if state.loading && !state.loaded {
        lines.push(ViewLine::text(texts.get(keys::LOADING)));
    }
    if state.probing {
        lines.push(ViewLine::text(texts.get(keys::CHECK_BUSY)));
    }
    if let Some(note) = &state.note {
        lines.push(ViewLine::new(vec![Segment::strong(note_text(note, texts))]));
    }
    if state.reload_hint {
        lines.push(ViewLine::text(texts.get(keys::RELOAD_PAGE)));
    }
    if let Some(domain) = &state.confirm {
        let number = state
            .shown()
            .iter()
            .position(|g| &g.domain == domain)
            .map_or(0, |i| i + 1);
        lines.push(ViewLine::new(vec![Segment::strong(
            texts.get(keys::AUTO_TITLE),
        )]));
        lines.push(ViewLine::text(texts.get(keys::AUTO_BODY)));
        lines.push(ViewLine::new(vec![Segment::strong(
            texts.fill(keys::CONFIRM, &[("n", number.to_string())]),
        )]));
    }
    lines
}

fn labelled(label: String, value: String) -> ViewLine {
    ViewLine::new(vec![
        Segment::plain(format!("{label}: ")),
        Segment::strong(value),
    ])
}

fn sort_label(mode: SortMode) -> Key {
    match mode {
        SortMode::MainRoute => keys::SORT_MAIN_ROUTE,
        SortMode::Newest => keys::SORT_NEWEST,
        SortMode::Consumers => keys::SORT_CONSUMERS,
        SortMode::Name => keys::SORT_NAME,
    }
}

fn note_text(note: &Note, texts: &Texts) -> String {
    let count = |key: Key, n: u32| texts.fill(key, &[("count", n.to_string())]);
    let item = |key: Key, n: usize| texts.fill(key, &[("n", n.to_string())]);
    match note {
        Note::Added(n) => count(keys::ADDED, *n),
        Note::Declined(n) => count(keys::DECLINED, *n),
        Note::Restored(n) => count(keys::RESTORED, *n),
        Note::AutoOn => texts.get(keys::AUTO_ON),
        Note::CheckStarted(n) => count(keys::CHECK_STARTED, *n),
        Note::CheckNothing => texts.get(keys::CHECK_NOTHING),
        Note::Failed(error) => texts.fill(keys::FAILED, &[("error", error.text(texts))]),
        Note::NoItem(n) => item(keys::NO_ITEM, *n),
        Note::NothingToDo(n) => item(keys::NOTHING_TO_DO, *n),
        Note::Cancelled => texts.get(keys::CANCELLED),
        Note::Offline => texts.get(common::ROUTING_DISCONNECTED),
    }
}

fn list_lines(app: &AppState, texts: &Texts) -> Vec<ViewLine> {
    let state = &app.suggestions;
    if !state.loaded {
        return Vec::new();
    }
    let shown = state.shown();
    if shown.is_empty() {
        return vec![ViewLine::text(empty_text(state, texts))];
    }
    let focused = app.focus == Focus::Feed;
    shown
        .iter()
        .enumerate()
        .flat_map(|(i, group)| group_lines(group, i, focused && i == state.selected, texts))
        .collect()
}

/// Why the list is empty, the most specific reason first, as the GUI says it.
fn empty_text(state: &Suggestions, texts: &Texts) -> String {
    let merged = group_rows(&state.candidates, &state.dismissed);
    if merged.is_empty() && state.inert_dropped > 0 {
        let sample: Vec<&str> = state
            .inert_sample
            .iter()
            .take(3)
            .map(String::as_str)
            .collect();
        return texts.fill(
            keys::EMPTY_INERT,
            &[
                ("count", state.inert_dropped.to_string()),
                ("sample", sample.join(", ")),
            ],
        );
    }
    let by_status = filter_by_status(&merged, state.show_dismissed);
    if by_status.is_empty() {
        let answered = count_dismissed_hosts(&merged);
        return if answered > 0 && !state.show_dismissed {
            texts.fill(keys::EMPTY_ANSWERED, &[("n", answered.to_string())])
        } else {
            texts.get(keys::EMPTY)
        };
    }
    texts.fill(
        keys::EMPTY_SERVED,
        &[("n", count_served_by_main_link(&by_status).to_string())],
    )
}

/// Rows one group takes; [`group_lines`] must agree (a test holds them).
fn group_line_count(group: &SuggestionGroup) -> usize {
    let consumers = usize::from(!group.consumers.is_empty());
    let hosts: usize = group
        .hosts
        .iter()
        .map(|h| 2 + usize::from(has_evidence(h)))
        .sum();
    1 + consumers + hosts
}

fn group_lines(
    group: &SuggestionGroup,
    index: usize,
    selected: bool,
    texts: &Texts,
) -> Vec<ViewLine> {
    let name = if group.is_app {
        texts.fill(keys::APP_GROUP, &[("name", group.domain.as_str())])
    } else {
        group.domain.clone()
    };
    let mut counts = Vec::new();
    let pending = group
        .hosts
        .iter()
        .filter(|h| h.status == HostStatus::Pending)
        .count();
    if pending > 0 {
        counts.push(format!("{} ({pending})", texts.get(keys::STATUS_PENDING)));
    }
    if !group.dismissed_ids.is_empty() {
        counts.push(format!(
            "{} ({})",
            texts.get(keys::STATUS_DISMISSED),
            group.dismissed_ids.len()
        ));
    }
    let marker = if selected { "> " } else { "" };
    let mut lines = vec![ViewLine::new(vec![
        Segment::plain(format!("{marker}{}. ", index + 1)),
        Segment::strong(name),
        Segment::plain(format!(" — {}", counts.join(", "))),
    ])];
    if !group.consumers.is_empty() {
        let names: Vec<&str> = group
            .consumers
            .iter()
            .take(CONSUMERS_SHOWN)
            .map(|c| c.hostname.as_str())
            .collect();
        let mut text = format!("   {} {}", texts.get(keys::NEEDED_BY), names.join(", "));
        let more = group.consumers.len().saturating_sub(CONSUMERS_SHOWN);
        if more > 0 {
            text.push(' ');
            text.push_str(&texts.fill(keys::MORE, &[("count", more.to_string())]));
        }
        lines.push(ViewLine::text(text));
    }
    for host in &group.hosts {
        lines.extend(host_lines(group, host, texts));
    }
    lines
}

fn host_lines(group: &SuggestionGroup, host: &SuggestionHost, texts: &Texts) -> Vec<ViewLine> {
    let shown_name = if host.match_kind == "suffix" {
        format!("*.{}", host.match_value)
    } else {
        host.match_value.clone()
    };
    let status = texts.get(match host.status {
        HostStatus::Pending => keys::STATUS_PENDING,
        HostStatus::Dismissed => keys::STATUS_DISMISSED,
    });
    let mut facts = vec![status, behavior_text(host, texts)];
    if let Some(third_party) = host.third_party {
        facts.push(texts.get(if third_party {
            keys::OWNERSHIP_THIRD_PARTY
        } else {
            keys::OWNERSHIP_OWN_NAME
        }));
    }
    let mut lines = vec![ViewLine::new(vec![
        Segment::plain("   "),
        Segment::strong(shown_name),
        Segment::plain(format!(" — {}", facts.join("; "))),
    ])];
    if has_evidence(host) {
        lines.push(ViewLine::text(format!(
            "     {}",
            evidence_text(host, texts)
        )));
    }
    lines.push(ViewLine::text(format!(
        "     {}",
        reach_text(group, host, texts)
    )));
    lines
}

/// What the main route does with the address: a fact, never advice.
fn behavior_text(host: &SuggestionHost, texts: &Texts) -> String {
    texts.get(match host.primary_behavior.as_str() {
        "responds" if host.anchor_refuses_main_link => keys::BEHAVIOR_RESPONDS_REFUSING,
        "responds" => keys::BEHAVIOR_RESPONDS,
        "stalls" => keys::BEHAVIOR_STALLS,
        _ => keys::BEHAVIOR_UNKNOWN,
    })
}

fn has_evidence(host: &SuggestionHost) -> bool {
    !host.signal.is_empty() || host.observations > 0 || host.affinity > 0.0
}

/// "How do you know?": the evidence travels with the offer.
fn evidence_text(host: &SuggestionHost, texts: &Texts) -> String {
    let mut parts = Vec::new();
    if !host.signal.is_empty() {
        let suffix = format!(".{}", host.signal);
        // A signal this build has no words for is shown by its slug.
        parts.push(
            keys::SIGNALS
                .iter()
                .find(|k| k.id.ends_with(&suffix))
                .map_or_else(|| host.signal.clone(), |k| texts.get(*k)),
        );
    }
    if host.observations > 0 {
        parts.push(texts.fill(
            keys::OBSERVATIONS,
            &[("count", host.observations.to_string())],
        ));
    }
    if host.affinity > 0.0 {
        let percent = (host.affinity * 100.0).round();
        parts.push(texts.fill(keys::AFFINITY, &[("percent", format!("{percent:.0}"))]));
    }
    parts.join(" · ")
}

/// How far the rule reaches against what was actually seen.
fn reach_text(group: &SuggestionGroup, host: &SuggestionHost, texts: &Texts) -> String {
    let scope = if group.is_app {
        texts.fill(keys::REACH_APP, &[("app", group.domain.as_str())])
    } else {
        texts.fill(keys::REACH, &[("domain", host.match_value.as_str())])
    };
    let members = &host.observed_members;
    if members.is_empty() {
        return scope;
    }
    let mut seen = members
        .iter()
        .take(MEMBERS_SHOWN)
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(", ");
    let more = members.len().saturating_sub(MEMBERS_SHOWN);
    if more > 0 {
        seen.push(' ');
        seen.push_str(&texts.fill(keys::MORE, &[("count", more.to_string())]));
    }
    format!(
        "{scope} {}",
        texts.fill(keys::REACH_SEEN, &[("hosts", seen.as_str())])
    )
}
