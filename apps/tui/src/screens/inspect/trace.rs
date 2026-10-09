//! «Connection trace»: recent outbound connections, the route each took and
//! why. The same `conn-trace.entries.list` the GUI reads, drained when the
//! screen first opens and again on `r`; it never refreshes by itself, so a
//! line is not pulled from under someone reading it.

use std::cell::RefCell;

use crossterm::event::{KeyCode, KeyEvent};
use nrr_client_logic::conn_trace::{is_ipv6_endpoint, is_non_internet_address};
use nrr_ipc_client::IpcClient;
use nrr_shared::ipc::IpcOperationName;
use nrr_shared::ipc_payloads::{
    ConnTraceEntriesListRequest, ConnTraceEntriesListResponse, ConnTraceEntryDto,
};
use nrr_shared::pagination::{PaginationParams, MAX_PAGE_SIZE};

use super::{
    bad_response, call, command, edit, error_text, fill_numbered, keys, page_lines, queue,
    typing_lines, unencodable, wall_clock, yes_no, Edit, Pager,
};
use crate::backend::Reply;
use crate::i18n::{Key, Texts};
use crate::screens::{Screen, ScreenId};
use crate::state::AppState;
use crate::view::{Panel, ScreenView, ViewLine};

/// The service keeps at most this many; reading them all lets the search
/// cover the whole ring, as the GUI's open-time drain does.
const DRAIN_CAP: usize = 1000;

#[derive(Debug)]
pub struct TraceState {
    asked: bool,
    loading: bool,
    entries: Vec<ConnTraceEntryDto>,
    observer_active: bool,
    stream_enabled: bool,
    error: Option<String>,
    query: String,
    typing: Option<String>,
    // Off by default, as in the GUI: what the user sees first is
    // internet-bound traffic that was let out.
    show_blocked: bool,
    show_local: bool,
    only_ipv6: bool,
    pager: Pager,
    generation: u64,
    /// The entries the last picture listed, in order. The search matches the
    /// words on screen, which only the renderer has; keys act on what was seen.
    visible: RefCell<Vec<usize>>,
}

impl Default for TraceState {
    fn default() -> Self {
        Self {
            asked: false,
            loading: false,
            entries: Vec::new(),
            observer_active: true,
            stream_enabled: true,
            error: None,
            query: String::new(),
            typing: None,
            show_blocked: false,
            show_local: false,
            only_ipv6: false,
            pager: Pager::default(),
            generation: 0,
            visible: RefCell::new(Vec::new()),
        }
    }
}

impl TraceState {
    /// The rows to list: view filters first, then the search, so the counts
    /// match what is listed.
    fn shown(&self, texts: &Texts) -> Vec<usize> {
        let query = self.query.trim().to_lowercase();
        self.entries
            .iter()
            .enumerate()
            .filter(|(_, e)| self.show_blocked || !e.verdict.starts_with("block"))
            .filter(|(_, e)| self.show_local || !is_non_internet_address(&e.remote))
            .filter(|(_, e)| !self.only_ipv6 || is_ipv6_endpoint(&e.remote))
            .filter(|(_, e)| query.is_empty() || blob(texts, e).contains(&query))
            .map(|(i, _)| i)
            .collect()
    }

    fn visible_len(&self) -> usize {
        self.visible.borrow().len()
    }

    fn selected_entry(&self) -> Option<ConnTraceEntryDto> {
        let index = *self.visible.borrow().get(self.pager.selected)?;
        self.entries.get(index).cloned()
    }

    fn set_query(&mut self, query: String) {
        self.query = query;
        self.pager = Pager::default();
    }

    fn toggle(&mut self, which: char) {
        match which {
            'b' => self.show_blocked = !self.show_blocked,
            'l' => self.show_local = !self.show_local,
            _ => self.only_ipv6 = !self.only_ipv6,
        }
        self.pager = Pager::default();
    }
}

struct Drained {
    entries: Vec<ConnTraceEntryDto>,
    observer_active: bool,
    stream_enabled: bool,
}

fn drain(client: &dyn IpcClient) -> Result<Drained, String> {
    let mut out = Drained {
        entries: Vec::new(),
        observer_active: true,
        stream_enabled: true,
    };
    let mut cursor = None;
    loop {
        let request = ConnTraceEntriesListRequest {
            pagination: PaginationParams {
                cursor,
                page_size: MAX_PAGE_SIZE,
            },
        };
        let payload = serde_json::to_value(&request).map_err(unencodable)?;
        let answer = call(client, IpcOperationName::ConnTraceEntriesList, payload)?;
        let page: ConnTraceEntriesListResponse =
            serde_json::from_value(answer).map_err(bad_response)?;
        out.observer_active = page.observer_active;
        out.stream_enabled = page.gui_stream_enabled;
        out.entries.extend(page.page.items);
        cursor = page.page.next_cursor;
        if cursor.is_none() || out.entries.len() >= DRAIN_CAP {
            return Ok(out);
        }
    }
}

fn load(app: &mut AppState) {
    let state = &mut app.inspect.trace;
    state.asked = true;
    state.loading = true;
    state.error = None;
    state.generation += 1;
    let generation = state.generation;
    queue(app, move |client| {
        let result = drain(client);
        Reply::new(move |app| {
            let state = &mut app.inspect.trace;
            // A newer read supersedes this one.
            if state.generation != generation {
                return;
            }
            state.loading = false;
            match result {
                Ok(drained) => {
                    state.entries = drained.entries;
                    state.observer_active = drained.observer_active;
                    state.stream_enabled = drained.stream_enabled;
                    state.pager.clamp(state.entries.len());
                }
                Err(slug) => state.error = Some(slug),
            }
        })
    });
}

fn label(texts: &Texts, family: &str, slug: &str) -> String {
    texts.dynamic(&format!("diag.conn-trace.{family}.{slug}"), slug)
}

/// A drop is NetRuleRouter's only when its own filter did it.
fn verdict_label(texts: &Texts, e: &ConnTraceEntryDto) -> String {
    if e.verdict == "block" {
        match e.blocked_by.as_str() {
            "netrulerouter" => return texts.get(keys::TRACE_BLOCK_BY_NRR),
            "other" => return texts.get(keys::TRACE_BLOCK_BY_OTHER),
            _ => {}
        }
    }
    label(texts, "verdict", &e.verdict)
}

/// A rule routes the address to the additional link, yet the flow was let
/// out over the main one: the GUI's leak indicator.
fn is_leak(e: &ConnTraceEntryDto) -> bool {
    e.expected_route == "secondary" && e.egress_role == "primary" && e.verdict == "permit"
}

fn host_count(e: &ConnTraceEntryDto) -> usize {
    (e.remote_host_count as usize).max(e.remote_hosts.len())
}

/// "address · name (+N)", as the GUI's Remote column.
fn remote_text(texts: &Texts, e: &ConnTraceEntryDto) -> String {
    let address = if e.remote.is_empty() {
        "—"
    } else {
        e.remote.as_str()
    };
    let Some(first) = e.remote_hosts.first() else {
        return if e.remote_fake_ip {
            format!("{address} · {}", texts.get(keys::TRACE_FAKE_IP))
        } else {
            address.to_owned()
        };
    };
    let name = if host_count(e) > 1 {
        let others = (host_count(e) - 1).to_string();
        fill_numbered(&texts.get(keys::TRACE_HOST_OTHERS), &[first, &others])
    } else {
        first.clone()
    };
    format!("{address} · {name}")
}

/// The GUI's search blob: every field as shown, lowercased.
fn blob(texts: &Texts, e: &ConnTraceEntryDto) -> String {
    let fake = if e.remote_fake_ip {
        texts.get(keys::TRACE_FAKE_IP)
    } else {
        String::new()
    };
    [
        e.process.clone(),
        label(texts, "proto", &e.proto),
        e.local.clone(),
        e.remote.clone(),
        e.remote_hosts.join(" "),
        fake,
        label(texts, "egress", &e.egress_role),
        label(texts, "verdict", &e.verdict),
        wall_clock(e.observed_at_ms),
    ]
    .join(" ")
    .to_lowercase()
}

/// The address of a remote without its port, as the GUI's row menu takes it.
fn remote_address(remote: &str) -> &str {
    match remote.rfind(':') {
        Some(at) if at > 0 => &remote[..at],
        _ => remote,
    }
}

/// "Why this route?": asked in Diagnostics by the rule host, else the name the
/// trace saw, else the address, with the address and program along so the
/// probe answers for this connection.
fn explain_selected(app: &mut AppState) {
    let Some(e) = app.inspect.trace.selected_entry() else {
        return;
    };
    let address = remote_address(&e.remote).to_owned();
    let first_name = e.remote_hosts.first().map_or("", String::as_str);
    let subject = [e.rule_host.as_str(), first_name, address.as_str()]
        .into_iter()
        .find(|s| !s.is_empty())
        .unwrap_or_default()
        .to_owned();
    if subject.is_empty() {
        return;
    }
    let process = if e.process == "?" {
        ""
    } else {
        e.process.as_str()
    };
    app.open(ScreenId::Diagnostics);
    super::diagnostics::probe(app, &subject, &address, process);
}

pub struct TraceScreen;

impl Screen for TraceScreen {
    fn view(&self, app: &AppState, texts: &Texts) -> ScreenView {
        let state = &app.inspect.trace;
        let shown = state.shown(texts);
        let mut pager = state.pager;
        pager.clamp(shown.len());
        let detail = shown
            .get(pager.selected)
            .map(|&i| detail_lines(texts, &state.entries[i]))
            .unwrap_or_default();
        let list = page_lines(texts, pager, shown.len(), false, |row| {
            row_text(texts, &state.entries[shown[row]])
        });
        let summary = summary_lines(app, texts, shown.len());
        *state.visible.borrow_mut() = shown;
        let title = texts.get(crate::keys::SCREEN_TRACE);
        ScreenView {
            title: title.clone(),
            panels: vec![
                Panel {
                    title,
                    lines: summary,
                    feed: false,
                },
                Panel {
                    title: texts.get(keys::TRACE_LIST),
                    lines: list,
                    feed: false,
                },
                Panel {
                    title: texts.get(keys::TRACE_DETAIL),
                    lines: detail,
                    feed: false,
                },
            ],
        }
    }

    fn help(&self) -> &'static [Key] {
        &[
            keys::TRACE_HELP_EXPLAIN,
            keys::TRACE_HELP_SEARCH,
            keys::TRACE_HELP_FILTERS,
            keys::HELP_PAGES,
            keys::HELP_REFRESH,
            keys::TRACE_HELP_OUTAGE,
            keys::TRACE_SUBTITLE,
            keys::TRACE_VERDICT_NOTE,
        ]
    }

    fn plain_help(&self) -> &'static [Key] {
        &[
            keys::PLAIN_PAGES,
            keys::TRACE_PLAIN_DETAILS,
            keys::TRACE_PLAIN_EXPLAIN,
            keys::TRACE_PLAIN_SEARCH,
            keys::TRACE_HELP_FILTERS,
            keys::HELP_REFRESH,
            keys::TRACE_HELP_OUTAGE,
        ]
    }

    fn on_show(&self, app: &mut AppState) {
        let state = &app.inspect.trace;
        if app.link.is_connected() && !state.loading && (!state.asked || state.error.is_some()) {
            load(app);
        }
    }

    fn takes_focus(&self) -> bool {
        true
    }

    fn captures_keys(&self, app: &AppState) -> bool {
        app.inspect.trace.typing.is_some()
    }

    fn on_key(&self, app: &mut AppState, key: KeyEvent) -> bool {
        let state = &mut app.inspect.trace;
        if let Some(buffer) = state.typing.as_mut() {
            match edit(buffer, key) {
                Edit::Typing => {}
                Edit::Done(text) => {
                    state.typing = None;
                    state.set_query(text);
                }
                Edit::Cancelled => state.typing = None,
            }
            return true;
        }
        match key.code {
            KeyCode::Char('/') => state.typing = Some(state.query.clone()),
            KeyCode::Char('r') => load(app),
            KeyCode::Char('o') => app.open(ScreenId::OutageBlocks),
            KeyCode::Char(c @ ('b' | 'l' | 'v')) => state.toggle(c),
            KeyCode::Enter => explain_selected(app),
            code => {
                let len = state.visible_len();
                return state.pager.on_key(code, len);
            }
        }
        true
    }

    fn on_line(&self, app: &mut AppState, line: &str) -> bool {
        let state = &mut app.inspect.trace;
        let len = state.visible_len();
        match command(line) {
            ("n", "") => {
                state.pager.next_page(len);
            }
            ("p", "") => state.pager.previous_page(),
            ("r", "") => load(app),
            ("o", "") => app.open(ScreenId::OutageBlocks),
            ("/", text) => state.set_query(text.to_owned()),
            ("b", "") => state.toggle('b'),
            ("l", "") => state.toggle('l'),
            ("v", "") => state.toggle('v'),
            ("d", number) => return state.pager.pick(number, len),
            ("e", number) => {
                if !state.pager.pick(number, len) {
                    return false;
                }
                explain_selected(app);
            }
            _ => return false,
        }
        true
    }
}

fn summary_lines(app: &AppState, texts: &Texts, shown: usize) -> Vec<ViewLine> {
    let state = &app.inspect.trace;
    let mut lines = Vec::new();
    if !app.link.is_connected() {
        let word = if state.asked {
            keys::STALE
        } else {
            keys::NO_DATA
        };
        lines.push(ViewLine::text(texts.get(word)));
    }
    if let Some(slug) = &state.error {
        lines.push(ViewLine::text(format!(
            "{}{}",
            texts.get(keys::TRACE_FAILED),
            error_text(texts, slug)
        )));
    }
    if state.loading && state.entries.is_empty() {
        lines.push(ViewLine::text(texts.get(keys::TRACE_LOADING)));
    } else if state.asked && !state.loading && state.error.is_none() && state.entries.is_empty() {
        // Three different silences, never presented as one.
        let why = if !state.stream_enabled {
            keys::TRACE_STREAM_OFF
        } else if state.observer_active {
            keys::TRACE_EMPTY
        } else {
            keys::TRACE_NOT_OBSERVING
        };
        lines.push(ViewLine::text(texts.get(why)));
    } else if !state.entries.is_empty() {
        lines.push(ViewLine::text(texts.fill(
            keys::TRACE_SHOWN,
            &[
                ("shown", shown.to_string()),
                ("total", state.entries.len().to_string()),
            ],
        )));
        if shown == 0 {
            lines.push(ViewLine::text(texts.get(keys::TRACE_NO_MATCH)));
        }
    }
    lines.push(ViewLine::text(format!(
        "{}: {} · {}: {} · {}: {}",
        texts.get(keys::TRACE_SHOW_BLOCKED),
        yes_no(texts, state.show_blocked),
        texts.get(keys::TRACE_SHOW_LOCAL),
        yes_no(texts, state.show_local),
        texts.get(keys::TRACE_ONLY_IPV6),
        yes_no(texts, state.only_ipv6),
    )));
    match &state.typing {
        Some(buffer) => {
            let label = texts.get(keys::TRACE_SEARCH_LABEL);
            lines.extend(typing_lines(texts, label.trim_end_matches('…'), buffer));
        }
        None if !state.query.is_empty() => lines.push(ViewLine::text(
            texts.fill(keys::TRACE_SEARCH, &[("text", &state.query)]),
        )),
        None => {}
    }
    lines
}

fn row_text(texts: &Texts, e: &ConnTraceEntryDto) -> String {
    let process = if e.process.is_empty() {
        "—"
    } else {
        e.process.as_str()
    };
    format!(
        "{process} → {} — {} · {}",
        remote_text(texts, e),
        label(texts, "egress", &e.egress_role),
        verdict_label(texts, e),
    )
}

fn detail_lines(texts: &Texts, e: &ConnTraceEntryDto) -> Vec<ViewLine> {
    let or_dash = |s: &str| {
        if s.is_empty() {
            "—".to_owned()
        } else {
            s.to_owned()
        }
    };
    let mut lines = vec![ViewLine::text(format!(
        "{}: {}",
        texts.get(keys::COL_PROCESS),
        or_dash(&e.process)
    ))];
    if !e.process_path.is_empty() {
        lines.push(ViewLine::text(
            texts.fill(keys::TRACE_PATH, &[("path", &e.process_path)]),
        ));
    }
    lines.push(ViewLine::text(format!(
        "{}: {}",
        texts.get(keys::COL_REMOTE),
        remote_text(texts, e)
    )));
    if !e.remote_hosts.is_empty() {
        let mut names = String::new();
        if e.remote_fake_ip {
            names.push_str(&texts.get(keys::TRACE_VIA_FAKE_IP));
            names.push(' ');
        }
        let count = host_count(e).to_string();
        names.push_str(&fill_numbered(&texts.get(keys::TRACE_NAMES), &[&count]));
        names.push(' ');
        names.push_str(&e.remote_hosts.join(", "));
        lines.push(ViewLine::text(names));
    }
    lines.push(ViewLine::text(format!(
        "{}: {}",
        texts.get(keys::COL_EGRESS),
        label(texts, "egress", &e.egress_role)
    )));
    if is_leak(e) {
        lines.push(ViewLine::text(texts.get(keys::TRACE_LEAK)));
    }
    let mut verdict = format!(
        "{}: {}",
        texts.get(keys::COL_VERDICT),
        verdict_label(texts, e)
    );
    // Which of our filters dropped it, in the block notice's words.
    if !e.block_reason.is_empty() {
        let id = format!("notifications.block-notice.reason.{}", e.block_reason);
        let reason = texts.dynamic(&id, "");
        if !reason.is_empty() {
            verdict.push_str(" — ");
            verdict.push_str(&reason);
        }
    }
    lines.push(ViewLine::text(verdict));
    let mut facts = format!(
        "{} · {} {} · {}",
        label(texts, "proto", &e.proto),
        texts.get(keys::TRACE_FROM),
        or_dash(&e.local),
        wall_clock(e.observed_at_ms)
    );
    // Without it the relay reads as the service going out on its own account.
    if !e.relay_for.is_empty() {
        facts.push_str(" · ");
        facts.push_str(&fill_numbered(
            &texts.get(keys::TRACE_RELAY_FOR),
            &[&e.relay_for],
        ));
    }
    lines.push(ViewLine::text(facts));
    lines.push(ViewLine::text(format!(
        "Enter / e: {}",
        texts.get(keys::TRACE_WHY)
    )));
    lines
}
