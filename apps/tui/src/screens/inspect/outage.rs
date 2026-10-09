//! «Blocked while the route was down»: what leak protection held back during
//! the last outage of the additional route, one row per program and address.
//! The same `conn-trace.outage-blocks.list` the GUI reads, on every visit and
//! on `r`; it never refreshes by itself, so a row is not pulled from under
//! someone reading it.

use crossterm::event::{KeyCode, KeyEvent};
use nrr_ipc_client::IpcClient;
use nrr_shared::ipc::IpcOperationName;
use nrr_shared::ipc_payloads::{
    ConnTraceOutageBlocksRequest, ConnTraceOutageBlocksResponse, OutageBlockDto,
};

use super::{
    bad_response, call, clock_time, command, error_text, keys, page_lines, queue, unencodable,
    Pager,
};
use crate::backend::Reply;
use crate::i18n::{Key, Texts};
use crate::screens::{Screen, ScreenId};
use crate::state::AppState;
use crate::view::{Panel, ScreenView, Segment, ViewLine};

#[derive(Debug, Default)]
pub struct OutageState {
    loading: bool,
    answer: Option<ConnTraceOutageBlocksResponse>,
    error: Option<String>,
    pager: Pager,
    generation: u64,
}

impl OutageState {
    fn entries(&self) -> &[OutageBlockDto] {
        self.answer
            .as_ref()
            .map(|a| a.entries.as_slice())
            .unwrap_or_default()
    }

    /// The route is down right now.
    fn ongoing(&self) -> bool {
        self.answer
            .as_ref()
            .and_then(|a| a.episode.as_ref())
            .is_some_and(|e| e.until_unix_ms.is_none())
    }
}

fn read(client: &dyn IpcClient) -> Result<ConnTraceOutageBlocksResponse, String> {
    let request = ConnTraceOutageBlocksRequest::default();
    let payload = serde_json::to_value(&request).map_err(unencodable)?;
    let op = IpcOperationName::ConnTraceOutageBlocksList;
    let answer = call(client, op, payload)?;
    serde_json::from_value(answer).map_err(bad_response)
}

fn load(app: &mut AppState) {
    let state = &mut app.inspect.outage;
    state.loading = true;
    state.error = None;
    state.generation += 1;
    let generation = state.generation;
    queue(app, move |client| {
        let result = read(client);
        Reply::new(move |app| {
            let state = &mut app.inspect.outage;
            // A newer read supersedes this one.
            if state.generation != generation {
                return;
            }
            state.loading = false;
            match result {
                Ok(answer) => {
                    state.pager.clamp(answer.entries.len());
                    state.answer = Some(answer);
                }
                Err(slug) => state.error = Some(slug),
            }
        })
    });
}

pub struct OutageScreen;

impl Screen for OutageScreen {
    fn view(&self, app: &AppState, texts: &Texts) -> ScreenView {
        let state = &app.inspect.outage;
        let entries = state.entries();
        let mut pager = state.pager;
        pager.clamp(entries.len());
        let detail = entries
            .get(pager.selected)
            .map(|e| detail_lines(texts, e))
            .unwrap_or_default();
        let mut list = Vec::new();
        if !entries.is_empty() {
            list.push(ViewLine::new(vec![Segment::strong(header(texts))]));
            list.extend(page_lines(texts, pager, entries.len(), false, |row| {
                row_text(&entries[row])
            }));
        }
        let title = texts.get(ScreenId::OutageBlocks.title());
        ScreenView {
            title: title.clone(),
            panels: vec![
                Panel {
                    title,
                    lines: summary_lines(app, texts),
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
        &[keys::HELP_PAGES, keys::HELP_REFRESH]
    }

    fn plain_help(&self) -> &'static [Key] {
        &[
            keys::PLAIN_PAGES,
            keys::TRACE_PLAIN_DETAILS,
            keys::HELP_REFRESH,
        ]
    }

    /// Read on every visit: an outage that is still on keeps adding rows.
    fn on_show(&self, app: &mut AppState) {
        if app.link.is_connected() && !app.inspect.outage.loading {
            load(app);
        }
    }

    fn takes_focus(&self) -> bool {
        true
    }

    fn on_key(&self, app: &mut AppState, key: KeyEvent) -> bool {
        if key.code == KeyCode::Char('r') {
            load(app);
            return true;
        }
        let state = &mut app.inspect.outage;
        let len = state.entries().len();
        state.pager.on_key(key.code, len)
    }

    fn on_line(&self, app: &mut AppState, line: &str) -> bool {
        let state = &mut app.inspect.outage;
        let len = state.entries().len();
        match command(line) {
            ("n", "") => {
                state.pager.next_page(len);
            }
            ("p", "") => state.pager.previous_page(),
            ("r", "") => load(app),
            ("d", number) => return state.pager.pick(number, len),
            _ => return false,
        }
        true
    }
}

/// Each line only when it has something to say, in reading order.
fn summary_lines(app: &AppState, texts: &Texts) -> Vec<ViewLine> {
    let state = &app.inspect.outage;
    let mut lines = vec![ViewLine::text(texts.get(keys::OUTAGE_INTRO))];
    if !app.link.is_connected() {
        let word = if state.answer.is_some() {
            keys::STALE
        } else {
            keys::NO_DATA
        };
        lines.push(ViewLine::text(texts.get(word)));
    }
    if let Some(slug) = &state.error {
        lines.push(ViewLine::new(vec![Segment::strong(format!(
            "{}{}",
            texts.get(keys::OUTAGE_FAILED),
            error_text(texts, slug)
        ))]));
    }
    let Some(answer) = &state.answer else {
        if state.loading {
            lines.push(ViewLine::text(texts.get(keys::LOADING)));
        }
        return lines;
    };
    lines.push(match &answer.episode {
        None => ViewLine::text(texts.get(keys::OUTAGE_NONE)),
        Some(episode) => {
            let since = clock_time(episode.since_unix_ms);
            match episode.until_unix_ms {
                None => {
                    let text = texts.fill(keys::OUTAGE_ACTIVE, &[("since", since)]);
                    ViewLine::new(vec![Segment::strong(text)])
                }
                Some(until) => ViewLine::text(texts.fill(
                    keys::OUTAGE_ENDED,
                    &[("since", since), ("until", clock_time(until))],
                )),
            }
        }
    });
    // An empty list means three different things; each is said as itself.
    if !answer.observer_active {
        lines.push(ViewLine::text(texts.get(keys::OUTAGE_OBSERVER_OFF)));
    }
    if !answer.gui_stream_enabled {
        lines.push(ViewLine::text(texts.get(keys::TRACE_STREAM_OFF)));
    }
    if answer.episode.is_some()
        && answer.observer_active
        && answer.gui_stream_enabled
        && answer.entries.is_empty()
    {
        lines.push(ViewLine::text(texts.get(keys::OUTAGE_EMPTY)));
    }
    if answer.omitted > 0 {
        lines.push(ViewLine::new(vec![Segment::strong(texts.fill(
            keys::OUTAGE_OMITTED,
            &[("count", answer.omitted.to_string())],
        ))]));
    }
    // While the route is down, the fix is on the interfaces screen.
    if let Some(key) = ScreenId::Interfaces.hotkey().filter(|_| state.ongoing()) {
        lines.push(ViewLine::text(format!(
            "{key}: {}",
            texts.get(keys::OUTAGE_OPEN_ROUTES)
        )));
    }
    lines
}

fn header(texts: &Texts) -> String {
    [
        keys::COL_PROCESS,
        keys::COL_REMOTE,
        keys::COL_ATTEMPTS,
        keys::COL_FIRST,
        keys::COL_LAST,
    ]
    .map(|k| texts.get(k))
    .join(" | ")
}

fn row_text(e: &OutageBlockDto) -> String {
    format!(
        "{} | {} | {} | {} | {}",
        process(e),
        remote_text(e),
        e.attempts,
        clock_time(e.first_seen_ms),
        clock_time(e.last_seen_ms),
    )
}

fn process(e: &OutageBlockDto) -> &str {
    if e.process.is_empty() {
        "—"
    } else {
        e.process.as_str()
    }
}

/// The name the address was asked by, else the rule that owns it, then the
/// address itself.
fn remote_text(e: &OutageBlockDto) -> String {
    let address = match (e.remote_port, e.remote_ip.contains(':')) {
        (0, _) => e.remote_ip.clone(),
        (port, true) => format!("[{}]:{port}", e.remote_ip),
        (port, false) => format!("{}:{port}", e.remote_ip),
    };
    let name = if e.host.is_empty() {
        e.rule_host.as_str()
    } else {
        e.host.as_str()
    };
    if name.is_empty() {
        address
    } else {
        format!("{name} · {address}")
    }
}

fn detail_lines(texts: &Texts, e: &OutageBlockDto) -> Vec<ViewLine> {
    let mut lines = vec![field(texts, keys::COL_PROCESS, process(e))];
    if !e.process_path.is_empty() {
        lines.push(ViewLine::text(
            texts.fill(keys::TRACE_PATH, &[("path", &e.process_path)]),
        ));
    }
    lines.push(field(texts, keys::COL_REMOTE, &remote_text(e)));
    lines.push(field(texts, keys::COL_ATTEMPTS, &e.attempts.to_string()));
    lines.push(field(texts, keys::COL_FIRST, &clock_time(e.first_seen_ms)));
    lines.push(field(texts, keys::COL_LAST, &clock_time(e.last_seen_ms)));
    lines
}

fn field(texts: &Texts, label: Key, value: &str) -> ViewLine {
    ViewLine::text(format!("{}: {value}", texts.get(label)))
}
