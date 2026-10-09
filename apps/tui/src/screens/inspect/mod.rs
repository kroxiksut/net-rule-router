//! The read-mostly screens over the service's own records: the connection
//! trace and what an outage blocked, the name cache, and diagnostics with the
//! log. Their state lives
//! here, their IPC runs as backend jobs, and their long lists go a page at a
//! time in both renderers.

pub mod cache;
pub mod diagnostics;
mod keys;
pub mod outage;
#[cfg(test)]
mod tests;
pub mod trace;

use std::time::Duration;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use nrr_ipc_client::{ipc_operation_timeout, IpcClient, IpcClientError};
use nrr_shared::ipc::IpcOperationName;
use serde_json::Value;

use crate::backend::Reply;
use crate::i18n::Texts;
use crate::state::AppState;
use crate::view::{Segment, ViewLine};

/// The screens' state, kept while the user is elsewhere so coming back finds
/// the list, the filters and the place in it.
#[derive(Debug, Default)]
pub struct Inspect {
    pub trace: trace::TraceState,
    pub outage: outage::OutageState,
    pub cache: cache::CacheState,
    pub diag: diagnostics::DiagState,
}

/// Rows on one page, in both renderers.
pub const PAGE_ROWS: usize = 10;

/// Queue an IPC job; its reply is applied on the interface thread.
fn queue(app: &mut AppState, job: impl FnOnce(&dyn IpcClient) -> Reply + Send + 'static) {
    app.outbox.push(Box::new(job));
}

/// A failed call as the slug the GUI's `errors.*` texts are keyed by.
fn error_slug(error: &IpcClientError) -> String {
    match error {
        IpcClientError::ServerError { code, .. } => serde_json::to_value(code)
            .ok()
            .and_then(|v| v.as_str().map(|s| s.replace('_', "-")))
            .unwrap_or_else(|| "unknown".to_owned()),
        IpcClientError::Disconnected => "transport-disconnected".to_owned(),
        IpcClientError::Timeout => "timeout".to_owned(),
        IpcClientError::BadResponse { .. } => "bad-response".to_owned(),
        IpcClientError::SerializationFailed(_) => "serialization-failed".to_owned(),
        IpcClientError::ClientShutdown => "client-shutdown".to_owned(),
    }
}

/// What a refusal or a failed call says (`ipcErrorLabel`): the localized
/// `errors.<slug>`, else the slug itself, which still names the cause.
fn error_text(texts: &Texts, slug: &str) -> String {
    let slug = if slug.is_empty() { "unknown" } else { slug };
    texts.dynamic(&format!("errors.{slug}"), slug)
}

fn call(client: &dyn IpcClient, op: IpcOperationName, payload: Value) -> Result<Value, String> {
    call_within(client, op, payload, ipc_operation_timeout(op))
}

fn call_within(
    client: &dyn IpcClient,
    op: IpcOperationName,
    payload: Value,
    timeout: Duration,
) -> Result<Value, String> {
    client
        .call(op, payload, timeout)
        .map_err(|e| error_slug(&e))
}

fn bad_response<E>(_: E) -> String {
    "bad-response".to_owned()
}

fn unencodable<E>(_: E) -> String {
    "serialization-failed".to_owned()
}

/// `YYYY-MM-DD HH:MM` in local time (`formatTimestamp`), "—" for none.
fn wall_clock(ms: i64) -> String {
    zoned(ms, "%Y-%m-%d %H:%M")
}

/// With seconds and the zone offset, as the GUI's log view shows a time.
fn wall_clock_seconds(ms: i64) -> String {
    zoned(ms, "%Y-%m-%d %H:%M:%S %:z")
}

fn zoned(ms: i64, format: &str) -> String {
    local_time(ms).map_or_else(|| "—".to_owned(), |at| at.format(format).to_string())
}

/// `HH:MM:SS` for a time today, with the date before it otherwise.
fn clock_time(ms: i64) -> String {
    clock_time_at(ms, chrono::Utc::now().timestamp_millis())
}

fn clock_time_at(ms: i64, now_ms: i64) -> String {
    let Some(at) = local_time(ms) else {
        return "—".to_owned();
    };
    let today = local_time(now_ms).map(|now| now.date_naive());
    let format = if today == Some(at.date_naive()) {
        "%H:%M:%S"
    } else {
        "%Y-%m-%d %H:%M:%S"
    };
    at.format(format).to_string()
}

fn local_time(ms: i64) -> Option<chrono::DateTime<chrono::FixedOffset>> {
    let at = chrono::DateTime::from_timestamp_millis(ms).filter(|_| ms > 0)?;
    // Snapshots must not depend on the zone of the machine running them.
    #[cfg(test)]
    let at = at.fixed_offset();
    #[cfg(not(test))]
    let at = at.with_timezone(&chrono::Local).fixed_offset();
    Some(at)
}

/// Where the reader is in a list.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Pager {
    selected: usize,
}

impl Pager {
    fn page_start(self) -> usize {
        self.selected / PAGE_ROWS * PAGE_ROWS
    }

    fn clamp(&mut self, len: usize) {
        self.selected = self.selected.min(len.saturating_sub(1));
    }

    /// A movement key; `false` when the key is not one.
    fn on_key(&mut self, code: KeyCode, len: usize) -> bool {
        let last = len.saturating_sub(1);
        self.selected = match code {
            KeyCode::Up => self.selected.saturating_sub(1),
            KeyCode::Down => (self.selected + 1).min(last),
            KeyCode::PageUp => self.selected.saturating_sub(PAGE_ROWS),
            KeyCode::PageDown => (self.selected + PAGE_ROWS).min(last),
            KeyCode::Home => 0,
            KeyCode::End => last,
            _ => return false,
        };
        true
    }

    /// To the first row of the next page; `false` on the last page.
    fn next_page(&mut self, len: usize) -> bool {
        let next = self.page_start() + PAGE_ROWS;
        if next >= len {
            return false;
        }
        self.selected = next;
        true
    }

    fn previous_page(&mut self) {
        self.selected = self.page_start().saturating_sub(PAGE_ROWS);
    }

    /// A 1-based row number from line mode, if it names a row.
    fn pick(&mut self, number: &str, len: usize) -> bool {
        match number.trim().parse::<usize>() {
            Ok(n) if (1..=len).contains(&n) => {
                self.selected = n - 1;
                true
            }
            _ => false,
        }
    }
}

/// The page holding the selection: rows numbered across the whole list, the
/// selected one marked `>` and in bold, so the place never rests on colour.
fn page_lines(
    texts: &Texts,
    pager: Pager,
    len: usize,
    more_on_service: bool,
    mut row: impl FnMut(usize) -> String,
) -> Vec<ViewLine> {
    let start = pager.page_start().min(len);
    let end = (start + PAGE_ROWS).min(len);
    let mut lines: Vec<ViewLine> = (start..end)
        .map(|i| {
            let text = format!("{}. {}", i + 1, row(i));
            if i == pager.selected {
                ViewLine::new(vec![Segment::strong(format!("> {text}"))])
            } else {
                ViewLine::text(format!("  {text}"))
            }
        })
        .collect();
    if len > 0 {
        lines.push(ViewLine::text(texts.fill(
            keys::PAGE,
            &[
                ("from", (start + 1).to_string()),
                ("to", end.to_string()),
                ("total", len.to_string()),
            ],
        )));
    }
    if more_on_service {
        lines.push(ViewLine::text(texts.get(keys::PAGE_MORE)));
    }
    lines
}

/// One key for a line being typed.
enum Edit {
    Typing,
    Done(String),
    Cancelled,
}

fn edit(buffer: &mut String, key: KeyEvent) -> Edit {
    match key.code {
        KeyCode::Enter => Edit::Done(std::mem::take(buffer)),
        KeyCode::Esc => Edit::Cancelled,
        KeyCode::Backspace => {
            buffer.pop();
            Edit::Typing
        }
        KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
            buffer.push(c);
            Edit::Typing
        }
        _ => Edit::Typing,
    }
}

/// The line being typed, with its label and how to finish it.
fn typing_lines(texts: &Texts, label: &str, buffer: &str) -> Vec<ViewLine> {
    vec![
        ViewLine::new(vec![Segment::strong(format!("{label}: {buffer}_"))]),
        ViewLine::text(texts.get(keys::TYPING_HINT)),
    ]
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Answer {
    Yes,
    No,
}

fn answer_key(key: KeyEvent) -> Option<Answer> {
    match key.code {
        KeyCode::Char('y' | 'Y') => Some(Answer::Yes),
        KeyCode::Char('n' | 'N') | KeyCode::Esc => Some(Answer::No),
        _ => None,
    }
}

fn answer_line(line: &str) -> Option<Answer> {
    match line.trim().to_lowercase().as_str() {
        "y" | "yes" | "д" | "да" => Some(Answer::Yes),
        "n" | "no" | "н" | "нет" => Some(Answer::No),
        _ => None,
    }
}

/// A line-mode command and its argument: `e 3`, `/text`.
fn command(line: &str) -> (&str, &str) {
    let line = line.trim();
    if let Some(rest) = line.strip_prefix('/') {
        return ("/", rest.trim());
    }
    match line.split_once(char::is_whitespace) {
        Some((head, rest)) => (head, rest.trim()),
        None => (line, ""),
    }
}

/// `%1`, `%2` as the GUI's Qt-style texts fill them.
fn fill_numbered(text: &str, values: &[&str]) -> String {
    values
        .iter()
        .enumerate()
        .rev()
        .fold(text.to_owned(), |out, (i, v)| {
            out.replace(&format!("%{}", i + 1), v)
        })
}

fn yes_no(texts: &Texts, on: bool) -> String {
    texts.get(if on { keys::YES } else { keys::NO })
}
