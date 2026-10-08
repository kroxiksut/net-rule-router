//! «Cache»: the names the service resolved and the addresses they gave, with
//! the search the service runs (`cache.entries.list` with its `query`) and the
//! two clearings the GUI offers (`cache.clear`). A clearing asks first: one
//! keystroke is easier to make by accident than a click.

use crossterm::event::{KeyCode, KeyEvent};
use nrr_ipc_client::IpcClient;
use nrr_shared::ipc::IpcOperationName;
use nrr_shared::ipc_payloads::{
    CacheClearRequest, CacheClearResponse, CacheEntriesListRequest, CacheEntriesListResponse,
    CacheEntryDto,
};
use nrr_shared::pagination::{PageCursor, PaginationParams};

use super::{
    answer_key, answer_line, bad_response, call, command, edit, error_text, keys, page_lines,
    queue, typing_lines, unencodable, wall_clock, Answer, Edit, Pager,
};
use crate::backend::Reply;
use crate::i18n::{Key, Texts};
use crate::screens::Screen;
use crate::state::AppState;
use crate::view::{Panel, ScreenView, ViewLine};

/// The GUI's page size for this list.
const PAGE_SIZE: u32 = 50;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Clear {
    App,
    OsDns,
}

#[derive(Debug)]
enum Cleared {
    App { removed: u64 },
    OsDns { flushed: bool },
    Failed(String),
}

#[derive(Debug, Default)]
pub struct CacheState {
    asked: bool,
    loading: bool,
    entries: Vec<CacheEntryDto>,
    cursor: Option<PageCursor>,
    total: Option<u64>,
    redacted: bool,
    error: Option<String>,
    query: String,
    typing: Option<String>,
    pager: Pager,
    generation: u64,
    /// Move on a page once the rows asked for with "more" arrive.
    advance: bool,
    question: Option<Clear>,
    clearing: bool,
    cleared: Option<Cleared>,
}

struct Page {
    entries: Vec<CacheEntryDto>,
    cursor: Option<PageCursor>,
    total: Option<u64>,
    redacted: bool,
}

fn read_page(
    client: &dyn IpcClient,
    cursor: Option<PageCursor>,
    query: String,
) -> Result<Page, String> {
    let request = CacheEntriesListRequest {
        pagination: PaginationParams {
            cursor,
            page_size: PAGE_SIZE,
        },
        query,
    };
    let payload = serde_json::to_value(&request).map_err(unencodable)?;
    let answer = call(client, IpcOperationName::CacheEntriesList, payload)?;
    let page: CacheEntriesListResponse = serde_json::from_value(answer).map_err(bad_response)?;
    Ok(Page {
        entries: page.page.items,
        cursor: page.page.next_cursor,
        total: page.page.total_count,
        redacted: page.redacted,
    })
}

/// The first page for the current search, or (`reset` false) the next one.
fn load(app: &mut AppState, reset: bool) {
    let state = &mut app.inspect.cache;
    if reset {
        state.generation += 1;
        state.entries.clear();
        state.cursor = None;
        state.pager = Pager::default();
        state.advance = false;
    }
    state.asked = true;
    state.loading = true;
    state.error = None;
    let generation = state.generation;
    let cursor = state.cursor.clone();
    let query = state.query.clone();
    queue(app, move |client| {
        let result = read_page(client, cursor, query);
        Reply::new(move |app| {
            let state = &mut app.inspect.cache;
            // An answer to an older search must not land under the new one.
            if state.generation != generation {
                return;
            }
            state.loading = false;
            match result {
                Ok(page) => {
                    state.entries.extend(page.entries);
                    state.cursor = page.cursor;
                    state.total = page.total.or(state.total);
                    state.redacted = page.redacted;
                    if std::mem::take(&mut state.advance) {
                        state.pager.next_page(state.entries.len());
                    }
                }
                Err(slug) => {
                    state.advance = false;
                    state.error = Some(slug);
                }
            }
        })
    });
}

/// The next page: from what is loaded, else asked of the service.
fn more(app: &mut AppState) {
    let state = &mut app.inspect.cache;
    let len = state.entries.len();
    if state.pager.next_page(len) || state.cursor.is_none() || state.loading {
        return;
    }
    state.advance = true;
    load(app, false);
}

fn clear(app: &mut AppState, what: Clear) {
    let state = &mut app.inspect.cache;
    state.question = None;
    state.clearing = true;
    state.cleared = None;
    queue(app, move |client| {
        let request = CacheClearRequest {
            dry_run: false,
            flush_os_cache: what == Clear::OsDns,
            clear_app_cache: what == Clear::App,
        };
        let result = serde_json::to_value(&request)
            .map_err(unencodable)
            .and_then(|payload| call(client, IpcOperationName::CacheClear, payload))
            .and_then(|answer| {
                serde_json::from_value::<CacheClearResponse>(answer).map_err(bad_response)
            });
        Reply::new(move |app| {
            app.inspect.cache.clearing = false;
            app.inspect.cache.cleared = Some(match result {
                Ok(done) if what == Clear::App => Cleared::App {
                    removed: done.resolutions_removed,
                },
                // True only when the flush really ran and succeeded.
                Ok(done) => Cleared::OsDns {
                    flushed: done.os_cache_flushed == Some(true),
                },
                Err(slug) => Cleared::Failed(slug),
            });
            if what == Clear::App && !matches!(app.inspect.cache.cleared, Some(Cleared::Failed(_)))
            {
                load(app, true);
            }
        })
    });
}

fn search(app: &mut AppState, query: String) {
    app.inspect.cache.query = query;
    load(app, true);
}

fn answer(app: &mut AppState, answer: Answer) {
    let Some(what) = app.inspect.cache.question else {
        return;
    };
    match answer {
        Answer::Yes => clear(app, what),
        Answer::No => app.inspect.cache.question = None,
    }
}

fn ask(app: &mut AppState, what: Clear) {
    let state = &mut app.inspect.cache;
    if !state.clearing {
        state.question = Some(what);
        state.cleared = None;
    }
}

pub struct CacheScreen;

impl Screen for CacheScreen {
    fn view(&self, app: &AppState, texts: &Texts) -> ScreenView {
        let state = &app.inspect.cache;
        let mut pager = state.pager;
        pager.clamp(state.entries.len());
        let mut list = page_lines(
            texts,
            pager,
            state.entries.len(),
            state.cursor.is_some(),
            |i| row_text(texts, &state.entries[i]),
        );
        if state.asked && !state.loading && state.error.is_none() && state.entries.is_empty() {
            let empty = if state.query.is_empty() {
                keys::CACHE_EMPTY
            } else {
                keys::CACHE_NO_MATCH
            };
            list.push(ViewLine::text(texts.get(empty)));
        }
        let title = texts.get(crate::keys::SCREEN_CACHE);
        ScreenView {
            title: title.clone(),
            panels: vec![
                Panel {
                    title,
                    lines: summary_lines(app, texts),
                    feed: false,
                },
                Panel {
                    title: texts.get(keys::CACHE_LIST),
                    lines: list,
                    feed: false,
                },
                Panel {
                    title: texts.get(keys::CACHE_DETAIL),
                    lines: state
                        .entries
                        .get(pager.selected)
                        .map(|e| detail_lines(texts, e))
                        .unwrap_or_default(),
                    feed: false,
                },
            ],
        }
    }

    fn help(&self) -> &'static [Key] {
        &[
            keys::CACHE_HELP_SEARCH,
            keys::CACHE_HELP_CLEAR,
            keys::HELP_PAGES,
            keys::HELP_REFRESH,
        ]
    }

    fn plain_help(&self) -> &'static [Key] {
        &[
            keys::PLAIN_PAGES,
            keys::CACHE_PLAIN_DETAILS,
            keys::CACHE_PLAIN_SEARCH,
            keys::CACHE_HELP_CLEAR,
            keys::HELP_REFRESH,
        ]
    }

    fn on_show(&self, app: &mut AppState) {
        let state = &app.inspect.cache;
        if app.link.is_connected() && !state.loading && (!state.asked || state.error.is_some()) {
            load(app, true);
        }
    }

    fn takes_focus(&self) -> bool {
        true
    }

    fn captures_keys(&self, app: &AppState) -> bool {
        let state = &app.inspect.cache;
        state.typing.is_some() || state.question.is_some()
    }

    fn on_key(&self, app: &mut AppState, key: KeyEvent) -> bool {
        if app.inspect.cache.question.is_some() {
            if let Some(given) = answer_key(key) {
                answer(app, given);
            }
            return true;
        }
        if let Some(buffer) = app.inspect.cache.typing.as_mut() {
            match edit(buffer, key) {
                Edit::Typing => {}
                Edit::Done(text) => {
                    app.inspect.cache.typing = None;
                    search(app, text.trim().to_owned());
                }
                Edit::Cancelled => app.inspect.cache.typing = None,
            }
            return true;
        }
        let state = &mut app.inspect.cache;
        let len = state.entries.len();
        match key.code {
            KeyCode::Char('/') => state.typing = Some(state.query.clone()),
            KeyCode::Char('r') => load(app, true),
            KeyCode::Char('c') => ask(app, Clear::App),
            KeyCode::Char('o') => ask(app, Clear::OsDns),
            KeyCode::PageDown if state.pager.page_start() + super::PAGE_ROWS >= len => more(app),
            KeyCode::Down if state.pager.selected + 1 >= len => more(app),
            code => return state.pager.on_key(code, len),
        }
        true
    }

    fn on_line(&self, app: &mut AppState, line: &str) -> bool {
        if app.inspect.cache.question.is_some() {
            return match answer_line(line) {
                Some(given) => {
                    answer(app, given);
                    true
                }
                None => false,
            };
        }
        let state = &mut app.inspect.cache;
        let len = state.entries.len();
        match command(line) {
            ("n", "") => more(app),
            ("p", "") => state.pager.previous_page(),
            ("r", "") => load(app, true),
            ("c", "") => ask(app, Clear::App),
            ("o", "") => ask(app, Clear::OsDns),
            ("/", text) => search(app, text.to_owned()),
            ("d", number) => return state.pager.pick(number, len),
            _ => return false,
        }
        true
    }
}

fn summary_lines(app: &AppState, texts: &Texts) -> Vec<ViewLine> {
    let state = &app.inspect.cache;
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
            texts.get(keys::CACHE_FAILED),
            error_text(texts, slug)
        )));
    }
    if state.loading && state.entries.is_empty() {
        lines.push(ViewLine::text(texts.get(keys::CACHE_LOADING)));
    }
    if let Some(total) = state.total {
        lines.push(ViewLine::text(
            texts.fill(keys::CACHE_TOTAL, &[("total", total.to_string())]),
        ));
    }
    if state.redacted {
        lines.push(ViewLine::text(texts.get(keys::CACHE_REDACTED)));
    }
    match &state.typing {
        Some(buffer) => lines.extend(typing_lines(
            texts,
            &texts.get(keys::CACHE_SEARCH_LABEL),
            buffer,
        )),
        None if !state.query.is_empty() => lines.push(ViewLine::text(
            texts.fill(keys::CACHE_SEARCH, &[("text", &state.query)]),
        )),
        None => {}
    }
    match state.question {
        Some(what) => {
            let question = match what {
                Clear::App => keys::CACHE_CLEAR_APP_QUESTION,
                Clear::OsDns => keys::CACHE_CLEAR_OS_QUESTION,
            };
            lines.push(ViewLine::new(vec![crate::view::Segment::strong(
                texts.get(question),
            )]));
            lines.push(ViewLine::text(texts.get(keys::YES_NO)));
        }
        None if state.clearing => lines.push(ViewLine::text(texts.get(keys::CACHE_CLEARING))),
        None => {
            if let Some(cleared) = &state.cleared {
                lines.push(ViewLine::text(cleared_text(texts, cleared)));
            }
            lines.push(ViewLine::text(format!(
                "c: {}   o: {}",
                texts.get(keys::CACHE_CLEAR_APP),
                texts.get(keys::CACHE_CLEAR_OS)
            )));
        }
    }
    lines
}

fn cleared_text(texts: &Texts, cleared: &Cleared) -> String {
    match cleared {
        Cleared::App { removed } => {
            texts.fill(keys::CACHE_CLEARED, &[("count", removed.to_string())])
        }
        Cleared::OsDns { flushed: true } => texts.get(keys::CACHE_OS_FLUSHED),
        Cleared::OsDns { flushed: false } => texts.get(keys::CACHE_OS_NOT_FLUSHED),
        Cleared::Failed(slug) => format!(
            "{}{}",
            texts.get(keys::CACHE_CLEAR_FAILED),
            error_text(texts, slug)
        ),
    }
}

/// Backend slugs are snake_case; locale key segments are kebab-case.
fn slug_label(texts: &Texts, family: &str, slug: &str) -> String {
    let id = format!("diag.cache.{family}.{}", slug.replace('_', "-"));
    texts.dynamic(&id, slug)
}

/// Where the rules would send it: the trace's route words, or "—".
fn route_label(texts: &Texts, route: &str) -> String {
    if route.is_empty() {
        "—".to_owned()
    } else {
        texts.dynamic(&format!("diag.conn-trace.egress.{route}"), route)
    }
}

fn row_text(texts: &Texts, e: &CacheEntryDto) -> String {
    format!(
        "{} → {} · {} · {}",
        e.hostname,
        e.ip,
        route_label(texts, &e.expected_route),
        slug_label(texts, "freshness", &e.freshness),
    )
}

fn detail_lines(texts: &Texts, e: &CacheEntryDto) -> Vec<ViewLine> {
    let field = |key: Key, value: String| ViewLine::text(format!("{}: {value}", texts.get(key)));
    let mut lines = vec![
        field(keys::COL_HOST, e.hostname.clone()),
        field(keys::COL_IP, e.ip.clone()),
    ];
    if !e.fake_ip.is_empty() {
        lines.push(field(keys::COL_FAKE_IP, e.fake_ip.clone()));
    }
    let route = if e.expected_route.is_empty() {
        texts.get(keys::CACHE_NO_RULE)
    } else {
        route_label(texts, &e.expected_route)
    };
    lines.push(field(keys::COL_ROUTE, route));
    lines.push(field(
        keys::COL_FRESHNESS,
        slug_label(texts, "freshness", &e.freshness),
    ));
    lines.push(field(
        keys::COL_SOURCE,
        slug_label(texts, "source", &e.source),
    ));
    lines.push(ViewLine::text(format!(
        "{}: {} · {}: {}",
        texts.get(keys::CACHE_RESOLVED),
        wall_clock(e.resolved_at_ms),
        texts.get(keys::CACHE_EXPIRES),
        wall_clock(e.expires_at_ms)
    )));
    lines
}
