//! The notice feed as a list to act on, as the window's notification cards
//! and the tray's block notice: a notice is chosen with Up and Down (line
//! mode names it by its number) and dismissed, or the notices like it stop
//! appearing. A block also goes over the additional route, is snoozed, or is
//! explained. Every "stop appearing" is the service-kept mute every surface
//! reads, so the window, the tray and Settings agree.

use crossterm::event::{KeyCode, KeyEvent};
use nrr_client_logic::block_notices::offers_route;
use nrr_client_logic::notice_mutes::{notice_mute_request, NOTICE_MUTE_CHOICES_MS};
use nrr_ipc_client::IpcClient;
use nrr_shared::display_text::display_text;
use nrr_shared::ipc::IpcOperationName;
use nrr_shared::ipc_payloads::{
    BlockNoticeMuteScopeDto, BlockNoticeMutesSetRequest, BlockNoticeMutesSetResponse,
};
use serde_json::Value;

use crate::backend::{Job, Reply};
use crate::i18n::{key, Key, Texts};
use crate::keys;
use crate::screens::suggestions::{call, CallError};
use crate::screens::ScreenId;
use crate::state::{AppState, Effect, Focus, Notice, NoticeLevel};
use crate::view::{Segment, StateTone, ViewLine};

/// What a notice is about, for the answers it offers.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum About {
    #[default]
    Nothing,
    /// A kind the user may hide as a whole, by its service slug.
    Kind(&'static str),
    Block(BlockSubject),
    /// A site that does not open, as the service named it: the site check
    /// tells whether the network or the site is at fault.
    Site(String),
}

/// A blocked connection as the service named it, before any display escaping:
/// a mute must name the host the service matches.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockSubject {
    pub destination: String,
    /// Empty when the service could not tell the program.
    pub app: String,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Question {
    /// For how long notices of a kind stay hidden.
    HideKind { id: usize, kind: &'static str },
    /// Which of the blocks like this one stop being told.
    Mute { id: usize, block: BlockSubject },
    /// For how long this blocked site is not told about.
    Snooze { id: usize, block: BlockSubject },
}

impl Question {
    fn id(&self) -> usize {
        match self {
            Self::HideKind { id, .. } | Self::Mute { id, .. } | Self::Snooze { id, .. } => *id,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Note {
    NoSuch(usize),
    Addresses { hidden: bool },
}

#[derive(Debug, Default)]
pub struct FeedState {
    /// The chosen notice by its number; none, or one gone, is the newest.
    selected: Option<usize>,
    pub question: Option<Question>,
    note: Option<Note>,
    /// A mute the service refused, told on the next tick with texts in hand.
    unannounced: Option<CallError>,
}

const SNOOZE_MS: [(Key, i64); 6] = [
    (SNOOZE_15M, 15 * 60 * 1000),
    (SNOOZE_1H, 60 * 60 * 1000),
    (SNOOZE_8H, 8 * 60 * 60 * 1000),
    (FOR_A_DAY, 24 * 60 * 60 * 1000),
    (FOR_7_DAYS, 7 * 24 * 60 * 60 * 1000),
    (FOR_30_DAYS, 30 * 24 * 60 * 60 * 1000),
];

pub const DISMISS: Key = key("action.dismiss", "Dismiss");
pub const DISMISS_ALL: Key = key("notifications.dismiss-all", "Dismiss all");
pub const DONT_SHOW: Key = key("action.dont-show", "Don't show…");
pub const SNOOZE: Key = key("tray.block-notice.action.snooze", "Snooze");
pub const WHY: Key = key("notifications.block-notice.explain", "Why?");
pub const CHECK_SITE: Key = key("diag.conn-trace.check-site", "Check site…");
pub const HIDE_ADDRESSES: Key = key(
    "settings.field.hide-block-notice-addresses",
    "Hide addresses in these notifications",
);
pub const ON: Key = key("tui.settings.on", "On");
pub const OFF: Key = key("tui.settings.off", "Off");
pub const KIND_TITLE: Key = key("tray.notice-mute.title", "Stop showing this notification?");
pub const KIND_BODY: Key = key(
    "tray.notice-mute.body",
    "\"{name}\" will not appear for as long as you choose.",
);
pub const FOR_A_DAY: Key = key("label.duration.for-a-day", "For a day");
pub const FOR_7_DAYS: Key = key("label.duration.for-7-days", "For 7 days");
pub const FOR_30_DAYS: Key = key("label.duration.for-30-days", "For 30 days");
pub const FOREVER: Key = key("label.duration.forever", "Forever");
pub const MUTE_TITLE: Key = key(
    "tray.block-notice.mute.title",
    "What should stop appearing?",
);
pub const MUTE_HINT: Key = key(
    "tray.mute.lift-hint",
    "Mutes can be lifted later in Settings, Notifications.",
);
pub const MUTE_HOST: Key = key("tray.block-notice.mute.this-host", "Only {name}");
pub const MUTE_APP: Key = key("tray.block-notice.mute.this-app", "All from {name}");
pub const MUTE_REASON: Key = key("tray.block-notice.mute.this-reason", "All \"{name}\"");
pub const MUTE_ALL: Key = key(
    "tray.block-notice.mute.all",
    "All blocks: any host, any app",
);
pub const REASON_ANY: Key = key("block-reason.any", "Blocks of this kind");
pub const SNOOZE_TITLE: Key = key("tray.block-notice.snooze.title", "Snooze this notice");
pub const SNOOZE_BODY: Key = key(
    "tray.block-notice.snooze.body",
    "Stop asking about {name} for a while.",
);
pub const SNOOZE_15M: Key = key("tray.block-notice.snooze.for-15-minutes", "15 minutes");
pub const SNOOZE_1H: Key = key("tray.block-notice.snooze.for-1-hour", "1 hour");
pub const SNOOZE_8H: Key = key("tray.block-notice.snooze.for-8-hours", "8 hours");
pub const FAILED: Key = key(
    "settings.block-notices.add.failed",
    "Could not add the mute: ",
);
pub const NEWER_ABOVE: Key = key(
    "tui.feed.newer-above",
    "Newer notifications above: {count}.",
);
pub const NO_SUCH: Key = key(
    "tui.feed.no-such",
    "No notification has the number {number}.",
);
pub const CHOOSE: Key = key(
    "tui.feed.choose",
    "Type the number of an answer. n or Esc: cancel.",
);
pub const ADDRESSES_HIDDEN: Key = key(
    "tui.feed.addresses-hidden",
    "Block notifications no longer show addresses.",
);
pub const ADDRESSES_SHOWN: Key = key(
    "tui.feed.addresses-shown",
    "Block notifications show addresses again.",
);
pub const HELP: Key = key(
    "tui.help.feed-keys",
    "In the notifications: x: dismiss the chosen one   X: dismiss all   m: stop showing ones like it   H: hide addresses in block notifications. A blocked connection also offers v: the additional route, s: snooze, w: why it was blocked.",
);
pub const PLAIN_DISMISS: Key = key(
    "tui.plain.feed-dismiss",
    "x N: dismiss notification N   X: dismiss all",
);
pub const PLAIN_MUTE: Key = key(
    "tui.plain.feed-mute",
    "m N: stop showing notifications like N   H: hide or show addresses in block notifications",
);
pub const PLAIN_BLOCK: Key = key(
    "tui.plain.feed-block",
    "For a blocked connection N: v N: send it over the additional route   s N: snooze   w N: why it was blocked",
);
pub const HELP_SITE: Key = key(
    "tui.help.feed-site",
    "A notification about a site that does not open offers c: check whether the network or the site is at fault (opens Diagnostics).",
);
pub const PLAIN_SITE: Key = key(
    "tui.plain.feed-site",
    "For a site that does not open in notification N: c N: check whether the network or the site is at fault",
);

#[cfg(test)]
pub fn keys() -> Vec<Key> {
    vec![
        DISMISS,
        DISMISS_ALL,
        DONT_SHOW,
        SNOOZE,
        WHY,
        CHECK_SITE,
        HIDE_ADDRESSES,
        ON,
        OFF,
        KIND_TITLE,
        KIND_BODY,
        FOR_A_DAY,
        FOR_7_DAYS,
        FOR_30_DAYS,
        FOREVER,
        MUTE_TITLE,
        MUTE_HINT,
        MUTE_HOST,
        MUTE_APP,
        MUTE_REASON,
        MUTE_ALL,
        REASON_ANY,
        SNOOZE_TITLE,
        SNOOZE_BODY,
        SNOOZE_15M,
        SNOOZE_1H,
        SNOOZE_8H,
        FAILED,
        NEWER_ABOVE,
        NO_SUCH,
        CHOOSE,
        ADDRESSES_HIDDEN,
        ADDRESSES_SHOWN,
        HELP,
        PLAIN_DISMISS,
        PLAIN_MUTE,
        PLAIN_BLOCK,
        HELP_SITE,
        PLAIN_SITE,
    ]
}

/// Whether block notices may name their destination now.
pub fn hide_addresses(app: &AppState) -> bool {
    app.settings.prefs.hide_block_addresses
}

/// Whether a question about a notice waits for its answer.
pub fn question_open(app: &AppState) -> bool {
    app.feed.question.is_some()
}

// ── Choosing ─────────────────────────────────────────────────────────────────

/// The chosen notice's place, newest first.
fn chosen_at(app: &AppState) -> usize {
    app.feed
        .selected
        .and_then(|id| app.notices.iter().rev().position(|n| n.id == id))
        .unwrap_or(0)
}

fn chosen(app: &AppState) -> Option<&Notice> {
    app.notices.iter().rev().nth(chosen_at(app))
}

fn by_id(app: &AppState, id: usize) -> Option<&Notice> {
    app.notices.iter().find(|n| n.id == id)
}

fn choose_at(app: &mut AppState, at: usize) {
    let last = app.notices.len().saturating_sub(1);
    app.feed.selected = app.notices.iter().rev().nth(at.min(last)).map(|n| n.id);
}

fn step(app: &mut AppState, by: isize) {
    let at = chosen_at(app).saturating_add_signed(by);
    choose_at(app, at);
}

// ── Answers ──────────────────────────────────────────────────────────────────

/// Take notice `id` down; the choice stays at the same place in the list.
fn dismiss(app: &mut AppState, id: usize) -> bool {
    let Some(at) = app.notices.iter().rev().position(|n| n.id == id) else {
        return false;
    };
    let chosen_here = chosen_at(app) == at;
    app.notices.retain(|n| n.id != id);
    if app.feed.question.as_ref().is_some_and(|q| q.id() == id) {
        app.feed.question = None;
    }
    if chosen_here {
        choose_at(app, at);
    }
    true
}

fn dismiss_all(app: &mut AppState) -> bool {
    app.notices.clear();
    app.feed.selected = None;
    app.feed.question = None;
    true
}

/// "Don't show…": how long for a kind, which scope for a block.
fn ask_mute(app: &mut AppState, id: usize) -> bool {
    let Some(notice) = by_id(app, id) else {
        return false;
    };
    let question = match &notice.about {
        About::Nothing | About::Site(_) => return false,
        About::Kind(kind) => Question::HideKind { id, kind },
        About::Block(block) => Question::Mute {
            id,
            block: block.clone(),
        },
    };
    app.feed.question = Some(question);
    true
}

fn block_of(app: &AppState, id: usize) -> Option<BlockSubject> {
    match &by_id(app, id)?.about {
        About::Block(block) if !block.destination.trim().is_empty() => Some(block.clone()),
        _ => None,
    }
}

fn ask_snooze(app: &mut AppState, id: usize) -> bool {
    let Some(block) = block_of(app, id) else {
        return false;
    };
    app.feed.question = Some(Question::Snooze { id, block });
    true
}

/// "To additional route" for this block: the question the Status screen
/// already asks for the newest one.
fn route(app: &mut AppState, id: usize) -> bool {
    let Some(block) = block_of(app, id) else {
        return false;
    };
    let asked = crate::block_route::ask_about(app, &block.destination, &block.reason);
    if asked {
        app.block_route.asked_from = Some(id);
    }
    asked
}

/// Take notice `id` off the feed, as a dismiss does.
pub fn dismiss_notice(app: &mut AppState, id: usize) {
    dismiss(app, id);
}

/// "Why?": the explain probe for the blocked host, run where it is answered.
fn why(app: &mut AppState, id: usize) -> bool {
    let Some(block) = block_of(app, id) else {
        return false;
    };
    app.open(ScreenId::Diagnostics);
    app.focus = Focus::Menu;
    crate::screens::inspect::diagnostics::probe(app, &block.destination, "", "");
    true
}

/// "Check site…": whether the network or the site is at fault, in Diagnostics.
fn check_site(app: &mut AppState, id: usize) -> bool {
    let Some(About::Site(site)) = by_id(app, id).map(|n| n.about.clone()) else {
        return false;
    };
    if site.trim().is_empty() {
        return false;
    }
    app.open(ScreenId::Diagnostics);
    app.focus = Focus::Menu;
    crate::screens::inspect::diagnostics::check_site(app, &site);
    true
}

fn toggle_hide(app: &mut AppState) -> bool {
    let prefs = &mut app.settings.prefs;
    prefs.hide_block_addresses = !prefs.hide_block_addresses;
    app.feed.note = Some(Note::Addresses {
        hidden: prefs.hide_block_addresses,
    });
    // Unsaved, it still holds for this run.
    let _ = app.settings.save_prefs();
    true
}

/// What an answer is called; the names are filled when shown.
enum Label {
    Key(Key),
    Host(String),
    App(String),
    Reason(String),
}

impl Label {
    fn text(&self, app: &AppState, texts: &Texts) -> String {
        match self {
            Self::Key(key) => texts.get(*key),
            Self::Host(host) => {
                texts.fill(MUTE_HOST, &[("name", shown_destination(app, host, texts))])
            }
            Self::App(name) => texts.fill(MUTE_APP, &[("name", display_text(name))]),
            Self::Reason(reason) => {
                let name = texts.dynamic(&format!("block-reason.{reason}"), &texts.get(REASON_ANY));
                texts.fill(MUTE_REASON, &[("name", name)])
            }
        }
    }
}

/// The answers the open question offers, in the order they are numbered,
/// each with the request it writes.
fn answers(app: &AppState, question: &Question) -> Vec<(Label, Value)> {
    let now = app.settings.clock.now();
    let request = |scope: BlockNoticeMuteScopeDto, until: Option<i64>| {
        serde_json::to_value(BlockNoticeMutesSetRequest {
            scope,
            until_unix_ms: until.and_then(|u| u64::try_from(u).ok()),
        })
        .unwrap_or(Value::Null)
    };
    match question {
        Question::HideKind { kind, .. } => NOTICE_MUTE_CHOICES_MS
            .iter()
            .zip([FOR_A_DAY, FOR_7_DAYS, FOR_30_DAYS, FOREVER])
            .filter_map(|((choice, _), label)| {
                notice_mute_request(kind, choice, now).map(|r| (Label::Key(label), r))
            })
            .collect(),
        Question::Snooze { block, .. } => SNOOZE_MS
            .iter()
            .map(|(label, span)| {
                let scope = BlockNoticeMuteScopeDto::Host {
                    host: block.destination.clone(),
                };
                (
                    Label::Key(*label),
                    request(scope, Some(now.saturating_add(*span))),
                )
            })
            .collect(),
        Question::Mute { block, .. } => {
            let mut offered = Vec::new();
            if !block.destination.trim().is_empty() {
                let host = block.destination.clone();
                offered.push((
                    Label::Host(host.clone()),
                    request(BlockNoticeMuteScopeDto::Host { host }, None),
                ));
            }
            // A connection with no program named has nothing for that scope.
            if !block.app.is_empty() {
                let app = block.app.clone();
                offered.push((
                    Label::App(app.clone()),
                    request(BlockNoticeMuteScopeDto::App { app }, None),
                ));
            }
            if well_formed_slug(&block.reason) {
                let reason = block.reason.clone();
                offered.push((
                    Label::Reason(reason.clone()),
                    request(BlockNoticeMuteScopeDto::Reason { reason }, None),
                ));
            }
            offered.push((
                Label::Key(MUTE_ALL),
                request(BlockNoticeMuteScopeDto::All, None),
            ));
            offered
        }
    }
}

fn well_formed_slug(slug: &str) -> bool {
    !slug.is_empty()
        && slug.len() <= 64
        && slug
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn shown_destination(app: &AppState, destination: &str, texts: &Texts) -> String {
    if hide_addresses(app) {
        texts.get(keys::BLOCK_NOTICE_DESTINATION_HIDDEN)
    } else {
        display_text(destination).into_owned()
    }
}

/// Answer `n` (from 1) of the open question.
fn answer(app: &mut AppState, n: usize) -> bool {
    let Some(question) = app.feed.question.clone() else {
        return false;
    };
    let Some((_, request)) = n
        .checked_sub(1)
        .and_then(|at| answers(app, &question).into_iter().nth(at))
    else {
        return false;
    };
    app.feed.question = None;
    if !app.link.is_connected() {
        return true;
    }
    app.outbox.push(mute_job(request, question.id()));
    true
}

fn mute_job(request: Value, id: usize) -> Job {
    Box::new(move |client: &dyn IpcClient| {
        let answer: Result<BlockNoticeMutesSetResponse, _> =
            call(client, IpcOperationName::BlockNoticeMutesSet, &request);
        Reply::new(move |app| match answer {
            Ok(written) => {
                crate::restore::record_mutes(app, &written.mutes);
                crate::notice_mutes::set(
                    app,
                    serde_json::to_value(&written.mutes).unwrap_or(Value::Null),
                );
                dismiss(app, id);
            }
            Err(error) => app.feed.unannounced = Some(error),
        })
    })
}

/// Say a refused mute, once texts are in hand.
pub fn announce(app: &mut AppState, texts: &Texts, now: std::time::Instant) -> Vec<Effect> {
    let Some(error) = app.feed.unannounced.take() else {
        return Vec::new();
    };
    let body = format!("{}{}", texts.get(FAILED), error.text(texts));
    app.notify(
        NoticeLevel::Warning,
        texts.get(keys::NOTICES_TITLE),
        body,
        now,
    )
}

// ── Keys and lines ───────────────────────────────────────────────────────────

/// A key for the feed: the open question's first, then, while the feed has
/// the focus, the chosen notice's. `false` leaves the key to the screen.
pub fn on_key(app: &mut AppState, key: KeyEvent) -> bool {
    if app.feed.question.is_some() {
        return match key.code {
            KeyCode::Char('n') | KeyCode::Esc => {
                app.feed.question = None;
                true
            }
            KeyCode::Char(c) => {
                if let Some(n) = c.to_digit(10) {
                    answer(app, n as usize);
                }
                // A digit is never a screen while a question is open.
                true
            }
            _ => false,
        };
    }
    if app.focus != Focus::Feed || app.notices.is_empty() {
        return false;
    }
    app.feed.note = None;
    let id = chosen(app).map_or(0, |n| n.id);
    match key.code {
        KeyCode::Up => step(app, -1),
        KeyCode::Down => step(app, 1),
        KeyCode::PageUp => step(app, -5),
        KeyCode::PageDown => step(app, 5),
        KeyCode::Home => choose_at(app, 0),
        KeyCode::End => choose_at(app, usize::MAX),
        KeyCode::Char('x') => return dismiss(app, id),
        KeyCode::Char('X') => return dismiss_all(app),
        KeyCode::Char('m') => return ask_mute(app, id),
        KeyCode::Char('s') => return ask_snooze(app, id),
        KeyCode::Char('v') => return route(app, id),
        KeyCode::Char('w') => return why(app, id),
        KeyCode::Char('c') => return check_site(app, id),
        KeyCode::Char('H') => return toggle_hide(app),
        _ => return false,
    }
    true
}

/// A line-mode command for the feed; notices are named by their number.
pub fn on_line(app: &mut AppState, line: &str) -> bool {
    let line = line.trim();
    if app.feed.question.is_some() {
        if line == "n" {
            app.feed.question = None;
            return true;
        }
        if let Ok(n) = line.parse::<usize>() {
            answer(app, n);
            return true;
        }
        // Quitting, help and a reprint stay the common commands.
        return !matches!(line, "" | "q" | "h" | "?");
    }
    match line {
        "X" => return dismiss_all(app),
        "H" => return toggle_hide(app),
        _ => {}
    }
    let mut chars = line.chars();
    let Some(letter) = chars.next() else {
        return false;
    };
    if !matches!(letter, 'x' | 'm' | 's' | 'v' | 'w' | 'c') {
        return false;
    }
    let Ok(number) = chars.as_str().trim().parse::<usize>() else {
        return false;
    };
    app.feed.note = None;
    if by_id(app, number).is_none() {
        app.feed.note = Some(Note::NoSuch(number));
        return true;
    }
    app.feed.selected = Some(number);
    match letter {
        'x' => dismiss(app, number),
        'm' => ask_mute(app, number),
        's' => ask_snooze(app, number),
        'v' => route(app, number),
        'c' => check_site(app, number),
        _ => why(app, number),
    };
    true
}

/// The feed, newest first, each notice under its number. While the feed has
/// the focus it starts at the chosen notice, which carries `>` and the keys
/// it offers, so the choice is always in view.
pub fn lines(app: &AppState, texts: &Texts) -> Vec<ViewLine> {
    let mut lines = Vec::new();
    match &app.feed.note {
        Some(Note::NoSuch(number)) => lines.push(ViewLine::new(vec![Segment::muted(
            texts.fill(NO_SUCH, &[("number", number.to_string())]),
        )])),
        Some(Note::Addresses { hidden }) => {
            lines.push(ViewLine::new(vec![Segment::muted(texts.get(if *hidden {
                ADDRESSES_HIDDEN
            } else {
                ADDRESSES_SHOWN
            }))]))
        }
        None => {}
    }
    if app.notices.is_empty() {
        lines.push(ViewLine::new(vec![Segment::muted(
            texts.get(keys::NOTICES_EMPTY),
        )]));
        return lines;
    }
    let focused = app.focus == Focus::Feed;
    let at = chosen_at(app);
    let start = if focused { at } else { 0 };
    if start > 0 {
        lines.push(ViewLine::new(vec![Segment::muted(
            texts.fill(NEWER_ABOVE, &[("count", start.to_string())]),
        )]));
    }
    let hide = hide_addresses(app);
    for (i, notice) in app.notices.iter().rev().enumerate().skip(start) {
        let level = match notice.level {
            NoticeLevel::Warning => {
                Segment::state(texts.get(keys::LEVEL_WARNING), StateTone::Caution)
            }
            NoticeLevel::Info => Segment::strong(texts.get(keys::LEVEL_INFO)),
        };
        let here = focused && i == at;
        let number = format!("{}. ", notice.id);
        let number = if here {
            Segment::selected(format!("> {number}"))
        } else if focused {
            Segment::plain(format!("  {number}"))
        } else {
            Segment::plain(number)
        };
        lines.push(ViewLine::new(vec![
            number,
            level,
            Segment::plain(": "),
            Segment::strong(notice.title.clone()),
        ]));
        lines.push(ViewLine::text(notice.shown_body(hide).to_owned()));
        match &app.feed.question {
            Some(question) if question.id() == notice.id => {
                lines.extend(question_lines(app, question, notice, texts));
            }
            _ if here => lines.push(ViewLine::new(vec![Segment::muted(offered_keys(
                app, notice, texts,
            ))])),
            _ => {}
        }
    }
    lines
}

fn question_lines(
    app: &AppState,
    question: &Question,
    notice: &Notice,
    texts: &Texts,
) -> Vec<ViewLine> {
    let mut lines = match question {
        Question::HideKind { .. } => vec![
            ViewLine::new(vec![Segment::strong(texts.get(KIND_TITLE))]),
            ViewLine::text(texts.fill(KIND_BODY, &[("name", notice.title.as_str())])),
        ],
        Question::Mute { .. } => vec![
            ViewLine::new(vec![Segment::strong(texts.get(MUTE_TITLE))]),
            ViewLine::text(texts.get(MUTE_HINT)),
        ],
        Question::Snooze { block, .. } => vec![
            ViewLine::new(vec![Segment::strong(texts.get(SNOOZE_TITLE))]),
            ViewLine::text(texts.fill(
                SNOOZE_BODY,
                &[("name", shown_destination(app, &block.destination, texts))],
            )),
        ],
    };
    for (n, (label, _)) in answers(app, question).into_iter().enumerate() {
        lines.push(ViewLine::text(format!(
            "  {}: {}",
            n + 1,
            label.text(app, texts)
        )));
    }
    lines.push(ViewLine::new(vec![Segment::muted(texts.get(CHOOSE))]));
    lines
}

/// The keys the chosen notice answers to, as one line.
fn offered_keys(app: &AppState, notice: &Notice, texts: &Texts) -> String {
    let mut offered = vec![
        format!("x: {}", texts.get(DISMISS)),
        format!("X: {}", texts.get(DISMISS_ALL)),
    ];
    if matches!(notice.about, About::Kind(_) | About::Block(_)) {
        offered.push(format!("m: {}", texts.get(DONT_SHOW)));
    }
    if matches!(&notice.about, About::Site(site) if !site.trim().is_empty()) {
        offered.push(format!("c: {}", texts.get(CHECK_SITE)));
    }
    if let About::Block(block) = &notice.about {
        if !block.destination.trim().is_empty() {
            if app.link.is_connected() && offers_route(&block.reason) {
                offered.push(format!("v: {}", texts.get(crate::block_route::ACTION)));
            }
            offered.push(format!("s: {}", texts.get(SNOOZE)));
            offered.push(format!("w: {}", texts.get(WHY)));
        }
    }
    if notice.private_body.is_some() {
        let state = texts.get(if hide_addresses(app) { ON } else { OFF });
        offered.push(format!("H: {}: {state}", texts.get(HIDE_ADDRESSES)));
    }
    offered.join("   ")
}

#[cfg(test)]
mod tests;
