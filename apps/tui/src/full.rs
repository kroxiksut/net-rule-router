//! The full-screen renderer and its loop. Every line it draws comes from the
//! screen model; this module only lays it out and marks it.

use std::io::{self, Write};
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph, Wrap};
use ratatui::{DefaultTerminal, Frame};

use crate::backend::{Backend, BackendEvent, Command};
use crate::elevation_prompt::PromptRequest;
use crate::i18n::Texts;
use crate::keys;
use crate::screens::{connection_lines, menu_step, screen, MenuItem, ScreenId, COMMON_HELP};
use crate::state::{AppState, Effect, Focus, NoticeLevel};
use crate::view::{Panel, Tone, ViewLine};

mod palette;
use palette::Palette;

/// How long a new notice also shows in the bottom line. It stays in the feed;
/// nothing the user must act on depends on this timer.
const NOTICE_LINE_FOR: Duration = Duration::from_secs(10);
/// Wait for a key at most this long, so pushes reach the screen promptly.
const INPUT_POLL: Duration = Duration::from_millis(250);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RenderOptions {
    pub colour: bool,
    /// Plain characters: no frame lines at all, panel titles carry the layout.
    pub ascii: bool,
}

pub fn run(
    app: &mut AppState,
    texts: &Texts,
    options: RenderOptions,
    backend: &Backend,
    events: &Receiver<BackendEvent>,
) -> io::Result<()> {
    let mut terminal = ratatui::try_init()?;
    let result = event_loop(&mut terminal, app, texts, options, backend, events);
    ratatui::restore();
    result
}

fn event_loop(
    terminal: &mut DefaultTerminal,
    app: &mut AppState,
    texts: &Texts,
    options: RenderOptions,
    backend: &Backend,
    events: &Receiver<BackendEvent>,
) -> io::Result<()> {
    // Replaced when the user picks another language.
    let mut current = texts.clone();
    while !app.quit {
        if let Some(language) = app.language_change.take() {
            current = Texts::load(Some(&language), &[]);
            crate::screens::rules::on_texts(app, &current);
        }
        let texts = &current;
        while let Some(request) = backend.take_prompt_request() {
            hand_over_for_password(terminal, request, texts)?;
        }
        let now = Instant::now();
        while let Ok(event) = events.try_recv() {
            for effect in app.apply(event, texts, now) {
                match effect {
                    Effect::Refresh => backend.send(Command::Refresh),
                    Effect::Bell => ring_bell(),
                }
            }
        }
        backend.send_outbox(&mut app.outbox);
        terminal.draw(|frame| draw(frame, app, texts, options, now))?;
        if event::poll(INPUT_POLL)? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    handle_key(app, key, texts);
                    backend.send_outbox(&mut app.outbox);
                }
            }
        }
    }
    Ok(())
}

/// The agent asks for the password on the terminal itself, so the screen goes
/// back to a plain terminal until the job that asked is done with it.
fn hand_over_for_password(
    terminal: &mut DefaultTerminal,
    request: PromptRequest,
    texts: &Texts,
) -> io::Result<()> {
    ratatui::restore();
    println!("{}", texts.get(keys::PASSWORD_PROMPT));
    let _ = request.ready.send(true);
    // Closes when the job is done, however it ended.
    let _ = request.done.recv();
    *terminal = ratatui::try_init()?;
    terminal.clear()
}

fn ring_bell() {
    let mut out = io::stdout();
    let _ = out.write_all(b"\x07");
    let _ = out.flush();
}

/// Keys never change meaning between screens; a screen only adds its own.
pub fn handle_key(app: &mut AppState, key: KeyEvent, texts: &Texts) {
    let current = screen(app.screen);
    let ctrl_c = key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL);
    // Typed text and pending questions take every key; the content takes the
    // keys it knows once it has the focus.
    if !ctrl_c
        && !app.help_open
        && (current.captures_keys(app) || app.focus == Focus::Feed)
        && current.on_key(app, key)
    {
        return;
    }
    match key.code {
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => app.quit = true,
        KeyCode::F(1) | KeyCode::Char('?') => app.help_open = !app.help_open,
        KeyCode::Esc => {
            if app.help_open {
                app.help_open = false;
            } else {
                app.focus = Focus::Menu;
            }
        }
        KeyCode::Char('q') => app.request_quit(),
        KeyCode::Char(c) => {
            if let Some(target) = ScreenId::from_hotkey(c) {
                app.open(target);
                app.focus = Focus::Menu;
            } else if !app.help_open {
                // A screen's letter works from the menu too.
                current.on_key(app, key);
            }
        }
        KeyCode::Tab | KeyCode::BackTab => {
            app.focus = match app.focus {
                Focus::Menu if has_feed(app, texts) => Focus::Feed,
                _ => Focus::Menu,
            };
        }
        KeyCode::Enter if app.focus == Focus::Menu && has_feed(app, texts) => {
            app.focus = Focus::Feed;
        }
        KeyCode::Up => match app.focus {
            Focus::Menu => menu_step(app, false),
            Focus::Feed => app.scroll = app.scroll.saturating_sub(1),
        },
        KeyCode::Down => match app.focus {
            Focus::Menu => menu_step(app, true),
            Focus::Feed => app.scroll = app.scroll.saturating_add(1),
        },
        KeyCode::PageUp if app.focus == Focus::Feed => app.scroll = app.scroll.saturating_sub(10),
        KeyCode::PageDown if app.focus == Focus::Feed => {
            app.scroll = app.scroll.saturating_add(10);
        }
        _ => {}
    }
}

fn has_feed(app: &AppState, texts: &Texts) -> bool {
    let current = screen(app.screen);
    !app.help_open
        && (current.takes_focus() || current.view(app, texts).panels.iter().any(|p| p.feed))
}

// ── Lines ────────────────────────────────────────────────────────────────────

fn style_for(tone: Tone, options: RenderOptions) -> Style {
    Palette::new(options).tone(tone)
}

fn styled_line(line: &ViewLine, style: impl Fn(Tone) -> Style) -> Line<'static> {
    Line::from(
        line.segments
            .iter()
            .map(|s| Span::styled(s.text.clone(), style(s.tone)))
            .collect::<Vec<_>>(),
    )
}

pub fn to_line(line: &ViewLine, options: RenderOptions) -> Line<'static> {
    styled_line(line, |tone| style_for(tone, options))
}

/// The connection lines, drawn on the title bar.
pub fn header_lines(app: &AppState, texts: &Texts, options: RenderOptions) -> Vec<Line<'static>> {
    let palette = Palette::new(options);
    connection_lines(app, texts)
        .iter()
        .map(|l| styled_line(l, |tone| palette.on_bar(tone)))
        .collect()
}

/// The menu: the current row carries `>`; while the menu has the focus it is
/// also inverted, so focus never depends on colour. A sub-screen shows,
/// indented under its parent, only while it is open; so do the Settings
/// sections.
pub fn menu_lines(app: &AppState, texts: &Texts) -> Vec<Line<'static>> {
    let here = MenuItem::current(app);
    MenuItem::shown(app)
        .into_iter()
        .map(|item| {
            let current = item == here;
            let marker = if current { '>' } else { ' ' };
            let text = match item {
                MenuItem::Screen(id) => {
                    let title = texts.get(id.title());
                    match id.hotkey() {
                        Some(key) => format!("{marker} {key} {title}"),
                        None => format!("{marker}     {title}"),
                    }
                }
                MenuItem::Section(category) => {
                    format!("{marker}     {}", texts.get(category.title()))
                }
            };
            if current && app.focus == Focus::Menu {
                Line::styled(text, Palette::focus())
            } else {
                Line::from(text)
            }
        })
        .collect()
}

/// The panels the content area shows: the screen's, or the help in their place.
pub fn content_panels(app: &AppState, texts: &Texts) -> Vec<Panel> {
    if app.help_open {
        let lines = COMMON_HELP
            .iter()
            .chain(screen(app.screen).help())
            .map(|&k| ViewLine::text(texts.get(k)))
            .collect();
        return vec![Panel {
            title: format!(
                "{} — {}",
                texts.get(keys::HELP_TITLE),
                texts.get(app.screen.title())
            ),
            lines,
            feed: false,
        }];
    }
    screen(app.screen).view(app, texts).panels
}

/// The bottom lines: a notice that just arrived, then the key hint, which
/// the status bar carries.
pub fn footer_lines(
    app: &AppState,
    texts: &Texts,
    options: RenderOptions,
    now: Instant,
) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    let recent = app
        .last_notice_at
        .is_some_and(|at| now.saturating_duration_since(at) < NOTICE_LINE_FOR);
    if let Some(notice) = app.notices.last().filter(|_| recent) {
        let (word, tone) = match notice.level {
            NoticeLevel::Warning => (keys::LEVEL_WARNING, Tone::Caution),
            NoticeLevel::Info => (keys::LEVEL_INFO, Tone::Strong),
        };
        lines.push(Line::from(vec![
            Span::styled(texts.get(word), style_for(tone, options)),
            Span::raw(format!(": {}", notice.title)),
        ]));
    }
    lines.push(Line::from(texts.get(keys::FOOTER)));
    lines
}

// ── Layout ───────────────────────────────────────────────────────────────────

/// Rows `lines` take once wrapped at `width`. Word wrapping can need a row more
/// than the characters do, so a wrapped line is given one spare.
fn wrapped_rows(lines: &[Line<'_>], width: u16) -> u16 {
    let width = usize::from(width.max(1));
    let rows: usize = lines
        .iter()
        .map(|line| {
            let w = line.width();
            if w <= width {
                1
            } else {
                w.div_ceil(width) + 1
            }
        })
        .sum();
    u16::try_from(rows).unwrap_or(u16::MAX)
}

pub fn draw(
    frame: &mut Frame,
    app: &AppState,
    texts: &Texts,
    options: RenderOptions,
    now: Instant,
) {
    let area = frame.area();
    let palette = Palette::new(options);
    let header = header_lines(app, texts, options);
    let mut notice = footer_lines(app, texts, options, now);
    let hint: Vec<Line<'static>> = notice.pop().into_iter().collect();
    let [header_area, body_area, notice_area, hint_area] = Layout::vertical([
        Constraint::Length(wrapped_rows(&header, area.width)),
        Constraint::Min(3),
        Constraint::Length(wrapped_rows(&notice, area.width)),
        Constraint::Length(wrapped_rows(&hint, area.width)),
    ])
    .areas(area);
    frame.render_widget(
        Paragraph::new(header)
            .style(palette.bar())
            .wrap(Wrap { trim: false }),
        header_area,
    );
    frame.render_widget(
        Paragraph::new(notice).wrap(Wrap { trim: false }),
        notice_area,
    );
    frame.render_widget(
        Paragraph::new(hint)
            .style(palette.bar())
            .wrap(Wrap { trim: false }),
        hint_area,
    );

    let menu = menu_lines(app, texts);
    let menu_width = menu
        .iter()
        .map(Line::width)
        .max()
        .unwrap_or(0)
        .saturating_add(if options.ascii { 2 } else { 3 });
    let menu_width = u16::try_from(menu_width)
        .unwrap_or(u16::MAX)
        .min((body_area.width / 5).saturating_mul(2))
        .max(12);
    let [menu_area, content_area] =
        Layout::horizontal([Constraint::Length(menu_width), Constraint::Min(10)]).areas(body_area);
    draw_panel(
        frame,
        menu_area,
        texts.get(keys::MENU_TITLE),
        menu,
        app.focus == Focus::Menu,
        0,
        options,
    );

    let panels = content_panels(app, texts);
    let frame_rows: u16 = if options.ascii { 1 } else { 2 };
    let inner_width = content_area
        .width
        .saturating_sub(if options.ascii { 0 } else { 2 });
    let rendered: Vec<Vec<Line<'static>>> = panels
        .iter()
        .map(|p| p.lines.iter().map(|l| to_line(l, options)).collect())
        .collect();
    let constraints: Vec<Constraint> = panels
        .iter()
        .zip(&rendered)
        .map(|(panel, lines)| {
            if panel.feed {
                Constraint::Min(frame_rows + 1)
            } else {
                Constraint::Length(wrapped_rows(lines, inner_width) + frame_rows)
            }
        })
        .collect();
    let areas = Layout::vertical(constraints).split(content_area);
    for ((panel, lines), &panel_area) in panels.into_iter().zip(rendered).zip(areas.iter()) {
        let focused = panel.feed && app.focus == Focus::Feed;
        let scroll = if panel.feed { app.scroll } else { 0 };
        draw_panel(
            frame,
            panel_area,
            panel.title,
            lines,
            focused,
            scroll,
            options,
        );
    }
}

/// A panel: its title as text (marked `>` and inverted when focused), the
/// lines wrapped, never cut. Rounded frame lines only when `--ascii` is off.
fn draw_panel(
    frame: &mut Frame,
    area: Rect,
    title: String,
    lines: Vec<Line<'static>>,
    focused: bool,
    scroll: u16,
    options: RenderOptions,
) {
    let palette = Palette::new(options);
    let title_line = if focused {
        Line::styled(format!("> {title}"), palette.title(true))
    } else {
        Line::styled(title, palette.title(false))
    };
    let body = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .scroll((scroll, 0));
    if options.ascii {
        let [title_area, body_area] =
            Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).areas(area);
        frame.render_widget(Paragraph::new(title_line), title_area);
        frame.render_widget(body, body_area);
    } else {
        let block = Block::bordered()
            .border_type(palette.border_type())
            .border_style(palette.border(focused))
            .title(title_line);
        frame.render_widget(body.block(block), area);
    }
}

#[cfg(test)]
mod tests;
