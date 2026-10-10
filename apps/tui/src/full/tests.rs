#![allow(clippy::expect_used)]

use std::time::Instant;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::backend::TestBackend;
use ratatui::style::Color;
use ratatui::text::Line;
use ratatui::Terminal;

use super::*;
use crate::link::{admin_command, Link};
use crate::screens::state_word_keys;
use crate::testing::{app_at, assert_snapshot, enforcement, texts_en, Bound, Fixture};

const COLOUR: RenderOptions = RenderOptions {
    colour: true,
    ascii: false,
};

fn render(app: &AppState, options: RenderOptions, width: u16, height: u16, now: Instant) -> String {
    let texts = texts_en();
    let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("test terminal");
    terminal
        .draw(|frame| draw(frame, app, &texts, options, now))
        .expect("draw");
    let buffer = terminal.backend().buffer();
    let mut out = String::new();
    for y in 0..height {
        let row: String = (0..width).map(|x| buffer[(x, y)].symbol()).collect();
        out.push_str(row.trim_end());
        out.push('\n');
    }
    out
}

fn limited() -> AppState {
    let mut app = app_at(Link::Connected, Some(&Fixture::healthy()));
    let texts = texts_en();
    app.apply(
        enforcement("secondary-down", "secondary"),
        &texts,
        Instant::now(),
    );
    app
}

/// Every state the status screen has words for, for the checks that walk them.
fn every_state() -> Vec<(&'static str, AppState)> {
    let gone = Fixture {
        secondary: Some(Bound {
            id: "{00000000-0000-0000-0000-000000000009}",
            name: "Removed Tunnel",
            availability: None,
        }),
        ..Fixture::healthy()
    };
    let down = Fixture {
        secondary: Some(Bound {
            id: "{00000000-0000-0000-0000-000000000002}",
            name: "Example Tunnel",
            availability: Some("unavailable"),
        }),
        ..Fixture::healthy()
    };
    let unbound = Fixture {
        secondary: None,
        ..Fixture::healthy()
    };
    let paused = Fixture {
        paused: true,
        ..Fixture::healthy()
    };
    vec![
        ("active", app_at(Link::Connected, Some(&Fixture::healthy()))),
        ("limited", limited()),
        ("paused", app_at(Link::Connected, Some(&paused))),
        ("gone", app_at(Link::Connected, Some(&gone))),
        ("down", app_at(Link::Connected, Some(&down))),
        ("unbound", app_at(Link::Connected, Some(&unbound))),
        ("connecting", app_at(Link::Connecting, None)),
        ("stale", app_at(Link::Offline, Some(&Fixture::healthy()))),
        ("stopped", app_at(Link::Stopped, None)),
        ("not-installed", app_at(Link::NotInstalled, None)),
        (
            "mismatch",
            app_at(
                Link::ProtocolMismatch {
                    server: 3,
                    client: 2,
                },
                None,
            ),
        ),
        (
            "refused",
            app_at(
                Link::Refused {
                    reason: "no free connection slot".into(),
                },
                None,
            ),
        ),
    ]
}

#[test]
fn status_screen_snapshot_healthy() {
    let app = app_at(Link::Connected, Some(&Fixture::healthy()));
    // Words are checked where no line wraps; the snapshot pins the 80x24 layout.
    let wide = render(&app, COLOUR, 140, 30, Instant::now());
    assert!(wide.contains("> 1 Status"), "{wide}");
    assert!(wide.contains("Routing active"), "{wide}");
    assert!(wide.contains("Available — Rules applied"), "{wide}");
    assert_snapshot(
        "status-healthy-80x24",
        &render(&app, COLOUR, 80, 24, Instant::now()),
    );
}

#[test]
fn status_screen_snapshot_limited_with_notice() {
    let app = limited();
    let wide = render(&app, COLOUR, 140, 30, Instant::now());
    assert!(wide.contains("Routing limited"), "{wide}");
    assert!(wide.contains("Rules not applied"), "{wide}");
    assert!(
        wide.contains("The additional connection is not up"),
        "{wide}"
    );
    assert_snapshot(
        "status-limited-80x24",
        &render(&app, COLOUR, 80, 24, Instant::now()),
    );
}

#[test]
fn status_screen_snapshot_without_service_ascii() {
    let app = app_at(Link::Offline, Some(&Fixture::healthy()));
    let options = RenderOptions {
        colour: false,
        ascii: true,
    };
    let picture = render(&app, options, 80, 24, Instant::now());
    assert!(picture.contains("Service not connected"), "{picture}");
    assert!(picture.contains("Status data may be outdated"), "{picture}");
    assert!(
        !picture
            .chars()
            .any(|c| ('\u{2500}'..='\u{257f}').contains(&c)),
        "--ascii must draw no frame lines:\n{picture}"
    );
    assert_snapshot("status-offline-ascii-80x24", &picture);
}

#[test]
fn the_fix_command_is_on_screen_and_fits_80_columns() {
    for (link, verb) in [(Link::NotInstalled, "install"), (Link::Stopped, "start")] {
        let picture = render(&app_at(link, None), COLOUR, 80, 24, Instant::now());
        let command = admin_command(verb);
        assert!(picture.contains(&command), "{command} missing:\n{picture}");
    }
}

#[test]
fn a_new_notice_shows_in_the_bottom_line_then_only_in_the_feed() {
    let app = limited();
    let at = app.last_notice_at.expect("a notice arrived");
    let texts = texts_en();
    let soon = footer_lines(&app, &texts, COLOUR, at);
    assert_eq!(soon.len(), 2);
    let later = footer_lines(&app, &texts, COLOUR, at + Duration::from_secs(11));
    assert_eq!(later.len(), 1, "the key hint stays");
    let picture = render(&app, COLOUR, 80, 40, at + Duration::from_secs(11));
    assert!(
        picture.contains("The additional connection is not up"),
        "{picture}"
    );
}

fn line_text(line: &Line<'_>) -> String {
    line.spans.iter().map(|s| s.content.as_ref()).collect()
}

fn coloured(span: &ratatui::text::Span<'_>) -> bool {
    let set = |c: Option<Color>| c.is_some_and(|c| c != Color::Reset);
    set(span.style.fg) || set(span.style.bg)
}

/// Meaning is never in colour alone: a coloured span sits on a line that says the
/// state in words, and is itself that word. Returns the offending lines.
fn colour_without_words(lines: &[Line<'_>], words: &[String]) -> Vec<String> {
    lines
        .iter()
        .filter(|line| {
            let text = line_text(line);
            line.spans.iter().filter(|s| coloured(s)).any(|s| {
                let span = s.content.trim();
                !words.iter().any(|w| text.contains(w.as_str())) || !words.iter().any(|w| w == span)
            })
        })
        .map(line_text)
        .collect()
}

fn all_lines(app: &AppState, texts: &Texts, options: RenderOptions) -> Vec<Line<'static>> {
    let mut lines = header_lines(app, texts, options);
    lines.extend(menu_lines(app, texts));
    for panel in content_panels(app, texts) {
        lines.extend(panel.lines.iter().map(|l| to_line(l, options)));
    }
    lines.extend(footer_lines(app, texts, options, Instant::now()));
    lines
}

#[test]
fn colour_never_carries_meaning_alone() {
    let texts = texts_en();
    let words: Vec<String> = state_word_keys().iter().map(|k| texts.get(*k)).collect();
    let mut checked = 0;
    for (name, mut app) in every_state() {
        app.apply(
            enforcement("adapter-gone", "primary"),
            &texts,
            Instant::now(),
        );
        let lines = all_lines(&app, &texts, COLOUR);
        checked += lines
            .iter()
            .flat_map(|l| &l.spans)
            .filter(|s| coloured(s))
            .count();
        let bad = colour_without_words(&lines, &words);
        assert!(
            bad.is_empty(),
            "state {name}: colour without a state word in {bad:?}"
        );
    }
    assert!(
        checked > 0,
        "no coloured span was seen: the walk proves nothing"
    );
}

#[test]
fn the_colour_check_can_fire() {
    let words = vec!["Available".to_string()];
    let red = Style::default().fg(Color::Red);
    let wordless = Line::from(vec![Span::raw("Main: "), Span::styled("Ethernet", red)]);
    assert_eq!(colour_without_words(&[wordless], &words).len(), 1);
    let worded = Line::from(vec![Span::raw("Main: "), Span::styled("Available", red)]);
    assert!(colour_without_words(&[worded], &words).is_empty());
}

#[test]
fn no_color_draws_no_colour() {
    let texts = texts_en();
    let options = RenderOptions {
        colour: false,
        ascii: false,
    };
    for (name, app) in every_state() {
        let lines = all_lines(&app, &texts, options);
        assert!(
            !lines.iter().flat_map(|l| &l.spans).any(coloured),
            "state {name} drew colour with --no-color"
        );
    }
}

fn press(app: &mut AppState, code: KeyCode) {
    handle_key(app, KeyEvent::new(code, KeyModifiers::NONE), &texts_en());
}

#[test]
fn keys_move_between_screens_focus_and_help() {
    let mut app = app_at(Link::Connected, Some(&Fixture::healthy()));
    press(&mut app, KeyCode::Char('4'));
    assert_eq!(app.screen, ScreenId::Rules);
    press(&mut app, KeyCode::Char('0'));
    assert_eq!(app.screen, ScreenId::Settings);
    // Settings opens into its sections, as the trace does into its sub-screen.
    for _ in crate::screens::settings::Category::ALL {
        press(&mut app, KeyCode::Down);
        assert_eq!(app.screen, ScreenId::Settings);
    }
    press(&mut app, KeyCode::Down);
    assert_eq!(app.screen, ScreenId::Status);

    press(&mut app, KeyCode::Tab);
    assert_eq!(app.focus, Focus::Feed, "Status has a feed to focus");
    press(&mut app, KeyCode::Esc);
    assert_eq!(app.focus, Focus::Menu);

    press(&mut app, KeyCode::F(1));
    assert!(app.help_open);
    let texts = texts_en();
    let help = content_panels(&app, &texts);
    assert!(help[0].lines.iter().any(|l| l.plain_text().contains("F1")));
    press(&mut app, KeyCode::Esc);
    assert!(!app.help_open);

    press(&mut app, KeyCode::Char('q'));
    assert!(app.quit);
}

#[test]
fn zero_opens_the_settings_sections() {
    let mut app = app_at(Link::Connected, Some(&Fixture::healthy()));
    press(&mut app, KeyCode::Char('0'));
    let picture = render(&app, COLOUR, 80, 24, Instant::now());
    assert!(picture.contains("> 0 Settings"), "{picture}");
    assert!(picture.contains("Settings sections"), "{picture}");
    assert!(picture.contains("      Notifications"), "{picture}");
}

#[test]
fn the_settings_sections_open_from_the_menu() {
    let texts = texts_en();
    let mut app = app_at(Link::Connected, Some(&Fixture::healthy()));
    let menu =
        |app: &AppState| -> Vec<String> { menu_lines(app, &texts).iter().map(line_text).collect() };
    assert!(
        !menu(&app).iter().any(|l| l.contains("Notifications")),
        "folded while Settings is closed"
    );

    press(&mut app, KeyCode::Char('0'));
    press(&mut app, KeyCode::Down);
    press(&mut app, KeyCode::Down);
    assert_eq!(app.screen, ScreenId::Settings);
    assert_eq!(
        app.settings.open,
        Some(crate::screens::settings::Category::Routing)
    );
    let shown = menu(&app);
    assert!(shown.contains(&"  0 Settings".to_owned()), "{shown:?}");
    assert!(
        shown.contains(&">     Routing behavior".to_owned()),
        "{shown:?}"
    );
    let panels = content_panels(&app, &texts);
    assert_eq!(
        panels.last().map(|p| p.title.as_str()),
        Some("Routing behavior")
    );

    press(&mut app, KeyCode::Up);
    press(&mut app, KeyCode::Up);
    assert_eq!(app.settings.open, None, "back on the list of sections");
    assert!(menu(&app).contains(&"> 0 Settings".to_owned()));
}
