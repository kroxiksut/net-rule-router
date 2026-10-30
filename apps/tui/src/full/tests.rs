#![allow(clippy::expect_used)]

use std::time::Instant;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::backend::TestBackend;
use ratatui::buffer::Buffer;
use ratatui::style::{Color, Modifier};
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

fn draw_buffer(
    app: &AppState,
    options: RenderOptions,
    width: u16,
    height: u16,
    now: Instant,
) -> Buffer {
    let texts = texts_en();
    let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("test terminal");
    terminal
        .draw(|frame| draw(frame, app, &texts, options, now))
        .expect("draw");
    terminal.backend().buffer().clone()
}

fn render(app: &AppState, options: RenderOptions, width: u16, height: u16, now: Instant) -> String {
    let buffer = draw_buffer(app, options, width, height, now);
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
    assert!(wide.contains("Rules are working"), "{wide}");
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
    assert!(wide.contains("Some rules not working"), "{wide}");
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

/// A foreign name reaches the frame through a notice; whatever the screen
/// model let through, the buffer holds nothing that executes or reorders.
#[test]
fn a_foreign_name_leaves_no_dangerous_character_in_the_frame() {
    let mut app = limited();
    let at = Instant::now();
    app.notices.push(crate::state::Notice::new(
        NoticeLevel::Warning,
        "gnp\u{202E}.exe \u{1b}]0;x\u{7}".into(),
        String::new(),
    ));
    app.last_notice_at = Some(at);
    let buffer = draw_buffer(&app, COLOUR, 80, 40, at);
    let mut shown = String::new();
    for y in 0..40 {
        for x in 0..80 {
            shown.push_str(buffer[(x, y)].symbol());
        }
    }
    assert!(shown.contains("gnp\u{b7}.exe"), "{shown}");
    assert!(!shown
        .chars()
        .any(nrr_shared::display_text::needs_substitute));
}

fn line_text(line: &Line<'_>) -> String {
    line.spans.iter().map(|s| s.content.as_ref()).collect()
}

fn coloured(span: &ratatui::text::Span<'_>) -> bool {
    let set = |c: Option<Color>| c.is_some_and(|c| c != Color::Reset);
    set(span.style.fg) || set(span.style.bg)
}

/// Whether a span is drawn in a colour that says something: a state's, as
/// text or as a badge on a bar, or a route's. Other colours (bars, headings,
/// the selection) only set text apart, and each keeps a mark of its own.
fn meaningful(span: &ratatui::text::Span<'_>) -> bool {
    let palette = Palette::new(COLOUR);
    let states = [Tone::Good, Tone::Caution, Tone::Bad];
    let routes = [Tone::RoutePrimary, Tone::RouteSecondary];
    let text: Vec<Color> = states
        .iter()
        .chain(&routes)
        .filter_map(|t| palette.tone(*t).fg)
        .collect();
    let badge: Vec<Color> = states
        .iter()
        .filter_map(|t| palette.on_bar(*t).bg)
        .collect();
    span.style.fg.is_some_and(|c| text.contains(&c))
        || span.style.bg.is_some_and(|c| badge.contains(&c))
}

/// Meaning is never in colour alone: a span in a meaning colour sits on a line
/// that says it in words, and is itself that word. Returns the offending lines.
fn colour_without_words(lines: &[Line<'_>], words: &[String]) -> Vec<String> {
    lines
        .iter()
        .filter(|line| {
            let text = line_text(line);
            line.spans.iter().filter(|s| meaningful(s)).any(|s| {
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
    let words: Vec<String> = state_word_keys()
        .iter()
        .chain(&[keys::ROLE_PRIMARY, keys::ROLE_SECONDARY])
        .map(|k| texts.get(*k))
        .collect();
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
            .filter(|s| meaningful(s))
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
    let route = style_for(Tone::RoutePrimary, COLOUR);
    let routed = Line::from(vec![Span::raw("Main: "), Span::styled("Ethernet", route)]);
    assert_eq!(colour_without_words(&[routed], &words).len(), 1);
    let badge = Palette::new(COLOUR).on_bar(Tone::Bad);
    let badged = Line::from(vec![Span::styled("Ethernet", badge)]);
    assert_eq!(colour_without_words(&[badged], &words).len(), 1);
}

/// Screens with every kind of marking: state words, the bars, routes, the
/// selection and a focused panel.
fn representative() -> Vec<(&'static str, AppState)> {
    let mut screens = every_state();
    let mut interfaces = app_at(Link::Connected, Some(&Fixture::healthy()));
    interfaces.open(ScreenId::Interfaces);
    screens.push(("interfaces", interfaces));
    let mut focused = limited();
    press(&mut focused, KeyCode::Tab);
    screens.push(("feed-focused", focused));
    let mut settings = app_at(Link::Connected, Some(&Fixture::healthy()));
    press(&mut settings, KeyCode::Char('0'));
    press(&mut settings, KeyCode::Down);
    screens.push(("settings", settings));
    screens
}

#[test]
fn no_color_leaves_no_colour_in_any_cell() {
    let options = RenderOptions {
        colour: false,
        ascii: false,
    };
    for (name, app) in representative() {
        let buffer = draw_buffer(&app, options, 100, 40, Instant::now());
        for cell in buffer.content() {
            assert!(
                cell.fg == Color::Reset && cell.bg == Color::Reset,
                "{name}: {:?} drew colour with --no-color: {:?}",
                cell.symbol(),
                cell.style()
            );
        }
    }
}

#[test]
fn with_colour_the_bars_routes_and_rounded_frames_are_drawn() {
    let app = app_at(Link::Connected, Some(&Fixture::healthy()));
    let palette = Palette::new(COLOUR);
    let bar = palette.bar().bg.expect("the bars have a background");
    let buffer = draw_buffer(&app, COLOUR, 100, 40, Instant::now());
    assert_eq!(buffer[(99_u16, 0_u16)].bg, bar, "title bar");
    assert_eq!(buffer[(99_u16, 39_u16)].bg, bar, "status bar");
    let primary = palette.tone(Tone::RoutePrimary).fg;
    assert!(
        buffer
            .content()
            .iter()
            .any(|c| Some(c.fg) == primary && c.symbol().chars().any(char::is_alphabetic)),
        "the main route's name is marked"
    );
    let picture = render(&app, COLOUR, 100, 40, Instant::now());
    assert!(picture.contains('\u{256d}'), "rounded corners:\n{picture}");
}

/// The cursor row stays findable without colour: its `>` and its bold.
#[test]
fn the_selected_row_keeps_its_marker_and_bold_without_colour() {
    let mut app = app_at(Link::Connected, Some(&Fixture::healthy()));
    app.open(ScreenId::Interfaces);
    let options = RenderOptions {
        colour: false,
        ascii: false,
    };
    let texts = texts_en();
    let selected: Vec<Line<'static>> = content_panels(&app, &texts)
        .iter()
        .flat_map(|p| p.lines.iter().map(|l| to_line(l, options)))
        .filter(|l| line_text(l).trim_start().starts_with("> "))
        .collect();
    assert_eq!(selected.len(), 1, "one cursor row");
    let style = selected[0].spans[0].style;
    assert!(style.add_modifier.contains(Modifier::BOLD), "{style:?}");
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

#[test]
fn ctrl_c_asks_before_dropping_unapplied_edits() {
    use nrr_client_logic::rules_table::{RuleRow, RuleType, TargetRoute};
    let texts = texts_en();
    let mut app = app_at(Link::Connected, Some(&Fixture::healthy()));
    app.rules.table.import(
        vec![RuleRow {
            id: String::new(),
            enabled: true,
            rule_type: RuleType::Domain,
            match_value: "example.org".into(),
            target_route: TargetRoute::Secondary,
            verify: false,
            comment: String::new(),
            origin: None,
        }],
        true,
    );
    let ctrl_c = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
    handle_key(&mut app, ctrl_c, &texts);
    assert!(!app.quit, "the first Ctrl+C asks");
    assert!(crate::screens::rules::quit_question_open(&app));
    handle_key(&mut app, ctrl_c, &texts);
    assert!(app.quit, "a second one leaves");
}

#[test]
fn panels_that_do_not_fit_give_up_rows_from_the_tallest_down() {
    assert_eq!(
        fit_heights(&[5, 6], 20, 3),
        vec![5, 6],
        "room enough: as asked"
    );
    assert_eq!(fit_heights(&[8, 6, 4], 15, 3), vec![6, 5, 4]);
    assert_eq!(
        fit_heights(&[8, 8], 4, 3),
        vec![3, 3],
        "none goes below a title and a row"
    );
}
