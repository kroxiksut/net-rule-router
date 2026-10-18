//! The Status screen: the routing state in words, both connections with
//! whether their rules are in force, and the notice feed.

use nrr_client_logic::adapters::{bound_row_index, display_name};
use nrr_client_logic::placeholders::list_summary;
use nrr_client_logic::Route;
use nrr_shared::display_text::display_text;
use nrr_shared::ipc_payloads::{InterfaceRowDto, RouteBindingDto};

use crossterm::event::{KeyCode, KeyEvent};

use super::Screen;
use crate::i18n::{Key, Texts};
use crate::keys;
use crate::link::{admin_command, Link};
use crate::primary_suggestion;
use crate::restore;
use crate::state::{enforcement_text, traffic_carried_text, AppState, NoticeLevel, RoutingState};
use crate::view::{Panel, ScreenView, Segment, StateTone, ViewLine};
use crate::vpn_trust;

pub struct StatusScreen;

impl Screen for StatusScreen {
    fn view(&self, app: &AppState, texts: &Texts) -> ScreenView {
        ScreenView {
            title: texts.get(keys::SCREEN_STATUS),
            panels: vec![
                Panel {
                    title: texts.get(keys::ROUTING_TITLE),
                    lines: routing_lines(app, texts),
                    feed: false,
                },
                Panel {
                    title: texts.get(keys::ROLES_TITLE),
                    lines: role_lines(app, texts),
                    feed: false,
                },
                Panel {
                    title: texts.get(keys::NOTICES_TITLE),
                    lines: notice_lines(app, texts),
                    feed: true,
                },
            ],
        }
    }

    fn help(&self) -> &'static [Key] {
        &[
            keys::HELP_STATUS_FEED,
            restore::HELP,
            vpn_trust::HELP,
            primary_suggestion::HELP,
        ]
    }

    fn plain_help(&self) -> &'static [Key] {
        &[
            restore::PLAIN_HELP,
            vpn_trust::HELP,
            primary_suggestion::HELP,
        ]
    }

    fn on_key(&self, app: &mut AppState, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Char('r') => restore::restore(app),
            KeyCode::Char('t') => vpn_trust::trust_pending(app),
            KeyCode::Char('p') => primary_suggestion::confirm(app),
            _ => false,
        }
    }

    fn on_line(&self, app: &mut AppState, line: &str) -> bool {
        match line {
            "r" => restore::restore(app),
            "t" => vpn_trust::trust_pending(app),
            "p" => primary_suggestion::confirm(app),
            _ => false,
        }
    }
}

/// The words that may carry colour, for the test that holds colour to them.
#[cfg(test)]
pub fn state_word_keys() -> &'static [Key] {
    &[
        keys::LINK_CONNECTED,
        keys::LINK_CONNECTING,
        keys::LINK_OFFLINE,
        keys::LINK_STOPPED,
        keys::LINK_NOT_INSTALLED,
        keys::LINK_MISMATCH,
        keys::LINK_REFUSED,
        keys::ROUTING_ACTIVE,
        keys::ROUTING_LIMITED,
        keys::ROUTING_PAUSED,
        keys::ROUTING_DISCONNECTED,
        keys::NOT_SELECTED,
        keys::AVAILABLE,
        keys::UNAVAILABLE,
        keys::REQUIRES_CHECK,
        keys::ADAPTER_MISSING,
        keys::RULES_APPLIED,
        keys::RULES_NOT_APPLIED,
        keys::LEVEL_WARNING,
    ]
}

/// The connection line every screen carries at the top, and below it what to
/// do about the state, when the user can do anything.
pub fn connection_lines(app: &AppState, texts: &Texts) -> Vec<ViewLine> {
    let (word, tone, banner) = match &app.link {
        Link::Connected => (keys::LINK_CONNECTED, StateTone::Good, None),
        Link::Connecting => (
            keys::LINK_CONNECTING,
            StateTone::Caution,
            Some(keys::BANNER_CONNECTING),
        ),
        Link::Offline => (
            keys::LINK_OFFLINE,
            StateTone::Bad,
            Some(keys::BANNER_OFFLINE),
        ),
        Link::Stopped => (
            keys::LINK_STOPPED,
            StateTone::Bad,
            Some(keys::BANNER_STOPPED),
        ),
        Link::NotInstalled => (
            keys::LINK_NOT_INSTALLED,
            StateTone::Bad,
            Some(keys::BANNER_NOT_INSTALLED),
        ),
        Link::ProtocolMismatch { .. } => (
            keys::LINK_MISMATCH,
            StateTone::Bad,
            Some(keys::BANNER_MISMATCH),
        ),
        Link::Refused { .. } => (
            keys::LINK_REFUSED,
            StateTone::Bad,
            Some(keys::BANNER_REFUSED),
        ),
    };
    let mut first = vec![
        Segment::strong(format!("{}: ", texts.get(keys::SERVICE_LABEL))),
        Segment::state(texts.get(word), tone),
    ];
    if let Some(banner) = banner {
        first.push(Segment::plain(format!(" — {}", texts.get(banner))));
    }
    let mut lines = vec![ViewLine::new(first)];
    match &app.link {
        Link::NotInstalled => {
            lines.push(fix_line(texts, keys::FIX_INSTALL, "install"));
            lines.push(ViewLine::text(texts.get(keys::RETRYING)));
        }
        Link::Stopped => {
            lines.push(fix_line(texts, keys::FIX_START, "start"));
            lines.push(ViewLine::text(texts.get(keys::RETRYING)));
        }
        Link::Offline => lines.push(ViewLine::text(texts.get(keys::RETRYING))),
        Link::ProtocolMismatch { server, client } => lines.push(ViewLine::text(texts.fill(
            keys::VERSIONS,
            &[
                ("server", &server.to_string()),
                ("client", &client.to_string()),
            ],
        ))),
        Link::Refused { reason } if !reason.is_empty() => lines.push(ViewLine::text(
            texts.fill(keys::REFUSED_REASON, &[("reason", reason)]),
        )),
        _ => {}
    }
    lines
}

/// The command stands on its own segment, so it reads and copies whole.
fn fix_line(texts: &Texts, key: Key, verb: &str) -> ViewLine {
    let template = texts.get(key);
    let (before, after) = template
        .split_once("{command}")
        .unwrap_or((template.as_str(), ""));
    ViewLine::new(vec![
        Segment::plain(before),
        Segment::strong(admin_command(verb)),
        Segment::plain(after),
    ])
}

fn routing_lines(app: &AppState, texts: &Texts) -> Vec<ViewLine> {
    let (word, tone, detail) = match app.routing_state() {
        RoutingState::Active => (
            keys::ROUTING_ACTIVE,
            StateTone::Good,
            Some(keys::DETAIL_ACTIVE),
        ),
        RoutingState::Limited => (
            keys::ROUTING_LIMITED,
            StateTone::Caution,
            Some(keys::DETAIL_LIMITED),
        ),
        RoutingState::Paused => (
            keys::ROUTING_PAUSED,
            StateTone::Caution,
            Some(keys::DETAIL_PAUSED),
        ),
        RoutingState::Disconnected => (keys::ROUTING_DISCONNECTED, StateTone::Bad, None),
    };
    let mut lines = vec![ViewLine::new(vec![Segment::state(texts.get(word), tone)])];
    match detail {
        Some(detail) => lines.push(ViewLine::text(texts.get(detail))),
        // Without the service the screen shows what it last knew and says so.
        None if app.snapshot.is_some() => lines.push(ViewLine::text(texts.get(keys::STALE))),
        None => lines.push(ViewLine::text(texts.get(keys::NO_DATA))),
    }
    if let Some(error) = &app.fetch_error {
        lines.push(ViewLine::text(
            texts.fill(keys::FETCH_FAILED, &[("error", error)]),
        ));
    }
    if app.restore.offer.is_some() {
        lines.push(ViewLine::text(texts.get(restore::OFFER_LINE)));
    }
    lines.extend(traffic_carried_lines(app, texts));
    lines.extend(unresolved_app_lines(app, texts));
    lines.extend(pending_vpn_client_lines(app, texts));
    lines
}

/// Another signed-in user's tunnel carrying this user's traffic: standing
/// while it lasts, so it sits with the state as well as in the feed.
fn traffic_carried_lines(app: &AppState, texts: &Texts) -> Vec<ViewLine> {
    let Some(link) = app
        .traffic_carried
        .as_ref()
        .filter(|_| app.link.is_connected())
    else {
        return Vec::new();
    };
    let (title, body) = traffic_carried_text(link, texts);
    vec![
        ViewLine::new(vec![Segment::state(title, StateTone::Caution)]),
        ViewLine::text(body),
    ]
}

/// VPN-named programs leak protection does not trust by place: standing,
/// named, with the key that answers.
fn pending_vpn_client_lines(app: &AppState, texts: &Texts) -> Vec<ViewLine> {
    if !app.link.is_connected() || app.vpn_trust.pending.is_empty() {
        return Vec::new();
    }
    let names = vpn_trust::names(&app.vpn_trust.pending);
    vec![
        ViewLine::new(vec![Segment::state(
            texts.get(keys::VPN_TRUST_TITLE),
            StateTone::Caution,
        )]),
        ViewLine::text(texts.fill(keys::VPN_TRUST_BODY, &[("apps", names.join(", "))])),
        ViewLine::text(texts.get(keys::VPN_TRUST_HINT)),
    ]
}

/// The caller's app rules that found no program: standing while it lasts, so
/// it sits with the state rather than in the feed.
fn unresolved_app_lines(app: &AppState, texts: &Texts) -> Vec<ViewLine> {
    let apps = match &app.snapshot {
        Some(snapshot) if app.link.is_connected() => &snapshot.unenforced_app_rules,
        _ => return Vec::new(),
    };
    if apps.is_empty() {
        return Vec::new();
    }
    let shown: Vec<String> = apps.iter().map(|a| display_text(a).into()).collect();
    let summary = list_summary(&shown, &texts.get(keys::APP_UNRESOLVED_MORE));
    vec![
        ViewLine::new(vec![Segment::state(
            texts.get(keys::APP_UNRESOLVED_TITLE),
            StateTone::Caution,
        )]),
        ViewLine::text(texts.fill(keys::APP_UNRESOLVED_BODY, &[("apps", summary)])),
    ]
}

fn role_lines(app: &AppState, texts: &Texts) -> Vec<ViewLine> {
    let Some(snapshot) = &app.snapshot else {
        return vec![ViewLine::new(vec![Segment::muted(
            texts.get(keys::NO_DATA),
        )])];
    };
    let policy = snapshot.route_policy.as_ref();
    let rows = &snapshot.adapters.rows;
    let mut lines = Vec::new();
    for route in Route::ALL {
        let (label, binding) = match route {
            Route::Primary => (keys::ROLE_PRIMARY, policy.and_then(|p| p.primary.as_ref())),
            Route::Secondary => (
                keys::ROLE_SECONDARY,
                policy.and_then(|p| p.secondary.as_ref()),
            ),
        };
        let mut segments = vec![
            Segment::route(texts.get(label), route),
            Segment::plain(": "),
        ];
        let Some(binding) = binding else {
            segments.push(Segment::state(
                texts.get(keys::NOT_SELECTED),
                StateTone::Caution,
            ));
            lines.push(ViewLine::new(segments));
            continue;
        };
        let row = bound_row(rows, binding);
        segments
            .push(Segment::plain(row.map(display_name).unwrap_or_else(|| {
                display_text(&binding.display_name).into_owned()
            })));
        segments.push(Segment::plain(" — "));
        segments.push(availability(row, texts));
        segments.push(Segment::plain(" — "));
        let down = app.enforcement_down.get(route.as_str());
        segments.push(rules_state(app, down.is_some(), texts));
        lines.push(ViewLine::new(segments));
        if let Some(down) = down.filter(|_| app.link.is_connected()) {
            let (title, _) =
                enforcement_text(&down.status, route.as_str(), &down.candidates, texts);
            lines.push(ViewLine::text(format!("  {title}")));
        }
    }
    // A report about no single role still stops the rules.
    if let Some(down) = app.enforcement_down.get("") {
        let (title, _) = enforcement_text(&down.status, "", &down.candidates, texts);
        lines.push(ViewLine::new(vec![
            Segment::state(texts.get(keys::RULES_NOT_APPLIED), StateTone::Bad),
            Segment::plain(format!(" — {title}")),
        ]));
    }
    lines
}

/// The row the binding names, by its current or an earlier id.
pub(crate) fn bound_row<'a>(
    rows: &'a [InterfaceRowDto],
    binding: &RouteBindingDto,
) -> Option<&'a InterfaceRowDto> {
    bound_row_index(rows, binding).and_then(|i| rows.get(i))
}

fn availability(row: Option<&InterfaceRowDto>, texts: &Texts) -> Segment {
    match row.map(|r| r.availability.as_str()) {
        None => Segment::state(texts.get(keys::ADAPTER_MISSING), StateTone::Bad),
        Some("available") => Segment::state(texts.get(keys::AVAILABLE), StateTone::Good),
        Some("unavailable") => Segment::state(texts.get(keys::UNAVAILABLE), StateTone::Bad),
        Some(_) => Segment::state(texts.get(keys::REQUIRES_CHECK), StateTone::Caution),
    }
}

fn rules_state(app: &AppState, reported_down: bool, texts: &Texts) -> Segment {
    if !app.link.is_connected() {
        return Segment::plain(texts.get(keys::RULES_UNKNOWN));
    }
    if reported_down {
        Segment::state(texts.get(keys::RULES_NOT_APPLIED), StateTone::Bad)
    } else if app.routing_state() == RoutingState::Paused {
        Segment::state(texts.get(keys::RULES_NOT_APPLIED), StateTone::Caution)
    } else {
        Segment::state(texts.get(keys::RULES_APPLIED), StateTone::Good)
    }
}

/// Newest first, so the latest is on screen without scrolling. Notices stay
/// until the program ends: nothing here disappears on a timer.
fn notice_lines(app: &AppState, texts: &Texts) -> Vec<ViewLine> {
    if app.notices.is_empty() {
        return vec![ViewLine::new(vec![Segment::muted(
            texts.get(keys::NOTICES_EMPTY),
        )])];
    }
    let mut lines = Vec::new();
    for notice in app.notices.iter().rev() {
        let level = match notice.level {
            NoticeLevel::Warning => {
                Segment::state(texts.get(keys::LEVEL_WARNING), StateTone::Caution)
            }
            NoticeLevel::Info => Segment::strong(texts.get(keys::LEVEL_INFO)),
        };
        lines.push(ViewLine::new(vec![
            level,
            Segment::plain(": "),
            Segment::strong(notice.title.clone()),
        ]));
        lines.push(ViewLine::text(notice.body.clone()));
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{app_at, texts_en, Fixture};

    fn shown(app: &AppState) -> Vec<String> {
        routing_lines(app, &texts_en())
            .iter()
            .map(|line| line.segments.iter().map(|s| s.text.as_str()).collect())
            .collect()
    }

    /// App rules with no program behind them stand under the routing state,
    /// named, the fourth and later counted; nothing while none or offline.
    #[test]
    fn app_rules_that_found_no_program_are_named_under_the_state() {
        let mut app = app_at(Link::Connected, Some(&Fixture::healthy()));
        assert!(!shown(&app).iter().any(|l| l.contains("weren't found")));
        if let Some(snapshot) = app.snapshot.as_mut() {
            snapshot.unenforced_app_rules = ["a.exe", "b.exe", "c.exe", "d.exe"]
                .map(String::from)
                .to_vec();
        }
        let lines = shown(&app);
        assert!(lines
            .iter()
            .any(|l| l == "App rules applied, but some apps weren't found"));
        assert!(
            lines
                .iter()
                .any(|l| l.contains(": a.exe, b.exe, c.exe +1 more.")),
            "{lines:?}"
        );
        app.link = Link::Offline;
        assert!(!shown(&app).iter().any(|l| l.contains("weren't found")));
    }

    /// A VPN-named program the service does not trust by place stands under
    /// the state with the key that confirms it; `t` writes the confirmation
    /// once, and nothing while offline.
    #[test]
    fn a_pending_vpn_client_is_named_with_its_key_and_t_confirms_it() {
        use nrr_shared::ipc_payloads::PendingVpnClientDto;
        let mut app = app_at(Link::Connected, Some(&Fixture::healthy()));
        assert!(!shown(&app).iter().any(|l| l.contains("Is this your VPN?")));
        app.vpn_trust.pending = vec![PendingVpnClientDto {
            exe_path: r"C:\Users\someone\Downloads\x-vpn.exe".into(),
            bundled_exe_paths: Vec::new(),
        }];
        let lines = shown(&app);
        assert!(lines.iter().any(|l| l == "Is this your VPN?"), "{lines:?}");
        assert!(
            lines.iter().any(|l| l.starts_with("x-vpn.exe: ")),
            "{lines:?}"
        );
        assert!(lines.iter().any(|l| l.starts_with("t: ")), "{lines:?}");

        assert!(
            vpn_trust::trust_pending(&mut app),
            "t sends the confirmation"
        );
        assert!(app.vpn_trust.busy);
        assert!(
            !vpn_trust::trust_pending(&mut app),
            "a second press while the write is in flight does nothing"
        );
        assert_eq!(app.outbox.take().len(), 1);

        app.link = Link::Offline;
        assert!(!shown(&app).iter().any(|l| l.contains("Is this your VPN?")));
    }

    /// Another user's tunnel carrying this user's traffic stands under the
    /// state, naming the connection; nothing while it does not, or offline.
    #[test]
    fn traffic_carried_by_another_users_tunnel_stands_under_the_state() {
        let mut app = app_at(Link::Connected, Some(&Fixture::healthy()));
        let title = "Your traffic goes through another user's tunnel";
        assert!(!shown(&app).iter().any(|l| l == title));

        app.traffic_carried = Some("Office\u{202E}Tunnel".into());
        let lines = shown(&app);
        assert!(lines.iter().any(|l| l == title), "{lines:?}");
        assert!(
            lines
                .iter()
                .any(|l| l.contains("through the tunnel \"Office\u{b7}Tunnel\".")),
            "the name is shown through display_text: {lines:?}"
        );

        app.traffic_carried = Some(String::new());
        assert!(
            shown(&app)
                .iter()
                .any(|l| l.contains("through their tunnel.")),
            "no name: the wording that does without one"
        );

        app.link = Link::Offline;
        assert!(!shown(&app).iter().any(|l| l == title));
    }
}
