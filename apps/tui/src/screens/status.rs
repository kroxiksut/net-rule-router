//! The Status screen: the routing state in words, both connections with
//! whether their rules are in force, and the notice feed.

use nrr_client_logic::adapters::{bound_row_index, display_name};
use nrr_client_logic::placeholders::list_summary;
use nrr_client_logic::Route;
use nrr_shared::display_text::display_text;
use nrr_shared::ipc::ContractSkew;
use nrr_shared::ipc_payloads::{
    BehaviorModeDto, InterfaceRowDto, LeakProtectionDto, RouteBindingDto, SnapshotInitialResponse,
};
use nrr_shared::platform_profile::PlatformProfile;

use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEvent};

use super::{overlaps, Screen};
use crate::block_route;
use crate::i18n::{Key, Texts};
use crate::keys;
use crate::link::{admin_command, Link};
use crate::primary_suggestion;
use crate::restore;
use crate::state::{enforcement_text, traffic_carried_text, AppState, NoticeLevel, RoutingState};
use crate::view::{Panel, ScreenView, Segment, StateTone, ViewLine};
use crate::vpn_gateway_trust;
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
            vpn_gateway_trust::HELP,
            primary_suggestion::HELP,
            block_route::HELP,
        ]
    }

    fn plain_help(&self) -> &'static [Key] {
        &[
            restore::PLAIN_HELP,
            vpn_trust::HELP,
            vpn_gateway_trust::HELP,
            primary_suggestion::HELP,
            block_route::HELP,
        ]
    }

    /// The "To additional route" question takes y, n and Esc first.
    fn captures_keys(&self, app: &AppState) -> bool {
        block_route::asking(app)
    }

    fn on_key(&self, app: &mut AppState, key: KeyEvent) -> bool {
        if block_route::asking(app) {
            return match key.code {
                KeyCode::Char('y') => block_route::answer(app, true),
                KeyCode::Char('n') | KeyCode::Esc => block_route::answer(app, false),
                _ => false,
            };
        }
        match key.code {
            KeyCode::Char('r') => restore::restore(app),
            KeyCode::Char('t') => vpn_trust::trust_first(app, false),
            KeyCode::Char('T') => vpn_trust::trust_first(app, true),
            KeyCode::Char('a') => vpn_gateway_trust::allow_first(app),
            KeyCode::Char('p') => primary_suggestion::confirm(app),
            KeyCode::Char('v') => block_route::ask(app),
            _ => false,
        }
    }

    fn on_line(&self, app: &mut AppState, line: &str) -> bool {
        if block_route::asking(app) {
            return match line {
                "y" => block_route::answer(app, true),
                "n" => block_route::answer(app, false),
                _ => false,
            };
        }
        match line {
            "r" => restore::restore(app),
            "t" => vpn_trust::trust_first(app, false),
            "T" => vpn_trust::trust_first(app, true),
            "a" => vpn_gateway_trust::allow_first(app),
            "p" => primary_suggestion::confirm(app),
            "v" => block_route::ask(app),
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
            Some(if app.service_loss_raised {
                keys::BANNER_LOST
            } else {
                keys::BANNER_STOPPED
            }),
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
    if app.link.is_connected() && app.rules_need_a_sign_in {
        lines.push(ViewLine::text(texts.get(keys::SSH_ONLY_SESSION)));
    }
    if let (Link::Connected, Some(skew)) = (&app.link, app.contract_skew) {
        let text = match skew {
            ContractSkew::ServiceOlder => keys::CONTRACT_SERVICE_OLDER,
            ContractSkew::ClientOlder => keys::CONTRACT_CLIENT_OLDER,
        };
        lines.push(ViewLine::new(vec![Segment::state(
            texts.get(text),
            StateTone::Bad,
        )]));
    }
    match &app.link {
        Link::NotInstalled => {
            lines.push(fix_line(texts, keys::FIX_INSTALL, "install"));
            lines.push(ViewLine::text(texts.get(keys::RETRYING)));
        }
        Link::Stopped => {
            lines.push(fix_line(texts, keys::FIX_START, "start"));
            if app.service_loss_raised && PlatformProfile::current().supports.kill_switch {
                lines.push(fix_line(
                    texts,
                    keys::FIX_RESTORE_NETWORK,
                    "reset-network --confirm",
                ));
            }
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

/// The sentences naming the commands that start the service and, where there is
/// something to undo, restore the network.
pub fn recovery_hints(texts: &Texts, can_restore: bool) -> Vec<String> {
    let mut hints = vec![texts.fill(keys::FIX_START, &[("command", &admin_command("start"))])];
    if can_restore {
        hints.push(texts.fill(
            keys::FIX_RESTORE_NETWORK,
            &[("command", &admin_command("reset-network --confirm"))],
        ));
    }
    hints
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

/// "12 min left" / "until restart" for a timed pause; `None` for one that
/// lasts until the user resumes.
fn pause_left(app: &AppState, texts: &Texts) -> Option<String> {
    let snapshot = app.snapshot.as_ref()?;
    if snapshot.routing_pause_until_restart {
        return Some(texts.dynamic("routing.pause.until-restart", "until restart"));
    }
    snapshot
        .routing_pause_resumes_at_ms
        .map(|at| crate::screens::rules::overrides::left_text(Some(at), texts))
}

fn routing_lines(app: &AppState, texts: &Texts) -> Vec<ViewLine> {
    let state = app.routing_state();
    let (word, tone, detail) = match state {
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
    let mut first = vec![Segment::state(texts.get(word), tone)];
    if state == RoutingState::Paused {
        if let Some(left) = pause_left(app, texts) {
            first.push(Segment::plain(format!(" · {left}")));
        }
    }
    let mut lines = vec![ViewLine::new(first)];
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
    // Not dismissible here: the terminal keeps no acknowledgement to hide it by.
    if app.link.is_connected()
        && app
            .snapshot
            .as_ref()
            .is_some_and(|s| s.kill_switch_holding_for_outage)
    {
        lines.push(ViewLine::new(vec![Segment::state(
            texts.get(keys::BLOCK_ALL_ARMED),
            StateTone::Bad,
        )]));
    }
    if let Some(snapshot) = app
        .snapshot
        .as_ref()
        .filter(|s| app.link.is_connected() && s.protection_filters_high)
    {
        lines.push(ViewLine::new(vec![Segment::state(
            texts.get(keys::PROTECTION_VOLUME_HIGH).replace(
                "{count}",
                &snapshot.protection_filters_on_machine.to_string(),
            ),
            StateTone::Caution,
        )]));
    }
    if let Some(line) = silence_line(app, texts) {
        lines.push(line);
    }
    if app
        .snapshot
        .as_ref()
        .filter(|_| app.link.is_connected())
        .is_some_and(revision_rejected)
    {
        lines.push(ViewLine::new(vec![
            Segment::state(texts.get(keys::REVISION_INTEGRITY), StateTone::Bad),
            Segment::plain(format!(" {}", texts.get(keys::SEE_DIAGNOSTICS_HINT))),
        ]));
    }
    if app.settings_unreadable {
        lines.push(ViewLine::new(vec![
            Segment::state(
                texts.get(keys::SETTINGS_UNREADABLE_TITLE),
                StateTone::Caution,
            ),
            Segment::plain(format!(" {}", texts.get(keys::SETTINGS_UNREADABLE_BODY))),
        ]));
    }
    if let Some(line) = delivery_line(app, texts) {
        lines.push(line);
    }
    lines.extend(traffic_carried_lines(app, texts));
    lines.extend(unresolved_app_lines(app, texts));
    lines.extend(pending_vpn_client_lines(app, texts));
    lines.extend(pending_vpn_gateway_lines(app, texts));
    lines.extend(block_route_lines(app, texts));
    lines
}

/// A rule set changed outside the app was refused and the alert is still
/// open: the service runs on the last verified one.
pub(crate) fn revision_rejected(snapshot: &SnapshotInitialResponse) -> bool {
    snapshot
        .diagnostics
        .active_alerts
        .iter()
        .any(|alert| alert.state == "active" && alert.kind == "untrusted_revision_rejected")
}

/// A VPN-like additional adapter is up while only the rules go through it:
/// its name and the rule count. Users read "VPN on, address unchanged" as
/// broken, so the window explains selective routing; so does this.
pub(crate) fn vpn_split(snapshot: &SnapshotInitialResponse) -> Option<(String, usize)> {
    let policy = snapshot.route_policy.as_ref()?;
    if policy.mode != BehaviorModeDto::PreferPrimary {
        return None;
    }
    let row = bound_row(&snapshot.adapters.rows, policy.secondary.as_ref()?)?;
    let vpn_like = matches!(
        row.derived_assessment.vpn_tunnel_likelihood.as_str(),
        "likely" | "possible"
    );
    let count = usize::try_from(snapshot.active_secondary_rule_count?).ok()?;
    (row.availability == "available" && vpn_like && count > 0).then(|| (display_name(row), count))
}

/// How long a service may hold rules and apply none before the line says so:
/// the window's settle (three 15 s watch ticks), longer than one reconcile
/// tick plus the binding re-push after a connect, so a service still coming
/// up stays quiet.
pub(crate) const POLICY_IDLE_SETTLE: Duration = Duration::from_secs(45);

/// The service holds rules but applies none, and no other line owns the
/// cause: not paused, not blocking everything, no additional adapter bound
/// (its own row tells its state).
fn policy_idle(snapshot: &SnapshotInitialResponse) -> bool {
    snapshot.active_rule_count.is_some_and(|count| count > 0)
        && !snapshot.routing_paused
        && !snapshot.kill_switch_block_all_armed
        && snapshot
            .route_policy
            .as_ref()
            .is_none_or(|p| p.secondary.is_none())
}

/// Each snapshot read: when the idle state began, or none once it ended.
pub(crate) fn track_policy_idle(app: &mut AppState, now: Instant) {
    let idle = app.link.is_connected() && app.snapshot.as_ref().is_some_and(policy_idle);
    app.policy_idle_since = match app.policy_idle_since {
        _ if !idle => None,
        Some(since) => Some(since),
        None => Some(now),
    };
}

/// A connected service that routes nothing looks healthy from outside; the
/// window's empty-rules and policy-inactive banners say so, and so does this,
/// the latter only once the state has held for [`POLICY_IDLE_SETTLE`].
/// Each stands down where another line already owns the cause.
fn silence_line(app: &AppState, texts: &Texts) -> Option<ViewLine> {
    let snapshot = app.snapshot.as_ref().filter(|_| app.link.is_connected())?;
    let count = snapshot.active_rule_count?;
    let key = if count == 0 {
        keys::RULES_EMPTY
    } else {
        let settled = app
            .policy_idle_since
            .is_some_and(|since| since.elapsed() >= POLICY_IDLE_SETTLE);
        if !policy_idle(snapshot) || !settled {
            return None;
        }
        let policy = snapshot.route_policy.as_ref();
        let protected = policy.is_some_and(|p| p.leak_protection != LeakProtectionDto::Off);
        if protected {
            keys::POLICY_INACTIVE_BLOCKING
        } else {
            keys::POLICY_INACTIVE_NO_ADAPTER
        }
    };
    Some(ViewLine::new(vec![Segment::state(
        texts.get(key),
        StateTone::Caution,
    )]))
}

/// A blocked site a rule can answer: standing until answered, with the key.
fn block_route_lines(app: &AppState, texts: &Texts) -> Vec<ViewLine> {
    let sentences = block_route::lines(app, texts);
    if sentences.is_empty() {
        return Vec::new();
    }
    let mut lines = vec![ViewLine::new(vec![Segment::state(
        texts.get(keys::BLOCK_NOTICE_TITLE),
        StateTone::Caution,
    )])];
    lines.extend(sentences.into_iter().map(ViewLine::text));
    lines
}

/// The package parts this copy lacks, named the way the window names them.
fn delivery_line(app: &AppState, texts: &Texts) -> Option<ViewLine> {
    let parts: Vec<String> = app
        .delivery_gaps
        .iter()
        .filter_map(|gap| match *gap {
            "presets" => Some(texts.get(keys::DELIVERY_PRESETS)),
            "locales" => Some(texts.get(keys::DELIVERY_LOCALES)),
            _ => None,
        })
        .collect();
    if parts.is_empty() {
        return None;
    }
    Some(ViewLine::new(vec![
        Segment::state(texts.get(keys::DELIVERY_TITLE), StateTone::Caution),
        Segment::plain(format!(
            " {}",
            texts.fill(keys::DELIVERY_BODY, &[("parts", parts.join("; "))])
        )),
    ]))
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
    let Some((name, bundled)) = vpn_trust::first_question(&app.vpn_trust.pending) else {
        return Vec::new();
    };
    let hint = if bundled == 0 {
        texts.fill(keys::VPN_TRUST_HINT, &[("name", name)])
    } else {
        texts.fill(
            keys::VPN_TRUST_HINT_BUNDLE,
            &[("name", name), ("count", bundled.to_string())],
        )
    };
    vec![
        ViewLine::new(vec![Segment::state(
            texts.get(keys::VPN_TRUST_TITLE),
            StateTone::Caution,
        )]),
        ViewLine::text(texts.fill(keys::VPN_TRUST_BODY, &[("apps", names.join(", "))])),
        ViewLine::text(hint),
    ]
}

/// Another VPN stopped on its way to its server: standing, each server named,
/// with the key that answers.
fn pending_vpn_gateway_lines(app: &AppState, texts: &Texts) -> Vec<ViewLine> {
    if !app.link.is_connected() {
        return Vec::new();
    }
    let sentences = vpn_gateway_trust::sentences(&app.vpn_gateway_trust.pending, texts);
    if sentences.is_empty() {
        return Vec::new();
    }
    let mut lines = vec![ViewLine::new(vec![Segment::state(
        texts.get(vpn_gateway_trust::TITLE),
        StateTone::Caution,
    )])];
    lines.extend(sentences.into_iter().map(ViewLine::text));
    lines.push(ViewLine::text(texts.get(vpn_gateway_trust::HINT)));
    lines
}

/// The caller's app rules that found no program: standing while it lasts, so
/// it sits with the state rather than in the feed.
fn unresolved_app_lines(app: &AppState, texts: &Texts) -> Vec<ViewLine> {
    let snapshot = match &app.snapshot {
        Some(snapshot) if app.link.is_connected() => snapshot,
        _ => return Vec::new(),
    };
    let reasons = &snapshot.unenforced_app_reasons;
    // A rule refused for its place says why, as Overlaps does.
    let mut lines: Vec<ViewLine> = snapshot
        .unenforced_app_rules
        .iter()
        .filter_map(|a| {
            let reason = reasons.get(a)?;
            Some(ViewLine::new(vec![Segment::state(
                overlaps::refusal_text(a, reason, texts),
                StateTone::Caution,
            )]))
        })
        .collect();
    let missing: Vec<String> = snapshot
        .unenforced_app_rules
        .iter()
        .filter(|a| !reasons.contains_key(*a))
        .map(|a| display_text(a).into())
        .collect();
    if !missing.is_empty() {
        let summary = list_summary(&missing, &texts.get(keys::APP_UNRESOLVED_MORE));
        lines.push(ViewLine::new(vec![Segment::state(
            texts.get(keys::APP_UNRESOLVED_TITLE),
            StateTone::Caution,
        )]));
        lines.push(ViewLine::text(
            texts.fill(keys::APP_UNRESOLVED_BODY, &[("apps", summary)]),
        ));
    }
    lines
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

    #[test]
    fn a_timed_pause_says_how_long_it_lasts() {
        let mut app = app_at(Link::Connected, Some(&Fixture::healthy()));
        let first_line = |app: &AppState| routing_lines(app, &texts_en())[0].plain_text();
        let snapshot = app.snapshot.as_mut().expect("snapshot");
        snapshot.routing_paused = true;
        snapshot.routing_pause_until_restart = true;
        assert!(
            first_line(&app).ends_with("until restart"),
            "{}",
            first_line(&app)
        );

        let snapshot = app.snapshot.as_mut().expect("snapshot");
        snapshot.routing_pause_until_restart = false;
        snapshot.routing_pause_resumes_at_ms = Some(i64::MAX);
        assert!(first_line(&app).contains("left"), "{}", first_line(&app));

        let snapshot = app.snapshot.as_mut().expect("snapshot");
        snapshot.routing_pause_resumes_at_ms = None;
        assert!(
            !first_line(&app).contains(" · "),
            "an untimed pause names no term"
        );
    }

    #[test]
    fn a_contract_skew_is_said_under_the_connection_line() {
        let mut app = app_at(Link::Connected, Some(&Fixture::healthy()));
        let lines = |app: &AppState| -> Vec<String> {
            connection_lines(app, &texts_en())
                .iter()
                .map(ViewLine::plain_text)
                .collect()
        };
        let before = lines(&app).len();
        app.contract_skew = Some(ContractSkew::ServiceOlder);
        let shown = lines(&app);
        assert_eq!(shown.len(), before + 1, "{shown:?}");
        assert!(
            shown.iter().any(|l| l.contains("older than this window")),
            "{shown:?}"
        );
        app.link = Link::Offline;
        assert!(!lines(&app)
            .iter()
            .any(|l| l.contains("older than this window")));
    }

    /// The SSH notice follows the flag read at start, not the environment the
    /// tests run in: a gate run over SSH used to redraw every snapshot.
    #[test]
    fn a_session_without_a_windows_sign_in_is_told_so_while_connected() {
        let mut app = app_at(Link::Connected, Some(&Fixture::healthy()));
        let said = |app: &AppState| {
            connection_lines(app, &texts_en())
                .iter()
                .map(ViewLine::plain_text)
                .any(|l| l.contains("Signed in over SSH"))
        };
        assert!(!said(&app));
        app.rules_need_a_sign_in = true;
        assert!(said(&app));
        app.link = Link::Offline;
        assert!(!said(&app));
    }

    /// The window's empty-rules and policy-inactive banners, in the status:
    /// only once the service's count is known, and silent where another line
    /// owns the cause.
    #[test]
    fn a_service_that_routes_nothing_says_why_under_the_state() {
        let said = |app: &AppState, needle: &str| shown(app).iter().any(|l| l.contains(needle));
        let mut app = app_at(Link::Connected, Some(&Fixture::healthy()));
        app.snapshot.as_mut().expect("snapshot").active_rule_count = None;
        assert!(
            !said(&app, "No rules are active"),
            "a service that does not count"
        );
        app.snapshot.as_mut().expect("snapshot").active_rule_count = Some(0);
        assert!(said(&app, "No rules are active"));

        app.snapshot.as_mut().expect("snapshot").active_rule_count = Some(3);
        assert!(!said(&app, "No rules are active"));
        assert!(
            !said(&app, "not being applied"),
            "a bound additional adapter tells its own state"
        );

        let mut app = app_at(
            Link::Connected,
            Some(&Fixture {
                secondary: None,
                ..Fixture::healthy()
            }),
        );
        app.snapshot.as_mut().expect("snapshot").active_rule_count = Some(3);
        track_policy_idle(&mut app, Instant::now());
        assert!(
            !said(&app, "not being applied"),
            "a service still coming up stays quiet for the settle window"
        );
        app.policy_idle_since = Instant::now().checked_sub(POLICY_IDLE_SETTLE);
        assert!(app.policy_idle_since.is_some(), "the clock reaches back");
        assert!(said(&app, "your rules are not being applied"));
        let policy = app
            .snapshot
            .as_mut()
            .and_then(|s| s.route_policy.as_mut())
            .expect("route policy");
        policy.leak_protection = LeakProtectionDto::Sites;
        assert!(said(&app, "is being blocked"));

        app.snapshot.as_mut().expect("snapshot").routing_paused = true;
        assert!(!said(&app, "is being blocked"), "the pause owns it");
        track_policy_idle(&mut app, Instant::now());
        assert_eq!(app.policy_idle_since, None, "the wait starts over");
        app.snapshot.as_mut().expect("snapshot").routing_paused = false;
        app.link = Link::Offline;
        assert!(!said(&app, "is being blocked"));
    }

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

    /// Leak protection holding everything stands under the state while the
    /// service says so, and not after it went away.
    #[test]
    fn leak_protection_holding_all_traffic_stands_under_the_state() {
        let mut app = app_at(Link::Connected, Some(&Fixture::healthy()));
        let holding = |app: &AppState| {
            shown(app)
                .iter()
                .any(|l| l.starts_with("Leak protection is holding all traffic"))
        };
        assert!(!holding(&app));
        if let Some(snapshot) = app.snapshot.as_mut() {
            snapshot.kill_switch_block_all_armed = true;
        }
        assert!(
            !holding(&app),
            "the catch-all over a live tunnel holds nothing back"
        );
        if let Some(snapshot) = app.snapshot.as_mut() {
            snapshot.kill_switch_holding_for_outage = true;
        }
        assert!(holding(&app), "{:?}", shown(&app));
        app.link = Link::Offline;
        assert!(!holding(&app), "a stale snapshot claims nothing");
    }

    /// Too many network filters on the machine is said with the count, while
    /// the service says so.
    #[test]
    fn too_many_filters_on_the_machine_is_said_with_the_count() {
        let mut app = app_at(Link::Connected, Some(&Fixture::healthy()));
        let warned = |app: &AppState| {
            shown(app)
                .iter()
                .any(|l| l.starts_with("Rules on this computer") && l.contains("4100 Windows"))
        };
        if let Some(snapshot) = app.snapshot.as_mut() {
            snapshot.protection_filters_on_machine = 4100;
        }
        assert!(!warned(&app), "a count under the line is not a warning");
        if let Some(snapshot) = app.snapshot.as_mut() {
            snapshot.protection_filters_high = true;
        }
        assert!(warned(&app), "{:?}", shown(&app));
        app.link = Link::Offline;
        assert!(!warned(&app), "a stale snapshot claims nothing");
    }

    #[test]
    fn a_package_without_its_rule_sets_says_so() {
        let mut app = app_at(Link::Connected, Some(&Fixture::healthy()));
        assert!(!shown(&app)
            .iter()
            .any(|l| l.contains("installation is incomplete")));
        app.delivery_gaps = vec!["presets", "locales"];
        let lines = shown(&app);
        assert!(
            lines
                .iter()
                .any(|l| l.starts_with("The installation is incomplete")
                    && l.contains("ready-made rule sets; the interface languages")
                    && l.contains("Reinstall")),
            "{lines:?}"
        );
    }

    #[test]
    fn unreadable_settings_say_the_run_is_on_defaults() {
        let mut app = app_at(Link::Connected, Some(&Fixture::healthy()));
        assert!(!shown(&app).iter().any(|l| l.contains("could not be read")));
        app.settings_unreadable = true;
        assert!(
            shown(&app)
                .iter()
                .any(|l| l.starts_with("Your settings could not be read")
                    && l.contains("default settings")),
            "{:?}",
            shown(&app)
        );
    }

    /// A rule refused for its place stands with the reason Overlaps gives, and
    /// is not counted among the programs that were not found.
    #[test]
    fn a_refused_app_rule_names_its_reason_not_a_missing_program() {
        let mut app = app_at(Link::Connected, Some(&Fixture::healthy()));
        if let Some(snapshot) = app.snapshot.as_mut() {
            snapshot.unenforced_app_rules = vec![r"c:\junk\*".to_string()];
            snapshot
                .unenforced_app_reasons
                .insert(r"c:\junk\*".to_string(), "other-users-folder".to_string());
        }
        let lines = shown(&app);
        assert!(
            lines.iter().any(|l| l.contains("another user's profile")),
            "{lines:?}"
        );
        assert!(
            !lines.iter().any(|l| l.contains("weren't found")),
            "{lines:?}"
        );
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
            vpn_trust::trust_first(&mut app, false),
            "t sends the confirmation"
        );
        assert!(app.vpn_trust.busy);
        assert!(
            !vpn_trust::trust_first(&mut app, false),
            "a second press while the write is in flight does nothing"
        );
        assert_eq!(app.outbox.take().len(), 1);

        app.link = Link::Offline;
        assert!(!shown(&app).iter().any(|l| l.contains("Is this your VPN?")));
    }

    /// Another VPN stopped on its way to its server stands under the state,
    /// with its program and the key that allows it; `a` writes once, and
    /// nothing is shown while offline.
    #[test]
    fn a_pending_vpn_gateway_is_named_with_its_key_and_a_allows_it() {
        use nrr_shared::ipc_payloads::VpnGatewayDto;
        let title = "Let this VPN connect?";
        let mut app = app_at(Link::Connected, Some(&Fixture::healthy()));
        assert!(!shown(&app).iter().any(|l| l == title));
        app.vpn_gateway_trust.pending = vec![VpnGatewayDto {
            address: "203.0.113.20".into(),
            program: r"C:\Program Files\Corp\corp-vpn.exe".into(),
        }];
        let lines = shown(&app);
        assert!(lines.iter().any(|l| l == title), "{lines:?}");
        assert!(
            lines
                .iter()
                .any(|l| l.contains("corp-vpn.exe") && l.contains("203.0.113.20")),
            "{lines:?}"
        );
        assert!(lines.iter().any(|l| l.starts_with("a: ")), "{lines:?}");

        let a = KeyEvent::new(KeyCode::Char('a'), crossterm::event::KeyModifiers::NONE);
        assert!(StatusScreen.on_key(&mut app, a), "a sends the answer");
        assert!(app.vpn_gateway_trust.busy);
        assert!(
            !vpn_gateway_trust::allow_first(&mut app),
            "a second press while the write is in flight does nothing"
        );
        assert_eq!(app.outbox.take().len(), 1);

        app.link = Link::Offline;
        assert!(!shown(&app).iter().any(|l| l == title));
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
