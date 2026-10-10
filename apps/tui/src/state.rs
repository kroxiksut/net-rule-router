//! What the interface knows and where the user is. Both renderers draw from
//! this; only [`AppState::apply`] and the key handlers change it.

use std::collections::BTreeMap;
use std::time::Instant;

use nrr_shared::ipc_payloads::{
    EnforcementStatusDto, RoutesHeldDto, SnapshotInitialResponse, StatusUpdateEvent,
};

use crate::backend::{BackendEvent, Outbox, PushEvent};
use crate::i18n::{Key, Texts};
use crate::keys;
use crate::link::Link;
use crate::screens::ScreenId;

/// How many notices the feed keeps; the oldest go first.
const FEED_CAPACITY: usize = 200;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoticeLevel {
    Info,
    Warning,
}

/// One line of the feed. Text is resolved when the notice arrives: the language
/// does not change while the program runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notice {
    pub level: NoticeLevel,
    pub title: String,
    pub body: String,
}

/// The service's report that a role's rules are not in force.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnforcementDown {
    pub status: String,
    pub candidates: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoutingState {
    /// Nothing is known to be applied: there is no service to ask.
    Disconnected,
    Paused,
    /// A role's rules are not in force.
    Limited,
    Active,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Focus {
    Menu,
    /// The screen's feed panel, which scrolls.
    Feed,
}

/// What the main loop does after a change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    Refresh,
    Bell,
}

#[derive(Debug)]
pub struct AppState {
    pub link: Link,
    /// The last snapshot the service gave; kept, and marked stale, while the
    /// service is away.
    pub snapshot: Option<SnapshotInitialResponse>,
    pub fetch_error: Option<String>,
    /// Keyed by role slug; an empty key is a report about no single role.
    pub enforcement_down: BTreeMap<String, EnforcementDown>,
    /// This user's destinations another signed-in user's routing holds.
    pub routes_held: Option<RoutesHeldDto>,
    /// The newest notices, at most [`FEED_CAPACITY`].
    pub notices: Vec<Notice>,
    /// Notices ever received, the dropped ones included.
    pub notice_count: usize,
    pub last_notice_at: Option<Instant>,
    pub screen: ScreenId,
    pub focus: Focus,
    /// Lines scrolled off the top of the focused panel.
    pub scroll: u16,
    pub help_open: bool,
    pub quit: bool,
    pub bell: bool,
    /// Jobs the screens asked for since the loop last sent them.
    pub outbox: Outbox,
    /// The trace, cache and diagnostics screens' own state.
    pub inspect: crate::screens::inspect::Inspect,
    /// The suggested-addresses screen's lists and answers.
    pub suggestions: crate::screens::suggestions::Suggestions,
    /// The overlaps screen's pairs and confirmations.
    pub overlaps: crate::screens::overlaps::Overlaps,
    pub interfaces: crate::screens::interfaces::InterfacesState,
    pub wizard: crate::screens::wizard::WizardState,
    /// The rules screen's list, edits and apply.
    pub rules: crate::screens::rules::RulesState,
    /// A language the user picked; the loop reloads the texts in it.
    pub language_change: Option<String>,
    /// "Restore my settings": what a service that lost them lacks.
    pub restore: crate::restore::RestoreState,
    /// The Settings screen's sections, what they read and the terminal's own
    /// saved options.
    pub settings: crate::screens::settings::SettingsState,
}

impl AppState {
    pub fn new(screen: ScreenId, bell: bool) -> Self {
        Self {
            link: Link::Connecting,
            snapshot: None,
            fetch_error: None,
            enforcement_down: BTreeMap::new(),
            routes_held: None,
            notices: Vec::new(),
            notice_count: 0,
            last_notice_at: None,
            screen,
            focus: Focus::Menu,
            scroll: 0,
            help_open: false,
            quit: false,
            bell,
            outbox: Outbox::default(),
            inspect: crate::screens::inspect::Inspect::default(),
            suggestions: Default::default(),
            overlaps: Default::default(),
            interfaces: crate::screens::interfaces::InterfacesState::default(),
            wizard: crate::screens::wizard::WizardState::default(),
            rules: crate::screens::rules::RulesState::default(),
            language_change: None,
            restore: crate::restore::RestoreState::default(),
            settings: crate::screens::settings::SettingsState::default(),
        }
    }

    /// Whether what is shown came from the service just now.
    #[cfg(test)]
    pub fn is_fresh(&self) -> bool {
        self.link.is_connected() && self.snapshot.is_some()
    }

    pub fn routing_state(&self) -> RoutingState {
        let Some(snapshot) = self.snapshot.as_ref().filter(|_| self.link.is_connected()) else {
            return RoutingState::Disconnected;
        };
        if snapshot.routing_paused {
            RoutingState::Paused
        } else if !self.enforcement_down.is_empty() {
            RoutingState::Limited
        } else {
            RoutingState::Active
        }
    }

    /// `q`: quit, unless rules on screen are not applied yet — then the rules
    /// screen asks "apply / discard / stay".
    pub fn request_quit(&mut self) {
        if crate::screens::rules::holds_unapplied(self) {
            crate::screens::rules::ask_before_quit(self);
        } else {
            self.quit = true;
        }
    }

    pub fn open(&mut self, screen: ScreenId) {
        if self.screen != screen {
            self.screen = screen;
            self.scroll = 0;
            crate::screens::screen(screen).on_show(self);
        }
        self.help_open = false;
    }

    pub fn apply(&mut self, event: BackendEvent, texts: &Texts, now: Instant) -> Vec<Effect> {
        match event {
            // Reports about rules in force are kept across a drop; the snapshot
            // read on reconnect brings them up to date.
            BackendEvent::Link(link) => {
                let reconnected = link.is_connected() && !self.link.is_connected();
                self.link = link;
                if reconnected {
                    crate::restore::on_connected(self);
                    crate::screens::rules::verdicts::load(self);
                    crate::screens::screen(self.screen).on_show(self);
                }
                Vec::new()
            }
            BackendEvent::Reply(reply) => {
                (reply.0)(self);
                let mut effects = crate::restore::announce(self, texts, now);
                for effect in crate::screens::rules::verdicts::announce(self, texts, now) {
                    if !effects.contains(&effect) {
                        effects.push(effect);
                    }
                }
                effects
            }
            BackendEvent::Snapshot(snapshot) => {
                let reports = snapshot.enforcement_status.clone();
                let held = snapshot.routes_held_by_another_user.clone();
                self.snapshot = Some(*snapshot);
                self.fetch_error = None;
                crate::screens::wizard::snapshot_arrived(self);
                crate::restore::on_snapshot(self);
                let mut effects = self.apply_standing_enforcement(reports, texts, now);
                for effect in self.routes_held_changed(held, texts, now) {
                    if !effects.contains(&effect) {
                        effects.push(effect);
                    }
                }
                effects
            }
            BackendEvent::FetchFailed(error) => {
                self.fetch_error = Some(error);
                Vec::new()
            }
            BackendEvent::Push(PushEvent::Gap) => vec![Effect::Refresh],
            BackendEvent::Push(PushEvent::Status(event)) => self.apply_push(*event, texts, now),
        }
    }

    fn apply_push(&mut self, event: StatusUpdateEvent, texts: &Texts, now: Instant) -> Vec<Effect> {
        match event {
            StatusUpdateEvent::EnforcementStatusChanged {
                status,
                role,
                candidates,
                ..
            } => {
                // The leak-guard banner is read from the snapshot, and a link
                // coming back moves no adapter: re-read it, as the GUI does.
                let restored = status.is_empty() || status == "ok";
                let mut effects = self.enforcement_changed(status, role, candidates, texts, now);
                if restored && !effects.contains(&Effect::Refresh) {
                    effects.push(Effect::Refresh);
                }
                effects
            }
            StatusUpdateEvent::RoutingPauseStateChanged { paused, .. } => {
                if let Some(snapshot) = self.snapshot.as_mut() {
                    snapshot.routing_paused = paused;
                }
                Vec::new()
            }
            StatusUpdateEvent::VerifyVerdictsChanged { .. } => {
                crate::screens::rules::verdicts::load(self);
                Vec::new()
            }
            StatusUpdateEvent::RoutesHeldByAnotherUser { count, sample, .. } => {
                let held = (count > 0).then_some(RoutesHeldDto { count, sample });
                self.routes_held_changed(held, texts, now)
            }
            StatusUpdateEvent::HostUnreachableOnBothRoutes { host, .. } => self.notify(
                NoticeLevel::Info,
                texts.get(keys::HOST_UNREACHABLE_TITLE),
                texts.fill(keys::HOST_UNREACHABLE_BODY, &[("host", &host)]),
                now,
            ),
            StatusUpdateEvent::SecondaryExternalAddressObserved {
                adapter_name,
                external_address,
                ..
            } => {
                let mut body = texts.fill(
                    keys::EXTERNAL_ADDRESS_BODY,
                    &[("address", &external_address)],
                );
                if !adapter_name.is_empty() {
                    body.push(' ');
                    body.push_str(
                        &texts.fill(keys::EXTERNAL_ADDRESS_ADAPTER, &[("name", &adapter_name)]),
                    );
                }
                self.notify(
                    NoticeLevel::Info,
                    texts.get(keys::EXTERNAL_ADDRESS_TITLE),
                    body,
                    now,
                )
            }
            StatusUpdateEvent::AdaptersChanged { .. }
            | StatusUpdateEvent::HealthChanged { .. }
            | StatusUpdateEvent::Overflow { .. } => vec![Effect::Refresh],
            StatusUpdateEvent::AutoRuleCandidatesChanged {
                pending_count,
                top_anchor,
                ..
            } => {
                match crate::screens::suggestions::changed(self, pending_count, &top_anchor, texts)
                {
                    Some((title, body)) => self.notify(NoticeLevel::Info, title, body, now),
                    None => Vec::new(),
                }
            }
            StatusUpdateEvent::MutationProgress {
                correlation_id,
                phase,
                error_code,
                error_args,
                ..
            } => {
                crate::screens::rules::on_progress(
                    self,
                    &correlation_id,
                    &phase,
                    error_code.as_deref(),
                    &error_args,
                );
                Vec::new()
            }
            StatusUpdateEvent::RevisionStatusChanged { .. } => {
                crate::screens::rules::on_revision_changed(self);
                Vec::new()
            }
            _ => Vec::new(),
        }
    }

    /// The snapshot's standing reports, handled as the pushes they stand for:
    /// the push fires on change only, so one that came before this interface
    /// connected is known only from here. A report equal to the state already
    /// held is skipped, since the snapshot is re-read on every refresh.
    fn apply_standing_enforcement(
        &mut self,
        reports: Vec<EnforcementStatusDto>,
        texts: &Texts,
        now: Instant,
    ) -> Vec<Effect> {
        let mut effects = Vec::new();
        for report in reports {
            let held = self
                .enforcement_down
                .get(&report.role)
                .map_or("ok", |down| down.status.as_str());
            let status = if report.status.is_empty() {
                "ok"
            } else {
                report.status.as_str()
            };
            if held == status {
                continue;
            }
            for effect in
                self.enforcement_changed(report.status, report.role, report.candidates, texts, now)
            {
                if !effects.contains(&effect) {
                    effects.push(effect);
                }
            }
        }
        effects
    }

    /// Another user's routing holds some of this user's destinations, or
    /// stopped holding them. The snapshot repeats the standing report on every
    /// refresh, so one equal to the state held is not news.
    fn routes_held_changed(
        &mut self,
        held: Option<RoutesHeldDto>,
        texts: &Texts,
        now: Instant,
    ) -> Vec<Effect> {
        if self.routes_held == held {
            return Vec::new();
        }
        let was_held = self.routes_held.is_some();
        self.routes_held = held.clone();
        match held {
            Some(held) => {
                let (title, body) = routes_held_text(&held, texts);
                self.notify(NoticeLevel::Warning, title, body, now)
            }
            None if was_held => self.notify(
                NoticeLevel::Info,
                texts.get(keys::ROUTES_HELD_TITLE),
                texts.get(keys::ROUTES_HELD_CLEARED),
                now,
            ),
            None => Vec::new(),
        }
    }

    /// A standing state per role: a later report replaces it, `ok` ends it.
    fn enforcement_changed(
        &mut self,
        status: String,
        role: String,
        candidates: Vec<String>,
        texts: &Texts,
        now: Instant,
    ) -> Vec<Effect> {
        if status.is_empty() || status == "ok" {
            if self.enforcement_down.remove(&role).is_some() {
                let mut body = texts.get(keys::ENF_RESTORED_BODY);
                // What leak protection held back meanwhile has a list of its own.
                if role == "secondary" {
                    let screen = texts.get(ScreenId::OutageBlocks.title());
                    let pointer = texts.fill(keys::ENF_RESTORED_WHERE, &[("screen", screen)]);
                    body.push(' ');
                    body.push_str(&pointer);
                }
                return self.notify(
                    NoticeLevel::Info,
                    texts.get(keys::ENF_RESTORED_TITLE),
                    body,
                    now,
                );
            }
            return Vec::new();
        }
        let (title, body) = enforcement_text(&status, &role, &candidates, texts);
        self.enforcement_down
            .insert(role, EnforcementDown { status, candidates });
        self.notify(NoticeLevel::Warning, title, body, now)
    }

    pub(crate) fn notify(
        &mut self,
        level: NoticeLevel,
        title: String,
        body: String,
        now: Instant,
    ) -> Vec<Effect> {
        self.notices.push(Notice { level, title, body });
        self.notice_count += 1;
        if self.notices.len() > FEED_CAPACITY {
            let excess = self.notices.len() - FEED_CAPACITY;
            self.notices.drain(..excess);
        }
        self.last_notice_at = Some(now);
        if self.bell {
            vec![Effect::Bell]
        } else {
            Vec::new()
        }
    }
}

/// The GUI's wording for destinations another signed-in user's routing holds.
pub fn routes_held_text(held: &RoutesHeldDto, texts: &Texts) -> (String, String) {
    let count = held.count.to_string();
    let list = held.sample.join(", ");
    (
        texts.get(keys::ROUTES_HELD_TITLE),
        texts.fill(
            keys::ROUTES_HELD_BODY,
            &[("count", count.as_str()), ("list", list.as_str())],
        ),
    )
}

/// The GUI's wording for an enforcement report: what happened, and what to do.
/// An unknown status still says the one thing that matters.
pub fn enforcement_text(
    status: &str,
    role: &str,
    candidates: &[String],
    texts: &Texts,
) -> (String, String) {
    let list = candidates.join(", ");
    let with_list = |title: Key, body: Key, empty: Key| {
        let body = if candidates.is_empty() {
            texts.get(empty)
        } else {
            texts.fill(body, &[("list", &list)])
        };
        (texts.get(title), body)
    };
    match status {
        "adapter-choice-needed" => (
            texts.get(keys::ENF_CHOICE_TITLE),
            texts.fill(keys::ENF_CHOICE_BODY, &[("list", &list)]),
        ),
        "adapter-gone" => with_list(
            keys::ENF_GONE_TITLE,
            keys::ENF_GONE_BODY,
            keys::ENF_GONE_BODY_EMPTY,
        ),
        "adapter-failed" => with_list(
            keys::ENF_FAILED_TITLE,
            keys::ENF_FAILED_BODY,
            keys::ENF_FAILED_BODY_EMPTY,
        ),
        "no-primary-route" => (
            texts.get(keys::ENF_NO_PRIMARY_TITLE),
            texts.get(keys::ENF_NO_PRIMARY_BODY),
        ),
        "primary-no-way-out" => (
            texts.get(keys::ENF_NO_WAY_OUT_TITLE),
            texts.get(keys::ENF_NO_WAY_OUT_BODY),
        ),
        "no-policy" => (
            texts.get(keys::ENF_NO_POLICY_TITLE),
            texts.get(keys::ENF_NO_POLICY_BODY),
        ),
        "secondary-down" if role == "primary" => (
            texts.get(keys::ENF_PRIMARY_DOWN_TITLE),
            texts.get(keys::ENF_PRIMARY_DOWN_BODY),
        ),
        "secondary-down" => (
            texts.get(keys::ENF_SECONDARY_DOWN_TITLE),
            texts.get(keys::ENF_SECONDARY_DOWN_BODY),
        ),
        "adapters-unreadable" => (
            texts.get(keys::ENF_UNREADABLE_TITLE),
            texts.get(keys::ENF_UNREADABLE_BODY),
        ),
        _ => (
            texts.get(keys::ENF_UNKNOWN_TITLE),
            texts.get(keys::ENF_UNKNOWN_BODY),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::Fixture;

    fn texts() -> Texts {
        Texts::load(Some("en"), &[])
    }

    fn connected(fixture: &Fixture) -> AppState {
        let mut app = AppState::new(ScreenId::Status, false);
        let t = texts();
        app.apply(BackendEvent::Link(Link::Connected), &t, Instant::now());
        app.apply(
            BackendEvent::Snapshot(Box::new(fixture.snapshot())),
            &t,
            Instant::now(),
        );
        app
    }

    fn enforcement(status: &str, role: &str) -> BackendEvent {
        BackendEvent::Push(PushEvent::Status(Box::new(
            StatusUpdateEvent::EnforcementStatusChanged {
                sid: "S".into(),
                status: status.into(),
                role: role.into(),
                candidates: Vec::new(),
                since_unix_ms: None,
            },
        )))
    }

    #[test]
    fn routing_reads_active_limited_paused_and_back() {
        let t = texts();
        let mut app = connected(&Fixture::healthy());
        assert_eq!(app.routing_state(), RoutingState::Active);

        app.apply(
            enforcement("secondary-down", "secondary"),
            &t,
            Instant::now(),
        );
        assert_eq!(app.routing_state(), RoutingState::Limited);
        assert_eq!(app.notices.len(), 1);
        assert_eq!(app.notices[0].level, NoticeLevel::Warning);

        assert!(
            app.apply(enforcement("ok", "secondary"), &t, Instant::now())
                .contains(&Effect::Refresh),
            "a link back re-reads the snapshot (the leak-guard banner lives there)"
        );
        assert_eq!(app.routing_state(), RoutingState::Active);
        assert_eq!(app.notices.len(), 2, "the return is news too");
        assert!(
            app.notices[1]
                .body
                .ends_with("The list of what was blocked: Blocked while the route was down"),
            "{:?}",
            app.notices[1]
        );

        let paused = Fixture {
            paused: true,
            ..Fixture::healthy()
        };
        assert_eq!(connected(&paused).routing_state(), RoutingState::Paused);
    }

    fn held(count: u64, sample: &[&str]) -> BackendEvent {
        BackendEvent::Push(PushEvent::Status(Box::new(
            StatusUpdateEvent::RoutesHeldByAnotherUser {
                sid: "S".into(),
                count,
                sample: sample.iter().map(|s| s.to_string()).collect(),
            },
        )))
    }

    #[test]
    fn destinations_held_by_another_user_are_told_once_and_their_end_too() {
        let t = texts();
        let mut app = connected(&Fixture::healthy());
        app.apply(
            held(2, &["198.51.100.1", "203.0.113.0/24"]),
            &t,
            Instant::now(),
        );
        assert_eq!(app.notices.len(), 1);
        assert_eq!(app.notices[0].level, NoticeLevel::Warning);
        assert_eq!(
            app.notices[0].title,
            "Some addresses follow another user's route"
        );
        assert!(
            app.notices[0].body.contains("Addresses affected: 2")
                && app.notices[0]
                    .body
                    .ends_with("Among them: 198.51.100.1, 203.0.113.0/24."),
            "{:?}",
            app.notices[0]
        );
        assert_eq!(
            app.routing_state(),
            RoutingState::Active,
            "the rules are in force; another user's route carries some of them"
        );

        // The snapshot repeats the standing report on every refresh.
        let mut snapshot = Fixture::healthy().snapshot();
        snapshot.routes_held_by_another_user = Some(RoutesHeldDto {
            count: 2,
            sample: vec!["198.51.100.1".into(), "203.0.113.0/24".into()],
        });
        app.apply(
            BackendEvent::Snapshot(Box::new(snapshot)),
            &t,
            Instant::now(),
        );
        assert_eq!(app.notices.len(), 1, "the same state is not news");

        app.apply(held(0, &[]), &t, Instant::now());
        assert_eq!(app.notices.len(), 2);
        assert_eq!(app.notices[1].level, NoticeLevel::Info);
        assert_eq!(
            app.notices[1].body,
            "Addresses from your rules follow your own route again."
        );
        assert!(app.routes_held.is_none());
    }

    /// A terminal opened after the conflict began learns it from the snapshot.
    #[test]
    fn a_late_terminal_learns_held_destinations_from_the_snapshot() {
        let t = texts();
        let mut app = AppState::new(ScreenId::Status, false);
        app.apply(BackendEvent::Link(Link::Connected), &t, Instant::now());
        let mut snapshot = Fixture::healthy().snapshot();
        snapshot.routes_held_by_another_user = Some(RoutesHeldDto {
            count: 1,
            sample: vec!["198.51.100.1".into()],
        });
        app.apply(
            BackendEvent::Snapshot(Box::new(snapshot)),
            &t,
            Instant::now(),
        );
        assert_eq!(app.notices.len(), 1);
        assert_eq!(app.notices[0].level, NoticeLevel::Warning);

        // A later snapshot without it says the conflict is over.
        app.apply(
            BackendEvent::Snapshot(Box::new(Fixture::healthy().snapshot())),
            &t,
            Instant::now(),
        );
        assert_eq!(app.notices.len(), 2);
        assert_eq!(app.notices[1].level, NoticeLevel::Info);
    }

    #[test]
    fn without_the_service_nothing_is_claimed_active() {
        let t = texts();
        let mut app = connected(&Fixture::healthy());
        app.apply(BackendEvent::Link(Link::Stopped), &t, Instant::now());
        assert_eq!(app.routing_state(), RoutingState::Disconnected);
        assert!(app.snapshot.is_some(), "the last known state is kept");
        assert!(!app.is_fresh(), "and not passed off as fresh");
    }

    #[test]
    fn a_hole_in_the_stream_asks_for_a_fresh_snapshot() {
        let mut app = connected(&Fixture::healthy());
        assert_eq!(
            app.apply(BackendEvent::Push(PushEvent::Gap), &texts(), Instant::now()),
            vec![Effect::Refresh]
        );
    }

    #[test]
    fn the_bell_rings_only_when_asked_for() {
        let t = texts();
        let mut app = connected(&Fixture::healthy());
        assert!(app
            .apply(enforcement("no-policy", ""), &t, Instant::now())
            .is_empty());
        app.bell = true;
        assert_eq!(
            app.apply(enforcement("adapter-gone", "primary"), &t, Instant::now()),
            vec![Effect::Bell]
        );
    }

    fn snapshot_reporting(reports: &[(&str, &str)]) -> BackendEvent {
        let mut snapshot = Fixture::healthy().snapshot();
        snapshot.enforcement_status = reports
            .iter()
            .map(|(status, role)| EnforcementStatusDto {
                status: (*status).into(),
                role: (*role).into(),
                candidates: Vec::new(),
                since_unix_ms: None,
            })
            .collect();
        BackendEvent::Snapshot(Box::new(snapshot))
    }

    /// The push came before this interface connected: the snapshot is the only
    /// place it learns the rules are not in force.
    #[test]
    fn a_standing_report_in_the_snapshot_reads_as_the_push_it_stands_for() {
        let t = texts();
        let mut app = connected(&Fixture::healthy());
        assert_eq!(app.routing_state(), RoutingState::Active);

        app.apply(
            snapshot_reporting(&[("ok", "primary"), ("secondary-down", "secondary")]),
            &t,
            Instant::now(),
        );
        assert_eq!(app.routing_state(), RoutingState::Limited);
        assert_eq!(app.notices.len(), 1, "an ok role is not news");
        assert_eq!(app.notices[0].level, NoticeLevel::Warning);

        app.apply(
            snapshot_reporting(&[("ok", "primary"), ("secondary-down", "secondary")]),
            &t,
            Instant::now(),
        );
        assert_eq!(app.notices.len(), 1, "a re-read repeats nothing");

        app.apply(
            snapshot_reporting(&[("ok", "secondary")]),
            &t,
            Instant::now(),
        );
        assert_eq!(app.routing_state(), RoutingState::Active);
        assert_eq!(app.notices.len(), 2, "a missed return is news too");
    }
}
