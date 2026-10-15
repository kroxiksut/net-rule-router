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
use crate::screens::settings::Category as SettingsCategory;
use crate::screens::ScreenId;

/// How many notices the feed keeps; the oldest go first.
const FEED_CAPACITY: usize = 200;

/// The sentence for a block reason the service names, as the window shows it;
/// a slug outside the known shape reads as the generic one.
fn block_reason_text(reason: &str, texts: &Texts) -> String {
    let unknown = texts.get(keys::BLOCK_NOTICE_REASON_UNKNOWN);
    let well_formed = !reason.is_empty()
        && reason.len() <= 64
        && reason
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if !well_formed {
        return unknown;
    }
    texts.dynamic(
        &[keys::BLOCK_NOTICE_REASON_PREFIX, reason].concat(),
        &unknown,
    )
}

/// The text behind a protection-coverage reason; `None` for one this build
/// does not know.
fn protection_text(reason: &str) -> Option<Key> {
    match reason {
        "blanket-block-not-armed" => Some(keys::PROTECTION_BLANKET_BLOCK_NOT_ARMED),
        "machine-wide-cut-by-another-user" => Some(keys::PROTECTION_MACHINE_WIDE_CUT),
        _ => None,
    }
}

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
    /// The system-DNS notice is up for the state as it stands.
    pub system_dns_notice_raised: bool,
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
    /// VPN-named programs leak protection does not trust by place, awaiting
    /// the user's word.
    pub vpn_trust: crate::vpn_trust::VpnTrustState,
    /// Blocks kept while no surface was open, read on connect.
    pub block_backlog: crate::block_backlog::BlockBacklogState,
    pub local_network_offer: crate::local_network_offer::LocalNetworkOfferState,
    pub forwarded_traffic: crate::forwarded_traffic::ForwardedTrafficState,
}

impl AppState {
    pub fn new(screen: ScreenId, bell: bool) -> Self {
        Self {
            link: Link::Connecting,
            snapshot: None,
            fetch_error: None,
            enforcement_down: BTreeMap::new(),
            routes_held: None,
            system_dns_notice_raised: false,
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
            vpn_trust: crate::vpn_trust::VpnTrustState::default(),
            block_backlog: Default::default(),
            local_network_offer: Default::default(),
            forwarded_traffic: Default::default(),
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
                    crate::block_backlog::drain(self);
                    crate::local_network_offer::check(self);
                    crate::screens::screen(self.screen).on_show(self);
                }
                Vec::new()
            }
            BackendEvent::Reply(reply) => {
                (reply.0)(self);
                let mut effects = crate::restore::announce(self, texts, now);
                let later = crate::screens::rules::verdicts::announce(self, texts, now)
                    .into_iter()
                    .chain(crate::vpn_trust::announce(self, texts, now))
                    .chain(crate::block_backlog::announce(self, texts, now))
                    .chain(crate::local_network_offer::announce(self, texts, now));
                for effect in later {
                    if !effects.contains(&effect) {
                        effects.push(effect);
                    }
                }
                effects
            }
            BackendEvent::Snapshot(snapshot) => {
                let reports = snapshot.enforcement_status.clone();
                let held = snapshot.routes_held_by_another_user.clone();
                self.vpn_trust.pending = snapshot.pending_vpn_clients.clone();
                self.snapshot = Some(*snapshot);
                self.fetch_error = None;
                crate::screens::wizard::snapshot_arrived(self);
                crate::restore::on_snapshot(self);
                let dns_not_restored = self
                    .snapshot
                    .as_ref()
                    .and_then(|s| serde_json::to_value(&s.health).ok())
                    .is_some_and(|health| nrr_client_logic::system_dns::not_restored(&health));
                let mut effects = self.apply_standing_enforcement(reports, texts, now);
                for effect in self
                    .routes_held_changed(held, texts, now)
                    .into_iter()
                    .chain(self.system_dns_reading(dns_not_restored, texts, now))
                    .chain(crate::forwarded_traffic::reading(self, texts, now))
                {
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
            StatusUpdateEvent::SystemDnsNotRestored => self.system_dns_reading(true, texts, now),
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
            StatusUpdateEvent::AdaptersChanged { .. } | StatusUpdateEvent::HealthChanged { .. } => {
                vec![Effect::Refresh]
            }
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
            StatusUpdateEvent::BlockNoticeRaised {
                destination,
                app,
                reason,
                attempts,
                ..
            } => {
                let app = if app.is_empty() {
                    texts.get(keys::BLOCK_NOTICE_APP_UNKNOWN)
                } else {
                    app
                };
                let body = texts.fill(
                    keys::BLOCK_NOTICE_BODY,
                    &[
                        ("reason", block_reason_text(&reason, texts).as_str()),
                        ("destination", destination.as_str()),
                        ("app", app.as_str()),
                        ("attempts", attempts.to_string().as_str()),
                    ],
                );
                self.notify(
                    NoticeLevel::Warning,
                    texts.get(keys::BLOCK_NOTICE_TITLE),
                    body,
                    now,
                )
            }
            StatusUpdateEvent::UnassignedTunnelDetected { adapter_name, .. } => {
                if adapter_name.is_empty() {
                    return Vec::new();
                }
                let body = texts.fill(
                    keys::UNASSIGNED_TUNNEL_BODY,
                    &[("adapter", adapter_name.as_str())],
                );
                self.notify(
                    NoticeLevel::Warning,
                    texts.get(keys::UNASSIGNED_TUNNEL_TITLE),
                    body,
                    now,
                )
            }
            StatusUpdateEvent::LocalNetworkTooWide {
                adapter_name,
                network,
                ..
            } => {
                if network.is_empty() {
                    return Vec::new();
                }
                let body = texts.fill(
                    keys::LOCAL_NETWORK_TOO_WIDE_BODY,
                    &[
                        ("adapter", adapter_name.as_str()),
                        ("network", network.as_str()),
                    ],
                );
                self.notify(
                    NoticeLevel::Warning,
                    texts.get(keys::LOCAL_NETWORK_TOO_WIDE_TITLE),
                    body,
                    now,
                )
            }
            StatusUpdateEvent::RuleDuplicatesDetected { count, sample, .. } => self.notify(
                NoticeLevel::Warning,
                texts.get(keys::RULE_DUPLICATES_TITLE),
                texts.fill(
                    keys::RULE_DUPLICATES_BODY,
                    &[
                        ("count", count.to_string().as_str()),
                        ("sample", sample.as_str()),
                    ],
                ),
                now,
            ),
            StatusUpdateEvent::AppRuleLearningDestinations { apps, .. } => self.notify(
                NoticeLevel::Info,
                texts.get(keys::APP_RULE_LEARNING_TITLE),
                texts.fill(
                    keys::APP_RULE_LEARNING_BODY,
                    &[("apps", apps.join(", ").as_str())],
                ),
                now,
            ),
            // The whole list each time; an empty one is a question withdrawn,
            // which the Status screen shows by no longer listing it.
            StatusUpdateEvent::VpnClientAwaitingConfirmation { clients, .. } => {
                let names = crate::vpn_trust::names(&clients);
                self.vpn_trust.pending = clients;
                if names.is_empty() {
                    vec![Effect::Refresh]
                } else {
                    self.notify(
                        NoticeLevel::Warning,
                        texts.get(keys::VPN_TRUST_TITLE),
                        texts.fill(keys::VPN_TRUST_BODY, &[("apps", names.join(", "))]),
                        now,
                    )
                }
            }
            // A reason this build does not know has no sentence to show; the
            // slug itself is never put on screen.
            StatusUpdateEvent::ProtectionCoverageChanged { reason } => {
                match protection_text(&reason) {
                    Some(body) => self.notify(
                        NoticeLevel::Warning,
                        texts.get(keys::PROTECTION_COVERAGE_TITLE),
                        texts.get(body),
                        now,
                    ),
                    None => Vec::new(),
                }
            }
            // What another surface changed is re-read where it is on screen.
            StatusUpdateEvent::SecurityAlertsChanged => {
                crate::screens::inspect::diagnostics::reload_alerts(self);
                Vec::new()
            }
            StatusUpdateEvent::ApplyFailurePolicyChanged { .. } => {
                crate::screens::settings::reload_if_open(self, SettingsCategory::FailurePolicy);
                Vec::new()
            }
            StatusUpdateEvent::RetentionSettingsChanged => {
                crate::screens::settings::reload_if_open(self, SettingsCategory::Logs);
                Vec::new()
            }
            StatusUpdateEvent::BlockNoticeMutesChanged { .. } => {
                crate::screens::settings::reload_if_open(self, SettingsCategory::Notifications);
                Vec::new()
            }
            // Autostart starts the desktop app at sign-in; nothing here shows it.
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
    /// The system DNS left redirected: said when it appears, with the way out;
    /// not repeated while it lasts.
    fn system_dns_reading(
        &mut self,
        not_restored: bool,
        texts: &Texts,
        now: Instant,
    ) -> Vec<Effect> {
        let step =
            nrr_client_logic::system_dns::notice_step(self.system_dns_notice_raised, not_restored);
        self.system_dns_notice_raised = step.raised;
        if !step.raise {
            return Vec::new();
        }
        self.notify(
            NoticeLevel::Warning,
            texts.get(keys::SYSTEM_DNS_TITLE),
            texts.get(crate::screens::inspect::keys::DNS_NOT_RESTORED),
            now,
        )
    }

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

    fn push(event: StatusUpdateEvent) -> BackendEvent {
        BackendEvent::Push(PushEvent::Status(Box::new(event)))
    }

    #[test]
    fn a_blocked_connection_is_reported_with_its_reason() {
        let t = texts();
        let mut app = connected(&Fixture::healthy());
        app.apply(
            push(StatusUpdateEvent::BlockNoticeRaised {
                sid: "S".into(),
                destination: "cdn.example".into(),
                app: "messenger.exe".into(),
                reason: "blocked-by-rule".into(),
                attempts: 3,
                launched_by: Vec::new(),
            }),
            &t,
            Instant::now(),
        );
        assert_eq!(app.notices.len(), 1);
        assert_eq!(app.notices[0].level, NoticeLevel::Warning);
        assert_eq!(app.notices[0].title, "Connection blocked");
        assert_eq!(
            app.notices[0].body,
            "A rule blocks this connection. Destination: cdn.example. Application: messenger.exe. Attempts: 3."
        );

        // A reason this build does not know, and no application named.
        app.apply(
            push(StatusUpdateEvent::BlockNoticeRaised {
                sid: "S".into(),
                destination: "cdn.example".into(),
                app: String::new(),
                reason: "Zz/../not-a-slug".into(),
                attempts: 1,
                launched_by: Vec::new(),
            }),
            &t,
            Instant::now(),
        );
        assert_eq!(
            app.notices[1].body,
            "This connection was blocked. Destination: cdn.example. Application: unknown application. Attempts: 1."
        );
    }

    #[test]
    fn tunnel_and_rule_news_reach_the_feed() {
        let t = texts();
        let mut app = connected(&Fixture::healthy());
        app.apply(
            push(StatusUpdateEvent::UnassignedTunnelDetected {
                sid: "S".into(),
                adapter_name: "Tunnel".into(),
            }),
            &t,
            Instant::now(),
        );
        app.apply(
            push(StatusUpdateEvent::RuleDuplicatesDetected {
                sid: "S".into(),
                count: 2,
                sample: "both.example".into(),
            }),
            &t,
            Instant::now(),
        );
        app.apply(
            push(StatusUpdateEvent::AppRuleLearningDestinations {
                sid: "S".into(),
                apps: vec!["messenger.exe".into(), "game.exe".into()],
            }),
            &t,
            Instant::now(),
        );
        app.apply(
            push(StatusUpdateEvent::VpnClientAwaitingConfirmation {
                sid: "S".into(),
                clients: vec![nrr_shared::ipc_payloads::PendingVpnClientDto {
                    exe_path: r"C:\Users\someone\Downloads\x-vpn.exe".into(),
                    bundled_exe_paths: Vec::new(),
                }],
            }),
            &t,
            Instant::now(),
        );
        assert_eq!(app.notices.len(), 4, "{:?}", app.notices);
        assert_eq!(app.notices[3].level, NoticeLevel::Warning);
        assert_eq!(app.notices[3].title, "Is this your VPN?");
        assert!(
            app.notices[3].body.starts_with("x-vpn.exe: "),
            "{:?}",
            app.notices[3]
        );
        assert_eq!(
            app.vpn_trust.pending.len(),
            1,
            "the question stands until answered"
        );
        // The whole list each time: an empty one withdraws the question.
        app.apply(
            push(StatusUpdateEvent::VpnClientAwaitingConfirmation {
                sid: "S".into(),
                clients: Vec::new(),
            }),
            &t,
            Instant::now(),
        );
        assert!(app.vpn_trust.pending.is_empty());
        assert_eq!(app.notices.len(), 4, "a withdrawn question is not news");
        assert_eq!(app.notices[0].level, NoticeLevel::Warning);
        assert_eq!(app.notices[0].title, "The additional route is not assigned");
        assert!(
            app.notices[0].body.starts_with("Tunnel is up"),
            "{:?}",
            app.notices[0]
        );
        assert_eq!(app.notices[1].title, "A rule is set on both routes");
        assert!(
            app.notices[1].body.starts_with(
                "2 of your rules are enabled on both routes, starting with both.example."
            ),
            "{:?}",
            app.notices[1]
        );
        assert_eq!(app.notices[2].level, NoticeLevel::Info);
        assert!(
            app.notices[2].body.starts_with("messenger.exe, game.exe: "),
            "{:?}",
            app.notices[2]
        );

        app.apply(
            push(StatusUpdateEvent::UnassignedTunnelDetected {
                sid: "S".into(),
                adapter_name: String::new(),
            }),
            &t,
            Instant::now(),
        );
        assert_eq!(app.notices.len(), 4, "a tunnel without a name is not news");
    }

    /// A segment too wide to be local is said with the link and the number,
    /// so the user can tell the café's access point from their own router.
    #[test]
    fn a_too_wide_local_network_reaches_the_feed() {
        let t = texts();
        let mut app = connected(&Fixture::healthy());
        app.apply(
            push(StatusUpdateEvent::LocalNetworkTooWide {
                sid: "S".into(),
                adapter_name: "Wi-Fi".into(),
                network: "0.0.0.0/1".into(),
            }),
            &t,
            Instant::now(),
        );
        assert_eq!(app.notices.len(), 1, "{:?}", app.notices);
        assert_eq!(app.notices[0].level, NoticeLevel::Warning);
        assert_eq!(app.notices[0].title, "This network looks suspicious");
        assert!(
            app.notices[0]
                .body
                .starts_with("Wi-Fi reports 0.0.0.0/1 as its local network"),
            "{:?}",
            app.notices[0]
        );
    }

    #[test]
    fn protection_coverage_is_told_for_the_reasons_this_build_knows() {
        let t = texts();
        let mut app = connected(&Fixture::healthy());
        app.apply(
            push(StatusUpdateEvent::ProtectionCoverageChanged {
                reason: "machine-wide-cut-by-another-user".into(),
            }),
            &t,
            Instant::now(),
        );
        assert_eq!(app.notices.len(), 1);
        assert_eq!(app.notices[0].level, NoticeLevel::Warning);
        assert_eq!(app.notices[0].title, "Leak protection coverage changed");
        assert!(
            app.notices[0]
                .body
                .starts_with("Another user of this computer"),
            "{:?}",
            app.notices[0]
        );
        app.apply(
            push(StatusUpdateEvent::ProtectionCoverageChanged {
                reason: "zz-unknown".into(),
            }),
            &t,
            Instant::now(),
        );
        assert_eq!(app.notices.len(), 1, "an unknown reason has nothing to say");
    }

    /// A setting another surface changed is re-read while its section is on
    /// screen, and left alone while the user is typing into it.
    #[test]
    fn a_settings_change_elsewhere_reloads_the_open_section() {
        let t = texts();
        let mut app = connected(&Fixture::healthy());
        app.open(ScreenId::Settings);
        crate::screens::settings::open_category(&mut app, SettingsCategory::FailurePolicy);
        app.outbox.take();

        app.apply(
            push(StatusUpdateEvent::RetentionSettingsChanged),
            &t,
            Instant::now(),
        );
        assert!(
            app.outbox.take().is_empty(),
            "retention lives in another section"
        );
        app.apply(
            push(StatusUpdateEvent::ApplyFailurePolicyChanged {
                policy: "best-effort".into(),
            }),
            &t,
            Instant::now(),
        );
        assert_eq!(app.outbox.take().len(), 1, "the open section is re-read");

        app.settings.mode = crate::screens::settings::Mode::Editing {
            buffer: String::new(),
        };
        app.apply(
            push(StatusUpdateEvent::ApplyFailurePolicyChanged {
                policy: "best-effort".into(),
            }),
            &t,
            Instant::now(),
        );
        assert!(
            app.outbox.take().is_empty(),
            "a read must not land under the user's edit"
        );
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

    /// The system DNS left redirected is said once while it lasts, whether the
    /// push or a snapshot brings it, and again once it clears and comes back.
    #[test]
    fn the_system_dns_notice_is_raised_once_per_occurrence() {
        let t = texts();
        let mut app = AppState::new(ScreenId::Status, false);
        app.apply(BackendEvent::Link(Link::Connected), &t, Instant::now());
        let not_restored = || {
            let mut snapshot = Fixture::healthy().snapshot();
            snapshot.health.components = vec![nrr_shared::ipc_payloads::HealthComponentResponse {
                component: "apply".into(),
                severity: "degraded".into(),
                message: Some(format!(
                    "{}: access denied",
                    nrr_shared::ipc_payloads::SYSTEM_DNS_NOT_RESTORED
                )),
            }];
            BackendEvent::Snapshot(Box::new(snapshot))
        };

        app.apply(
            push(StatusUpdateEvent::SystemDnsNotRestored),
            &t,
            Instant::now(),
        );
        app.apply(not_restored(), &t, Instant::now());
        app.apply(
            push(StatusUpdateEvent::SystemDnsNotRestored),
            &t,
            Instant::now(),
        );
        assert_eq!(app.notices.len(), 1);
        assert_eq!(app.notices[0].level, NoticeLevel::Warning);

        app.apply(
            BackendEvent::Snapshot(Box::new(Fixture::healthy().snapshot())),
            &t,
            Instant::now(),
        );
        app.apply(not_restored(), &t, Instant::now());
        assert_eq!(app.notices.len(), 2, "cleared, then back: news again");
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
