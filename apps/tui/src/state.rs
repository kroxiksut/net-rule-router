//! What the interface knows and where the user is. Both renderers draw from
//! this; only [`AppState::apply`] and the key handlers change it.

use std::collections::BTreeMap;
use std::time::Instant;

use nrr_shared::display_text::display_text;
use nrr_shared::ipc_payloads::{
    EnforcementStatusDto, RoutesHeldDto, SnapshotInitialResponse, StatusUpdateEvent,
};

use crate::backend::{BackendEvent, Outbox, PushEvent};
use crate::feed::About;
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
    /// Its place in the order of arrival, from 1: the number the feed shows
    /// and line mode's commands name, unchanged while newer ones arrive.
    pub id: usize,
    pub level: NoticeLevel,
    pub title: String,
    pub body: String,
    /// The body with the addresses it names left out, for "hide addresses".
    pub private_body: Option<String>,
    pub about: crate::feed::About,
}

impl Notice {
    pub fn new(level: NoticeLevel, title: String, body: String) -> Self {
        Self {
            id: 0,
            level,
            title,
            body,
            private_body: None,
            about: crate::feed::About::Nothing,
        }
    }

    pub fn about(mut self, about: crate::feed::About) -> Self {
        self.about = about;
        self
    }

    pub fn private(mut self, body: String) -> Self {
        self.private_body = Some(body);
        self
    }

    /// The body as it may be shown now.
    pub fn shown_body(&self, hide_addresses: bool) -> &str {
        match &self.private_body {
            Some(private) if hide_addresses => private,
            _ => &self.body,
        }
    }
}

/// The service's report that a role's rules are not in force.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnforcementDown {
    pub status: String,
    pub candidates: Vec<String>,
    /// Not up since the service started and still within the start-up wait:
    /// shown, never announced, and its end is no news either.
    pub quiet: bool,
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
    /// Another signed-in user's connection that carries what this user's
    /// rules do not route, as the service names it (empty when it could not).
    pub traffic_carried: Option<String>,
    /// The system-DNS notice is up for the state as it stands.
    pub system_dns_notice_raised: bool,
    /// The notice that this user's saved rules do not read is up.
    pub rules_book_notice_raised: bool,
    /// The notice that a rule set changed outside the app was refused is up.
    pub revision_integrity_raised: bool,
    /// Selective routing over a VPN-like adapter has been explained this run.
    pub vpn_split_told: bool,
    /// The notice that a work VPN lets only its own DNS answer is up.
    pub dns_foreign_notice_raised: bool,
    /// The service has been seen running since this program started.
    pub service_was_running: bool,
    /// The service stopped on its own and the notice is up for it.
    pub service_loss_raised: bool,
    /// Which side is behind on the wire contract; the client refuses writes across it.
    pub contract_skew: Option<nrr_shared::ipc::ContractSkew>,
    /// The user's settings file could not be read: this run is on defaults.
    pub settings_unreadable: bool,
    /// This session alone does not get the rules applied (SSH without a
    /// Windows sign-in). Read once at start, never from tests' environment.
    pub rules_need_a_sign_in: bool,
    /// Parts of the package this copy lacks (`presets`, `locales`).
    pub delivery_gaps: Vec<&'static str>,
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
    /// The application routes screen's scan and choices.
    pub app_groups: crate::screens::app_groups::AppGroups,
    pub interfaces: crate::screens::interfaces::InterfacesState,
    pub wizard: crate::screens::wizard::WizardState,
    /// The rules screen's list, edits and apply.
    pub rules: crate::screens::rules::RulesState,
    /// A language the user picked; the loop reloads the texts in it.
    pub language_change: Option<String>,
    /// Something the service reports in the snapshot (conflicts, enforcement)
    /// changed under this session; the loop reads the snapshot again.
    pub snapshot_refresh_due: bool,
    /// Since when the snapshots have said the service holds rules but applies
    /// none; the Status line waits for it to hold.
    pub policy_idle_since: Option<Instant>,
    /// "Restore my settings": what a service that lost them lacks.
    pub restore: crate::restore::RestoreState,
    /// The Settings screen's sections, what they read and the terminal's own
    /// saved options.
    pub settings: crate::screens::settings::SettingsState,
    /// VPN-named programs leak protection does not trust by place, awaiting
    /// the user's word.
    pub vpn_trust: crate::vpn_trust::VpnTrustState,
    /// Another VPN's servers leak protection stopped, and those let through.
    pub vpn_gateway_trust: crate::vpn_gateway_trust::VpnGatewayTrustState,
    pub primary_suggestion: crate::primary_suggestion::PrimarySuggestionState,
    /// Blocks kept while no surface was open, read on connect.
    pub block_backlog: crate::block_backlog::BlockBacklogState,
    /// Rule-set loads applied or not, told in the feed on the next tick.
    pub rule_set_load: crate::rule_set_load::RuleSetLoadState,
    /// Blocked sites offered "To additional route", and the question asked.
    pub block_route: crate::block_route::BlockRouteState,
    pub local_network_offer: crate::local_network_offer::LocalNetworkOfferState,
    pub app_groups_offer: crate::app_groups_offer::AppGroupsOfferState,
    pub vpn_client_offer: crate::vpn_client_offer::VpnClientOfferState,
    /// When the feed last told that a site does not open, and of which.
    pub site_notices: crate::site_notices::SiteNoticeLog,
    /// What the window holds for a service that was not running.
    pub window_parked: Option<crate::window_parked::WindowParked>,
    pub forwarded_traffic: crate::forwarded_traffic::ForwardedTrafficState,
    /// The notice kinds the user silenced on any surface.
    pub notice_mutes: crate::notice_mutes::NoticeMutesState,
    /// The notice chosen in the feed and the question asked about it.
    pub feed: crate::feed::FeedState,
}

impl AppState {
    pub fn new(screen: ScreenId, bell: bool) -> Self {
        Self {
            link: Link::Connecting,
            snapshot: None,
            fetch_error: None,
            enforcement_down: BTreeMap::new(),
            routes_held: None,
            traffic_carried: None,
            system_dns_notice_raised: false,
            rules_book_notice_raised: false,
            revision_integrity_raised: false,
            vpn_split_told: false,
            dns_foreign_notice_raised: false,
            service_was_running: false,
            service_loss_raised: false,
            contract_skew: None,
            notices: Vec::new(),
            notice_count: 0,
            settings_unreadable: false,
            rules_need_a_sign_in: false,
            delivery_gaps: Vec::new(),
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
            app_groups: Default::default(),
            interfaces: crate::screens::interfaces::InterfacesState::default(),
            wizard: crate::screens::wizard::WizardState::default(),
            rules: crate::screens::rules::RulesState::default(),
            language_change: None,
            snapshot_refresh_due: false,
            policy_idle_since: None,
            restore: crate::restore::RestoreState::default(),
            settings: crate::screens::settings::SettingsState::default(),
            vpn_trust: crate::vpn_trust::VpnTrustState::default(),
            vpn_gateway_trust: Default::default(),
            primary_suggestion: crate::primary_suggestion::PrimarySuggestionState::default(),
            block_backlog: Default::default(),
            rule_set_load: Default::default(),
            block_route: Default::default(),
            local_network_offer: Default::default(),
            app_groups_offer: Default::default(),
            vpn_client_offer: Default::default(),
            site_notices: Default::default(),
            window_parked: None,
            forwarded_traffic: Default::default(),
            notice_mutes: Default::default(),
            feed: Default::default(),
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
        // The agreement comes before any other screen.
        if screen != ScreenId::Wizard && self.wizard.licence_pending() {
            return;
        }
        if self.screen != screen {
            self.screen = screen;
            self.scroll = 0;
            if screen == ScreenId::Wizard {
                crate::screens::rules::offer::setup_shown(self);
            }
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
                if !link.is_connected() {
                    // A service coming back gets the whole settle window again.
                    self.policy_idle_since = None;
                }
                self.link = link;
                // The window sends what it parked once it reaches the service.
                crate::window_parked::refresh(self);
                let loss = self.service_loss_reading(texts, now);
                if reconnected {
                    // Read before the backlog, so its summary meets the mutes.
                    crate::notice_mutes::load(self);
                    crate::restore::on_connected(self);
                    crate::screens::rules::verdicts::load(self);
                    crate::block_backlog::drain(self);
                    crate::local_network_offer::check(self);
                    crate::app_groups_offer::check(self);
                    crate::screens::inspect::diagnostics::on_reconnected(self);
                    crate::screens::inspect::cache::on_reconnected(self);
                    crate::screens::screen(self.screen).on_show(self);
                }
                loss
            }
            BackendEvent::Reply(reply) => {
                (reply.0)(self);
                let mut effects = crate::restore::announce(self, texts, now);
                let later = crate::screens::rules::verdicts::announce(self, texts, now)
                    .into_iter()
                    .chain(crate::vpn_trust::announce(self, texts, now))
                    .chain(crate::vpn_gateway_trust::announce(self, texts, now))
                    .chain(crate::primary_suggestion::announce(self, texts, now))
                    .chain(crate::block_backlog::announce(self, texts, now))
                    .chain(crate::rule_set_load::announce(self, texts, now))
                    .chain(crate::screens::suggestions::announce(self, texts))
                    .chain(crate::block_route::announce(self, texts, now))
                    .chain(crate::feed::announce(self, texts, now))
                    .chain(crate::local_network_offer::announce(self, texts, now))
                    .chain(crate::app_groups_offer::announce(self, texts, now))
                    .chain(crate::vpn_client_offer::announce(self, texts, now))
                    .chain(crate::screens::wizard::announce(self, texts, now));
                if std::mem::take(&mut self.snapshot_refresh_due) {
                    effects.push(Effect::Refresh);
                }
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
                let carried = snapshot
                    .traffic_carried_by_another_user
                    .as_ref()
                    .filter(|report| report.carried)
                    .map(|report| report.link.clone());
                let rules_book_unreadable = snapshot.rules_book_unreadable;
                let revision_rejected = crate::screens::revision_rejected(&snapshot);
                let vpn_split = crate::screens::vpn_split(&snapshot);
                self.vpn_trust.pending = snapshot.pending_vpn_clients.clone();
                self.vpn_gateway_trust.pending = snapshot.pending_vpn_gateways.clone();
                self.vpn_gateway_trust.confirmed = snapshot.confirmed_vpn_gateways.clone();
                self.snapshot = Some(*snapshot);
                crate::screens::track_policy_idle(self, now);
                crate::screens::rules::overrides::on_snapshot(self);
                self.fetch_error = None;
                crate::screens::wizard::snapshot_arrived(self);
                crate::restore::on_snapshot(self);
                let dns_not_restored = self
                    .snapshot
                    .as_ref()
                    .and_then(|s| serde_json::to_value(&s.health).ok())
                    .is_some_and(|health| nrr_client_logic::system_dns::not_restored(&health));
                let dns_foreign_only = self
                    .snapshot
                    .as_ref()
                    .and_then(|s| serde_json::to_value(&s.health).ok())
                    .is_some_and(|health| {
                        nrr_client_logic::system_dns::upstream_foreign_only(&health)
                    });
                let mut effects = self.apply_standing_enforcement(reports, texts, now);
                for effect in self
                    .routes_held_changed(held, texts, now)
                    .into_iter()
                    .chain(self.traffic_carried_changed(carried, texts, now))
                    .chain(self.system_dns_reading(dns_not_restored, texts, now))
                    .chain(self.rules_book_reading(rules_book_unreadable, texts, now))
                    .chain(self.revision_integrity_reading(revision_rejected, texts, now))
                    .chain(self.vpn_split_reading(vpn_split, texts, now))
                    .chain(self.dns_foreign_reading(dns_foreign_only, texts, now))
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
            BackendEvent::Push(PushEvent::Gap) => {
                self.reread_after_gap();
                vec![Effect::Refresh]
            }
            BackendEvent::Push(PushEvent::Status(event)) => self.apply_push(*event, texts, now),
        }
    }

    /// A hole in the push stream: what the lost pushes would have changed is
    /// read again, beside the snapshot the caller asks for.
    fn reread_after_gap(&mut self) {
        crate::screens::rules::on_revision_changed(self);
        crate::screens::rules::verdicts::load(self);
        crate::screens::suggestions::reload_if_in_use(self);
        crate::screens::inspect::diagnostics::reload_alerts(self);
        if let Some(category) = self.settings.open {
            crate::screens::settings::reload_if_open(self, category);
        }
    }

    fn apply_push(&mut self, event: StatusUpdateEvent, texts: &Texts, now: Instant) -> Vec<Effect> {
        match event {
            StatusUpdateEvent::EnforcementStatusChanged {
                status,
                role,
                candidates,
                quiet,
                ..
            } => {
                // The leak-guard banner is read from the snapshot, and a link
                // coming back moves no adapter: re-read it, as the GUI does.
                let restored = status.is_empty() || status == "ok";
                let mut effects =
                    self.enforcement_changed(status, role, candidates, quiet, texts, now);
                if restored && !effects.contains(&Effect::Refresh) {
                    effects.push(Effect::Refresh);
                }
                effects
            }
            StatusUpdateEvent::RoutingPauseStateChanged {
                paused,
                paused_at,
                resumes_at_ms,
                until_restart,
                ..
            } => {
                if let Some(snapshot) = self.snapshot.as_mut() {
                    snapshot.routing_paused = paused;
                    snapshot.routing_paused_at = paused_at.filter(|_| paused);
                    snapshot.routing_pause_resumes_at_ms = resumes_at_ms;
                    snapshot.routing_pause_until_restart = until_restart;
                }
                Vec::new()
            }
            StatusUpdateEvent::VerifyVerdictsChanged { .. } => {
                crate::screens::rules::verdicts::load(self);
                Vec::new()
            }
            StatusUpdateEvent::RuleOverridesChanged { expired, cause, .. } => {
                // The marks follow the snapshot; an end or a withdrawal is said.
                let mut effects = vec![Effect::Refresh];
                effects.extend(crate::screens::rules::overrides::announce_ended(
                    self, &expired, &cause, texts, now,
                ));
                effects
            }
            StatusUpdateEvent::RoutesHeldByAnotherUser { count, sample, .. } => {
                let held = (count > 0).then_some(RoutesHeldDto { count, sample });
                self.routes_held_changed(held, texts, now)
            }
            StatusUpdateEvent::TrafficCarriedByAnotherUser { carried, link, .. } => {
                self.traffic_carried_changed(carried.then_some(link), texts, now)
            }
            StatusUpdateEvent::SystemDnsNotRestored => self.system_dns_reading(true, texts, now),
            StatusUpdateEvent::RulesBookUnreadable { unreadable, .. } => {
                self.rules_book_reading(unreadable, texts, now)
            }
            StatusUpdateEvent::HostUnreachableOnBothRoutes { host, .. } => {
                let shown = display_text(&host).into_owned();
                let notice = Notice::new(
                    NoticeLevel::Info,
                    texts.get(keys::HOST_UNREACHABLE_TITLE),
                    texts.fill(keys::HOST_UNREACHABLE_BODY, &[("host", &shown)]),
                )
                .about(About::Site(host));
                self.post(notice, Some(now))
            }
            StatusUpdateEvent::LinkKeepsDropping { role, .. } => {
                if crate::notice_mutes::muted(self, "link-keeps-dropping") {
                    return Vec::new();
                }
                let title = if role == "primary" {
                    keys::LINK_DROPPING_TITLE_PRIMARY
                } else {
                    keys::LINK_DROPPING_TITLE_SECONDARY
                };
                let notice = Notice::new(
                    NoticeLevel::Warning,
                    texts.get(title),
                    texts.get(keys::LINK_DROPPING_BODY),
                )
                .about(About::Kind("link-keeps-dropping"));
                self.post(notice, Some(now))
            }
            // The interfaces list reads the address off the rows, where the
            // service filed it before pushing: re-read them. A reconnect inside
            // the service's quiet period is not announced.
            StatusUpdateEvent::SecondaryExternalAddressObserved { quiet: true, .. }
            | StatusUpdateEvent::SecondaryExternalAddressCleared { .. } => vec![Effect::Refresh],
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
                    body.push_str(&texts.fill(
                        keys::EXTERNAL_ADDRESS_ADAPTER,
                        &[("name", display_text(&adapter_name))],
                    ));
                }
                // A muted notice still leaves the rows to follow.
                if crate::notice_mutes::muted(self, "external-address") {
                    return vec![Effect::Refresh];
                }
                let notice = Notice::new(
                    NoticeLevel::Info,
                    texts.get(keys::EXTERNAL_ADDRESS_TITLE),
                    body,
                )
                .about(About::Kind("external-address"));
                let mut effects = self.post(notice, None);
                if !effects.contains(&Effect::Refresh) {
                    effects.push(Effect::Refresh);
                }
                effects
            }
            StatusUpdateEvent::AdaptersChanged { .. } => vec![Effect::Refresh],
            StatusUpdateEvent::AutoRuleCandidatesChanged {
                pending_count,
                top_anchor,
                announces,
                ..
            } => {
                match crate::screens::suggestions::changed(
                    self,
                    pending_count,
                    announces,
                    &top_anchor,
                    texts,
                ) {
                    Some((title, body)) => self.note_in_feed(NoticeLevel::Info, title, body),
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
                vec![Effect::Refresh]
            }
            StatusUpdateEvent::BlockNoticeRaised {
                destination,
                app,
                reason,
                attempts,
                ..
            } => {
                crate::block_route::offer(self, &destination, &reason);
                let app_name = if app.is_empty() {
                    texts.get(keys::BLOCK_NOTICE_APP_UNKNOWN)
                } else {
                    display_text(&app).into_owned()
                };
                let reason_text = block_reason_text(&reason, texts);
                let attempts = attempts.to_string();
                let body = |shown: &str| {
                    texts.fill(
                        keys::BLOCK_NOTICE_BODY,
                        &[
                            ("reason", reason_text.as_str()),
                            ("destination", shown),
                            ("app", app_name.as_str()),
                            ("attempts", attempts.as_str()),
                        ],
                    )
                };
                let shown = body(&display_text(&destination));
                let private = body(&texts.get(keys::BLOCK_NOTICE_DESTINATION_HIDDEN));
                let notice = Notice::new(
                    NoticeLevel::Warning,
                    texts.get(keys::BLOCK_NOTICE_TITLE),
                    shown,
                )
                .private(private)
                .about(About::Block(crate::feed::BlockSubject {
                    destination,
                    app,
                    reason,
                }));
                self.post(notice, Some(now))
            }
            StatusUpdateEvent::UnassignedTunnelDetected { adapter_name, .. } => {
                if adapter_name.is_empty() || crate::notice_mutes::muted(self, "unassigned-tunnel")
                {
                    return Vec::new();
                }
                let body = texts.fill(
                    keys::UNASSIGNED_TUNNEL_BODY,
                    &[("adapter", display_text(&adapter_name))],
                );
                let notice = Notice::new(
                    NoticeLevel::Warning,
                    texts.get(keys::UNASSIGNED_TUNNEL_TITLE),
                    body,
                )
                .about(About::Kind("unassigned-tunnel"));
                self.post(notice, Some(now))
            }
            StatusUpdateEvent::AdditionalConnectionMoved { adapter_name, .. } => {
                if adapter_name.is_empty() {
                    return Vec::new();
                }
                self.notify(
                    NoticeLevel::Info,
                    texts.get(keys::ADDITIONAL_MOVED_TITLE),
                    texts.fill(
                        keys::ADDITIONAL_MOVED_BODY,
                        &[("adapter", display_text(&adapter_name))],
                    ),
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
                        ("adapter", display_text(&adapter_name)),
                        ("network", display_text(&network)),
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
                texts.fill(keys::APP_RULE_LEARNING_BODY, &[("apps", shown_list(&apps))]),
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
            // As above; a withdrawn question may have been answered elsewhere,
            // so the snapshot read brings the allowed list up to date.
            StatusUpdateEvent::VpnGatewayAwaitingConfirmation { gateways, .. } => {
                let sentences = crate::vpn_gateway_trust::sentences(&gateways, texts);
                self.vpn_gateway_trust.pending = gateways;
                if sentences.is_empty() {
                    vec![Effect::Refresh]
                } else {
                    self.notify(
                        NoticeLevel::Warning,
                        texts.get(crate::vpn_gateway_trust::TITLE),
                        sentences.join(" "),
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
                crate::screens::wizard::alerts_changed(self);
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
                crate::notice_mutes::load(self);
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
                .map_or(("ok", false), |down| (down.status.as_str(), down.quiet));
            let status = if report.status.is_empty() {
                "ok"
            } else {
                report.status.as_str()
            };
            if held == (status, report.quiet && status != "ok") {
                continue;
            }
            for effect in self.enforcement_changed(
                report.status,
                report.role,
                report.candidates,
                report.quiet,
                texts,
                now,
            ) {
                if !effects.contains(&effect) {
                    effects.push(effect);
                }
            }
        }
        effects
    }

    /// The service stopped though nobody asked for it: said once, with the
    /// commands that start it and restore the network.
    fn service_loss_reading(&mut self, texts: &Texts, now: Instant) -> Vec<Effect> {
        let slug = match self.link {
            Link::Connected => "running",
            Link::Stopped => "stopped",
            _ => "unknown",
        };
        if slug == "running" {
            self.service_was_running = true;
        }
        let can_restore = nrr_shared::platform_profile::PlatformProfile::current()
            .supports
            .kill_switch;
        let step = nrr_client_logic::service_loss::step(
            self.service_loss_raised,
            slug,
            self.service_was_running,
            crate::link::stop_was_expected(),
            can_restore,
        );
        self.service_loss_raised = step.raised;
        if !step.raise {
            return Vec::new();
        }
        let mut body = texts.get(keys::SERVICE_LOST_BODY);
        for line in crate::screens::recovery_hints(texts, can_restore) {
            body.push(' ');
            body.push_str(&line);
        }
        self.notify(
            NoticeLevel::Warning,
            texts.get(keys::SERVICE_LOST_TITLE),
            body,
            now,
        )
    }

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

    /// This user's saved rules do not read: said once while it lasts, with
    /// where the details are; its end is news too.
    fn rules_book_reading(&mut self, unreadable: bool, texts: &Texts, now: Instant) -> Vec<Effect> {
        let was_raised = self.rules_book_notice_raised;
        let step = nrr_client_logic::diagnostics::rules_book_notice_step(was_raised, unreadable);
        self.rules_book_notice_raised = step.raised;
        if step.raise {
            let mut body = texts.get(keys::RULES_BOOK_BODY);
            body.push(' ');
            body.push_str(&texts.get(keys::SEE_DIAGNOSTICS_HINT));
            return self.notify(
                NoticeLevel::Warning,
                texts.get(keys::RULES_BOOK_TITLE),
                body,
                now,
            );
        }
        if was_raised && !step.raised {
            return self.notify(
                NoticeLevel::Info,
                texts.get(keys::RULES_BOOK_TITLE),
                texts.get(keys::RULES_BOOK_CLEARED),
                now,
            );
        }
        Vec::new()
    }

    /// A rule set refused for changing outside the app: said when the alert
    /// appears; the status keeps it standing until it is acknowledged.
    fn revision_integrity_reading(
        &mut self,
        rejected: bool,
        texts: &Texts,
        now: Instant,
    ) -> Vec<Effect> {
        let was_raised = std::mem::replace(&mut self.revision_integrity_raised, rejected);
        if !rejected || was_raised {
            return Vec::new();
        }
        let mut body = texts.get(keys::REVISION_INTEGRITY);
        body.push(' ');
        body.push_str(&texts.get(keys::SEE_DIAGNOSTICS_HINT));
        self.notify(
            NoticeLevel::Warning,
            texts.get(keys::REVISION_INTEGRITY_TITLE),
            body,
            now,
        )
    }

    /// Explained once a run: it describes routing working as asked.
    fn vpn_split_reading(
        &mut self,
        split: Option<(String, usize)>,
        texts: &Texts,
        now: Instant,
    ) -> Vec<Effect> {
        let Some((name, count)) = split.filter(|_| !self.vpn_split_told) else {
            return Vec::new();
        };
        self.vpn_split_told = true;
        let body = nrr_client_logic::placeholders::fill_placeholders(
            &texts.counted(keys::VPN_SPLIT_COUNTED, count),
            [("name", name.as_str())],
        );
        self.notify(
            NoticeLevel::Info,
            texts.get(keys::VPN_SPLIT_TITLE),
            body,
            now,
        )
    }

    /// A work VPN that lets only its own DNS answer: said when it appears, not
    /// repeated while it lasts.
    fn dns_foreign_reading(
        &mut self,
        foreign_only: bool,
        texts: &Texts,
        now: Instant,
    ) -> Vec<Effect> {
        let step = nrr_client_logic::system_dns::foreign_only_notice_step(
            self.dns_foreign_notice_raised,
            foreign_only,
        );
        self.dns_foreign_notice_raised = step.raised;
        if !step.raise {
            return Vec::new();
        }
        self.notify(
            NoticeLevel::Warning,
            texts.get(keys::DNS_FOREIGN_TITLE),
            texts.get(keys::DNS_FOREIGN_BODY),
            now,
        )
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
        if crate::notice_mutes::muted(self, "routes-held") {
            return Vec::new();
        }
        let notice = match held {
            Some(held) => {
                let (title, body) = routes_held_text(&held, texts);
                Notice::new(NoticeLevel::Warning, title, body)
            }
            None if was_held => Notice::new(
                NoticeLevel::Info,
                texts.get(keys::ROUTES_HELD_TITLE),
                texts.get(keys::ROUTES_HELD_CLEARED),
            ),
            None => return Vec::new(),
        };
        self.post(notice.about(About::Kind("routes-held")), Some(now))
    }

    /// Another user's tunnel carries this user's unrouted traffic, or stopped
    /// carrying it; like the held destinations, a repeat is not news.
    fn traffic_carried_changed(
        &mut self,
        link: Option<String>,
        texts: &Texts,
        now: Instant,
    ) -> Vec<Effect> {
        if self.traffic_carried == link {
            return Vec::new();
        }
        let was_carried = self.traffic_carried.is_some();
        self.traffic_carried = link.clone();
        if crate::notice_mutes::muted(self, "traffic-carried") {
            return Vec::new();
        }
        let notice = match link {
            Some(link) => {
                let (title, body) = traffic_carried_text(&link, texts);
                Notice::new(NoticeLevel::Warning, title, body)
            }
            None if was_carried => Notice::new(
                NoticeLevel::Info,
                texts.get(keys::TRAFFIC_CARRIED_TITLE),
                texts.get(keys::TRAFFIC_CARRIED_CLEARED),
            ),
            None => return Vec::new(),
        };
        self.post(notice.about(About::Kind("traffic-carried")), Some(now))
    }

    /// A standing state per role: a later report replaces it, `ok` ends it.
    fn enforcement_changed(
        &mut self,
        status: String,
        role: String,
        candidates: Vec<String>,
        quiet: bool,
        texts: &Texts,
        now: Instant,
    ) -> Vec<Effect> {
        if status.is_empty() || status == "ok" {
            // The additional link just came up: its VPN client may be unset.
            if role == "secondary" && self.enforcement_down.contains_key(&role) {
                crate::vpn_client_offer::check(self);
            }
            if self.enforcement_down.remove(&role).is_some_and(|down| {
                !down.quiet && nrr_client_logic::enforcement_notice::restore_is_news(&down.status)
            }) && !crate::notice_mutes::muted(self, "enforcement-restored")
            {
                let mut body = texts.get(keys::ENF_RESTORED_BODY);
                // What leak protection held back meanwhile has a list of its own.
                if role == "secondary" {
                    let screen = texts.get(ScreenId::OutageBlocks.title());
                    let pointer = texts.fill(keys::ENF_RESTORED_WHERE, &[("screen", screen)]);
                    body.push(' ');
                    body.push_str(&pointer);
                }
                let notice =
                    Notice::new(NoticeLevel::Info, texts.get(keys::ENF_RESTORED_TITLE), body)
                        .about(About::Kind("enforcement-restored"));
                return self.post(notice, Some(now));
            }
            return Vec::new();
        }
        let leak_protection = self
            .snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.route_policy.as_ref())
            .map_or("", |policy| policy.leak_protection.as_slug());
        let (title, body) =
            enforcement_text_for(&status, &role, &candidates, leak_protection, texts);
        // A switched-off tunnel is the one fault here the user may silence.
        let routine = status == "secondary-down" && role != "primary";
        self.enforcement_down.insert(
            role,
            EnforcementDown {
                status,
                candidates,
                quiet,
            },
        );
        if quiet || (routine && crate::notice_mutes::muted(self, "secondary-down")) {
            return Vec::new();
        }
        let notice = Notice::new(NoticeLevel::Warning, title, body);
        let notice = if routine {
            notice.about(About::Kind("secondary-down"))
        } else {
            notice
        };
        self.post(notice, Some(now))
    }

    /// Into the feed only: no footer line, no bell. For news that matters
    /// when looked for, not when it happens.
    pub(crate) fn note_in_feed(
        &mut self,
        level: NoticeLevel,
        title: String,
        body: String,
    ) -> Vec<Effect> {
        self.post(Notice::new(level, title, body), None)
    }

    pub(crate) fn notify(
        &mut self,
        level: NoticeLevel,
        title: String,
        body: String,
        now: Instant,
    ) -> Vec<Effect> {
        self.post(Notice::new(level, title, body), Some(now))
    }

    /// Into the feed; with `now` also on the bottom line and with the bell.
    pub(crate) fn post(&mut self, mut notice: Notice, now: Option<Instant>) -> Vec<Effect> {
        self.notice_count += 1;
        notice.id = self.notice_count;
        self.notices.push(notice);
        if self.notices.len() > FEED_CAPACITY {
            let excess = self.notices.len() - FEED_CAPACITY;
            self.notices.drain(..excess);
        }
        let Some(now) = now else {
            return Vec::new();
        };
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

/// The GUI's wording for traffic another signed-in user's tunnel carries,
/// naming the connection when the service could.
pub fn traffic_carried_text(link: &str, texts: &Texts) -> (String, String) {
    let body = if link.is_empty() {
        texts.get(keys::TRAFFIC_CARRIED_BODY_UNNAMED)
    } else {
        texts.fill(keys::TRAFFIC_CARRIED_BODY, &[("link", display_text(link))])
    };
    (texts.get(keys::TRAFFIC_CARRIED_TITLE), body)
}

/// Names someone else chose, as a comma list fit for the screen.
fn shown_list(names: &[String]) -> String {
    names
        .iter()
        .map(|name| display_text(name))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The GUI's wording for an enforcement report: what happened, and what to do.
/// An unknown status still says the one thing that matters.
pub fn enforcement_text(
    status: &str,
    role: &str,
    candidates: &[String],
    texts: &Texts,
) -> (String, String) {
    enforcement_text_for(status, role, candidates, "", texts)
}

/// [`enforcement_text`] with the user's leak protection, which decides what a
/// tunnel being down means for their traffic.
pub fn enforcement_text_for(
    status: &str,
    role: &str,
    candidates: &[String],
    leak_protection: &str,
    texts: &Texts,
) -> (String, String) {
    let list = shown_list(candidates);
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
            texts.fill(
                match nrr_client_logic::enforcement_notice::adapter_choice_body_key(
                    candidates.len(),
                ) {
                    "notifications.enforcement.adapter-choice.body-one" => {
                        keys::ENF_CHOICE_BODY_ONE
                    }
                    _ => keys::ENF_CHOICE_BODY,
                },
                &[("list", &list)],
            ),
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
        "no-policy" if !candidates.is_empty() => (
            texts.fill(
                keys::ENF_SUGGEST_TITLE,
                &[("name", &*display_text(&candidates[0]))],
            ),
            texts.get(keys::ENF_SUGGEST_BODY),
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
            texts.get(
                match nrr_client_logic::enforcement_notice::secondary_down_body_key(leak_protection)
                {
                    "notifications.enforcement.secondary-down.body-off" => {
                        keys::ENF_SECONDARY_DOWN_BODY_OFF
                    }
                    "notifications.enforcement.secondary-down.body-everything" => {
                        keys::ENF_SECONDARY_DOWN_BODY_EVERYTHING
                    }
                    _ => keys::ENF_SECONDARY_DOWN_BODY,
                },
            ),
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
    use nrr_shared::ipc_payloads::{BehaviorModeDto, TrafficCarriedDto};

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

    fn quiet_enforcement(status: &str, role: &str) -> BackendEvent {
        BackendEvent::Push(PushEvent::Status(Box::new(
            StatusUpdateEvent::EnforcementStatusChanged {
                sid: "S".into(),
                status: status.into(),
                role: role.into(),
                candidates: Vec::new(),
                since_unix_ms: None,
                quiet: true,
            },
        )))
    }

    /// Drops each too short to announce, told once by the service as one
    /// fact about the link, named by its role.
    #[test]
    fn a_link_that_keeps_dropping_is_told_with_its_role() {
        let fixture = Fixture::healthy();
        let mut app = connected(&fixture);
        let t = texts();
        let before = app.notices.len();
        app.apply(
            BackendEvent::Push(PushEvent::Status(Box::new(
                StatusUpdateEvent::LinkKeepsDropping {
                    sid: "S".into(),
                    role: "secondary".into(),
                },
            ))),
            &t,
            Instant::now(),
        );
        assert_eq!(app.notices.len(), before + 1);
        let notice = app.notices.last().expect("told");
        assert_eq!(notice.title, "The additional connection keeps dropping");
        assert!(notice.body.contains("several times"), "{}", notice.body);
    }

    /// The interfaces list reads the external address off the rows, and the
    /// service files what the connect-time check found before it pushes: the
    /// list follows without a manual check, a quiet refill included.
    #[test]
    fn an_observed_external_address_reaches_the_interfaces_list() {
        let fixture = Fixture::healthy();
        let mut app = connected(&fixture);
        let t = texts();
        for quiet in [false, true] {
            let effects = app.apply(
                BackendEvent::Push(PushEvent::Status(Box::new(
                    StatusUpdateEvent::SecondaryExternalAddressObserved {
                        sid: "S".into(),
                        adapter_name: "Tunnel".into(),
                        external_address: "203.0.113.9".into(),
                        quiet,
                    },
                ))),
                &t,
                Instant::now(),
            );
            assert!(
                effects.contains(&Effect::Refresh),
                "quiet={quiet}: the rows are not re-read"
            );
        }
    }

    #[test]
    fn a_route_not_up_yet_at_start_is_shown_but_not_announced() {
        let fixture = Fixture::healthy();
        let mut app = connected(&fixture);
        let t = texts();
        let before = app.notices.len();
        app.apply(
            quiet_enforcement("secondary-down", "secondary"),
            &t,
            Instant::now(),
        );
        assert_eq!(app.routing_state(), RoutingState::Limited);
        assert_eq!(app.notices.len(), before, "quiet at start");
        app.apply(enforcement("ok", "secondary"), &t, Instant::now());
        assert_eq!(app.notices.len(), before, "coming up is no news either");

        app.apply(
            quiet_enforcement("secondary-down", "secondary"),
            &t,
            Instant::now(),
        );
        app.apply(
            enforcement("secondary-down", "secondary"),
            &t,
            Instant::now(),
        );
        assert_eq!(
            app.notices.len(),
            before + 1,
            "the wait is over: one notice"
        );
    }

    fn enforcement(status: &str, role: &str) -> BackendEvent {
        BackendEvent::Push(PushEvent::Status(Box::new(
            StatusUpdateEvent::EnforcementStatusChanged {
                sid: "S".into(),
                status: status.into(),
                role: role.into(),
                candidates: Vec::new(),
                since_unix_ms: None,
                quiet: false,
            },
        )))
    }

    /// Confirming the first main connection applies the rules for the first
    /// time: "routing works again" there would report an outage that never was.
    #[test]
    fn finishing_the_first_setup_is_not_announced_as_a_recovery() {
        let t = texts();
        let mut app = connected(&Fixture::healthy());
        app.apply(enforcement("no-policy", "primary"), &t, Instant::now());
        let before = app.notices.len();
        app.apply(enforcement("ok", "primary"), &t, Instant::now());
        assert_eq!(app.notices.len(), before, "{:?}", app.notices.last());

        app.apply(
            enforcement("no-primary-route", "primary"),
            &t,
            Instant::now(),
        );
        let before = app.notices.len();
        app.apply(enforcement("ok", "primary"), &t, Instant::now());
        assert_eq!(app.notices.len(), before + 1, "a real outage ended");
    }

    /// One adapter named while the saved one is down is a sibling to consider;
    /// "several answer to the saved name" would send the user looking for a
    /// second one that is not there.
    #[test]
    fn one_adapter_to_choose_is_not_called_several() {
        let t = texts();
        let one = ["Ethernet 5".to_owned()];
        let (_, body) = enforcement_text("adapter-choice-needed", "secondary", &one, &t);
        assert!(body.contains("Ethernet 5"), "{body}");
        assert!(!body.contains("Several"), "{body}");
        let two = ["A".to_owned(), "B".to_owned()];
        let (_, body) = enforcement_text("adapter-choice-needed", "secondary", &two, &t);
        assert!(body.contains("Several"), "{body}");
    }

    #[test]
    fn a_suggested_main_connection_is_named_in_the_notice() {
        let t = texts();
        let (title, body) = enforcement_text("no-policy", "", &["Ethernet".to_owned()], &t);
        assert!(title.contains("Ethernet"), "{title}");
        assert!(!body.is_empty());
        let (plain, _) = enforcement_text("no-policy", "", &[], &t);
        let held = |level| enforcement_text_for("secondary-down", "secondary", &[], level, &t).1;
        assert_eq!(held("sites"), t.get(keys::ENF_SECONDARY_DOWN_BODY));
        assert_eq!(
            held("off"),
            t.get(keys::ENF_SECONDARY_DOWN_BODY_OFF),
            "nothing is held"
        );
        assert_eq!(
            held("everything"),
            t.get(keys::ENF_SECONDARY_DOWN_BODY_EVERYTHING),
            "the whole internet waits"
        );
        assert!(!plain.contains("Ethernet"));
        assert_ne!(plain, title);
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
            app.notices[1].body.ends_with(
                "The list of what was blocked: Blocked while the additional connection was down"
            ),
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
            "A rule denies this connection. Destination: cdn.example. Application: messenger.exe. Attempts: 3."
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
        assert_eq!(
            app.notices[0].title,
            "The additional connection is not chosen"
        );
        assert!(
            app.notices[0].body.starts_with("Tunnel is up"),
            "{:?}",
            app.notices[0]
        );
        assert_eq!(app.notices[1].title, "A rule is set on both connections");
        assert!(
            app.notices[1].body.starts_with(
                "2 of your rules are enabled on both connections, starting with both.example."
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
            "Some addresses follow another user's connection"
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
            "Addresses from your rules follow your own connection again."
        );
        assert!(app.routes_held.is_none());
    }

    fn carried(carried: bool, link: &str) -> BackendEvent {
        BackendEvent::Push(PushEvent::Status(Box::new(
            StatusUpdateEvent::TrafficCarriedByAnotherUser {
                sid: "S".into(),
                carried,
                link: link.into(),
            },
        )))
    }

    /// Another user's tunnel carrying this user's traffic is told once, by the
    /// connection's name, whether the push or a snapshot brings it; its end
    /// is news too.
    #[test]
    fn traffic_carried_by_another_user_is_told_once_and_its_end_too() {
        let t = texts();
        let mut app = connected(&Fixture::healthy());
        app.apply(carried(true, "Office Tunnel"), &t, Instant::now());
        assert_eq!(app.notices.len(), 1);
        assert_eq!(app.notices[0].level, NoticeLevel::Warning);
        assert_eq!(
            app.notices[0].title,
            "Your traffic goes through another user's connection"
        );
        assert!(
            app.notices[0].body.contains("through \"Office Tunnel\"."),
            "{:?}",
            app.notices[0]
        );
        assert_eq!(app.routing_state(), RoutingState::Active);

        let mut snapshot = Fixture::healthy().snapshot();
        snapshot.traffic_carried_by_another_user = Some(TrafficCarriedDto {
            carried: true,
            link: "Office Tunnel".into(),
        });
        app.apply(
            BackendEvent::Snapshot(Box::new(snapshot)),
            &t,
            Instant::now(),
        );
        assert_eq!(app.notices.len(), 1, "the same state is not news");

        app.apply(carried(false, ""), &t, Instant::now());
        assert_eq!(app.notices.len(), 2);
        assert_eq!(app.notices[1].level, NoticeLevel::Info);
        assert_eq!(
            app.notices[1].body,
            "Your traffic no longer goes through another user's connection."
        );
        assert!(app.traffic_carried.is_none());
    }

    /// A terminal opened later learns it from the snapshot, and a later
    /// snapshot without it ends it.
    #[test]
    fn a_late_terminal_learns_carried_traffic_from_the_snapshot() {
        let t = texts();
        let mut app = AppState::new(ScreenId::Status, false);
        app.apply(BackendEvent::Link(Link::Connected), &t, Instant::now());
        let mut snapshot = Fixture::healthy().snapshot();
        snapshot.traffic_carried_by_another_user = Some(TrafficCarriedDto {
            carried: true,
            link: String::new(),
        });
        app.apply(
            BackendEvent::Snapshot(Box::new(snapshot)),
            &t,
            Instant::now(),
        );
        assert_eq!(app.notices.len(), 1);
        assert!(
            app.notices[0]
                .body
                .contains("through their own connection (for example a VPN)."),
            "{:?}",
            app.notices[0]
        );

        app.apply(
            BackendEvent::Snapshot(Box::new(Fixture::healthy().snapshot())),
            &t,
            Instant::now(),
        );
        assert_eq!(app.notices.len(), 2);
        assert_eq!(app.notices[1].level, NoticeLevel::Info);
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

    /// This user's unreadable saved rules are one feed line while they last,
    /// whether the push or a snapshot brings it; reading again is a line too,
    /// and the next occurrence is news again.
    #[test]
    fn an_unreadable_rule_book_is_one_line_per_occurrence() {
        let t = texts();
        let mut app = AppState::new(ScreenId::Status, false);
        app.apply(BackendEvent::Link(Link::Connected), &t, Instant::now());
        let book = |unreadable: bool| {
            push(StatusUpdateEvent::RulesBookUnreadable {
                sid: "S".into(),
                unreadable,
            })
        };
        let unreadable_snapshot = || {
            let mut snapshot = Fixture::healthy().snapshot();
            snapshot.rules_book_unreadable = true;
            BackendEvent::Snapshot(Box::new(snapshot))
        };

        app.apply(book(true), &t, Instant::now());
        app.apply(unreadable_snapshot(), &t, Instant::now());
        app.apply(book(true), &t, Instant::now());
        assert_eq!(app.notices.len(), 1);
        assert_eq!(app.notices[0].level, NoticeLevel::Warning);
        assert_eq!(app.notices[0].title, "Your saved rules cannot be read");
        assert!(
            app.notices[0].body.starts_with(
                "Your saved rules cannot be read; the last applied rules stay in force."
            ),
            "{:?}",
            app.notices[0]
        );
        assert!(
            app.notices[0].body.contains("Diagnostics and logs"),
            "{:?}",
            app.notices[0]
        );

        app.apply(
            BackendEvent::Snapshot(Box::new(Fixture::healthy().snapshot())),
            &t,
            Instant::now(),
        );
        assert_eq!(app.notices.len(), 2);
        assert_eq!(app.notices[1].level, NoticeLevel::Info);
        assert_eq!(
            app.notices[1].body,
            "Your saved rules can be read again; changes apply again."
        );
        app.apply(book(false), &t, Instant::now());
        assert_eq!(app.notices.len(), 2, "the end is said once");

        app.apply(book(true), &t, Instant::now());
        assert_eq!(app.notices.len(), 3, "read again, then broke: news again");
    }

    /// A VPN that lets only its own DNS answer is said once while it lasts, and
    /// again once it clears and comes back.
    #[test]
    fn the_foreign_dns_notice_is_raised_once_per_occurrence() {
        let t = texts();
        let mut app = AppState::new(ScreenId::Status, false);
        app.apply(BackendEvent::Link(Link::Connected), &t, Instant::now());
        let foreign = || {
            let mut snapshot = Fixture::healthy().snapshot();
            snapshot.health.components = vec![nrr_shared::ipc_payloads::HealthComponentResponse {
                component: "adapters".into(),
                severity: "degraded".into(),
                message: Some(format!(
                    "{} (corp0)",
                    nrr_shared::ipc_payloads::DNS_ONLY_FOREIGN_RESOLVER
                )),
            }];
            BackendEvent::Snapshot(Box::new(snapshot))
        };

        app.apply(foreign(), &t, Instant::now());
        app.apply(foreign(), &t, Instant::now());
        assert_eq!(app.notices.len(), 1);
        assert_eq!(app.notices[0].level, NoticeLevel::Warning);

        app.apply(
            BackendEvent::Snapshot(Box::new(Fixture::healthy().snapshot())),
            &t,
            Instant::now(),
        );
        app.apply(foreign(), &t, Instant::now());
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
    fn a_service_never_seen_running_is_not_reported_lost() {
        let t = texts();
        let mut app = AppState::new(ScreenId::Status, false);
        app.apply(BackendEvent::Link(Link::Stopped), &t, Instant::now());
        assert!(!app.service_loss_raised);
        assert!(app.notices.is_empty());
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

    /// A rule set refused for changing outside the app reaches the feed once
    /// per appearance, not on every snapshot that still lists the alert.
    #[test]
    fn a_refused_rule_set_is_told_once_while_its_alert_stays_open() {
        let t = texts();
        let mut app = AppState::new(ScreenId::Status, false);
        app.apply(BackendEvent::Link(Link::Connected), &t, Instant::now());
        let with_alert = |state: &str| {
            let mut snapshot = Fixture::healthy().snapshot();
            snapshot.diagnostics.active_alerts =
                vec![nrr_shared::diagnostics_dto::SecurityAlertDto {
                    alert_id: "a-1".into(),
                    kind: "untrusted_revision_rejected".into(),
                    state: state.into(),
                    created_at: 0,
                    updated_at: 0,
                    reason_code: String::new(),
                    raised_file: String::new(),
                    requires_action: true,
                }];
            BackendEvent::Snapshot(Box::new(snapshot))
        };

        app.apply(with_alert("active"), &t, Instant::now());
        app.apply(with_alert("active"), &t, Instant::now());
        assert_eq!(app.notices.len(), 1, "{:?}", app.notices);
        assert_eq!(app.notices[0].level, NoticeLevel::Warning);
        assert_eq!(app.notices[0].title, "Rule set changed outside the app");
        assert!(app.notices[0].body.contains("Diagnostics and logs"));

        app.apply(with_alert("acknowledged"), &t, Instant::now());
        app.apply(with_alert("active"), &t, Instant::now());
        assert_eq!(app.notices.len(), 2, "a new appearance is told again");
    }

    /// Selective routing over a VPN-like adapter is routing as asked: told
    /// once a run, and only while the rules actually go through it.
    #[test]
    fn selective_routing_over_a_vpn_is_explained_once_a_run() {
        let t = texts();
        let mut app = AppState::new(ScreenId::Status, false);
        app.apply(BackendEvent::Link(Link::Connected), &t, Instant::now());
        let split = |vpn: &str, rules: u32, mode: BehaviorModeDto| {
            let mut snapshot = Fixture::healthy().snapshot();
            snapshot.adapters.rows[1]
                .derived_assessment
                .vpn_tunnel_likelihood = vpn.into();
            snapshot.active_secondary_rule_count = Some(rules);
            if let Some(policy) = snapshot.route_policy.as_mut() {
                policy.mode = mode;
            }
            BackendEvent::Snapshot(Box::new(snapshot))
        };
        let full = BehaviorModeDto::PreferSecondaryWhenAvailable;
        for quiet in [
            split("unlikely", 2, BehaviorModeDto::PreferPrimary),
            split("likely", 0, BehaviorModeDto::PreferPrimary),
            split("likely", 2, full),
        ] {
            app.apply(quiet, &t, Instant::now());
        }
        assert!(app.notices.is_empty(), "{:?}", app.notices);

        app.apply(
            split("possible", 2, BehaviorModeDto::PreferPrimary),
            &t,
            Instant::now(),
        );
        app.apply(
            split("likely", 3, BehaviorModeDto::PreferPrimary),
            &t,
            Instant::now(),
        );
        assert_eq!(app.notices.len(), 1, "{:?}", app.notices);
        assert_eq!(app.notices[0].level, NoticeLevel::Info);
        assert!(
            app.notices[0]
                .body
                .contains("\"Example Tunnel — Example Network Adapter\""),
            "{:?}",
            app.notices[0]
        );
        assert!(app.notices[0].body.contains("your 2 rules go through it"));
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
                quiet: false,
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
