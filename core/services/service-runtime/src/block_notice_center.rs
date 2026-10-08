//! Shared owner of the block-notice ledgers — the one place in the running
//! service that turns [`BlockAttempt`]s into logged notices.
//!
//! The ledger itself ([`nrr_domain::block_notice`]) is pure and I/O-free by
//! design: it needs a clock and a place to send the notices it decides are
//! worth showing. This is that place. Behind a `Mutex` because the connection
//! observer (writer) and the mute-management surface (reader/writer) both reach
//! it, and the drop path this feeds must never block on anything heavier than a
//! short lock.
//!
//! **One ledger per principal.** Mutes are personal — one user silencing a
//! noisy game launcher must not silence anyone else's blocks — so a shared
//! ledger would leak the loudest user's choices onto everyone. Episode folding
//! is per-principal for the same reason: two users blocked on the same host are
//! two separate pieces of news.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use nrr_domain::block_notice::{BlockAttempt, BlockNoticeLedger, BlockReason, Mute};
use nrr_domain::canonical::CanonicalRuleBook;
use nrr_domain::decision_matching::{MatchClass, RequestedRouteDecision, ZonePriorityPolicy};
use nrr_domain::{RouteBehaviorMode, RuleAction};
use nrr_platform_api::process_lineage::ProcessLineagePort;
use nrr_shared::ipc_payloads::StatusUpdateEvent;

use crate::block_notice_journal_store::BlockNoticeJournalStore;
use crate::ipc_handlers::event_bus::EventBus;
use crate::per_sid_orchestrator::RulesProvider;

/// Loads the persisted mutes of one principal. Consulted when a principal's
/// ledger is first created and again on [`BlockNoticeCenter::reload_mutes`],
/// so a mute the user just set takes effect without a restart.
pub type MuteLoaderFn = Arc<dyn Fn(&str) -> Vec<Mute> + Send + Sync>;

/// Names the blocked network an attempt fell into, when a network Block rule is
/// what dropped it; `None` leaves the attempt named as it came.
pub type BlockedNetworkFn = Arc<dyn Fn(&str, &BlockAttempt) -> Option<String> + Send + Sync>;

/// Principals tracked at once. A machine has a handful of interactive users;
/// the cap only bounds memory if something upstream starts inventing SIDs.
const MAX_TRACKED_PRINCIPALS: usize = 16;

/// Owns one ledger per principal; logs on `nrr::block-notice` for every attempt
/// that opens a fresh, unmuted episode. Delivery to the tray/GUI is a later
/// step — this is the sole consumer of `record`'s result today.
pub struct BlockNoticeCenter {
    ledgers: Mutex<HashMap<String, BlockNoticeLedger>>,
    mute_loader: Option<MuteLoaderFn>,
    events: Option<Arc<EventBus>>,
    journal: Option<Arc<dyn BlockNoticeJournalStore>>,
    /// Attached once the process recorder is up, which is after this center
    /// is built; empty until then and on platforms without one.
    lineage: Mutex<Option<Arc<dyn ProcessLineagePort>>>,
    blocked_network: Option<BlockedNetworkFn>,
}

impl Default for BlockNoticeCenter {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockNoticeCenter {
    #[must_use]
    pub fn new() -> Self {
        Self {
            ledgers: Mutex::new(HashMap::new()),
            mute_loader: None,
            events: None,
            journal: None,
            lineage: Mutex::new(None),
            blocked_network: None,
        }
    }

    /// Name an attempt dropped by a network Block rule after that network, so
    /// a scan across it is one notice the user can act on.
    #[must_use]
    pub fn with_blocked_network(mut self, namer: BlockedNetworkFn) -> Self {
        self.blocked_network = Some(namer);
        self
    }

    /// Attach the persisted mute set. Without it every ledger starts unmuted,
    /// which is the correct inert default: notices are shown, never silently
    /// swallowed because a store was missing.
    #[must_use]
    pub fn with_mute_loader(mut self, loader: MuteLoaderFn) -> Self {
        self.mute_loader = Some(loader);
        self
    }

    /// Attach the push channel so the tray learns about a new block episode
    /// without polling. Without it the notice is still logged — this only
    /// adds delivery, it never gates whether an episode is recorded.
    #[must_use]
    pub fn with_event_bus(mut self, events: Arc<EventBus>) -> Self {
        self.events = Some(events);
        self
    }

    /// Attach the backlog so a notice raised while no surface is subscribed
    /// still reaches its user later. Push delivery is live-only: without this
    /// the tray being closed means the notice was never told to anyone.
    #[must_use]
    pub fn with_journal(mut self, journal: Arc<dyn BlockNoticeJournalStore>) -> Self {
        self.journal = Some(journal);
        self
    }

    /// Name who started the blocked program on each new notice. Asked once
    /// per episode, never per retried packet.
    pub fn attach_process_lineage(&self, lineage: Arc<dyn ProcessLineagePort>) {
        *self.lineage.lock().unwrap_or_else(|p| p.into_inner()) = Some(lineage);
    }

    /// Record one blocked attempt for `sid` and log the notice, if any.
    pub fn record(&self, sid: &str, attempt: &BlockAttempt) {
        self.record_observed(sid, attempt, None);
    }

    /// [`Self::record`] for an attempt seen at `observed_ms` (wall-clock Unix
    /// ms). The time anchors only the ancestry lookup: the notice names the
    /// run that was live when the drop happened, not a later one of the same
    /// program.
    ///
    /// Wall-clock is read here rather than threaded through the caller — this
    /// is the one place the ledger's clock dependency is resolved for the live
    /// service. An attempt whose owner is unknown is attributed to the empty
    /// principal: it still deserves a notice, and lumping it in with a real
    /// user would let that user's mutes silence it.
    pub fn record_observed(&self, sid: &str, attempt: &BlockAttempt, observed_ms: Option<u64>) {
        let named;
        let attempt = match self.blocked_network.as_ref().and_then(|f| f(sid, attempt)) {
            Some(network) => {
                named = attempt.clone().within_network(network);
                &named
            }
            None => attempt,
        };
        let now_ms = now_ms();
        let notice = {
            let mut guard = self.ledgers.lock().unwrap_or_else(|p| p.into_inner());
            if !guard.contains_key(sid) {
                evict_if_full(&mut guard);
                let mut ledger = BlockNoticeLedger::default();
                if let Some(loader) = self.mute_loader.as_ref() {
                    ledger.set_mutes(loader(sid));
                }
                guard.insert(sid.to_owned(), ledger);
            }
            guard.get_mut(sid).and_then(|l| l.record(now_ms, attempt))
        };
        if let Some(mut notice) = notice {
            // Outside the ledger lock: the lookup may read the process table.
            notice.launched_by = self.launched_by(sid, &notice.app, observed_ms.unwrap_or(now_ms));
            tracing::info!(
                target: "nrr::block-notice",
                msg_key = "blocknotice-episode-opened",
                destination = %notice.destination,
                app = %notice.app,
                reason = notice.reason.slug(),
                attempts = notice.attempts,
                launched_by = %notice.launched_by.join(" < "),
                "blocked connection — new episode",
            );
            // Journalled before publishing, and unconditionally: whether a
            // subscriber exists is not knowable here, and a duplicate the user
            // sees twice beats a block they are never told about. The surface
            // that shows a backlog entry acknowledges it, which is what stops
            // the repeat.
            if let Some(journal) = self.journal.as_ref() {
                journal.append(sid, &notice, now_ms as i64);
            }
            if let Some(bus) = self.events.as_ref() {
                bus.publish_for(
                    sid,
                    StatusUpdateEvent::BlockNoticeRaised {
                        sid: sid.to_owned(),
                        destination: notice.destination,
                        app: notice.app,
                        reason: notice.reason.slug().to_string(),
                        attempts: u64::from(notice.attempts),
                        launched_by: notice.launched_by,
                    },
                );
            }
        }
    }

    fn launched_by(&self, sid: &str, app: &str, at_ms: u64) -> Vec<String> {
        if app.is_empty() {
            return Vec::new();
        }
        let lineage = self
            .lineage
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let Some(lineage) = lineage else {
            return Vec::new();
        };
        let owner = (!sid.is_empty()).then_some(sid);
        lineage.ancestry_of(app, owner, UNIX_EPOCH + Duration::from_millis(at_ms))
    }

    /// Close every episode `sid` has about `destination` — the user acted on
    /// the notice, so the question it asked is answered. Not a mute: a block
    /// after this is news again and speaks.
    pub fn resolve_destination(&self, sid: &str, destination: &str) {
        let cleared = {
            let mut guard = self.ledgers.lock().unwrap_or_else(|p| p.into_inner());
            guard
                .get_mut(sid)
                .map_or(0, |l| l.resolve_destination(destination))
        };
        if cleared > 0 {
            tracing::debug!(
                target: "nrr::block-notice",
                destination = %destination,
                episodes = cleared,
                "notice resolved by the user — episodes closed",
            );
        }
    }

    /// Re-read `sid`'s mutes from the store. Called after the user adds or
    /// removes one, so "do not show this again" takes hold on the next block
    /// rather than after a restart.
    pub fn reload_mutes(&self, sid: &str) {
        if let Some(bus) = self.events.as_ref() {
            bus.publish_for(
                sid,
                StatusUpdateEvent::BlockNoticeMutesChanged {
                    sid: sid.to_owned(),
                },
            );
        }
        let Some(loader) = self.mute_loader.as_ref() else {
            return;
        };
        let mutes = loader(sid);
        let mut guard = self.ledgers.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(ledger) = guard.get_mut(sid) {
            ledger.set_mutes(mutes);
        }
    }
}

/// How long one principal's rule book serves the network lookup before a
/// re-read: a rule edit shows within seconds, a scan costs one read.
const BLOCKED_BOOK_TTL: Duration = Duration::from_secs(5);

/// One principal's book as the network lookup needs it.
struct BlockedBook {
    book: CanonicalRuleBook,
    behavior_mode: RouteBehaviorMode,
    /// Every block an enabled network Block rule names: the cheap first test,
    /// so a drop outside them never reaches the matcher.
    blocks: Vec<nrr_shared::ip_block::IpBlock>,
}

/// The production [`BlockedNetworkFn`]: asks the engine which rule dropped the
/// address and names it when it is a network Block.
pub struct BlockedNetworks {
    rules: Arc<dyn RulesProvider>,
    memo: Mutex<HashMap<String, (Instant, Arc<BlockedBook>)>>,
}

impl BlockedNetworks {
    #[must_use]
    pub fn new(rules: Arc<dyn RulesProvider>) -> Self {
        Self {
            rules,
            memo: Mutex::new(HashMap::new()),
        }
    }

    #[must_use]
    pub fn into_fn(self) -> BlockedNetworkFn {
        let this = Arc::new(self);
        Arc::new(move |sid: &str, attempt: &BlockAttempt| this.network_for(sid, attempt))
    }

    /// The network rule that dropped `attempt`, as the user wrote it. Only a
    /// rule block can be one; the matcher decides, so a narrower rule naming
    /// the host keeps the attempt named by its host.
    pub fn network_for(&self, sid: &str, attempt: &BlockAttempt) -> Option<String> {
        self.network_at(sid, attempt, Instant::now())
    }

    fn network_at(&self, sid: &str, attempt: &BlockAttempt, now: Instant) -> Option<String> {
        if attempt.reason != BlockReason::BlockedByRule || sid.is_empty() {
            return None;
        }
        let ip: IpAddr = attempt.dest.parse().ok()?;
        let book = self.book_for(sid, now)?;
        if !book.blocks.iter().any(|block| block.contains(ip)) {
            return None;
        }
        let decision = nrr_domain::decision_engine_input::match_sample(
            &book.book,
            attempt.host.as_deref(),
            Some(ip),
            attempt.app.as_deref(),
            ZonePriorityPolicy::default(),
            book.behavior_mode,
        );
        let RequestedRouteDecision::MatchedRoute { candidate } = decision else {
            return None;
        };
        if candidate.action != RuleAction::Block || candidate.match_class != MatchClass::Subnet {
            return None;
        }
        let address = book
            .book
            .primary
            .rules()
            .iter()
            .chain(book.book.secondary.rules())
            .find(|rule| rule.id == candidate.rule_id)?
            .address_match
            .as_ref()?;
        Some(address.to_display_string())
    }

    fn book_for(&self, sid: &str, now: Instant) -> Option<Arc<BlockedBook>> {
        let mut memo = self.memo.lock().unwrap_or_else(|p| p.into_inner());
        if let Some((at, book)) = memo.get(sid) {
            if now.saturating_duration_since(*at) < BLOCKED_BOOK_TTL {
                return Some(Arc::clone(book));
            }
        }
        let snapshot = self.rules.active_rules_for(sid)?;
        let blocks = snapshot
            .rule_book
            .primary
            .rules()
            .iter()
            .chain(snapshot.rule_book.secondary.rules())
            .filter(|rule| rule.enabled && rule.action == RuleAction::Block)
            .filter_map(|rule| rule.address_match.as_ref()?.ip_blocks())
            .flatten()
            .copied()
            .collect();
        let book = Arc::new(BlockedBook {
            book: snapshot.rule_book,
            behavior_mode: snapshot.behavior_mode,
            blocks,
        });
        if memo.len() >= MAX_TRACKED_PRINCIPALS && !memo.contains_key(sid) {
            memo.clear();
        }
        memo.insert(sid.to_owned(), (now, Arc::clone(&book)));
        Some(book)
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Drops one tracked principal when the cap is reached. Which one is arbitrary
/// — the cost is a repeated notice for a user who is no longer active.
fn evict_if_full(ledgers: &mut HashMap<String, BlockNoticeLedger>) {
    if ledgers.len() < MAX_TRACKED_PRINCIPALS {
        return;
    }
    let victim = ledgers.keys().next().cloned();
    if let Some(victim) = victim {
        ledgers.remove(&victim);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_domain::block_notice::{BlockReason, MuteScope};

    const ALICE: &str = "S-1-5-21-1";
    const BOB: &str = "S-1-5-21-2";

    fn attempt() -> BlockAttempt {
        BlockAttempt {
            host: Some("cdn.example".to_owned()),
            dest: "203.0.113.7".to_owned(),
            app: Some("chrome.exe".to_owned()),
            reason: BlockReason::NotCoveredByRules,
        }
    }

    /// Counts notices by watching the ledger's own bookkeeping: a principal
    /// whose episode was opened has a non-zero attempt count.
    fn attempts_for(center: &BlockNoticeCenter, sid: &str, attempt: &BlockAttempt) -> u32 {
        let guard = center.ledgers.lock().unwrap_or_else(|p| p.into_inner());
        guard.get(sid).map_or(0, |l| l.attempts_so_far(attempt))
    }

    #[test]
    fn record_does_not_panic_and_can_be_called_repeatedly() {
        let center = BlockNoticeCenter::new();
        center.record(ALICE, &attempt());
        center.record(ALICE, &attempt());
        assert_eq!(attempts_for(&center, ALICE, &attempt()), 2);
    }

    #[test]
    fn one_users_mute_never_silences_another() {
        let center = BlockNoticeCenter::new().with_mute_loader(Arc::new(|sid: &str| {
            if sid == ALICE {
                vec![Mute::forever(MuteScope::Host("cdn.example".into()))]
            } else {
                Vec::new()
            }
        }));

        center.record(ALICE, &attempt());
        center.record(BOB, &attempt());

        // Both counted the attempt; only Bob's ledger was allowed to speak.
        assert_eq!(attempts_for(&center, ALICE, &attempt()), 1);
        assert_eq!(attempts_for(&center, BOB, &attempt()), 1);
        let guard = center.ledgers.lock().unwrap_or_else(|p| p.into_inner());
        assert_eq!(guard.get(ALICE).map(|l| l.active_mutes(0).len()), Some(1));
        assert_eq!(guard.get(BOB).map(|l| l.active_mutes(0).len()), Some(0));
    }

    #[test]
    fn an_unknown_owner_gets_its_own_ledger_not_a_real_users() {
        let center = BlockNoticeCenter::new();
        center.record("", &attempt());
        center.record(ALICE, &attempt());

        assert_eq!(attempts_for(&center, "", &attempt()), 1);
        assert_eq!(attempts_for(&center, ALICE, &attempt()), 1);
    }

    #[test]
    fn reload_picks_up_a_mute_set_after_the_ledger_existed() {
        let muted = Arc::new(Mutex::new(false));
        let flag = Arc::clone(&muted);
        let center = BlockNoticeCenter::new().with_mute_loader(Arc::new(move |_sid: &str| {
            if *flag.lock().unwrap_or_else(|p| p.into_inner()) {
                vec![Mute::forever(MuteScope::All)]
            } else {
                Vec::new()
            }
        }));

        center.record(ALICE, &attempt());
        *muted.lock().unwrap_or_else(|p| p.into_inner()) = true;
        center.reload_mutes(ALICE);

        let guard = center.ledgers.lock().unwrap_or_else(|p| p.into_inner());
        assert_eq!(guard.get(ALICE).map(|l| l.active_mutes(0).len()), Some(1));
    }

    #[test]
    fn a_new_episode_publishes_a_push_event_alongside_the_log_line() {
        let bus = Arc::new(EventBus::new());
        let sub = bus.subscribe_as("test-client".to_string(), Some(ALICE.to_string()), None);
        let center = BlockNoticeCenter::new().with_event_bus(Arc::clone(&bus));

        center.record(ALICE, &attempt());

        let pending = bus.peek_pending_for(&sub.subscription_id, 10);
        assert_eq!(pending.len(), 1, "one episode, one push event");
        match &pending[0].event {
            StatusUpdateEvent::BlockNoticeRaised {
                sid,
                destination,
                app,
                reason,
                attempts,
                launched_by,
            } => {
                assert!(launched_by.is_empty(), "no recorder attached");
                assert_eq!(sid, ALICE);
                assert_eq!(destination, "cdn.example");
                assert_eq!(app, "chrome.exe");
                assert_eq!(reason, "not-covered-by-rules");
                assert_eq!(*attempts, 1);
            }
            other => panic!("expected BlockNoticeRaised, got {other:?}"),
        }
    }

    #[test]
    fn a_retry_of_a_live_episode_does_not_publish_a_second_event() {
        let bus = Arc::new(EventBus::new());
        let sub = bus.subscribe_as("test-client".to_string(), Some(ALICE.to_string()), None);
        let center = BlockNoticeCenter::new().with_event_bus(Arc::clone(&bus));

        center.record(ALICE, &attempt());
        center.record(ALICE, &attempt());

        assert_eq!(bus.peek_pending_for(&sub.subscription_id, 10).len(), 1);
    }

    #[test]
    fn a_raised_notice_is_journalled_for_a_surface_that_is_not_up_yet() {
        let journal =
            Arc::new(crate::block_notice_journal_store::InMemoryBlockNoticeJournalStore::new());
        let center = BlockNoticeCenter::new().with_journal(journal.clone());

        center.record(ALICE, &attempt());

        let pending = journal.list_pending(ALICE, i64::MAX);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].notice.destination, attempt().destination_label());
        assert!(journal.list_pending(BOB, i64::MAX).is_empty());
    }

    #[test]
    fn a_muted_episode_journals_nothing_either() {
        let journal =
            Arc::new(crate::block_notice_journal_store::InMemoryBlockNoticeJournalStore::new());
        let center = BlockNoticeCenter::new()
            .with_journal(journal.clone())
            .with_mute_loader(Arc::new(|_sid: &str| vec![Mute::forever(MuteScope::All)]));

        center.record(ALICE, &attempt());

        assert!(journal.list_pending(ALICE, i64::MAX).is_empty());
    }

    /// Counts lookups; answers a fixed ancestry.
    struct CountingLineage {
        calls: Mutex<Vec<(String, Option<String>, u64)>>,
    }

    impl ProcessLineagePort for CountingLineage {
        fn coverage(&self) -> nrr_platform_api::process_lineage::LineageCoverage {
            nrr_platform_api::process_lineage::LineageCoverage::History
        }

        fn ancestry_of(&self, image_path: &str, sid: Option<&str>, at: SystemTime) -> Vec<String> {
            self.calls.lock().unwrap_or_else(|p| p.into_inner()).push((
                image_path.to_owned(),
                sid.map(str::to_owned),
                nrr_platform_api::process_lineage::unix_ms(at),
            ));
            vec!["pwsh.exe".into(), "explorer.exe".into()]
        }
    }

    fn counting() -> Arc<CountingLineage> {
        Arc::new(CountingLineage {
            calls: Mutex::new(Vec::new()),
        })
    }

    #[test]
    fn ancestry_is_asked_once_per_episode_and_rides_on_the_notice() {
        let bus = Arc::new(EventBus::new());
        let sub = bus.subscribe_as("test-client".to_string(), Some(ALICE.to_string()), None);
        let journal =
            Arc::new(crate::block_notice_journal_store::InMemoryBlockNoticeJournalStore::new());
        let center = BlockNoticeCenter::new()
            .with_event_bus(Arc::clone(&bus))
            .with_journal(journal.clone());
        let lineage = counting();
        center.attach_process_lineage(lineage.clone());

        center.record_observed(ALICE, &attempt(), Some(1_234));
        center.record_observed(ALICE, &attempt(), Some(1_300));
        center.record_observed(ALICE, &attempt(), Some(1_400));

        let calls = lineage
            .calls
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        assert_eq!(
            calls,
            vec![("chrome.exe".to_string(), Some(ALICE.to_string()), 1_234)],
            "one lookup for the episode, anchored at the drop that opened it"
        );
        let pending = bus.peek_pending_for(&sub.subscription_id, 10);
        match &pending[0].event {
            StatusUpdateEvent::BlockNoticeRaised { launched_by, .. } => {
                assert_eq!(
                    launched_by,
                    &vec!["pwsh.exe".to_string(), "explorer.exe".to_string()]
                );
            }
            other => panic!("expected BlockNoticeRaised, got {other:?}"),
        }
        let journalled = journal.list_pending(ALICE, i64::MAX);
        assert_eq!(journalled[0].notice.launched_by.len(), 2);
    }

    #[test]
    fn an_unnamed_program_or_a_muted_episode_is_never_looked_up() {
        let muted = BlockNoticeCenter::new()
            .with_mute_loader(Arc::new(|_sid: &str| vec![Mute::forever(MuteScope::All)]));
        let lineage = counting();
        muted.attach_process_lineage(lineage.clone());
        muted.record(ALICE, &attempt());

        let unnamed = BlockNoticeCenter::new();
        unnamed.attach_process_lineage(lineage.clone());
        unnamed.record(
            ALICE,
            &BlockAttempt {
                app: None,
                ..attempt()
            },
        );

        assert!(lineage
            .calls
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_empty());
    }

    #[test]
    fn an_unknown_owner_is_looked_up_without_a_user() {
        let center = BlockNoticeCenter::new();
        let lineage = counting();
        center.attach_process_lineage(lineage.clone());
        center.record("", &attempt());

        let calls = lineage
            .calls
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].1, None);
    }

    #[test]
    fn a_muted_episode_publishes_nothing() {
        let bus = Arc::new(EventBus::new());
        let sub = bus.subscribe_as("test-client".to_string(), Some(ALICE.to_string()), None);
        let center = BlockNoticeCenter::new()
            .with_event_bus(Arc::clone(&bus))
            .with_mute_loader(Arc::new(|_sid: &str| vec![Mute::forever(MuteScope::All)]));

        center.record(ALICE, &attempt());

        assert!(bus.peek_pending_for(&sub.subscription_id, 10).is_empty());
    }

    // ── a blocked network names the notice ───────────────────────────────

    struct FixedRules(nrr_domain::canonical::CanonicalRuleBook);

    impl RulesProvider for FixedRules {
        fn active_rules(&self) -> Option<crate::per_sid_orchestrator::ActiveRulesSnapshot> {
            self.active_rules_for(ALICE)
        }
        fn active_rules_for(
            &self,
            _principal: &str,
        ) -> Option<crate::per_sid_orchestrator::ActiveRulesSnapshot> {
            Some(crate::per_sid_orchestrator::ActiveRulesSnapshot {
                rule_book: self.0.clone(),
                behavior_mode: RouteBehaviorMode::PreferPrimary,
            })
        }
    }

    fn rule(
        id: &str,
        m: nrr_domain::canonical::CanonicalAddressMatch,
        action: RuleAction,
    ) -> nrr_domain::canonical::CanonicalRule {
        nrr_domain::canonical::CanonicalRule {
            id: nrr_domain::RuleId(id.into()),
            enabled: true,
            address_match: Some(m),
            app_match: None,
            comment: String::new(),
            action,
            origin: None,
        }
    }

    fn networks(rules: Vec<nrr_domain::canonical::CanonicalRule>) -> BlockedNetworks {
        BlockedNetworks::new(Arc::new(FixedRules(CanonicalRuleBook {
            primary: nrr_domain::canonical::CanonicalRuleSet::from_rules(rules),
            secondary: nrr_domain::canonical::CanonicalRuleSet::from_rules(vec![]),
        })))
    }

    fn blocked_to(dest: &str, host: Option<&str>) -> BlockAttempt {
        BlockAttempt {
            host: host.map(str::to_owned),
            dest: dest.to_owned(),
            app: Some("scanner.exe".to_owned()),
            reason: BlockReason::BlockedByRule,
        }
    }

    fn subnet(text: &str) -> nrr_domain::canonical::CanonicalAddressMatch {
        nrr_domain::canonical::CanonicalAddressMatch::Subnet(
            nrr_shared::ip_block::IpBlock::parse(text).expect("network"),
        )
    }

    #[test]
    fn an_address_inside_a_blocked_network_is_named_by_that_network() {
        let namer = networks(vec![rule(
            "n-1",
            subnet("198.51.100.0/24"),
            RuleAction::Block,
        )]);
        assert_eq!(
            namer
                .network_for(ALICE, &blocked_to("198.51.100.9", None))
                .as_deref(),
            Some("198.51.100.0/24")
        );
        assert!(namer
            .network_for(ALICE, &blocked_to("198.51.101.9", None))
            .is_none());
    }

    #[test]
    fn a_range_is_named_as_written_and_a_routed_network_names_nothing() {
        let range =
            nrr_shared::ip_block::IpRange::parse("198.51.100.5-198.51.100.40").expect("range");
        let namer = networks(vec![
            rule(
                "r-1",
                nrr_domain::canonical::CanonicalAddressMatch::ip_range(range),
                RuleAction::Block,
            ),
            rule("n-2", subnet("203.0.113.0/24"), RuleAction::Route),
        ]);
        assert_eq!(
            namer
                .network_for(ALICE, &blocked_to("198.51.100.20", None))
                .as_deref(),
            Some("198.51.100.5-198.51.100.40")
        );
        assert!(namer
            .network_for(ALICE, &blocked_to("203.0.113.9", None))
            .is_none());
    }

    /// The narrower rule decides: a literal-IP Block inside the network is
    /// its own notice, and only a rule drop is ever attributed to a network.
    #[test]
    fn a_narrower_rule_or_another_cause_keeps_the_attempt_as_it_came() {
        let inside: std::net::IpAddr = "198.51.100.9".parse().expect("ip");
        let namer = networks(vec![
            rule("n-1", subnet("198.51.100.0/24"), RuleAction::Block),
            rule(
                "i-1",
                nrr_domain::canonical::CanonicalAddressMatch::ExactIp(inside),
                RuleAction::Block,
            ),
        ]);
        assert!(namer
            .network_for(ALICE, &blocked_to("198.51.100.9", None))
            .is_none());
        let mut outage = blocked_to("198.51.100.10", None);
        outage.reason = BlockReason::RouteUnavailable;
        assert!(namer.network_for(ALICE, &outage).is_none());
        assert!(namer
            .network_for("", &blocked_to("198.51.100.10", None))
            .is_none());
    }

    #[test]
    fn a_scan_across_a_blocked_network_is_one_notice() {
        let namer = networks(vec![rule(
            "n-1",
            subnet("198.51.100.0/24"),
            RuleAction::Block,
        )]);
        let bus = Arc::new(EventBus::new());
        let sub = bus.subscribe_as("test-client".to_string(), Some(ALICE.to_string()), None);
        let center = BlockNoticeCenter::new()
            .with_event_bus(Arc::clone(&bus))
            .with_blocked_network(namer.into_fn());

        for last in 1..=20 {
            center.record(ALICE, &blocked_to(&format!("198.51.100.{last}"), None));
        }

        let pending = bus.peek_pending_for(&sub.subscription_id, 10);
        assert_eq!(pending.len(), 1, "{pending:?}");
        match &pending[0].event {
            StatusUpdateEvent::BlockNoticeRaised { destination, .. } => {
                assert_eq!(destination, "198.51.100.0/24");
            }
            other => panic!("expected BlockNoticeRaised, got {other:?}"),
        }
    }
}
