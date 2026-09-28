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
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use nrr_domain::block_notice::{BlockAttempt, BlockNoticeLedger, Mute};
use nrr_platform_api::process_lineage::ProcessLineagePort;
use nrr_shared::ipc_payloads::StatusUpdateEvent;

use crate::block_notice_journal_store::BlockNoticeJournalStore;
use crate::ipc_handlers::event_bus::EventBus;

/// Loads the persisted mutes of one principal. Consulted when a principal's
/// ledger is first created and again on [`BlockNoticeCenter::reload_mutes`],
/// so a mute the user just set takes effect without a restart.
pub type MuteLoaderFn = Arc<dyn Fn(&str) -> Vec<Mute> + Send + Sync>;

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
        }
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
}
