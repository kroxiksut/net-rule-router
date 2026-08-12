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
use std::time::{SystemTime, UNIX_EPOCH};

use nrr_domain::block_notice::{BlockAttempt, BlockNoticeLedger, Mute};
use nrr_shared::ipc_payloads::StatusUpdateEvent;

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

    /// Record one blocked attempt for `sid` and log the notice, if any.
    ///
    /// Wall-clock is read here rather than threaded through the caller — this
    /// is the one place the ledger's clock dependency is resolved for the live
    /// service. An attempt whose owner is unknown is attributed to the empty
    /// principal: it still deserves a notice, and lumping it in with a real
    /// user would let that user's mutes silence it.
    pub fn record(&self, sid: &str, attempt: &BlockAttempt) {
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
        if let Some(notice) = notice {
            tracing::info!(
                target: "nrr::block-notice",
                destination = %notice.destination,
                app = %notice.app,
                reason = notice.reason.slug(),
                attempts = notice.attempts,
                "blocked connection — new episode",
            );
            if let Some(bus) = self.events.as_ref() {
                bus.publish(StatusUpdateEvent::BlockNoticeRaised {
                    sid: sid.to_owned(),
                    destination: notice.destination,
                    app: notice.app,
                    reason: notice.reason.slug().to_string(),
                    attempts: u64::from(notice.attempts),
                });
            }
        }
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
        let sub = bus.subscribe("test-client".to_string(), None);
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
            } => {
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
        let sub = bus.subscribe("test-client".to_string(), None);
        let center = BlockNoticeCenter::new().with_event_bus(Arc::clone(&bus));

        center.record(ALICE, &attempt());
        center.record(ALICE, &attempt());

        assert_eq!(bus.peek_pending_for(&sub.subscription_id, 10).len(), 1);
    }

    #[test]
    fn a_muted_episode_publishes_nothing() {
        let bus = Arc::new(EventBus::new());
        let sub = bus.subscribe("test-client".to_string(), None);
        let center = BlockNoticeCenter::new()
            .with_event_bus(Arc::clone(&bus))
            .with_mute_loader(Arc::new(|_sid: &str| vec![Mute::forever(MuteScope::All)]));

        center.record(ALICE, &attempt());

        assert!(bus.peek_pending_for(&sub.subscription_id, 10).is_empty());
    }
}
