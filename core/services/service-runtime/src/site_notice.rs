//! "A site does not open" while none of the user's surfaces runs.
//!
//! A site the user opened that the main link will not carry is worth one card
//! even with the tray closed: the user is looking at a page that does not load
//! and has nothing on screen to say why. The service starts their tray for that card, at most once per
//! [`SITE_NOTICE_GAP_MS`] and per site once per [`SAME_SITE_GAP_MS`] (the
//! rule a running tray applies too), never while a surface of theirs listens (it says so
//! itself), and never once they muted the kind. The launch is the OS's
//! ([`SiteNoticeLauncher`]); everything here is neutral.
//!
//! The report comes from the connection observer, which must never wait: the
//! decision is taken there, the start itself on a worker of its own.

use std::collections::HashMap;
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};

use nrr_domain::block_notice::{MuteScope, NoticeKind};
use nrr_platform_api::session_notice::{
    notice_site_argument, SiteNoticeLauncher, SiteNoticeRefused,
};

use crate::block_notice_mute_store::BlockNoticeMuteStore;

/// The pacing every surface shares (`siteNoticeDue` in `pure.js`).
pub use nrr_shared::site_notice::{SAME_SITE_GAP_MS, SITE_NOTICE_GAP_MS};
/// Users whose last card is remembered.
const MAX_PRINCIPALS: usize = 64;
/// Sites whose last card is remembered, all users together.
const MAX_SITES: usize = 1024;
/// Starts waiting behind the one in progress; any more are dropped.
pub const SITE_NOTICE_QUEUE: usize = 8;

/// Whether a surface of this user's is subscribed to the service's pushes.
pub type ListeningFn = Arc<dyn Fn(&str) -> bool + Send + Sync>;

/// What one report of a site came to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SiteNoticeOutcome {
    /// Handed to the worker that starts the tray.
    Queued,
    /// The worker had too many starts waiting; this window's card is spent.
    Dropped,
    /// The user turned these off.
    Muted,
    /// A surface of theirs is running and tells them itself.
    Listening,
    /// A card was offered less than [`SITE_NOTICE_GAP_MS`] ago.
    TooSoon,
    /// This site had its card less than [`SAME_SITE_GAP_MS`] ago.
    ShownToday,
    Refused(SiteNoticeRefused),
}

/// One start for the worker: `(sid, host)`, the host already checked.
type StartRequest = (String, String);

/// When each user, and each of their sites, last had a card.
#[derive(Default)]
struct Shown {
    by_user: HashMap<String, i64>,
    by_site: HashMap<(String, String), i64>,
}

impl Shown {
    /// The shared rule. The service never sees a card answered: an answer is
    /// a rule (the site stops being reported) or the mute.
    fn due(&self, sid: &str, host: &str, now_ms: i64) -> Result<(), SiteNoticeOutcome> {
        let user = self.by_user.get(sid).copied();
        if !nrr_shared::site_notice::site_notice_due(false, user, None, false, now_ms) {
            return Err(SiteNoticeOutcome::TooSoon);
        }
        let site = self
            .by_site
            .get(&(sid.to_owned(), host.to_owned()))
            .copied();
        if !nrr_shared::site_notice::site_notice_due(false, None, site, false, now_ms) {
            return Err(SiteNoticeOutcome::ShownToday);
        }
        Ok(())
    }

    /// Room for one more entry of each, forgetting what no rule needs any
    /// more; `false` when there is none.
    fn make_room(&mut self, sid: &str, host: &str, now_ms: i64) -> bool {
        if self.by_user.len() >= MAX_PRINCIPALS && !self.by_user.contains_key(sid) {
            self.by_user
                .retain(|_, at| now_ms.saturating_sub(*at) < SITE_NOTICE_GAP_MS);
        }
        let key = (sid.to_owned(), host.to_owned());
        if self.by_site.len() >= MAX_SITES && !self.by_site.contains_key(&key) {
            self.by_site
                .retain(|_, at| now_ms.saturating_sub(*at) < SAME_SITE_GAP_MS);
        }
        (self.by_user.len() < MAX_PRINCIPALS || self.by_user.contains_key(sid))
            && (self.by_site.len() < MAX_SITES || self.by_site.contains_key(&key))
    }

    fn record(&mut self, sid: &str, host: &str, now_ms: i64) {
        self.by_user.insert(sid.to_owned(), now_ms);
        self.by_site
            .insert((sid.to_owned(), host.to_owned()), now_ms);
    }
}

/// Decides the card for each user and hands the start to its worker.
pub struct SiteNoticeGate {
    mutes: Arc<dyn BlockNoticeMuteStore>,
    listening: ListeningFn,
    shown: Mutex<Shown>,
    starts: SyncSender<StartRequest>,
}

impl SiteNoticeGate {
    /// Spawns the worker, which ends when the gate is dropped. A worker that
    /// cannot be spawned turns every start into [`SiteNoticeOutcome::Dropped`].
    pub fn new(
        launcher: Arc<dyn SiteNoticeLauncher>,
        mutes: Arc<dyn BlockNoticeMuteStore>,
        listening: ListeningFn,
    ) -> Self {
        let (starts, queued) = mpsc::sync_channel::<StartRequest>(SITE_NOTICE_QUEUE);
        let spawned = std::thread::Builder::new()
            .name("nrr-site-notice".into())
            .spawn(move || {
                for (sid, host) in queued {
                    start(launcher.as_ref(), &sid, &host);
                }
            });
        if let Err(error) = spawned {
            tracing::warn!(
                target: "nrr::site-notice",
                error = %error,
                "no worker to start the tray for site notices",
            );
        }
        Self {
            mutes,
            listening,
            shown: Mutex::new(Shown::default()),
            starts,
        }
    }

    fn muted(&self, sid: &str, now_ms: i64) -> bool {
        self.mutes
            .list_active(sid, now_ms)
            .iter()
            .any(|m| m.scope == MuteScope::Notice(NoticeKind::SiteNotOpening))
    }

    /// Whether a report of `host` for `sid` now would start the tray; changes
    /// nothing.
    pub fn would_tell(&self, sid: &str, host: &str, now_ms: i64) -> bool {
        !self.muted(sid, now_ms)
            && !(self.listening)(sid)
            && self
                .shown
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .due(sid, host, now_ms)
                .is_ok()
    }

    /// `host`, opened by `sid`, does not open over the main link (and, where
    /// the user lets the service check, answered over the additional one).
    /// Never waits for the start: it is queued, or dropped when the queue is
    /// full.
    pub fn site_not_opening(&self, sid: &str, host: &str, now_ms: i64) -> SiteNoticeOutcome {
        // Before the window is counted: a name no card may show must not hold
        // back the card about a site that can be named.
        if notice_site_argument(host).is_none() {
            return SiteNoticeOutcome::Refused(SiteNoticeRefused::BadHost);
        }
        if self.muted(sid, now_ms) {
            return SiteNoticeOutcome::Muted;
        }
        if (self.listening)(sid) {
            return SiteNoticeOutcome::Listening;
        }
        {
            let mut shown = self.shown.lock().unwrap_or_else(|p| p.into_inner());
            if let Err(outcome) = shown.due(sid, host, now_ms) {
                return outcome;
            }
            if !shown.make_room(sid, host, now_ms) {
                return SiteNoticeOutcome::TooSoon;
            }
            // Counted as offered whatever the start does, here and not on the
            // worker: a refusal repeats on every report otherwise, and a burst
            // would queue several.
            shown.record(sid, host, now_ms);
        }
        match self.starts.try_send((sid.to_owned(), host.to_owned())) {
            Ok(()) => SiteNoticeOutcome::Queued,
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                log_refused(
                    sid,
                    host,
                    &SiteNoticeRefused::Failed("too many tray starts waiting".into()),
                );
                SiteNoticeOutcome::Dropped
            }
        }
    }
}

fn start(launcher: &dyn SiteNoticeLauncher, sid: &str, host: &str) {
    match launcher.show_site_notice(sid, host) {
        Ok(()) => tracing::info!(
            target: "nrr::site-notice",
            msg_key = "site-notice-started",
            sid = %sid,
            host = %host,
            "started the tray to tell of a site that does not open",
        ),
        Err(SiteNoticeRefused::Unsupported) => {}
        Err(refused) => log_refused(sid, host, &refused),
    }
}

fn log_refused(sid: &str, host: &str, refused: &SiteNoticeRefused) {
    tracing::warn!(
        target: "nrr::site-notice",
        msg_key = "site-notice-refused",
        sid = %sid,
        host = %host,
        reason = ?refused,
        "did not start the tray to tell of a site that does not open",
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_notice_mute_store::InMemoryBlockNoticeMuteStore;
    use nrr_domain::block_notice::Mute;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc;
    use std::time::Duration;

    const ALICE: &str = "S-1-5-21-1-2-3-1001";
    const BOB: &str = "S-1-5-21-1-2-3-1002";

    #[derive(Default)]
    struct Recording {
        started: Mutex<Vec<(String, String)>>,
    }

    impl SiteNoticeLauncher for Recording {
        fn show_site_notice(&self, sid: &str, host: &str) -> Result<(), SiteNoticeRefused> {
            self.started
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push((sid.to_owned(), host.to_owned()));
            Ok(())
        }
    }

    struct Fixture {
        launcher: Arc<Recording>,
        mutes: Arc<InMemoryBlockNoticeMuteStore>,
        tray_up: Arc<AtomicBool>,
        gate: SiteNoticeGate,
    }

    fn fixture() -> Fixture {
        let launcher = Arc::new(Recording::default());
        let mutes = Arc::new(InMemoryBlockNoticeMuteStore::new());
        let tray_up = Arc::new(AtomicBool::new(false));
        let up = Arc::clone(&tray_up);
        let gate = SiteNoticeGate::new(
            Arc::clone(&launcher) as Arc<dyn SiteNoticeLauncher>,
            Arc::clone(&mutes) as Arc<dyn BlockNoticeMuteStore>,
            Arc::new(move |_sid: &str| up.load(Ordering::SeqCst)),
        );
        Fixture {
            launcher,
            mutes,
            tray_up,
            gate,
        }
    }

    fn started(f: &Fixture) -> Vec<(String, String)> {
        f.launcher
            .started
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    /// The starts once the worker has made `count` of them, or what it made
    /// in [`WAIT`].
    fn wait_started(f: &Fixture, count: usize) -> Vec<(String, String)> {
        let deadline = std::time::Instant::now() + WAIT;
        loop {
            let now = started(f);
            if now.len() >= count || std::time::Instant::now() >= deadline {
                return now;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn a_user_who_turned_it_off_never_gets_the_tray_started() {
        let f = fixture();
        f.mutes.upsert(
            ALICE,
            &Mute::forever(MuteScope::Notice(NoticeKind::SiteNotOpening)),
            0,
        );
        assert_eq!(
            f.gate.site_not_opening(ALICE, "site.example", 1_000),
            SiteNoticeOutcome::Muted
        );
        assert!(started(&f).is_empty());
        // Another kind muted is not this one.
        f.mutes.upsert(
            BOB,
            &Mute::forever(MuteScope::Notice(NoticeKind::SecondaryDown)),
            0,
        );
        assert_eq!(
            f.gate.site_not_opening(BOB, "site.example", 1_000),
            SiteNoticeOutcome::Queued
        );
    }

    #[test]
    fn at_most_one_card_per_window_whatever_the_site() {
        let f = fixture();
        let t0 = 1_000_000;
        assert_eq!(
            f.gate.site_not_opening(ALICE, "one.example", t0),
            SiteNoticeOutcome::Queued
        );
        assert_eq!(
            f.gate
                .site_not_opening(ALICE, "two.example", t0 + SITE_NOTICE_GAP_MS - 1),
            SiteNoticeOutcome::TooSoon
        );
        assert_eq!(
            f.gate.site_not_opening(BOB, "two.example", t0 + 1),
            SiteNoticeOutcome::Queued,
            "one user's card does not hold another's"
        );
        assert_eq!(
            f.gate
                .site_not_opening(ALICE, "two.example", t0 + SITE_NOTICE_GAP_MS),
            SiteNoticeOutcome::Queued
        );
        assert_eq!(wait_started(&f, 3).len(), 3);
    }

    /// Past the half hour another site may be told, but the same one waits a
    /// day: the user saw it and did nothing, and a card a day is the most a
    /// site that keeps failing may cost them.
    #[test]
    fn the_same_site_is_not_told_twice_in_a_day() {
        let f = fixture();
        let t0 = 10_000_000;
        assert_eq!(
            f.gate.site_not_opening(ALICE, "site.example", t0),
            SiteNoticeOutcome::Queued
        );
        let later = t0 + SITE_NOTICE_GAP_MS;
        assert!(!f.gate.would_tell(ALICE, "site.example", later));
        assert_eq!(
            f.gate.site_not_opening(ALICE, "site.example", later),
            SiteNoticeOutcome::ShownToday
        );
        assert!(f.gate.would_tell(ALICE, "other.example", later));
        assert_eq!(
            f.gate.site_not_opening(ALICE, "other.example", later),
            SiteNoticeOutcome::Queued,
            "a day for one site holds back no other"
        );
        assert_eq!(
            f.gate
                .site_not_opening(ALICE, "site.example", t0 + SAME_SITE_GAP_MS),
            SiteNoticeOutcome::Queued
        );
        assert_eq!(wait_started(&f, 3).len(), 3);
    }

    #[test]
    fn a_user_whose_tray_runs_gets_no_second_one() {
        let f = fixture();
        f.tray_up.store(true, Ordering::SeqCst);
        assert_eq!(
            f.gate.site_not_opening(ALICE, "site.example", 1_000),
            SiteNoticeOutcome::Listening
        );
        assert!(started(&f).is_empty());
        f.tray_up.store(false, Ordering::SeqCst);
        assert_eq!(
            f.gate.site_not_opening(ALICE, "site.example", 2_000),
            SiteNoticeOutcome::Queued,
            "a running tray did not use up the window"
        );
    }

    #[test]
    fn a_refused_launch_still_counts_as_the_windows_card() {
        let mutes = Arc::new(InMemoryBlockNoticeMuteStore::new());
        let gate = SiteNoticeGate::new(
            Arc::new(nrr_platform_api::session_notice::NoSiteNotice),
            mutes,
            Arc::new(|_: &str| false),
        );
        assert_eq!(
            gate.site_not_opening(ALICE, "site.example", 0),
            SiteNoticeOutcome::Queued
        );
        assert_eq!(
            gate.site_not_opening(ALICE, "site.example", 1),
            SiteNoticeOutcome::TooSoon
        );
    }

    const WAIT: Duration = Duration::from_secs(5);

    /// A launcher that holds every start until the test lets it go.
    struct Blocking {
        entered: Mutex<mpsc::Sender<String>>,
        release: Mutex<mpsc::Receiver<()>>,
    }

    impl SiteNoticeLauncher for Blocking {
        fn show_site_notice(&self, sid: &str, _host: &str) -> Result<(), SiteNoticeRefused> {
            let _ = self
                .entered
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .send(sid.to_owned());
            let _ = self
                .release
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .recv();
            Ok(())
        }
    }

    fn blocking_gate() -> (
        Arc<SiteNoticeGate>,
        mpsc::Receiver<String>,
        mpsc::Sender<()>,
    ) {
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let gate = SiteNoticeGate::new(
            Arc::new(Blocking {
                entered: Mutex::new(entered_tx),
                release: Mutex::new(release_rx),
            }),
            Arc::new(InMemoryBlockNoticeMuteStore::new()),
            Arc::new(|_: &str| false),
        );
        (Arc::new(gate), entered_rx, release_tx)
    }

    /// The report as the observer makes it, or `None` when it did not return
    /// in time: the observer was made to wait.
    fn report_within(gate: &Arc<SiteNoticeGate>, sid: &str, now: i64) -> Option<SiteNoticeOutcome> {
        let (done_tx, done_rx) = mpsc::channel();
        let gate = Arc::clone(gate);
        let sid = sid.to_owned();
        std::thread::spawn(move || {
            let _ = done_tx.send(gate.site_not_opening(&sid, "site.example", now));
        });
        done_rx.recv_timeout(WAIT).ok()
    }

    /// The connection observer never waits for a tray to start: starting one
    /// takes the OS tens of milliseconds, and observation would stall for it.
    #[test]
    fn the_observer_returns_while_the_tray_is_still_starting() {
        let (gate, entered, release) = blocking_gate();
        let outcome = report_within(&gate, ALICE, 0);
        let _ = release.send(());
        assert_eq!(
            outcome,
            Some(SiteNoticeOutcome::Queued),
            "the observer waited for the start"
        );
        assert_eq!(
            entered.recv_timeout(WAIT).ok().as_deref(),
            Some(ALICE),
            "the start still happened"
        );
    }

    /// Starts piling up behind a slow one are dropped, never waited for, and
    /// a dropped one still uses up that user's window.
    #[test]
    fn a_full_queue_drops_instead_of_waiting() {
        let (gate, entered, release) = blocking_gate();
        let user = |i: usize| format!("S-1-5-21-1-2-3-{}", 2000 + i);
        assert_eq!(
            report_within(&gate, &user(0), 0),
            Some(SiteNoticeOutcome::Queued)
        );
        // The worker now holds the first start; the queue behind it is empty.
        let busy = entered.recv_timeout(WAIT).ok();
        for i in 1..=SITE_NOTICE_QUEUE {
            assert_eq!(
                report_within(&gate, &user(i), 0),
                Some(SiteNoticeOutcome::Queued),
                "user {i}"
            );
        }
        let overflow = user(SITE_NOTICE_QUEUE + 1);
        let dropped = report_within(&gate, &overflow, 0);
        let again = report_within(&gate, &overflow, 1);
        for _ in 0..=SITE_NOTICE_QUEUE {
            let _ = release.send(());
        }
        assert_eq!(busy.as_deref(), Some(user(0).as_str()));
        assert_eq!(dropped, Some(SiteNoticeOutcome::Dropped));
        assert_eq!(again, Some(SiteNoticeOutcome::TooSoon));
    }

    /// A name no card may show is refused before it can hold back the card
    /// about a site the user really opened.
    #[test]
    fn a_host_no_card_may_name_does_not_use_up_the_window() {
        let f = fixture();
        assert_eq!(
            f.gate.site_not_opening(ALICE, "bad_host.example", 0),
            SiteNoticeOutcome::Refused(SiteNoticeRefused::BadHost)
        );
        assert_eq!(
            f.gate.site_not_opening(ALICE, "site.example", 1),
            SiteNoticeOutcome::Queued
        );
    }
}
