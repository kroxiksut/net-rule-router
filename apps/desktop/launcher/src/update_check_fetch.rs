//! GitHub release check, fetch side: the scheduled check and the one the user
//! asks for from the Help menu.
//!
//! Counterpart of `nrr_desktop_gui::update_check`, which owns the cache shape,
//! its location and the version compare. Both checks run here, in the LAUNCHER
//! (the GUI crate stays HTTP-free), and share one path: one anonymous GET to the
//! public GitHub API for this repository's latest release, no telemetry, and
//! only the small cache file written.
//!
//! The scheduled check runs on a detached thread at GUI start, once every N
//! days the user chose, counted from the last check of either kind, or from the
//! first start before any; it is never made while the user has it switched off,
//! and its result surfaces on the next start. The manual check is the user's
//! own gesture: it runs whatever that switch says, always asks the network,
//! answers the menu item directly and restarts the count.
//!
//! One request at a time: a check arriving while another is out waits for it
//! and takes its answer instead of asking again.

use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;

use serde_json::{json, Value};

use nrr_desktop_gui::update_check::{
    cache_path, clock_start_ms, interpret_release, is_check_due, read_cache, ReleaseAnswer,
    UpdateCheckCache, RELEASES_REPO,
};

/// The Help menu's "Check for updates".
pub const MANUAL_CHECK_OP: &str = "local.update-check.run";

/// Wire code of a manual check whose request got no usable answer.
pub const CHECK_FAILED_CODE: &str = "update-check-failed";

/// What a fetched release is compared with.
const RUNNING_VERSION: &str = env!("CARGO_PKG_VERSION");

static FLIGHT: SingleFlight = SingleFlight::new();

/// Spawn the scheduled check in a background thread (detached — the launcher
/// never joins it; worst case the process exits first and the cache write is
/// lost until the next start). Call once per GUI launch with the user's
/// settings.
pub fn spawn_scheduled_release_check(enabled: bool, interval_days: u32) {
    let _ = spawn_release_check_with(
        enabled,
        interval_days,
        &FLIGHT,
        fetch_latest_release,
        write_cache,
    );
}

/// Run the user's check now and answer with what the menu item shows:
/// `{status: "update-available", latestVersion, url}` or
/// `{status: "up-to-date", currentVersion}`; `None` when the release page gave
/// no usable answer. Blocks for at most one request.
pub fn run_manual_check() -> Option<Value> {
    manual_check(
        &read_cache(),
        &FLIGHT,
        now_ms(),
        fetch_latest_release,
        write_cache,
    )
    .to_wire()
}

/// `None` when the check is off: no thread, no request.
fn spawn_release_check_with<F, S>(
    enabled: bool,
    interval_days: u32,
    flight: &'static SingleFlight,
    fetch: F,
    store: S,
) -> Option<JoinHandle<()>>
where
    F: FnOnce() -> Option<(String, String)> + Send + 'static,
    S: FnOnce(&UpdateCheckCache) + Send + 'static,
{
    if !enabled {
        return None;
    }
    Some(std::thread::spawn(move || {
        let _ = scheduled_check(&read_cache(), now_ms(), interval_days, flight, fetch, store);
    }))
}

/// The scheduled check's outcome, or `None` when it is not due. The first
/// start only starts the clock: a fresh install asks nothing yet.
fn scheduled_check<F, S>(
    cached: &UpdateCheckCache,
    now_ms: u128,
    interval_days: u32,
    flight: &SingleFlight,
    fetch: F,
    store: S,
) -> Option<FetchOutcome>
where
    F: FnOnce() -> Option<(String, String)>,
    S: FnOnce(&UpdateCheckCache),
{
    if clock_start_ms(cached).is_none() {
        store(&UpdateCheckCache {
            first_seen_ms: now_ms,
            ..cached.clone()
        });
        return None;
    }
    if !is_check_due(cached, now_ms, interval_days) {
        return None;
    }
    Some(flight.run_or_join(|| ask(cached, now_ms, fetch, store)))
}

/// Unlike the scheduled check, never skipped for a fresh cache: the user asked.
fn manual_check<F, S>(
    cached: &UpdateCheckCache,
    flight: &SingleFlight,
    now_ms: u128,
    fetch: F,
    store: S,
) -> ManualAnswer
where
    F: FnOnce() -> Option<(String, String)>,
    S: FnOnce(&UpdateCheckCache),
{
    ManualAnswer::from_outcome(
        &flight.run_or_join(|| ask(cached, now_ms, fetch, store)),
        RUNNING_VERSION,
    )
}

/// One request. Only a successful one is stored, and it restarts the clock: a
/// failed fetch keeps the previous cache, so a transient offline day never
/// erases a known update.
fn ask<F, S>(cached: &UpdateCheckCache, now_ms: u128, fetch: F, store: S) -> FetchOutcome
where
    F: FnOnce() -> Option<(String, String)>,
    S: FnOnce(&UpdateCheckCache),
{
    let Some((latest_tag, html_url)) = fetch() else {
        return FetchOutcome::Failed;
    };
    let cache = UpdateCheckCache {
        checked_at_ms: now_ms,
        first_seen_ms: cached.first_seen_ms,
        latest_tag,
        html_url,
    };
    store(&cache);
    FetchOutcome::Fetched(cache)
}

#[derive(Clone, Debug)]
enum FetchOutcome {
    Fetched(UpdateCheckCache),
    Failed,
}

#[derive(Debug, PartialEq, Eq)]
enum ManualAnswer {
    UpdateAvailable {
        version: String,
        url: String,
    },
    UpToDate,
    /// No usable verdict: the request itself failed, or it answered with
    /// something we cannot trust (no parseable tag, or a release link outside
    /// our own repository). Either way the menu item reports a failed check,
    /// never "you have the latest version".
    Failed,
}

impl ManualAnswer {
    fn from_outcome(outcome: &FetchOutcome, running: &str) -> Self {
        match outcome {
            FetchOutcome::Failed => Self::Failed,
            FetchOutcome::Fetched(cache) => match interpret_release(cache, running) {
                ReleaseAnswer::UpdateAvailable(version, url) => {
                    Self::UpdateAvailable { version, url }
                }
                ReleaseAnswer::UpToDate => Self::UpToDate,
                ReleaseAnswer::Unparseable => Self::Failed,
            },
        }
    }

    fn to_wire(&self) -> Option<Value> {
        match self {
            Self::UpdateAvailable { version, url } => Some(json!({
                "status": "update-available",
                "latestVersion": version,
                "url": url,
            })),
            Self::UpToDate => Some(json!({
                "status": "up-to-date",
                "currentVersion": RUNNING_VERSION,
            })),
            Self::Failed => None,
        }
    }
}

/// At most one request out at a time; whoever arrives meanwhile shares its
/// outcome.
struct SingleFlight {
    state: Mutex<Flight>,
    landed: Condvar,
}

struct Flight {
    running: bool,
    landings: u64,
    last: Option<FetchOutcome>,
    joiners: usize,
}

impl SingleFlight {
    const fn new() -> Self {
        Self {
            state: Mutex::new(Flight {
                running: false,
                landings: 0,
                last: None,
                joiners: 0,
            }),
            landed: Condvar::new(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Flight> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn run_or_join(&self, ask: impl FnOnce() -> FetchOutcome) -> FetchOutcome {
        let mut flight = self.lock();
        if flight.running {
            let joined = flight.landings;
            flight.joiners += 1;
            while flight.landings == joined {
                flight = self
                    .landed
                    .wait(flight)
                    .unwrap_or_else(PoisonError::into_inner);
            }
            flight.joiners -= 1;
            return flight.last.clone().unwrap_or(FetchOutcome::Failed);
        }
        flight.running = true;
        drop(flight);
        // Lands from `Drop`, so a panicking fetch cannot leave joiners waiting.
        let mut landing = Landing {
            flight: self,
            outcome: FetchOutcome::Failed,
        };
        landing.outcome = ask();
        landing.outcome.clone()
    }
}

struct Landing<'a> {
    flight: &'a SingleFlight,
    outcome: FetchOutcome,
}

impl Drop for Landing<'_> {
    fn drop(&mut self) {
        let mut flight = self.flight.lock();
        flight.running = false;
        flight.landings = flight.landings.wrapping_add(1);
        flight.last = Some(self.outcome.clone());
        self.flight.landed.notify_all();
    }
}

fn now_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

fn write_cache(cache: &UpdateCheckCache) {
    let path = cache_path();
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Ok(serialized) = serde_json::to_string(cache) {
        let _ = std::fs::write(path, serialized);
    }
}

/// GET the latest-release `tag_name` + `html_url`. Best-effort: any HTTP or
/// parse failure returns `None`.
fn fetch_latest_release() -> Option<(String, String)> {
    let api_url = format!("https://api.github.com/repos/{RELEASES_REPO}/releases/latest");
    let response = ureq::get(&api_url)
        // GitHub requires a UA; name the product honestly.
        .set("User-Agent", "NetRuleRouter-update-check")
        .set("Accept", "application/vnd.github+json")
        .timeout(std::time::Duration::from_secs(5))
        .call()
        .ok()?;
    let body: serde_json::Value = response.into_json().ok()?;
    let tag = body.get("tag_name")?.as_str()?.trim().to_string();
    if tag.is_empty() {
        return None;
    }
    let url = body
        .get("html_url")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    Some((tag, url))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{mpsc, Arc};
    use std::time::{Duration, Instant};

    const RELEASE_PAGE: &str = "https://github.com/kroxiksut/net-rule-router/releases/tag/v9.9.9";
    const DAY_MS: u128 = 24 * 60 * 60 * 1000;
    const INSTALLED_AT: u128 = 1_000;

    fn counting_fetch(calls: &Arc<AtomicU32>) -> impl FnOnce() -> Option<(String, String)> {
        let calls = Arc::clone(calls);
        move || {
            calls.fetch_add(1, Ordering::SeqCst);
            Some(("v9.9.9".into(), RELEASE_PAGE.into()))
        }
    }

    fn leaked_flight() -> &'static SingleFlight {
        Box::leak(Box::new(SingleFlight::new()))
    }

    fn fetched(tag: &str) -> FetchOutcome {
        FetchOutcome::Fetched(UpdateCheckCache {
            checked_at_ms: 1,
            latest_tag: tag.into(),
            html_url: RELEASE_PAGE.into(),
            ..UpdateCheckCache::default()
        })
    }

    fn installed() -> UpdateCheckCache {
        UpdateCheckCache {
            first_seen_ms: INSTALLED_AT,
            ..UpdateCheckCache::default()
        }
    }

    /// Scheduled check at `now_ms` with the given interval; the request count
    /// and what it stored.
    fn scheduled(
        cached: &UpdateCheckCache,
        now_ms: u128,
        interval_days: u32,
    ) -> (u32, Option<UpdateCheckCache>) {
        let calls = Arc::new(AtomicU32::new(0));
        let mut written = None;
        let _ = scheduled_check(
            cached,
            now_ms,
            interval_days,
            &SingleFlight::new(),
            counting_fetch(&calls),
            |cache| written = Some(cache.clone()),
        );
        (calls.load(Ordering::SeqCst), written)
    }

    #[test]
    fn a_switched_off_check_makes_no_request() {
        let calls = Arc::new(AtomicU32::new(0));
        assert!(spawn_release_check_with(
            false,
            14,
            leaked_flight(),
            counting_fetch(&calls),
            |_| {}
        )
        .is_none());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn the_first_start_starts_the_clock_without_a_request() {
        let (calls, written) = scheduled(&UpdateCheckCache::default(), INSTALLED_AT, 14);
        assert_eq!(calls, 0, "a fresh install asks nothing yet");
        let written = written.expect("the first start is stamped");
        assert_eq!(written.first_seen_ms, INSTALLED_AT);
        assert_eq!(written.checked_at_ms, 0);
    }

    #[test]
    fn nothing_is_asked_before_the_interval_and_once_after_it() {
        let (calls, written) = scheduled(&installed(), INSTALLED_AT + 14 * DAY_MS - 1, 14);
        assert_eq!(calls, 0, "before the interval");
        assert!(written.is_none(), "a check that is not due writes nothing");

        let due_at = INSTALLED_AT + 14 * DAY_MS;
        let (calls, written) = scheduled(&installed(), due_at, 14);
        assert_eq!(calls, 1, "once the interval has passed");
        let written = written.expect("a due check stores what it fetched");
        assert_eq!(written.latest_tag, "v9.9.9");
        assert_eq!(written.checked_at_ms, due_at);
        assert_eq!(
            written.first_seen_ms, INSTALLED_AT,
            "the first start is kept"
        );

        let (calls, _) = scheduled(&written, due_at + 14 * DAY_MS - 1, 14);
        assert_eq!(calls, 0, "the check just made restarts the count");
    }

    #[test]
    fn the_chosen_interval_decides_when_the_check_is_due() {
        let at = INSTALLED_AT + 10 * DAY_MS;
        assert_eq!(scheduled(&installed(), at, 7).0, 1);
        assert_eq!(scheduled(&installed(), at, 14).0, 0);
        assert_eq!(scheduled(&installed(), at, 30).0, 0);
    }

    #[test]
    fn a_manual_check_pushes_the_scheduled_one_back() {
        let flight = SingleFlight::new();
        let calls = Arc::new(AtomicU32::new(0));
        let manual_at = INSTALLED_AT + 13 * DAY_MS;
        let mut after_manual = None;
        manual_check(
            &installed(),
            &flight,
            manual_at,
            counting_fetch(&calls),
            |cache| after_manual = Some(cache.clone()),
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let after_manual = after_manual.expect("a manual check stores its answer");

        // Due by the first start, not due any more by the manual check.
        let (calls, _) = scheduled(&after_manual, INSTALLED_AT + 14 * DAY_MS, 14);
        assert_eq!(calls, 0, "the manual check restarted the count");
        let (calls, _) = scheduled(&after_manual, manual_at + 14 * DAY_MS, 14);
        assert_eq!(calls, 1);
    }

    #[test]
    fn a_failed_fetch_keeps_the_previous_cache() {
        let outcome = ask(
            &installed(),
            1_000,
            || None,
            |_| panic!("a failed fetch stores nothing"),
        );
        assert!(matches!(outcome, FetchOutcome::Failed));
    }

    #[test]
    fn a_manual_check_with_the_scheduled_one_off_makes_exactly_one_request() {
        let flight = leaked_flight();
        let calls = Arc::new(AtomicU32::new(0));
        assert!(
            spawn_release_check_with(false, 14, flight, counting_fetch(&calls), |_| {}).is_none()
        );

        let mut stored = 0;
        let answer = manual_check(
            &UpdateCheckCache::default(),
            flight,
            5_000,
            counting_fetch(&calls),
            |cache| {
                assert_eq!(cache.checked_at_ms, 5_000);
                stored += 1;
            },
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            stored, 1,
            "the answer refreshes the cache the scheduled check reads"
        );
        assert!(matches!(answer, ManualAnswer::UpdateAvailable { .. }));
    }

    #[test]
    fn a_manual_check_asks_even_right_after_a_fresh_one() {
        let flight = SingleFlight::new();
        let calls = Arc::new(AtomicU32::new(0));
        let cached = UpdateCheckCache::default();
        manual_check(&cached, &flight, 1_000, counting_fetch(&calls), |_| {});
        manual_check(&cached, &flight, 1_001, counting_fetch(&calls), |_| {});
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn a_check_arriving_mid_request_shares_it_instead_of_asking_again() {
        let flight = leaked_flight();
        let calls = Arc::new(AtomicU32::new(0));
        let (release, hold) = mpsc::channel::<()>();

        let first_calls = Arc::clone(&calls);
        let first = std::thread::spawn(move || {
            manual_check(
                &UpdateCheckCache::default(),
                flight,
                1_000,
                move || {
                    first_calls.fetch_add(1, Ordering::SeqCst);
                    let _ = hold.recv();
                    Some(("v9.9.9".into(), RELEASE_PAGE.into()))
                },
                |_| {},
            )
        });
        wait_until(|| flight.lock().running);

        let second_calls = Arc::clone(&calls);
        let second = std::thread::spawn(move || {
            manual_check(
                &UpdateCheckCache::default(),
                flight,
                1_001,
                counting_fetch(&second_calls),
                |_| {},
            )
        });
        wait_until(|| flight.lock().joiners == 1);
        release
            .send(())
            .expect("the first request is still waiting");

        let first = first.join().expect("first check");
        let second = second.join().expect("second check");
        assert_eq!(calls.load(Ordering::SeqCst), 1, "one request for both");
        assert_eq!(first, second, "the joiner gets the same answer");
    }

    fn wait_until(condition: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !condition() {
            assert!(Instant::now() < deadline, "condition never came true");
            std::thread::yield_now();
        }
    }

    #[test]
    fn manual_answers_map_to_what_the_menu_shows() {
        let newer = ManualAnswer::from_outcome(&fetched("v9.9.9"), "0.1.0");
        assert_eq!(
            newer.to_wire(),
            Some(json!({
                "status": "update-available",
                "latestVersion": "9.9.9",
                "url": RELEASE_PAGE,
            }))
        );

        let same = ManualAnswer::from_outcome(&fetched("v0.1.0"), "0.1.0");
        assert_eq!(same, ManualAnswer::UpToDate);
        let wire = same.to_wire().expect("up to date is an answer");
        assert_eq!(wire["status"], "up-to-date");
        assert_eq!(wire["currentVersion"], RUNNING_VERSION);

        let offline = ManualAnswer::from_outcome(&FetchOutcome::Failed, "0.1.0");
        assert_eq!(offline, ManualAnswer::Failed);
        assert!(
            offline.to_wire().is_none(),
            "a failure is an error, not a status"
        );
    }

    #[test]
    fn an_unreadable_release_answer_fails_the_manual_check_instead_of_claiming_up_to_date() {
        let garbled = FetchOutcome::Fetched(UpdateCheckCache {
            checked_at_ms: 1,
            latest_tag: "not-a-version".into(),
            html_url: RELEASE_PAGE.into(),
            ..UpdateCheckCache::default()
        });
        let answer = ManualAnswer::from_outcome(&garbled, "0.1.0");
        assert_eq!(answer, ManualAnswer::Failed);
        assert!(
            answer.to_wire().is_none(),
            "an unparseable answer must not read as 'you have the latest version'"
        );

        let untrusted_link = FetchOutcome::Fetched(UpdateCheckCache {
            checked_at_ms: 1,
            latest_tag: "v9.9.9".into(),
            html_url: "https://example.com/not-ours".into(),
            ..UpdateCheckCache::default()
        });
        assert_eq!(
            ManualAnswer::from_outcome(&untrusted_link, "0.1.0"),
            ManualAnswer::Failed
        );
    }
}
