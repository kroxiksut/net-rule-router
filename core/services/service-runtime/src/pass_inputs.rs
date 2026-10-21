//! Whether anything an enforcement pass reads has changed since the last one.
//!
//! A pass costs a full plan and an apply, and most passes are asked for by a
//! timer or by an event that turned out to change nothing. Each input exposes a
//! cheap number that moves when it changes; the pass hashes them and skips when
//! the hash is the one it last applied. A full pass still runs every
//! [`FULL_PASS_EVERY`], because some inputs change with time alone (an address
//! ageing out of its confirmation window) and the platform's own state can be
//! changed behind our back.

use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The longest a pass may be skipped for, whatever the inputs say.
pub const FULL_PASS_EVERY: Duration = Duration::from_secs(5 * 60);

/// One input's change number. `None` = it cannot tell, and the pass must run.
pub type InputGeneration = Arc<dyn Fn() -> Option<u64> + Send + Sync>;

/// What the last fingerprint and the last applied state were made of.
#[derive(Default)]
struct Readings {
    /// Each source's value at the last [`PassInputs::fingerprint`], and the
    /// hash of the pass's own part.
    seen: Vec<Option<u64>>,
    seen_extra: u64,
    /// The last [`PassInputs::is_settled`] answered `false` to a requested full pass.
    forced: bool,
    /// The fingerprint applied last, when, and what it was made of.
    settled: Option<Settled>,
}

/// A caller's demand that the next pass run in full whatever its inputs say:
/// it brings a fact no source can see, or it must not return before the pass.
#[derive(Clone, Default)]
pub struct FullPassRequest(Arc<AtomicBool>);

impl FullPassRequest {
    pub fn request(&self) {
        self.0.store(true, Ordering::Release);
    }

    pub(crate) fn take(&self) -> bool {
        self.0.swap(false, Ordering::AcqRel)
    }
}

/// `hook`, preceded by a request that the pass it starts run in full.
pub fn forcing(
    request: FullPassRequest,
    hook: Arc<dyn Fn() + Send + Sync>,
) -> Arc<dyn Fn() + Send + Sync> {
    Arc::new(move || {
        request.request();
        hook();
    })
}

struct Settled {
    fingerprint: u64,
    at: Instant,
    values: Vec<Option<u64>>,
    extra: u64,
}

/// The inputs of one pass and the fingerprint it last applied.
pub struct PassInputs {
    sources: Vec<(&'static str, InputGeneration)>,
    /// Per source: whether the pass itself moves it (the route table it
    /// writes). Re-read at [`Self::settle`] so the pass's own apply does not
    /// come back as a change and cost an identical second pass.
    own_writes: Vec<bool>,
    /// Per source: a reading that bypasses its cache, for [`Self::settle`].
    fresh: Vec<Option<InputGeneration>>,
    full_every: Duration,
    full_request: FullPassRequest,
    readings: Mutex<Readings>,
}

impl PassInputs {
    #[must_use]
    pub fn new() -> Self {
        Self {
            sources: Vec::new(),
            own_writes: Vec::new(),
            fresh: Vec::new(),
            full_every: FULL_PASS_EVERY,
            full_request: FullPassRequest::default(),
            readings: Mutex::new(Readings::default()),
        }
    }

    /// Share the request a caller raises before asking for a pass.
    #[must_use]
    pub fn with_full_pass_request(mut self, request: FullPassRequest) -> Self {
        self.full_request = request;
        self
    }

    /// Add an input. `name` is what [`Self::moved`] reports it as.
    #[must_use]
    pub fn with_source(mut self, name: &'static str, source: InputGeneration) -> Self {
        self.sources.push((name, source));
        self.own_writes.push(false);
        self.fresh.push(None);
        self
    }

    /// Add an input the pass itself writes. A change landing from elsewhere
    /// while the pass applies is absorbed until the next full pass; the
    /// alternative is every changing pass running twice.
    #[must_use]
    pub fn with_own_writes_source(mut self, name: &'static str, source: InputGeneration) -> Self {
        self.sources.push((name, source));
        self.own_writes.push(true);
        self.fresh.push(None);
        self
    }

    /// [`Self::with_own_writes_source`] for a cached source: `fresh` reads the
    /// OS past the cache, because the notice for the pass's own write has not
    /// necessarily arrived when the pass settles.
    #[must_use]
    pub fn with_cached_own_writes_source(
        mut self,
        name: &'static str,
        source: InputGeneration,
        fresh: InputGeneration,
    ) -> Self {
        self.sources.push((name, source));
        self.own_writes.push(true);
        self.fresh.push(Some(fresh));
        self
    }

    #[must_use]
    pub fn with_full_pass_every(mut self, every: Duration) -> Self {
        self.full_every = every;
        self
    }

    /// The fingerprint of every source plus `extra` — what the pass itself
    /// already knows, such as who is present. `None` when a source cannot tell.
    pub fn fingerprint(&self, extra: &impl Hash) -> Option<u64> {
        let values: Vec<Option<u64>> = self.sources.iter().map(|(_, read)| read()).collect();
        let mut extra_hasher = DefaultHasher::new();
        extra.hash(&mut extra_hasher);
        let extra = extra_hasher.finish();
        let fingerprint = digest(extra, &values);

        let mut readings = self.lock();
        readings.seen = values;
        readings.seen_extra = extra;
        readings.forced = false;
        fingerprint
    }

    /// Whether `fingerprint` is the one last applied, recently enough that a
    /// full pass is not yet due, and nobody asked for one. Consumes the request.
    pub fn is_settled(&self, fingerprint: u64) -> bool {
        let mut readings = self.lock();
        if self.full_request.take() {
            readings.forced = true;
            return false;
        }
        readings.settled.as_ref().is_some_and(|settled| {
            settled.fingerprint == fingerprint && settled.at.elapsed() < self.full_every
        })
    }

    /// Record that the platform now holds what `fingerprint` describes, with
    /// the sources the pass writes itself read again after its apply.
    pub fn settle(&self, fingerprint: u64) {
        let fresh: Vec<(usize, Option<u64>)> = self
            .sources
            .iter()
            .zip(&self.own_writes)
            .zip(&self.fresh)
            .enumerate()
            .filter(|(_, ((_, own), _))| **own)
            .map(|(i, (((_, read), _), fresh))| (i, fresh.as_ref().unwrap_or(read)()))
            .collect();
        let mut readings = self.lock();
        let mut values = readings.seen.clone();
        let mut settled_fp = Some(fingerprint);
        // Only when `seen` is what `fingerprint` was taken from: a reading
        // taken in between would otherwise be settled without being applied.
        if !fresh.is_empty() && digest(readings.seen_extra, &values) == Some(fingerprint) {
            for (i, value) in fresh {
                if let Some(slot) = values.get_mut(i) {
                    *slot = value;
                }
            }
            settled_fp = digest(readings.seen_extra, &values);
        }
        let extra = readings.seen_extra;
        readings.settled = settled_fp.map(|fingerprint| Settled {
            fingerprint,
            at: Instant::now(),
            values,
            extra,
        });
    }

    /// Forget the last applied state: the next pass runs whatever it hashes to.
    pub fn unsettle(&self) {
        self.lock().settled = None;
    }

    /// Why the last fingerprint did not match the applied one: the names of
    /// the sources that moved, `extra` for the pass's own part, `due` when only
    /// the periodic full pass came round, `first` before anything was applied,
    /// `forced` (first in the list) when a caller asked for the pass.
    pub fn moved(&self) -> String {
        let readings = self.lock();
        let Some(settled) = readings.settled.as_ref() else {
            return if readings.forced { "forced" } else { "first" }.to_string();
        };
        let mut names: Vec<&str> = self
            .sources
            .iter()
            .zip(readings.seen.iter().zip(settled.values.iter()))
            .filter(|(_, (now, then))| now != then)
            .map(|((name, _), _)| *name)
            .collect();
        if readings.seen_extra != settled.extra {
            names.push("extra");
        }
        // A forced pass still says what else moved: the caller's own request
        // must not hide a network change from whoever reads the reason.
        if readings.forced {
            names.insert(0, "forced");
        }
        if names.is_empty() {
            "due".to_string()
        } else {
            names.join(",")
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Readings> {
        self.readings.lock().unwrap_or_else(|p| p.into_inner())
    }
}

/// `None` when a source cannot tell.
fn digest(extra: u64, values: &[Option<u64>]) -> Option<u64> {
    let mut hasher = DefaultHasher::new();
    extra.hash(&mut hasher);
    values.hash(&mut hasher);
    values.iter().all(Option::is_some).then(|| hasher.finish())
}

impl Default for PassInputs {
    fn default() -> Self {
        Self::new()
    }
}

/// Whether a pass reason from [`PassInputs::moved`] means the machine's links
/// may have changed: an adapter moved, nothing was applied yet, or the periodic
/// full pass came due. Work that only a new network needs runs on these and not
/// on a pass that a cache or an observation asked for.
#[must_use]
pub fn network_may_have_changed(moved: &str) -> bool {
    moved
        .split([',', ':'])
        .any(|reason| matches!(reason, "adapters" | "first" | "due"))
}

/// State tables no enforcement pass reads: journals, suggestions, tokens and
/// alerts. The service writes them on nearly every event, and counting them
/// re-ran the whole pass after each one. A table missing here is counted, so a
/// new table costs passes, never a stale plan.
pub const PLAN_BLIND_STATE_TABLES: &[&str] = &[
    "block_notice_journal",
    "block_notice_mutes",
    "auto_rule_evidence",
    "auto_rule_pending_candidates",
    "auto_rule_dismissals",
    "mutation_tokens",
    "explain_snapshots",
    "apply_snapshots",
    "security_alerts",
    "integrity_log",
];

/// Row changes this process made to the database at `path` outside `ignored`.
pub fn table_writes(path: PathBuf, ignored: &'static [&'static str]) -> InputGeneration {
    Arc::new(move || Some(nrr_storage::write_ledger::changes_outside(&path, ignored)))
}

/// Which counted tables moved between two reports, for the slow-pass line.
pub struct TableWriteDiff {
    path: PathBuf,
    ignored: &'static [&'static str],
    last: Mutex<HashMap<String, u64>>,
}

impl TableWriteDiff {
    #[must_use]
    pub fn new(path: PathBuf, ignored: &'static [&'static str]) -> Self {
        let last = Mutex::new(nrr_storage::write_ledger::snapshot(&path));
        Self {
            path,
            ignored,
            last,
        }
    }

    /// `table+n` for each counted table written since the previous call.
    pub fn since_last(&self) -> String {
        let now = nrr_storage::write_ledger::snapshot(&self.path);
        let mut last = self.last.lock().unwrap_or_else(|p| p.into_inner());
        let mut moved: Vec<String> = now
            .iter()
            .filter(|(table, _)| !self.ignored.contains(&table.as_str()))
            .filter_map(|(table, n)| {
                let delta = n.saturating_sub(last.get(table).copied().unwrap_or(0));
                (delta > 0).then(|| format!("{table}+{delta}"))
            })
            .collect();
        moved.sort_unstable();
        *last = now;
        moved.join(",")
    }
}

/// The revision an activation is applying: served to every rules read
/// before its pointer commits, and invisible to the table counts.
pub fn applying_revision() -> InputGeneration {
    Arc::new(|| Some(crate::applying_revision_overlay::changes()))
}

/// The `?` rules a check verdict moved to the other link, held in memory.
pub fn verify_verdicts() -> InputGeneration {
    Arc::new(|| Some(crate::verify_overlay::changes()))
}

/// The confirmed overrides of the protection, and whether one is due: a term
/// that ran out moves a pass even if its timer never fired.
pub fn rule_overrides() -> InputGeneration {
    Arc::new(|| Some(crate::override_grants::pass_generation()))
}

/// The hash of whatever `read` returns; `None` when it fails.
pub fn hashed<T: Hash, E>(
    read: impl Fn() -> Result<T, E> + Send + Sync + 'static,
) -> InputGeneration {
    Arc::new(move || {
        let value = read().ok()?;
        let mut hasher = DefaultHasher::new();
        value.hash(&mut hasher);
        Some(hasher.finish())
    })
}

/// [`hashed`] over a reading taken again only after an OS change notice (or the
/// safety interval). Returns the cached source and one that reads past the
/// cache, for [`PassInputs::with_cached_own_writes_source`].
pub fn change_hashed<T: Hash, E>(
    generation: nrr_platform_api::net_change::NetChangeGeneration,
    read: impl Fn() -> Result<T, E> + Send + Sync + 'static,
) -> (InputGeneration, InputGeneration) {
    let cache = Arc::new(nrr_platform_api::net_change::ChangeCached::new(
        generation,
        move || {
            let value = read().ok()?;
            let mut hasher = DefaultHasher::new();
            value.hash(&mut hasher);
            Some(hasher.finish())
        },
    ));
    let cached = Arc::clone(&cache);
    (
        Arc::new(move || cached.get()),
        Arc::new(move || cache.refresh()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn counter() -> (Arc<AtomicU64>, InputGeneration) {
        let value = Arc::new(AtomicU64::new(0));
        let read = Arc::clone(&value);
        (value, Arc::new(move || Some(read.load(Ordering::Relaxed))))
    }

    #[test]
    fn an_unchanged_input_is_settled_and_a_changed_one_is_not() {
        let (value, source) = counter();
        let inputs = PassInputs::new().with_source("cache", source);
        let first = inputs.fingerprint(&"alice").expect("fingerprint");
        assert!(!inputs.is_settled(first), "nothing was applied yet");
        assert_eq!(inputs.moved(), "first");

        inputs.settle(first);
        assert!(inputs.is_settled(inputs.fingerprint(&"alice").expect("fp")));

        value.store(1, Ordering::Relaxed);
        assert!(!inputs.is_settled(inputs.fingerprint(&"alice").expect("fp")));
        assert_eq!(inputs.moved(), "cache");
        assert!(
            !inputs.is_settled(inputs.fingerprint(&"bob").expect("fp")),
            "who is present is part of the input"
        );
        assert_eq!(inputs.moved(), "cache,extra");
    }

    #[test]
    fn only_a_network_reason_counts_as_a_network_change() {
        for network in [
            "adapters",
            "first",
            "due",
            "cache,adapters",
            "forced,adapters",
        ] {
            assert!(network_may_have_changed(network), "{network}");
        }
        for other in [
            "cache",
            "apps,cache",
            "forced",
            "state:apps+1",
            "extra",
            "routes",
        ] {
            assert!(!network_may_have_changed(other), "{other}");
        }
    }

    #[test]
    fn a_forced_pass_still_names_what_moved() {
        let (value, source) = counter();
        let request = FullPassRequest::default();
        let inputs = PassInputs::new()
            .with_source("adapters", source)
            .with_full_pass_request(request.clone());
        let fp = inputs.fingerprint(&()).expect("fingerprint");
        inputs.settle(fp);
        value.store(1, Ordering::Relaxed);
        request.request();
        let fp = inputs.fingerprint(&()).expect("fingerprint");
        assert!(!inputs.is_settled(fp));
        assert_eq!(inputs.moved(), "forced,adapters");
        assert!(network_may_have_changed(&inputs.moved()));
    }

    #[test]
    fn a_source_that_cannot_tell_never_lets_a_pass_be_skipped() {
        let inputs = PassInputs::new().with_source("blind", Arc::new(|| None));
        assert_eq!(inputs.fingerprint(&()), None);
    }

    #[test]
    fn a_full_pass_comes_due_however_still_the_inputs() {
        let (_, source) = counter();
        let inputs = PassInputs::new()
            .with_source("cache", source)
            .with_full_pass_every(Duration::ZERO);
        let fp = inputs.fingerprint(&()).expect("fingerprint");
        inputs.settle(fp);
        assert!(!inputs.is_settled(fp));
        assert_eq!(inputs.moved(), "due");
    }

    #[test]
    fn a_requested_full_pass_runs_once_however_still_the_inputs() {
        let (_, source) = counter();
        let request = FullPassRequest::default();
        let inputs = PassInputs::new()
            .with_source("cache", source)
            .with_full_pass_request(request.clone());
        let fp = inputs.fingerprint(&()).expect("fingerprint");
        inputs.settle(fp);

        let hook_ran = Arc::new(AtomicU64::new(0));
        let ran = Arc::clone(&hook_ran);
        forcing(
            request,
            Arc::new(move || {
                ran.fetch_add(1, Ordering::Relaxed);
            }),
        )();
        assert_eq!(hook_ran.load(Ordering::Relaxed), 1);

        let fp = inputs.fingerprint(&()).expect("fingerprint");
        assert!(!inputs.is_settled(fp), "the request was ignored");
        assert_eq!(inputs.moved(), "forced");
        inputs.settle(fp);
        let fp = inputs.fingerprint(&()).expect("fingerprint");
        assert!(
            inputs.is_settled(fp),
            "one request forced more than one pass"
        );
    }

    /// The pass's own route writes must not bring back an identical pass; a
    /// move anywhere else during the pass still must.
    #[test]
    fn the_pass_own_writes_settle_with_it_and_nothing_else_does() {
        let (routes, routes_source) = counter();
        let (cache, cache_source) = counter();
        let inputs = PassInputs::new()
            .with_own_writes_source("routes", routes_source)
            .with_source("cache", cache_source);

        let fp = inputs.fingerprint(&()).expect("fingerprint");
        routes.store(1, Ordering::Relaxed); // the apply wrote the table
        inputs.settle(fp);
        let after = inputs.fingerprint(&()).expect("fingerprint");
        assert!(
            inputs.is_settled(after),
            "the pass's own apply came back as a change"
        );

        let fp = inputs.fingerprint(&()).expect("fingerprint");
        routes.store(2, Ordering::Relaxed);
        cache.store(1, Ordering::Relaxed); // learned while the pass applied
        inputs.settle(fp);
        assert!(
            !inputs.is_settled(inputs.fingerprint(&()).expect("fingerprint")),
            "a change that landed mid-pass was settled unplanned",
        );
        assert_eq!(inputs.moved(), "cache");
    }

    #[test]
    fn a_change_hashed_source_reads_the_os_only_after_a_notice() {
        use nrr_platform_api::net_change::NetChangeGeneration;
        let generation = NetChangeGeneration::new();
        let _feed = generation.follow(&AlwaysUp).expect("subscribed");
        let reads = Arc::new(AtomicU64::new(0));
        let counter = Arc::clone(&reads);
        let (cached, _fresh) = change_hashed(generation.clone(), move || {
            Ok::<_, ()>(counter.fetch_add(1, Ordering::SeqCst))
        });
        let first = cached();
        assert_eq!(cached(), first);
        assert_eq!(reads.load(Ordering::SeqCst), 1);
        generation.bump();
        assert_ne!(cached(), first, "a notice must show the new reading");
        assert_eq!(reads.load(Ordering::SeqCst), 2);
    }

    struct AlwaysUp;
    impl nrr_platform_api::network_change::NetworkChangeObserver for AlwaysUp {
        fn subscribe(
            &self,
            _on_change: nrr_platform_api::network_change::NetworkChangeCallback,
        ) -> Result<
            nrr_platform_api::network_change::NetworkChangeSubscription,
            nrr_platform_api::error::PlatformError,
        > {
            Ok(nrr_platform_api::network_change::NetworkChangeSubscription::inert())
        }
    }

    #[test]
    fn a_cached_own_write_is_settled_from_a_fresh_read() {
        let (routes, routes_fresh) = counter();
        let stale = Arc::new(AtomicU64::new(0));
        let cached_view = Arc::clone(&stale);
        let inputs = PassInputs::new().with_cached_own_writes_source(
            "routes",
            Arc::new(move || Some(cached_view.load(Ordering::Relaxed))),
            routes_fresh,
        );
        let fp = inputs.fingerprint(&()).expect("fingerprint");
        routes.store(1, Ordering::Relaxed); // the apply wrote the table
        inputs.settle(fp);
        // The notice for that write lands and the cache catches up.
        stale.store(1, Ordering::Relaxed);
        let after = inputs.fingerprint(&()).expect("fingerprint");
        assert!(inputs.is_settled(after), "the pass's own write came back");
    }

    #[test]
    fn unsettling_forces_the_next_pass() {
        let (_, source) = counter();
        let inputs = PassInputs::new().with_source("cache", source);
        let fp = inputs.fingerprint(&()).expect("fingerprint");
        inputs.settle(fp);
        inputs.unsettle();
        assert!(!inputs.is_settled(fp));
    }
}
