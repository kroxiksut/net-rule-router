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
use std::hash::{Hash, Hasher};
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
    /// The fingerprint applied last, when, and what it was made of.
    settled: Option<Settled>,
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
    full_every: Duration,
    readings: Mutex<Readings>,
}

impl PassInputs {
    #[must_use]
    pub fn new() -> Self {
        Self {
            sources: Vec::new(),
            full_every: FULL_PASS_EVERY,
            readings: Mutex::new(Readings::default()),
        }
    }

    /// Add an input. `name` is what [`Self::moved`] reports it as.
    #[must_use]
    pub fn with_source(mut self, name: &'static str, source: InputGeneration) -> Self {
        self.sources.push((name, source));
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

        let mut hasher = DefaultHasher::new();
        extra.hash(&mut hasher);
        values.hash(&mut hasher);
        let known = values.iter().all(Option::is_some);

        let mut readings = self.lock();
        readings.seen = values;
        readings.seen_extra = extra;
        known.then(|| hasher.finish())
    }

    /// Whether `fingerprint` is the one last applied, recently enough that a
    /// full pass is not yet due.
    pub fn is_settled(&self, fingerprint: u64) -> bool {
        self.lock().settled.as_ref().is_some_and(|settled| {
            settled.fingerprint == fingerprint && settled.at.elapsed() < self.full_every
        })
    }

    /// Record that the platform now holds what `fingerprint` describes.
    pub fn settle(&self, fingerprint: u64) {
        let mut readings = self.lock();
        readings.settled = Some(Settled {
            fingerprint,
            at: Instant::now(),
            values: readings.seen.clone(),
            extra: readings.seen_extra,
        });
    }

    /// Forget the last applied state: the next pass runs whatever it hashes to.
    pub fn unsettle(&self) {
        self.lock().settled = None;
    }

    /// Why the last fingerprint did not match the applied one: the names of
    /// the sources that moved, `extra` for the pass's own part, `due` when only
    /// the periodic full pass came round, `first` before anything was applied.
    pub fn moved(&self) -> String {
        let readings = self.lock();
        let Some(settled) = readings.settled.as_ref() else {
            return "first".to_string();
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

impl Default for PassInputs {
    fn default() -> Self {
        Self::new()
    }
}

/// A SQLite connection's change number.
pub fn sqlite_generation(conn: Arc<Mutex<rusqlite::Connection>>) -> InputGeneration {
    Arc::new(move || {
        let guard = conn.lock().ok()?;
        nrr_storage::change_generation::of(&guard)
    })
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
    fn unsettling_forces_the_next_pass() {
        let (_, source) = counter();
        let inputs = PassInputs::new().with_source("cache", source);
        let fp = inputs.fingerprint(&()).expect("fingerprint");
        inputs.settle(fp);
        inputs.unsettle();
        assert!(!inputs.is_settled(fp));
    }
}
