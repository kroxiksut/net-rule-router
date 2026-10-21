//! Which hosts the upstream resolver recently answered with something unusable
//! while an independent resolver answered clean.
//!
//! Fed only by verdicts the poison-fallback resolver already reaches, so it adds
//! nothing to the query path. Read by the status snapshot.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use nrr_shared::diagnostics_dto::DnsTamperCard;

/// How long a host counts as affected after its last replaced answer.
const WINDOW: Duration = Duration::from_secs(30 * 60);
/// Hosts remembered; past it new hosts are dropped until old ones age out.
const CAPACITY: usize = 256;
/// Example names handed to the client.
const EXAMPLES: usize = 3;

#[derive(Default)]
pub struct TamperLog {
    seen: HashMap<Box<str>, Instant>,
}

impl TamperLog {
    pub fn record(&mut self, host: &str, now: Instant) {
        let key = host.to_ascii_lowercase().into_boxed_str();
        if self.seen.len() >= CAPACITY && !self.seen.contains_key(&key) {
            self.seen.retain(|_, at| now.duration_since(*at) < WINDOW);
            if self.seen.len() >= CAPACITY {
                return;
            }
        }
        self.seen.insert(key, now);
    }

    /// Count of hosts inside the window; names only when `with_examples`.
    pub fn card(&self, now: Instant, with_examples: bool) -> DnsTamperCard {
        let mut live: Vec<(&str, Instant)> = self
            .seen
            .iter()
            .filter(|(_, at)| now.duration_since(**at) < WINDOW)
            .map(|(host, at)| (&**host, *at))
            .collect();
        // Newest first, name as tie-break so the answer is stable.
        live.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
        DnsTamperCard {
            affected_hosts: live.len() as u32,
            examples: if with_examples {
                live.iter()
                    .take(EXAMPLES)
                    .map(|(host, _)| (*host).to_string())
                    .collect()
            } else {
                Vec::new()
            },
        }
    }
}

fn log() -> &'static Mutex<TamperLog> {
    static LOG: OnceLock<Mutex<TamperLog>> = OnceLock::new();
    LOG.get_or_init(Mutex::default)
}

/// A host whose upstream answer was unusable while a public resolver answered clean.
pub fn record(host: &str) {
    log()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .record(host, Instant::now());
}

/// The card for the status snapshot. Whose names a host belongs to is not
/// known here, so only a machine-wide reader gets examples.
#[must_use]
pub fn current(with_examples: bool) -> DnsTamperCard {
    log()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .card(Instant::now(), with_examples)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_age_out_of_the_window() {
        let t0 = Instant::now();
        let mut log = TamperLog::default();
        log.record("a.example", t0);
        log.record("b.example", t0 + WINDOW / 2);
        assert_eq!(log.card(t0 + WINDOW / 2, false).affected_hosts, 2);
        assert_eq!(
            log.card(t0 + WINDOW + Duration::from_secs(1), false)
                .affected_hosts,
            1
        );
    }

    #[test]
    fn a_repeat_counts_once_and_case_is_ignored() {
        let t0 = Instant::now();
        let mut log = TamperLog::default();
        log.record("A.Example", t0);
        log.record("a.example", t0 + Duration::from_secs(5));
        assert_eq!(
            log.card(t0 + Duration::from_secs(6), true).affected_hosts,
            1
        );
    }

    #[test]
    fn examples_are_capped_newest_first() {
        let t0 = Instant::now();
        let mut log = TamperLog::default();
        for (i, h) in ["a", "b", "c", "d", "e"].iter().enumerate() {
            log.record(h, t0 + Duration::from_secs(i as u64));
        }
        let card = log.card(t0 + Duration::from_secs(10), true);
        assert_eq!(card.affected_hosts, 5);
        assert_eq!(card.examples, ["e", "d", "c"]);
    }

    #[test]
    fn a_principal_reader_gets_the_count_but_no_names() {
        let t0 = Instant::now();
        let mut log = TamperLog::default();
        log.record("secret.example", t0);
        let card = log.card(t0, false);
        assert_eq!(card.affected_hosts, 1);
        assert!(card.examples.is_empty());
    }

    #[test]
    fn the_memory_is_bounded_and_recovers_after_the_window() {
        let t0 = Instant::now();
        let mut log = TamperLog::default();
        for i in 0..(CAPACITY + 50) {
            log.record(&format!("h{i}.example"), t0);
        }
        assert_eq!(log.card(t0, false).affected_hosts as usize, CAPACITY);
        log.record("late.example", t0 + WINDOW + Duration::from_secs(1));
        assert_eq!(
            log.card(t0 + WINDOW + Duration::from_secs(1), true)
                .examples,
            ["late.example"]
        );
    }
}
