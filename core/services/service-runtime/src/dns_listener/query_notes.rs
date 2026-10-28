//! Which per-query log lines of the listener are written.
//!
//! Some facts the listener notes recur on every query for the same name: a
//! domain PC asks its internal names dozens of times a minute, and a page can
//! enumerate names on a shared CDN. Written each time, they rotate weeks of the
//! log away within a day. A fact is written once per key, and at most
//! [`NOTES_PER_WINDOW`] new ones per window, the next written line counting
//! what was held back.

use std::collections::HashSet;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

const NOTES_PER_WINDOW: u32 = 30;
const WINDOW: Duration = Duration::from_secs(600);
/// Keys remembered; past it the memory starts over and facts may repeat.
const KEYS_KEPT: usize = 1024;

#[derive(Default)]
pub(super) struct QueryNotes {
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    seen: HashSet<String>,
    window_started: Option<Instant>,
    written: u32,
    held_back: u64,
}

impl QueryNotes {
    /// `Some(held_back)` when the line for `key` is to be written, `held_back`
    /// being how many new facts were not written since the last line.
    pub(super) fn admit(&self, key: &str, now: Instant) -> Option<u64> {
        let mut s = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if s.seen.contains(key) {
            return None;
        }
        if s.window_started
            .is_none_or(|start| now.saturating_duration_since(start) >= WINDOW)
        {
            s.window_started = Some(now);
            s.written = 0;
        }
        if s.written >= NOTES_PER_WINDOW {
            s.held_back = s.held_back.saturating_add(1);
            return None;
        }
        if s.seen.len() >= KEYS_KEPT {
            s.seen.clear();
        }
        s.seen.insert(key.to_owned());
        s.written += 1;
        Some(std::mem::take(&mut s.held_back))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fact_repeated_on_every_query_is_written_once() {
        let notes = QueryNotes::default();
        let now = Instant::now();
        assert_eq!(notes.admit("resolver 10.0.0.53", now), Some(0));
        for _ in 0..1000 {
            assert_eq!(notes.admit("resolver 10.0.0.53", now), None);
        }
    }

    #[test]
    fn a_flood_of_new_names_is_capped_per_window_and_counted() {
        let notes = QueryNotes::default();
        let start = Instant::now();
        let written = (0..10_000)
            .filter(|n| {
                notes
                    .admit(&format!("shared n{n}.cdn.test"), start)
                    .is_some()
            })
            .count();
        assert_eq!(written, NOTES_PER_WINDOW as usize);

        let later = start + WINDOW;
        let held = notes.admit("shared next.cdn.test", later);
        assert_eq!(held, Some(10_000 - u64::from(NOTES_PER_WINDOW)));
    }
}
