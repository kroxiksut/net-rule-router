//! Telling a service that keeps stopping unexpectedly from one that crashed once.
//!
//! One unclean stop changes nothing. A series of them inside a window withdraws
//! every confirmation of a protected rule, so a confirmed rule that brings the
//! service or the network down is not applied again on every restart. The
//! record is a small file in the data directory, which is closed to ordinary
//! users like the database holding the confirmations.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::override_grants::{Ending, OverrideGrants};

/// Unclean starts in a row, inside [`WINDOW_MS`], that count as a crash loop.
pub const THRESHOLD: usize = 3;
/// How far back an unclean start still counts toward a series.
pub const WINDOW_MS: i64 = 15 * 60 * 1000;

const FILE_NAME: &str = "service-run.state";
/// A real record is a few dozen bytes.
const MAX_FILE_BYTES: u64 = 4096;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct RunState {
    /// Set at start, cleared by a clean stop: still set at the next start means
    /// the last run did not stop cleanly.
    #[serde(default)]
    running: bool,
    /// Starts that followed an unclean stop, oldest first.
    #[serde(default)]
    unclean_ms: Vec<i64>,
}

impl RunState {
    /// The state after a start at `now_ms`, and whether it completes a series.
    fn started(mut self, now_ms: i64) -> (Self, bool) {
        if self.running {
            self.unclean_ms.push(now_ms);
        }
        self.unclean_ms
            .retain(|at| *at <= now_ms && now_ms.saturating_sub(*at) <= WINDOW_MS);
        let excess = self.unclean_ms.len().saturating_sub(THRESHOLD);
        self.unclean_ms.drain(..excess);
        let looping = self.unclean_ms.len() >= THRESHOLD;
        if looping {
            self.unclean_ms.clear();
        }
        self.running = true;
        (self, looping)
    }

    /// A clean stop ends the series.
    fn stopped(self) -> Self {
        Self::default()
    }
}

fn read(dir: &Path) -> RunState {
    let path = dir.join(FILE_NAME);
    let Ok(meta) = std::fs::metadata(&path) else {
        return RunState::default();
    };
    if meta.len() > MAX_FILE_BYTES {
        return RunState::default();
    }
    std::fs::read(&path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

fn write(dir: &Path, state: &RunState) -> std::io::Result<()> {
    let tmp = dir.join(format!("{FILE_NAME}.tmp"));
    let bytes = serde_json::to_vec(state).map_err(std::io::Error::other)?;
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, dir.join(FILE_NAME))
}

/// Record a start in `dir`; `true` when it completes a crash loop.
pub fn begin_run(dir: &Path, now_ms: i64) -> bool {
    let (state, looping) = read(dir).started(now_ms);
    if let Err(e) = write(dir, &state) {
        tracing::warn!(
            target: "nrr::override",
            msg_key = "svc-run-state-write-failed",
            error = %e,
            "the start could not be recorded; a crash loop would go unnoticed",
        );
    }
    looping
}

/// Record a clean stop in `dir`.
pub fn end_run(dir: &Path) {
    let _ = write(dir, &read(dir).stopped());
}

/// Record a start and, when it completes a crash loop, withdraw every
/// confirmation before the first enforcement pass reads one. Returns how many
/// users lost theirs.
pub fn withdraw_on_crash_loop(dir: &Path, grants: &OverrideGrants, now_ms: i64) -> usize {
    if !begin_run(dir, now_ms) {
        return 0;
    }
    tracing::warn!(
        target: "nrr::override",
        msg_key = "protection-override-crash-loop",
        "the service stopped unexpectedly several times in a row; every confirmation of a protected rule is withdrawn",
    );
    grants.revoke_all(Ending::CrashLoop, now_ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: i64 = 1_000_000_000;

    #[test]
    fn a_clean_start_after_a_clean_stop_is_no_series() {
        let (state, looping) = RunState::default().started(T0);
        assert!(!looping);
        let (_, looping) = state.stopped().started(T0 + 1000);
        assert!(!looping);
    }

    #[test]
    fn a_series_below_the_threshold_is_not_a_loop() {
        let mut state = RunState::default();
        for step in 0..THRESHOLD {
            let (next, looping) = state.started(T0 + step as i64 * 1000);
            assert!(!looping, "start {step}");
            state = next;
        }
    }

    #[test]
    fn the_threshold_completes_the_loop_and_starts_a_new_series() {
        let mut state = RunState::default();
        let mut looped_at = None;
        for step in 0..=THRESHOLD {
            let (next, looping) = state.started(T0 + step as i64 * 1000);
            if looping {
                looped_at = Some(step);
                assert!(next.unclean_ms.is_empty());
            }
            state = next;
        }
        assert_eq!(looped_at, Some(THRESHOLD));
    }

    #[test]
    fn a_clean_stop_resets_the_series() {
        let mut state = RunState::default();
        for step in 0..THRESHOLD {
            state = state.started(T0 + step as i64 * 1000).0;
        }
        let (_, looping) = state.stopped().started(T0 + 10_000);
        assert!(!looping);
    }

    #[test]
    fn old_crashes_fall_out_of_the_window() {
        let mut state = RunState::default();
        for step in 0..THRESHOLD {
            state = state.started(T0 + step as i64 * 1000).0;
        }
        let (_, looping) = state.started(T0 + WINDOW_MS + 60_000);
        assert!(!looping);
    }

    #[test]
    fn the_record_survives_in_a_file_and_a_damaged_one_reads_clean() {
        let dir = tempfile::tempdir().expect("tempdir");
        for step in 0..THRESHOLD as i64 {
            assert!(!begin_run(dir.path(), T0 + step));
        }
        assert!(begin_run(dir.path(), T0 + 10));
        end_run(dir.path());
        assert_eq!(read(dir.path()), RunState::default());
        std::fs::write(dir.path().join(FILE_NAME), b"not json").expect("write");
        assert_eq!(read(dir.path()), RunState::default());
    }
}
