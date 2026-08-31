//! on-disk ledger of installed WFP filter ids.
//!
//! The WFP session is **non-dynamic** (the deliberate fail-safe posture for a
//! leak-protection tool: block filters survive a service crash, so there is no
//! leak window while the supervisor restarts). The cost is that a hard-kill
//! that skips graceful cleanup leaves the filters behind until they are stripped
//! — and the startup strip that removes them relies on `wfp_enumerate_our_
//! filters`, whose reliability the `stripped_filters:0` HW anomaly put in doubt.
//!
//! This append-only ledger closes that gap WITHOUT going dynamic: every filter
//! id the service installs is recorded to a small file, so a FRESH process
//! (after a hard-kill) can delete the prior instance's orphaned filters **by
//! id** — independent of enumerate. A hard-kill lockout therefore always
//! self-heals on the next service start.
//!
//! Best-effort throughout: a write/read failure is logged and ignored — booting
//! and applying must never hinge on the ledger, and the enumerate-based strip
//! remains as defence in depth.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::Mutex;

use nrr_platform_api::types::WfpFilterId;

/// Append-only file of the raw `u64` WFP filter ids this service installed.
/// One id per line. Truncated on drain (startup cleanup) and on graceful stop.
pub struct WfpFilterLedger {
    path: PathBuf,
    /// Ids this process has already written, and the lock that serialises
    /// record/drain across the apply + observe threads.
    ///
    /// The reconcile re-records the same ids every pass it touches anything, so
    /// without this the file grew for the life of the service (a two-hour
    /// session left 182 KB of the same few hundred ids) and every pass paid an
    /// open+append on the enforcement path for nothing. The reader deduplicates
    /// anyway — this just stops writing what is already there.
    written: Mutex<BTreeSet<u64>>,
}

impl WfpFilterLedger {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            written: Mutex::new(BTreeSet::new()),
        }
    }

    /// Append the given filter ids (best-effort — a failure is logged, ignored).
    /// Ids already written this session are skipped, so an unchanged pass does
    /// not touch the disk at all.
    pub fn record(&self, ids: &[WfpFilterId]) {
        if ids.is_empty() {
            return;
        }
        let mut written = self.written.lock().unwrap_or_else(|p| p.into_inner());
        let fresh: Vec<u64> = ids
            .iter()
            .map(|id| id.raw)
            .filter(|raw| !written.contains(raw))
            .collect();
        if fresh.is_empty() {
            return;
        }
        match OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            Ok(mut f) => {
                let mut buf = String::with_capacity(fresh.len() * 20);
                for raw in &fresh {
                    let _ = writeln!(buf, "{raw}");
                }
                match f.write_all(buf.as_bytes()) {
                    // Remember only what reached the file: a failed write must
                    // stay retryable on the next pass, or the id is orphaned
                    // with nothing on disk to reap it by.
                    Ok(()) => written.extend(fresh),
                    Err(e) => {
                        tracing::warn!(target: "nrr::wfp-ledger", "ledger append failed: {e}")
                    }
                }
            }
            Err(e) => {
                tracing::warn!(target: "nrr::wfp-ledger", "ledger open-for-append failed: {e}")
            }
        }
    }

    /// Read every recorded id (deduped), then TRUNCATE the ledger. A missing
    /// file yields an empty vec. Called once at startup to reap a prior
    /// instance's orphaned filters.
    pub fn drain(&self) -> Vec<u64> {
        let mut written = self.written.lock().unwrap_or_else(|p| p.into_inner());
        written.clear();
        let ids: Vec<u64> = match File::open(&self.path) {
            Ok(f) => {
                let mut set: BTreeSet<u64> = BTreeSet::new();
                for line in BufReader::new(f).lines().map_while(Result::ok) {
                    let t = line.trim();
                    if !t.is_empty() {
                        if let Ok(v) = t.parse::<u64>() {
                            set.insert(v);
                        }
                    }
                }
                set.into_iter().collect()
            }
            Err(_) => Vec::new(),
        };
        // Truncate so the current process starts with a clean ledger.
        let _ = File::create(&self.path);
        ids
    }

    /// Truncate the ledger — graceful stop already deleted the filters, so the
    /// next start has nothing to reap.
    pub fn clear(&self) {
        let mut written = self.written.lock().unwrap_or_else(|p| p.into_inner());
        written.clear();
        let _ = File::create(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(raw: u64) -> WfpFilterId {
        WfpFilterId { raw }
    }

    #[test]
    fn record_then_drain_returns_deduped_ids_and_truncates() {
        let dir = tempfile::tempdir().expect("temp dir");
        let ledger = WfpFilterLedger::new(dir.path().join("wfp.ledger"));

        ledger.record(&[id(10), id(20)]);
        ledger.record(&[id(20), id(30)]); // 20 duplicated across appends

        let mut got = ledger.drain();
        got.sort_unstable();
        assert_eq!(got, vec![10, 20, 30], "deduped union of all appends");

        // Drain truncated the ledger.
        assert!(ledger.drain().is_empty(), "second drain is empty");
    }

    #[test]
    fn re_recording_the_same_ids_does_not_grow_the_file() {
        // The reconcile hands the same ids back on every pass it touches
        // anything; the file used to grow for the life of the service.
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("wfp.ledger");
        let ledger = WfpFilterLedger::new(path.clone());

        ledger.record(&[id(10), id(20)]);
        let after_first = std::fs::metadata(&path).expect("ledger file").len();
        for _ in 0..50 {
            ledger.record(&[id(10), id(20)]);
        }
        assert_eq!(
            std::fs::metadata(&path).expect("ledger file").len(),
            after_first,
            "a pass that installs nothing new must not write"
        );

        // A genuinely new id still lands.
        ledger.record(&[id(20), id(30)]);
        let mut got = ledger.drain();
        got.sort_unstable();
        assert_eq!(got, vec![10, 20, 30]);

        // After a drain the session starts over: the same id is written again,
        // because the file it would be reaped from is empty now.
        ledger.record(&[id(10)]);
        assert_eq!(ledger.drain(), vec![10]);
    }

    #[test]
    fn drain_missing_file_is_empty() {
        let dir = tempfile::tempdir().expect("temp dir");
        let ledger = WfpFilterLedger::new(dir.path().join("absent.ledger"));
        assert!(ledger.drain().is_empty());
    }

    #[test]
    fn clear_truncates() {
        let dir = tempfile::tempdir().expect("temp dir");
        let ledger = WfpFilterLedger::new(dir.path().join("wfp.ledger"));
        ledger.record(&[id(1), id(2)]);
        ledger.clear();
        assert!(ledger.drain().is_empty());
    }

    #[test]
    fn record_empty_is_noop() {
        let dir = tempfile::tempdir().expect("temp dir");
        let ledger = WfpFilterLedger::new(dir.path().join("wfp.ledger"));
        ledger.record(&[]);
        assert!(ledger.drain().is_empty());
    }
}
