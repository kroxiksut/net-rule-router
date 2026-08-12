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
    /// Serialises concurrent record/drain across the apply + observe threads.
    lock: Mutex<()>,
}

impl WfpFilterLedger {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            lock: Mutex::new(()),
        }
    }

    /// Append the given filter ids (best-effort — a failure is logged, ignored).
    pub fn record(&self, ids: &[WfpFilterId]) {
        if ids.is_empty() {
            return;
        }
        let _g = self.lock.lock().unwrap_or_else(|p| p.into_inner());
        match OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            Ok(mut f) => {
                let mut buf = String::with_capacity(ids.len() * 20);
                for id in ids {
                    let _ = writeln!(buf, "{}", id.raw);
                }
                if let Err(e) = f.write_all(buf.as_bytes()) {
                    tracing::warn!(target: "nrr::wfp-ledger", "ledger append failed: {e}");
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
        let _g = self.lock.lock().unwrap_or_else(|p| p.into_inner());
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
        let _g = self.lock.lock().unwrap_or_else(|p| p.into_inner());
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
