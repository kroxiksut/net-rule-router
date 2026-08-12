//! Audit NDJSON trail reader and chain verifier.
//!
//! # Scan model
//!
//! Files are scanned in lexicographic order (which equals chronological order
//! because filenames embed the UTC date + rotation index).  Each file is read
//! line-by-line; lines that fail to parse are counted as corrupt but do not
//! abort the scan.
//!
//! # Chain verification
//!
//! [`AuditReader::verify_chain`] reads the most-recent audit file and verifies
//! that the rolling hash chain is intact.  A mismatch at any sequence number
//! is reported with the offending seq and the expected vs. actual hashes.

use std::path::{Path, PathBuf};

use crate::audit::writer::{compute_chain_hash, AUDIT_CHAIN_GENESIS};
use crate::event::AuditEvent;

// ── AuditQueryFilter ──────────────────────────────────────────────────────────

/// Filter applied during an audit NDJSON scan.
#[derive(Clone, Debug, Default)]
pub struct AuditQueryFilter {
    /// Only return events at or after this UTC Unix milliseconds timestamp.
    pub from_ms: Option<i64>,
    /// Only return events at or before this UTC Unix milliseconds timestamp.
    pub to_ms: Option<i64>,
    /// Only return events whose `kind` matches this string.
    pub kind: Option<String>,
    /// Only return events associated with this revision id.
    pub revision_id: Option<String>,
}

impl AuditQueryFilter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_ms(mut self, ms: i64) -> Self {
        self.from_ms = Some(ms);
        self
    }
    pub fn to_ms(mut self, ms: i64) -> Self {
        self.to_ms = Some(ms);
        self
    }
    pub fn kind(mut self, kind: impl Into<String>) -> Self {
        self.kind = Some(kind.into());
        self
    }
    pub fn revision_id(mut self, id: impl Into<String>) -> Self {
        self.revision_id = Some(id.into());
        self
    }

    fn matches(&self, event: &AuditEvent) -> bool {
        if let Some(from) = self.from_ms {
            if event.created_at < from {
                return false;
            }
        }
        if let Some(to) = self.to_ms {
            if event.created_at > to {
                return false;
            }
        }
        if let Some(kind) = &self.kind {
            if &event.kind != kind {
                return false;
            }
        }
        if let Some(rev) = &self.revision_id {
            if event.revision_id.as_deref() != Some(rev.as_str()) {
                return false;
            }
        }
        true
    }
}

// ── AuditChainVerification ────────────────────────────────────────────────────

/// Result of verifying the rolling hash chain in an audit file.
#[derive(Clone, Debug)]
pub struct AuditChainVerification {
    /// `true` if all hashes in the scanned file are intact.
    pub chain_ok: bool,
    /// Number of events successfully verified.
    pub events_verified: usize,
    /// Sequence number of the first hash mismatch, if any.
    pub mismatch_at_seq: Option<u64>,
    /// Expected hash at the mismatch position.
    pub expected_hash: Option<String>,
    /// Actual stored hash at the mismatch position.
    pub actual_hash: Option<String>,
    /// Number of lines in the file that could not be parsed.
    pub corrupt_lines: usize,
}

impl AuditChainVerification {
    pub fn ok(events_verified: usize) -> Self {
        Self {
            chain_ok: true,
            events_verified,
            mismatch_at_seq: None,
            expected_hash: None,
            actual_hash: None,
            corrupt_lines: 0,
        }
    }
}

// ── AuditReader ───────────────────────────────────────────────────────────────

/// Read-only accessor for audit NDJSON files.
pub struct AuditReader {
    audit_dir: PathBuf,
}

impl AuditReader {
    pub fn new(audit_dir: impl Into<PathBuf>) -> Self {
        Self {
            audit_dir: audit_dir.into(),
        }
    }

    /// Returns all audit files in the directory, sorted lexicographically
    /// (which equals chronological order for `nrr_audit_YYYYMMDD-N.ndjson`).
    pub fn list_files(&self) -> Vec<PathBuf> {
        list_audit_files(&self.audit_dir)
    }

    /// Scans all files and returns events matching `filter`.
    pub fn scan(&self, filter: &AuditQueryFilter) -> Vec<AuditEvent> {
        let mut results = Vec::new();
        for path in self.list_files() {
            let events = parse_events_from_file(&path);
            for event in events {
                if filter.matches(&event) {
                    results.push(event);
                }
            }
        }
        results
    }

    /// Verifies the hash chain of the most recent audit file.
    ///
    /// Returns `AuditChainVerification::ok(0)` if no files exist.
    pub fn verify_latest_chain(&self) -> AuditChainVerification {
        let files = self.list_files();
        match files.split_last() {
            None => AuditChainVerification::ok(0),
            Some((latest, earlier)) => {
                // The audit writer continues the hash chain across
                // file rotations (`AuditWriterInner::rotate` keeps
                // `prev_hash`), so the FIRST event of the latest
                // file expects `prev = last hash of the prior file`.
                // Verifying the latest file in isolation against
                // `AUDIT_CHAIN_GENESIS` would always fail on the
                // first event whenever rotation has happened. Seed
                // `prev` from the last event of the most recent
                // earlier file when present.
                let seed = earlier
                    .iter()
                    .rev()
                    .find_map(|p| last_event_hash_in_file(p))
                    .unwrap_or_else(|| AUDIT_CHAIN_GENESIS.to_string());
                verify_chain_in_file_with_seed(latest, &seed)
            }
        }
    }

    /// Verifies the hash chain of a specific file.
    pub fn verify_chain_in_file(&self, path: &Path) -> AuditChainVerification {
        verify_chain_in_file(path)
    }

    /// Returns raw audit NDJSON lines VERBATIM (each line exactly as written,
    /// including the `prev_hash` / `event_hash` chain fields), keeping the most
    /// recent events whose combined size fits `max_bytes`.
    ///
    /// The returned slice is a CONTIGUOUS suffix of the chronological chain (the
    /// oldest lines are dropped first when over budget), so the chain stays
    /// re-verifiable from the first included line's `prev_hash` forward. Lines
    /// are returned oldest-first, matching on-disk order. Empty lines are
    /// skipped; no parsing is done, so a corrupt line is preserved verbatim for
    /// the triager rather than silently dropped.
    ///
    /// Backs the diagnostic archive's `audit_chain.ndjson`
    /// ([`crate::facade::service::DiagnosticsFacade::recent_audit_chain_lines`]).
    pub fn recent_raw_lines(&self, max_bytes: usize) -> Vec<String> {
        if max_bytes == 0 {
            return Vec::new();
        }
        // Collect every line across all files in chronological order.
        let mut lines: Vec<String> = Vec::new();
        for path in self.list_files() {
            let Ok(contents) = std::fs::read_to_string(&path) else {
                continue;
            };
            for line in contents.lines() {
                if !line.is_empty() {
                    lines.push(line.to_string());
                }
            }
        }
        // Keep the newest contiguous suffix under the byte budget. Walk from the
        // end summing each line plus its newline; always keep the newest line,
        // then stop before adding the (older) line that would overflow.
        let mut kept_from = lines.len();
        let mut used: usize = 0;
        for (idx, line) in lines.iter().enumerate().rev() {
            let cost = line.len() + 1; // +1 for the newline separator
            if kept_from != lines.len() && used + cost > max_bytes {
                break;
            }
            used += cost;
            kept_from = idx;
        }
        lines.split_off(kept_from)
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn list_audit_files(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with("nrr_audit_") && n.ends_with(".ndjson"))
                .unwrap_or(false)
        })
        .collect();
    files.sort();
    files
}

/// Returns the `event_hash` of the last well-formed event in the
/// file, or `None` if the file is missing/empty/all-corrupt. Used
/// to seed cross-file chain verification.
fn last_event_hash_in_file(path: &Path) -> Option<String> {
    let content = std::fs::read_to_string(path).ok()?;
    content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .rev()
        .find_map(|l| serde_json::from_str::<AuditEvent>(l).ok())
        .map(|e| e.event_hash)
}

fn parse_events_from_file(path: &Path) -> Vec<AuditEvent> {
    let Ok(content) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

fn verify_chain_in_file(path: &Path) -> AuditChainVerification {
    verify_chain_in_file_with_seed(path, AUDIT_CHAIN_GENESIS)
}

fn verify_chain_in_file_with_seed(path: &Path, seed_prev_hash: &str) -> AuditChainVerification {
    let Ok(content) = std::fs::read_to_string(path) else {
        return AuditChainVerification {
            chain_ok: false,
            events_verified: 0,
            mismatch_at_seq: None,
            expected_hash: None,
            actual_hash: None,
            corrupt_lines: 1,
        };
    };

    let mut prev = seed_prev_hash.to_string();
    let mut verified = 0usize;
    let mut corrupt = 0usize;

    for line in content.lines().filter(|l| !l.trim().is_empty()) {
        let Ok(event): Result<AuditEvent, _> = serde_json::from_str(line) else {
            corrupt += 1;
            continue;
        };

        // Recompute: strip event_hash from event, serialize, hash.
        let mut canonical_event = event.clone();
        let stored_hash = canonical_event.event_hash.clone();
        canonical_event.event_hash = String::new();
        let Ok(canonical) = serde_json::to_string(&canonical_event) else {
            corrupt += 1;
            continue;
        };

        let expected = compute_chain_hash(&prev, &canonical);
        if expected != stored_hash {
            return AuditChainVerification {
                chain_ok: false,
                events_verified: verified,
                mismatch_at_seq: Some(event.seq),
                expected_hash: Some(expected),
                actual_hash: Some(stored_hash),
                corrupt_lines: corrupt,
            };
        }
        prev = stored_hash;
        verified += 1;
    }

    AuditChainVerification {
        chain_ok: true,
        events_verified: verified,
        mismatch_at_seq: None,
        expected_hash: None,
        actual_hash: None,
        corrupt_lines: corrupt,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::kind::{ActorKind, AuditEventKind, AuditEventResult};
    use crate::audit::writer::{AuditEventInput, AuditWriter, AuditWriterConfig};
    use crate::reason;
    use crate::sink::AuditSink;

    fn write_events(dir: &Path, n: u32) {
        let writer = AuditWriter::open(AuditWriterConfig::new(dir));
        for i in 1..=n {
            let input = AuditEventInput {
                event_id: format!("adt-{i:04}"),
                kind: AuditEventKind::RevisionActivated,
                created_at: 1_745_000_000_000 + i as i64 * 1000,
                actor_kind: ActorKind::User,
                actor_id_hash: None,
                revision_id: Some("rev-001".into()),
                risk_level: None,
                result: AuditEventResult::Success,
                reason_code: reason::review::APPROVED,
                payload_summary_json: None,
            };
            writer.append(input).expect("append");
        }
    }

    #[test]
    fn list_files_empty_dir() {
        let dir = tempfile::tempdir().expect("temp");
        let reader = AuditReader::new(dir.path());
        assert!(reader.list_files().is_empty());
    }

    #[test]
    fn list_files_after_writes() {
        let dir = tempfile::tempdir().expect("temp");
        write_events(dir.path(), 3);
        let reader = AuditReader::new(dir.path());
        assert_eq!(reader.list_files().len(), 1);
    }

    #[test]
    fn scan_returns_all_events() {
        let dir = tempfile::tempdir().expect("temp");
        write_events(dir.path(), 5);
        let reader = AuditReader::new(dir.path());
        let events = reader.scan(&AuditQueryFilter::new());
        assert_eq!(events.len(), 5);
    }

    #[test]
    fn recent_raw_lines_returns_verbatim_chain_fields() {
        let dir = tempfile::tempdir().expect("temp");
        write_events(dir.path(), 3);
        let reader = AuditReader::new(dir.path());
        let lines = reader.recent_raw_lines(1024 * 1024);
        assert_eq!(lines.len(), 3);
        // Raw lines keep the chain fields the AuditEntryDto summary drops.
        // `event_hash` is on every event; `prev_hash` is on every event EXCEPT
        // the genesis one (its prev is empty and omitted from serialization).
        assert!(lines.iter().all(|l| l.contains("event_hash")), "{lines:?}");
        assert!(lines[1].contains("prev_hash"), "{}", lines[1]);
        assert!(lines[2].contains("prev_hash"), "{}", lines[2]);
        // Oldest-first, matching on-disk order (seq 1 line first, seq 3 last).
        assert!(lines[0].contains("adt-0001"), "{}", lines[0]);
        assert!(lines[2].contains("adt-0003"), "{}", lines[2]);
    }

    #[test]
    fn recent_raw_lines_keeps_the_newest_suffix_under_budget() {
        let dir = tempfile::tempdir().expect("temp");
        write_events(dir.path(), 5);
        let reader = AuditReader::new(dir.path());
        let all = reader.recent_raw_lines(usize::MAX);
        assert_eq!(all.len(), 5);
        // Budget that fits only the last two lines plus their newlines.
        let budget = all[3].len() + 1 + all[4].len() + 1;
        let trimmed = reader.recent_raw_lines(budget);
        assert_eq!(trimmed.len(), 2, "keeps the newest contiguous suffix");
        assert_eq!(trimmed[0], all[3]);
        assert_eq!(trimmed[1], all[4]);
    }

    #[test]
    fn recent_raw_lines_always_keeps_at_least_the_newest_line() {
        let dir = tempfile::tempdir().expect("temp");
        write_events(dir.path(), 3);
        let reader = AuditReader::new(dir.path());
        // A budget smaller than any single line still yields the newest one, so
        // the section is never empty when audit data exists.
        let trimmed = reader.recent_raw_lines(1);
        assert_eq!(trimmed.len(), 1);
        let all = reader.recent_raw_lines(usize::MAX);
        assert_eq!(trimmed[0], all[2]);
    }

    #[test]
    fn recent_raw_lines_zero_budget_is_empty() {
        let dir = tempfile::tempdir().expect("temp");
        write_events(dir.path(), 3);
        let reader = AuditReader::new(dir.path());
        assert!(reader.recent_raw_lines(0).is_empty());
    }

    #[test]
    fn scan_filters_by_kind() {
        let dir = tempfile::tempdir().expect("temp");
        write_events(dir.path(), 3);

        // Add a tamper alert event.
        let writer = AuditWriter::open(AuditWriterConfig::new(dir.path()));
        let tamper = AuditEventInput {
            event_id: "adt-tamper".into(),
            kind: AuditEventKind::TamperAlertRaised,
            created_at: 1_745_001_000_000,
            actor_kind: ActorKind::System,
            actor_id_hash: None,
            revision_id: None,
            risk_level: None,
            result: AuditEventResult::Failure,
            reason_code: reason::integrity::AUDIT_CHAIN_MISMATCH,
            payload_summary_json: None,
        };
        writer.append(tamper).expect("append tamper");

        let reader = AuditReader::new(dir.path());
        let tamper_events = reader.scan(&AuditQueryFilter::new().kind("tamper_alert_raised"));
        assert_eq!(tamper_events.len(), 1);
    }

    #[test]
    fn scan_filters_by_revision_id() {
        let dir = tempfile::tempdir().expect("temp");
        write_events(dir.path(), 3); // all have rev-001

        // Add event with different revision.
        let writer = AuditWriter::open(AuditWriterConfig::new(dir.path()));
        let input = AuditEventInput {
            event_id: "adt-rev2".into(),
            kind: AuditEventKind::RevisionActivated,
            created_at: 1_745_002_000_000,
            actor_kind: ActorKind::User,
            actor_id_hash: None,
            revision_id: Some("rev-002".into()),
            risk_level: None,
            result: AuditEventResult::Success,
            reason_code: reason::review::APPROVED,
            payload_summary_json: None,
        };
        writer.append(input).expect("append");

        let reader = AuditReader::new(dir.path());
        let rev2 = reader.scan(&AuditQueryFilter::new().revision_id("rev-002"));
        assert_eq!(rev2.len(), 1);
    }

    #[test]
    fn verify_latest_chain_ok_for_valid_file() {
        let dir = tempfile::tempdir().expect("temp");
        write_events(dir.path(), 4);
        let reader = AuditReader::new(dir.path());
        let v = reader.verify_latest_chain();
        assert!(v.chain_ok, "chain must be valid for freshly written events");
        assert_eq!(v.events_verified, 4);
        assert_eq!(v.corrupt_lines, 0);
    }

    #[test]
    fn verify_latest_chain_ok_for_empty_dir() {
        let dir = tempfile::tempdir().expect("temp");
        let reader = AuditReader::new(dir.path());
        let v = reader.verify_latest_chain();
        assert!(v.chain_ok);
        assert_eq!(v.events_verified, 0);
    }

    #[test]
    fn verify_latest_chain_ok_when_chain_spans_two_files() {
        // Regression for the false-positive "audit chain mismatch"
        // banner: the writer keeps `prev_hash` across rotations, so
        // the first event of the latest file has prev = last hash
        // of the prior file. Verifying the latest file alone with
        // `AUDIT_CHAIN_GENESIS` as the seed used to fail on every
        // multi-file deployment.
        let dir = tempfile::tempdir().expect("temp");
        // Write the first file.
        write_events(dir.path(), 3);
        // Force rotation by renaming the existing file so the next
        // write opens a fresh one with an incremented suffix.
        let files = list_audit_files(dir.path());
        assert_eq!(files.len(), 1);
        let first = files[0].clone();
        let rotated = first.with_file_name("nrr_audit_20260101-1.ndjson");
        std::fs::rename(&first, &rotated).expect("rename");
        // Append more events; AuditWriter::open reads the last hash
        // from the rotated file to continue the chain.
        write_events(dir.path(), 2);
        let after = list_audit_files(dir.path());
        assert_eq!(after.len(), 2, "must have two audit files now");
        let reader = AuditReader::new(dir.path());
        let v = reader.verify_latest_chain();
        assert!(
            v.chain_ok,
            "chain must verify across file rotations (events_verified={}, mismatch_at_seq={:?})",
            v.events_verified, v.mismatch_at_seq
        );
    }

    #[test]
    fn verify_chain_detects_corruption() {
        let dir = tempfile::tempdir().expect("temp");
        write_events(dir.path(), 3);

        // Corrupt the file by appending a malformed line.
        let path = std::fs::read_dir(dir.path())
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let content = std::fs::read_to_string(&path).expect("read");
        // Tamper with the second line's event_hash.
        let lines: Vec<&str> = content.lines().collect();
        let mut tampered: serde_json::Value = serde_json::from_str(lines[1]).expect("parse line 2");
        tampered["event_hash"] = serde_json::json!("deadbeefdeadbeef");
        let new_line = serde_json::to_string(&tampered).expect("serialize");
        // Rebuild file with tampered second line.
        let new_content = format!("{}\n{}\n{}\n", lines[0], new_line, lines[2]);
        std::fs::write(&path, new_content).expect("write tampered");

        let reader = AuditReader::new(dir.path());
        let v = reader.verify_latest_chain();
        assert!(!v.chain_ok, "corruption must be detected");
        assert!(v.mismatch_at_seq.is_some());
    }

    #[test]
    fn files_are_sorted_lexicographically() {
        let dir = tempfile::tempdir().expect("temp");
        // Write two files with different names to test sorting.
        std::fs::write(dir.path().join("nrr_audit_20260423-2.ndjson"), "").unwrap();
        std::fs::write(dir.path().join("nrr_audit_20260423-1.ndjson"), "").unwrap();
        std::fs::write(dir.path().join("nrr_audit_20260422-1.ndjson"), "").unwrap();

        let reader = AuditReader::new(dir.path());
        let files = reader.list_files();
        let names: Vec<_> = files
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            names,
            [
                "nrr_audit_20260422-1.ndjson",
                "nrr_audit_20260423-1.ndjson",
                "nrr_audit_20260423-2.ndjson",
            ]
        );
    }
}
