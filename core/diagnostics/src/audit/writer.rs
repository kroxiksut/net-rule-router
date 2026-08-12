//! Append-only NDJSON audit trail writer with rolling hash chain.
//!
//! # File naming
//!
//! Audit files are stored in a dedicated `audit/` directory with names of the
//! form `nrr_audit_YYYYMMDD-N.ndjson` (local date, `N` starting at 1).
//! When a file exceeds [`AuditWriterConfig::max_file_size_bytes`], a new file
//! is created for the next write (`N` increments).
//!
//! # Hash chain
//!
//! Each event carries:
//! - `seq` — monotonic sequence number within the file (resets to 1 per file).
//! - `prev_hash` — the `event_hash` of the previous event (or genesis constant
//!   for the first event in a file).
//! - `event_hash` — `SHA-256(prev_hash || canonical_payload_json)`.
//!
//! On startup the [`crate::audit::reader::AuditReader`] verifies the chain for
//! the most recent file and raises `integrity.audit_chain_mismatch` on failure.
//!
//! # Append-only invariant
//!
//! The public API has no update or delete methods.  Files are only written in
//! append mode.  Acknowledgement / resolution events are new NDJSON lines —
//! never overwrites of earlier lines.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use sha2::{Digest, Sha256};

use crate::audit::kind::{ActorKind, AuditEventKind, AuditEventResult};
use crate::error::{DiagnosticsError, DiagnosticsResult};
use crate::event::{AuditEvent, AUDIT_EVENT_SCHEMA_VERSION};
use crate::reason::ReasonCode;
use crate::sink::AuditSink;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Genesis hash used as `prev_hash` for the first event in a new file.
pub const AUDIT_CHAIN_GENESIS: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Default maximum file size before rotation (10 MiB).
pub const DEFAULT_MAX_FILE_SIZE_BYTES: u64 = 10 * 1024 * 1024;

// ── AuditEventInput ───────────────────────────────────────────────────────────

/// Caller-supplied fields for a new audit event.
///
/// The writer fills in `seq`, `prev_hash`, and `event_hash` before persisting.
pub struct AuditEventInput {
    /// Unique event id (`adt-{uuid_v4}`), assigned by the caller (service layer).
    pub event_id: String,
    /// The security-visible action that occurred.
    pub kind: AuditEventKind,
    /// UTC Unix milliseconds.
    pub created_at: i64,
    /// Who performed the action.
    pub actor_kind: ActorKind,
    /// One-way hash of the actor identifier.  Never the raw username.
    pub actor_id_hash: Option<String>,
    /// Active policy revision at event time.
    pub revision_id: Option<String>,
    /// Risk level (from review/import system).
    pub risk_level: Option<String>,
    /// Outcome of the action.
    pub result: AuditEventResult,
    /// Namespaced reason code.
    pub reason_code: ReasonCode,
    /// Compact redacted payload summary (max ~200 chars).
    pub payload_summary_json: Option<String>,
}

// ── AuditWriterConfig ─────────────────────────────────────────────────────────

/// Configuration for an [`AuditWriter`].
#[derive(Clone, Debug)]
pub struct AuditWriterConfig {
    /// Directory where `nrr_audit_*.ndjson` files are stored.
    pub audit_dir: PathBuf,
    /// Rotate to a new file when the current exceeds this size (bytes).
    pub max_file_size_bytes: u64,
}

impl AuditWriterConfig {
    pub fn new(audit_dir: impl Into<PathBuf>) -> Self {
        Self {
            audit_dir: audit_dir.into(),
            max_file_size_bytes: DEFAULT_MAX_FILE_SIZE_BYTES,
        }
    }
}

// ── AuditWriter internals ─────────────────────────────────────────────────────

struct AuditWriterInner {
    config: AuditWriterConfig,
    /// Currently open file and its path.
    current: Option<(File, PathBuf)>,
    /// Current approximate file size (bytes written since open).
    current_size: u64,
    /// Last hash written (or genesis if no events written yet in this file).
    prev_hash: String,
    /// Next sequence number within the current file.
    next_seq: u64,
}

// `expect()`s here are invariants (file open right after `ensure_open`) and
// lock-poisoning propagation — both panic-worthy, not recoverable errors.
#[allow(clippy::expect_used)]
impl AuditWriterInner {
    fn new(config: AuditWriterConfig) -> Self {
        Self {
            config,
            current: None,
            current_size: 0,
            prev_hash: AUDIT_CHAIN_GENESIS.to_string(),
            next_seq: 1,
        }
    }

    /// Ensures a writable file is open, rotating if needed.
    fn ensure_open(&mut self) -> DiagnosticsResult<()> {
        let needs_open = match &self.current {
            None => true,
            Some(_) => self.current_size >= self.config.max_file_size_bytes,
        };
        if needs_open {
            self.rotate()?;
        }
        Ok(())
    }

    fn rotate(&mut self) -> DiagnosticsResult<()> {
        // Close the old file (implicitly via drop).
        self.current = None;

        let path = next_audit_filename(&self.config.audit_dir);
        std::fs::create_dir_all(&self.config.audit_dir).map_err(|e| {
            DiagnosticsError::AuditWriteFailed {
                reason: format!("cannot create audit dir: {e}"),
            }
        })?;
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| DiagnosticsError::AuditWriteFailed {
                reason: format!("cannot open audit file {}: {e}", path.display()),
            })?;
        self.current_size = file.metadata().map(|m| m.len()).unwrap_or(0);
        // prev_hash intentionally NOT reset here — the chain continues
        // across file rotations and service restarts.  Genesis is only set
        // in new() (no prior audit files exist at all).
        self.next_seq = 1;
        self.current = Some((file, path));
        Ok(())
    }

    fn append_inner(&mut self, input: AuditEventInput) -> DiagnosticsResult<()> {
        self.ensure_open()?;

        let seq = self.next_seq;
        let (_canonical, event) = build_event(&input, seq, &self.prev_hash)?;
        let event_hash = event.event_hash.clone();

        let line = event
            .to_ndjson()
            .map_err(|e| DiagnosticsError::AuditWriteFailed {
                reason: format!("serialize audit event: {e}"),
            })?;
        let line_with_newline = format!("{line}\n");

        let (file, _path) = self.current.as_mut().expect("file open after ensure_open");
        file.write_all(line_with_newline.as_bytes()).map_err(|e| {
            DiagnosticsError::AuditWriteFailed {
                reason: format!("write audit line: {e}"),
            }
        })?;
        file.flush()
            .map_err(|e| DiagnosticsError::AuditWriteFailed {
                reason: format!("flush audit file: {e}"),
            })?;

        self.current_size += line_with_newline.len() as u64;
        self.prev_hash = event_hash;
        self.next_seq += 1;
        Ok(())
    }
}

// ── AuditWriter ───────────────────────────────────────────────────────────────

/// Thread-safe, append-only NDJSON audit trail writer.
///
/// Implements [`AuditSink<AuditEventInput>`] so it can be injected wherever
/// an `AuditSink` is expected.
pub struct AuditWriter {
    inner: Mutex<AuditWriterInner>,
}

impl AuditWriter {
    /// Opens (or creates) the audit writer for the given configuration.
    ///
    /// On startup, scans the audit directory for the most recent file and
    /// reads its last `event_hash` to continue the rolling hash chain.
    /// This ensures chain continuity across service restarts.
    ///
    /// If no prior audit files exist, the chain starts from
    /// [`AUDIT_CHAIN_GENESIS`].
    pub fn open(config: AuditWriterConfig) -> Self {
        let (prev_hash, next_seq) = resume_chain_state(&config.audit_dir);
        let mut inner = AuditWriterInner::new(config);
        inner.prev_hash = prev_hash;
        inner.next_seq = next_seq;
        Self {
            inner: Mutex::new(inner),
        }
    }
}

// Lock-poisoning `expect()` propagates a prior panic — not recoverable.
#[allow(clippy::expect_used)]
impl AuditSink for AuditWriter {
    type Event = AuditEventInput;

    fn append(&self, input: AuditEventInput) -> Result<(), DiagnosticsError> {
        self.inner
            .lock()
            .expect("AuditWriter mutex")
            .append_inner(input)
    }
}

// ── Hash chain helpers ────────────────────────────────────────────────────────

/// Builds the canonical payload JSON (without `event_hash`) and the full event.
fn build_event(
    input: &AuditEventInput,
    seq: u64,
    prev_hash: &str,
) -> DiagnosticsResult<(String, AuditEvent)> {
    // Build a preliminary AuditEvent without event_hash so we can hash it.
    let mut event = AuditEvent {
        schema_version: AUDIT_EVENT_SCHEMA_VERSION,
        seq,
        event_id: input.event_id.clone(),
        kind: input.kind.as_str().to_string(),
        created_at: input.created_at,
        actor_kind: input.actor_kind.as_str().to_string(),
        actor_id_hash: input.actor_id_hash.clone(),
        revision_id: input.revision_id.clone(),
        risk_level: input.risk_level.clone(),
        result: input.result.as_str().to_string(),
        reason_code: input.reason_code.as_str().to_string(),
        payload_summary_json: input.payload_summary_json.clone(),
        prev_hash: if prev_hash == AUDIT_CHAIN_GENESIS {
            None
        } else {
            Some(prev_hash.to_string())
        },
        event_hash: String::new(), // filled below
    };

    // Canonical payload = the full event JSON (without event_hash field).
    // We use the JSON of the event with an empty event_hash, then hash that.
    let canonical =
        serde_json::to_string(&event).map_err(|e| DiagnosticsError::AuditWriteFailed {
            reason: format!("canonical serialization failed: {e}"),
        })?;

    let event_hash = compute_chain_hash(prev_hash, &canonical);
    event.event_hash = event_hash;

    Ok((canonical, event))
}

/// Computes the rolling chain hash: `SHA-256(prev_hash || canonical_json)`.
pub fn compute_chain_hash(prev_hash: &str, canonical_json: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prev_hash.as_bytes());
    hasher.update(canonical_json.as_bytes());
    let result = hasher.finalize();
    result.iter().map(|b| format!("{b:02x}")).collect()
}

// ── Chain resume ─────────────────────────────────────────────────────────────

/// Reads the last `event_hash` from the tail of the most recent audit file
/// and returns `(prev_hash, next_seq)` so a new writer session continues
/// the chain rather than restarting from genesis.
///
/// Returns `(AUDIT_CHAIN_GENESIS.to_string(), 1)` when:
/// - The audit directory does not exist or is empty.
/// - The last file has no parseable events.
/// - Any I/O error occurs (fails gracefully — does not abort startup).
///
/// `next_seq` is always 1 because seq resets per file (the new session opens
/// a new file).  The continuity is carried by `prev_hash` alone.
fn resume_chain_state(audit_dir: &Path) -> (String, u64) {
    let files = sorted_audit_files(audit_dir);
    let last_file = match files.last() {
        None => return (AUDIT_CHAIN_GENESIS.to_string(), 1),
        Some(p) => p.clone(),
    };

    // Read the last non-empty line from the last audit file.
    let Ok(content) = std::fs::read_to_string(&last_file) else {
        return (AUDIT_CHAIN_GENESIS.to_string(), 1);
    };

    let last_line = content.lines().rev().find(|l| !l.trim().is_empty());

    let Some(line) = last_line else {
        return (AUDIT_CHAIN_GENESIS.to_string(), 1);
    };

    let Ok(event): Result<crate::event::AuditEvent, _> = serde_json::from_str(line) else {
        return (AUDIT_CHAIN_GENESIS.to_string(), 1);
    };

    // The new file starts with seq=1; continuity is via prev_hash.
    (event.event_hash, 1)
}

/// Returns audit files in the directory sorted lexicographically (= chronologically).
fn sorted_audit_files(dir: &Path) -> Vec<PathBuf> {
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

// ── Filename policy ───────────────────────────────────────────────────────────

/// Returns the path for a new audit file using today's local date.
///
/// Format: `<dir>/nrr_audit_YYYYMMDD-N.ndjson`
/// `N` increments if a file for today already exists.
fn next_audit_filename(dir: &Path) -> PathBuf {
    let date = local_date_string(SystemTime::now());
    let mut n = 1u32;
    loop {
        let name = format!("nrr_audit_{date}-{n}.ndjson");
        let path = dir.join(&name);
        if !path.exists() {
            return path;
        }
        n += 1;
    }
}

/// Converts a `SystemTime` to a `"YYYYMMDD"` string on the LOCAL calendar —
/// the day the user would call it. Every file-name date goes through here.
pub fn local_date_string(t: SystemTime) -> String {
    let offset = crate::local_offset::seconds();
    let shifted = if offset >= 0 {
        t.checked_add(Duration::from_secs(offset.unsigned_abs().into()))
    } else {
        t.checked_sub(Duration::from_secs(offset.unsigned_abs().into()))
    };
    utc_date_string(shifted.unwrap_or(t))
}

/// Converts a `SystemTime` to a `"YYYYMMDD"` string in UTC.
pub fn utc_date_string(t: SystemTime) -> String {
    let secs = t
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = secs / 86400;
    // Civil date from Unix day count (proleptic Gregorian, UTC).
    let (y, m, d) = days_to_ymd(days);
    format!("{y:04}{m:02}{d:02}")
}

/// Civil date from days since 1970-01-01 (Gregorian calendar).
fn days_to_ymd(mut z: u64) -> (u32, u32, u32) {
    z += 719468;
    let era = z / 146097;
    let doe = z % 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as u32, m as u32, d as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reason;

    fn sample_input(event_id: &str) -> AuditEventInput {
        AuditEventInput {
            event_id: event_id.into(),
            kind: AuditEventKind::RevisionActivated,
            created_at: 1_745_000_000_000,
            actor_kind: ActorKind::User,
            actor_id_hash: Some("hash_abc".into()),
            revision_id: Some("rev-001".into()),
            risk_level: None,
            result: AuditEventResult::Success,
            reason_code: reason::review::APPROVED,
            payload_summary_json: None,
        }
    }

    #[test]
    fn utc_date_string_epoch() {
        let epoch = SystemTime::UNIX_EPOCH;
        assert_eq!(utc_date_string(epoch), "19700101");
    }

    #[test]
    fn utc_date_string_known_date() {
        use std::time::Duration;
        // 2025-04-23 00:00:00 UTC = 1745366400 seconds
        let t = SystemTime::UNIX_EPOCH + Duration::from_secs(1_745_366_400);
        assert_eq!(utc_date_string(t), "20250423");
        // 2026-04-23 00:00:00 UTC = 1776902400 seconds
        let t2 = SystemTime::UNIX_EPOCH + Duration::from_secs(1_776_902_400);
        assert_eq!(utc_date_string(t2), "20260423");
    }

    #[test]
    fn compute_chain_hash_is_deterministic() {
        let h1 = compute_chain_hash(AUDIT_CHAIN_GENESIS, r#"{"kind":"revision_activated"}"#);
        let h2 = compute_chain_hash(AUDIT_CHAIN_GENESIS, r#"{"kind":"revision_activated"}"#);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64, "SHA-256 hex is 64 chars");
    }

    #[test]
    fn compute_chain_hash_differs_for_different_content() {
        let h1 = compute_chain_hash(AUDIT_CHAIN_GENESIS, r#"{"kind":"a"}"#);
        let h2 = compute_chain_hash(AUDIT_CHAIN_GENESIS, r#"{"kind":"b"}"#);
        assert_ne!(h1, h2);
    }

    #[test]
    fn compute_chain_hash_differs_for_different_prev() {
        let h1 = compute_chain_hash("aaa", r#"{"kind":"a"}"#);
        let h2 = compute_chain_hash("bbb", r#"{"kind":"a"}"#);
        assert_ne!(h1, h2);
    }

    #[test]
    fn audit_writer_creates_ndjson_file() {
        let dir = tempfile::tempdir().expect("temp dir");
        let config = AuditWriterConfig::new(dir.path());
        let writer = AuditWriter::open(config);
        writer.append(sample_input("adt-001")).expect("append");

        let files: Vec<_> = std::fs::read_dir(dir.path())
            .expect("read dir")
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(files.len(), 1, "one audit file created");
        let name = files[0].file_name();
        let name = name.to_string_lossy();
        assert!(
            name.starts_with("nrr_audit_"),
            "file name has correct prefix: {name}"
        );
        assert!(
            name.ends_with(".ndjson"),
            "file has .ndjson extension: {name}"
        );
    }

    #[test]
    fn audit_writer_appends_multiple_events() {
        let dir = tempfile::tempdir().expect("temp dir");
        let writer = AuditWriter::open(AuditWriterConfig::new(dir.path()));
        writer.append(sample_input("adt-001")).expect("1");
        writer.append(sample_input("adt-002")).expect("2");
        writer.append(sample_input("adt-003")).expect("3");

        let files: Vec<_> = std::fs::read_dir(dir.path())
            .expect("read dir")
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(files.len(), 1, "still one file (no rotation needed)");

        let content = std::fs::read_to_string(files[0].path()).expect("read");
        let lines: Vec<_> = content.lines().collect();
        assert_eq!(lines.len(), 3, "three NDJSON lines");
    }

    #[test]
    fn audit_writer_events_have_monotonic_seq() {
        let dir = tempfile::tempdir().expect("temp dir");
        let writer = AuditWriter::open(AuditWriterConfig::new(dir.path()));
        for i in 1u64..=5 {
            writer
                .append(sample_input(&format!("adt-{i:03}")))
                .expect("append");
        }

        let content = std::fs::read_to_string(
            std::fs::read_dir(dir.path())
                .unwrap()
                .next()
                .unwrap()
                .unwrap()
                .path(),
        )
        .expect("read");

        let events: Vec<AuditEvent> = content
            .lines()
            .map(|l| serde_json::from_str(l).expect("parse event"))
            .collect();

        for (i, e) in events.iter().enumerate() {
            assert_eq!(e.seq, (i + 1) as u64, "seq must be monotonic");
        }
    }

    #[test]
    fn audit_writer_hash_chain_is_valid() {
        let dir = tempfile::tempdir().expect("temp dir");
        let writer = AuditWriter::open(AuditWriterConfig::new(dir.path()));
        writer.append(sample_input("adt-001")).expect("1");
        writer.append(sample_input("adt-002")).expect("2");
        writer.append(sample_input("adt-003")).expect("3");

        let content = std::fs::read_to_string(
            std::fs::read_dir(dir.path())
                .unwrap()
                .next()
                .unwrap()
                .unwrap()
                .path(),
        )
        .expect("read");

        let events: Vec<AuditEvent> = content
            .lines()
            .map(|l| serde_json::from_str(l).expect("parse"))
            .collect();

        let mut prev = AUDIT_CHAIN_GENESIS.to_string();
        for event in &events {
            // Recompute hash with stored event_hash = "" replaced, same as writer does.
            let mut e_clone = event.clone();
            let stored_hash = e_clone.event_hash.clone();
            e_clone.event_hash = String::new();
            let canonical = serde_json::to_string(&e_clone).expect("serialize");
            let expected_hash = compute_chain_hash(&prev, &canonical);
            assert_eq!(
                stored_hash, expected_hash,
                "hash chain broken at seq {}",
                event.seq
            );
            prev = stored_hash;
        }
    }

    #[test]
    fn audit_writer_first_event_has_no_prev_hash() {
        let dir = tempfile::tempdir().expect("temp dir");
        let writer = AuditWriter::open(AuditWriterConfig::new(dir.path()));
        writer.append(sample_input("adt-001")).expect("append");

        let content = std::fs::read_to_string(
            std::fs::read_dir(dir.path())
                .unwrap()
                .next()
                .unwrap()
                .unwrap()
                .path(),
        )
        .expect("read");
        let event: AuditEvent = serde_json::from_str(content.lines().next().unwrap()).unwrap();
        assert!(
            event.prev_hash.is_none(),
            "first event must have no prev_hash field"
        );
    }

    #[test]
    fn audit_writer_rotates_file_when_size_exceeded() {
        let dir = tempfile::tempdir().expect("temp dir");
        // Set tiny max size so every event triggers rotation.
        let mut config = AuditWriterConfig::new(dir.path());
        config.max_file_size_bytes = 1; // rotate after 1 byte
        let writer = AuditWriter::open(config);
        writer.append(sample_input("adt-001")).expect("1");
        writer.append(sample_input("adt-002")).expect("2");
        writer.append(sample_input("adt-003")).expect("3");

        let mut files: Vec<_> = std::fs::read_dir(dir.path())
            .expect("read dir")
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .collect();
        files.sort();
        assert_eq!(files.len(), 3, "one file per event due to tiny max_size");
    }

    #[test]
    fn audit_writer_events_are_valid_json_per_line() {
        let dir = tempfile::tempdir().expect("temp dir");
        let writer = AuditWriter::open(AuditWriterConfig::new(dir.path()));
        writer.append(sample_input("adt-001")).expect("append");

        let content = std::fs::read_to_string(
            std::fs::read_dir(dir.path())
                .unwrap()
                .next()
                .unwrap()
                .unwrap()
                .path(),
        )
        .expect("read");
        for line in content.lines() {
            let _v: serde_json::Value = serde_json::from_str(line).expect("valid JSON per line");
        }
    }

    #[test]
    fn audit_writer_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<AuditWriter>();
    }

    #[test]
    fn audit_writer_resumes_chain_on_restart() {
        let dir = tempfile::tempdir().expect("temp dir");

        // Session 1: write 3 events.
        let last_hash_session1 = {
            let writer = AuditWriter::open(AuditWriterConfig::new(dir.path()));
            writer.append(sample_input("adt-001")).expect("s1-1");
            writer.append(sample_input("adt-002")).expect("s1-2");
            writer.append(sample_input("adt-003")).expect("s1-3");

            // Read the last hash from the written file.
            let content = std::fs::read_to_string(
                std::fs::read_dir(dir.path())
                    .unwrap()
                    .next()
                    .unwrap()
                    .unwrap()
                    .path(),
            )
            .expect("read");
            let last_event: crate::event::AuditEvent =
                serde_json::from_str(content.lines().last().unwrap()).expect("parse");
            last_event.event_hash.clone()
        }; // writer dropped here, simulating service restart

        // Session 2: create a NEW writer — it must resume from session 1's last hash.
        let writer2 = AuditWriter::open(AuditWriterConfig::new(dir.path()));
        writer2.append(sample_input("adt-004")).expect("s2-1");

        // Session 2's first event must have prev_hash = session 1's last event_hash.
        let files: Vec<_> = {
            let mut v: Vec<_> = std::fs::read_dir(dir.path())
                .unwrap()
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .collect();
            v.sort();
            v
        };
        assert_eq!(files.len(), 2, "session 2 creates a new file");

        // Read session 2's first event.
        let s2_content = std::fs::read_to_string(&files[1]).expect("read s2");
        let s2_event: crate::event::AuditEvent =
            serde_json::from_str(s2_content.lines().next().unwrap()).expect("parse s2");

        assert_eq!(
            s2_event.prev_hash.as_deref(),
            Some(last_hash_session1.as_str()),
            "session 2 must continue chain from session 1's last hash"
        );
    }

    #[test]
    fn audit_writer_resume_from_empty_dir_uses_genesis() {
        let dir = tempfile::tempdir().expect("temp dir");
        // Open writer on empty dir — must start with genesis.
        let writer = AuditWriter::open(AuditWriterConfig::new(dir.path()));
        writer.append(sample_input("adt-001")).expect("write");

        let content = std::fs::read_to_string(
            std::fs::read_dir(dir.path())
                .unwrap()
                .next()
                .unwrap()
                .unwrap()
                .path(),
        )
        .expect("read");
        let event: crate::event::AuditEvent =
            serde_json::from_str(content.lines().next().unwrap()).expect("parse");

        // First event in an empty dir has no prev_hash (genesis).
        assert!(
            event.prev_hash.is_none(),
            "first event in empty dir must have no prev_hash"
        );
    }
}
