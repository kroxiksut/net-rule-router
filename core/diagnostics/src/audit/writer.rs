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
//! - `prev_hash` — the `event_hash` of the previous event, across files and
//!   restarts (omitted only for the very first event of a trail).
//! - `event_hash` — `SHA-256(prev_hash || canonical_payload_json)`.
//!
//! [`crate::audit::reader::AuditChainVerifier`] checks the whole chain.
//!
//! # One writer per chain
//!
//! A writer takes an OS lock on [`CHAIN_LOCK_FILE_NAME`] before its first
//! append and resumes from the tail on disk at that moment; a second writer
//! on the same directory fails its appends instead of forking the chain.
//!
//! # Append-only invariant
//!
//! The public API has no update or delete methods. Acknowledgement /
//! resolution events are new NDJSON lines — never overwrites of earlier lines.
//! The one truncation is taking back a line whose write failed.

use super::anchor::{check_tail, AuditChainAnchor, AuditChainAnchorStore, AuditTailIntegrity};
use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use sha2::{Digest, Sha256};

use crate::audit::kind::{ActorKind, AuditEventKind, AuditEventResult};
use crate::audit::reader::{AuditChainVerification, AuditChainVerifier, AuditReader};
use crate::audit::restart::{
    seal_event, AuditChainRestartError, AuditChainRestartRequest, AuditRestartKey,
};
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

/// The file whose OS lock makes one writer the owner of the chain. Not an
/// `nrr_audit_*.ndjson` name, so no reader or retention pass ever lists it.
pub const CHAIN_LOCK_FILE_NAME: &str = "nrr_audit.lock";

/// How long a writer waits for the chain on its first append: long enough for
/// a restart to outlast the previous instance's slow stop.
pub const DEFAULT_CHAIN_LOCK_WAIT: Duration = Duration::from_secs(5);

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

/// Where a committed event sits: the file it went to and its `seq` there.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditEventLocation {
    pub file_name: String,
    pub seq: u64,
}

// ── AuditWriterConfig ─────────────────────────────────────────────────────────

/// Configuration for an [`AuditWriter`].
#[derive(Clone, Debug)]
pub struct AuditWriterConfig {
    /// Directory where `nrr_audit_*.ndjson` files are stored.
    pub audit_dir: PathBuf,
    /// Rotate to a new file when the current exceeds this size (bytes).
    pub max_file_size_bytes: u64,
    /// How long the first append waits for another writer to release the
    /// chain; later appends try once.
    pub chain_lock_wait: Duration,
}

impl AuditWriterConfig {
    pub fn new(audit_dir: impl Into<PathBuf>) -> Self {
        Self {
            audit_dir: audit_dir.into(),
            max_file_size_bytes: DEFAULT_MAX_FILE_SIZE_BYTES,
            chain_lock_wait: DEFAULT_CHAIN_LOCK_WAIT,
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
    /// Out-of-band record of the last committed event, when configured.
    anchor: Option<std::sync::Arc<dyn AuditChainAnchorStore>>,
    /// Held for the writer's lifetime once taken. Exclusive file creation
    /// guards a FILE, not the chain: two writers each opened their own next
    /// file on the same `prev_hash` and forked it.
    chain_lock: Option<File>,
    /// Whether the first append's wait for the lock has been spent.
    lock_wait_spent: bool,
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
            anchor: None,
            chain_lock: None,
            lock_wait_spent: false,
        }
    }

    /// Takes the chain lock if this writer does not hold it yet, then resumes
    /// the chain from what is on disk NOW: another writer may have appended
    /// since this one opened.
    fn ensure_chain_owned(&mut self) -> DiagnosticsResult<()> {
        if self.chain_lock.is_some() {
            return Ok(());
        }
        let wait = if self.lock_wait_spent {
            Duration::ZERO
        } else {
            self.config.chain_lock_wait
        };
        self.lock_wait_spent = true;
        let lock = acquire_chain_lock(&self.config.audit_dir, wait)?;
        let (prev_hash, next_seq) = resume_anchored(&self.config.audit_dir, self.anchor.as_deref());
        self.prev_hash = prev_hash;
        self.next_seq = next_seq;
        // A file opened before the lock may sit behind another writer's.
        self.current = None;
        self.chain_lock = Some(lock);
        Ok(())
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

        std::fs::create_dir_all(&self.config.audit_dir).map_err(|e| {
            DiagnosticsError::AuditWriteFailed {
                reason: format!("cannot create audit dir: {e}"),
            }
        })?;
        let (file, path) =
            crate::rotation::open_next_rotation(&self.config.audit_dir, &audit_prefix_today())
                .map_err(|e| DiagnosticsError::AuditWriteFailed {
                    reason: format!("cannot open audit file: {e}"),
                })?;
        self.current_size = file.metadata().map(|m| m.len()).unwrap_or(0);
        // prev_hash intentionally NOT reset here — the chain continues
        // across file rotations and service restarts.  Genesis is only set
        // in new() (no prior audit files exist at all).
        self.next_seq = 1;
        self.current = Some((file, path));
        Ok(())
    }

    fn append_inner(&mut self, input: AuditEventInput) -> DiagnosticsResult<AuditEventLocation> {
        self.ensure_chain_owned()?;
        self.ensure_open()?;
        let (_canonical, event) = build_event(&input, self.next_seq, &self.prev_hash)?;
        self.commit_event(event)
    }

    /// Appends a restart over exactly the breaks the administrator was shown.
    ///
    /// Verified under the writer's lock, so the restart links onto the event
    /// the verification last saw rather than one appended in between.
    fn restart_inner(
        &mut self,
        key: &AuditRestartKey,
        shown_digest: &str,
        request: AuditChainRestartRequest,
    ) -> Result<AuditChainVerification, AuditChainRestartError> {
        self.ensure_chain_owned()
            .map_err(AuditChainRestartError::Write)?;
        let anchor = self.anchor.as_ref().and_then(|a| a.load());
        let verdict = AuditChainVerifier::with_restart_key(key.clone())
            .verify(&AuditReader::new(&self.config.audit_dir), anchor.as_ref());
        match verdict.breaks_digest.as_deref() {
            None => return Err(AuditChainRestartError::Intact),
            Some(digest) if digest != shown_digest => {
                return Err(AuditChainRestartError::ChangedSinceShown)
            }
            Some(_) => {}
        }
        // Onto the event on disk, not the anchored one a cut tail resumed
        // from: the restart accepts what is there.
        let (head, _) = resume_chain_state(&self.config.audit_dir);
        self.prev_hash = head.clone();
        self.ensure_open().map_err(AuditChainRestartError::Write)?;

        let first = verdict.breaks.first().map(|b| {
            serde_json::json!({
                "kind": b.kind.slug(),
                "file": b.file_name,
                "line": b.line,
                "seq": b.seq,
            })
        });
        let input = AuditEventInput {
            event_id: request.event_id,
            kind: AuditEventKind::AuditChainRestarted,
            created_at: request.created_at,
            actor_kind: ActorKind::User,
            actor_id_hash: request.actor_id_hash,
            revision_id: None,
            risk_level: None,
            result: AuditEventResult::Success,
            reason_code: crate::reason::integrity::AUDIT_CHAIN_RESTARTED,
            payload_summary_json: Some(
                serde_json::json!({
                    "breaks": verdict.break_count,
                    "first_break": first,
                    "breaks_digest": shown_digest,
                    "head": head,
                })
                .to_string(),
            ),
        };
        let event = build_sealed_event(&input, self.next_seq, &self.prev_hash, key)
            .map_err(AuditChainRestartError::Write)?;
        self.commit_event(event)
            .map_err(AuditChainRestartError::Write)?;
        Ok(verdict)
    }

    fn commit_event(&mut self, event: AuditEvent) -> DiagnosticsResult<AuditEventLocation> {
        let seq = event.seq;
        let event_hash = event.event_hash.clone();

        let mut line = event
            .to_ndjson()
            .map_err(|e| DiagnosticsError::AuditWriteFailed {
                reason: format!("serialize audit event: {e}"),
            })?;
        line.push('\n');

        let start = self.current_size;
        let (file, _path) = self.current.as_mut().expect("file open after ensure_open");
        if let Err(e) = commit_line(file, start, line.as_bytes()) {
            // Whether or not the rollback held, the next event starts a fresh
            // file rather than landing after a fragment.
            self.current = None;
            return Err(DiagnosticsError::AuditWriteFailed {
                reason: format!("write audit line: {e}"),
            });
        }

        self.current_size += line.len() as u64;
        self.prev_hash = event_hash.clone();
        self.next_seq += 1;

        let file_name = self
            .current
            .as_ref()
            .and_then(|(_, p)| p.file_name())
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_string();
        if let Some(anchor) = &self.anchor {
            anchor.save(&AuditChainAnchor {
                file_name: file_name.clone(),
                seq,
                event_hash,
            });
        }
        Ok(AuditEventLocation { file_name, seq })
    }
}

// ── AuditWriter ───────────────────────────────────────────────────────────────

/// Thread-safe, append-only NDJSON audit trail writer.
///
/// Implements [`AuditSink<AuditEventInput>`] so it can be injected wherever
/// an `AuditSink` is expected.
pub struct AuditWriter {
    inner: Mutex<AuditWriterInner>,
    tail_integrity: AuditTailIntegrity,
    /// Read without the writer's lock, for verification.
    audit_dir: PathBuf,
    anchor: Option<std::sync::Arc<dyn AuditChainAnchorStore>>,
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
        Self::open_anchored(config, None)
    }

    /// Opens the writer with an out-of-band tail anchor.
    ///
    /// When the anchor disagrees with what is on disk, the chain resumes from
    /// the ANCHORED hash rather than the file's current tail: a shortened file
    /// then fails verification at the seam instead of quietly becoming the new
    /// truth. Call [`AuditWriter::tail_integrity`] right after opening to
    /// report the verdict.
    pub fn open_anchored(
        config: AuditWriterConfig,
        anchor: Option<std::sync::Arc<dyn AuditChainAnchorStore>>,
    ) -> Self {
        let stored = anchor.as_ref().and_then(|a| a.load());
        let integrity = check_tail(&config.audit_dir, stored.as_ref());
        // Where the chain resumes is read when the lock is taken, not here:
        // another writer may still be appending.
        let audit_dir = config.audit_dir.clone();
        let mut inner = AuditWriterInner::new(config);
        inner.anchor = anchor.clone();
        Self {
            inner: Mutex::new(inner),
            tail_integrity: integrity,
            audit_dir,
            anchor,
        }
    }

    /// [`AuditSink::append`], also saying where the event landed, so a record
    /// that refers to it can point at the line.
    #[allow(clippy::expect_used)] // lock poisoning propagates a prior panic
    pub fn append_located(&self, input: AuditEventInput) -> DiagnosticsResult<AuditEventLocation> {
        self.inner
            .lock()
            .expect("AuditWriter mutex")
            .append_inner(input)
    }

    /// What the anchor said about the tail when this writer opened.
    pub fn tail_integrity(&self) -> &AuditTailIntegrity {
        &self.tail_integrity
    }

    /// The chain as it stands, honouring restarts sealed with `key`.
    pub fn verify_chain(&self, key: Option<&AuditRestartKey>) -> AuditChainVerification {
        let mut verifier = match key {
            Some(key) => AuditChainVerifier::with_restart_key(key.clone()),
            None => AuditChainVerifier::new(),
        };
        let anchor = self.anchor.as_ref().and_then(|a| a.load());
        verifier.verify(&AuditReader::new(&self.audit_dir), anchor.as_ref())
    }

    /// Restarts the chain over the breaks whose digest the administrator was
    /// shown, and returns the verification it papered over. Refused when the
    /// chain is intact or the breaks have changed since.
    ///
    /// Only a holder of `key` can write a restart the verifier honours.
    #[allow(clippy::expect_used)] // lock poisoning propagates a prior panic
    pub fn restart_chain(
        &self,
        key: &AuditRestartKey,
        shown_digest: &str,
        request: AuditChainRestartRequest,
    ) -> Result<AuditChainVerification, AuditChainRestartError> {
        self.inner
            .lock()
            .expect("AuditWriter mutex")
            .restart_inner(key, shown_digest, request)
    }
}

// Lock-poisoning `expect()` propagates a prior panic — not recoverable.
#[allow(clippy::expect_used)]
impl AuditSink for AuditWriter {
    type Event = AuditEventInput;

    fn append(&self, input: AuditEventInput) -> Result<(), DiagnosticsError> {
        self.append_located(input).map(|_| ())
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
        seal: None,
        prev_hash: if prev_hash == AUDIT_CHAIN_GENESIS {
            None
        } else {
            Some(prev_hash.to_string())
        },
        event_hash: String::new(), // filled below
    };

    // Canonical payload = the full event JSON with an empty `event_hash`.
    //
    // This is a live struct, so ADDING A FIELD to `AuditEvent` changes the
    // canonical bytes and makes every previously written event unverifiable —
    // silently, since the hashes still recompute consistently going forward.
    // Only an optional field omitted when absent (`seal`) leaves them alone.
    // `schema_version` is part of the hashed payload but nothing compares it on
    // read. The golden test below pins the exact bytes so such a change fails
    // loudly with an explanation instead of rewriting history's verdict.
    let canonical =
        serde_json::to_string(&event).map_err(|e| DiagnosticsError::AuditWriteFailed {
            reason: format!("canonical serialization failed: {e}"),
        })?;

    let event_hash = compute_chain_hash(prev_hash, &canonical);
    event.event_hash = event_hash;

    Ok((canonical, event))
}

/// [`build_event`], sealed with the service's key before it is hashed, so the
/// chain covers the seal too.
fn build_sealed_event(
    input: &AuditEventInput,
    seq: u64,
    prev_hash: &str,
    key: &AuditRestartKey,
) -> DiagnosticsResult<AuditEvent> {
    let (_, mut event) = build_event(input, seq, prev_hash)?;
    event.event_hash = String::new();
    seal_event(&mut event, key)?;
    let canonical =
        serde_json::to_string(&event).map_err(|e| DiagnosticsError::AuditWriteFailed {
            reason: format!("canonical serialization failed: {e}"),
        })?;
    event.event_hash = compute_chain_hash(prev_hash, &canonical);
    Ok(event)
}

/// Computes the rolling chain hash: `SHA-256(prev_hash || canonical_json)`.
pub fn compute_chain_hash(prev_hash: &str, canonical_json: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prev_hash.as_bytes());
    hasher.update(canonical_json.as_bytes());
    let result = hasher.finalize();
    result.iter().map(|b| format!("{b:02x}")).collect()
}

// ── Chain ownership and commit ───────────────────────────────────────────────

/// Takes the chain's exclusive OS lock, retrying for up to `wait`.
fn acquire_chain_lock(audit_dir: &Path, wait: Duration) -> DiagnosticsResult<File> {
    let fail = |reason: String| DiagnosticsError::AuditWriteFailed { reason };
    std::fs::create_dir_all(audit_dir)
        .map_err(|e| fail(format!("cannot create audit dir: {e}")))?;
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(audit_dir.join(CHAIN_LOCK_FILE_NAME))
        .map_err(|e| fail(format!("cannot open audit chain lock: {e}")))?;
    let deadline = std::time::Instant::now() + wait;
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(file),
            Err(std::fs::TryLockError::WouldBlock) if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(std::fs::TryLockError::WouldBlock) => {
                return Err(fail("audit chain is held by another writer".to_string()));
            }
            Err(std::fs::TryLockError::Error(e)) => {
                return Err(fail(format!("cannot lock audit chain: {e}")));
            }
        }
    }
}

/// What the writer needs from the file it appends to; a trait so a failing
/// disk can be simulated.
trait AuditFile: Write + Seek {
    fn truncate_to(&mut self, len: u64) -> std::io::Result<()>;
    fn make_durable(&mut self) -> std::io::Result<()>;
}

impl AuditFile for File {
    fn truncate_to(&mut self, len: u64) -> std::io::Result<()> {
        self.set_len(len)
    }

    fn make_durable(&mut self) -> std::io::Result<()> {
        self.sync_data()
    }
}

/// Appends one whole line, durable before it counts, or leaves the file as it
/// was.
///
/// Durable first because the anchor written next is fsynced: an anchor that
/// outlives its event after a power loss reads as a truncated trail. Rolled
/// back on failure because a half line reads as a corrupt one. Both are the
/// tamper alarm nobody caused.
fn commit_line<F: AuditFile>(file: &mut F, start: u64, line: &[u8]) -> std::io::Result<()> {
    let result = file.write_all(line).and_then(|()| file.make_durable());
    if result.is_err() {
        let _ = file
            .truncate_to(start)
            .and_then(|()| file.seek(SeekFrom::Start(start)));
    }
    result
}

// ── Chain resume ─────────────────────────────────────────────────────────────

/// [`resume_chain_state`], except that a tail shorter than the anchor resumes
/// from the ANCHORED hash, so the gap fails verification at the seam instead
/// of quietly becoming the new truth.
fn resume_anchored(audit_dir: &Path, anchor: Option<&dyn AuditChainAnchorStore>) -> (String, u64) {
    let (prev_hash, next_seq) = resume_chain_state(audit_dir);
    let Some(stored) = anchor.and_then(|a| a.load()) else {
        return (prev_hash, next_seq);
    };
    if check_tail(audit_dir, Some(&stored)).is_truncated() {
        return (stored.event_hash, next_seq);
    }
    (prev_hash, next_seq)
}

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
    // Walk back through the files, not just the newest one. A single unreadable
    // file — an antivirus holding it for a second, a truncated tail — used to
    // drop the chain to GENESIS, and the next verification then reported a
    // mismatch nobody caused. The reader has always walked back like this; the
    // writer, which is the side that PERSISTS the consequence, did not.
    for path in sorted_audit_files(audit_dir).into_iter().rev() {
        if let Some(hash) = last_event_hash_in_file(&path) {
            // The new file starts with seq=1; continuity is via prev_hash.
            return (hash, 1);
        }
    }
    (AUDIT_CHAIN_GENESIS.to_string(), 1)
}

/// The `event_hash` of the last well-formed event in a file, if any.
fn last_event_hash_in_file(path: &Path) -> Option<String> {
    let content = std::fs::read_to_string(path).ok()?;
    content
        .lines()
        .rev()
        .filter(|l| !l.trim().is_empty())
        .find_map(|line| {
            serde_json::from_str::<crate::event::AuditEvent>(line)
                .ok()
                .map(|event| event.event_hash)
        })
}

/// Returns audit files in the directory in chronological order.
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
    crate::rotation::sort_chronologically(&mut files);
    files
}

// ── Filename policy ───────────────────────────────────────────────────────────

/// Returns the path for a new audit file using today's local date.
///
/// Format: `<dir>/nrr_audit_YYYYMMDD-N.ndjson`
/// `N` increments if a file for today already exists.
/// Prefix of today's audit files, e.g. `nrr_audit_20260830-`.
fn audit_prefix_today() -> String {
    format!("nrr_audit_{}-", local_date_string(SystemTime::now()))
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

        let files: Vec<_> = sorted_audit_files(dir.path());
        assert_eq!(files.len(), 1, "one audit file created");
        let name = files[0].file_name().expect("name").to_string_lossy();
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

        let files: Vec<_> = sorted_audit_files(dir.path());
        assert_eq!(files.len(), 1, "still one file (no rotation needed)");

        let content = std::fs::read_to_string(files[0].clone()).expect("read");
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

        let content =
            std::fs::read_to_string(sorted_audit_files(dir.path())[0].clone()).expect("read");

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

        let content =
            std::fs::read_to_string(sorted_audit_files(dir.path())[0].clone()).expect("read");

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

        let content =
            std::fs::read_to_string(sorted_audit_files(dir.path())[0].clone()).expect("read");
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

        let mut files: Vec<_> = sorted_audit_files(dir.path());
        files.sort();
        assert_eq!(files.len(), 3, "one file per event due to tiny max_size");
    }

    #[test]
    fn audit_writer_events_are_valid_json_per_line() {
        let dir = tempfile::tempdir().expect("temp dir");
        let writer = AuditWriter::open(AuditWriterConfig::new(dir.path()));
        writer.append(sample_input("adt-001")).expect("append");

        let content =
            std::fs::read_to_string(sorted_audit_files(dir.path())[0].clone()).expect("read");
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
            let content =
                std::fs::read_to_string(sorted_audit_files(dir.path())[0].clone()).expect("read");
            let last_event: crate::event::AuditEvent =
                serde_json::from_str(content.lines().last().unwrap()).expect("parse");
            last_event.event_hash.clone()
        }; // writer dropped here, simulating service restart

        // Session 2: create a NEW writer — it must resume from session 1's last hash.
        let writer2 = AuditWriter::open(AuditWriterConfig::new(dir.path()));
        writer2.append(sample_input("adt-004")).expect("s2-1");

        // Session 2's first event must have prev_hash = session 1's last event_hash.
        let files: Vec<_> = {
            let mut v: Vec<_> = sorted_audit_files(dir.path());
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

        let content =
            std::fs::read_to_string(sorted_audit_files(dir.path())[0].clone()).expect("read");
        let event: crate::event::AuditEvent =
            serde_json::from_str(content.lines().next().unwrap()).expect("parse");

        // First event in an empty dir has no prev_hash (genesis).
        assert!(
            event.prev_hash.is_none(),
            "first event in empty dir must have no prev_hash"
        );
    }

    #[test]
    fn the_chain_resumes_from_the_eleventh_file_not_the_ninth() {
        let dir = tempfile::tempdir().expect("temp");
        // A lexicographic sort puts `-9` last and the chain forks from there.
        let line_of = |id: &str| {
            let (_, event) = build_event(&sample_input(id), 1, AUDIT_CHAIN_GENESIS).expect("event");
            (
                serde_json::to_string(&event).expect("serialize")
                    + "
",
                event.event_hash,
            )
        };
        let (stale_line, _) = line_of("stale");
        let (newest_line, newest_hash) = line_of("newest");
        std::fs::write(dir.path().join("nrr_audit_20260423-9.ndjson"), stale_line).unwrap();
        std::fs::write(dir.path().join("nrr_audit_20260423-11.ndjson"), newest_line).unwrap();

        let (prev_hash, next_seq) = resume_chain_state(dir.path());
        assert_eq!(prev_hash, newest_hash);
        assert_eq!(next_seq, 1);
    }

    #[test]
    fn a_freed_rotation_number_is_never_handed_out_again() {
        let dir = tempfile::tempdir().expect("temp");
        let prefix = audit_prefix_today();
        // Retention deleted `-1` and `-2`; the next file must be `-4`.
        std::fs::write(dir.path().join(format!("{prefix}3.ndjson")), "").unwrap();

        let writer = AuditWriter::open(AuditWriterConfig::new(dir.path()));
        writer.append(sample_input("e1")).expect("append");

        let names: Vec<_> = sorted_audit_files(dir.path())
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            names,
            [format!("{prefix}3.ndjson"), format!("{prefix}4.ndjson")]
        );
    }

    #[test]
    fn the_canonical_payload_bytes_are_pinned() {
        let (canonical, _) =
            build_event(&sample_input("evt-golden"), 7, AUDIT_CHAIN_GENESIS).expect("event");

        // Changing this string means every audit event ever written stops
        // verifying. If a field genuinely has to join `AuditEvent`, the chain
        // needs a versioned canonical form first — not a new golden value.
        assert_eq!(
            canonical,
            concat!(
                r#"{"schema_version":1,"seq":7,"event_id":"evt-golden","#,
                r#""kind":"revision_activated","created_at":1745000000000,"#,
                r#""actor_kind":"user","actor_id_hash":"hash_abc","#,
                r#""revision_id":"rev-001","result":"success","#,
                r#""reason_code":"review.approved","event_hash":""}"#
            )
        );
    }

    fn no_wait(dir: &Path) -> AuditWriterConfig {
        let mut config = AuditWriterConfig::new(dir);
        config.chain_lock_wait = Duration::ZERO;
        config
    }

    fn events_in_order(dir: &Path) -> Vec<AuditEvent> {
        sorted_audit_files(dir)
            .iter()
            .flat_map(|p| {
                std::fs::read_to_string(p)
                    .expect("read")
                    .lines()
                    .map(|l| serde_json::from_str::<AuditEvent>(l).expect("parse"))
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    /// Two live writers on one directory — the service and a console run, or a
    /// restart that caught up with a slow stop — used to open files N and N+1
    /// on the same `prev_hash`. The second now cannot append while the first
    /// holds the chain, and once it can, it continues from what the first
    /// wrote, not from what it saw when it opened.
    #[test]
    fn a_second_writer_cannot_fork_the_chain() {
        let dir = tempfile::tempdir().expect("temp");
        let first = AuditWriter::open(no_wait(dir.path()));
        let second = AuditWriter::open(no_wait(dir.path()));
        first.append(sample_input("a1")).expect("a1");
        first.append(sample_input("a2")).expect("a2");

        assert!(
            second.append(sample_input("b1")).is_err(),
            "the chain has one writer"
        );

        drop(first);
        second
            .append(sample_input("b1"))
            .expect("the chain is free");
        let events = events_in_order(dir.path());
        let ids: Vec<_> = events.iter().map(|e| e.event_id.as_str()).collect();
        assert_eq!(ids, ["a1", "a2", "b1"]);
        assert_eq!(
            events[2].prev_hash.as_deref(),
            Some(events[1].event_hash.as_str()),
            "b1 chains onto a2"
        );
    }

    /// Positive control: one writer after another, the usual restart, keeps
    /// working without any wait.
    #[test]
    fn writers_in_turn_share_the_chain() {
        let dir = tempfile::tempdir().expect("temp");
        AuditWriter::open(no_wait(dir.path()))
            .append(sample_input("a1"))
            .expect("a1");
        AuditWriter::open(no_wait(dir.path()))
            .append(sample_input("b1"))
            .expect("b1");
        let events = events_in_order(dir.path());
        assert_eq!(
            events[1].prev_hash.as_deref(),
            Some(events[0].event_hash.as_str())
        );
    }

    /// A file that accepts `room` bytes and then fails, or fails at fsync.
    struct FlakyFile {
        bytes: std::io::Cursor<Vec<u8>>,
        room: usize,
        fail_sync: bool,
    }

    impl Write for FlakyFile {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if self.room == 0 {
                return Err(std::io::Error::other("disk full"));
            }
            let n = buf.len().min(self.room);
            self.room -= n;
            self.bytes.write(&buf[..n])
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Seek for FlakyFile {
        fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
            self.bytes.seek(pos)
        }
    }

    impl AuditFile for FlakyFile {
        fn truncate_to(&mut self, len: u64) -> std::io::Result<()> {
            self.bytes.get_mut().truncate(len as usize);
            Ok(())
        }

        fn make_durable(&mut self) -> std::io::Result<()> {
            if self.fail_sync {
                Err(std::io::Error::other("sync failed"))
            } else {
                Ok(())
            }
        }
    }

    fn flaky(room: usize, fail_sync: bool) -> FlakyFile {
        FlakyFile {
            bytes: std::io::Cursor::new(Vec::new()),
            room,
            fail_sync,
        }
    }

    /// A write that fails halfway leaves no half line behind, and the next
    /// line lands right after the last whole one.
    #[test]
    fn a_failed_write_leaves_no_fragment() {
        let mut file = flaky(12, false);
        commit_line(&mut file, 0, b"first\n").expect("fits");
        assert!(commit_line(&mut file, 6, b"second line\n").is_err());
        assert_eq!(file.bytes.get_ref().as_slice(), b"first\n");

        file.room = usize::MAX;
        commit_line(&mut file, 6, b"third\n").expect("fits");
        assert_eq!(file.bytes.get_ref().as_slice(), b"first\nthird\n");
    }

    /// A line that is not durable does not count: the caller must not anchor
    /// it, so the commit fails and the line is taken back.
    #[test]
    fn a_line_that_cannot_be_made_durable_is_not_committed() {
        let mut file = flaky(usize::MAX, true);
        assert!(commit_line(&mut file, 0, b"line\n").is_err());
        assert!(file.bytes.get_ref().is_empty());

        file.fail_sync = false;
        commit_line(&mut file, 0, b"line\n").expect("positive control");
        assert_eq!(file.bytes.get_ref().as_slice(), b"line\n");
    }
}
