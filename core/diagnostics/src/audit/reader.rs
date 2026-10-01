//! Audit NDJSON trail reader and chain verifier.
//!
//! # Scan model
//!
//! Files are scanned in chronological order (date + rotation index). Each file
//! is read line-by-line; lines that fail to parse are counted as corrupt but do
//! not abort the scan.
//!
//! # Chain verification
//!
//! [`AuditChainVerifier`] checks every file still on disk as one chain: each
//! file on its own, and each file's first event against the last event of the
//! file before it. The writer opens a new file on every start, so a check of
//! the newest file alone covered only "since the last boot". A sealed restart
//! (see [`crate::audit::restart`]) is where verification starts over.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::audit::anchor::AuditChainAnchor;
use crate::audit::restart::{AuditChainBreak, AuditChainBreakKind, AuditRestartKey, BreakLog};
use crate::audit::writer::{compute_chain_hash, AUDIT_CHAIN_GENESIS};
use crate::event::AuditEvent;
use crate::facade::dto::DiagnosticsAudience;

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

/// Result of verifying the rolling hash chain.
#[derive(Clone, Debug)]
pub struct AuditChainVerification {
    /// `true` if every hash since the last restart is intact.
    pub chain_ok: bool,
    /// Number of events successfully verified.
    pub events_verified: usize,
    /// Sequence number of the first hash mismatch, if any.
    pub mismatch_at_seq: Option<u64>,
    /// Expected hash at the mismatch position.
    pub expected_hash: Option<String>,
    /// Actual stored hash at the mismatch position.
    pub actual_hash: Option<String>,
    /// Number of lines that could not be parsed.
    pub corrupt_lines: usize,
    /// `true` when the out-of-band anchor names an event the files no longer
    /// hold. A chain with its tail cut off is still internally consistent, so
    /// `chain_ok` alone says nothing about it.
    pub tail_truncated: bool,
    /// The breaks since the last restart, the first
    /// [`LISTED_BREAKS`](crate::audit::restart::LISTED_BREAKS) of them.
    pub breaks: Vec<AuditChainBreak>,
    /// How many breaks there are in all.
    pub break_count: usize,
    /// Covers every break, listed or not. A restart names the digest it was
    /// shown and is refused when the breaks have changed since.
    pub breaks_digest: Option<String>,
    /// Whether verification started from a sealed restart rather than from
    /// the oldest file.
    pub restarted: bool,
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
            tail_truncated: false,
            breaks: Vec::new(),
            break_count: 0,
            breaks_digest: None,
            restarted: false,
        }
    }
}

// ── AuditChainVerifier ────────────────────────────────────────────────────────

/// A stretch of one file's chain.
#[derive(Clone, Default)]
struct Segment {
    events: usize,
    corrupt: usize,
    breaks: BreakLog,
    first_hash_break: Option<AuditChainBreak>,
}

impl Segment {
    fn record(&mut self, found: Option<AuditChainBreak>) {
        let Some(found) = found else {
            self.events += 1;
            return;
        };
        if found.kind.breaks_hashes() {
            self.first_hash_break.get_or_insert_with(|| found.clone());
        } else {
            self.corrupt += 1;
        }
        self.breaks.push(found);
    }
}

/// One file's stretch of the chain, verified on its own.
#[derive(Clone, Default)]
struct FileLink {
    /// What the file's first event claims to follow.
    first_prev: Option<String>,
    /// Line and seq of that event, where a seam break is reported.
    first_at: (usize, u64),
    /// The stored hash of the last event, verified or not: the writer chains
    /// onto whatever is on disk.
    tail_hash: Option<String>,
    whole: Segment,
    /// From the file's last sealed restart on.
    restart: Option<RestartLink>,
}

#[derive(Clone)]
struct RestartLink {
    /// Set when the restart is the file's first event: its link to the event
    /// before it is checked across the seam.
    seam_prev: Option<String>,
    after: Segment,
}

/// SHA-256 of a file's bytes, the key a cached verdict is reused under.
///
/// Length and modification time are both the editor's to set: a same-length
/// edit with its time put back passed as the file already verified. An edit
/// anywhere breaks the chain from that line on, so no part of the file can be
/// left out of the key.
type FileDigest = [u8; 32];

/// Verifies the chain in the retention window from the last sealed restart
/// (or the oldest file), re-parsing only the files whose bytes changed since
/// the last call. Every call still hashes every file: hashing is the cheap
/// half of a verification, parsing is the rest.
///
/// The first surviving file's own `prev_hash` is taken as given: retention
/// removed what it pointed at. Every later seam is checked.
#[derive(Default)]
pub struct AuditChainVerifier {
    /// Without it no restart is honoured: nothing else tells the service's
    /// restart from a forged one.
    restart_key: Option<AuditRestartKey>,
    links: HashMap<PathBuf, (FileDigest, FileLink)>,
    last: Option<LastVerdict>,
}

/// The whole verdict, and everything it was reached from.
struct LastVerdict {
    files: Vec<PathBuf>,
    digests: Vec<FileDigest>,
    anchor: Option<AuditChainAnchor>,
    verdict: AuditChainVerification,
}

impl AuditChainVerifier {
    pub fn new() -> Self {
        Self::default()
    }

    /// A verifier that honours restarts sealed with `key`.
    pub fn with_restart_key(key: AuditRestartKey) -> Self {
        Self {
            restart_key: Some(key),
            ..Self::default()
        }
    }

    /// The verdict over every file in `reader`'s directory, with the tail
    /// compared against `anchor`.
    pub fn verify(
        &mut self,
        reader: &AuditReader,
        anchor: Option<&AuditChainAnchor>,
    ) -> AuditChainVerification {
        let files = reader.list_files();
        let mut digests: Vec<Option<FileDigest>> = files.iter().map(|p| file_digest(p)).collect();
        if let Some(last) = &self.last {
            let unchanged = last.files == files
                && last.digests.len() == digests.len()
                && last
                    .digests
                    .iter()
                    .zip(&digests)
                    .all(|(last, now)| Some(last) == now.as_ref());
            if unchanged && last.anchor.as_ref() == anchor {
                return last.verdict.clone();
            }
        }

        self.links.retain(|path, _| files.contains(path));
        let links: Vec<FileLink> = files
            .iter()
            .zip(&mut digests)
            .map(|(path, digest)| match self.links.get(path) {
                Some((cached, link)) if Some(cached) == digest.as_ref() => link.clone(),
                _ => {
                    // Keyed by the bytes verified, not by the ones hashed
                    // above: the file may have moved on in between.
                    let (verified, link) = read_and_verify(path, self.restart_key.as_ref());
                    *digest = verified;
                    match verified {
                        Some(d) => self.links.insert(path.clone(), (d, link.clone())),
                        None => self.links.remove(path),
                    };
                    link
                }
            })
            .collect();

        let start = last_usable_restart(&links);
        let mut verdict = AuditChainVerification::ok(0);
        let mut breaks = BreakLog::default();
        let mut first_hash_break: Option<AuditChainBreak> = None;
        let mut prev_tail: Option<&String> = None;
        for (index, (path, link)) in files.iter().zip(&links).enumerate() {
            if start.is_some_and(|s| index < s) {
                continue;
            }
            let segment = match (&link.restart, start) {
                (Some(restart), Some(s)) if s == index => &restart.after,
                _ => {
                    if let (Some(tail), Some(first)) = (prev_tail, &link.first_prev) {
                        if tail != first {
                            let seam = AuditChainBreak {
                                kind: AuditChainBreakKind::Seam,
                                file_name: file_name_of(path),
                                line: link.first_at.0,
                                seq: Some(link.first_at.1),
                                expected_hash: Some(tail.clone()),
                                actual_hash: Some(first.clone()),
                            };
                            first_hash_break.get_or_insert_with(|| seam.clone());
                            breaks.push(seam);
                        }
                    }
                    &link.whole
                }
            };
            verdict.events_verified += segment.events;
            verdict.corrupt_lines += segment.corrupt;
            if let Some(found) = &segment.first_hash_break {
                first_hash_break.get_or_insert_with(|| found.clone());
            }
            breaks.absorb(&segment.breaks);
            if let Some(tail) = &link.tail_hash {
                prev_tail = Some(tail);
            }
        }

        if let Some(anchor) = anchor {
            if crate::audit::anchor::check_tail(&reader.audit_dir, Some(anchor)).is_truncated() {
                verdict.tail_truncated = true;
                breaks.push(AuditChainBreak {
                    kind: AuditChainBreakKind::TailTruncated,
                    file_name: anchor.file_name.clone(),
                    line: 0,
                    seq: Some(anchor.seq),
                    expected_hash: Some(anchor.event_hash.clone()),
                    actual_hash: None,
                });
            }
        }
        if let Some(found) = first_hash_break {
            verdict.chain_ok = false;
            verdict.mismatch_at_seq = found.seq;
            verdict.expected_hash = found.expected_hash;
            verdict.actual_hash = found.actual_hash;
        }
        if verdict.tail_truncated {
            verdict.chain_ok = false;
        }
        verdict.break_count = breaks.count;
        verdict.breaks_digest = (breaks.count > 0).then(|| breaks.fingerprint());
        verdict.breaks = breaks.listed;
        verdict.restarted = start.is_some();

        // An unreadable file has no key, so the next call looks at it again.
        self.last = digests
            .into_iter()
            .collect::<Option<Vec<_>>>()
            .map(|digests| LastVerdict {
                files,
                digests,
                anchor: anchor.cloned(),
                verdict: verdict.clone(),
            });
        verdict
    }
}

/// The file holding the last restart that links onto the event before it.
///
/// A restart that opens a file links across the seam: onto the last event of
/// the nearest earlier file that has one, or onto nothing when retention
/// removed everything before it.
fn last_usable_restart(links: &[FileLink]) -> Option<usize> {
    (0..links.len()).rev().find(|&index| {
        let Some(restart) = &links[index].restart else {
            return false;
        };
        match &restart.seam_prev {
            None => true,
            Some(claimed) => links[..index]
                .iter()
                .rev()
                .find_map(|l| l.tail_hash.as_ref())
                .is_none_or(|tail| tail == claimed),
        }
    })
}

/// Streamed, so an unchanged trail costs a buffer rather than its size in
/// memory. `None` when the file cannot be read.
fn file_digest(path: &Path) -> Option<FileDigest> {
    let file = std::fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    std::io::copy(
        &mut std::io::BufReader::with_capacity(64 * 1024, file),
        &mut hasher,
    )
    .ok()?;
    Some(hasher.finalize().into())
}

/// The file's link, and the digest of exactly the bytes it was verified from.
fn read_and_verify(path: &Path, key: Option<&AuditRestartKey>) -> (Option<FileDigest>, FileLink) {
    let file_name = file_name_of(path);
    match std::fs::read(path) {
        Ok(bytes) => (
            Some(Sha256::digest(&bytes).into()),
            verify_file_link(&file_name, std::str::from_utf8(&bytes).ok(), key),
        ),
        Err(_) => (None, verify_file_link(&file_name, None, key)),
    }
}

fn file_name_of(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// The event on a line, and the bytes its hash covers.
fn parse_event(line: &str) -> Option<(AuditEvent, String)> {
    let event = serde_json::from_str::<AuditEvent>(line).ok()?;
    let mut bare = event.clone();
    bare.event_hash = String::new();
    let canonical = serde_json::to_string(&bare).ok()?;
    Some((event, canonical))
}

/// `content` is `None` for a file that could not be read as text.
fn verify_file_link(
    file_name: &str,
    content: Option<&str>,
    key: Option<&AuditRestartKey>,
) -> FileLink {
    let file_name = file_name.to_string();
    let mut link = FileLink::default();
    let Some(content) = content else {
        link.whole
            .record(Some(AuditChainBreak::unreadable(&file_name)));
        return link;
    };
    let mut prev: Option<String> = None;
    for (index, line) in content.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let line_no = index + 1;
        let Some((event, canonical)) = parse_event(line) else {
            let found = AuditChainBreak::corrupt_line(&file_name, line_no, line);
            if let Some(restart) = link.restart.as_mut() {
                restart.after.record(Some(found.clone()));
            }
            link.whole.record(Some(found));
            continue;
        };
        let claimed_prev = event
            .prev_hash
            .clone()
            .unwrap_or_else(|| AUDIT_CHAIN_GENESIS.to_string());
        let chain_prev = match &prev {
            Some(p) => p.clone(),
            None => {
                link.first_prev = Some(claimed_prev.clone());
                link.first_at = (line_no, event.seq);
                claimed_prev.clone()
            }
        };
        let expected = compute_chain_hash(&chain_prev, &canonical);
        let found = (expected != event.event_hash).then(|| AuditChainBreak {
            kind: AuditChainBreakKind::HashMismatch,
            file_name: file_name.clone(),
            line: line_no,
            seq: Some(event.seq),
            expected_hash: Some(expected),
            actual_hash: Some(event.event_hash.clone()),
        });
        // The seal fixes `prev_hash` and this check fixes where that is, so a
        // genuine restart copied anywhere else is just an event.
        if found.is_none()
            && claimed_prev == chain_prev
            && super::restart::is_sealed_restart(&event, key)
        {
            let mut after = Segment::default();
            after.record(None);
            link.restart = Some(RestartLink {
                seam_prev: prev.is_none().then(|| chain_prev.clone()),
                after,
            });
        } else if let Some(restart) = link.restart.as_mut() {
            restart.after.record(found.clone());
        }
        link.whole.record(found);
        prev = Some(event.event_hash);
        link.tail_hash.clone_from(&prev);
    }
    link
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

    /// Scans all files and returns the events matching `filter` that
    /// `audience` may see.
    ///
    /// The audience is a required argument, not a filter applied afterwards:
    /// the directory is closed to ordinary users on disk, and a read that could
    /// be written without one would hand out what those permissions withhold.
    pub fn scan(
        &self,
        filter: &AuditQueryFilter,
        audience: &DiagnosticsAudience,
    ) -> Vec<AuditEvent> {
        // Hashed with the writer's own function, so "mine" cannot be spelled
        // as somebody else's.
        let mine = audience.principal().map(crate::audit::actor_id_hash);
        let mut results = Vec::new();
        for path in self.list_files() {
            let events = parse_events_from_file(&path);
            for event in events {
                let visible = match &mine {
                    None => true,
                    Some(mine) => event_is_visible_to(&event, mine.as_deref()),
                };
                if visible && filter.matches(&event) {
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
        self.verify_latest_chain_anchored(None)
    }

    /// Verifies the latest file AND compares the tail against an out-of-band
    /// anchor. Without the anchor a removed tail is indistinguishable from
    /// "nothing happened since" — the remaining events verify perfectly.
    pub fn verify_latest_chain_anchored(
        &self,
        anchor: Option<&AuditChainAnchor>,
    ) -> AuditChainVerification {
        let mut verification = self.verify_latest_chain_inner();
        if crate::audit::anchor::check_tail(&self.audit_dir, anchor).is_truncated() {
            verification.tail_truncated = true;
            verification.chain_ok = false;
        }
        verification
    }

    fn verify_latest_chain_inner(&self) -> AuditChainVerification {
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
    ///
    /// Only a machine-wide audience gets any: the chain's value is that every
    /// event links to the next, so a subset scoped to one principal cannot be
    /// verified and would only fail its own check.
    pub fn recent_raw_lines(
        &self,
        max_bytes: usize,
        audience: &DiagnosticsAudience,
    ) -> Vec<String> {
        if max_bytes == 0 || !audience.is_machine_wide() {
            return Vec::new();
        }
        // Walk the files NEWEST first and stop as soon as the budget is met.
        // Reading every file first and trimming afterwards pulled the entire
        // trail — up to the 50 MiB retention cap — into the service's memory to
        // answer a request for its last few hundred KiB.
        let mut newest_first: Vec<String> = Vec::new();
        let mut used: usize = 0;
        'files: for path in self.list_files().into_iter().rev() {
            let Ok(contents) = std::fs::read_to_string(&path) else {
                continue;
            };
            for line in contents.lines().rev() {
                if line.is_empty() {
                    continue;
                }
                let cost = line.len() + 1;
                // The newest line is always kept, however long it is: a caller
                // asking for the tail must not get an empty answer.
                if !newest_first.is_empty() && used + cost > max_bytes {
                    break 'files;
                }
                used += cost;
                newest_first.push(line.to_string());
            }
        }
        newest_first.reverse();
        newest_first
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Whether a principal-scoped reader may see `event`.
///
/// What the SERVICE did on its own behalf, and events with no actor at all,
/// are facts about the machine and visible to everyone. Everything else belongs
/// to whoever performed it.
fn event_is_visible_to(event: &AuditEvent, my_actor_hash: Option<&str>) -> bool {
    if event.actor_kind == crate::audit::ActorKind::Service.as_str() {
        return true;
    }
    match (event.actor_id_hash.as_deref(), my_actor_hash) {
        (None, _) => true,
        (Some(theirs), Some(mine)) => theirs == mine,
        (Some(_), None) => false,
    }
}

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
    crate::rotation::sort_chronologically(&mut files);
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
            corrupt_lines: 1,
            ..AuditChainVerification::ok(0)
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
                mismatch_at_seq: Some(event.seq),
                expected_hash: Some(expected),
                actual_hash: Some(stored_hash),
                corrupt_lines: corrupt,
                ..AuditChainVerification::ok(verified)
            };
        }
        prev = stored_hash;
        verified += 1;
    }

    AuditChainVerification {
        corrupt_lines: corrupt,
        ..AuditChainVerification::ok(verified)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::kind::{ActorKind, AuditEventKind, AuditEventResult};
    use crate::audit::restart::{AuditChainRestartError, AuditChainRestartRequest};
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
        let events = reader.scan(&AuditQueryFilter::new(), &DiagnosticsAudience::Machine);
        assert_eq!(events.len(), 5);
    }

    #[test]
    fn recent_raw_lines_returns_verbatim_chain_fields() {
        let dir = tempfile::tempdir().expect("temp");
        write_events(dir.path(), 3);
        let reader = AuditReader::new(dir.path());
        let lines = reader.recent_raw_lines(1024 * 1024, &DiagnosticsAudience::Machine);
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
        let all = reader.recent_raw_lines(usize::MAX, &DiagnosticsAudience::Machine);
        assert_eq!(all.len(), 5);
        // Budget that fits only the last two lines plus their newlines.
        let budget = all[3].len() + 1 + all[4].len() + 1;
        let trimmed = reader.recent_raw_lines(budget, &DiagnosticsAudience::Machine);
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
        let trimmed = reader.recent_raw_lines(1, &DiagnosticsAudience::Machine);
        assert_eq!(trimmed.len(), 1);
        let all = reader.recent_raw_lines(usize::MAX, &DiagnosticsAudience::Machine);
        assert_eq!(trimmed[0], all[2]);
    }

    #[test]
    fn recent_raw_lines_zero_budget_is_empty() {
        let dir = tempfile::tempdir().expect("temp");
        write_events(dir.path(), 3);
        let reader = AuditReader::new(dir.path());
        assert!(reader
            .recent_raw_lines(0, &DiagnosticsAudience::Machine)
            .is_empty());
    }

    fn write_actor_event(writer: &AuditWriter, id: &str, actor: ActorKind, who: Option<&str>) {
        writer
            .append(AuditEventInput {
                event_id: id.into(),
                kind: AuditEventKind::RevisionActivated,
                created_at: 1_745_000_000_000,
                actor_kind: actor,
                actor_id_hash: who.and_then(crate::audit::actor_id_hash),
                revision_id: None,
                risk_level: None,
                result: AuditEventResult::Success,
                reason_code: reason::review::APPROVED,
                payload_summary_json: None,
            })
            .expect("append");
    }

    /// A principal reads its own events and the machine's, never another
    /// person's; the machine-wide reader is the positive control.
    #[test]
    fn a_scan_returns_only_what_the_audience_may_see() {
        let dir = tempfile::tempdir().expect("temp");
        let writer = AuditWriter::open(AuditWriterConfig::new(dir.path()));
        write_actor_event(&writer, "mine", ActorKind::User, Some("S-1-5-21-mine"));
        write_actor_event(&writer, "theirs", ActorKind::User, Some("S-1-5-21-theirs"));
        write_actor_event(&writer, "service", ActorKind::Service, None);
        drop(writer);
        let reader = AuditReader::new(dir.path());
        let ids = |audience: &DiagnosticsAudience| -> Vec<String> {
            reader
                .scan(&AuditQueryFilter::new(), audience)
                .into_iter()
                .map(|e| e.event_id)
                .collect()
        };

        assert_eq!(
            ids(&DiagnosticsAudience::Principal("S-1-5-21-mine".into())),
            ["mine", "service"]
        );
        assert_eq!(
            ids(&DiagnosticsAudience::Machine),
            ["mine", "theirs", "service"]
        );
    }

    /// A chain scoped to one principal cannot be verified, so only the
    /// machine-wide reader gets raw lines at all.
    #[test]
    fn raw_chain_lines_are_for_the_machine_wide_reader_only() {
        let dir = tempfile::tempdir().expect("temp");
        write_events(dir.path(), 2);
        let reader = AuditReader::new(dir.path());
        let principal = DiagnosticsAudience::Principal("S-1-5-21-mine".into());
        assert!(reader.recent_raw_lines(usize::MAX, &principal).is_empty());
        assert_eq!(
            reader
                .recent_raw_lines(usize::MAX, &DiagnosticsAudience::Machine)
                .len(),
            2
        );
    }

    /// Three sessions, three files, one chain.
    fn three_sessions(dir: &Path) -> Vec<PathBuf> {
        for _ in 0..3 {
            write_events(dir, 2);
        }
        let files = list_audit_files(dir);
        assert_eq!(files.len(), 3);
        files
    }

    #[test]
    fn the_whole_chain_verifies_and_an_older_file_is_checked_too() {
        let dir = tempfile::tempdir().expect("temp");
        let files = three_sessions(dir.path());
        let reader = AuditReader::new(dir.path());
        let mut verifier = AuditChainVerifier::new();
        let v = verifier.verify(&reader, None);
        assert!(v.chain_ok, "positive control: {v:?}");
        assert_eq!(v.events_verified, 6);

        let oldest = std::fs::read_to_string(&files[0]).expect("read");
        std::fs::write(&files[0], oldest.replace("rev-001", "rev-999")).expect("tamper");
        let v = verifier.verify(&reader, None);
        assert!(!v.chain_ok, "a changed file is re-read: {v:?}");
        assert!(
            reader.verify_latest_chain().chain_ok,
            "what the newest-file check could not see"
        );
    }

    /// A same-length edit in the middle of a file, with its modification time
    /// put back, is caught by a verifier that already vouched for the file.
    #[test]
    fn a_same_length_edit_with_its_time_restored_is_caught() {
        let dir = tempfile::tempdir().expect("temp");
        write_events(dir.path(), 5);
        let file = list_audit_files(dir.path()).pop().expect("a file");
        let reader = AuditReader::new(dir.path());
        let mut verifier = AuditChainVerifier::new();
        assert!(verifier.verify(&reader, None).chain_ok, "positive control");

        let written_at = std::fs::metadata(&file)
            .and_then(|m| m.modified())
            .expect("mtime");
        let content = std::fs::read_to_string(&file).expect("read");
        let middle = content.find("adt-0003").expect("the middle event");
        let mut bytes = content.into_bytes();
        bytes[middle + "adt-000".len()] = b'9';
        let len_before = bytes.len();
        std::fs::write(&file, &bytes).expect("tamper");
        std::fs::File::options()
            .write(true)
            .open(&file)
            .and_then(|f| f.set_modified(written_at))
            .expect("put the time back");
        let meta = std::fs::metadata(&file).expect("meta");
        assert_eq!(meta.len() as usize, len_before);
        assert_eq!(meta.modified().expect("mtime"), written_at);

        let v = verifier.verify(&reader, None);
        assert!(!v.chain_ok, "{v:?}");
        assert_eq!(v.mismatch_at_seq, Some(3));
    }

    /// Two files that both continue from the same event are a fork, even
    /// though each verifies on its own.
    #[test]
    fn a_fork_between_files_is_caught() {
        let dir = tempfile::tempdir().expect("temp");
        let files = three_sessions(dir.path());
        std::fs::copy(&files[1], dir.path().join("nrr_audit_20990101-1.ndjson")).expect("fork");
        let v = AuditChainVerifier::new().verify(&AuditReader::new(dir.path()), None);
        assert!(!v.chain_ok, "{v:?}");
    }

    /// Retention removes the oldest files; what the first survivor pointed at
    /// is gone, and that is not tampering.
    #[test]
    fn retention_removing_the_oldest_file_is_not_a_break() {
        let dir = tempfile::tempdir().expect("temp");
        let files = three_sessions(dir.path());
        std::fs::remove_file(&files[0]).expect("retire");
        let v = AuditChainVerifier::new().verify(&AuditReader::new(dir.path()), None);
        assert!(v.chain_ok, "{v:?}");
        assert_eq!(v.events_verified, 4);
    }

    // ── Restart ──────────────────────────────────────────────────────────────

    fn service_key() -> AuditRestartKey {
        AuditRestartKey::derive(b"the service's integrity key").expect("key")
    }

    fn restart_request() -> AuditChainRestartRequest {
        AuditChainRestartRequest {
            event_id: "adt-restart".into(),
            created_at: 1_745_100_000_000,
            actor_id_hash: crate::audit::actor_id_hash("S-1-5-21-admin"),
        }
    }

    fn verify_with(dir: &Path, key: Option<AuditRestartKey>) -> AuditChainVerification {
        let mut verifier = match key {
            Some(key) => AuditChainVerifier::with_restart_key(key),
            None => AuditChainVerifier::new(),
        };
        verifier.verify(&AuditReader::new(dir), None)
    }

    /// Three sessions with the oldest file edited: the break an old edit leaves.
    fn broken_trail(dir: &Path) -> Vec<PathBuf> {
        let files = three_sessions(dir);
        let oldest = std::fs::read_to_string(&files[0]).expect("read");
        std::fs::write(&files[0], oldest.replacen("rev-001", "rev-999", 1)).expect("tamper");
        files
    }

    /// Appends `event` to the newest file, chained onto its last event the way
    /// anyone who can write the directory could.
    fn append_forged(dir: &Path, mut event: AuditEvent, seal_key: Option<&AuditRestartKey>) {
        let newest = list_audit_files(dir).pop().expect("a file");
        let prev = last_event_hash_in_file(&newest).expect("an event");
        event.prev_hash = Some(prev.clone());
        event.event_hash = String::new();
        if let Some(key) = seal_key {
            crate::audit::restart::seal_event(&mut event, key).expect("seal");
        }
        let canonical = serde_json::to_string(&event).expect("serialize");
        event.event_hash = compute_chain_hash(&prev, &canonical);
        let mut content = std::fs::read_to_string(&newest).expect("read");
        content.push_str(&serde_json::to_string(&event).expect("serialize"));
        content.push('\n');
        std::fs::write(&newest, content).expect("append");
    }

    fn restart_event() -> AuditEvent {
        AuditEvent {
            schema_version: crate::event::AUDIT_EVENT_SCHEMA_VERSION,
            seq: 99,
            event_id: "adt-forged".into(),
            kind: AuditEventKind::AuditChainRestarted.as_str().into(),
            created_at: 1_745_100_000_000,
            actor_kind: ActorKind::User.as_str().into(),
            actor_id_hash: None,
            revision_id: None,
            risk_level: None,
            result: AuditEventResult::Success.as_str().into(),
            reason_code: reason::integrity::AUDIT_CHAIN_RESTARTED.as_str().into(),
            payload_summary_json: None,
            seal: Some("00".repeat(32)),
            prev_hash: None,
            event_hash: String::new(),
        }
    }

    /// An old break stays reported until an administrator restarts the chain;
    /// after the restart the trail verifies, and the next break flips it back.
    #[test]
    fn a_restart_clears_an_old_break_and_a_new_one_is_caught_again() {
        let dir = tempfile::tempdir().expect("temp");
        broken_trail(dir.path());
        let before = verify_with(dir.path(), Some(service_key()));
        assert!(!before.chain_ok, "positive control: {before:?}");
        assert_eq!(before.break_count, 1);
        let digest = before.breaks_digest.clone().expect("digest");

        let writer = AuditWriter::open(AuditWriterConfig::new(dir.path()));
        let covered = writer
            .restart_chain(&service_key(), &digest, restart_request())
            .expect("restart");
        assert_eq!(covered.break_count, 1);
        writer
            .append(AuditEventInput {
                event_id: "after".into(),
                kind: AuditEventKind::RevisionActivated,
                created_at: 1_745_200_000_000,
                actor_kind: ActorKind::User,
                actor_id_hash: None,
                revision_id: Some("rev-after".into()),
                risk_level: None,
                result: AuditEventResult::Success,
                reason_code: reason::review::APPROVED,
                payload_summary_json: None,
            })
            .expect("append after restart");

        let after = verify_with(dir.path(), Some(service_key()));
        assert!(after.chain_ok && after.restarted, "{after:?}");
        assert_eq!(
            after.events_verified, 2,
            "the restart and the event after it"
        );

        let newest = list_audit_files(dir.path()).pop().expect("file");
        let content = std::fs::read_to_string(&newest).expect("read");
        assert!(
            content.contains("audit_chain_restarted") && content.contains("head"),
            "the restart records what it chained onto"
        );
        std::fs::write(&newest, content.replace("rev-after", "rev-edit")).expect("tamper");
        let again = verify_with(dir.path(), Some(service_key()));
        assert!(!again.chain_ok, "a break after the restart: {again:?}");
        assert_eq!(again.breaks[0].kind, AuditChainBreakKind::HashMismatch);
    }

    /// A restart written by someone without the service's key — unsealed, or
    /// sealed with another key — is an ordinary event, and the old break is
    /// still what the verification reports.
    #[test]
    fn a_forged_restart_is_rejected_and_the_break_still_reported() {
        let other = AuditRestartKey::derive(b"a key the forger made up").expect("key");
        for seal_key in [None, Some(&other)] {
            let dir = tempfile::tempdir().expect("temp");
            let files = broken_trail(dir.path());
            let before = verify_with(dir.path(), Some(service_key()));

            append_forged(dir.path(), restart_event(), seal_key);
            let after = verify_with(dir.path(), Some(service_key()));
            assert!(!after.chain_ok && !after.restarted, "{after:?}");
            assert_eq!(after.breaks, before.breaks);
            assert_eq!(after.breaks[0].file_name, file_name_of(&files[0]));
        }
        // Positive control: the same event sealed with the service's key.
        let dir = tempfile::tempdir().expect("temp");
        broken_trail(dir.path());
        append_forged(dir.path(), restart_event(), Some(&service_key()));
        assert!(verify_with(dir.path(), Some(service_key())).chain_ok);
    }

    /// A genuine restart copied past a later break does not cover it: the
    /// seal fixes what it chained onto.
    #[test]
    fn a_genuine_restart_copied_elsewhere_does_not_count() {
        let dir = tempfile::tempdir().expect("temp");
        broken_trail(dir.path());
        let digest = verify_with(dir.path(), Some(service_key()))
            .breaks_digest
            .expect("digest");
        let writer = AuditWriter::open(AuditWriterConfig::new(dir.path()));
        writer
            .restart_chain(&service_key(), &digest, restart_request())
            .expect("restart");
        drop(writer);
        write_events(dir.path(), 2);
        let newest = list_audit_files(dir.path()).pop().expect("file");
        let content = std::fs::read_to_string(&newest).expect("read");
        std::fs::write(&newest, content.replacen("rev-001", "rev-999", 1)).expect("tamper");
        assert!(!verify_with(dir.path(), Some(service_key())).chain_ok);

        let files = list_audit_files(dir.path());
        let restart_line = files
            .iter()
            .flat_map(|f| {
                std::fs::read_to_string(f)
                    .expect("read")
                    .lines()
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            })
            .find(|l| l.contains("audit_chain_restarted"))
            .expect("the restart");
        // The seal does not cover `event_hash`, so the copy is re-hashed onto
        // its new predecessor: only the link check can tell.
        let mut copy: AuditEvent = serde_json::from_str(&restart_line).expect("parse");
        let (_, canonical) = parse_event(&restart_line).expect("event");
        copy.event_hash =
            compute_chain_hash(&last_event_hash_in_file(&newest).expect("tail"), &canonical);
        let mut content = std::fs::read_to_string(&newest).expect("read");
        content.push_str(&serde_json::to_string(&copy).expect("serialize"));
        content.push('\n');
        std::fs::write(&newest, content).expect("copy");
        let verdict = verify_with(dir.path(), Some(service_key()));
        assert!(!verdict.chain_ok, "{verdict:?}");
        assert!(
            verdict
                .breaks
                .iter()
                .all(|b| b.kind == AuditChainBreakKind::HashMismatch),
            "the copy itself chains cleanly: {verdict:?}"
        );
    }

    /// The restart covers what was shown and nothing else, and needs
    /// something to cover.
    #[test]
    fn a_restart_is_refused_when_nothing_is_broken_or_the_breaks_changed() {
        let dir = tempfile::tempdir().expect("temp");
        three_sessions(dir.path());
        let writer = AuditWriter::open(AuditWriterConfig::new(dir.path()));
        assert!(matches!(
            writer.restart_chain(&service_key(), "anything", restart_request()),
            Err(AuditChainRestartError::Intact)
        ));
        drop(writer);

        let dir = tempfile::tempdir().expect("temp");
        let files = broken_trail(dir.path());
        let shown = verify_with(dir.path(), Some(service_key()))
            .breaks_digest
            .expect("digest");
        let second = std::fs::read_to_string(&files[1]).expect("read");
        std::fs::write(&files[1], second.replacen("rev-001", "rev-998", 1)).expect("tamper");
        let writer = AuditWriter::open(AuditWriterConfig::new(dir.path()));
        assert!(matches!(
            writer.restart_chain(&service_key(), &shown, restart_request()),
            Err(AuditChainRestartError::ChangedSinceShown)
        ));
        assert!(!verify_with(dir.path(), Some(service_key())).restarted);
    }

    /// Without the service's key a verifier honours no restart at all.
    #[test]
    fn without_the_key_no_restart_is_honoured() {
        let dir = tempfile::tempdir().expect("temp");
        broken_trail(dir.path());
        let digest = verify_with(dir.path(), Some(service_key()))
            .breaks_digest
            .expect("digest");
        AuditWriter::open(AuditWriterConfig::new(dir.path()))
            .restart_chain(&service_key(), &digest, restart_request())
            .expect("restart");
        assert!(verify_with(dir.path(), Some(service_key())).chain_ok);
        assert!(!verify_with(dir.path(), None).chain_ok);
    }

    /// A corrupt line and a cut tail are breaks like any other: listed, and
    /// covered by a restart.
    #[test]
    fn a_restart_covers_a_corrupt_line_and_a_cut_tail() {
        let dir = tempfile::tempdir().expect("temp");
        let anchor: std::sync::Arc<dyn crate::audit::anchor::AuditChainAnchorStore> =
            std::sync::Arc::new(crate::audit::anchor::FileAnchorStore::in_dir(dir.path()));
        write_events(dir.path(), 2);
        let writer =
            AuditWriter::open_anchored(AuditWriterConfig::new(dir.path()), Some(anchor.clone()));
        write_actor_event(&writer, "last", ActorKind::Service, None);
        drop(writer);
        let files = list_audit_files(dir.path());
        std::fs::write(&files[1], "").expect("cut the tail");
        let mut first = std::fs::read_to_string(&files[0]).expect("read");
        first.push_str("not an event\n");
        std::fs::write(&files[0], first).expect("corrupt");

        let mut verifier = AuditChainVerifier::with_restart_key(service_key());
        let before = verifier.verify(&AuditReader::new(dir.path()), anchor.load().as_ref());
        assert!(
            before.tail_truncated && before.corrupt_lines == 1,
            "{before:?}"
        );
        let kinds: Vec<_> = before.breaks.iter().map(|b| b.kind).collect();
        assert_eq!(
            kinds,
            [
                AuditChainBreakKind::CorruptLine,
                AuditChainBreakKind::TailTruncated
            ]
        );

        let writer =
            AuditWriter::open_anchored(AuditWriterConfig::new(dir.path()), Some(anchor.clone()));
        writer
            .restart_chain(
                &service_key(),
                before.breaks_digest.as_deref().expect("digest"),
                restart_request(),
            )
            .expect("restart");
        let after = AuditChainVerifier::with_restart_key(service_key())
            .verify(&AuditReader::new(dir.path()), anchor.load().as_ref());
        assert!(after.chain_ok && after.corrupt_lines == 0, "{after:?}");
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
        let tamper_events = reader.scan(
            &AuditQueryFilter::new().kind("tamper_alert_raised"),
            &DiagnosticsAudience::Machine,
        );
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
        let rev2 = reader.scan(
            &AuditQueryFilter::new().revision_id("rev-002"),
            &DiagnosticsAudience::Machine,
        );
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
        let path = list_audit_files(dir.path())[0].clone();
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
    fn files_are_sorted_chronologically_past_the_ninth_rotation() {
        let dir = tempfile::tempdir().expect("temp");
        for name in [
            "nrr_audit_20260423-2.ndjson",
            "nrr_audit_20260423-11.ndjson",
            "nrr_audit_20260423-1.ndjson",
            "nrr_audit_20260422-9.ndjson",
        ] {
            std::fs::write(dir.path().join(name), "").unwrap();
        }

        let reader = AuditReader::new(dir.path());
        let names: Vec<_> = reader
            .list_files()
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            names,
            [
                "nrr_audit_20260422-9.ndjson",
                "nrr_audit_20260423-1.ndjson",
                "nrr_audit_20260423-2.ndjson",
                "nrr_audit_20260423-11.ndjson",
            ]
        );
    }
}
