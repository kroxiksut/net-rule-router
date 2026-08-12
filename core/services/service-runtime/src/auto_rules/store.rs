//! Durable record of companion-domain suggestions: what was refused, and what
//! is still waiting for an answer.
//!
//! Both halves are persisted. A refusal is a decision made once, and the
//! evidence behind the suggestion keeps accumulating, so without a durable
//! record the same rejected host is offered again after every restart —
//! that half was durable from the start.
//!
//! Pending suggestions were originally kept in memory only, on the theory that
//! a pending offer re-derives itself from the next few minutes of browsing. In
//! practice the set a user is meant to work through accumulates over weeks —
//! which sites need a host, how many, since when — and that composition does
//! not come back from a few minutes of fresh traffic after a restart. Pending
//! suggestions are durable too, from `STATE_DB_V47_DDL` on; re-derivation still
//! covers the ordinary "service was down for an hour" case, it just no longer
//! has to cover "the user hasn't gotten around to reviewing these yet". See
//! `STATE_DB_V43_DDL` (refusals) and `STATE_DB_V47_DDL` (pending).

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use nrr_domain::companion_affinity::{
    AnchorSnapshot, CandidateSnapshot, CompanionEvidenceSnapshot, PairSnapshot,
};
use nrr_shared::RouteRole;
use nrr_storage::auto_rule_dismissals::{
    AutoRuleDismissal, AutoRuleDismissalRecord, AutoRuleDismissalsRepository,
};
use nrr_storage::auto_rule_evidence::AutoRuleEvidenceRepository;
use nrr_storage::auto_rule_pending::{AutoRulePendingRecord, AutoRulePendingRepository};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};

/// Per-SID record of the suggestions a user refused.
///
/// A port rather than a concrete type so the engine can be exercised without a
/// database and so a degraded boot (no state DB) still runs the discovery pass
/// with in-memory-only refusals instead of refusing to run at all.
pub trait DismissalStore: Send + Sync {
    /// Every candidate id `sid` has refused. Called once per SID per service
    /// session; the engine caches the result in memory.
    fn load(&self, sid: &str) -> HashSet<String>;

    /// Record refusals. Best-effort by contract — a write failure is logged and
    /// the refusal still holds for the current session.
    fn record(&self, sid: &str, dismissals: &[AutoRuleDismissal], now_ms: i64);

    /// Every refusal `sid` has recorded, most recent first — backs
    /// `autorules.dismissed.list`.
    fn list(&self, sid: &str) -> Vec<AutoRuleDismissalRecord>;

    /// Undoes one refusal so the host may be offered again. Returns whether it
    /// was actually recorded.
    fn forget(&self, sid: &str, candidate_id: &str) -> bool;
}

/// In-memory store: used by tests and as the fallback when the state DB is
/// unavailable. Refusals hold for the process lifetime only.
///
/// Keyed by candidate id (rather than a bare `HashSet`) so the fallback path
/// can answer `list` with the same shape the durable store does — a refusal
/// made when the state DB is unavailable must still be reviewable within the
/// session.
#[derive(Default)]
pub struct InMemoryDismissalStore {
    by_sid: Mutex<HashMap<String, HashMap<String, AutoRuleDismissalRecord>>>,
}

impl InMemoryDismissalStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl DismissalStore for InMemoryDismissalStore {
    fn load(&self, sid: &str) -> HashSet<String> {
        self.by_sid
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(sid)
            .map(|entries| entries.keys().cloned().collect())
            .unwrap_or_default()
    }

    fn record(&self, sid: &str, dismissals: &[AutoRuleDismissal], now_ms: i64) {
        let mut guard = self.by_sid.lock().unwrap_or_else(|p| p.into_inner());
        let entry = guard.entry(sid.to_string()).or_default();
        for d in dismissals {
            entry.insert(
                d.candidate_id.clone(),
                AutoRuleDismissalRecord {
                    candidate_id: d.candidate_id.clone(),
                    anchor: d.anchor.clone(),
                    proposed_match: d.proposed_match.clone(),
                    dto_json: d.dto_json.clone(),
                    dismissed_at: now_ms,
                },
            );
        }
    }

    fn list(&self, sid: &str) -> Vec<AutoRuleDismissalRecord> {
        let mut out: Vec<AutoRuleDismissalRecord> = self
            .by_sid
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(sid)
            .map(|entries| entries.values().cloned().collect())
            .unwrap_or_default();
        out.sort_by(|a, b| b.dismissed_at.cmp(&a.dismissed_at));
        out
    }

    fn forget(&self, sid: &str, candidate_id: &str) -> bool {
        self.by_sid
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get_mut(sid)
            .is_some_and(|entries| entries.remove(candidate_id).is_some())
    }
}

/// State-DB-backed store — the production implementation.
pub struct SqliteDismissalStore {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteDismissalStore {
    pub fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self { conn }
    }
}

impl DismissalStore for SqliteDismissalStore {
    fn load(&self, sid: &str) -> HashSet<String> {
        let guard = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        match AutoRuleDismissalsRepository::new(&guard).load_ids(sid) {
            Ok(ids) => ids,
            Err(e) => {
                tracing::warn!(
                    target: "nrr::auto-rules",
                    error = %e,
                    "could not read refused suggestions — this session may re-offer a host the user already declined",
                );
                HashSet::new()
            }
        }
    }

    fn record(&self, sid: &str, dismissals: &[AutoRuleDismissal], now_ms: i64) {
        let guard = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        if let Err(e) = AutoRuleDismissalsRepository::new(&guard).record(sid, dismissals, now_ms) {
            tracing::warn!(
                target: "nrr::auto-rules",
                error = %e,
                count = dismissals.len(),
                "could not persist refused suggestions — the refusal holds for this session only",
            );
        }
    }

    fn list(&self, sid: &str) -> Vec<AutoRuleDismissalRecord> {
        let guard = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        match AutoRuleDismissalsRepository::new(&guard).load_all(sid) {
            Ok(rows) => rows,
            Err(e) => {
                tracing::warn!(
                    target: "nrr::auto-rules",
                    error = %e,
                    "could not read declined suggestions for review",
                );
                Vec::new()
            }
        }
    }

    fn forget(&self, sid: &str, candidate_id: &str) -> bool {
        let guard = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        match AutoRuleDismissalsRepository::new(&guard).forget(sid, candidate_id) {
            Ok(changed) => changed,
            Err(e) => {
                tracing::warn!(
                    target: "nrr::auto-rules",
                    error = %e,
                    "could not undo a declined suggestion — it stays refused for this session",
                );
                false
            }
        }
    }
}

// ── Pending suggestions ──────────────────────────────────────────────────────

/// Durable mirror of one principal's unanswered suggestions.
///
/// A port rather than a concrete type for the same reason as
/// [`DismissalStore`]: the engine must be exercisable without a database, and
/// a degraded boot (no state DB) should lose durability, not the feature.
pub trait PendingSuggestionStore: Send + Sync {
    /// Every persisted suggestion for every SID, grouped by SID. Read once at
    /// construction to restore the in-memory pending set after a restart.
    fn load_all(&self) -> HashMap<String, Vec<AutoRulePendingRecord>>;

    /// Replaces `sid`'s persisted set with `candidates` — the caller always
    /// holds the definitive in-memory set, so this mirrors it wholesale rather
    /// than diffing. An empty slice clears the SID.
    fn replace(&self, sid: &str, candidates: &[AutoRulePendingRecord]);

    /// Drops every persisted suggestion for `sid` (companion discovery turned
    /// off for that principal).
    fn clear(&self, sid: &str);
}

/// In-memory store: used by tests and as the fallback when the state DB is
/// unavailable. Pending suggestions hold for the process lifetime only.
#[derive(Default)]
pub struct InMemoryPendingStore {
    by_sid: Mutex<HashMap<String, Vec<AutoRulePendingRecord>>>,
}

impl InMemoryPendingStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl PendingSuggestionStore for InMemoryPendingStore {
    fn load_all(&self) -> HashMap<String, Vec<AutoRulePendingRecord>> {
        self.by_sid
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    fn replace(&self, sid: &str, candidates: &[AutoRulePendingRecord]) {
        let mut guard = self.by_sid.lock().unwrap_or_else(|p| p.into_inner());
        if candidates.is_empty() {
            guard.remove(sid);
        } else {
            guard.insert(sid.to_string(), candidates.to_vec());
        }
    }

    fn clear(&self, sid: &str) {
        self.by_sid
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(sid);
    }
}

/// State-DB-backed store — the production implementation.
pub struct SqlitePendingStore {
    conn: Arc<Mutex<Connection>>,
}

impl SqlitePendingStore {
    pub fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self { conn }
    }
}

impl PendingSuggestionStore for SqlitePendingStore {
    fn load_all(&self) -> HashMap<String, Vec<AutoRulePendingRecord>> {
        let guard = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        match AutoRulePendingRepository::new(&guard).load_all() {
            Ok(rows) => {
                let mut out: HashMap<String, Vec<AutoRulePendingRecord>> = HashMap::new();
                for (sid, record) in rows {
                    out.entry(sid).or_default().push(record);
                }
                out
            }
            Err(e) => {
                tracing::warn!(
                    target: "nrr::auto-rules",
                    error = %e,
                    "could not read pending suggestions — this session starts with an empty offer set",
                );
                HashMap::new()
            }
        }
    }

    fn replace(&self, sid: &str, candidates: &[AutoRulePendingRecord]) {
        let guard = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        if let Err(e) = AutoRulePendingRepository::new(&guard).replace(sid, candidates) {
            tracing::warn!(
                target: "nrr::auto-rules",
                error = %e,
                count = candidates.len(),
                "could not persist pending suggestions — they will not survive a restart",
            );
        }
    }

    fn clear(&self, sid: &str) {
        let guard = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        if let Err(e) = AutoRulePendingRepository::new(&guard).clear(sid) {
            tracing::warn!(
                target: "nrr::auto-rules",
                error = %e,
                "could not clear persisted pending suggestions",
            );
        }
    }
}

// ── Accumulated evidence ─────────────────────────────────────────────────────

/// Durable record of what the learner has observed for one principal.
///
/// A proposal needs the same host beside the same site in two distinct windows.
/// Restarts used to reset that count, and on a laptop that sleeps and restarts
/// several times a day the second window never arrived — a full acceptance run
/// produced no candidate at all for exactly this reason. Same port shape and
/// same degraded-boot tolerance as the two stores above.
pub trait EvidenceStore: Send + Sync {
    /// What `sid` had learned when it was last saved, or `None` for a principal
    /// that has never been saved (or whose saved form this build cannot read).
    fn load(&self, sid: &str) -> Option<CompanionEvidenceSnapshot>;

    /// Replaces `sid`'s saved evidence.
    fn save(&self, sid: &str, snapshot: &CompanionEvidenceSnapshot, now_ms: i64);

    /// Forgets everything saved for `sid` (companion discovery turned off).
    fn clear(&self, sid: &str);
}

/// In-memory store: tests and the degraded boot. Evidence still accumulates
/// within the session, it just does not outlive the process.
#[derive(Default)]
pub struct InMemoryEvidenceStore {
    by_sid: Mutex<HashMap<String, CompanionEvidenceSnapshot>>,
}

impl InMemoryEvidenceStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl EvidenceStore for InMemoryEvidenceStore {
    fn load(&self, sid: &str) -> Option<CompanionEvidenceSnapshot> {
        self.by_sid
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(sid)
            .cloned()
    }

    fn save(&self, sid: &str, snapshot: &CompanionEvidenceSnapshot, _now_ms: i64) {
        self.by_sid
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(sid.to_string(), snapshot.clone());
    }

    fn clear(&self, sid: &str) {
        self.by_sid
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(sid);
    }
}

/// State-DB-backed store — the production implementation. The JSON shape lives
/// here rather than in the domain (which stays serde-free) and in the storage
/// crate (which keeps the column opaque), so this module owns both ends of the
/// translation and nothing else has to know the encoding.
pub struct SqliteEvidenceStore {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteEvidenceStore {
    pub fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self { conn }
    }
}

impl EvidenceStore for SqliteEvidenceStore {
    fn load(&self, sid: &str) -> Option<CompanionEvidenceSnapshot> {
        let guard = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        let json = match AutoRuleEvidenceRepository::new(&guard).load(sid) {
            Ok(json) => json?,
            Err(e) => {
                tracing::warn!(
                    target: "nrr::auto-rules",
                    error = %e,
                    "could not read saved companion evidence — learning starts over this session",
                );
                return None;
            }
        };
        match serde_json::from_str::<EvidenceSnapshotJson>(&json) {
            Ok(wire) => Some(wire.into_domain()),
            Err(e) => {
                // A snapshot this build cannot read is dropped, not repaired:
                // evidence re-accumulates, a wrong reconstruction would not.
                tracing::warn!(
                    target: "nrr::auto-rules",
                    error = %e,
                    "saved companion evidence is not readable by this build — starting over",
                );
                None
            }
        }
    }

    fn save(&self, sid: &str, snapshot: &CompanionEvidenceSnapshot, now_ms: i64) {
        let json = match serde_json::to_string(&EvidenceSnapshotJson::from_domain(snapshot)) {
            Ok(json) => json,
            Err(e) => {
                tracing::warn!(
                    target: "nrr::auto-rules",
                    error = %e,
                    "could not serialise companion evidence",
                );
                return;
            }
        };
        let guard = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        if let Err(e) = AutoRuleEvidenceRepository::new(&guard).save(sid, &json, now_ms) {
            tracing::warn!(
                target: "nrr::auto-rules",
                error = %e,
                "could not persist companion evidence — it will not survive a restart",
            );
        }
    }

    fn clear(&self, sid: &str) {
        let guard = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        if let Err(e) = AutoRuleEvidenceRepository::new(&guard).clear(sid) {
            tracing::warn!(
                target: "nrr::auto-rules",
                error = %e,
                "could not clear saved companion evidence",
            );
        }
    }
}

// ── Wire form of the evidence snapshot ───────────────────────────────────────
//
// Short field names on purpose: one row per principal holding a few hundred
// candidates is written on a timer, and the long names would be most of it.

#[derive(Serialize, Deserialize)]
struct EvidenceSnapshotJson {
    #[serde(default)]
    a: Vec<AnchorJson>,
    #[serde(default)]
    c: Vec<CandidateJson>,
    #[serde(default)]
    next_anchor: u32,
    #[serde(default)]
    next_window: u64,
}

#[derive(Serialize, Deserialize)]
struct AnchorJson {
    h: String,
    id: u32,
    /// Route slug — an unknown one drops the anchor rather than guessing.
    r: String,
    w: u64,
    ws: u64,
    we: u64,
    ls: u64,
}

#[derive(Serialize, Deserialize)]
struct PairJson {
    a: u32,
    dw: u32,
    lw: u64,
    nh: u32,
    uh: u32,
}

#[derive(Serialize, Deserialize)]
struct CandidateJson {
    h: String,
    fs: u64,
    ls: u64,
    tw: u32,
    th: u32,
    #[serde(default)]
    used: bool,
    #[serde(default)]
    stalls: u32,
    #[serde(default)]
    cuts: u32,
    #[serde(default)]
    done: u32,
    #[serde(default)]
    p: Vec<PairJson>,
}

impl EvidenceSnapshotJson {
    fn from_domain(snapshot: &CompanionEvidenceSnapshot) -> Self {
        Self {
            a: snapshot
                .anchors
                .iter()
                .map(|a| AnchorJson {
                    h: a.hostname.clone(),
                    id: a.id,
                    r: a.route.slug().to_string(),
                    w: a.window_id,
                    ws: a.window_start_ms,
                    we: a.window_end_ms,
                    ls: a.last_seen_ms,
                })
                .collect(),
            c: snapshot
                .candidates
                .iter()
                .map(|c| CandidateJson {
                    h: c.hostname.clone(),
                    fs: c.first_seen_ms,
                    ls: c.last_seen_ms,
                    tw: c.total_windows,
                    th: c.total_hits,
                    used: c.seen_in_use,
                    stalls: c.primary_stalls,
                    cuts: c.primary_cuts,
                    done: c.primary_completions,
                    p: c.pairs
                        .iter()
                        .map(|p| PairJson {
                            a: p.anchor_id,
                            dw: p.distinct_windows,
                            lw: p.last_window_id,
                            nh: p.nearest_hits,
                            uh: p.uncontested_hits,
                        })
                        .collect(),
                })
                .collect(),
            next_anchor: snapshot.next_anchor_id,
            next_window: snapshot.next_window_id,
        }
    }

    fn into_domain(self) -> CompanionEvidenceSnapshot {
        CompanionEvidenceSnapshot {
            anchors: self
                .a
                .into_iter()
                .filter_map(|a| {
                    let route = [RouteRole::Primary, RouteRole::Secondary]
                        .into_iter()
                        .find(|r| r.slug() == a.r)?;
                    Some(AnchorSnapshot {
                        hostname: a.h,
                        id: a.id,
                        route,
                        window_id: a.w,
                        window_start_ms: a.ws,
                        window_end_ms: a.we,
                        last_seen_ms: a.ls,
                    })
                })
                .collect(),
            candidates: self
                .c
                .into_iter()
                .map(|c| CandidateSnapshot {
                    hostname: c.h,
                    first_seen_ms: c.fs,
                    last_seen_ms: c.ls,
                    total_windows: c.tw,
                    total_hits: c.th,
                    seen_in_use: c.used,
                    primary_stalls: c.stalls,
                    primary_cuts: c.cuts,
                    primary_completions: c.done,
                    pairs: c
                        .p
                        .into_iter()
                        .map(|p| PairSnapshot {
                            anchor_id: p.a,
                            distinct_windows: p.dw,
                            last_window_id: p.lw,
                            nearest_hits: p.nh,
                            uncontested_hits: p.uh,
                        })
                        .collect(),
                })
                .collect(),
            next_anchor_id: self.next_anchor,
            next_window_id: self.next_window,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dismissal(id: &str) -> AutoRuleDismissal {
        AutoRuleDismissal {
            candidate_id: id.to_string(),
            anchor: "site.example".to_string(),
            proposed_match: "cdn.example".to_string(),
            dto_json: String::new(),
        }
    }

    #[test]
    fn in_memory_store_records_and_reloads_per_sid() {
        let store = InMemoryDismissalStore::new();
        store.record("S-A", &[dismissal("arc-1")], 0);
        assert!(store.load("S-A").contains("arc-1"));
        assert!(store.load("S-B").is_empty());
    }

    #[test]
    fn in_memory_store_lists_full_records_newest_first() {
        let store = InMemoryDismissalStore::new();
        store.record("S-A", &[dismissal("arc-1")], 100);
        store.record("S-A", &[dismissal("arc-2")], 200);
        let rows = store.list("S-A");
        assert_eq!(
            rows.iter()
                .map(|r| r.candidate_id.as_str())
                .collect::<Vec<_>>(),
            vec!["arc-2", "arc-1"]
        );
        assert!(store.list("S-B").is_empty());
    }

    #[test]
    fn in_memory_store_forget_removes_the_record_and_reports_whether_one_existed() {
        let store = InMemoryDismissalStore::new();
        store.record("S-A", &[dismissal("arc-1")], 0);
        assert!(store.forget("S-A", "arc-1"));
        assert!(!store.load("S-A").contains("arc-1"));
        assert!(store.list("S-A").is_empty());
        assert!(!store.forget("S-A", "arc-1"));
        assert!(!store.forget("S-B", "arc-1"));
    }

    fn pending(id: &str) -> AutoRulePendingRecord {
        AutoRulePendingRecord {
            candidate_id: id.to_string(),
            route: "secondary".to_string(),
            match_kind: "exact".to_string(),
            dto_json: format!("{{\"id\":\"{id}\"}}"),
            parked_at: 0,
        }
    }

    #[test]
    fn in_memory_pending_store_replaces_and_reloads_per_sid() {
        let store = InMemoryPendingStore::new();
        store.replace("S-A", &[pending("arc-1"), pending("arc-2")]);
        let all = store.load_all();
        assert_eq!(all.get("S-A").map(Vec::len), Some(2));
        assert!(!all.contains_key("S-B"));
    }

    #[test]
    fn in_memory_pending_store_replace_is_a_full_mirror() {
        let store = InMemoryPendingStore::new();
        store.replace("S-A", &[pending("arc-1"), pending("arc-2")]);
        store.replace("S-A", &[pending("arc-1")]);
        assert_eq!(store.load_all().get("S-A").map(Vec::len), Some(1));
    }

    #[test]
    fn in_memory_pending_store_replace_with_empty_clears_the_sid() {
        let store = InMemoryPendingStore::new();
        store.replace("S-A", &[pending("arc-1")]);
        store.replace("S-A", &[]);
        assert!(!store.load_all().contains_key("S-A"));
    }

    #[test]
    fn in_memory_pending_store_clear_drops_only_the_named_sid() {
        let store = InMemoryPendingStore::new();
        store.replace("S-A", &[pending("arc-1")]);
        store.replace("S-B", &[pending("arc-2")]);
        store.clear("S-A");
        let all = store.load_all();
        assert!(!all.contains_key("S-A"));
        assert!(all.contains_key("S-B"));
    }
}
