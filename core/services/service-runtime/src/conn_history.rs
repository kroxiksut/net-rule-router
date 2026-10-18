//! Each user's connection history: the trace, kept past its ring.
//!
//! Fed by the same pass that fills the connection trace — one fold into a
//! bounded map per row the observer already produced, nothing on the traffic
//! path. The map is folded per user, program, destination, route, verdict and
//! hour, and written in one transaction at most once a minute on the flush
//! task's own thread (`nrr_conn_history.db`). Expiry follows each user's chosen
//! period; a byte cap for the whole machine removes the oldest hours first and
//! the reader is told how much went.
//!
//! Only people have a history: service accounts and connections nobody owns
//! are skipped, and a user who switched it off is not recorded at all.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use nrr_storage::conn_history::{ConnHistoryPrefs, DEFAULT_RETENTION_DAYS, MAX_RETENTION_DAYS};
use nrr_storage::{
    ConnHistoryEntry, ConnHistoryQuery, ConnHistoryRow, SqliteConnHistoryStore, StorageError,
};

use crate::conn_observation_consumer::{role_str, verdict_str, ConnectionTraceRecord};

/// The size the whole machine's history may reach.
pub const MAX_HISTORY_BYTES: u64 = 50 * 1024 * 1024;

/// Folded rows held between two flushes. A minute of a busy machine folds to a
/// few hundred; past this, a new row is skipped and counted, never queued.
pub const MAX_PENDING_ROWS: usize = 20_000;

/// Longest program path or host name kept; a longer one is cut at a character
/// boundary. Both come from the OS or a DNS answer, and neither needs more.
pub const MAX_FIELD_BYTES: usize = 512;

/// How often expiry and the size cap run, at most.
const PRUNE_INTERVAL_MS: u64 = 10 * 60_000;

const HOUR_MS: u64 = 3_600_000;
const DAY_MS: u64 = 86_400_000;

/// Writes one user's choices where they survive a rebuild of the history file.
pub type PersistPrefsFn = Arc<dyn Fn(&str, ConnHistoryPrefs) -> Result<(), String> + Send + Sync>;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct FoldKey {
    principal: String,
    hour: u64,
    program: String,
    host: String,
    remote_ip: IpAddr,
    route: &'static str,
    verdict: &'static str,
    blocked_by: &'static str,
}

#[derive(Clone, Copy, Debug)]
struct Fold {
    first_ms: u64,
    last_ms: u64,
    attempts: u32,
    block_reason: &'static str,
}

#[derive(Default)]
struct Pending {
    rows: HashMap<FoldKey, Fold>,
    /// Per user, rows the full map turned away since the service started.
    skipped: HashMap<String, u64>,
}

/// Why a read or a write of the history failed.
#[derive(Debug)]
pub enum HistoryError {
    /// The history file could not be opened; nothing is kept.
    Unavailable,
    /// Days outside `1..=MAX_RETENTION_DAYS`.
    InvalidDays(u32),
    Storage(String),
}

impl std::fmt::Display for HistoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable => f.write_str("connection history is unavailable"),
            Self::InvalidDays(d) => write!(
                f,
                "retention of {d} days is outside 1..={MAX_RETENTION_DAYS}"
            ),
            Self::Storage(e) => write!(f, "connection history storage: {e}"),
        }
    }
}

/// What a reader asks for.
#[derive(Clone, Debug, Default)]
pub struct HistoryRead<'a> {
    /// `None` reads every user's history; no client read asks for it.
    pub principal: Option<&'a str>,
    pub from_ms: u64,
    pub to_ms: u64,
    pub program: Option<&'a str>,
    pub verdict: Option<&'a str>,
    pub offset: u32,
    pub limit: u32,
}

/// The per-user history and the one connection to its file.
pub struct ConnHistory {
    pending: Mutex<Pending>,
    prefs: RwLock<HashMap<String, ConnHistoryPrefs>>,
    store: Mutex<Option<SqliteConnHistoryStore>>,
    /// Where a damaged file is rebuilt; `None` keeps a damaged store closed.
    db_path: Option<PathBuf>,
    persist_prefs: Option<PersistPrefsFn>,
    max_bytes: u64,
    last_prune_ms: AtomicU64,
}

/// Whether a connection owner is a person the history is kept for.
fn is_person(owner: &str) -> bool {
    !owner.is_empty()
        && !crate::ipc_handlers::diagnostics_handlers::is_service_account(
            owner,
            crate::ipc_handlers::diagnostics_handlers::DEFAULT_UNIX_SYS_UID_MAX,
        )
}

/// `s` cut to at most [`MAX_FIELD_BYTES`] at a character boundary.
fn bounded(s: &str) -> String {
    if s.len() <= MAX_FIELD_BYTES {
        return s.to_owned();
    }
    let mut end = MAX_FIELD_BYTES;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_owned()
}

fn wire_i64(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

impl ConnHistory {
    /// A history over an already opened store. `db_path` is where a damaged
    /// file is rebuilt; without it a damaged store stays closed.
    pub fn new(store: Option<SqliteConnHistoryStore>, db_path: Option<PathBuf>) -> Self {
        Self {
            pending: Mutex::new(Pending::default()),
            prefs: RwLock::new(HashMap::new()),
            store: Mutex::new(store),
            db_path,
            persist_prefs: None,
            max_bytes: MAX_HISTORY_BYTES,
            last_prune_ms: AtomicU64::new(0),
        }
    }

    /// Opens `nrr_conn_history.db` at `path`, rebuilding a damaged file once.
    /// A file that cannot be opened leaves the history unavailable — said in
    /// the log and to every reader — and never stops the service.
    pub fn open(path: PathBuf) -> Self {
        let store = match nrr_storage::open_conn_history_connection_or_rebuild(&path) {
            Ok(opened) => {
                if let Some(reason) = &opened.rebuilt_reason {
                    tracing::warn!(
                        target: "nrr::conn-history",
                        msg_key = "conn-history-db-rebuilt",
                        reason = %reason,
                        "connection history file was damaged and has been created again",
                    );
                }
                Some(SqliteConnHistoryStore::new(opened.connection))
            }
            Err(e) => {
                tracing::warn!(
                    target: "nrr::conn-history",
                    msg_key = "conn-history-db-unavailable",
                    error = %e,
                    "connection history file cannot be opened; no history is kept",
                );
                None
            }
        };
        Self::new(store, Some(path))
    }

    /// Start from the choices users already made.
    #[must_use]
    pub fn with_prefs(self, prefs: Vec<(String, ConnHistoryPrefs)>) -> Self {
        if let Ok(mut map) = self.prefs.write() {
            map.extend(prefs);
        }
        self
    }

    /// Where a changed choice is stored. Without it a choice lasts until the
    /// service restarts.
    #[must_use]
    pub fn with_prefs_persist(mut self, persist: PersistPrefsFn) -> Self {
        self.persist_prefs = Some(persist);
        self
    }

    #[must_use]
    pub fn with_max_bytes(mut self, max_bytes: u64) -> Self {
        self.max_bytes = max_bytes;
        self
    }

    pub fn is_available(&self) -> bool {
        self.store.lock().map(|s| s.is_some()).unwrap_or(false)
    }

    /// `principal`'s choices, the defaults when they made none.
    pub fn prefs_for(&self, principal: &str) -> ConnHistoryPrefs {
        self.prefs
            .read()
            .ok()
            .and_then(|map| map.get(principal).copied())
            .unwrap_or_default()
    }

    /// Fold one trace row into its owner's hour. Cheap and never waits on
    /// the file: it takes the in-memory map only.
    pub fn record(&self, rec: &ConnectionTraceRecord, now_ms: u64) {
        let Some(owner) = rec.user_sid.as_deref().filter(|o| is_person(o)) else {
            return;
        };
        if !self.prefs_for(owner).enabled {
            return;
        }
        let at_ms = rec.observed_unix_ms.unwrap_or(now_ms);
        let key = FoldKey {
            principal: owner.to_owned(),
            hour: at_ms / HOUR_MS,
            program: rec.process_path.as_deref().map(bounded).unwrap_or_default(),
            host: rec
                .remote_names
                .as_ref()
                .and_then(|n| n.names.first())
                .map(|h| bounded(h))
                .unwrap_or_default(),
            remote_ip: rec.remote.ip(),
            route: role_str(rec.egress.role),
            verdict: verdict_str(rec.verdict),
            blocked_by: match rec.blocked_by_nrr {
                Some(true) => "netrulerouter",
                Some(false) => "other",
                None => "",
            },
        };
        let block_reason = rec.nrr_block_reason.unwrap_or_default();
        let mut pending = self.pending.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(fold) = pending.rows.get_mut(&key) {
            fold.first_ms = fold.first_ms.min(at_ms);
            fold.last_ms = fold.last_ms.max(at_ms);
            fold.attempts = fold.attempts.saturating_add(1);
            if !block_reason.is_empty() {
                fold.block_reason = block_reason;
            }
            return;
        }
        if pending.rows.len() >= MAX_PENDING_ROWS {
            *pending.skipped.entry(key.principal).or_default() += 1;
            return;
        }
        pending.rows.insert(
            key,
            Fold {
                first_ms: at_ms,
                last_ms: at_ms,
                attempts: 1,
                block_reason,
            },
        );
    }

    /// Write what was folded since the last flush, then — at most every few
    /// minutes — expire old hours and hold the file to its cap. Runs on the
    /// flush task's thread, or on a reader's before it reads.
    pub fn flush(&self, now_ms: u64) {
        self.write(Some(now_ms));
    }

    /// Write what was folded and nothing more: the last minute, at stop, when
    /// expiry and the cap can wait for the next start.
    pub fn flush_pending(&self) {
        self.write(None);
    }

    /// `prune_at` is the clock a due prune runs against; `None` never prunes.
    fn write(&self, prune_at: Option<u64>) {
        let rows: Vec<ConnHistoryRow> = {
            let mut pending = self.pending.lock().unwrap_or_else(|p| p.into_inner());
            std::mem::take(&mut pending.rows)
                .into_iter()
                .map(|(k, f)| ConnHistoryRow {
                    principal: k.principal,
                    hour: wire_i64(k.hour),
                    program: k.program,
                    host: k.host,
                    remote_ip: k.remote_ip.to_string(),
                    route: k.route.to_owned(),
                    verdict: k.verdict.to_owned(),
                    blocked_by: k.blocked_by.to_owned(),
                    first_ms: wire_i64(f.first_ms),
                    last_ms: wire_i64(f.last_ms),
                    attempts: f.attempts,
                    block_reason: f.block_reason.to_owned(),
                })
                .collect()
        };
        let mut guard = self.store.lock().unwrap_or_else(|p| p.into_inner());
        let Some(store) = guard.as_ref() else {
            return;
        };
        let mut outcome = store.upsert(&rows);
        let due = prune_at.filter(|now_ms| {
            now_ms.saturating_sub(self.last_prune_ms.load(Ordering::Relaxed)) >= PRUNE_INTERVAL_MS
        });
        if let (true, Some(now_ms)) = (outcome.is_ok(), due) {
            self.last_prune_ms.store(now_ms, Ordering::Relaxed);
            outcome = self.prune(store, now_ms);
        }
        if let Err(e) = outcome {
            self.on_store_error(&mut guard, e, rows.len());
        }
    }

    fn prune(&self, store: &SqliteConnHistoryStore, now_ms: u64) -> Result<(), StorageError> {
        let prefs = self
            .prefs
            .read()
            .map(|m| HashMap::clone(&m))
            .unwrap_or_default();
        let cutoff = |principal: &str| -> i64 {
            let days = prefs
                .get(principal)
                .map_or(DEFAULT_RETENTION_DAYS, |p| p.retention_days);
            wire_i64(now_ms.saturating_sub(u64::from(days) * DAY_MS) / HOUR_MS)
        };
        store.expire(cutoff)?;
        let removed = store.enforce_cap(self.max_bytes)?;
        if removed > 0 {
            tracing::info!(
                target: "nrr::conn-history",
                msg_key = "conn-history-cap-removed",
                removed,
                "connection history reached its size limit; the oldest hours were removed",
            );
        }
        // A refused checkpoint only leaves the journal for the next pass.
        let _ = store.checkpoint_wal();
        Ok(())
    }

    /// A damaged file is created again empty; any other failure loses this
    /// flush only. Either way the service carries on.
    fn on_store_error(
        &self,
        guard: &mut std::sync::MutexGuard<'_, Option<SqliteConnHistoryStore>>,
        e: StorageError,
        lost_rows: usize,
    ) {
        if !matches!(e, StorageError::CorruptCache(_)) {
            tracing::warn!(
                target: "nrr::conn-history",
                msg_key = "conn-history-write-failed",
                error = %e,
                lost_rows,
                "connection history could not be written; this minute is lost",
            );
            return;
        }
        // Dropped before the delete: Windows refuses to delete an open file.
        **guard = None;
        let Some(path) = self.db_path.as_ref() else {
            return;
        };
        match nrr_storage::rebuild_conn_history_db(path, &e.to_string()) {
            Ok(opened) => {
                tracing::warn!(
                    target: "nrr::conn-history",
                    msg_key = "conn-history-db-rebuilt",
                    reason = %e,
                    "connection history file was damaged and has been created again",
                );
                **guard = Some(SqliteConnHistoryStore::new(opened.connection));
            }
            Err(rebuild) => tracing::warn!(
                target: "nrr::conn-history",
                msg_key = "conn-history-db-unavailable",
                error = %rebuild,
                "connection history file cannot be opened; no history is kept",
            ),
        }
    }

    /// The asked period, newest first, with what the cap removed and what
    /// the full map turned away for the same audience. Flushes first, so the
    /// last minute is in the answer.
    pub fn read(
        &self,
        q: &HistoryRead<'_>,
        now_ms: u64,
    ) -> Result<(Vec<ConnHistoryEntry>, u64, u64), HistoryError> {
        self.flush(now_ms);
        let skipped = {
            let pending = self.pending.lock().unwrap_or_else(|p| p.into_inner());
            match q.principal {
                Some(p) => pending.skipped.get(p).copied().unwrap_or(0),
                None => pending.skipped.values().sum(),
            }
        };
        let guard = self.store.lock().unwrap_or_else(|p| p.into_inner());
        let store = guard.as_ref().ok_or(HistoryError::Unavailable)?;
        let storage = |e: StorageError| HistoryError::Storage(e.to_string());
        let rows = store
            .list(&ConnHistoryQuery {
                principal: q.principal,
                from_ms: wire_i64(q.from_ms),
                to_ms: wire_i64(q.to_ms),
                program: q.program,
                verdict: q.verdict,
                offset: q.offset,
                limit: q.limit,
            })
            .map_err(storage)?;
        let removed = store.removed_for(q.principal).map_err(storage)?;
        Ok((rows, removed, skipped))
    }

    /// Erase `principal`'s history: what is waiting to be written, what the
    /// file holds and what was counted against it. Returns rows erased.
    pub fn clear(&self, principal: &str) -> Result<u64, HistoryError> {
        let waiting = {
            let mut pending = self.pending.lock().unwrap_or_else(|p| p.into_inner());
            let before = pending.rows.len();
            pending.rows.retain(|k, _| k.principal != principal);
            pending.skipped.remove(principal);
            (before - pending.rows.len()) as u64
        };
        let guard = self.store.lock().unwrap_or_else(|p| p.into_inner());
        let store = guard.as_ref().ok_or(HistoryError::Unavailable)?;
        let erased = store
            .clear_principal(principal)
            .map_err(|e| HistoryError::Storage(e.to_string()))?;
        // The journal still holds the erased pages until it is folded in.
        let _ = store.checkpoint_wal();
        Ok(erased.saturating_add(waiting))
    }

    /// Full reset of one user: their choices go back to the defaults (the
    /// stored row is the state DB's to erase) and their history is erased.
    /// The choices are dropped even when the file cannot be reached.
    pub fn forget(&self, principal: &str) -> Result<u64, HistoryError> {
        if let Ok(mut map) = self.prefs.write() {
            map.remove(principal);
        }
        self.clear(principal)
    }

    /// Full reset of the whole machine: every user's choices and history.
    pub fn forget_all(&self) -> Result<u64, HistoryError> {
        if let Ok(mut map) = self.prefs.write() {
            map.clear();
        }
        {
            let mut pending = self.pending.lock().unwrap_or_else(|p| p.into_inner());
            pending.rows.clear();
            pending.skipped.clear();
        }
        let guard = self.store.lock().unwrap_or_else(|p| p.into_inner());
        let store = guard.as_ref().ok_or(HistoryError::Unavailable)?;
        let erased = store
            .clear_all()
            .map_err(|e| HistoryError::Storage(e.to_string()))?;
        let _ = store.checkpoint_wal();
        Ok(erased)
    }

    /// Change `principal`'s choices; an absent value keeps its current one.
    /// Stored before it takes effect, so a choice the service could not keep
    /// is refused rather than silently forgotten at the next start. Switching
    /// off stops recording at once; what is kept stays until cleared.
    pub fn set_prefs(
        &self,
        principal: &str,
        enabled: Option<bool>,
        retention_days: Option<u32>,
    ) -> Result<ConnHistoryPrefs, HistoryError> {
        if let Some(days) = retention_days {
            if !(1..=MAX_RETENTION_DAYS).contains(&days) {
                return Err(HistoryError::InvalidDays(days));
            }
        }
        let current = self.prefs_for(principal);
        let next = ConnHistoryPrefs {
            enabled: enabled.unwrap_or(current.enabled),
            retention_days: retention_days.unwrap_or(current.retention_days),
        };
        if let Some(persist) = self.persist_prefs.as_ref() {
            persist(principal, next).map_err(HistoryError::Storage)?;
        }
        if let Ok(mut map) = self.prefs.write() {
            map.insert(principal.to_owned(), next);
        }
        if !next.enabled {
            let mut pending = self.pending.lock().unwrap_or_else(|p| p.into_inner());
            pending.rows.retain(|k, _| k.principal != principal);
        }
        Ok(next)
    }
}

/// The history as the service runs it: the file at `path`, each user's
/// choices read from and stored in the state DB. Choices that cannot be read
/// keep the history closed — recording someone who switched it off is worse
/// than recording nobody — and a choice that cannot be stored is refused.
pub fn open_for_service(
    path: PathBuf,
    state: Option<Arc<Mutex<rusqlite::Connection>>>,
) -> Arc<ConnHistory> {
    use nrr_storage::ConnHistoryPrefsRepository;

    let Some(state) = state else {
        return Arc::new(ConnHistory::open(path).with_prefs_persist(Arc::new(|_, _| {
            Err("no service state database to keep the choice in".to_string())
        })));
    };
    let prefs = {
        let conn = state.lock().unwrap_or_else(|p| p.into_inner());
        ConnHistoryPrefsRepository::new(&conn).list()
    };
    let prefs = match prefs {
        Ok(prefs) => prefs,
        Err(e) => {
            tracing::warn!(
                target: "nrr::conn-history",
                msg_key = "conn-history-prefs-unreadable",
                error = %e,
                "connection history choices cannot be read; no history is kept",
            );
            return Arc::new(ConnHistory::new(None, None));
        }
    };
    let persist: PersistPrefsFn = Arc::new(move |sid, prefs| {
        let conn = state.lock().unwrap_or_else(|p| p.into_inner());
        ConnHistoryPrefsRepository::new(&conn)
            .set(
                sid,
                prefs,
                wire_i64(crate::conn_observation_consumer::now_unix_ms()),
            )
            .map_err(|e| e.to_string())
    });
    Arc::new(
        ConnHistory::open(path)
            .with_prefs(prefs)
            .with_prefs_persist(persist),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_platform_api::conn_observe::egress::{EgressInterface, EgressRole};
    use nrr_platform_api::conn_observe::{ConnectionVerdict, TransportProtocol};
    use std::net::{Ipv4Addr, SocketAddr};

    const ALICE: &str = "S-1-5-21-1-2-3-1001";
    const BOB: &str = "S-1-5-21-1-2-3-1002";
    const T0: u64 = 1_700_000_000_000;

    fn history() -> (tempfile::TempDir, ConnHistory) {
        let dir = tempfile::tempdir().expect("temp dir");
        let history = ConnHistory::open(dir.path().join("nrr_conn_history.db"));
        assert!(history.is_available());
        (dir, history)
    }

    fn rec(
        owner: Option<&str>,
        program: &str,
        last_octet: u8,
        at_ms: u64,
    ) -> ConnectionTraceRecord {
        ConnectionTraceRecord {
            process_path: Some(program.to_owned()),
            user_sid: owner.map(str::to_owned),
            protocol: TransportProtocol::Tcp,
            local: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 5)), 50_000),
            remote: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, last_octet)), 443),
            egress: EgressInterface {
                ifindex: 2,
                role: EgressRole::Primary,
            },
            verdict: ConnectionVerdict::Permit,
            blocked_by_nrr: None,
            nrr_drop_spec_id: None,
            nrr_block_reason: None,
            observed_unix_ms: Some(at_ms),
            remote_names: None,
        }
    }

    fn mine<'a>(principal: &'a str) -> HistoryRead<'a> {
        HistoryRead {
            principal: Some(principal),
            from_ms: 0,
            to_ms: T0 * 2,
            limit: 100,
            ..HistoryRead::default()
        }
    }

    #[test]
    fn repeats_fold_per_hour_and_survive_a_reopen() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("nrr_conn_history.db");
        {
            let h = ConnHistory::open(path.clone());
            for n in 0..5 {
                h.record(&rec(Some(ALICE), r"C:\Apps\browser.exe", 10, T0 + n), T0);
            }
            h.record(
                &rec(Some(ALICE), r"C:\Apps\browser.exe", 10, T0 + HOUR_MS),
                T0,
            );
            h.flush(T0 + HOUR_MS);
        }
        let reopened = ConnHistory::open(path);
        let (rows, removed, skipped) = reopened.read(&mine(ALICE), T0).expect("read");
        assert_eq!(rows.len(), 1, "one destination of one program");
        assert_eq!(
            rows[0].attempts, 6,
            "five in the first hour, one in the next"
        );
        assert_eq!(rows[0].first_ms, T0 as i64);
        assert_eq!(rows[0].last_ms, (T0 + HOUR_MS) as i64);
        assert_eq!((removed, skipped), (0, 0));
    }

    #[test]
    fn another_users_history_is_not_theirs_to_read_or_clear() {
        let (_dir, h) = history();
        h.record(&rec(Some(ALICE), "alice.exe", 1, T0), T0);
        h.record(&rec(Some(BOB), "bob.exe", 2, T0), T0);
        let (alice, _, _) = h.read(&mine(ALICE), T0).expect("alice");
        assert_eq!(alice.len(), 1);
        assert_eq!(alice[0].program, "alice.exe");
        let machine = HistoryRead {
            principal: None,
            ..mine(ALICE)
        };
        assert_eq!(h.read(&machine, T0).expect("admin").0.len(), 2);

        assert_eq!(h.clear(ALICE).expect("clear"), 1);
        assert!(h.read(&mine(ALICE), T0).expect("alice").0.is_empty());
        assert_eq!(h.read(&mine(BOB), T0).expect("bob").0.len(), 1);
    }

    #[test]
    fn service_accounts_and_unowned_connections_have_no_history() {
        let (_dir, h) = history();
        for owner in [
            None,
            Some(""),
            Some("S-1-5-18"),
            Some("S-1-5-80-1-2"),
            Some("unix:uid:0"),
        ] {
            h.record(&rec(owner, "svc.exe", 1, T0), T0);
        }
        let machine = HistoryRead {
            principal: None,
            ..mine(ALICE)
        };
        assert!(h.read(&machine, T0).expect("read").0.is_empty());
        h.record(&rec(Some("unix:uid:1000"), "/usr/bin/app", 1, T0), T0);
        assert_eq!(
            h.read(&machine, T0).expect("read").0.len(),
            1,
            "a person on Linux"
        );
    }

    #[test]
    fn switched_off_stops_recording_and_keeps_what_was_kept() {
        let (_dir, h) = history();
        h.record(&rec(Some(ALICE), "kept.exe", 1, T0), T0);
        h.flush(T0);
        h.record(&rec(Some(ALICE), "waiting.exe", 2, T0), T0);
        let off = h.set_prefs(ALICE, Some(false), None).expect("off");
        assert!(!off.enabled);
        assert_eq!(off.retention_days, DEFAULT_RETENTION_DAYS);
        h.record(&rec(Some(ALICE), "after.exe", 3, T0), T0);
        let (rows, _, _) = h.read(&mine(ALICE), T0).expect("read");
        let programs: Vec<&str> = rows.iter().map(|r| r.program.as_str()).collect();
        assert_eq!(programs, ["kept.exe"], "nothing recorded once off");
        assert!(h.set_prefs(ALICE, None, Some(0)).is_err());
        assert!(h
            .set_prefs(ALICE, None, Some(MAX_RETENTION_DAYS + 1))
            .is_err());
    }

    #[test]
    fn a_choice_that_cannot_be_stored_is_refused() {
        let (_dir, h) = history();
        let h = h.with_prefs_persist(Arc::new(|_, _| Err("state db busy".into())));
        assert!(h.set_prefs(ALICE, Some(false), None).is_err());
        assert!(h.prefs_for(ALICE).enabled, "the old choice stands");
    }

    #[test]
    fn expiry_follows_each_users_period() {
        let (_dir, h) = history();
        let h = h.with_prefs(vec![(
            ALICE.to_owned(),
            ConnHistoryPrefs {
                enabled: true,
                retention_days: 1,
            },
        )]);
        let old = T0 - 3 * DAY_MS;
        h.record(&rec(Some(ALICE), "a.exe", 1, old), old);
        h.record(&rec(Some(BOB), "b.exe", 2, old), old);
        h.record(&rec(Some(ALICE), "a.exe", 3, T0), T0);
        h.flush(T0);
        let alice = h.read(&mine(ALICE), T0).expect("alice").0;
        assert_eq!(alice.len(), 1, "a day kept, three days old is gone");
        assert_eq!(
            h.read(&mine(BOB), T0).expect("bob").0.len(),
            1,
            "the default week keeps three days"
        );
    }

    #[test]
    fn the_cap_removes_old_hours_and_says_so() {
        let (_dir, h) = history();
        let h = h.with_max_bytes(64 * 1024);
        for hour in 0..48u64 {
            for n in 0..40u8 {
                let at = T0 + hour * HOUR_MS;
                h.record(&rec(Some(ALICE), &format!("program-{n}.exe"), n, at), at);
            }
            h.flush(T0 + hour * HOUR_MS);
        }
        h.flush(T0 + 49 * HOUR_MS + PRUNE_INTERVAL_MS);
        let (rows, removed, _) = h.read(&mine(ALICE), T0).expect("read");
        assert!(removed > 0, "the reader is told what went");
        assert!(
            rows.iter().all(|r| r.first_ms > T0 as i64),
            "oldest hours first"
        );
    }

    #[test]
    fn a_full_map_skips_and_counts_instead_of_growing() {
        let (_dir, h) = history();
        for n in 0..=MAX_PENDING_ROWS {
            let at = T0 + n as u64;
            let mut r = rec(Some(ALICE), "app.exe", 1, at);
            r.remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::from(0x0A00_0000 + n as u32)), 443);
            h.record(&r, at);
        }
        let (_, _, skipped) = h.read(&mine(ALICE), T0).expect("read");
        assert_eq!(skipped, 1);
    }

    #[test]
    fn long_names_are_cut_at_a_character_boundary() {
        // One ASCII byte first, so the limit falls inside a two-byte character.
        let long = format!("a{}", "\u{0434}".repeat(MAX_FIELD_BYTES));
        let cut = bounded(&long);
        assert!(cut.len() <= MAX_FIELD_BYTES);
        assert!(long.starts_with(&cut));
    }

    #[test]
    fn a_damaged_file_is_created_again_and_the_service_carries_on() {
        let (dir, h) = history();
        h.record(&rec(Some(ALICE), "a.exe", 1, T0), T0);
        h.flush(T0);
        {
            let mut guard = h.store.lock().expect("store");
            guard.take();
        }
        std::fs::write(dir.path().join("nrr_conn_history.db"), b"not a database").expect("damage");
        let mut guard = h.store.lock().expect("store");
        h.on_store_error(&mut guard, StorageError::CorruptCache("damaged".into()), 0);
        assert!(guard.is_some(), "rebuilt and open again");
        drop(guard);
        h.record(&rec(Some(ALICE), "b.exe", 2, T0), T0);
        let (rows, _, _) = h.read(&mine(ALICE), T0).expect("read");
        assert_eq!(rows.len(), 1, "only what came after the rebuild");
    }

    #[test]
    fn a_full_reset_erases_the_users_history_and_resets_their_choices() {
        let (_dir, h) = history();
        h.set_prefs(ALICE, Some(true), Some(2)).expect("choose");
        h.record(&rec(Some(ALICE), "a.exe", 1, T0), T0);
        h.flush(T0);
        h.record(&rec(Some(ALICE), "b.exe", 2, T0), T0);
        h.record(&rec(Some(BOB), "c.exe", 3, T0), T0);
        assert_eq!(
            h.forget(ALICE).expect("forget"),
            2,
            "kept and waiting alike"
        );
        assert!(h.read(&mine(ALICE), T0).expect("alice").0.is_empty());
        assert_eq!(h.prefs_for(ALICE), ConnHistoryPrefs::default());
        assert_eq!(h.read(&mine(BOB), T0).expect("bob").0.len(), 1);

        h.set_prefs(BOB, Some(false), None).expect("off");
        h.forget_all().expect("forget all");
        assert!(h.read(&mine(BOB), T0).expect("bob").0.is_empty());
        assert!(h.prefs_for(BOB).enabled, "back to the default");
    }

    #[test]
    fn a_reset_without_the_file_still_drops_the_choices() {
        let h = ConnHistory::new(None, None);
        h.set_prefs(ALICE, Some(false), None).expect("off");
        assert!(matches!(h.forget(ALICE), Err(HistoryError::Unavailable)));
        assert!(h.prefs_for(ALICE).enabled);
    }

    #[test]
    fn the_last_minute_is_written_at_stop_without_pruning() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("nrr_conn_history.db");
        let h = ConnHistory::open(path.clone());
        h.record(&rec(Some(ALICE), "a.exe", 1, T0), T0);
        h.flush_pending();
        assert_eq!(
            h.last_prune_ms.load(Ordering::Relaxed),
            0,
            "no prune at stop"
        );
        let other = ConnHistory::open(path);
        assert_eq!(other.read(&mine(ALICE), T0).expect("read").0.len(), 1);
    }

    #[test]
    fn an_unopenable_file_leaves_the_history_unavailable() {
        let h = ConnHistory::new(None, None);
        h.record(&rec(Some(ALICE), "a.exe", 1, T0), T0);
        h.flush(T0);
        assert!(!h.is_available());
        assert!(matches!(
            h.read(&mine(ALICE), T0),
            Err(HistoryError::Unavailable)
        ));
    }
}
