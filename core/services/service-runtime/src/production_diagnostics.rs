//! Production [`DiagnosticsFacade`] implementation.
//!
//! Composes the existing `nrr-diagnostics` primitives (`LogReader`,
//! `AuditReader`, `SecurityAlertsRepository`) and `nrr-storage`
//! cache stats into the wire-shaped DTOs the GUI's Diagnostics
//! section consumes. Replaces the long-standing
//! [`MockDiagnosticsFacade::healthy()`](nrr_diagnostics::facade::mock::MockDiagnosticsFacade)
//! placeholder in `runtime_deps.rs:316`.
//!
//! # Method map
//!
//! | Trait method            | Source(s)                                                          |
//! |-------------------------|--------------------------------------------------------------------|
//! | `get_status`            | `AuditReader` (chain), alerts repo (count), `SqliteCacheStore`     |
//! |                         | (entry count + `last_rebuild_at`), `LogReader` (size+count),       |
//! |                         | `RevisionsRepository` (active + pending), diagnostic-session state |
//! | `list_log_entries`      | `LogReader::scan(filter)` + in-memory cursor pagination            |
//! | `list_audit_entries`    | `AuditReader::scan(filter)` + in-memory cursor pagination          |
//! | `list_active_alerts`    | `SecurityAlertsRepository::list_open`                              |
//! | `acknowledge_alert`     | Returns `RecoveryAction` — canonical path is                       |
//! |                         | `MutationKind::SecurityAlertAck` via the mutation queue (16.10).   |
//! |                         | This method is deliberately a non-mutating sentinel so the wire    |
//! |                         | invariant "single writer = MutationDispatcher" holds.              |
//! | `set_diagnostic_mode`   | Mutates internal [`DiagnosticSessionHandle`] (Arc<Mutex<...>>)     |
//! | `clear_logs`            | Walks `LogReader::list_files`, deletes each (`dry_run` skips)      |
//! | `get_explain`           | `Synthetic` runs the REAL rule engine (`match_sample`) against the |
//! |                         | caller's per-SID active rule book + behavior mode and returns a    |
//! |                         | real route/reason (`Available`). `Historical` (by decision id)     |
//! |                         | returns `DecisionNotFound` until the explain snapshot write-side   |
//! |                         | is wired — there is no UI consumer of the historical path today.   |
//!
//! # Threading
//!
//! All methods are `&self` synchronous. The facade is `Send + Sync` so
//! the IPC handler can hold an `Arc<dyn DiagnosticsFacade>` across
//! threads. Internal state (`DiagnosticSessionHandle`) uses
//! `Arc<Mutex<...>>` for interior mutability.
//!
//! # Pagination semantics
//!
//! Both `list_log_entries` and `list_audit_entries` scan the full
//! NDJSON tree, filter in-memory, then slice the matching events by
//! cursor. The cursor encodes `(created_at_ms, event_id)` of the last
//! item returned. Future blocks may add SQLite-indexed log storage —
//! the trait surface won't change.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use rusqlite::{Connection, OptionalExtension};

use nrr_diagnostics::audit::alert::{SecurityAlert, SecurityAlertsRepository};
use nrr_diagnostics::audit::anchor::AuditChainAnchorStore;
use nrr_diagnostics::audit::reader::{AuditQueryFilter, AuditReader};
use nrr_diagnostics::error::{DiagnosticsError, DiagnosticsResult};
use nrr_diagnostics::event::{AuditEvent, LogEvent};
use nrr_diagnostics::explain::{ExplainDataAvailability, ExplainQuery, ExplainResponse};
use nrr_diagnostics::facade::dto::{
    AcknowledgeAlertRequest, AuditEntryDto, AuditEntryFilter, CacheHealthCard, ClearLogsRequest,
    ClearLogsResult, DiagnosticModeStateDto, DiagnosticsAudience, DiagnosticsDataOrigin,
    DiagnosticsStatusDto, LogEntryDto, LogEntryFilter, LogHealthCard, SecurityAlertDto,
    SecurityStatusCard, ServiceHealthCard, SetDiagnosticModeRequest,
};
use nrr_diagnostics::facade::pagination::{PageCursor, PageResult, PaginationParams};
use nrr_diagnostics::facade::service::DiagnosticsFacade;
use nrr_diagnostics::logs::reader::{LogQueryFilter, LogReader};
use nrr_diagnostics::privacy::redact::redact_hostname;
use nrr_diagnostics::privacy::{DiagnosticSession, DiagnosticSessionScope, RedactionMode};
use nrr_diagnostics::redaction::ExplainDetailLevel;
use nrr_diagnostics::retention::health::is_dir_writable;
use nrr_diagnostics::taxonomy::{EventCategory, EventLevel};

// ── DiagnosticSessionHandle ──────────────────────────────────────────────────

/// Shared, mutable holder for the active [`DiagnosticSession`] (if
/// any). Owned by [`ProductionDiagnosticsFacade`] but exposed as a
/// distinct type so other components (the redaction-aware log
/// projector, the explain handler) can read the current redaction
/// mode via `Arc::clone`.
#[derive(Clone, Default)]
pub struct DiagnosticSessionHandle {
    inner: Arc<Mutex<Option<DiagnosticSession>>>,
}

impl DiagnosticSessionHandle {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the current session if it's still active at `now_ms`.
    /// Returns `None` for missing or expired sessions; expired ones
    /// are NOT auto-evicted from the holder (the GUI may still want
    /// to display the recent expiration timestamp).
    pub fn current(&self, now_ms: i64) -> Option<DiagnosticSession> {
        let guard = self.inner.lock().ok()?;
        guard.as_ref().filter(|s| s.is_active(now_ms)).cloned()
    }

    /// Effective redaction mode at `now_ms`. Defaults to
    /// [`RedactionMode::Default`] when no session is active.
    pub fn redaction_mode(&self, now_ms: i64) -> RedactionMode {
        self.current(now_ms)
            .map(|s| s.redaction_mode())
            .unwrap_or(RedactionMode::Default)
    }

    fn store(&self, session: Option<DiagnosticSession>) {
        if let Ok(mut g) = self.inner.lock() {
            *g = session;
        }
    }
}

// ── ProductionDiagnosticsFacade ──────────────────────────────────────────────

/// Production wiring of the [`DiagnosticsFacade`] trait.
///
/// Both `state_conn` and `cache_conn` are `Option` because the
/// service can boot in degraded mode without either DB open (recovery
/// path). In that case the facade returns conservative defaults
/// (0 entries, no active revision, healthy = false where applicable).
pub struct ProductionDiagnosticsFacade {
    logs_dir: PathBuf,
    audit_dir: PathBuf,
    /// Shared lock on the FQDN/IP cache SQLite connection. Used for
    /// `cache_metadata.last_rebuild_at` and resolution-row counts.
    /// `None` when the cache DB is unavailable (corrupt + rebuild
    /// pending, or fresh service install before bootstrap).
    cache_conn: Option<Arc<Mutex<Connection>>>,
    alerts_repo: Arc<dyn SecurityAlertsRepository>,
    /// Shared lock on the service-state SQLite connection. Used for
    /// reading the active revision id + pending revisions count from
    /// `RevisionsRepository`. `None` when storage is degraded.
    state_conn: Option<Arc<Mutex<Connection>>>,
    diagnostic_session: DiagnosticSessionHandle,
    /// The operational log writer, when one is installed. Its drop counter is
    /// the only place that knows an event was lost, and `None` here is what a
    /// caller with no writer looks like — not "nothing was dropped".
    log_writer: Option<Arc<nrr_diagnostics::LogWriter>>,
    /// Last chain verification, keyed by the newest audit file's
    /// (path, length, mtime). The GUI polls `get_status` on a timer and each
    /// call re-read the whole current audit file and re-hashed every line;
    /// nothing about that answer changes until the file grows.
    chain_cache: Mutex<Option<(ChainCacheKey, bool)>>,
    /// The host's operator log, read for one fact: when this boot reached the
    /// sign-in phase. `None` on a host with no such record, which the card
    /// reports as "cannot tell".
    system_event_log: Option<Arc<dyn nrr_platform_api::system_event_log::SystemEventLogPort>>,
    /// When THIS service process started, Unix ms. Half of the comparison; the
    /// other half comes from the OS log.
    started_at_ms: Option<u64>,
}

type ChainCacheKey = (PathBuf, u64, Option<std::time::SystemTime>);

impl ProductionDiagnosticsFacade {
    /// Whether the audit trail is intact, recomputed only when the newest
    /// audit file has changed.
    ///
    /// `chain_ok` alone answers "was anything edited"; the anchor is what
    /// answers "is anything missing", and a cut tail passes the first check.
    fn audit_chain_ok(&self, reader: &AuditReader) -> bool {
        let newest = reader.list_files().pop();
        let key: Option<ChainCacheKey> = newest.map(|path| {
            let meta = std::fs::metadata(&path).ok();
            let len = meta.as_ref().map(|m| m.len()).unwrap_or(0);
            let modified = meta.and_then(|m| m.modified().ok());
            (path, len, modified)
        });

        // A poisoned lock only means a prior panic while holding it; the cache
        // is an optimisation, so take the value and carry on.
        let mut cache = match self.chain_cache.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let (Some(key), Some((cached_key, cached))) = (key.as_ref(), cache.as_ref()) {
            if cached_key == key {
                return *cached;
            }
        }

        let anchor = nrr_diagnostics::FileAnchorStore::in_dir(&self.audit_dir).load();
        let chain = reader.verify_latest_chain_anchored(anchor.as_ref());
        let ok = chain.chain_ok && chain.corrupt_lines == 0;
        *cache = key.map(|key| (key, ok));
        ok
    }

    pub fn new(
        logs_dir: impl Into<PathBuf>,
        audit_dir: impl Into<PathBuf>,
        cache_conn: Option<Arc<Mutex<Connection>>>,
        alerts_repo: Arc<dyn SecurityAlertsRepository>,
        state_conn: Option<Arc<Mutex<Connection>>>,
    ) -> Self {
        Self {
            logs_dir: logs_dir.into(),
            audit_dir: audit_dir.into(),
            cache_conn,
            alerts_repo,
            state_conn,
            diagnostic_session: DiagnosticSessionHandle::new(),
            log_writer: None,
            chain_cache: Mutex::new(None),
            system_event_log: None,
            started_at_ms: None,
        }
    }

    /// Attach the host log and this process's start moment, so the card can
    /// answer "did the service delay the boot" with a measurement.
    ///
    /// Both or neither: a start time with no log to compare it against is not
    /// an answer, and the card would have to invent one.
    pub fn with_boot_timing(
        mut self,
        system_event_log: Arc<dyn nrr_platform_api::system_event_log::SystemEventLogPort>,
        started_at_ms: u64,
    ) -> Self {
        self.system_event_log = Some(system_event_log);
        self.started_at_ms = Some(started_at_ms);
        self
    }

    /// Where this service's start sits relative to the boot's sign-in phase.
    fn start_relative_to_sign_in(&self) -> nrr_domain::boot_timing::ServiceStartRelativeToSignIn {
        let prompt = self
            .system_event_log
            .as_ref()
            .and_then(|log| log.sign_in_prompt_at_ms());
        nrr_domain::boot_timing::service_start_relative_to_sign_in(prompt, self.started_at_ms)
    }

    /// Attach the installed log writer so the health card can report events
    /// the service actually lost.
    pub fn with_log_writer(mut self, writer: Option<Arc<nrr_diagnostics::LogWriter>>) -> Self {
        self.log_writer = writer;
        self
    }

    /// Hand a clone of the shared diagnostic-session handle to other
    /// components (explain projector, log redactor). Cheap clone.
    pub fn diagnostic_session_handle(&self) -> DiagnosticSessionHandle {
        self.diagnostic_session.clone()
    }
}

mod facade_impl;
mod internals;
use internals::*;
mod mapping;
use mapping::*;
// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
