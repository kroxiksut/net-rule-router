//! Production [`DiagnosticsFacade`] implementation.
//!
//! Composes the existing `nrr-diagnostics` primitives (`LogReader`,
//! `AuditReader`, `SecurityAlertsRepository`) and `nrr-storage`
//! cache stats into the wire-shaped DTOs the GUI's Diagnostics
//! section consumes.
//!
//! # Method map
//!
//! | Trait method            | Source(s)                                                          |
//! |-------------------------|--------------------------------------------------------------------|
//! | `get_status`            | `AuditReader` (chain), alerts repo (count), `SqliteCacheStore`     |
//! |                         | (entry count + `last_rebuild_at`), `LogReader` (size+count),       |
//! |                         | `RevisionsRepository` (active + pending)                           |
//! | `list_log_entries`      | `LogReader::page_newest_first` over a per-file time-span index     |
//! | `list_audit_entries`    | `AuditReader::scan(filter)` + in-memory cursor pagination          |
//! | `list_alerts`           | alerts repo, scoped by `alert_audience`                            |
//! | `acknowledge_alert`     | Returns `RecoveryAction` — canonical path is                       |
//! |                         | `MutationKind::SecurityAlertAck` via the mutation queue.           |
//! |                         | This method is deliberately a non-mutating sentinel so the wire    |
//! |                         | invariant "single writer = MutationDispatcher" holds.              |
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
//! threads.
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

use rusqlite::{Connection, OptionalExtension};

use nrr_diagnostics::audit::alert::{SecurityAlert, SecurityAlertState, SecurityAlertsRepository};
use nrr_diagnostics::audit::anchor::AuditChainAnchorStore;
use nrr_diagnostics::audit::reader::{AuditQueryFilter, AuditReader};
use nrr_diagnostics::error::{DiagnosticsError, DiagnosticsResult};
use nrr_diagnostics::event::{AuditEvent, LogEvent};
use nrr_diagnostics::explain::{ExplainDataAvailability, ExplainQuery, ExplainResponse};
use nrr_diagnostics::facade::dto::{
    AcknowledgeAlertRequest, AuditEntryDto, AuditEntryFilter, CacheHealthCard, ClearLogsRequest,
    ClearLogsResult, DiagnosticsAudience, DiagnosticsDataOrigin, DiagnosticsStatusDto, LogEntryDto,
    LogEntryFilter, LogHealthCard, SecurityAlertDto, SecurityStatusCard, ServiceHealthCard,
};
use nrr_diagnostics::facade::pagination::{PageCursor, PageResult, PaginationParams};
use nrr_diagnostics::facade::service::{AlertListFilter, DiagnosticsFacade};
use nrr_diagnostics::logs::reader::{LogFileIndex, LogPage, LogQueryFilter, LogReader};
use nrr_diagnostics::privacy::redact::redact_hostname;
use nrr_diagnostics::privacy::RedactionMode;
use nrr_diagnostics::redaction::ExplainDetailLevel;
use nrr_diagnostics::retention::health::is_dir_writable;
use nrr_diagnostics::taxonomy::{EventCategory, EventLevel};

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
    /// The operational log writer, when one is installed. Its drop counter is
    /// the only place that knows an event was lost, and `None` here is what a
    /// caller with no writer looks like — not "nothing was dropped".
    log_writer: Option<Arc<nrr_diagnostics::LogWriter>>,
    /// Time span of each log file, so a "Logs" page parses only the files it
    /// draws from instead of the whole retention window.
    log_index: LogFileIndex,
    /// Whole-chain verification, re-parsing only the audit files whose bytes
    /// changed: every `get_status` asks, and the answer moves only with them.
    chain_verifier: Mutex<nrr_diagnostics::AuditChainVerifier>,
    /// The host's operator log, read for one fact: when this boot reached the
    /// sign-in phase. `None` on a host with no such record, which the card
    /// reports as "cannot tell".
    system_event_log: Option<Arc<dyn nrr_platform_api::system_event_log::SystemEventLogPort>>,
    /// When THIS service process started, Unix ms. Half of the comparison; the
    /// other half comes from the OS log.
    started_at_ms: Option<u64>,
}

impl ProductionDiagnosticsFacade {
    /// Whether the audit trail in the retention window is intact.
    ///
    /// `chain_ok` alone answers "was anything edited"; the anchor is what
    /// answers "is anything missing", and a cut tail passes the first check.
    fn audit_chain_ok(&self, reader: &AuditReader) -> bool {
        let anchor = nrr_diagnostics::FileAnchorStore::in_dir(&self.audit_dir).load();
        // A poisoned lock only means a prior panic while holding it; the
        // verifier's cache is an optimisation, so carry on with it.
        let mut verifier = match self.chain_verifier.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let chain = verifier.verify(reader, anchor.as_ref());
        chain.chain_ok && chain.corrupt_lines == 0
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
            log_writer: None,
            log_index: LogFileIndex::new(),
            chain_verifier: Mutex::new(nrr_diagnostics::AuditChainVerifier::new()),
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
        let log = self.system_event_log.as_ref();
        nrr_domain::boot_timing::service_start_relative_to_sign_in(
            log.and_then(|log| log.boot_started_at_ms()),
            log.and_then(|log| log.sign_in_prompt_at_ms()),
            self.started_at_ms,
        )
    }

    /// Honour audit chain restarts sealed with `key`. Without it an old break
    /// is reported until its file ages out, restart or not.
    pub fn with_chain_restart_key(mut self, key: Option<nrr_diagnostics::AuditRestartKey>) -> Self {
        if let Some(key) = key {
            self.chain_verifier =
                Mutex::new(nrr_diagnostics::AuditChainVerifier::with_restart_key(key));
        }
        self
    }

    /// Attach the installed log writer so the health card can report events
    /// the service actually lost.
    pub fn with_log_writer(mut self, writer: Option<Arc<nrr_diagnostics::LogWriter>>) -> Self {
        self.log_writer = writer;
        self
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
