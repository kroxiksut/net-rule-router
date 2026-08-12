//! `IpcBackendFacade`.
//!
//! `BackendFacade` implementation that talks to the Windows service over
//! the named-pipe transport and falls back to a file-based snapshot cache
//! ([`crate::snapshot_cache`]) when the pipe is down.
//!
//! ## Boundaries
//!
//! The facade satisfies the existing `nrr_application::backend_facade::BackendFacade`
//! trait so the GUI/Tray can swap it in for `MockBackendFacade` /
//! `PreviewLocalBackendFacade` without changing call sites. Methods
//! split into two camps:
//!
//! 1. **Wire-aligned** — `diagnostics_status_snapshot`,
//!    `list_log_entries`, `list_audit_entries`, `list_security_alerts`.
//!    The trait return types are exactly the wire DTOs (shared with
//!    `nrr-shared`); the facade issues a real IPC call, deserialises the
//!    typed response, writes the snapshot cache where applicable.
//!
//! 2. **Preview-shaped** — `status_snapshot`, `interfaces_snapshot`,
//!    `interface_checks_snapshot`, `rules_snapshot`,
//!    `route_bindings_snapshot`. The trait return types are
//!    `nrr-mock-backend` preview snapshots that include UI-derived
//!    decoration (assessments, recommendations, dialogs). These methods
//!    (a) issue the underlying IPC so the cache stays warm and the user
//!    sees real connectivity errors, and (b) delegate the rendered
//!    snapshot to `MockBackendFacade` until the wire→preview mapping is
//!    built out. The delegation sites are marked with `TODO:`.
//!
//! ## Failure modes
//!
//! Every wire-aligned method follows the same fallback:
//!
//! | Scenario                         | Behaviour                                     |
//! |----------------------------------|-----------------------------------------------|
//! | Connected, response OK           | Write cache, return payload, `stale=false`    |
//! | Connected, response timeout      | Read cache; if fresh return it tagged stale; else fallback |
//! | Connected, server error          | Propagate as fallback (no cache lookup)       |
//! | Disconnected, cache fresh        | Return cached payload tagged `stale=true`     |
//! | Disconnected, cache stale/missing| Fallback to mock (last-resort empty data)     |
//!
//! Mutations (none on this trait yet) will *not* consult the cache; per
//! spec, mutation requests on a disconnected pipe must surface
//! `Disconnected` immediately.
//!
//! ## Threading
//!
//! `IpcBackendFacade` is `Send + Sync` and cheap to clone (everything
//! lives behind `Arc`). The GUI normally instantiates one and stores
//! it in a global `OnceLock`.

#![cfg(target_os = "windows")]

use std::sync::Arc;
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde_json::{json, Value};

use crate::client::NamedPipeIpcClient;
use crate::connection::{ConnectionStatus, IpcClient, IpcClientError};
use crate::snapshot_cache::{CacheKey, FileCache};
use nrr_application::backend_facade::UiPreferences;
use nrr_application::backend_facade::{
    diagnostics::{DiagnosticsStatusDto, SecurityAlertDto},
    logs::{
        AuditEntryDto, AuditEntryFilter, LogEntryDto, LogEntryFilter, PageResult, PaginationParams,
    },
    network_interfaces::{
        decorate_interface_rows, InterfaceDiagnosticsChecksSnapshot, InterfaceRouteRow,
        InterfacesRoutesPreviewSnapshot, RouteSelectionRequest,
    },
    rules::{RulesScreenPreviewSnapshot, RulesScreenRequest},
    security_status::SecurityStatusSnapshot,
    BackendConnectionStatus, BackendFacade, BackendProviderKind, CacheError, MockBackendFacade,
};
use nrr_application::route_bindings::{
    route_bindings_export_snapshot, RouteBindingsExportSnapshot,
};
use nrr_shared::ipc::IpcOperationName;
use nrr_shared::ipc_payloads::{
    AuditListRequest, AuditListResponse, LogsListRequest, LogsListResponse, SecurityAlertsRequest,
    SecurityAlertsResponse, SnapshotDiagnosticsRequest, SnapshotDiagnosticsResponse,
    SnapshotInitialRequest, SnapshotInterfacesRequest, SnapshotInterfacesResponse,
};

/// Per-operation timeout matrix.
///
/// `SnapshotInterfaces` and `InterfacesRefresh` carry the same 5-second
/// budget because force-refresh blocks on the adapter monitor; the
/// service guarantees a response within that window or returns a
/// degraded snapshot.
fn timeout_for(op: IpcOperationName) -> Duration {
    match op {
        IpcOperationName::ContractNegotiate => Duration::from_secs(2),
        IpcOperationName::ServiceHealthGet => Duration::from_secs(1),
        IpcOperationName::SnapshotInitialGet => Duration::from_secs(3),
        IpcOperationName::SnapshotInterfacesGet => Duration::from_secs(5),
        IpcOperationName::SnapshotDiagnosticsGet => Duration::from_secs(2),
        IpcOperationName::LogsList | IpcOperationName::AuditList => Duration::from_secs(5),
        IpcOperationName::SecurityAlertsList => Duration::from_secs(1),
        // `rules.list` shares the state-DB connection mutex with the mutation
        // executor; right after an activation the GUI's refetch contends for
        // that lock while the heavy preset-import is still committing, so a
        // short budget can time the refetch out (lost response → empty
        // table). 5s covers the contention window.
        IpcOperationName::RulesList => Duration::from_secs(5),
        // MutationSubmit confirm does the real work — parse + canonicalise
        // a preset, persist the revision, and apply per-SID WFP filters.
        // For a large rule set on a debug build this routinely exceeds a 5s
        // budget, so a shorter timeout can fire while the service keeps
        // going (active revision committed server-side but the GUI lost the
        // response → no refetch, divergence). 30s matches the QML-side
        // `rpcTimeoutMs`.
        IpcOperationName::MutationSubmit => Duration::from_secs(30),
        IpcOperationName::OperationStatusGet => Duration::from_secs(1),
        IpcOperationName::RollbackRequest => Duration::from_secs(1),
        IpcOperationName::InterfacesRefreshRequest => Duration::from_secs(5),
        IpcOperationName::ProductImpactDisableTemporary => Duration::from_secs(5),
        IpcOperationName::StatusUpdatesPoll | IpcOperationName::StatusUpdatesSubscribe => {
            Duration::from_secs(2)
        }
        // Per-SID configuration writes and migration ledger reads. Single
        // SQLite write per call; 1 s is generous. RouteLinkProviderSet is
        // the same shape (one SQLite replace + best-effort recompile
        // trigger).
        IpcOperationName::RoutePolicyUpdate
        | IpcOperationName::RouteLinkProviderSet
        | IpcOperationName::MigrationStatusGet
        | IpcOperationName::MigrationMarkComplete => Duration::from_secs(1),
        // Settings reads/writes. Singleton row + simple validation for the
        // four 'Set' ops; routing-pause writes also poke the apply layer
        // through the coordinator. 2 s budget covers the apply step.
        IpcOperationName::RetentionSettingsGet
        | IpcOperationName::ApplyFailurePolicyGet
        | IpcOperationName::RoutingPauseGet
        // Log/audit retention config get/set (singleton row).
        | IpcOperationName::LogRetentionConfigGet
        | IpcOperationName::AutostartGet => Duration::from_secs(1),
        IpcOperationName::RetentionSettingsSet
        | IpcOperationName::ApplyFailurePolicySet
        | IpcOperationName::LogRetentionConfigSet
        | IpcOperationName::AutostartToggle => Duration::from_secs(1),
        IpcOperationName::RoutingPauseToggle => Duration::from_secs(2),
        // Storage scan walks `%ProgramData%`, deliberately on-demand —
        // 5 s covers cold-disk worst-case.
        IpcOperationName::StorageUsageGet => Duration::from_secs(5),
        // Explain runs the decision engine plus an audit lookup; pure CPU +
        // one indexed SQLite read. 2 s budget matches diagnostics snapshot.
        IpcOperationName::ExplainGet => Duration::from_secs(2),
        // Archive build scans logs/audit directories + zips. Cold-disk
        // worst-case can be a few seconds for large log volumes; 10 s
        // is the upper guard.
        IpcOperationName::DiagnosticsExportArchive => Duration::from_secs(10),
        // Singleton-row reads/writes.
        IpcOperationName::ServiceStabilityConfigGet
        | IpcOperationName::ServiceStabilityConfigSet => Duration::from_secs(1),
        // LogsClear walks the rotated NDJSON file list and unlinks
        // each one. Bound by the number of files (capped by the
        // retention policy); 10 s mirrors the archive-build ceiling.
        IpcOperationName::LogsClear => Duration::from_secs(10),
        // CacheClear runs one SQLite transaction that deletes all cache
        // rows (or a stats read on dry-run). Bounded by row count; 10 s
        // is a conservative upper guard.
        IpcOperationName::CacheClear => Duration::from_secs(10),
        // CacheEntriesList runs one bounded indexed SELECT (page-sized).
        // 5 s mirrors the other paginated reads (LogsList / AuditList).
        IpcOperationName::CacheEntriesList => Duration::from_secs(5),
        // Read active revision + canonicalize + write_rules_file + SHA-256 +
        // base64 wrap. Pure CPU, single indexed SQLite read; 5 s is the
        // conservative upper bound even for a full `MAX_RULES_PER_FILE = 9999`
        // revision.
        IpcOperationName::PresetExportGet => Duration::from_secs(5),
        // Assemble YAML from route_bindings + behavior mode + per-user UI
        // prefs paths (paths only, no file contents). Three singleton-row
        // reads + serde_yaml emit. 3 s is generous.
        IpcOperationName::SettingsExportFull => Duration::from_secs(3),
        // Merge preview: one indexed state-DB read + parse + canonicalize
        // both file texts + merge + encode. Pure CPU on top of a single
        // read; 5 s matches the other rules reads under lock contention.
        IpcOperationName::RulesMergePreview => Duration::from_secs(5),
        // One bounded in-memory ring snapshot (page-sized). As cheap as the
        // cache read; 5 s mirrors the other paginated reads.
        IpcOperationName::ConnTraceEntriesList => Duration::from_secs(5),
        // Hashes a ~400 KiB DLL and verifies its signature; the signature
        // check can touch the certificate store, so give it more room than a
        // pure in-memory read.
        IpcOperationName::ThirdPartyComponentsList => Duration::from_secs(10),
        // In-memory diagnostic-session write; trivial.
        IpcOperationName::DiagnosticModeSet => Duration::from_secs(1),
        // DoH resolver baseline list read/replace. One bounded SELECT / one
        // delete+insert transaction (~100 rows). 2 s is generous.
        IpcOperationName::DohResolversGet | IpcOperationName::DohResolversSet => {
            Duration::from_secs(2)
        }
        // Traffic-stats read is a couple of indexed SQLite reads plus
        // in-memory session totals; the write is one singleton-row upsert. 2 s.
        IpcOperationName::TrafficStatsGet
        | IpcOperationName::TrafficStatsSet
        | IpcOperationName::TrafficStatsClear => Duration::from_secs(2),
        // Kicks off the async browser-history seed and returns immediately;
        // the read+resolve happens on a service worker thread.
        IpcOperationName::SeedFromBrowserHistory => Duration::from_secs(2),
        // Companion-domain suggestions. The list is an in-memory registry
        // read and the refusal is one SQLite upsert, so both are trivial.
        // Accepting authors rules and drives a full activation, which is the
        // same work `MutationSubmit` does — it gets the same budget, or the
        // tray would time out while the service was still applying.
        IpcOperationName::AutoRuleCandidatesList
        | IpcOperationName::AutoRuleCandidatesDismiss => Duration::from_secs(2),
        IpcOperationName::AutoRuleCandidatesAccept => Duration::from_secs(30),
        // Reviewing/restoring past refusals is the same shape as list/dismiss:
        // an indexed SQLite read and a single-row delete.
        // Restoring re-parks the stored offer and erasing deletes rows: still
        // in-memory work plus one small write.
        IpcOperationName::AutoRuleDismissedList
        | IpcOperationName::AutoRuleDismissedRestore
        | IpcOperationName::AutoRuleCandidatesForget => Duration::from_secs(2),
        // Block-notice mutes: an indexed per-SID read and single-row
        // upsert/delete — same trivial shape as the companion-domain
        // refusal ops above.
        IpcOperationName::BlockNoticeMutesList
        | IpcOperationName::BlockNoticeMutesSet
        | IpcOperationName::BlockNoticeMutesRemove
        | IpcOperationName::BlockNoticeMutesClear => Duration::from_secs(2),
        // Authors a rule and drives a full activation — same work
        // `AutoRuleCandidatesAccept` does, same budget.
        IpcOperationName::BlockNoticeRouteToSecondary => Duration::from_secs(30),
        // Nine bounded per-SID DELETEs in one transaction — small row counts,
        // same tier as the other maintenance transactions above.
        IpcOperationName::PrincipalDataPurge => Duration::from_secs(5),
    }
}

/// Per-operation timeout matrix exposed for property tests in
/// `tests/backend_facade_test.rs`.
pub fn ipc_operation_timeout(op: IpcOperationName) -> Duration {
    timeout_for(op)
}

/// IPC-backed `BackendFacade` implementation. See module docs for
/// failure-mode and threading semantics.
///
/// Stored behind `Arc<dyn IpcClient>` rather than the concrete
/// `NamedPipeIpcClient` so integration tests can inject a fake sink
/// without touching the Win32 transport. The production wiring (GUI
/// startup) builds with [`Self::with_named_pipe`], which boxes a
/// real `NamedPipeIpcClient`.
#[derive(Clone)]
pub struct IpcBackendFacade {
    client: Arc<dyn IpcClient>,
    cache: Arc<FileCache>,
    /// Used for preview-shape methods pending a real wire→preview mapping.
    fallback: MockBackendFacade,
}

impl IpcBackendFacade {
    /// Build a facade over an existing client sink and cache. Tests
    /// pass an in-process fake; production passes a real
    /// `NamedPipeIpcClient` via [`Self::with_named_pipe`].
    pub fn new(client: Arc<dyn IpcClient>, cache: Arc<FileCache>) -> Self {
        Self {
            client,
            cache,
            fallback: MockBackendFacade,
        }
    }

    /// Production constructor: wrap a `NamedPipeIpcClient` and use the
    /// default `%LOCALAPPDATA%\NetRuleRouter\snapshot_cache\` cache
    /// root. Returns `CacheError` only if the cache directory cannot
    /// be created; callers in production typically `.expect()` that.
    pub fn with_named_pipe(client: Arc<NamedPipeIpcClient>) -> Result<Self, CacheError> {
        let cache = Arc::new(FileCache::at_default_location()?);
        // Sweep stragglers from previous schema versions on first use so
        // the directory doesn't accumulate forever.
        let _ = cache.purge_unknown_files();
        Ok(Self::new(client, cache))
    }

    /// Access to the underlying client sink (tests use this to flip
    /// fake connection state).
    pub fn client(&self) -> &Arc<dyn IpcClient> {
        &self.client
    }

    /// Access to the cache (tests verify per-mutation invalidation).
    pub fn cache(&self) -> &Arc<FileCache> {
        &self.cache
    }

    /// Issue an IPC call and apply the standard cache-fallback policy:
    ///
    /// - On success: write the response into `cache_key` (when given).
    /// - On `Timeout` or `Disconnected`: read the cache; if fresh
    ///   enough, return it with the in-band `stale` flag set so the
    ///   caller can surface the staleness to the user.
    /// - On other errors: return them; cache is not consulted because
    ///   the error indicates a structured server-side problem, not
    ///   transport breakage.
    ///
    /// Returns `(payload, stale_flag)` so the caller can stamp `stale`
    /// into typed response wrappers (e.g. `DiagnosticsStatusDto.stale`).
    fn call_with_cache(
        &self,
        op: IpcOperationName,
        payload: Value,
        cache_key: Option<CacheKey>,
    ) -> Result<(Value, bool), IpcClientError> {
        let timeout = timeout_for(op);
        match self.client.call(op, payload, timeout) {
            Ok(resp) => {
                if let Some(key) = cache_key {
                    // Fire-and-forget: a failed cache write must not
                    // block the IPC return path.
                    let _ = self.cache.write(key, resp.clone());
                }
                Ok((resp, false))
            }
            Err(IpcClientError::Timeout) | Err(IpcClientError::Disconnected) => {
                if let Some(key) = cache_key {
                    if let Some(cached) = self.cache.read(key) {
                        if !cached.expired {
                            return Ok((cached.payload, true));
                        }
                    }
                }
                Err(IpcClientError::Disconnected)
            }
            Err(other) => Err(other),
        }
    }

    /// Type-safe wrapper around [`Self::call_with_cache`] that
    /// deserialises the payload into `R`. Errors collapse into the
    /// caller's fallback branch; deserialisation failures are treated
    /// as `BadResponse` and surfaced through the same path.
    fn call_typed<R: DeserializeOwned>(
        &self,
        op: IpcOperationName,
        payload: Value,
        cache_key: Option<CacheKey>,
    ) -> Result<(R, bool), IpcClientError> {
        let (raw, stale) = self.call_with_cache(op, payload, cache_key)?;
        match serde_json::from_value::<R>(raw) {
            Ok(typed) => Ok((typed, stale)),
            Err(e) => Err(IpcClientError::BadResponse {
                reason: format!("response for {} did not match schema: {e}", op.slug()),
            }),
        }
    }
}

/// Map the rich `ConnectionStatus` from the transport into the narrower
/// `BackendConnectionStatus` exposed to GUI consumers.
fn map_connection_status(s: ConnectionStatus) -> BackendConnectionStatus {
    match s {
        ConnectionStatus::Connected => BackendConnectionStatus::Connected,
        ConnectionStatus::Connecting => BackendConnectionStatus::Connecting,
        ConnectionStatus::Disconnected { last_error } => {
            BackendConnectionStatus::Disconnected { last_error }
        }
        ConnectionStatus::ServiceStopped => BackendConnectionStatus::ServiceStopped,
        ConnectionStatus::NotInstalled => BackendConnectionStatus::ServiceNotInstalled,
        ConnectionStatus::ProtocolMismatch {
            server_version,
            client_version,
        } => BackendConnectionStatus::ProtocolMismatch {
            server_version,
            client_version,
        },
    }
}

fn provider_kind_from_status(s: &ConnectionStatus) -> BackendProviderKind {
    match s {
        ConnectionStatus::Connected => BackendProviderKind::IpcConnected,
        ConnectionStatus::NotInstalled => BackendProviderKind::IpcServiceNotInstalled,
        ConnectionStatus::ProtocolMismatch { .. } => BackendProviderKind::IpcProtocolMismatch,
        _ => BackendProviderKind::IpcDisconnected,
    }
}

impl BackendFacade for IpcBackendFacade {
    fn provider_kind(&self) -> BackendProviderKind {
        provider_kind_from_status(&self.client.connection_status())
    }

    fn connection_status(&self) -> BackendConnectionStatus {
        map_connection_status(self.client.connection_status())
    }

    fn force_reconnect(&self) {
        self.client.force_reconnect();
    }

    fn clear_cache(&self) -> Result<(), CacheError> {
        self.cache.clear_all()
    }

    // ── Wire-aligned methods ──────────────────────────────────────────

    fn diagnostics_status_snapshot(&self) -> DiagnosticsStatusDto {
        let req = json!(SnapshotDiagnosticsRequest::default());
        match self.call_typed::<SnapshotDiagnosticsResponse>(
            IpcOperationName::SnapshotDiagnosticsGet,
            req,
            Some(CacheKey::SnapshotDiagnostics),
        ) {
            Ok((resp, stale)) => {
                let mut status = resp.status;
                if stale {
                    status.stale = true;
                }
                status
            }
            // Last-resort fallback: a placeholder mock snapshot.
            // The user-visible cue here is the `stale=true` rendering
            // path that the GUI already supports for mock data.
            Err(_) => self.fallback.diagnostics_status_snapshot(),
        }
    }

    fn list_log_entries(
        &self,
        filter: &LogEntryFilter,
        pagination: &PaginationParams,
    ) -> PageResult<LogEntryDto> {
        let req = LogsListRequest {
            filter: filter.clone(),
            pagination: pagination.clone(),
        };
        let payload = match serde_json::to_value(&req) {
            Ok(v) => v,
            Err(_) => return PageResult::empty(),
        };
        // Logs are query-shaped per (filter, pagination) — not cached.
        match self.client.call(
            IpcOperationName::LogsList,
            payload,
            timeout_for(IpcOperationName::LogsList),
        ) {
            Ok(raw) => serde_json::from_value::<LogsListResponse>(raw).unwrap_or_else(|_| {
                let mut p = PageResult::<LogEntryDto>::empty();
                p.stale = true;
                p
            }),
            Err(_) => {
                let mut p = PageResult::<LogEntryDto>::empty();
                p.stale = true;
                p
            }
        }
    }

    fn list_audit_entries(
        &self,
        filter: &AuditEntryFilter,
        pagination: &PaginationParams,
    ) -> PageResult<AuditEntryDto> {
        let req = AuditListRequest {
            filter: filter.clone(),
            pagination: pagination.clone(),
        };
        let payload = match serde_json::to_value(&req) {
            Ok(v) => v,
            Err(_) => return PageResult::empty(),
        };
        match self.client.call(
            IpcOperationName::AuditList,
            payload,
            timeout_for(IpcOperationName::AuditList),
        ) {
            Ok(raw) => serde_json::from_value::<AuditListResponse>(raw).unwrap_or_else(|_| {
                let mut p = PageResult::<AuditEntryDto>::empty();
                p.stale = true;
                p
            }),
            Err(_) => {
                let mut p = PageResult::<AuditEntryDto>::empty();
                p.stale = true;
                p
            }
        }
    }

    fn list_security_alerts(&self, state_filter: Option<&str>) -> Vec<SecurityAlertDto> {
        let req = SecurityAlertsRequest {
            state_filter: state_filter.map(str::to_string),
        };
        let payload = match serde_json::to_value(&req) {
            Ok(v) => v,
            Err(_) => return Vec::new(),
        };
        match self.call_typed::<SecurityAlertsResponse>(
            IpcOperationName::SecurityAlertsList,
            payload,
            Some(CacheKey::SecurityAlerts),
        ) {
            Ok((resp, _stale)) => resp.alerts,
            Err(_) => Vec::new(),
        }
    }

    // ── Preview-shaped methods (mappers pending) ─────
    //
    // Every preview-shape entry point still issues the underlying IPC
    // when possible so (a) the snapshot cache stays warm for offline
    // re-renders and (b) connectivity problems surface promptly to the
    // user via `connection_status()`. The rendered snapshot itself
    // delegates to `MockBackendFacade` until the wire→preview mappers land.

    fn status_snapshot(&self) -> SecurityStatusSnapshot {
        // SnapshotInitialGet bundles health + alerts + active_revision in
        // one round-trip — exactly what the SecurityStatusSnapshot wants.
        // We populate the cache here so a future mapper can lift the typed
        // response into a real SecurityStatusSnapshot without changing the
        // call site.
        let _ = self.call_with_cache(
            IpcOperationName::SnapshotInitialGet,
            json!(SnapshotInitialRequest::default()),
            Some(CacheKey::SnapshotInitial),
        );
        // TODO: build SecurityStatusSnapshot from
        // SnapshotInitialResponse fields (health, active_alerts_count,
        // active_revision_id). Until then, the preview snapshot is the
        // GUI contract.
        self.fallback.status_snapshot()
    }

    fn interfaces_snapshot(
        &self,
        request: RouteSelectionRequest,
    ) -> InterfacesRoutesPreviewSnapshot {
        // The service is the single source of truth for the live adapter
        // list. When connected, project its enriched `rows`
        // into the preview snapshot and re-apply this caller's role
        // bindings + advisory recommendations locally (the service does
        // not run the preview engine). Cache warming happens inside
        // `call_typed`. Only the disconnected / error / older-server
        // (empty `rows`) paths fall back to a local enumeration so the
        // GUI never blanks the list.
        match self.call_typed::<SnapshotInterfacesResponse>(
            IpcOperationName::SnapshotInterfacesGet,
            json!(SnapshotInterfacesRequest::default()),
            Some(CacheKey::SnapshotInterfaces),
        ) {
            Ok((resp, _stale)) if !resp.rows.is_empty() => {
                let rows = resp
                    .rows
                    .iter()
                    .map(InterfaceRouteRow::from_wire_dto)
                    .collect::<Vec<_>>();
                decorate_interface_rows(rows, &request)
            }
            _ => self.fallback.interfaces_snapshot(request),
        }
    }

    fn interface_checks_snapshot(
        &self,
        request: RouteSelectionRequest,
    ) -> InterfaceDiagnosticsChecksSnapshot {
        // No dedicated wire op for the checks snapshot today; the data
        // comes from the same SnapshotInterfacesGet payload. Cache is
        // already warmed by `interfaces_snapshot` above when the GUI
        // renders both panes in the same screen.
        // TODO: derive checks rows from AdapterEntry[].
        self.fallback.interface_checks_snapshot(request)
    }

    fn rules_snapshot(&self, request: RulesScreenRequest) -> RulesScreenPreviewSnapshot {
        // We could issue RulesList here for cache warming, but the
        // route filter on RulesScreenRequest doesn't directly map to
        // the wire `RulesRouteFilter` — that mapping is GUI-shape work
        // pending. Until then, the mock snapshot drives the GUI.
        // TODO: issue RulesList with a derived
        // RulesRouteFilter and map RuleRowEntry[] → RuleRowPreview[].
        self.fallback.rules_snapshot(request)
    }

    fn route_bindings_snapshot(
        &self,
        preferences: &UiPreferences,
        active_revision: &str,
    ) -> RouteBindingsExportSnapshot {
        // Pure helper — no IPC. Same semantics as MockBackendFacade.
        route_bindings_export_snapshot(preferences, active_revision)
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────
//
// Most behavioural coverage lives in `tests/backend_facade_test.rs`, where
// we can spin up the full IpcRouter from `nrr-service-runtime` over a
// memory transport. Here we keep only the pure-function coverage that does
// not need the worker thread.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeout_matrix_covers_every_operation_in_catalog() {
        for op in IpcOperationName::ALL {
            let t = timeout_for(op);
            assert!(t >= Duration::from_secs(1), "{} too small", op.slug());
            // Upper guard is 30 s: MutationSubmit's confirm phase does the
            // real parse+canonicalise+persist+WFP-apply work and matches
            // the QML `rpcTimeoutMs`.
            assert!(t <= Duration::from_secs(30), "{} too large", op.slug());
        }
    }

    #[test]
    fn timeout_matrix_matches_spec_values() {
        assert_eq!(
            timeout_for(IpcOperationName::ContractNegotiate),
            Duration::from_secs(2)
        );
        assert_eq!(
            timeout_for(IpcOperationName::ServiceHealthGet),
            Duration::from_secs(1)
        );
        assert_eq!(
            timeout_for(IpcOperationName::SnapshotInitialGet),
            Duration::from_secs(3)
        );
        assert_eq!(
            timeout_for(IpcOperationName::SnapshotInterfacesGet),
            Duration::from_secs(5)
        );
        assert_eq!(
            timeout_for(IpcOperationName::SnapshotDiagnosticsGet),
            Duration::from_secs(2)
        );
        assert_eq!(
            timeout_for(IpcOperationName::LogsList),
            Duration::from_secs(5)
        );
        assert_eq!(
            timeout_for(IpcOperationName::AuditList),
            Duration::from_secs(5)
        );
        assert_eq!(
            timeout_for(IpcOperationName::SecurityAlertsList),
            Duration::from_secs(1)
        );
        // rules.list contends for the state-DB lock right after an
        // activation, hence the 5s budget.
        assert_eq!(
            timeout_for(IpcOperationName::RulesList),
            Duration::from_secs(5)
        );
        assert_eq!(
            timeout_for(IpcOperationName::OperationStatusGet),
            Duration::from_secs(1)
        );
        assert_eq!(
            timeout_for(IpcOperationName::RollbackRequest),
            Duration::from_secs(1)
        );
        assert_eq!(
            timeout_for(IpcOperationName::InterfacesRefreshRequest),
            Duration::from_secs(5)
        );
    }

    #[test]
    fn provider_kind_mapping_is_total() {
        assert_eq!(
            provider_kind_from_status(&ConnectionStatus::Connected),
            BackendProviderKind::IpcConnected
        );
        assert_eq!(
            provider_kind_from_status(&ConnectionStatus::NotInstalled),
            BackendProviderKind::IpcServiceNotInstalled
        );
        assert_eq!(
            provider_kind_from_status(&ConnectionStatus::ProtocolMismatch {
                server_version: 9,
                client_version: 1
            }),
            BackendProviderKind::IpcProtocolMismatch
        );
        assert_eq!(
            provider_kind_from_status(&ConnectionStatus::Connecting),
            BackendProviderKind::IpcDisconnected
        );
        assert_eq!(
            provider_kind_from_status(&ConnectionStatus::ServiceStopped),
            BackendProviderKind::IpcDisconnected
        );
        assert_eq!(
            provider_kind_from_status(&ConnectionStatus::Disconnected {
                last_error: "x".into()
            }),
            BackendProviderKind::IpcDisconnected
        );
    }

    #[test]
    fn connection_status_mapping_preserves_payload() {
        let mapped = map_connection_status(ConnectionStatus::Disconnected {
            last_error: "pipe down".into(),
        });
        match mapped {
            BackendConnectionStatus::Disconnected { last_error } => {
                assert_eq!(last_error, "pipe down");
            }
            other => panic!("unexpected mapping: {other:?}"),
        }
        let mismatch = map_connection_status(ConnectionStatus::ProtocolMismatch {
            server_version: 7,
            client_version: 1,
        });
        match mismatch {
            BackendConnectionStatus::ProtocolMismatch {
                server_version,
                client_version,
            } => {
                assert_eq!(server_version, 7);
                assert_eq!(client_version, 1);
            }
            other => panic!("unexpected mapping: {other:?}"),
        }
    }
}
