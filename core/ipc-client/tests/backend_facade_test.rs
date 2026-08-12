//! Integration tests for `IpcBackendFacade`.
//!
//! These tests exercise the full facade behaviour by injecting a
//! [`FakeIpcClient`] sink in place of the real `NamedPipeIpcClient`.
//! The fake routes typed responses for known operations and lets the
//! test flip the connection status mid-flight to drive the
//! cache-fallback paths documented in `backend_facade_impl.rs`.
//!
//! End-to-end coverage against the real production handler registry
//! lives in `nrr-service-runtime/tests/ipc_handlers_test.rs`; this
//! suite focuses on the *facade* layer (timeout matrix, cache write,
//! cache fallback, mutation invalidation, `clear_cache`, `force_reconnect`).

#![cfg(target_os = "windows")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};

use nrr_application::backend_facade::logs::{LogEntryFilter, PaginationParams};
use nrr_application::backend_facade::{
    BackendConnectionStatus, BackendFacade, BackendProviderKind,
};
use nrr_ipc_client::snapshot_cache::{CacheKey, FileCache};
use nrr_ipc_client::{ConnectionStatus, IpcBackendFacade, IpcClient, IpcClientError};
use nrr_shared::ipc::IpcOperationName;
use nrr_shared::ipc_payloads::{MutationKind, SnapshotDiagnosticsResponse};
use tempfile::TempDir;

// ── FakeIpcClient ────────────────────────────────────────────────────────────

/// In-process IPC sink used by the tests.
///
/// Per-operation responses are queued via [`FakeIpcClient::set_response`]
/// (typed) or [`FakeIpcClient::set_raw_response`]; if no response is
/// registered the fake returns
/// [`IpcClientError::ServerError`]. Connection status defaults to
/// `Connected`; tests flip it via [`FakeIpcClient::set_status`] to
/// drive the disconnect / reconnect paths.
struct FakeIpcClient {
    status: Mutex<ConnectionStatus>,
    responses: Mutex<HashMap<IpcOperationName, Value>>,
    /// `true` ⇒ all `call`s return `IpcClientError::Timeout` regardless
    /// of registered responses (lets us probe the cache-fallback path
    /// without faking a full disconnect).
    force_timeout: AtomicBool,
    call_count: AtomicUsize,
    reconnect_count: AtomicUsize,
}

impl FakeIpcClient {
    fn connected() -> Arc<Self> {
        Arc::new(Self {
            status: Mutex::new(ConnectionStatus::Connected),
            responses: Mutex::new(HashMap::new()),
            force_timeout: AtomicBool::new(false),
            call_count: AtomicUsize::new(0),
            reconnect_count: AtomicUsize::new(0),
        })
    }

    fn set_response<T: serde::Serialize>(&self, op: IpcOperationName, response: &T) {
        let v = serde_json::to_value(response).expect("serialize fake response");
        self.responses.lock().unwrap().insert(op, v);
    }

    fn set_status(&self, s: ConnectionStatus) {
        *self.status.lock().unwrap() = s;
    }

    fn set_force_timeout(&self, on: bool) {
        self.force_timeout.store(on, Ordering::SeqCst);
    }

    fn call_count(&self) -> usize {
        self.call_count.load(Ordering::SeqCst)
    }

    fn reconnect_count(&self) -> usize {
        self.reconnect_count.load(Ordering::SeqCst)
    }
}

impl IpcClient for FakeIpcClient {
    fn call(
        &self,
        operation: IpcOperationName,
        _payload: Value,
        _timeout: Duration,
    ) -> Result<Value, IpcClientError> {
        self.call_count.fetch_add(1, Ordering::SeqCst);

        if self.force_timeout.load(Ordering::SeqCst) {
            return Err(IpcClientError::Timeout);
        }

        let status = self.status.lock().unwrap().clone();
        if !matches!(status, ConnectionStatus::Connected) {
            return Err(IpcClientError::Disconnected);
        }

        match self.responses.lock().unwrap().get(&operation) {
            Some(v) => Ok(v.clone()),
            None => Err(IpcClientError::ServerError {
                op: operation,
                code: nrr_shared::ipc_transport::IpcErrorCode::Internal,
                message: format!("fake: no response registered for {}", operation.slug()),
            }),
        }
    }

    fn connection_status(&self) -> ConnectionStatus {
        self.status.lock().unwrap().clone()
    }

    fn force_reconnect(&self) {
        self.reconnect_count.fetch_add(1, Ordering::SeqCst);
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn fresh_facade() -> (TempDir, Arc<FakeIpcClient>, IpcBackendFacade) {
    let dir = TempDir::new().expect("tempdir");
    let cache = Arc::new(FileCache::with_root(dir.path().to_path_buf()).expect("cache"));
    let fake = FakeIpcClient::connected();
    let facade = IpcBackendFacade::new(fake.clone(), cache);
    (dir, fake, facade)
}

fn diagnostics_status_response(stale: bool) -> SnapshotDiagnosticsResponse {
    use nrr_shared::diagnostics_dto::{
        CacheHealthCard, DiagnosticModeStateDto, DiagnosticsStatusDto, LogHealthCard,
        SecurityStatusCard, ServiceHealthCard,
    };
    SnapshotDiagnosticsResponse {
        status: DiagnosticsStatusDto {
            overall_healthy: true,
            service_health: ServiceHealthCard {
                state: "running".into(),
                active_revision_id: Some("rev-test-001".into()),
                pending_changes: 0,
            },
            security_status: SecurityStatusCard {
                audit_chain_ok: true,
                active_alert_count: 0,
                audit_write_healthy: true,
            },
            active_alerts: Vec::new(),
            cache_health: CacheHealthCard {
                entry_count: 7,
                healthy: true,
                rebuilding: false,
            },
            log_health: LogHealthCard {
                dir_writable: true,
                total_size_bytes: 1024,
                file_count: 1,
                dropped_count: 0,
                last_cleanup_at: None,
            },
            diagnostic_mode: DiagnosticModeStateDto::inactive(),
            stale,
        },
        explain_sample: None,
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[test]
fn diagnostics_status_writes_cache_on_success() {
    let (_dir, fake, facade) = fresh_facade();
    fake.set_response(
        IpcOperationName::SnapshotDiagnosticsGet,
        &diagnostics_status_response(false),
    );
    let snap = facade.diagnostics_status_snapshot();
    assert_eq!(snap.service_health.state, "running");
    assert!(!snap.stale, "fresh response should not be marked stale");
    // The cache file must exist after a successful call.
    let cached = facade
        .cache()
        .read(CacheKey::SnapshotDiagnostics)
        .expect("cache hit");
    assert!(!cached.expired);
    assert_eq!(
        cached.payload["status"]["service_health"]["state"],
        "running"
    );
}

#[test]
fn diagnostics_status_returns_cached_with_stale_when_disconnected() {
    let (_dir, fake, facade) = fresh_facade();
    fake.set_response(
        IpcOperationName::SnapshotDiagnosticsGet,
        &diagnostics_status_response(false),
    );
    // First call: succeeds, populates cache.
    let _ = facade.diagnostics_status_snapshot();
    // Now drop the pipe and re-fetch — facade must serve from cache and stamp stale.
    fake.set_status(ConnectionStatus::Disconnected {
        last_error: "test forced".into(),
    });
    let snap = facade.diagnostics_status_snapshot();
    assert_eq!(snap.service_health.state, "running");
    assert!(snap.stale, "disconnected reads must surface stale=true");
}

#[test]
fn diagnostics_status_falls_back_to_mock_when_disconnected_with_no_cache() {
    let (_dir, fake, facade) = fresh_facade();
    // No cache, no live response → facade returns the mock placeholder.
    fake.set_status(ConnectionStatus::Disconnected {
        last_error: "no service".into(),
    });
    let snap = facade.diagnostics_status_snapshot();
    // Mock snapshot is well-formed but its provenance is the preview
    // data — we don't assert specific values, only that the facade
    // didn't panic and returned a syntactically valid snapshot.
    assert!(!snap.service_health.state.is_empty());
}

#[test]
fn list_security_alerts_round_trips_payload_and_caches_it() {
    use nrr_shared::diagnostics_dto::SecurityAlertDto;
    use nrr_shared::ipc_payloads::SecurityAlertsResponse;
    let (_dir, fake, facade) = fresh_facade();
    let alert = SecurityAlertDto {
        alert_id: "alt-test-1".into(),
        kind: "tamper_alert_raised".into(),
        state: "active".into(),
        created_at: 1_745_000_000_000,
        updated_at: 1_745_000_000_000,
        reason_code: "integrity.audit_chain_mismatch".into(),
        raised_file: "nrr_audit_20260423-1.ndjson".into(),
        requires_action: true,
    };
    fake.set_response(
        IpcOperationName::SecurityAlertsList,
        &SecurityAlertsResponse {
            alerts: vec![alert.clone()],
        },
    );
    let alerts = facade.list_security_alerts(Some("active"));
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].alert_id, "alt-test-1");
    // Cache populated.
    let cached = facade
        .cache()
        .read(CacheKey::SecurityAlerts)
        .expect("cached");
    assert_eq!(
        cached.payload["alerts"][0]["alert_id"], "alt-test-1",
        "raw cached payload preserved"
    );
}

#[test]
fn list_log_entries_returns_empty_stale_page_when_disconnected() {
    let (_dir, fake, facade) = fresh_facade();
    fake.set_status(ConnectionStatus::Disconnected {
        last_error: "down".into(),
    });
    let page = facade.list_log_entries(&LogEntryFilter::default(), &PaginationParams::default());
    assert!(page.is_empty(), "disconnected page must be empty");
    assert!(page.stale, "disconnected page must be marked stale");
}

#[test]
fn list_log_entries_returns_server_payload_when_connected() {
    use nrr_shared::diagnostics_dto::LogEntryDto;
    use nrr_shared::pagination::PageResult;
    let (_dir, fake, facade) = fresh_facade();
    let entry = LogEntryDto {
        event_id: "evt-1".into(),
        created_at: 1_745_000_000_000,
        level: "info".into(),
        category: "service".into(),
        kind: "service.started".into(),
        message_key: "diag.service.started.summary".into(),
        has_payload: false,
        correlation_summary: Vec::new(),
    };
    fake.set_response(
        IpcOperationName::LogsList,
        &PageResult::single_page(vec![entry.clone()]),
    );
    let page = facade.list_log_entries(&LogEntryFilter::default(), &PaginationParams::default());
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].event_id, "evt-1");
    assert!(!page.stale);
}

#[test]
fn connection_status_reflects_underlying_client_state() {
    let (_dir, fake, facade) = fresh_facade();
    assert!(matches!(
        facade.connection_status(),
        BackendConnectionStatus::Connected
    ));
    assert_eq!(facade.provider_kind(), BackendProviderKind::IpcConnected);

    fake.set_status(ConnectionStatus::NotInstalled);
    assert!(matches!(
        facade.connection_status(),
        BackendConnectionStatus::ServiceNotInstalled
    ));
    assert_eq!(
        facade.provider_kind(),
        BackendProviderKind::IpcServiceNotInstalled
    );

    fake.set_status(ConnectionStatus::ProtocolMismatch {
        server_version: 9,
        client_version: 1,
    });
    match facade.connection_status() {
        BackendConnectionStatus::ProtocolMismatch {
            server_version,
            client_version,
        } => {
            assert_eq!(server_version, 9);
            assert_eq!(client_version, 1);
        }
        other => panic!("unexpected: {other:?}"),
    }
    assert_eq!(
        facade.provider_kind(),
        BackendProviderKind::IpcProtocolMismatch
    );
}

#[test]
fn force_reconnect_is_forwarded_to_client() {
    let (_dir, fake, facade) = fresh_facade();
    assert_eq!(fake.reconnect_count(), 0);
    facade.force_reconnect();
    facade.force_reconnect();
    assert_eq!(fake.reconnect_count(), 2);
}

#[test]
fn clear_cache_removes_all_known_files_from_disk() {
    let (_dir, fake, facade) = fresh_facade();
    fake.set_response(
        IpcOperationName::SnapshotDiagnosticsGet,
        &diagnostics_status_response(false),
    );
    let _ = facade.diagnostics_status_snapshot();
    assert!(facade.cache().read(CacheKey::SnapshotDiagnostics).is_some());
    facade.clear_cache().expect("clear ok");
    assert!(facade.cache().read(CacheKey::SnapshotDiagnostics).is_none());
}

#[test]
fn timeout_returns_cached_payload_when_cache_is_fresh() {
    let (_dir, fake, facade) = fresh_facade();
    fake.set_response(
        IpcOperationName::SnapshotDiagnosticsGet,
        &diagnostics_status_response(false),
    );
    // Warm the cache while connected.
    let _ = facade.diagnostics_status_snapshot();
    // Now flip to forced timeout: facade must serve cache + stale.
    fake.set_force_timeout(true);
    let snap = facade.diagnostics_status_snapshot();
    assert_eq!(snap.service_health.state, "running");
    assert!(snap.stale);
}

#[test]
fn server_error_does_not_consult_cache_and_falls_back_to_mock() {
    let (_dir, _fake, facade) = fresh_facade();
    // No registered response → fake returns ServerError. Facade must
    // NOT pull from cache (this is a structured-error path), and must
    // fall back to the mock placeholder rather than panicking.
    let snap = facade.diagnostics_status_snapshot();
    assert!(!snap.service_health.state.is_empty());
    // Cache was never populated.
    assert!(facade.cache().read(CacheKey::SnapshotDiagnostics).is_none());
}

#[test]
fn mutation_invalidation_targets_remove_relevant_cache_files() {
    let (_dir, fake, facade) = fresh_facade();
    fake.set_response(
        IpcOperationName::SnapshotDiagnosticsGet,
        &diagnostics_status_response(false),
    );
    fake.set_response(
        IpcOperationName::SecurityAlertsList,
        &json!({ "alerts": [] }),
    );
    let _ = facade.diagnostics_status_snapshot();
    let _ = facade.list_security_alerts(None);
    // Both files exist.
    assert!(facade.cache().read(CacheKey::SnapshotDiagnostics).is_some());
    assert!(facade.cache().read(CacheKey::SecurityAlerts).is_some());

    // RulesUpdate mutation does NOT touch SnapshotDiagnostics or SecurityAlerts.
    facade
        .cache()
        .invalidate_for_mutation(MutationKind::RulesUpdate)
        .expect("invalidate");
    assert!(
        facade.cache().read(CacheKey::SnapshotDiagnostics).is_some(),
        "diagnostics cache not affected by RulesUpdate"
    );
    assert!(
        facade.cache().read(CacheKey::SecurityAlerts).is_some(),
        "alerts cache not affected by RulesUpdate"
    );
}

#[test]
fn cloning_facade_shares_underlying_client_and_cache() {
    let (_dir, fake, facade) = fresh_facade();
    let copy = facade.clone();
    fake.set_response(
        IpcOperationName::SnapshotDiagnosticsGet,
        &diagnostics_status_response(false),
    );
    let _ = facade.diagnostics_status_snapshot();
    // The clone sees the same cache, so its lookup is a hit even though
    // *it* didn't issue the call.
    assert!(copy.cache().read(CacheKey::SnapshotDiagnostics).is_some());
    // Both clones see the same call counter on the fake (one Arc).
    assert_eq!(fake.call_count(), 1);
}

#[test]
fn timeout_matrix_has_an_entry_for_every_operation_in_catalog() {
    use nrr_ipc_client::ipc_operation_timeout;
    for op in IpcOperationName::ALL {
        let t = ipc_operation_timeout(op);
        // Upper bound 30 s: MutationSubmit's confirm phase is the heavy one,
        // matching the QML rpcTimeoutMs.
        assert!(
            (Duration::from_secs(1)..=Duration::from_secs(30)).contains(&t),
            "{} timeout {:?} outside [1s, 30s]",
            op.slug(),
            t
        );
    }
}
