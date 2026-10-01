//! `IpcBackendFacade`: the `BackendFacade` served by the running service.
//!
//! It drives whatever [`IpcClient`] it is handed — the named pipe on Windows,
//! the `AF_UNIX` socket on Linux, a fake in tests — and falls back to the
//! snapshot cache when the channel is down. It lives here, above the client,
//! because its return types are the desktop preview snapshots: in the client
//! crate they linked the preview and UI crates into every client binary.
//!
//! Two kinds of method:
//!
//! 1. **Wire-aligned** — `diagnostics_status_snapshot`,
//!    `list_security_alerts`: the trait types are the wire DTOs, so the
//!    answer is the service's.
//! 2. **Desktop-shaped** — `interfaces_snapshot` reads the service's rows and
//!    applies the user's bindings; `rules_snapshot` still renders the preview
//!    until the `rules.list` mapping exists.
//!
//! ## Failure modes
//!
//! | Scenario                         | Behaviour                                     |
//! |----------------------------------|-----------------------------------------------|
//! | Connected, response OK           | Write cache, return payload, `stale=false`    |
//! | Connected, response timeout      | Read cache; if fresh return it tagged stale; else fallback |
//! | Connected, server error          | Propagate as fallback (no cache lookup)       |
//! | Disconnected, cache fresh        | Return cached payload tagged `stale=true`     |
//! | Disconnected, cache stale/missing| Explicit "unknown" answer, never preview data |

use std::sync::Arc;

use serde::de::DeserializeOwned;
use serde_json::{json, Value};

use nrr_application::backend_facade::{
    BackendConnectionStatus, BackendFacade, BackendProviderKind, MockBackendFacade,
};
use nrr_application::mock_backend::{
    network_interfaces::{
        decorate_interface_rows, InterfaceRouteRow, InterfacesDataSource,
        InterfacesRoutesPreviewSnapshot, RouteSelectionRequest,
    },
    rules::{RulesScreenPreviewSnapshot, RulesScreenRequest},
};
use nrr_ipc_client::snapshot_cache::{CacheError, CacheKey, FileCache};
use nrr_ipc_client::{ipc_operation_timeout, ConnectionStatus, IpcClient, IpcClientError};
use nrr_shared::diagnostics_dto::{DiagnosticsStatusDto, SecurityAlertsView};
use nrr_shared::ipc::IpcOperationName;
use nrr_shared::ipc_payloads::{
    SecurityAlertsRequest, SecurityAlertsResponse, SnapshotDiagnosticsRequest,
    SnapshotDiagnosticsResponse, SnapshotInterfacesRequest, SnapshotInterfacesResponse,
};

use crate::backend_factory::ipc_status_to_backend_status;

/// Service-backed `BackendFacade`. `Send + Sync` and cheap to clone:
/// everything lives behind `Arc`.
#[derive(Clone)]
pub struct IpcBackendFacade {
    client: Arc<dyn IpcClient>,
    cache: Arc<FileCache>,
    /// Local enumeration and the rules preview.
    fallback: MockBackendFacade,
}

impl IpcBackendFacade {
    pub fn new(client: Arc<dyn IpcClient>, cache: Arc<FileCache>) -> Self {
        Self {
            client,
            cache,
            fallback: MockBackendFacade::default(),
        }
    }

    /// Production constructor: this OS's service transport over the default
    /// cache root. Fails only when the cache directory cannot be created.
    pub fn with_service_transport(
        client: Arc<nrr_ipc_client::ServiceIpcClient>,
    ) -> Result<Self, CacheError> {
        let cache = Arc::new(FileCache::at_default_location()?);
        // Stragglers from older contracts would otherwise accumulate forever.
        let _ = cache.purge_unknown_files();
        Ok(Self::new(client, cache))
    }

    pub fn client(&self) -> &Arc<dyn IpcClient> {
        &self.client
    }

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
        let timeout = ipc_operation_timeout(op);
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
            Err(e) => {
                // A cached payload that no longer fits its type is a cache
                // written by an older shape. The fingerprint catches most of
                // those; this catches the rest, and keeps the bad entry from
                // failing every read until its TTL runs out.
                if stale {
                    if let Some(key) = cache_key {
                        let _ = self.cache.invalidate(key);
                    }
                }
                Err(IpcClientError::BadResponse {
                    reason: format!("response for {} did not match schema: {e}", op.slug()),
                })
            }
        }
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
        ipc_status_to_backend_status(self.client.connection_status())
    }

    fn force_reconnect(&self) {
        self.client.force_reconnect();
    }

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
            // A failed call is not an answer: hand out the "unknown"
            // snapshot, never the preview one, which reads as healthy.
            Err(_) => DiagnosticsStatusDto::unavailable(),
        }
    }

    fn list_security_alerts(&self, state_filter: Option<&str>) -> SecurityAlertsView {
        let req = SecurityAlertsRequest {
            state_filter: state_filter.map(str::to_string),
        };
        let payload = match serde_json::to_value(&req) {
            Ok(v) => v,
            Err(_) => return SecurityAlertsView::unavailable(),
        };
        // One cache key cannot stand for every filter: a filtered read would
        // overwrite the unfiltered entry and then be served back as the whole
        // list. Only the unfiltered read is cached; a filtered one is a query,
        // and queries go to the service.
        let cache_key = state_filter.is_none().then_some(CacheKey::SecurityAlerts);
        match self.call_typed::<SecurityAlertsResponse>(
            IpcOperationName::SecurityAlertsList,
            payload,
            cache_key,
        ) {
            Ok((resp, stale)) => SecurityAlertsView {
                alerts: resp.alerts,
                stale,
            },
            // "No alerts" and "could not ask" must not look alike.
            Err(_) => SecurityAlertsView::unavailable(),
        }
    }

    // ── Desktop-shaped methods ─────

    fn interfaces_snapshot(
        &self,
        request: RouteSelectionRequest,
    ) -> InterfacesRoutesPreviewSnapshot {
        // The service owns the adapter list; this caller's bindings are applied
        // here. Only a failed or empty answer falls back to a local
        // enumeration, so the GUI never blanks the list.
        match self.call_typed::<SnapshotInterfacesResponse>(
            IpcOperationName::SnapshotInterfacesGet,
            json!(SnapshotInterfacesRequest::default()),
            Some(CacheKey::SnapshotInterfaces),
        ) {
            // A cached adapter list is a list of adapters that existed an hour
            // ago. Rendered as live it invites the user to bind a route to one
            // that is gone, so prefer a local enumeration — but only where the
            // fallback actually enumerates: on a host where it answers with the
            // preview mock, the cache is still the better of the two.
            Ok((resp, stale)) if !resp.rows.is_empty() => {
                if stale {
                    let live = self.fallback.interfaces_snapshot(request.clone());
                    if live.data_source != InterfacesDataSource::FallbackMock {
                        return live;
                    }
                }
                let rows = resp
                    .rows
                    .iter()
                    .map(InterfaceRouteRow::from_wire_dto)
                    .collect::<Vec<_>>();
                // Carry the service's own verdict on the rows: it answers with
                // a deterministic placeholder set when its live enumeration
                // came back empty, and only it knows which happened.
                let data_source = InterfacesDataSource::from_title(&resp.data_source);
                decorate_interface_rows(rows, &request, data_source)
            }
            _ => self.fallback.interfaces_snapshot(request),
        }
    }

    fn rules_snapshot(&self, request: RulesScreenRequest) -> RulesScreenPreviewSnapshot {
        // TODO: issue RulesList with a RulesRouteFilter derived from the request
        // and map RuleRowEntry[] to RuleRowPreview[]; the mock drives the GUI.
        self.fallback.rules_snapshot(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
