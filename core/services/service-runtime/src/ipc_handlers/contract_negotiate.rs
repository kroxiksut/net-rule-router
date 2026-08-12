//! `ContractNegotiate` handler — the handshake the GUI/Tray performs
//! immediately after connecting to the named pipe.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

use crate::ipc::{
    HandlerOutcome, IpcError, IpcErrorCode, IpcHandler, IpcRequestContext, IpcRequestEnvelope,
    IPC_PROTOCOL_VERSION,
};
use crate::ipc_handlers::payloads::{ContractNegotiateRequest, ContractNegotiateResponse};

/// Lowest client protocol version this service binary still recognises.
/// Bumped only on hard wire-format breaks; today we only ship v1.
pub const MIN_SUPPORTED_CLIENT_VERSION: u32 = 1;

/// Semver of the running service binary, configured
/// by the `nrr-windows-service` crate at startup via
/// [`set_service_binary_version`]. We can't use `env!("CARGO_PKG_VERSION")`
/// directly here because this crate (`nrr-service-runtime`) is a
/// library; its `CARGO_PKG_VERSION` is its own, not the binary's.
///
/// Reads return `""` when the binary hasn't called the setter — the
/// GUI degrades to showing only protocol numbers in the banner.
static SERVICE_BINARY_VERSION: OnceLock<&'static str> = OnceLock::new();

/// Called once by `nrr-windows-service::main.rs` (or any other binary
/// that hosts the IPC runtime) before the handshake handler runs.
/// Re-calls are silently ignored — `OnceLock` rejects them; the first
/// setter wins so test harnesses pinning a fake version stay
/// deterministic.
pub fn set_service_binary_version(version: &'static str) {
    let _ = SERVICE_BINARY_VERSION.set(version);
}

/// Snapshot the configured binary version. Empty string when the
/// setter has never been called.
pub fn service_binary_version() -> &'static str {
    SERVICE_BINARY_VERSION.get().copied().unwrap_or("")
}

/// Monotonic per-process session id source. Sessions are scoped to a
/// single named-pipe connection lifetime — pipe drop invalidates the
/// session, so collisions across service restarts are not a concern.
static SESSION_COUNTER: AtomicU64 = AtomicU64::new(1);

fn next_session_id() -> String {
    let n = SESSION_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("sess-{n:016x}")
}

pub struct ContractNegotiateHandler;

impl ContractNegotiateHandler {
    pub fn new() -> Self {
        Self
    }
}

impl Default for ContractNegotiateHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl IpcHandler for ContractNegotiateHandler {
    fn handle(&self, request: &IpcRequestEnvelope, _ctx: &IpcRequestContext) -> HandlerOutcome {
        let req: ContractNegotiateRequest = serde_json::from_value(request.payload.clone())
            .map_err(|e| IpcError {
                code: IpcErrorCode::MalformedRequest,
                message: format!("contract.negotiate payload invalid: {e}"),
                diagnostics_id: None,
            })?;

        if req.client_version < MIN_SUPPORTED_CLIENT_VERSION {
            return Err(IpcError {
                code: IpcErrorCode::InvalidVersion,
                message: format!(
                    "client v{} predates the minimum supported v{}",
                    req.client_version, MIN_SUPPORTED_CLIENT_VERSION
                ),
                diagnostics_id: None,
            });
        }

        let resp = ContractNegotiateResponse {
            server_version: IPC_PROTOCOL_VERSION,
            negotiated_protocol: IPC_PROTOCOL_VERSION,
            session_id: next_session_id(),
            // Semver pulled from the OnceLock the
            // service binary configures at startup. Empty when the
            // setter wasn't called (test harnesses / older callers).
            service_version: service_binary_version().to_string(),
        };
        serde_json::to_value(resp).map_err(|e| IpcError {
            code: IpcErrorCode::Internal,
            message: format!("contract.negotiate response serialisation failed: {e}"),
            diagnostics_id: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::IpcOperationClass;
    use nrr_shared::ipc::{IpcClientProfile, IpcOperationName};

    fn ctx() -> IpcRequestContext {
        IpcRequestContext {
            client_profile: IpcClientProfile::GuiInteractive,
            caller_is_elevated: false,
            caller_principal: None,
        }
    }

    fn req(payload: serde_json::Value) -> IpcRequestEnvelope {
        IpcRequestEnvelope {
            protocol_version: IPC_PROTOCOL_VERSION,
            request_id: "r-cn".into(),
            correlation_id: None,
            operation: IpcOperationName::ContractNegotiate,
            operation_class: IpcOperationClass::ReadSnapshot,
            confirmation_token: None,
            payload,
        }
    }

    #[test]
    fn returns_server_version_and_session_id_on_happy_path() {
        let h = ContractNegotiateHandler::new();
        let resp = h
            .handle(
                &req(serde_json::json!({
                    "client-version": 1,
                    "client-kind": "gui",
                })),
                &ctx(),
            )
            .expect("happy path");
        let parsed: ContractNegotiateResponse = serde_json::from_value(resp).unwrap();
        assert_eq!(parsed.server_version, IPC_PROTOCOL_VERSION);
        assert_eq!(parsed.negotiated_protocol, IPC_PROTOCOL_VERSION);
        assert!(parsed.session_id.starts_with("sess-"));
    }

    #[test]
    fn rejects_clients_below_minimum_version() {
        let h = ContractNegotiateHandler::new();
        let err = h
            .handle(
                &req(serde_json::json!({
                    "client-version": 0,
                    "client-kind": "tray",
                })),
                &ctx(),
            )
            .expect_err("must reject");
        assert_eq!(err.code, IpcErrorCode::InvalidVersion);
    }

    #[test]
    fn malformed_payload_returns_malformed_request() {
        let h = ContractNegotiateHandler::new();
        let err = h
            .handle(
                &req(serde_json::json!({ "client-version": "not-a-number" })),
                &ctx(),
            )
            .expect_err("must reject");
        assert_eq!(err.code, IpcErrorCode::MalformedRequest);
    }

    #[test]
    fn session_ids_are_unique_per_call() {
        let h = ContractNegotiateHandler::new();
        let payload = || serde_json::json!({ "client-version": 1, "client-kind": "gui" });
        let r1: ContractNegotiateResponse =
            serde_json::from_value(h.handle(&req(payload()), &ctx()).unwrap()).unwrap();
        let r2: ContractNegotiateResponse =
            serde_json::from_value(h.handle(&req(payload()), &ctx()).unwrap()).unwrap();
        assert_ne!(r1.session_id, r2.session_id);
    }
}
