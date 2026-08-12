//! Wire contract integration tests.
//!
//! Verifies that the JSON envelopes the client emits (via internal
//! builders, exposed for tests) deserialize correctly into the server
//! `IpcRequestEnvelope` and round-trip through `IpcRouter::dispatch`.
//!
//! This is the cross-platform equivalent of "client speaks the same
//! protocol as the server". It catches regressions in either side
//! without needing a real Windows pipe.

use std::sync::Arc;

use nrr_ipc_client::wire::{read_frame, write_frame};
use nrr_service_runtime::{
    HandlerOutcome, IpcAuditEmitter, IpcHandler, IpcHandlerRegistry, IpcOperationClass,
    IpcRequestContext, IpcRequestEnvelope, IpcResponseEnvelope, IpcRouter, NoopIpcAuditEmitter,
    IPC_PROTOCOL_VERSION,
};
use nrr_shared::ipc::{IpcClientProfile, IpcOperationName};

struct EchoHandler;
impl IpcHandler for EchoHandler {
    fn handle(&self, request: &IpcRequestEnvelope, _ctx: &IpcRequestContext) -> HandlerOutcome {
        Ok(serde_json::json!({
            "echoed_op": request.operation.slug(),
            "echoed_request_id": request.request_id,
        }))
    }
}

fn make_router() -> IpcRouter {
    let mut reg = IpcHandlerRegistry::new();
    reg.register(IpcOperationName::ServiceHealthGet, EchoHandler);
    reg.register(IpcOperationName::ContractNegotiate, EchoHandler);
    let audit: Arc<dyn IpcAuditEmitter> = Arc::new(NoopIpcAuditEmitter);
    IpcRouter::new(reg, audit, 1)
}

fn elevated_gui() -> IpcRequestContext {
    IpcRequestContext {
        client_profile: IpcClientProfile::GuiInteractive,
        caller_is_elevated: true,
        // `caller_principal: Option<UserPrincipal>` is the neutral
        // replacement for the old `caller_sid: String`. `None` = unattributed,
        // matching the old empty SID.
        caller_principal: None,
    }
}

/// Build a JSON envelope in the same shape the client's
/// `build_request_envelope` produces.
fn client_style_request(op: IpcOperationName, request_id: &str) -> serde_json::Value {
    serde_json::json!({
        "protocol-version": IPC_PROTOCOL_VERSION,
        "request-id": request_id,
        "operation": op.slug(),
        "operation-class": "read-snapshot",
        "payload": {},
    })
}

#[test]
fn client_request_envelope_deserializes_into_server_envelope() {
    let json = client_style_request(IpcOperationName::ServiceHealthGet, "req-1");
    let env: IpcRequestEnvelope = serde_json::from_value(json).expect("deserialize");
    assert_eq!(env.protocol_version, IPC_PROTOCOL_VERSION);
    assert_eq!(env.request_id, "req-1");
    assert_eq!(env.operation, IpcOperationName::ServiceHealthGet);
    assert_eq!(env.operation_class, IpcOperationClass::ReadSnapshot);
}

#[test]
fn client_request_dispatched_through_router_returns_ok() {
    let router = make_router();
    let json = client_style_request(IpcOperationName::ServiceHealthGet, "req-2");
    let env: IpcRequestEnvelope = serde_json::from_value(json).expect("deserialize");
    let response = router.dispatch(env, elevated_gui());
    assert!(response.ok);
    assert_eq!(response.request_id, "req-2");
    let payload = response.payload.expect("payload");
    assert_eq!(payload["echoed_op"], "service.health.get");
    assert_eq!(payload["echoed_request_id"], "req-2");
}

#[test]
fn server_response_envelope_serializes_with_fields_client_expects() {
    let router = make_router();
    let json = client_style_request(IpcOperationName::ServiceHealthGet, "req-3");
    let env: IpcRequestEnvelope = serde_json::from_value(json).expect("deserialize");
    let response = router.dispatch(env, elevated_gui());
    let serialized = serde_json::to_value(&response).expect("serialize");
    // Client parses these fields out of the response — must be present.
    assert_eq!(serialized["ok"], true);
    assert!(serialized.get("request-id").is_some());
    assert!(serialized.get("payload").is_some());
}

#[test]
fn wire_codec_roundtrips_client_request_through_pipe_buffers() {
    let json = client_style_request(IpcOperationName::ServiceHealthGet, "req-4");
    let env: IpcRequestEnvelope = serde_json::from_value(json).expect("deserialize");

    let mut buf: Vec<u8> = Vec::new();
    write_frame(&mut buf, &env).expect("write");

    let mut cursor = std::io::Cursor::new(buf);
    let decoded: IpcRequestEnvelope = read_frame(&mut cursor).expect("read");
    assert_eq!(decoded.request_id, env.request_id);
    assert_eq!(decoded.operation, env.operation);
}

#[test]
fn invalid_protocol_version_in_client_envelope_rejected_by_router() {
    let router = make_router();
    let mut json = client_style_request(IpcOperationName::ServiceHealthGet, "req-5");
    json["protocol-version"] = serde_json::json!(999);
    let env: IpcRequestEnvelope = serde_json::from_value(json).expect("deserialize");
    let response = router.dispatch(env, elevated_gui());
    assert!(!response.ok);
    let err = response.error.expect("error");
    assert_eq!(err.code, nrr_service_runtime::IpcErrorCode::InvalidVersion);
}

#[test]
fn full_pipe_roundtrip_through_in_memory_buffers() {
    let router = make_router();

    // Client side: build + write envelope
    let json = client_style_request(IpcOperationName::ServiceHealthGet, "req-6");
    let req_env: IpcRequestEnvelope = serde_json::from_value(json).expect("deserialize");

    let mut wire: Vec<u8> = Vec::new();
    write_frame(&mut wire, &req_env).expect("client writes request");

    // Server side: read frame, dispatch, write response
    let mut cursor_a = std::io::Cursor::new(wire);
    let received_req: IpcRequestEnvelope = read_frame(&mut cursor_a).expect("server reads request");

    let response = router.dispatch(received_req, elevated_gui());

    let mut response_wire: Vec<u8> = Vec::new();
    write_frame(&mut response_wire, &response).expect("server writes response");

    // Client side: read response back
    let mut cursor_b = std::io::Cursor::new(response_wire);
    let received_resp: IpcResponseEnvelope =
        read_frame(&mut cursor_b).expect("client reads response");

    assert!(received_resp.ok);
    assert_eq!(received_resp.request_id, "req-6");
}
