//! Transport-neutral IPC protocol layer.
//!
//! The request/response *protocol* — envelope construction, operation-class
//! resolution, `ContractNegotiate` handshake interpretation, response parsing —
//! is identical on every byte carrier, so the Windows named-pipe client and
//! the Unix client ([`crate::client_unix`]) share this one definition instead
//! of duplicating it: the protocol is neutral *policy* (one definition,
//! tested once); the byte carrier + threading are per-OS *mechanism* (named
//! pipe vs `AF_UNIX`).
//!
//! Everything here is pure (no I/O) and used by BOTH the Windows and the Unix
//! client, so nothing is dead code on either target. The transport-generic
//! frame exchanges that drive these helpers over a concrete stream live with
//! their consumer in [`crate::client_unix`].

use serde_json::Value;

use nrr_shared::ipc::IpcOperationName;
use nrr_shared::ipc_payloads::ContractNegotiateClientKind;

use crate::connection::NegotiateInfo;

/// Local protocol version. Mirrors `nrr_service_runtime::IPC_PROTOCOL_VERSION = 1`.
/// Hardcoded here so the client doesn't take a dep on service-runtime.
pub(crate) const CLIENT_PROTOCOL_VERSION: u32 = 1;

/// Outcome of one request/response exchange, delivered back to the caller
/// thread. Neutral: carries only wire types (`Value`, `IpcOperationName`,
/// `IpcErrorCode`).
pub(crate) enum RequestResponse {
    Ok(Value),
    ServerError {
        op: IpcOperationName,
        // Preserve the wire code so the launcher's RPC dispatcher can emit
        // it to the bridge instead of collapsing every server error under
        // "ipc-call-failed".
        code: nrr_shared::ipc_transport::IpcErrorCode,
        message: String,
    },
    BadResponse(String),
    Disconnected,
}

/// Result of interpreting a `ContractNegotiate` response frame. The I/O that
/// produces the frame is per-transport; this classification is not.
pub(crate) enum NegotiateParse {
    Ok(NegotiateInfo),
    ProtocolMismatch { server_version: u32 },
    Unexpected(String),
}

/// Build the request envelope for one operation call.
///
/// `ProductImpactDisableTemporary` is a two-phase operation where dry-run and
/// confirm use DIFFERENT envelope classes (read-snapshot vs safe-disable);
/// this peeks the payload to discriminate. It also threads a top-level
/// `confirmation-token` extracted from the payload's
/// `_envelope_confirmation_token` key — routed to the envelope so callers don't
/// need a separate `call_with_token` overload on the `IpcClient` trait.
pub(crate) fn build_request_envelope(
    operation: IpcOperationName,
    request_id: &str,
    payload: Value,
) -> Value {
    let mut envelope = serde_json::Map::new();
    envelope.insert(
        "protocol-version".into(),
        serde_json::json!(CLIENT_PROTOCOL_VERSION),
    );
    envelope.insert("request-id".into(), serde_json::json!(request_id));
    envelope.insert("operation".into(), serde_json::json!(operation.slug()));
    envelope.insert(
        "operation-class".into(),
        serde_json::json!(operation_class_slug_for_call(operation, &payload)),
    );

    // Promote envelope-level token if present.
    let mut payload_owned = payload.clone();
    if let Some(obj) = payload_owned.as_object_mut() {
        if let Some(token) = obj
            .remove("_envelope_confirmation_token")
            .and_then(|v| v.as_str().map(str::to_string))
        {
            if !token.is_empty() {
                envelope.insert(
                    "confirmation-token".into(),
                    serde_json::Value::String(token),
                );
            }
        }
    }
    envelope.insert("payload".into(), payload_owned);
    Value::Object(envelope)
}

/// What this PROCESS declares itself to be when it shakes hands.
///
/// A property of the binary, not of a connection: the launcher is a GUI, the
/// console is a console, and neither changes its mind at runtime. Declared once
/// at start-up via [`crate::declare_client_kind`]; unset means `Gui`, which is
/// what the launcher (the original and still the common caller) is.
///
/// The declaration can only ever COST capability — the service narrows by it,
/// never widens. On Windows the service proves the same fact from the connecting
/// executable and does not need to be told; on Unix, where peer credentials name
/// the user but not the program, this is the only thing that distinguishes a
/// console from an application.
static DECLARED_CLIENT_KIND: std::sync::OnceLock<ContractNegotiateClientKind> =
    std::sync::OnceLock::new();

/// Declare this process's client kind. First call wins; later calls are ignored,
/// so a library cannot quietly re-label a binary that already introduced itself.
pub fn declare_client_kind(kind: ContractNegotiateClientKind) {
    let _ = DECLARED_CLIENT_KIND.set(kind);
}

fn declared_client_kind() -> ContractNegotiateClientKind {
    *DECLARED_CLIENT_KIND
        .get()
        .unwrap_or(&ContractNegotiateClientKind::Gui)
}

/// Build the `ContractNegotiate` handshake request.
pub(crate) fn build_contract_negotiate(client_version: u32) -> Value {
    let kind = match declared_client_kind() {
        ContractNegotiateClientKind::Gui => "gui",
        ContractNegotiateClientKind::Tray => "tray",
        ContractNegotiateClientKind::Console => "console",
    };
    serde_json::json!({
        "protocol-version": client_version,
        "request-id": "handshake-1",
        "operation": IpcOperationName::ContractNegotiate.slug(),
        "operation-class": "read-snapshot",
        "payload": {
            "client-version": client_version,
            "client-kind": kind,
        },
    })
}

/// Interpret a `ContractNegotiate` response frame into a [`NegotiateParse`].
/// Pure: the caller does the transport I/O and hands the decoded frame here.
pub(crate) fn interpret_negotiate_response(response: &Value) -> NegotiateParse {
    if response.get("ok").and_then(|v| v.as_bool()) == Some(true) {
        // Extract the contract.negotiate body so the GUI's compatibility
        // banner has the protocol/semver pair without a second probe.
        // Best-effort: missing fields collapse to defaults.
        let payload = response.get("payload").cloned().unwrap_or(Value::Null);
        let server_protocol = payload
            .get("server-version")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        let service_version = payload
            .get("service-version")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let session_id = payload
            .get("session-id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        return NegotiateParse::Ok(NegotiateInfo {
            server_protocol,
            service_version,
            session_id,
        });
    }
    // Server may have responded with an InvalidVersion error; surface that.
    if let Some(err) = response.get("error") {
        if err.get("code").and_then(|v| v.as_str()) == Some("InvalidVersion") {
            // Best-effort: try to extract server version from message
            // (format documented as "client speaks vN, service speaks vM").
            let msg = err
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let server_version =
                parse_server_version_from_message(msg).unwrap_or(CLIENT_PROTOCOL_VERSION);
            return NegotiateParse::ProtocolMismatch { server_version };
        }
    }
    NegotiateParse::Unexpected(format!("unexpected handshake response: {response}"))
}

pub(crate) fn parse_server_version_from_message(msg: &str) -> Option<u32> {
    // "service speaks v<N>"
    let needle = "service speaks v";
    let idx = msg.find(needle)?;
    let tail = &msg[idx + needle.len()..];
    let digits: String = tail.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

/// Parse a response envelope frame into a [`RequestResponse`].
pub(crate) fn parse_response(response: &Value) -> RequestResponse {
    let ok = response
        .get("ok")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if ok {
        let payload = response.get("payload").cloned().unwrap_or(Value::Null);
        return RequestResponse::Ok(payload);
    }
    if let Some(err) = response.get("error") {
        let message = err
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("(no message)")
            .to_string();
        // Extract the typed `code` so callers can discriminate
        // `precondition-failed` vs `forbidden` vs `internal` without parsing
        // the message. The wire schema is `IpcErrorCode` serialized in
        // snake_case; fall back to `Internal` when the response is malformed.
        let code = err
            .get("code")
            .and_then(|v| {
                serde_json::from_value::<nrr_shared::ipc_transport::IpcErrorCode>(v.clone()).ok()
            })
            .unwrap_or(nrr_shared::ipc_transport::IpcErrorCode::Internal);
        // The original IpcOperationName isn't echoed in the response; we
        // surface a placeholder. Callers can always inspect the request_id
        // <-> operation mapping themselves.
        return RequestResponse::ServerError {
            op: IpcOperationName::ContractNegotiate,
            code,
            message,
        };
    }
    RequestResponse::BadResponse(format!(
        "response has neither ok=true nor error: {response}"
    ))
}

pub(crate) fn new_request_serial() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    COUNTER.fetch_add(1, Ordering::SeqCst)
}

/// Envelope class for a call — the SAME derivation the service admits by
/// (`nrr_shared::ipc_transport::canonical_operation_class`).
///
/// The client used to carry its own copy of this table, which made the label on
/// the wire an independent opinion; the service now derives the class itself, so
/// a divergent copy here could only ever produce a warning and a confusing
/// envelope. One declaration, both sides.
pub(crate) fn operation_class_slug_for_call(op: IpcOperationName, payload: &Value) -> &'static str {
    nrr_shared::ipc_transport::canonical_operation_class(op, payload).slug()
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_request_envelope_has_required_fields() {
        let env = build_request_envelope(
            IpcOperationName::ServiceHealthGet,
            "req-1",
            serde_json::json!({"k": "v"}),
        );
        assert_eq!(env["protocol-version"], 1);
        assert_eq!(env["request-id"], "req-1");
        assert_eq!(env["operation"], "service.health.get");
        assert_eq!(env["payload"]["k"], "v");
    }

    #[test]
    fn product_impact_disable_dry_run_uses_read_snapshot_class() {
        // Dry-run phase must surface the `read-snapshot` envelope class so
        // the server handler (which strictly checks `operation_class`)
        // accepts the dry-run pass.
        let env = build_request_envelope(
            IpcOperationName::ProductImpactDisableTemporary,
            "req-d1",
            serde_json::json!({"reason": "test", "dry-run": true}),
        );
        assert_eq!(env["operation-class"], "read-snapshot");
        assert_eq!(env["payload"]["dry-run"], true);
        assert!(env.get("confirmation-token").is_none());
    }

    #[test]
    fn product_impact_disable_confirm_uses_safe_disable_class_and_promotes_token() {
        // Confirm phase needs `safe-disable` + the envelope-level
        // confirmation-token. Caller passes the token via the
        // `_envelope_confirmation_token` payload key; the builder strips it and
        // promotes to the envelope root.
        let env = build_request_envelope(
            IpcOperationName::ProductImpactDisableTemporary,
            "req-d2",
            serde_json::json!({
                "reason": "test",
                "dry-run": false,
                "_envelope_confirmation_token": "tok-abc",
            }),
        );
        assert_eq!(env["operation-class"], "safe-disable");
        assert_eq!(env["confirmation-token"], "tok-abc");
        // The synthetic key must NOT leak into payload.
        assert!(env["payload"].get("_envelope_confirmation_token").is_none());
        assert_eq!(env["payload"]["reason"], "test");
    }

    #[test]
    fn envelope_token_promotion_ignores_empty_string() {
        let env = build_request_envelope(
            IpcOperationName::MutationSubmit,
            "req-m1",
            serde_json::json!({"_envelope_confirmation_token": ""}),
        );
        assert!(env.get("confirmation-token").is_none());
    }

    #[test]
    fn handshake_uses_client_version() {
        let req = build_contract_negotiate(1);
        assert_eq!(req["protocol-version"], 1);
        assert_eq!(req["operation"], "contract.negotiate");
    }

    #[test]
    fn parse_server_version_from_message_matches_router_format() {
        let msg = "client speaks v1, service speaks v3";
        assert_eq!(parse_server_version_from_message(msg), Some(3));
    }

    #[test]
    fn parse_server_version_returns_none_for_unparseable() {
        assert_eq!(parse_server_version_from_message("garbage"), None);
    }

    #[test]
    fn interpret_negotiate_ok_extracts_info() {
        let r = serde_json::json!({
            "ok": true,
            "payload": {
                "server-version": 1,
                "service-version": "0.1.0",
                "session-id": "sess-9",
            }
        });
        match interpret_negotiate_response(&r) {
            NegotiateParse::Ok(info) => {
                assert_eq!(info.server_protocol, 1);
                assert_eq!(info.service_version, "0.1.0");
                assert_eq!(info.session_id, "sess-9");
            }
            _ => panic!("expected Ok"),
        }
    }

    #[test]
    fn interpret_negotiate_version_mismatch() {
        let r = serde_json::json!({
            "ok": false,
            "error": {
                "code": "InvalidVersion",
                "message": "client speaks v1, service speaks v4",
            }
        });
        match interpret_negotiate_response(&r) {
            NegotiateParse::ProtocolMismatch { server_version } => assert_eq!(server_version, 4),
            _ => panic!("expected ProtocolMismatch"),
        }
    }

    #[test]
    fn interpret_negotiate_unexpected_frame() {
        let r = serde_json::json!({ "ok": false });
        assert!(matches!(
            interpret_negotiate_response(&r),
            NegotiateParse::Unexpected(_)
        ));
    }

    #[test]
    fn parse_response_ok_extracts_payload() {
        let r = serde_json::json!({
            "ok": true,
            "payload": { "x": 42 }
        });
        match parse_response(&r) {
            RequestResponse::Ok(p) => assert_eq!(p["x"], 42),
            other => panic!("expected Ok, got {:?}", debug_response(&other)),
        }
    }

    #[test]
    fn parse_response_error_extracts_message_and_code() {
        // `IpcErrorCode` is serde-encoded as snake_case — verify the parser
        // extracts both the typed code and the message.
        let r = serde_json::json!({
            "ok": false,
            "error": { "code": "forbidden", "message": "no admin" }
        });
        match parse_response(&r) {
            RequestResponse::ServerError { code, message, .. } => {
                assert_eq!(message, "no admin");
                assert_eq!(code, nrr_shared::ipc_transport::IpcErrorCode::Forbidden);
            }
            other => panic!("expected ServerError, got {:?}", debug_response(&other)),
        }
    }

    #[test]
    fn parse_response_error_falls_back_to_internal_on_unknown_code() {
        // An older / broken server emits an unknown code; we want graceful
        // degradation rather than a hard panic.
        let r = serde_json::json!({
            "ok": false,
            "error": { "code": "future-code", "message": "huh" }
        });
        match parse_response(&r) {
            RequestResponse::ServerError { code, message, .. } => {
                assert_eq!(code, nrr_shared::ipc_transport::IpcErrorCode::Internal);
                assert_eq!(message, "huh");
            }
            other => panic!("expected ServerError, got {:?}", debug_response(&other)),
        }
    }

    #[test]
    fn parse_response_bad_returns_bad_response() {
        let r = serde_json::json!({ "ok": false });
        assert!(matches!(
            parse_response(&r),
            RequestResponse::BadResponse(_)
        ));
    }

    #[test]
    fn operation_class_slug_covers_every_operation() {
        for op in IpcOperationName::ALL {
            let slug = operation_class_slug_for_call(op, &serde_json::json!({}));
            assert!(
                !slug.is_empty(),
                "operation {} has empty class slug",
                op.slug()
            );
        }
    }

    #[test]
    fn interfaces_refresh_request_uses_diagnostic_query_class() {
        // Regression pin: the refresh (adapter re-enumeration + external-IP
        // probe) must dispatch outside the mutation queue — a policy apply
        // holding the queue would push the call past its deadline — and must
        // never route through a class that drags an elevation prompt.
        assert_eq!(
            operation_class_slug_for_call(
                IpcOperationName::InterfacesRefreshRequest,
                &serde_json::json!({})
            ),
            "diagnostic-query",
        );
    }

    #[test]
    fn mutation_submit_dry_run_routes_to_read_snapshot() {
        // Dry-run must NOT carry the `mutation-request` class because the
        // router would pre-reject it with PreconditionFailed (no confirmation
        // token yet — dry-run is the very thing that mints one).
        let payload = serde_json::json!({
            "mutation-kind": "rules-update",
            "payload": {},
            "dry-run": true,
        });
        assert_eq!(
            operation_class_slug_for_call(IpcOperationName::MutationSubmit, &payload),
            "read-snapshot",
        );
    }

    #[test]
    fn mutation_submit_confirm_rules_update_routes_to_user_scoped_mutation() {
        // Confirm of a rules edit carries the token but is per-principal —
        // `user-scoped-mutation` (two-phase, NOT elevation-gated).
        let payload = serde_json::json!({
            "mutation-kind": "rules-update",
            "payload": {},
            "dry-run": false,
        });
        assert_eq!(
            operation_class_slug_for_call(IpcOperationName::MutationSubmit, &payload),
            "user-scoped-mutation",
        );
    }

    #[test]
    fn mutation_submit_confirm_preset_import_routes_to_user_scoped_mutation() {
        // Preset import is the other per-principal edit path, so it confirms
        // as `user-scoped-mutation` too.
        let payload = serde_json::json!({
            "mutation-kind": "preset-import",
            "payload": {},
            "dry-run": false,
        });
        assert_eq!(
            operation_class_slug_for_call(IpcOperationName::MutationSubmit, &payload),
            "user-scoped-mutation",
        );
    }

    #[test]
    fn mutation_submit_confirm_admin_baseline_routes_to_mutation_request() {
        // An admin "set baseline" edit carries `admin-baseline: true` in the
        // inner payload → elevated `mutation-request` (the broker relays the
        // UAC), NOT the per-principal `user-scoped-mutation`.
        let payload = serde_json::json!({
            "mutation-kind": "rules-update",
            "payload": { "rules-json": "{}", "admin-baseline": true },
            "dry-run": false,
        });
        assert_eq!(
            operation_class_slug_for_call(IpcOperationName::MutationSubmit, &payload),
            "mutation-request",
        );
    }

    #[test]
    fn mutation_submit_dry_run_admin_baseline_still_read_snapshot() {
        // The dry-run phase is always `read-snapshot` (it mints the token)
        // regardless of the admin-baseline flag.
        let payload = serde_json::json!({
            "mutation-kind": "rules-update",
            "payload": { "rules-json": "{}", "admin-baseline": true },
            "dry-run": true,
        });
        assert_eq!(
            operation_class_slug_for_call(IpcOperationName::MutationSubmit, &payload),
            "read-snapshot",
        );
    }

    #[test]
    fn mutation_submit_confirm_reset_to_baseline_routes_to_user_scoped_mutation() {
        // "Reset to baseline" discards the caller's OWN per-SID rules — a
        // user-scoped mutation, no elevation.
        let payload = serde_json::json!({
            "mutation-kind": "rules-reset-to-baseline",
            "payload": {},
            "dry-run": false,
        });
        assert_eq!(
            operation_class_slug_for_call(IpcOperationName::MutationSubmit, &payload),
            "user-scoped-mutation",
        );
    }

    #[test]
    fn mutation_submit_confirm_non_rules_kind_stays_mutation_request() {
        // Only rules/preset edits are per-principal. Service-global mutations
        // (e.g. security-alert ack) keep the elevated `mutation-request` class.
        let payload = serde_json::json!({
            "mutation-kind": "security-alert-ack",
            "payload": { "alert-id": "alt-1" },
            "dry-run": false,
        });
        assert_eq!(
            operation_class_slug_for_call(IpcOperationName::MutationSubmit, &payload),
            "mutation-request",
        );
    }

    #[test]
    fn mutation_submit_without_dry_run_field_defaults_to_confirm_class() {
        // Defensive: an absent `dry-run` field defaults to false (confirm) so a
        // malformed client cannot accidentally bypass the token gate by omitting
        // the flag. For a rules edit the confirm class is the per-principal
        // `user-scoped-mutation`.
        let payload = serde_json::json!({
            "mutation-kind": "rules-update",
            "payload": {},
        });
        assert_eq!(
            operation_class_slug_for_call(IpcOperationName::MutationSubmit, &payload),
            "user-scoped-mutation",
        );
    }

    fn debug_response(r: &RequestResponse) -> &'static str {
        match r {
            RequestResponse::Ok(_) => "Ok",
            RequestResponse::ServerError { .. } => "ServerError",
            RequestResponse::BadResponse(_) => "BadResponse",
            RequestResponse::Disconnected => "Disconnected",
        }
    }
}
