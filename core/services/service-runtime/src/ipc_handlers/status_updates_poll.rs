//! `StatusUpdatesPoll` handler — **deprecated by design**.
//!
//! The IPC catalogue keeps the operation slot reserved so a future
//! fallback path stays available, but the production transport for
//! status-update events is `StatusUpdatesSubscribe` (push).
//! Calling `StatusUpdatesPoll` always surfaces `RecoveryRequired` with
//! a stable migration message so a misconfigured client surfaces the
//! issue immediately rather than silently spinning on no events.
//!
//! The handler does not write audit, does not consume a token, and has
//! no side effects.

use crate::ipc::{
    HandlerOutcome, IpcError, IpcErrorCode, IpcHandler, IpcRequestContext, IpcRequestEnvelope,
};

/// Stable English message the client logs / displays. Pinned because
/// downstream tooling may match on it during deprecation tracking.
pub const STATUS_UPDATES_POLL_DEPRECATION_MESSAGE: &str =
    "polling deprecated; use status.updates.subscribe (block 16.3 phase D)";

#[derive(Default)]
pub struct StatusUpdatesPollHandler;

impl StatusUpdatesPollHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IpcHandler for StatusUpdatesPollHandler {
    fn handle(&self, _request: &IpcRequestEnvelope, _ctx: &IpcRequestContext) -> HandlerOutcome {
        Err(IpcError {
            code: IpcErrorCode::RecoveryRequired,
            message: STATUS_UPDATES_POLL_DEPRECATION_MESSAGE.into(),
            diagnostics_id: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::{IpcOperationClass, IPC_PROTOCOL_VERSION};
    use nrr_shared::ipc::{IpcClientProfile, IpcOperationName};

    #[test]
    fn always_returns_recovery_required_with_deprecation_message() {
        let h = StatusUpdatesPollHandler::new();
        let req = IpcRequestEnvelope {
            protocol_version: IPC_PROTOCOL_VERSION,
            request_id: "r-poll".into(),
            correlation_id: None,
            operation: IpcOperationName::StatusUpdatesPoll,
            operation_class: IpcOperationClass::ReadSnapshot,
            confirmation_token: None,
            payload: serde_json::json!({ "anything": "ignored" }),
        };
        let ctx = IpcRequestContext {
            client_profile: IpcClientProfile::GuiInteractive,
            caller_is_elevated: false,
            caller_principal: None,
        };
        let err = h.handle(&req, &ctx).expect_err("always errors");
        assert_eq!(err.code, IpcErrorCode::RecoveryRequired);
        assert_eq!(err.message, STATUS_UPDATES_POLL_DEPRECATION_MESSAGE);
    }
}
