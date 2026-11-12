use std::sync::Arc;

use crate::dns_compatibility::DnsCompatibilityCenter;
use crate::ipc::{
    CheckedIpcHandler, HandlerOutcome, IpcError, IpcErrorCode, IpcRequestContext,
    IpcRequestEnvelope, Prechecked,
};
use nrr_shared::ipc_payloads::DnsCompatibilityRecheckRequest;

pub struct DnsCompatibilityRecheckHandler {
    center: Arc<DnsCompatibilityCenter>,
}

impl DnsCompatibilityRecheckHandler {
    pub fn new(center: Arc<DnsCompatibilityCenter>) -> Self {
        Self { center }
    }
}

impl CheckedIpcHandler for DnsCompatibilityRecheckHandler {
    type Checked = DnsCompatibilityRecheckRequest;

    fn precheck(
        &self,
        request: &IpcRequestEnvelope,
        ctx: &IpcRequestContext,
    ) -> Result<Self::Checked, IpcError> {
        if ctx.caller_stored().is_empty() {
            return Err(IpcError {
                code: IpcErrorCode::Forbidden,
                message: "DNS compatibility checks require an identified caller".to_owned(),
                diagnostics_id: None,
            });
        }
        if !request.payload.is_object() {
            return Err(IpcError {
                code: IpcErrorCode::MalformedRequest,
                message: "DNS compatibility checks require an object payload".to_owned(),
                diagnostics_id: None,
            });
        }
        serde_json::from_value(request.payload.clone()).map_err(|error| IpcError {
            code: IpcErrorCode::MalformedRequest,
            message: format!("invalid DNS compatibility check: {error}"),
            diagnostics_id: None,
        })
    }

    fn execute(
        &self,
        _checked: Prechecked<Self::Checked>,
        _request: &IpcRequestEnvelope,
        ctx: &IpcRequestContext,
    ) -> HandlerOutcome {
        if !self.center.request_recheck(ctx.caller_stored()) {
            return Err(IpcError {
                code: IpcErrorCode::BusyConflict,
                message: "a DNS compatibility check is running or cooling down".to_owned(),
                diagnostics_id: None,
            });
        }
        serde_json::to_value(self.center.snapshot(
            Some(ctx.caller_stored()),
            crate::dns_compatibility::now_ms(),
        ))
        .map_err(|error| IpcError {
            code: IpcErrorCode::Internal,
            message: format!("DNS compatibility response could not be encoded: {error}"),
            diagnostics_id: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::{IpcOperationClass, IPC_PROTOCOL_VERSION};
    use nrr_shared::ipc::{IpcClientProfile, IpcOperationName};
    use serde_json::json;

    fn context(identified: bool) -> IpcRequestContext {
        IpcRequestContext {
            client_profile: IpcClientProfile::GuiInteractive,
            caller_is_elevated: false,
            caller_principal: identified.then(|| crate::UserPrincipal::from_linux_uid(1000)),
            caller_pid: None,
        }
    }

    fn request(payload: serde_json::Value) -> IpcRequestEnvelope {
        IpcRequestEnvelope {
            protocol_version: IPC_PROTOCOL_VERSION,
            request_id: "dns-check".to_owned(),
            correlation_id: None,
            operation: IpcOperationName::DnsCompatibilityRecheck,
            operation_class: IpcOperationClass::DiagnosticAction,
            confirmation_token: None,
            payload,
        }
    }

    #[test]
    fn a_peer_cannot_check_another_user_or_supply_a_profile_path() {
        let center = Arc::new(DnsCompatibilityCenter::default());
        let handler = DnsCompatibilityRecheckHandler::new(Arc::clone(&center));
        for payload in [
            json!({"sid":"another-user"}),
            json!({"path":"/another/profile"}),
            json!([]),
        ] {
            let result = handler.precheck(&request(payload), &context(true));
            assert!(matches!(
                result,
                Err(IpcError {
                    code: IpcErrorCode::MalformedRequest,
                    ..
                })
            ));
        }
        let state = center.snapshot(Some(context(true).caller_stored()), 0);
        assert!(state.last_checked_ms.is_none());
        assert!(!state.recovery_pending);
    }

    #[test]
    fn an_unidentified_peer_cannot_trigger_dns_recovery() {
        let handler =
            DnsCompatibilityRecheckHandler::new(Arc::new(DnsCompatibilityCenter::default()));
        assert!(matches!(
            handler.precheck(&request(json!({})), &context(false)),
            Err(IpcError {
                code: IpcErrorCode::Forbidden,
                ..
            })
        ));
    }
}
