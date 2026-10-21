//! `route.vpn-gateways.set` handler.
//!
//! Replaces the caller's confirmed VPN gateways (see
//! [`crate::vpn_gateway_confirm`]). User-scoped: the list opens a hole in that
//! user's protection only. Checked before it is audited, and refused whole on
//! one bad entry. A stored change recompiles the caller at once, so a VPN
//! waiting on its handshake connects without a reconnect.

use std::sync::Arc;

use crate::ipc::{
    CheckedIpcHandler, HandlerOutcome, IpcError, IpcErrorCode, IpcRequestContext,
    IpcRequestEnvelope, Prechecked,
};
use crate::ipc_handlers::providers::RoutePolicyApplyTrigger;
use crate::vpn_gateway_confirm::{checked_gateways, VpnGatewayBook};
use nrr_shared::ipc_payloads::{
    RouteVpnGatewaysSetRequest, RouteVpnGatewaysSetResponse, VpnGatewayDto,
};

pub struct RouteVpnGatewaysSetHandler {
    book: &'static VpnGatewayBook,
    apply_trigger: Option<Arc<dyn RoutePolicyApplyTrigger>>,
}

impl RouteVpnGatewaysSetHandler {
    pub fn new(
        book: &'static VpnGatewayBook,
        apply_trigger: Option<Arc<dyn RoutePolicyApplyTrigger>>,
    ) -> Self {
        Self {
            book,
            apply_trigger,
        }
    }
}

impl CheckedIpcHandler for RouteVpnGatewaysSetHandler {
    type Checked = Vec<VpnGatewayDto>;

    fn precheck(
        &self,
        request: &IpcRequestEnvelope,
        ctx: &IpcRequestContext,
    ) -> Result<Self::Checked, IpcError> {
        if ctx.caller_stored().is_empty() {
            return Err(IpcError {
                code: IpcErrorCode::Internal,
                message: "caller SID unavailable; transport must populate IpcRequestContext.caller_stored()".into(),
                diagnostics_id: None,
            });
        }
        let req: RouteVpnGatewaysSetRequest = serde_json::from_value(request.payload.clone())
            .map_err(|e| IpcError {
                code: IpcErrorCode::MalformedRequest,
                message: format!("route.vpn-gateways.set payload invalid: {e}"),
                diagnostics_id: None,
            })?;
        checked_gateways(&req).map_err(|message| IpcError {
            code: IpcErrorCode::PreconditionFailed,
            message,
            diagnostics_id: None,
        })
    }

    fn execute(
        &self,
        checked: Prechecked<Self::Checked>,
        _request: &IpcRequestEnvelope,
        ctx: &IpcRequestContext,
    ) -> HandlerOutcome {
        let sid = ctx.caller_stored();
        let stored = self
            .book
            .replace_confirmed(sid, checked.into_inner())
            .map_err(|message| IpcError {
                code: IpcErrorCode::Internal,
                message,
                diagnostics_id: None,
            })?;
        if let Some(trigger) = self.apply_trigger.as_ref() {
            trigger.on_policy_changed(sid);
        }
        serde_json::to_value(RouteVpnGatewaysSetResponse { gateways: stored }).map_err(|e| {
            IpcError {
                code: IpcErrorCode::Internal,
                message: format!("route.vpn-gateways.set response serialisation failed: {e}"),
                diagnostics_id: None,
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::{IpcHandler, IpcOperationClass, IPC_PROTOCOL_VERSION};
    use nrr_shared::ipc::{IpcClientProfile, IpcOperationName};
    use std::sync::{Mutex, OnceLock};

    struct RecordingTrigger(Mutex<Vec<String>>);
    impl RoutePolicyApplyTrigger for RecordingTrigger {
        fn on_policy_changed(&self, sid: &str) {
            self.0.lock().unwrap().push(sid.to_string());
        }
    }

    fn book() -> &'static VpnGatewayBook {
        static BOOK: OnceLock<VpnGatewayBook> = OnceLock::new();
        BOOK.get_or_init(VpnGatewayBook::new)
    }

    fn ctx(sid: &str) -> IpcRequestContext {
        IpcRequestContext {
            client_profile: IpcClientProfile::GuiInteractive,
            caller_is_elevated: false,
            caller_principal: crate::UserPrincipal::from_windows_sid(sid).ok(),
            caller_pid: None,
        }
    }

    fn req(payload: serde_json::Value) -> IpcRequestEnvelope {
        IpcRequestEnvelope {
            protocol_version: IPC_PROTOCOL_VERSION,
            request_id: "r-1".into(),
            correlation_id: None,
            operation: IpcOperationName::RouteVpnGatewaysSet,
            operation_class: IpcOperationClass::UserScopedConfiguration,
            confirmation_token: None,
            payload,
        }
    }

    #[test]
    fn a_valid_list_is_stored_for_the_caller_and_recompiles_them() {
        let trigger = Arc::new(RecordingTrigger(Mutex::new(Vec::new())));
        let h = RouteVpnGatewaysSetHandler::new(
            book(),
            Some(Arc::clone(&trigger) as Arc<dyn RoutePolicyApplyTrigger>),
        );
        let sid = "S-1-5-21-91-92-93-1001";
        let value = h
            .handle(
                &req(serde_json::json!({
                    "gateways": [{ "address": "198.51.100.20", "program": "" }]
                })),
                &ctx(sid),
            )
            .expect("stored");
        let parsed: RouteVpnGatewaysSetResponse = serde_json::from_value(value).unwrap();
        assert_eq!(parsed.gateways.len(), 1);
        assert_eq!(
            book().confirmed_addresses(sid),
            vec!["198.51.100.20".parse::<std::net::IpAddr>().unwrap()]
        );
        assert_eq!(trigger.0.lock().unwrap().as_slice(), &[sid.to_string()]);
    }

    /// Refused in the precheck: nothing reaches the book, the audit or the
    /// recompile.
    #[test]
    fn a_bad_entry_is_refused_before_anything_is_written() {
        let trigger = Arc::new(RecordingTrigger(Mutex::new(Vec::new())));
        let h = RouteVpnGatewaysSetHandler::new(
            book(),
            Some(Arc::clone(&trigger) as Arc<dyn RoutePolicyApplyTrigger>),
        );
        let sid = "S-1-5-21-91-92-93-1002";
        let request = req(serde_json::json!({
            "gateways": [{ "address": "127.0.0.1", "program": "" }]
        }));
        let err = h.precheck(&request, &ctx(sid)).expect_err("refused");
        assert_eq!(err.code, IpcErrorCode::PreconditionFailed);
        assert!(h.handle(&request, &ctx(sid)).is_err());
        assert!(book().confirmed_addresses(sid).is_empty());
        assert!(trigger.0.lock().unwrap().is_empty());
    }
}
