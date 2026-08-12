//! `third-party.components.list` handler.
//!
//! Reports the third-party binaries this build ships, each with its publisher,
//! licence and a LIVE integrity check of the copy on disk (path, SHA-256,
//! signature). The service answers rather than the GUI because the platform
//! ports live here — and because the service is the process that actually loads
//! the driver, so its view is the authoritative one.
//!
//! Read-only in the strict sense: it hashes a file and inspects a signature,
//! and changes nothing. Platforms that ship no third-party binary (Linux and
//! macOS, whose kernels provide TUN natively) return no binary rows at all —
//! only the attribution-only assets, which are part of every build. So the
//! Windows-only driver never appears where it is not shipped.

use std::sync::Arc;

use nrr_platform_api::third_party::{ThirdPartyComponentStatus, ThirdPartyIntegrityPort};
use nrr_shared::ipc_payloads::{ThirdPartyComponentsListRequest, ThirdPartyComponentsListResponse};

use crate::ipc::{
    HandlerOutcome, IpcError, IpcErrorCode, IpcHandler, IpcRequestContext, IpcRequestEnvelope,
};

const OP: &str = "third-party.components.list";

pub struct ThirdPartyComponentsListHandler {
    integrity: Arc<dyn ThirdPartyIntegrityPort>,
}

impl ThirdPartyComponentsListHandler {
    pub fn new(integrity: Arc<dyn ThirdPartyIntegrityPort>) -> Self {
        Self { integrity }
    }
}

impl IpcHandler for ThirdPartyComponentsListHandler {
    fn handle(&self, request: &IpcRequestEnvelope, _ctx: &IpcRequestContext) -> HandlerOutcome {
        // The request carries no parameters today; still reject a malformed
        // payload rather than ignoring it, so a client bug surfaces here
        // instead of silently doing something else later.
        if !request.payload.is_null() {
            let _: ThirdPartyComponentsListRequest =
                serde_json::from_value(request.payload.clone()).map_err(|e| IpcError {
                    code: IpcErrorCode::MalformedRequest,
                    message: format!("{OP} payload invalid: {e}"),
                    diagnostics_id: None,
                })?;
        }
        // Verifiable binaries first (they carry a live integrity verdict the
        // user may need to act on), then the attribution-only assets, which are
        // present in every build on every OS.
        let mut components = self.integrity.inspect_components();
        components.extend(ThirdPartyComponentStatus::asset_components());
        let response = ThirdPartyComponentsListResponse { components };
        serde_json::to_value(response).map_err(|e| IpcError {
            code: IpcErrorCode::Internal,
            message: format!("{OP}: response serialisation: {e}"),
            diagnostics_id: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_platform_api::third_party::{
        IntegrityVerdict, MockThirdPartyIntegrity, NoopThirdPartyIntegrity, WINTUN_COMPONENT,
    };
    use nrr_shared::ipc::IpcOperationName;

    fn envelope(payload: serde_json::Value) -> IpcRequestEnvelope {
        IpcRequestEnvelope {
            protocol_version: crate::ipc::IPC_PROTOCOL_VERSION,
            request_id: "r-1".to_string(),
            correlation_id: None,
            operation: IpcOperationName::ThirdPartyComponentsList,
            operation_class: crate::ipc::IpcOperationClass::ReadSnapshot,
            confirmation_token: None,
            payload,
        }
    }

    fn decode(outcome: HandlerOutcome) -> ThirdPartyComponentsListResponse {
        let value = outcome.expect("handler succeeded");
        serde_json::from_value(value).expect("response decodes")
    }

    #[test]
    fn platforms_without_third_party_binaries_report_only_the_asset_attribution() {
        // Linux / macOS: no Wintun, no binary of any kind — but the icons are
        // shipped everywhere, so their credit is still listed.
        let handler = ThirdPartyComponentsListHandler::new(Arc::new(NoopThirdPartyIntegrity));
        let response = decode(handler.handle(&envelope(serde_json::Value::Null), &ctx()));
        assert!(response.components.iter().all(|c| c.key != "wintun"));
        let icons = response
            .components
            .iter()
            .find(|c| c.key == "tabler-icons")
            .expect("icon attribution is reported on every platform");
        assert_eq!(icons.verdict, IntegrityVerdict::NotApplicable);
    }

    #[test]
    fn reported_binaries_reach_the_wire_unchanged_and_come_first() {
        let handler =
            ThirdPartyComponentsListHandler::new(Arc::new(MockThirdPartyIntegrity::new(vec![
                ThirdPartyComponentStatus::missing(&WINTUN_COMPONENT),
            ])));
        let response = decode(handler.handle(&envelope(serde_json::json!({})), &ctx()));
        assert_eq!(response.components[0].key, "wintun");
        assert_eq!(response.components[0].publisher, "WireGuard LLC");
        assert_eq!(response.components[0].verdict, IntegrityVerdict::Missing);
        assert!(response.components.iter().any(|c| c.key == "tabler-icons"));
    }

    #[test]
    fn a_malformed_payload_is_rejected() {
        let handler = ThirdPartyComponentsListHandler::new(Arc::new(NoopThirdPartyIntegrity));
        let outcome = handler.handle(&envelope(serde_json::json!("not-an-object")), &ctx());
        let err = outcome.expect_err("malformed payload rejected");
        assert_eq!(err.code, IpcErrorCode::MalformedRequest);
    }

    fn ctx() -> IpcRequestContext {
        IpcRequestContext {
            client_profile: nrr_shared::IpcClientProfile::GuiInteractive,
            caller_is_elevated: false,
            caller_principal: None,
        }
    }
}
