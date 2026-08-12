//! `ServiceHealthGet` handler — returns the top-level service state +
//! worst severity + active revision id. Component breakdown and
//! degraded-mode list are not wired yet.

use std::sync::Arc;

use crate::fake_ip::FakeIpDatapathStatus;
use crate::ipc::{
    HandlerOutcome, IpcError, IpcErrorCode, IpcHandler, IpcRequestContext, IpcRequestEnvelope,
};
use crate::ipc_handlers::payloads::{
    FakeIpDatapathDto, ServiceHealthRequest, ServiceHealthResponse,
};
use crate::managers::{HealthReporter, PolicyManager};
use crate::state::{ServiceHealthSeverity, ServiceRuntimeState};

/// Instant, non-blocking probe over the live fake-IP controller. The
/// closure must stay as cheap as `FakeIpController::datapath_status`
/// (one short-lived mutex lock, no I/O): `service.health.get` rides the
/// side channel, so anything heavier here would stall the GUI's health
/// polling.
pub type FakeIpDatapathProbe = Arc<dyn Fn() -> FakeIpDatapathStatus + Send + Sync>;

pub fn service_state_slug(state: ServiceRuntimeState) -> &'static str {
    match state {
        ServiceRuntimeState::Starting => "starting",
        ServiceRuntimeState::Running => "running",
        ServiceRuntimeState::Degraded => "degraded",
        ServiceRuntimeState::RecoveryRequired => "recovery-required",
        ServiceRuntimeState::Disabled => "disabled",
        ServiceRuntimeState::Stopping => "stopping",
        ServiceRuntimeState::Stopped => "stopped",
    }
}

pub fn severity_slug(severity: ServiceHealthSeverity) -> &'static str {
    match severity {
        ServiceHealthSeverity::Ok => "ok",
        ServiceHealthSeverity::Warning => "warning",
        ServiceHealthSeverity::Degraded => "degraded",
        ServiceHealthSeverity::Blocking => "blocking",
        ServiceHealthSeverity::Unknown => "unknown",
    }
}

/// Build a wire-format `ServiceHealthResponse` from the trait surface
/// available today. Reused by [`SnapshotInitialHandler`] so the
/// composer's "health" sub-payload is byte-identical with what
/// `ServiceHealthGet` would return.
pub fn build_service_health_response(
    health: &dyn HealthReporter,
    policy: &dyn PolicyManager,
    fake_ip_datapath: Option<&FakeIpDatapathProbe>,
) -> ServiceHealthResponse {
    let active_revision_id = policy.current_revision().map(|r| r.revision_id);
    ServiceHealthResponse {
        service_state: service_state_slug(health.current_state()).into(),
        worst_severity: severity_slug(health.worst_severity()).into(),
        active_revision_id,
        // TODO:: populate per-component statuses once the
        // HealthReporter trait exposes them.
        components: Vec::new(),
        // TODO:: wire DegradedMode list from the runtime.
        degraded_modes: Vec::new(),
        fake_ip_datapath: fake_ip_datapath.map(|probe| fake_ip_datapath_to_dto(probe())),
    }
}

/// Project the controller's status onto the wire DTO. `zombies` is
/// saturated into `u32` — the count is bounded by live threads in
/// practice, so the clamp can never fire outside of pathological input.
fn fake_ip_datapath_to_dto(status: FakeIpDatapathStatus) -> FakeIpDatapathDto {
    FakeIpDatapathDto {
        desired: status.desired,
        running: status.running,
        zombies: u32::try_from(status.zombies).unwrap_or(u32::MAX),
    }
}

pub struct ServiceHealthHandler {
    health: Arc<dyn HealthReporter>,
    policy: Arc<dyn PolicyManager>,
    /// `None` (degraded boot / tests) omits the wire field entirely, so
    /// clients cannot mistake "probe not wired" for "datapath down".
    fake_ip_datapath: Option<FakeIpDatapathProbe>,
}

impl ServiceHealthHandler {
    pub fn new(health: Arc<dyn HealthReporter>, policy: Arc<dyn PolicyManager>) -> Self {
        Self {
            health,
            policy,
            fake_ip_datapath: None,
        }
    }

    /// Attach the live fake-IP datapath probe so the health payload
    /// carries the `fake-ip-datapath` field.
    #[must_use]
    pub fn with_fake_ip_datapath_probe(mut self, probe: FakeIpDatapathProbe) -> Self {
        self.fake_ip_datapath = Some(probe);
        self
    }
}

impl IpcHandler for ServiceHealthHandler {
    fn handle(&self, request: &IpcRequestEnvelope, _ctx: &IpcRequestContext) -> HandlerOutcome {
        // Allow `null` and `{}` interchangeably so very-early clients
        // that ship an empty payload don't get a confusing 400.
        if !request.payload.is_null() {
            let _: ServiceHealthRequest =
                serde_json::from_value(request.payload.clone()).map_err(|e| IpcError {
                    code: IpcErrorCode::MalformedRequest,
                    message: format!("service.health.get payload invalid: {e}"),
                    diagnostics_id: None,
                })?;
        }

        let resp = build_service_health_response(
            self.health.as_ref(),
            self.policy.as_ref(),
            self.fake_ip_datapath.as_ref(),
        );
        serde_json::to_value(resp).map_err(|e| IpcError {
            code: IpcErrorCode::Internal,
            message: format!("service.health.get response serialisation failed: {e}"),
            diagnostics_id: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::{IpcOperationClass, IPC_PROTOCOL_VERSION};
    use crate::ipc_handlers::test_fakes::{FakeHealth, FakePolicy};
    use crate::state::ActiveRevisionState;
    use nrr_shared::ipc::{IpcClientProfile, IpcOperationName};

    fn ctx() -> IpcRequestContext {
        IpcRequestContext {
            client_profile: IpcClientProfile::GuiInteractive,
            caller_is_elevated: true,
            caller_principal: None,
        }
    }

    fn req(payload: serde_json::Value) -> IpcRequestEnvelope {
        IpcRequestEnvelope {
            protocol_version: IPC_PROTOCOL_VERSION,
            request_id: "r-sh".into(),
            correlation_id: None,
            operation: IpcOperationName::ServiceHealthGet,
            operation_class: IpcOperationClass::ReadSnapshot,
            confirmation_token: None,
            payload,
        }
    }

    fn h(
        state: ServiceRuntimeState,
        severity: ServiceHealthSeverity,
        revision: Option<ActiveRevisionState>,
    ) -> ServiceHealthHandler {
        ServiceHealthHandler::new(
            Arc::new(FakeHealth { state, severity }),
            Arc::new(FakePolicy { revision }),
        )
    }

    #[test]
    fn returns_state_and_severity_slugs() {
        let h = h(
            ServiceRuntimeState::Degraded,
            ServiceHealthSeverity::Warning,
            None,
        );
        let resp = h.handle(&req(serde_json::json!({})), &ctx()).unwrap();
        let parsed: ServiceHealthResponse = serde_json::from_value(resp).unwrap();
        assert_eq!(parsed.service_state, "degraded");
        assert_eq!(parsed.worst_severity, "warning");
        assert!(parsed.active_revision_id.is_none());
        assert!(parsed.components.is_empty());
        assert!(parsed.degraded_modes.is_empty());
        // No probe wired -> the field is omitted, not fabricated.
        assert!(parsed.fake_ip_datapath.is_none());
    }

    #[test]
    fn surfaces_fake_ip_datapath_outage_from_probe() {
        // The GUI's "toggle says ON but the datapath is dead" signal:
        // desired=true + running=false must ride the health payload.
        let probe: FakeIpDatapathProbe = Arc::new(|| FakeIpDatapathStatus {
            desired: true,
            running: false,
            zombies: 1,
        });
        let h = h(
            ServiceRuntimeState::Running,
            ServiceHealthSeverity::Ok,
            None,
        )
        .with_fake_ip_datapath_probe(probe);
        let resp = h.handle(&req(serde_json::json!({})), &ctx()).unwrap();
        // Pin the wire key spelling (kebab-case) before typed parsing.
        assert_eq!(resp["fake-ip-datapath"]["desired"], true);
        assert_eq!(resp["fake-ip-datapath"]["running"], false);
        assert_eq!(resp["fake-ip-datapath"]["zombies"], 1);
        let parsed: ServiceHealthResponse = serde_json::from_value(resp).unwrap();
        let datapath = parsed.fake_ip_datapath.expect("probe wired");
        assert!(datapath.desired);
        assert!(!datapath.running);
        assert_eq!(datapath.zombies, 1);
    }

    #[test]
    fn surfaces_active_revision_id_when_policy_loaded() {
        let revision = ActiveRevisionState {
            revision_id: "rev-abc-123".into(),
            provenance: "import".into(),
            rule_count: 17,
            behavior_mode: "prefer-primary".into(),
            content_hash_hex: "0".repeat(64),
            activated_at_iso: "2026-05-04T00:00:00Z".into(),
        };
        let h = h(
            ServiceRuntimeState::Running,
            ServiceHealthSeverity::Ok,
            Some(revision),
        );
        let resp = h.handle(&req(serde_json::Value::Null), &ctx()).unwrap();
        let parsed: ServiceHealthResponse = serde_json::from_value(resp).unwrap();
        assert_eq!(parsed.active_revision_id.as_deref(), Some("rev-abc-123"));
    }

    #[test]
    fn rejects_non_object_payload() {
        let h = h(
            ServiceRuntimeState::Running,
            ServiceHealthSeverity::Ok,
            None,
        );
        let err = h
            .handle(&req(serde_json::json!("not an object")), &ctx())
            .expect_err("must reject");
        assert_eq!(err.code, IpcErrorCode::MalformedRequest);
    }
}
