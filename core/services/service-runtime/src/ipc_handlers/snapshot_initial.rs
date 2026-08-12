//! `SnapshotInitial` handler — bundles the GUI's first-render data
//! (health + adapters + diagnostics + alerts count) into a single
//! round-trip. Composes the same building blocks the per-section
//! handlers use so the bundled response is byte-identical with
//! per-section responses.

use std::sync::Arc;

use nrr_diagnostics::facade::service::DiagnosticsFacade;

use crate::app_enforcement_status::AppEnforcementStatus;
use crate::ipc::{
    HandlerOutcome, IpcError, IpcErrorCode, IpcHandler, IpcRequestContext, IpcRequestEnvelope,
};
use crate::ipc_handlers::payloads::{
    RevisionSummaryDto, RoutePolicyDto, SnapshotInitialRequest, SnapshotInitialResponse,
};
use crate::ipc_handlers::providers::{
    AdaptersSnapshotProvider, ApplyFailurePolicyProvider, AutostartProvider,
    RetentionSettingsProvider, RoutePolicyProvider, RoutingPauseProvider,
};
use crate::ipc_handlers::service_health::{build_service_health_response, FakeIpDatapathProbe};
use crate::managers::{HealthReporter, PolicyManager};

pub struct SnapshotInitialHandler {
    health: Arc<dyn HealthReporter>,
    policy: Arc<dyn PolicyManager>,
    adapters: Arc<dyn AdaptersSnapshotProvider>,
    diagnostics: Arc<dyn DiagnosticsFacade>,
    /// Per-SID route policy reader. Returns the
    /// configuration for the caller's SID, or `None` if none is stored
    /// (caller is expected to drive the migration flow in that case).
    route_policy: Arc<dyn RoutePolicyProvider>,
    // Settings sources.
    apply_failure_policy: Arc<dyn ApplyFailurePolicyProvider>,
    routing_pause: Arc<dyn RoutingPauseProvider>,
    autostart: Arc<dyn AutostartProvider>,
    retention: Arc<dyn RetentionSettingsProvider>,
    /// Latest set of unenforced application rules (exe
    /// resolved to no path), published by the per-SID orchestrator and read
    /// here so the GUI can show a banner.
    app_enforcement: AppEnforcementStatus,
    /// Latest smart-kill-switch shared-IP
    /// exclusion count, published by the orchestrator on every filter compute.
    shared_ip_exemptions: crate::app_enforcement_status::SharedIpExemptionStatus,
    /// Whether the fail-closed catch-all block-all is
    /// armed for any active user, published by the orchestrator on every
    /// block-all transition edge (GUI warning banner).
    block_all_posture: crate::app_enforcement_status::BlockAllPostureStatus,
    /// Live fake-IP datapath probe. Shared with `ServiceHealthHandler` so
    /// the bundled health sub-payload stays byte-identical with what
    /// `service.health.get` returns. `None` omits the wire field.
    fake_ip_datapath: Option<FakeIpDatapathProbe>,
}

impl SnapshotInitialHandler {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        health: Arc<dyn HealthReporter>,
        policy: Arc<dyn PolicyManager>,
        adapters: Arc<dyn AdaptersSnapshotProvider>,
        diagnostics: Arc<dyn DiagnosticsFacade>,
        route_policy: Arc<dyn RoutePolicyProvider>,
        apply_failure_policy: Arc<dyn ApplyFailurePolicyProvider>,
        routing_pause: Arc<dyn RoutingPauseProvider>,
        autostart: Arc<dyn AutostartProvider>,
        retention: Arc<dyn RetentionSettingsProvider>,
        app_enforcement: AppEnforcementStatus,
        shared_ip_exemptions: crate::app_enforcement_status::SharedIpExemptionStatus,
        block_all_posture: crate::app_enforcement_status::BlockAllPostureStatus,
    ) -> Self {
        Self {
            health,
            policy,
            adapters,
            diagnostics,
            route_policy,
            apply_failure_policy,
            routing_pause,
            autostart,
            retention,
            app_enforcement,
            shared_ip_exemptions,
            block_all_posture,
            fake_ip_datapath: None,
        }
    }

    /// Attach the live fake-IP datapath probe (same instance the
    /// `ServiceHealthGet` handler holds) so the bundled health payload
    /// carries the `fake-ip-datapath` field.
    #[must_use]
    pub fn with_fake_ip_datapath_probe(mut self, probe: FakeIpDatapathProbe) -> Self {
        self.fake_ip_datapath = Some(probe);
        self
    }
}

impl IpcHandler for SnapshotInitialHandler {
    fn handle(&self, request: &IpcRequestEnvelope, ctx: &IpcRequestContext) -> HandlerOutcome {
        if !request.payload.is_null() {
            let _: SnapshotInitialRequest = serde_json::from_value(request.payload.clone())
                .map_err(|e| IpcError {
                    code: IpcErrorCode::MalformedRequest,
                    message: format!("snapshot.initial.get payload invalid: {e}"),
                    diagnostics_id: None,
                })?;
        }

        let health = build_service_health_response(
            self.health.as_ref(),
            self.policy.as_ref(),
            self.fake_ip_datapath.as_ref(),
        );
        let adapters = self.adapters.adapters_snapshot(false);
        let diag_status = self.diagnostics.get_status();
        let active_alerts_count = diag_status.active_alerts.len() as u32;
        let active_revision_id = health.active_revision_id.clone();

        // Read route policy for caller's SID. Empty SID
        // (e.g. cross-platform tests) returns `None`, which is the
        // documented "no policy yet — drive migration first" signal.
        let route_policy: Option<RoutePolicyDto> = if ctx.caller_stored().is_empty() {
            None
        } else {
            self.route_policy.get_for_sid(ctx.caller_stored())
        };

        // Settings snapshot.
        let pending_revisions: Vec<RevisionSummaryDto> = self
            .policy
            .pending_revisions()
            .into_iter()
            .map(|rs| RevisionSummaryDto {
                revision_id: rs.revision_id,
                status: rs.status_slug.to_string(),
                source: rs.source_slug.to_string(),
                correlation_id: rs.correlation_id,
                created_at: rs.created_at,
                activated_at: rs.activated_at,
                superseded_at: rs.superseded_at,
                risk_level: rs.risk_level_slug.map(str::to_string),
                content_hash: rs.content_hash,
            })
            .collect();
        let last_known_good = self.policy.last_known_good_id();
        let apply_failure_policy = Some(self.apply_failure_policy.get());
        let routing_paused = if ctx.caller_stored().is_empty() {
            false
        } else {
            self.routing_pause.get(ctx.caller_stored()).paused
        };
        let autostart = Some(self.autostart.get());
        let retention_settings = Some(self.retention.get());
        // App rules whose exe resolved to no path (the
        // orchestrator publishes the set on every filter compute).
        let unenforced_app_rules = self.app_enforcement.unresolved();
        // Smart-kill-switch shared-IP exclusion count for the GUI
        // "strictness reduced for N shared IPs" warning.
        let kill_switch_shared_ip_exemptions = self.shared_ip_exemptions.count();
        // The addresses themselves, for the GUI's "show details" list.
        let kill_switch_shared_ip_exemption_addresses = self.shared_ip_exemptions.addresses();
        // Block-all posture for the "leak protection is blocking
        // unknown traffic" banner.
        let kill_switch_block_all_armed = self.block_all_posture.armed();

        let resp = SnapshotInitialResponse {
            health,
            adapters,
            diagnostics: diag_status,
            active_alerts_count,
            active_revision_id,
            route_policy,
            pending_revisions,
            last_known_good,
            apply_failure_policy,
            routing_paused,
            autostart,
            retention_settings,
            unenforced_app_rules,
            kill_switch_shared_ip_exemptions,
            kill_switch_shared_ip_exemption_addresses,
            kill_switch_block_all_armed,
        };
        serde_json::to_value(resp).map_err(|e| IpcError {
            code: IpcErrorCode::Internal,
            message: format!("snapshot.initial.get response serialisation failed: {e}"),
            diagnostics_id: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::{IpcOperationClass, IPC_PROTOCOL_VERSION};
    use crate::ipc_handlers::payloads::AdapterEntry;
    use crate::ipc_handlers::test_fakes::{FakeAdapters, FakeDiagnostics, FakeHealth, FakePolicy};
    use crate::state::{ActiveRevisionState, ServiceHealthSeverity, ServiceRuntimeState};
    use nrr_shared::ipc::{IpcClientProfile, IpcOperationName};

    fn ctx() -> IpcRequestContext {
        IpcRequestContext {
            client_profile: IpcClientProfile::GuiInteractive,
            caller_is_elevated: false,
            caller_principal: None,
        }
    }

    fn req() -> IpcRequestEnvelope {
        IpcRequestEnvelope {
            protocol_version: IPC_PROTOCOL_VERSION,
            request_id: "r-init".into(),
            correlation_id: None,
            operation: IpcOperationName::SnapshotInitialGet,
            operation_class: IpcOperationClass::ReadSnapshot,
            confirmation_token: None,
            payload: serde_json::json!({}),
        }
    }

    #[test]
    fn bundles_health_adapters_and_diagnostics() {
        let adapter = AdapterEntry {
            persistent_id: "pid-1".into(),
            adapter_name: "Wi-Fi".into(),
            ipv6_if_index: 12,
            physical_address: None,
            windows_name: "Wireless LAN".into(),
            interface_description: "".into(),
            interface_type: "ieee80211".into(),
            oper_status: "up".into(),
        };
        let h = SnapshotInitialHandler::new(
            Arc::new(FakeHealth {
                state: ServiceRuntimeState::Running,
                severity: ServiceHealthSeverity::Ok,
            }),
            Arc::new(FakePolicy {
                revision: Some(ActiveRevisionState {
                    revision_id: "rev-init".into(),
                    provenance: "import".into(),
                    rule_count: 3,
                    behavior_mode: "prefer-primary".into(),
                    content_hash_hex: "0".repeat(64),
                    activated_at_iso: "2026-05-04T00:00:00Z".into(),
                }),
            }),
            Arc::new(FakeAdapters::with_one(adapter)),
            Arc::new(FakeDiagnostics::healthy()),
            Arc::new(crate::ipc_handlers::test_fakes::FakeRoutePolicy::default()),
            Arc::new(crate::ipc_handlers::test_fakes::FakeApplyFailurePolicy),
            Arc::new(crate::ipc_handlers::test_fakes::FakeRoutingPause),
            Arc::new(crate::ipc_handlers::test_fakes::FakeAutostart),
            Arc::new(crate::ipc_handlers::test_fakes::FakeRetention),
            AppEnforcementStatus::new(),
            crate::app_enforcement_status::SharedIpExemptionStatus::new(),
            crate::app_enforcement_status::BlockAllPostureStatus::new(),
        );

        let resp = h.handle(&req(), &ctx()).unwrap();
        let parsed: SnapshotInitialResponse = serde_json::from_value(resp).unwrap();
        assert_eq!(parsed.health.service_state, "running");
        assert_eq!(
            parsed.health.active_revision_id.as_deref(),
            Some("rev-init")
        );
        assert_eq!(parsed.adapters.adapters.len(), 1);
        assert!(parsed.diagnostics.overall_healthy);
        assert_eq!(parsed.active_alerts_count, 0);
        assert_eq!(parsed.active_revision_id.as_deref(), Some("rev-init"));
        assert!(parsed.unenforced_app_rules.is_empty());
        assert_eq!(parsed.kill_switch_shared_ip_exemptions, 0);
        assert!(!parsed.kill_switch_block_all_armed, "disarmed by default");
    }

    #[test]
    fn surfaces_unenforced_app_rules_from_status() {
        let adapter = AdapterEntry {
            persistent_id: "pid-1".into(),
            adapter_name: "Wi-Fi".into(),
            ipv6_if_index: 12,
            physical_address: None,
            windows_name: "Wireless LAN".into(),
            interface_description: "".into(),
            interface_type: "ieee80211".into(),
            oper_status: "up".into(),
        };
        let app_enforcement = AppEnforcementStatus::new();
        app_enforcement.set_unresolved(vec!["vk.exe".into(), "disko*.exe".into()]);
        let shared_exemptions = crate::app_enforcement_status::SharedIpExemptionStatus::new();
        shared_exemptions.set(&[
            std::net::Ipv4Addr::new(8, 6, 112, 1),
            std::net::Ipv4Addr::new(8, 6, 112, 2),
            std::net::Ipv4Addr::new(8, 6, 112, 3),
        ]);
        // An armed block-all posture rides the same snapshot.
        let block_all = crate::app_enforcement_status::BlockAllPostureStatus::new();
        block_all.set(true);
        let h = SnapshotInitialHandler::new(
            Arc::new(FakeHealth {
                state: ServiceRuntimeState::Running,
                severity: ServiceHealthSeverity::Ok,
            }),
            Arc::new(FakePolicy { revision: None }),
            Arc::new(FakeAdapters::with_one(adapter)),
            Arc::new(FakeDiagnostics::healthy()),
            Arc::new(crate::ipc_handlers::test_fakes::FakeRoutePolicy::default()),
            Arc::new(crate::ipc_handlers::test_fakes::FakeApplyFailurePolicy),
            Arc::new(crate::ipc_handlers::test_fakes::FakeRoutingPause),
            Arc::new(crate::ipc_handlers::test_fakes::FakeAutostart),
            Arc::new(crate::ipc_handlers::test_fakes::FakeRetention),
            app_enforcement,
            shared_exemptions,
            block_all,
        );

        let resp = h.handle(&req(), &ctx()).unwrap();
        let parsed: SnapshotInitialResponse = serde_json::from_value(resp).unwrap();
        // Sorted + deduped by the status.
        assert_eq!(parsed.unenforced_app_rules, vec!["disko*.exe", "vk.exe"]);
        // The smart-kill-switch exclusion count rides the same snapshot.
        assert_eq!(parsed.kill_switch_shared_ip_exemptions, 3);
        // The excluded addresses ride the same snapshot for the GUI's
        // "show details" list.
        assert_eq!(
            parsed.kill_switch_shared_ip_exemption_addresses,
            vec!["8.6.112.1", "8.6.112.2", "8.6.112.3"]
        );
        // The block-all posture rides the same snapshot.
        assert!(parsed.kill_switch_block_all_armed);
    }
}
