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
    /// Standing per-role enforcement reports the route coordinator pushes on
    /// change. Empty when no coordinator is wired.
    route_enforcement: crate::app_enforcement_status::RouteEnforcementStatus,
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
            route_enforcement: crate::app_enforcement_status::RouteEnforcementStatus::new(),
        }
    }

    /// Share the route coordinator's standing enforcement reports.
    #[must_use]
    pub fn with_route_enforcement_status(
        mut self,
        status: crate::app_enforcement_status::RouteEnforcementStatus,
    ) -> Self {
        self.route_enforcement = status;
        self
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
            ctx.caller_stored(),
        );
        let adapters = self.adapters.adapters_snapshot(false);
        let diag_status = self.diagnostics.get_status(&ctx.diagnostics_audience());
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
        // A caller with no policy settles its first choice against this.
        let first_policy = if route_policy.is_none() && !ctx.caller_stored().is_empty() {
            self.route_policy.first_policy()
        } else {
            None
        };

        // Settings snapshot.
        let pending_revisions: Vec<RevisionSummaryDto> = self
            .policy
            .pending_revisions(ctx.caller_stored())
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
        let (routing_paused, pause_term) = if ctx.caller_stored().is_empty() {
            (false, Default::default())
        } else {
            (
                self.routing_pause.get(ctx.caller_stored()).paused,
                self.routing_pause.term(ctx.caller_stored()),
            )
        };
        let autostart = Some(self.autostart.get());
        let retention_settings = Some(self.retention.get());
        // The caller's own app rules whose exe resolved to no path.
        let (unenforced_app_rules, unenforced_app_reasons) =
            self.app_enforcement.unenforced_apps(ctx.caller_stored());
        // Smart-kill-switch shared-IP exclusion count for the GUI
        // "strictness reduced for N shared IPs" warning.
        let kill_switch_shared_ip_exemptions = self.shared_ip_exemptions.count();
        // The addresses themselves, for the GUI's "show details" list.
        let kill_switch_shared_ip_exemption_addresses = self.shared_ip_exemptions.addresses();
        // Block-all posture for the "leak protection is blocking
        // unknown traffic" banner.
        let kill_switch_block_all_armed = self.block_all_posture.armed();
        // The caller's own conflicts only: they name its rules and addresses.
        let rule_conflicts = self.app_enforcement.rule_conflicts(ctx.caller_stored());
        // The caller's own reports only: candidates name that user's adapters.
        let enforcement_status = if ctx.caller_stored().is_empty() {
            Vec::new()
        } else {
            self.route_enforcement.for_principal(ctx.caller_stored())
        };
        let routes_held_by_another_user = if ctx.caller_stored().is_empty() {
            None
        } else {
            self.route_enforcement.routes_held(ctx.caller_stored())
        };
        let traffic_carried_by_another_user = if ctx.caller_stored().is_empty() {
            None
        } else {
            self.route_enforcement.traffic_carried(ctx.caller_stored())
        };
        // The caller's own book only: another user's failing read is theirs.
        let rules_book_unreadable = !ctx.caller_stored().is_empty()
            && crate::rules_book_notice::service().unreadable_for(ctx.caller_stored());
        // The caller's own: a client waits for the user who can confirm it.
        let pending_vpn_clients = if ctx.caller_stored().is_empty() {
            Vec::new()
        } else {
            crate::vpn_client_trust::global_pending_vpn_clients().dtos_for(ctx.caller_stored())
        };
        // The caller's own gateways, asked and answered.
        let (pending_vpn_gateways, confirmed_vpn_gateways) = if ctx.caller_stored().is_empty() {
            (Vec::new(), Vec::new())
        } else {
            let book = crate::vpn_gateway_confirm::global_vpn_gateways();
            (
                book.pending_for(ctx.caller_stored()),
                book.confirmed_for(ctx.caller_stored()),
            )
        };
        // The caller's own confirmations of protected rules, with their terms.
        let rule_overrides = match crate::override_grants::installed() {
            Some(grants) if !ctx.caller_stored().is_empty() => grants
                .grants_for(ctx.caller_stored())
                .iter()
                .map(crate::override_grants::Grant::dto)
                .collect(),
            _ => Vec::new(),
        };

        let resp = SnapshotInitialResponse {
            health,
            adapters,
            diagnostics: diag_status,
            active_alerts_count,
            active_revision_id,
            route_policy,
            first_policy,
            pending_revisions,
            last_known_good,
            apply_failure_policy,
            routing_paused,
            routing_pause_resumes_at_ms: pause_term.resumes_at_ms,
            routing_pause_until_restart: pause_term.until_restart,
            autostart,
            retention_settings,
            unenforced_app_rules,
            unenforced_app_reasons,
            kill_switch_shared_ip_exemptions,
            kill_switch_shared_ip_exemption_addresses,
            kill_switch_block_all_armed,
            rule_conflicts,
            enforcement_status,
            routes_held_by_another_user,
            traffic_carried_by_another_user,
            rules_book_unreadable,
            pending_vpn_clients,
            pending_vpn_gateways,
            confirmed_vpn_gateways,
            rule_overrides,
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
            caller_pid: None,
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
            name: "Wireless LAN".into(),
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
            name: "Wireless LAN".into(),
            interface_description: "".into(),
            interface_type: "ieee80211".into(),
            oper_status: "up".into(),
        };
        let app_enforcement = AppEnforcementStatus::new();
        app_enforcement.set_unresolved("unix:uid:1000", vec!["ab.exe".into(), "disko*.exe".into()]);
        app_enforcement.set_unresolved("unix:uid:1001", vec!["other.exe".into()]);
        let shared_exemptions = crate::app_enforcement_status::SharedIpExemptionStatus::new();
        shared_exemptions.set(&[
            std::net::Ipv4Addr::new(192, 0, 2, 1),
            std::net::Ipv4Addr::new(192, 0, 2, 2),
            std::net::Ipv4Addr::new(192, 0, 2, 3),
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

        let caller = IpcRequestContext {
            caller_principal: Some(nrr_domain::user_principal::UserPrincipal::from_linux_uid(
                1000,
            )),
            ..ctx()
        };
        let resp = h.handle(&req(), &caller).unwrap();
        let parsed: SnapshotInitialResponse = serde_json::from_value(resp).unwrap();
        // The caller's own, sorted + deduped by the status; another user's stay out.
        assert_eq!(parsed.unenforced_app_rules, vec!["ab.exe", "disko*.exe"]);
        // The smart-kill-switch exclusion count rides the same snapshot.
        assert_eq!(parsed.kill_switch_shared_ip_exemptions, 3);
        // The excluded addresses ride the same snapshot for the GUI's
        // "show details" list.
        assert_eq!(
            parsed.kill_switch_shared_ip_exemption_addresses,
            vec!["192.0.2.1", "192.0.2.2", "192.0.2.3"]
        );
        // The block-all posture rides the same snapshot.
        assert!(parsed.kill_switch_block_all_armed);
    }

    /// Conflicts are read for the CALLER: they name its own rules and
    /// addresses, and another user's never reach it.
    #[test]
    fn surfaces_only_the_callers_rule_conflicts() {
        use nrr_domain::user_principal::UserPrincipal;
        use nrr_shared::ipc_payloads::{RuleConflictDto, RuleConflictKind};
        let caller = UserPrincipal::from_linux_uid(1000);
        let conflict = RuleConflictDto {
            kind: RuleConflictKind::LiteralBlockOverridesRoute,
            rule_id: "r1".into(),
            rule_value: "a.example".into(),
            ip: "192.0.2.10".into(),
            count: 1,
            other_rule_id: "b1".into(),
            host: "a.example".into(),
            via_host: String::new(),
            app: String::new(),
            reason: String::new(),
        };
        let unsupported = RuleConflictDto {
            kind: RuleConflictKind::UnsupportedRuleShape,
            rule_id: "c1".into(),
            rule_value: "c.example".into(),
            ip: String::new(),
            count: 0,
            other_rule_id: String::new(),
            host: String::new(),
            via_host: String::new(),
            app: "app.exe".into(),
            reason: String::new(),
        };
        let app_enforcement = AppEnforcementStatus::new();
        app_enforcement.set_rule_conflicts(
            caller.as_stored(),
            vec![conflict.clone(), unsupported.clone()],
        );
        app_enforcement.set_rule_conflicts(
            UserPrincipal::from_linux_uid(1001).as_stored(),
            vec![RuleConflictDto {
                rule_id: "other".into(),
                ..conflict.clone()
            }],
        );
        let h = SnapshotInitialHandler::new(
            Arc::new(FakeHealth {
                state: ServiceRuntimeState::Running,
                severity: ServiceHealthSeverity::Ok,
            }),
            Arc::new(FakePolicy { revision: None }),
            Arc::new(FakeAdapters::empty()),
            Arc::new(FakeDiagnostics::healthy()),
            Arc::new(crate::ipc_handlers::test_fakes::FakeRoutePolicy::default()),
            Arc::new(crate::ipc_handlers::test_fakes::FakeApplyFailurePolicy),
            Arc::new(crate::ipc_handlers::test_fakes::FakeRoutingPause),
            Arc::new(crate::ipc_handlers::test_fakes::FakeAutostart),
            Arc::new(crate::ipc_handlers::test_fakes::FakeRetention),
            app_enforcement,
            crate::app_enforcement_status::SharedIpExemptionStatus::new(),
            crate::app_enforcement_status::BlockAllPostureStatus::new(),
        );
        let ctx = IpcRequestContext {
            caller_principal: Some(caller),
            ..ctx()
        };

        let resp = h.handle(&req(), &ctx).unwrap();
        assert_eq!(
            resp["rule-conflicts"][0]["kind"],
            "literal-block-overrides-route"
        );
        assert_eq!(resp["rule-conflicts"][1]["kind"], "unsupported-rule-shape");
        assert_eq!(resp["rule-conflicts"][1]["app"], "app.exe");
        assert!(resp["rule-conflicts"][0].get("app").is_none());
        let parsed: SnapshotInitialResponse = serde_json::from_value(resp).unwrap();
        assert_eq!(parsed.rule_conflicts, vec![conflict, unsupported]);
    }

    /// A client that connects after the push reads the standing report here —
    /// its own, never another user's, whose candidates name that user's adapters.
    #[test]
    fn surfaces_only_the_callers_standing_enforcement_status() {
        use nrr_domain::user_principal::UserPrincipal;
        use nrr_shared::ipc_payloads::EnforcementStatusDto;
        let caller = UserPrincipal::from_linux_uid(1000);
        let report = |status: &str, role: &str, candidates: &[&str]| EnforcementStatusDto {
            status: status.into(),
            role: role.into(),
            candidates: candidates.iter().map(|c| (*c).to_string()).collect(),
            since_unix_ms: Some(1_000),
            quiet: false,
        };
        let board = crate::app_enforcement_status::RouteEnforcementStatus::new();
        board.record_at(
            caller.as_stored(),
            &report("secondary-down", "secondary", &[]),
            1_000,
        );
        board.record_at(caller.as_stored(), &report("ok", "primary", &[]), 1_000);
        board.record_at(
            UserPrincipal::from_linux_uid(1001).as_stored(),
            &report("adapter-gone", "secondary", &["Other Tunnel"]),
            1_000,
        );
        let h = SnapshotInitialHandler::new(
            Arc::new(FakeHealth {
                state: ServiceRuntimeState::Running,
                severity: ServiceHealthSeverity::Ok,
            }),
            Arc::new(FakePolicy { revision: None }),
            Arc::new(FakeAdapters::empty()),
            Arc::new(FakeDiagnostics::healthy()),
            Arc::new(crate::ipc_handlers::test_fakes::FakeRoutePolicy::default()),
            Arc::new(crate::ipc_handlers::test_fakes::FakeApplyFailurePolicy),
            Arc::new(crate::ipc_handlers::test_fakes::FakeRoutingPause),
            Arc::new(crate::ipc_handlers::test_fakes::FakeAutostart),
            Arc::new(crate::ipc_handlers::test_fakes::FakeRetention),
            AppEnforcementStatus::new(),
            crate::app_enforcement_status::SharedIpExemptionStatus::new(),
            crate::app_enforcement_status::BlockAllPostureStatus::new(),
        )
        .with_route_enforcement_status(board);

        let own = IpcRequestContext {
            caller_principal: Some(caller),
            ..ctx()
        };
        let resp = h.handle(&req(), &own).unwrap();
        assert_eq!(resp["enforcement-status"][1]["status"], "secondary-down");
        assert_eq!(resp["enforcement-status"][1]["since-unix-ms"], 1_000);
        let parsed: SnapshotInitialResponse = serde_json::from_value(resp).unwrap();
        assert_eq!(
            parsed.enforcement_status,
            vec![
                report("ok", "primary", &[]),
                report("secondary-down", "secondary", &[]),
            ]
        );

        let anonymous = h.handle(&req(), &ctx()).unwrap();
        assert!(
            anonymous.get("enforcement-status").is_none(),
            "a caller with no principal is shown nobody's"
        );
    }

    /// A client that connects after another user took some of its
    /// destinations learns it here — its own report only.
    #[test]
    fn surfaces_only_the_callers_routes_held_by_another_user() {
        use nrr_domain::user_principal::UserPrincipal;
        use nrr_shared::ipc_payloads::RoutesHeldDto;
        let caller = UserPrincipal::from_linux_uid(1000);
        let other = UserPrincipal::from_linux_uid(1001);
        let board = crate::app_enforcement_status::RouteEnforcementStatus::new();
        let held = RoutesHeldDto {
            count: 1,
            sample: vec!["198.51.100.1".into()],
        };
        board.record_routes_held(caller.as_stored(), held.clone());
        let h = SnapshotInitialHandler::new(
            Arc::new(FakeHealth {
                state: ServiceRuntimeState::Running,
                severity: ServiceHealthSeverity::Ok,
            }),
            Arc::new(FakePolicy { revision: None }),
            Arc::new(FakeAdapters::empty()),
            Arc::new(FakeDiagnostics::healthy()),
            Arc::new(crate::ipc_handlers::test_fakes::FakeRoutePolicy::default()),
            Arc::new(crate::ipc_handlers::test_fakes::FakeApplyFailurePolicy),
            Arc::new(crate::ipc_handlers::test_fakes::FakeRoutingPause),
            Arc::new(crate::ipc_handlers::test_fakes::FakeAutostart),
            Arc::new(crate::ipc_handlers::test_fakes::FakeRetention),
            AppEnforcementStatus::new(),
            crate::app_enforcement_status::SharedIpExemptionStatus::new(),
            crate::app_enforcement_status::BlockAllPostureStatus::new(),
        )
        .with_route_enforcement_status(board);

        let own = IpcRequestContext {
            caller_principal: Some(caller),
            ..ctx()
        };
        let resp = h.handle(&req(), &own).unwrap();
        assert_eq!(resp["routes-held-by-another-user"]["count"], 1);
        let parsed: SnapshotInitialResponse = serde_json::from_value(resp).unwrap();
        assert_eq!(parsed.routes_held_by_another_user, Some(held));

        let theirs = IpcRequestContext {
            caller_principal: Some(other),
            ..ctx()
        };
        let resp = h.handle(&req(), &theirs).unwrap();
        assert!(resp.get("routes-held-by-another-user").is_none());
        let anonymous = h.handle(&req(), &ctx()).unwrap();
        assert!(anonymous.get("routes-held-by-another-user").is_none());
    }

    /// A client that connects after its traffic began riding another user's
    /// tunnel learns it here — its own report only.
    #[test]
    fn surfaces_only_the_callers_traffic_carried_by_another_user() {
        use nrr_domain::user_principal::UserPrincipal;
        use nrr_shared::ipc_payloads::TrafficCarriedDto;
        let caller = UserPrincipal::from_linux_uid(1000);
        let other = UserPrincipal::from_linux_uid(1001);
        let board = crate::app_enforcement_status::RouteEnforcementStatus::new();
        let carried = TrafficCarriedDto {
            carried: true,
            link: "Example Tunnel".into(),
        };
        board.record_traffic_carried(caller.as_stored(), carried.clone());
        let h = SnapshotInitialHandler::new(
            Arc::new(FakeHealth {
                state: ServiceRuntimeState::Running,
                severity: ServiceHealthSeverity::Ok,
            }),
            Arc::new(FakePolicy { revision: None }),
            Arc::new(FakeAdapters::empty()),
            Arc::new(FakeDiagnostics::healthy()),
            Arc::new(crate::ipc_handlers::test_fakes::FakeRoutePolicy::default()),
            Arc::new(crate::ipc_handlers::test_fakes::FakeApplyFailurePolicy),
            Arc::new(crate::ipc_handlers::test_fakes::FakeRoutingPause),
            Arc::new(crate::ipc_handlers::test_fakes::FakeAutostart),
            Arc::new(crate::ipc_handlers::test_fakes::FakeRetention),
            AppEnforcementStatus::new(),
            crate::app_enforcement_status::SharedIpExemptionStatus::new(),
            crate::app_enforcement_status::BlockAllPostureStatus::new(),
        )
        .with_route_enforcement_status(board);

        let own = IpcRequestContext {
            caller_principal: Some(caller),
            ..ctx()
        };
        let resp = h.handle(&req(), &own).unwrap();
        assert_eq!(
            resp["traffic-carried-by-another-user"]["link"],
            "Example Tunnel"
        );
        let parsed: SnapshotInitialResponse = serde_json::from_value(resp).unwrap();
        assert_eq!(parsed.traffic_carried_by_another_user, Some(carried));

        let theirs = IpcRequestContext {
            caller_principal: Some(other),
            ..ctx()
        };
        let resp = h.handle(&req(), &theirs).unwrap();
        assert!(resp.get("traffic-carried-by-another-user").is_none());
        let anonymous = h.handle(&req(), &ctx()).unwrap();
        assert!(anonymous.get("traffic-carried-by-another-user").is_none());
    }

    /// A client that connects while its own rule book does not read learns it
    /// here; another user and an anonymous caller see nothing.
    #[test]
    fn surfaces_only_the_callers_unreadable_rule_book() {
        use nrr_domain::user_principal::UserPrincipal;
        // Uids no other test uses: the registry is the service's own.
        let caller = UserPrincipal::from_linux_uid(47_011);
        let other = UserPrincipal::from_linux_uid(47_012);
        crate::rules_book_notice::service().raise(caller.as_stored());
        let h = SnapshotInitialHandler::new(
            Arc::new(FakeHealth {
                state: ServiceRuntimeState::Running,
                severity: ServiceHealthSeverity::Ok,
            }),
            Arc::new(FakePolicy { revision: None }),
            Arc::new(FakeAdapters::empty()),
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

        let own = IpcRequestContext {
            caller_principal: Some(caller.clone()),
            ..ctx()
        };
        let resp = h.handle(&req(), &own).unwrap();
        assert_eq!(resp["rules-book-unreadable"], true);

        let theirs = IpcRequestContext {
            caller_principal: Some(other),
            ..ctx()
        };
        let resp = h.handle(&req(), &theirs).unwrap();
        assert!(resp.get("rules-book-unreadable").is_none());
        let anonymous = h.handle(&req(), &ctx()).unwrap();
        assert!(anonymous.get("rules-book-unreadable").is_none());

        crate::rules_book_notice::service().clear(caller.as_stored());
        let resp = h.handle(&req(), &own).unwrap();
        assert!(
            resp.get("rules-book-unreadable").is_none(),
            "cleared once it reads"
        );
    }

    /// The install-time start reaches only a caller with no policy of its own.
    #[test]
    fn the_first_policy_is_reported_only_while_the_caller_has_none() {
        use crate::ipc_handlers::payloads::{BehaviorModeDto, FirstPolicyDto, LeakProtectionDto};
        use crate::ipc_handlers::test_fakes::FakeRoutePolicy;
        let first = FirstPolicyDto {
            mode: BehaviorModeDto::PreferSecondaryWhenAvailable,
            leak_protection_at_least: LeakProtectionDto::Everything,
        };
        let handler = |stored: Option<RoutePolicyDto>| {
            SnapshotInitialHandler::new(
                Arc::new(FakeHealth {
                    state: ServiceRuntimeState::Running,
                    severity: ServiceHealthSeverity::Ok,
                }),
                Arc::new(FakePolicy { revision: None }),
                Arc::new(FakeAdapters::empty()),
                Arc::new(FakeDiagnostics::healthy()),
                Arc::new(FakeRoutePolicy {
                    stored: std::sync::Mutex::new(stored),
                    first: Some(first),
                }),
                Arc::new(crate::ipc_handlers::test_fakes::FakeApplyFailurePolicy),
                Arc::new(crate::ipc_handlers::test_fakes::FakeRoutingPause),
                Arc::new(crate::ipc_handlers::test_fakes::FakeAutostart),
                Arc::new(crate::ipc_handlers::test_fakes::FakeRetention),
                AppEnforcementStatus::new(),
                crate::app_enforcement_status::SharedIpExemptionStatus::new(),
                crate::app_enforcement_status::BlockAllPostureStatus::new(),
            )
        };
        let own = IpcRequestContext {
            caller_principal: Some(nrr_domain::user_principal::UserPrincipal::from_linux_uid(
                1000,
            )),
            ..ctx()
        };

        let resp = handler(None).handle(&req(), &own).unwrap();
        assert_eq!(
            resp["first-policy"]["mode"],
            "prefer-secondary-when-available"
        );
        assert_eq!(
            resp["first-policy"]["leak-protection-at-least"],
            "everything"
        );
        let parsed: SnapshotInitialResponse = serde_json::from_value(resp).unwrap();
        assert_eq!(parsed.first_policy, Some(first));

        let stored: RoutePolicyDto = serde_json::from_value(serde_json::json!({
            "mode": "prefer-primary",
            "leak-protection": "off",
            "doh-lockdown-enabled": false,
            "kill-switch-strict-shared-ips": false,
            "binding-source": "user-assigned"
        }))
        .unwrap();
        let resp = handler(Some(stored)).handle(&req(), &own).unwrap();
        assert!(resp.get("first-policy").is_none());
    }
}
