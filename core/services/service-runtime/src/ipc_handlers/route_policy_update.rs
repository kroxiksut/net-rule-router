//! `RoutePolicyUpdate` handler.
//!
//! Atomically writes the caller's per-SID route policy (primary +
//! secondary bindings + behavior mode + secondary-block flag) to
//! `nrr_service_state.db`. Validation runs server-side: `stable_id`
//! against the live `AdapterMonitor`, `mode = strict-...` requires a
//! bound secondary, primary ≠ secondary.
//!
//! User-scoped class (`UserScopedConfiguration` in `IpcOperationClass`):
//! flows through the mutation queue (single-writer invariant) and is
//! audited before execution, but does not require an elevated client.

use std::sync::Arc;

use crate::ipc::{
    HandlerOutcome, IpcError, IpcErrorCode, IpcHandler, IpcRequestContext, IpcRequestEnvelope,
};
use crate::ipc_handlers::payloads::RoutePolicyUpdateRequest;
use crate::ipc_handlers::providers::{
    RoutePolicyApplyTrigger, RoutePolicyWriteError, RoutePolicyWriter,
};

pub struct RoutePolicyUpdateHandler {
    writer: Arc<dyn RoutePolicyWriter>,
    /// Fired after a successful write so a routing-active caller's WFP
    /// filters recompile immediately. `None` (no orchestrator / WFP
    /// unavailable) ⇒ persist-only.
    apply_trigger: Option<Arc<dyn RoutePolicyApplyTrigger>>,
}

impl RoutePolicyUpdateHandler {
    pub fn new(
        writer: Arc<dyn RoutePolicyWriter>,
        apply_trigger: Option<Arc<dyn RoutePolicyApplyTrigger>>,
    ) -> Self {
        Self {
            writer,
            apply_trigger,
        }
    }
}

impl IpcHandler for RoutePolicyUpdateHandler {
    fn handle(&self, request: &IpcRequestEnvelope, ctx: &IpcRequestContext) -> HandlerOutcome {
        if ctx.caller_stored().is_empty() {
            return Err(IpcError {
                code: IpcErrorCode::Internal,
                message:
                    "caller SID unavailable; transport must populate IpcRequestContext.caller_stored()"
                        .into(),
                diagnostics_id: None,
            });
        }

        let req: RoutePolicyUpdateRequest = serde_json::from_value(request.payload.clone())
            .map_err(|e| IpcError {
                code: IpcErrorCode::MalformedRequest,
                message: format!("route.policy.update payload invalid: {e}"),
                diagnostics_id: None,
            })?;

        match self.writer.update_for_sid(ctx.caller_stored(), &req) {
            Ok(dto) => {
                // The policy is durably written; trigger a mid-session WFP
                // recompile for this SID (no-op when it isn't routing-active,
                // or when no orchestrator is wired). Best-effort: errors are
                // logged inside the trigger, never surfaced — the write
                // already succeeded.
                if let Some(trigger) = self.apply_trigger.as_ref() {
                    trigger.on_policy_changed(ctx.caller_stored());
                }
                serde_json::to_value(dto).map_err(|e| IpcError {
                    code: IpcErrorCode::Internal,
                    message: format!("route.policy.update response serialisation failed: {e}"),
                    diagnostics_id: None,
                })
            }
            Err(e) => Err(map_write_error(e)),
        }
    }
}

fn map_write_error(err: RoutePolicyWriteError) -> IpcError {
    match err {
        RoutePolicyWriteError::EmptySid => IpcError {
            code: IpcErrorCode::Internal,
            message: err.to_string(),
            diagnostics_id: None,
        },
        RoutePolicyWriteError::UnknownAdapter { .. }
        | RoutePolicyWriteError::PrimaryEqualsSecondary
        | RoutePolicyWriteError::StrictModeRequiresSecondary => IpcError {
            code: IpcErrorCode::PreconditionFailed,
            message: err.to_string(),
            diagnostics_id: None,
        },
        RoutePolicyWriteError::Storage(_) => IpcError {
            code: IpcErrorCode::Internal,
            message: err.to_string(),
            diagnostics_id: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::{IpcOperationClass, IPC_PROTOCOL_VERSION};
    use crate::ipc_handlers::payloads::{
        BehaviorModeDto, BindingSourceDto, RouteBindingDto, RoutePolicyDto,
    };
    use nrr_shared::ipc::{IpcClientProfile, IpcOperationName};
    use std::sync::Mutex;

    struct ScriptedWriter {
        outcome: Mutex<Result<RoutePolicyDto, RoutePolicyWriteError>>,
        seen_sid: Mutex<Option<String>>,
    }
    impl RoutePolicyWriter for ScriptedWriter {
        fn update_for_sid(
            &self,
            sid: &str,
            _req: &RoutePolicyUpdateRequest,
        ) -> Result<RoutePolicyDto, RoutePolicyWriteError> {
            *self.seen_sid.lock().unwrap() = Some(sid.to_string());
            self.outcome.lock().unwrap().clone()
        }
    }

    fn ctx(sid: &str) -> IpcRequestContext {
        IpcRequestContext {
            client_profile: IpcClientProfile::GuiInteractive,
            caller_is_elevated: false,
            caller_principal: crate::UserPrincipal::from_windows_sid(sid).ok(),
        }
    }

    fn req(payload: serde_json::Value) -> IpcRequestEnvelope {
        IpcRequestEnvelope {
            protocol_version: IPC_PROTOCOL_VERSION,
            request_id: "r-1".into(),
            correlation_id: None,
            operation: IpcOperationName::RoutePolicyUpdate,
            operation_class: IpcOperationClass::UserScopedConfiguration,
            confirmation_token: None,
            payload,
        }
    }

    fn sample_dto() -> RoutePolicyDto {
        RoutePolicyDto {
            primary: Some(RouteBindingDto {
                stable_id: "Wi-Fi".into(),
                display_name: "Wi-Fi".into(),
                user_confirmed: true,
            }),
            secondary: None,
            mode: BehaviorModeDto::PreferPrimary,
            block_secondary_when_unavailable: false,
            kill_switch_fail_closed: true,
            kill_switch_protocols: 0x7F,
            kill_switch_block_all: false,
            kill_switch_enabled: false,
            allow_dns_over_primary: false,
            include_subdomains: false,
            shared_ip_policy: "majority-of-ip".into(),
            mode_a_coverage_strategy: "per-ip".into(),
            resolve_hosts_bypass: true,
            secondary_link_provider_apps: Vec::new(),
            doh_lockdown_enabled: false,
            doh_lockdown_scope: "leak-protection-only".into(),
            browser_history_auto_seed: false,
            kill_switch_strict_shared_ips: false,
            auto_rules_mode: "suggest".to_string(),
            auto_rules_eager_delivery_names: false,
            binding_source: BindingSourceDto::UserAssigned,
        }
    }

    #[test]
    fn empty_sid_is_internal_error_before_writer_is_called() {
        let writer = Arc::new(ScriptedWriter {
            outcome: Mutex::new(Ok(sample_dto())),
            seen_sid: Mutex::new(None),
        });
        let h = RoutePolicyUpdateHandler::new(writer.clone() as Arc<dyn RoutePolicyWriter>, None);
        let payload = serde_json::to_value(RoutePolicyUpdateRequest {
            primary: None,
            secondary: None,
            mode: BehaviorModeDto::PreferPrimary,
            block_secondary_when_unavailable: false,
            kill_switch_fail_closed: true,
            kill_switch_protocols: 0x7F,
            kill_switch_block_all: false,
            kill_switch_enabled: false,
            allow_dns_over_primary: false,
            include_subdomains: false,
            shared_ip_policy: "majority-of-ip".into(),
            mode_a_coverage_strategy: "per-ip".into(),
            resolve_hosts_bypass: true,
            doh_lockdown_enabled: false,
            doh_lockdown_scope: "leak-protection-only".into(),
            browser_history_auto_seed: false,
            kill_switch_strict_shared_ips: false,
            auto_rules_mode: "suggest".to_string(),
            auto_rules_eager_delivery_names: false,
            binding_source: BindingSourceDto::UserAssigned,
        })
        .unwrap();
        let err = h.handle(&req(payload), &ctx("")).unwrap_err();
        assert_eq!(err.code, IpcErrorCode::Internal);
        assert!(err.message.contains("SID unavailable"));
        assert!(writer.seen_sid.lock().unwrap().is_none());
    }

    #[test]
    fn malformed_payload_is_malformed_request() {
        let writer = Arc::new(ScriptedWriter {
            outcome: Mutex::new(Ok(sample_dto())),
            seen_sid: Mutex::new(None),
        });
        let h = RoutePolicyUpdateHandler::new(writer as Arc<dyn RoutePolicyWriter>, None);
        let err = h
            .handle(&req(serde_json::json!({"garbage": 1})), &ctx("S"))
            .unwrap_err();
        assert_eq!(err.code, IpcErrorCode::MalformedRequest);
    }

    #[test]
    fn writer_unknown_adapter_maps_to_precondition_failed() {
        let writer = Arc::new(ScriptedWriter {
            outcome: Mutex::new(Err(RoutePolicyWriteError::UnknownAdapter {
                stable_id: "ghost".into(),
            })),
            seen_sid: Mutex::new(None),
        });
        let h = RoutePolicyUpdateHandler::new(writer as Arc<dyn RoutePolicyWriter>, None);
        let payload = serde_json::to_value(RoutePolicyUpdateRequest {
            primary: Some(RouteBindingDto {
                stable_id: "ghost".into(),
                display_name: "?".into(),
                user_confirmed: false,
            }),
            secondary: None,
            mode: BehaviorModeDto::PreferPrimary,
            block_secondary_when_unavailable: false,
            kill_switch_fail_closed: true,
            kill_switch_protocols: 0x7F,
            kill_switch_block_all: false,
            kill_switch_enabled: false,
            allow_dns_over_primary: false,
            include_subdomains: false,
            shared_ip_policy: "majority-of-ip".into(),
            mode_a_coverage_strategy: "per-ip".into(),
            resolve_hosts_bypass: true,
            doh_lockdown_enabled: false,
            doh_lockdown_scope: "leak-protection-only".into(),
            browser_history_auto_seed: false,
            kill_switch_strict_shared_ips: false,
            auto_rules_mode: "suggest".to_string(),
            auto_rules_eager_delivery_names: false,
            binding_source: BindingSourceDto::UserAssigned,
        })
        .unwrap();
        let err = h.handle(&req(payload), &ctx("S")).unwrap_err();
        assert_eq!(err.code, IpcErrorCode::PreconditionFailed);
        assert!(err.message.contains("ghost"));
    }

    #[test]
    fn writer_strict_mode_violation_maps_to_precondition_failed() {
        let writer = Arc::new(ScriptedWriter {
            outcome: Mutex::new(Err(RoutePolicyWriteError::StrictModeRequiresSecondary)),
            seen_sid: Mutex::new(None),
        });
        let h = RoutePolicyUpdateHandler::new(writer as Arc<dyn RoutePolicyWriter>, None);
        let payload = serde_json::to_value(RoutePolicyUpdateRequest {
            primary: None,
            secondary: None,
            mode: BehaviorModeDto::StrictSecondaryFailClosed,
            block_secondary_when_unavailable: false,
            kill_switch_fail_closed: true,
            kill_switch_protocols: 0x7F,
            kill_switch_block_all: false,
            kill_switch_enabled: false,
            allow_dns_over_primary: false,
            include_subdomains: false,
            shared_ip_policy: "majority-of-ip".into(),
            mode_a_coverage_strategy: "per-ip".into(),
            resolve_hosts_bypass: true,
            doh_lockdown_enabled: false,
            doh_lockdown_scope: "leak-protection-only".into(),
            browser_history_auto_seed: false,
            kill_switch_strict_shared_ips: false,
            auto_rules_mode: "suggest".to_string(),
            auto_rules_eager_delivery_names: false,
            binding_source: BindingSourceDto::UserAssigned,
        })
        .unwrap();
        let err = h.handle(&req(payload), &ctx("S")).unwrap_err();
        assert_eq!(err.code, IpcErrorCode::PreconditionFailed);
    }

    #[test]
    fn writer_storage_error_maps_to_internal() {
        let writer = Arc::new(ScriptedWriter {
            outcome: Mutex::new(Err(RoutePolicyWriteError::Storage("disk full".into()))),
            seen_sid: Mutex::new(None),
        });
        let h = RoutePolicyUpdateHandler::new(writer as Arc<dyn RoutePolicyWriter>, None);
        let payload = serde_json::to_value(RoutePolicyUpdateRequest {
            primary: None,
            secondary: None,
            mode: BehaviorModeDto::PreferPrimary,
            block_secondary_when_unavailable: false,
            kill_switch_fail_closed: true,
            kill_switch_protocols: 0x7F,
            kill_switch_block_all: false,
            kill_switch_enabled: false,
            allow_dns_over_primary: false,
            include_subdomains: false,
            shared_ip_policy: "majority-of-ip".into(),
            mode_a_coverage_strategy: "per-ip".into(),
            resolve_hosts_bypass: true,
            doh_lockdown_enabled: false,
            doh_lockdown_scope: "leak-protection-only".into(),
            browser_history_auto_seed: false,
            kill_switch_strict_shared_ips: false,
            auto_rules_mode: "suggest".to_string(),
            auto_rules_eager_delivery_names: false,
            binding_source: BindingSourceDto::UserAssigned,
        })
        .unwrap();
        let err = h.handle(&req(payload), &ctx("S")).unwrap_err();
        assert_eq!(err.code, IpcErrorCode::Internal);
        assert!(err.message.contains("disk full"));
    }

    #[test]
    fn success_returns_full_policy_dto() {
        let dto = sample_dto();
        let writer = Arc::new(ScriptedWriter {
            outcome: Mutex::new(Ok(dto.clone())),
            seen_sid: Mutex::new(None),
        });
        let h =
            RoutePolicyUpdateHandler::new(Arc::clone(&writer) as Arc<dyn RoutePolicyWriter>, None);
        let payload = serde_json::to_value(RoutePolicyUpdateRequest {
            primary: dto.primary.clone(),
            secondary: dto.secondary.clone(),
            mode: dto.mode,
            block_secondary_when_unavailable: dto.block_secondary_when_unavailable,
            kill_switch_fail_closed: dto.kill_switch_fail_closed,
            kill_switch_protocols: dto.kill_switch_protocols,
            kill_switch_block_all: dto.kill_switch_block_all,
            kill_switch_enabled: dto.kill_switch_enabled,
            allow_dns_over_primary: dto.allow_dns_over_primary,
            include_subdomains: dto.include_subdomains,
            shared_ip_policy: dto.shared_ip_policy.clone(),
            mode_a_coverage_strategy: dto.mode_a_coverage_strategy.clone(),
            resolve_hosts_bypass: dto.resolve_hosts_bypass,
            doh_lockdown_enabled: dto.doh_lockdown_enabled,
            doh_lockdown_scope: dto.doh_lockdown_scope.clone(),
            browser_history_auto_seed: dto.browser_history_auto_seed,
            kill_switch_strict_shared_ips: dto.kill_switch_strict_shared_ips,
            auto_rules_mode: dto.auto_rules_mode.clone(),
            auto_rules_eager_delivery_names: dto.auto_rules_eager_delivery_names,
            binding_source: dto.binding_source,
        })
        .unwrap();
        let value = h.handle(&req(payload), &ctx("S-1-5-21-A")).unwrap();
        let parsed: RoutePolicyDto = serde_json::from_value(value).unwrap();
        assert_eq!(parsed, dto);
        assert_eq!(
            writer.seen_sid.lock().unwrap().as_deref(),
            Some("S-1-5-21-A")
        );
    }

    /// Records the SID it was fired with so
    /// the handler tests can assert the post-write recompile hook ran (or not).
    struct RecordingTrigger {
        fired_for: Mutex<Vec<String>>,
    }
    impl RoutePolicyApplyTrigger for RecordingTrigger {
        fn on_policy_changed(&self, sid: &str) {
            self.fired_for.lock().unwrap().push(sid.to_string());
        }
    }

    #[test]
    fn successful_write_fires_apply_trigger_with_caller_sid() {
        let dto = sample_dto();
        let writer = Arc::new(ScriptedWriter {
            outcome: Mutex::new(Ok(dto.clone())),
            seen_sid: Mutex::new(None),
        });
        let trigger = Arc::new(RecordingTrigger {
            fired_for: Mutex::new(Vec::new()),
        });
        let h = RoutePolicyUpdateHandler::new(
            writer as Arc<dyn RoutePolicyWriter>,
            Some(Arc::clone(&trigger) as Arc<dyn RoutePolicyApplyTrigger>),
        );
        let payload = serde_json::to_value(RoutePolicyUpdateRequest {
            primary: dto.primary.clone(),
            secondary: dto.secondary.clone(),
            mode: dto.mode,
            block_secondary_when_unavailable: dto.block_secondary_when_unavailable,
            kill_switch_fail_closed: dto.kill_switch_fail_closed,
            kill_switch_protocols: dto.kill_switch_protocols,
            kill_switch_block_all: dto.kill_switch_block_all,
            kill_switch_enabled: dto.kill_switch_enabled,
            allow_dns_over_primary: dto.allow_dns_over_primary,
            include_subdomains: dto.include_subdomains,
            shared_ip_policy: dto.shared_ip_policy.clone(),
            mode_a_coverage_strategy: dto.mode_a_coverage_strategy.clone(),
            resolve_hosts_bypass: dto.resolve_hosts_bypass,
            doh_lockdown_enabled: dto.doh_lockdown_enabled,
            doh_lockdown_scope: dto.doh_lockdown_scope.clone(),
            browser_history_auto_seed: dto.browser_history_auto_seed,
            kill_switch_strict_shared_ips: dto.kill_switch_strict_shared_ips,
            auto_rules_mode: dto.auto_rules_mode.clone(),
            auto_rules_eager_delivery_names: dto.auto_rules_eager_delivery_names,
            binding_source: dto.binding_source,
        })
        .unwrap();
        h.handle(&req(payload), &ctx("S-1-5-21-A")).unwrap();
        assert_eq!(
            trigger.fired_for.lock().unwrap().as_slice(),
            &["S-1-5-21-A".to_string()],
            "successful per-SID policy write must fire the recompile hook with the caller SID"
        );
    }

    #[test]
    fn failed_write_does_not_fire_apply_trigger() {
        let writer = Arc::new(ScriptedWriter {
            outcome: Mutex::new(Err(RoutePolicyWriteError::Storage("disk full".into()))),
            seen_sid: Mutex::new(None),
        });
        let trigger = Arc::new(RecordingTrigger {
            fired_for: Mutex::new(Vec::new()),
        });
        let h = RoutePolicyUpdateHandler::new(
            writer as Arc<dyn RoutePolicyWriter>,
            Some(Arc::clone(&trigger) as Arc<dyn RoutePolicyApplyTrigger>),
        );
        let payload = serde_json::to_value(RoutePolicyUpdateRequest {
            primary: None,
            secondary: None,
            mode: BehaviorModeDto::PreferPrimary,
            block_secondary_when_unavailable: false,
            kill_switch_fail_closed: true,
            kill_switch_protocols: 0x7F,
            kill_switch_block_all: false,
            kill_switch_enabled: false,
            allow_dns_over_primary: false,
            include_subdomains: false,
            shared_ip_policy: "majority-of-ip".into(),
            mode_a_coverage_strategy: "per-ip".into(),
            resolve_hosts_bypass: true,
            doh_lockdown_enabled: false,
            doh_lockdown_scope: "leak-protection-only".into(),
            browser_history_auto_seed: false,
            kill_switch_strict_shared_ips: false,
            auto_rules_mode: "suggest".to_string(),
            auto_rules_eager_delivery_names: false,
            binding_source: BindingSourceDto::UserAssigned,
        })
        .unwrap();
        let _ = h.handle(&req(payload), &ctx("S")).unwrap_err();
        assert!(
            trigger.fired_for.lock().unwrap().is_empty(),
            "a failed write must NOT fire the recompile hook"
        );
    }
}
