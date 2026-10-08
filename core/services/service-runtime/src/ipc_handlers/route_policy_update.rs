//! `RoutePolicyUpdate` handler.
//!
//! Atomically writes the caller's per-SID route policy (primary +
//! secondary bindings + behavior mode + secondary-block flag) to
//! `nrr_service_state.db`. Validation runs server-side: a `stable_id` from the
//! placeholder dataset is refused here, and the writer holds the rest
//! (`mode = strict-...` requires a bound secondary, primary ≠ secondary).
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

        let payload = apply_only_over_stored(request.payload.clone(), || {
            self.writer.stored_for_sid(ctx.caller_stored())
        })?;
        let req: RoutePolicyUpdateRequest =
            serde_json::from_value(payload).map_err(|e| malformed(format!("{e}")))?;

        // The placeholder rows a GUI shows when no live enumeration arrived name
        // no adapter of this machine. Refused here rather than in the GUI: a
        // stored binding to one produces an apply that silently changes nothing,
        // and the check belongs where every client passes.
        if let Some(stable_id) = placeholder_binding(&req) {
            return Err(map_write_error(RoutePolicyWriteError::PlaceholderAdapter {
                stable_id,
            }));
        }

        if !nrr_shared::ipc_payloads::is_valid_kill_switch_protocols(req.kill_switch_protocols) {
            return Err(map_write_error(
                RoutePolicyWriteError::InvalidKillSwitchProtocols {
                    bits: req.kill_switch_protocols,
                },
            ));
        }

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

fn malformed(detail: String) -> IpcError {
    IpcError {
        code: IpcErrorCode::MalformedRequest,
        message: format!("route.policy.update payload invalid: {detail}"),
        diagnostics_id: None,
    }
}

/// An `apply-only` request laid over the stored row: the named fields from the
/// request, the rest as stored, provenance from the request. With nothing
/// stored yet the request writes whole, as one without the list does.
fn apply_only_over_stored(
    payload: serde_json::Value,
    stored: impl FnOnce() -> Option<nrr_shared::ipc_payloads::RoutePolicyDto>,
) -> Result<serde_json::Value, IpcError> {
    let only: Vec<String> = match payload.get("apply-only") {
        None => return Ok(payload),
        Some(list) => serde_json::from_value(list.clone())
            .map_err(|e| malformed(format!("apply-only: {e}")))?,
    };
    if only.is_empty() {
        return Ok(payload);
    }
    // A slot may be named while absent: that is how a request unbinds it.
    if let Some(unknown) = only.iter().find(|name| {
        payload.get(name.as_str()).is_none() && !matches!(name.as_str(), "primary" | "secondary")
    }) {
        return Err(malformed(format!(
            "apply-only names `{unknown}`, which the request lacks"
        )));
    }
    let Some(stored) = stored() else {
        return Ok(payload);
    };
    let serde_json::Value::Object(mut base) =
        serde_json::to_value(stored).map_err(|e| malformed(format!("stored policy: {e}")))?
    else {
        return Ok(payload);
    };
    for name in only.iter().map(String::as_str).chain(["binding-source"]) {
        match payload.get(name) {
            Some(value) => base.insert(name.to_owned(), value.clone()),
            None => base.remove(name),
        };
    }
    Ok(serde_json::Value::Object(base))
}

/// The first binding in `req` naming a placeholder adapter, if any.
fn placeholder_binding(req: &RoutePolicyUpdateRequest) -> Option<String> {
    [req.primary.as_ref(), req.secondary.as_ref()]
        .into_iter()
        .flatten()
        .map(|b| b.stable_id.as_str())
        .find(|id| nrr_platform_api::interface_rows::is_preview_persistent_id(id))
        .map(str::to_string)
}

fn map_write_error(err: RoutePolicyWriteError) -> IpcError {
    match err {
        RoutePolicyWriteError::EmptySid => IpcError {
            code: IpcErrorCode::Internal,
            message: err.to_string(),
            diagnostics_id: None,
        },
        RoutePolicyWriteError::UnknownAdapter { .. }
        | RoutePolicyWriteError::PlaceholderAdapter { .. }
        | RoutePolicyWriteError::PrimaryEqualsSecondary
        | RoutePolicyWriteError::StrictModeRequiresSecondary
        | RoutePolicyWriteError::InvalidNetworkDomain
        | RoutePolicyWriteError::InvalidKillSwitchProtocols { .. } => IpcError {
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
            caller_pid: None,
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
                known_stable_ids: Vec::new(),
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
            primary_probe_auto: false,
            primary_probe_timeout_ms: 1500,
            primary_probe_max_targets: 8,
            primary_probe_repeat_secs: 300,
            local_networks_auto_accept: false,
            zone_priority_over_ip: false,
            short_name_completion: false,
            short_name_suffix: String::new(),
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
            primary_probe_auto: false,
            primary_probe_timeout_ms: 1500,
            primary_probe_max_targets: 8,
            primary_probe_repeat_secs: 300,
            local_networks_auto_accept: false,
            zone_priority_over_ip: false,
            short_name_completion: false,
            short_name_suffix: String::new(),
            binding_source: BindingSourceDto::UserAssigned,
            apply_only: Vec::new(),
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

    /// The payload a GUI sends to bind `stable_id` as primary. Built from the
    /// sample policy so a field added to the request cannot quietly go missing
    /// here.
    fn bind_primary_payload(stable_id: &str) -> serde_json::Value {
        let mut payload = serde_json::to_value(sample_dto()).expect("policy serialises");
        payload["primary"]["stable-id"] = serde_json::Value::String(stable_id.to_string());
        payload
    }

    #[test]
    fn a_placeholder_adapter_is_refused_before_the_writer_is_called() {
        let writer = Arc::new(ScriptedWriter {
            outcome: Mutex::new(Ok(sample_dto())),
            seen_sid: Mutex::new(None),
        });
        let h = RoutePolicyUpdateHandler::new(writer.clone() as Arc<dyn RoutePolicyWriter>, None);
        let placeholder = nrr_platform_api::interface_rows::PREVIEW_WIFI_PERSISTENT_ID;
        let err = h
            .handle(&req(bind_primary_payload(placeholder)), &ctx("S-1-5-21-1"))
            .unwrap_err();
        assert_eq!(err.code, IpcErrorCode::PreconditionFailed);
        assert!(err.message.contains(placeholder), "{}", err.message);
        assert!(
            writer.seen_sid.lock().unwrap().is_none(),
            "a binding that names no adapter of this machine must not reach storage"
        );
    }

    /// Leak protection is switched off by its master toggle; a mask with no
    /// protocol left would read as on while blocking nothing.
    #[test]
    fn a_protocol_mask_that_selects_nothing_is_refused_before_the_writer() {
        for bits in [0u16, 0x80] {
            let writer = Arc::new(ScriptedWriter {
                outcome: Mutex::new(Ok(sample_dto())),
                seen_sid: Mutex::new(None),
            });
            let h =
                RoutePolicyUpdateHandler::new(writer.clone() as Arc<dyn RoutePolicyWriter>, None);
            let mut payload = bind_primary_payload("Wi-Fi");
            payload["kill-switch-protocols"] = bits.into();
            let err = h
                .handle(&req(payload), &ctx("S-1-5-21-1"))
                .expect_err("an empty mask is refused");
            assert_eq!(err.code, IpcErrorCode::PreconditionFailed, "{bits:#x}");
            assert!(writer.seen_sid.lock().unwrap().is_none(), "{bits:#x}");
        }
    }

    #[test]
    fn a_live_adapter_id_still_reaches_the_writer() {
        let writer = Arc::new(ScriptedWriter {
            outcome: Mutex::new(Ok(sample_dto())),
            seen_sid: Mutex::new(None),
        });
        let h = RoutePolicyUpdateHandler::new(writer.clone() as Arc<dyn RoutePolicyWriter>, None);
        h.handle(
            &req(bind_primary_payload("linux-adapter:wlp3s0")),
            &ctx("S-1-5-21-1"),
        )
        .expect("a live adapter id is accepted");
        assert_eq!(
            writer.seen_sid.lock().unwrap().as_deref(),
            Some("S-1-5-21-1")
        );
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
                known_stable_ids: Vec::new(),
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
            primary_probe_auto: false,
            primary_probe_timeout_ms: 1500,
            primary_probe_max_targets: 8,
            primary_probe_repeat_secs: 300,
            local_networks_auto_accept: false,
            zone_priority_over_ip: false,
            short_name_completion: false,
            short_name_suffix: String::new(),
            binding_source: BindingSourceDto::UserAssigned,
            apply_only: Vec::new(),
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
            primary_probe_auto: false,
            primary_probe_timeout_ms: 1500,
            primary_probe_max_targets: 8,
            primary_probe_repeat_secs: 300,
            local_networks_auto_accept: false,
            zone_priority_over_ip: false,
            short_name_completion: false,
            short_name_suffix: String::new(),
            binding_source: BindingSourceDto::UserAssigned,
            apply_only: Vec::new(),
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
            primary_probe_auto: false,
            primary_probe_timeout_ms: 1500,
            primary_probe_max_targets: 8,
            primary_probe_repeat_secs: 300,
            local_networks_auto_accept: false,
            zone_priority_over_ip: false,
            short_name_completion: false,
            short_name_suffix: String::new(),
            binding_source: BindingSourceDto::UserAssigned,
            apply_only: Vec::new(),
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
            primary_probe_auto: false,
            primary_probe_timeout_ms: 1500,
            primary_probe_max_targets: 8,
            primary_probe_repeat_secs: 300,
            local_networks_auto_accept: false,
            zone_priority_over_ip: false,
            short_name_completion: false,
            short_name_suffix: String::new(),
            binding_source: dto.binding_source,
            apply_only: Vec::new(),
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
            primary_probe_auto: false,
            primary_probe_timeout_ms: 1500,
            primary_probe_max_targets: 8,
            primary_probe_repeat_secs: 300,
            local_networks_auto_accept: false,
            zone_priority_over_ip: false,
            short_name_completion: false,
            short_name_suffix: String::new(),
            binding_source: dto.binding_source,
            apply_only: Vec::new(),
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
            primary_probe_auto: false,
            primary_probe_timeout_ms: 1500,
            primary_probe_max_targets: 8,
            primary_probe_repeat_secs: 300,
            local_networks_auto_accept: false,
            zone_priority_over_ip: false,
            short_name_completion: false,
            short_name_suffix: String::new(),
            binding_source: BindingSourceDto::UserAssigned,
            apply_only: Vec::new(),
        })
        .unwrap();
        let _ = h.handle(&req(payload), &ctx("S")).unwrap_err();
        assert!(
            trigger.fired_for.lock().unwrap().is_empty(),
            "a failed write must NOT fire the recompile hook"
        );
    }

    /// Two clients each writing the row they read lose each other's change;
    /// a request naming its fields lands on the stored row instead.
    #[test]
    fn an_apply_only_request_changes_only_what_it_names() {
        // What the window read before the tray turned the kill switch on.
        let mut stale = serde_json::to_value(sample_dto()).expect("dto");
        stale["auto-rules-mode"] = serde_json::json!("auto");
        stale["apply-only"] = serde_json::json!(["auto-rules-mode"]);
        stale["binding-source"] = serde_json::json!("user-assigned");
        let mut stored = sample_dto();
        stored.kill_switch_enabled = true;

        let merged = apply_only_over_stored(stale, || Some(stored)).expect("merged");
        let req: RoutePolicyUpdateRequest = serde_json::from_value(merged).expect("request");
        assert_eq!(req.auto_rules_mode, "auto");
        assert!(req.kill_switch_enabled, "the tray's change survives");
        assert_eq!(req.binding_source, BindingSourceDto::UserAssigned);
    }

    #[test]
    fn naming_an_absent_slot_unbinds_it_and_an_unknown_name_is_refused() {
        let mut unbind = serde_json::to_value(sample_dto()).expect("dto");
        unbind.as_object_mut().expect("object").remove("primary");
        unbind["apply-only"] = serde_json::json!(["primary"]);
        let merged = apply_only_over_stored(unbind, || Some(sample_dto())).expect("merged");
        let req: RoutePolicyUpdateRequest = serde_json::from_value(merged).expect("request");
        assert!(req.primary.is_none());

        let mut typo = serde_json::to_value(sample_dto()).expect("dto");
        typo["apply-only"] = serde_json::json!(["kill-switch-enable"]);
        let err = apply_only_over_stored(typo, || Some(sample_dto())).expect_err("refused");
        assert_eq!(err.code, IpcErrorCode::MalformedRequest);
    }

    #[test]
    fn with_nothing_stored_an_apply_only_request_writes_whole() {
        let mut first = serde_json::to_value(sample_dto()).expect("dto");
        first["kill-switch-enabled"] = serde_json::json!(true);
        first["apply-only"] = serde_json::json!(["kill-switch-enabled"]);
        let merged = apply_only_over_stored(first.clone(), || None).expect("merged");
        assert_eq!(merged, first);
    }
}
