//! `RoutePolicyUpdate` handler.
//!
//! Atomically writes the caller's per-SID route policy (primary +
//! secondary bindings + behavior mode + leak protection) to
//! `nrr_service_state.db`. Validation runs server-side: a placeholder
//! `stable_id` and leak protection `sites` under the additional default route
//! are refused here, and the writer holds the rest (primary ≠ secondary).
//!
//! User-scoped class (`UserScopedConfiguration` in `IpcOperationClass`):
//! flows through the mutation queue (single-writer invariant) and is
//! audited before execution, but does not require an elevated client.

use std::sync::{Arc, Mutex};

use crate::ipc::{
    CheckedIpcHandler, HandlerOutcome, IpcError, IpcErrorCode, IpcRequestContext,
    IpcRequestEnvelope, Prechecked,
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
    /// Held across "read the stored row, lay the request over it, write": the
    /// mutation queue admits several at once, and two partial updates racing
    /// here would each write over the other's field.
    write_gate: Mutex<()>,
}

impl RoutePolicyUpdateHandler {
    pub fn new(
        writer: Arc<dyn RoutePolicyWriter>,
        apply_trigger: Option<Arc<dyn RoutePolicyApplyTrigger>>,
    ) -> Self {
        Self {
            writer,
            apply_trigger,
            write_gate: Mutex::new(()),
        }
    }
}

impl CheckedIpcHandler for RoutePolicyUpdateHandler {
    /// The request with any `apply-only` fields laid over the stored row.
    type Checked = RoutePolicyUpdateRequest;

    fn precheck(
        &self,
        request: &IpcRequestEnvelope,
        ctx: &IpcRequestContext,
    ) -> Result<Self::Checked, IpcError> {
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

        if sites_under_additional_route(&req) {
            return Err(map_write_error(RoutePolicyWriteError::SitesNeedsMainRoute));
        }

        if !nrr_shared::ipc_payloads::is_valid_kill_switch_protocols(req.kill_switch_protocols) {
            return Err(map_write_error(
                RoutePolicyWriteError::InvalidKillSwitchProtocols {
                    bits: req.kill_switch_protocols,
                },
            ));
        }
        Ok(req)
    }

    fn execute(
        &self,
        req: Prechecked<Self::Checked>,
        request: &IpcRequestEnvelope,
        ctx: &IpcRequestContext,
    ) -> HandlerOutcome {
        let _gate = self
            .write_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Laid over the row as it is now, not as the precheck saw it.
        let req = match request.payload.get("apply-only") {
            Some(list) if list.as_array().is_some_and(|l| !l.is_empty()) => {
                let merged = apply_only_over_stored(request.payload.clone(), || {
                    self.writer.stored_for_sid(ctx.caller_stored())
                })?;
                let merged: RoutePolicyUpdateRequest =
                    serde_json::from_value(merged).map_err(|e| malformed(format!("{e}")))?;
                // The row may have changed since the precheck merged over it.
                if sites_under_additional_route(&merged) {
                    return Err(map_write_error(RoutePolicyWriteError::SitesNeedsMainRoute));
                }
                merged
            }
            _ => req.into_inner(),
        };
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

/// Most unknown keys a refusal names, and the longest spelling of each: the
/// keys come from the peer.
const NAMED_UNKNOWN_KEYS: usize = 8;
const NAMED_KEY_CHARS: usize = 64;

/// A key this build does not know is refused before anything is merged: the
/// merge below takes only the named fields, so an unknown one would otherwise
/// vanish and the rest of the request apply as if it had said nothing.
fn refuse_unknown_keys(payload: &serde_json::Value) -> Result<(), IpcError> {
    let Some(fields) = payload.as_object() else {
        return Ok(());
    };
    let unknown = nrr_shared::wire_fields::unknown_wire_keys::<RoutePolicyUpdateRequest>(fields);
    if unknown.is_empty() {
        return Ok(());
    }
    let named: Vec<String> = unknown
        .iter()
        .take(NAMED_UNKNOWN_KEYS)
        .map(|key| key.chars().take(NAMED_KEY_CHARS).collect())
        .collect();
    Err(malformed(format!(
        "fields this service does not know: {}; the client and the service are from different \
         builds",
        named.join(", ")
    )))
}

/// An `apply-only` request laid over the stored row: the named fields from the
/// request, the rest as stored, provenance from the request. With nothing
/// stored yet the request writes whole, as one without the list does.
fn apply_only_over_stored(
    payload: serde_json::Value,
    stored: impl FnOnce() -> Option<nrr_shared::ipc_payloads::RoutePolicyDto>,
) -> Result<serde_json::Value, IpcError> {
    refuse_unknown_keys(&payload)?;
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
    for key in nrr_shared::ipc_payloads::ROUTE_POLICY_SNAPSHOT_ONLY_KEYS {
        base.remove(key);
    }
    for name in only.iter().map(String::as_str).chain(["binding-source"]) {
        match payload.get(name) {
            Some(value) => base.insert(name.to_owned(), value.clone()),
            None => base.remove(name),
        };
    }
    Ok(serde_json::Value::Object(base))
}

/// `sites` would mean `everything` there; no client offers it, so a request
/// carrying it is refused rather than silently widened.
fn sites_under_additional_route(req: &RoutePolicyUpdateRequest) -> bool {
    use nrr_shared::ipc_payloads::{BehaviorModeDto, LeakProtectionDto};
    req.leak_protection == LeakProtectionDto::Sites
        && req.mode == BehaviorModeDto::PreferSecondaryWhenAvailable
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
        | RoutePolicyWriteError::SitesNeedsMainRoute
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
    use crate::ipc::{IpcHandler, IpcOperationClass, IPC_PROTOCOL_VERSION};
    use crate::ipc_handlers::payloads::{
        BehaviorModeDto, BindingSourceDto, LeakProtectionDto, RouteBindingDto, RoutePolicyDto,
    };
    use crate::ipc_handlers::providers::SITES_NEEDS_MAIN_ROUTE_CODE;
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
            leak_protection: LeakProtectionDto::Off,
            kill_switch_protocols: 0x7F,
            allow_dns_over_primary: false,
            include_subdomains: false,
            shared_ip_policy: "majority-of-ip".into(),
            resolve_hosts_bypass: true,
            secondary_link_provider_apps: Vec::new(),
            doh_lockdown_enabled: false,
            doh_lockdown_scope: "leak-protection-only".into(),
            doh_lockdown_auto: true,
            doh_lockdown_effective: false,
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
            app_rules_take_all_addresses: false,
            forwarded_outage: String::new(),
            external_address_auto_check: false,
            binding_source: BindingSourceDto::UserAssigned,
        }
    }

    /// `dto` as a client echoes it back: the snapshot-only keys dropped.
    fn request_json(dto: &RoutePolicyDto) -> serde_json::Value {
        let mut value = serde_json::to_value(dto).expect("dto");
        for key in nrr_shared::ipc_payloads::ROUTE_POLICY_SNAPSHOT_ONLY_KEYS {
            value.as_object_mut().expect("object").remove(key);
        }
        value
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
            leak_protection: LeakProtectionDto::Off,
            kill_switch_protocols: 0x7F,
            allow_dns_over_primary: false,
            include_subdomains: false,
            shared_ip_policy: "majority-of-ip".into(),
            resolve_hosts_bypass: true,
            doh_lockdown_enabled: false,
            doh_lockdown_scope: "leak-protection-only".into(),
            doh_lockdown_auto: true,
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
            app_rules_take_all_addresses: false,
            forwarded_outage: String::new(),
            external_address_auto_check: false,
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
        let mut payload = request_json(&sample_dto());
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

    /// Leak protection is switched off by choosing `off`; a mask with no
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

    /// The opt-in that sends a request through the tunnel takes a boolean and
    /// nothing that merely looks like one.
    #[test]
    fn the_external_address_check_is_validated_before_the_writer() {
        let writer = Arc::new(ScriptedWriter {
            outcome: Mutex::new(Ok(sample_dto())),
            seen_sid: Mutex::new(None),
        });
        let h = RoutePolicyUpdateHandler::new(writer.clone() as Arc<dyn RoutePolicyWriter>, None);
        let mut payload = bind_primary_payload("Wi-Fi");
        payload["external-address-auto-check"] = serde_json::json!("yes");
        let err = h
            .handle(&req(payload), &ctx("S-1-5-21-1"))
            .expect_err("a string is not a choice");
        assert_eq!(err.code, IpcErrorCode::MalformedRequest);
        assert!(writer.seen_sid.lock().unwrap().is_none());

        let mut on = request_json(&sample_dto());
        on["external-address-auto-check"] = serde_json::json!(true);
        on["apply-only"] = serde_json::json!(["external-address-auto-check"]);
        on["binding-source"] = serde_json::json!("user-assigned");
        let mut stored = sample_dto();
        stored.leak_protection = LeakProtectionDto::Everything;
        let merged = apply_only_over_stored(on, || Some(stored)).expect("merged");
        let req: RoutePolicyUpdateRequest = serde_json::from_value(merged).expect("request");
        assert!(req.external_address_auto_check);
        assert_eq!(req.leak_protection, LeakProtectionDto::Everything);
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
            leak_protection: LeakProtectionDto::Off,
            kill_switch_protocols: 0x7F,
            allow_dns_over_primary: false,
            include_subdomains: false,
            shared_ip_policy: "majority-of-ip".into(),
            resolve_hosts_bypass: true,
            doh_lockdown_enabled: false,
            doh_lockdown_scope: "leak-protection-only".into(),
            doh_lockdown_auto: true,
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
            app_rules_take_all_addresses: false,
            forwarded_outage: String::new(),
            external_address_auto_check: false,
            binding_source: BindingSourceDto::UserAssigned,
            apply_only: Vec::new(),
        })
        .unwrap();
        let err = h.handle(&req(payload), &ctx("S")).unwrap_err();
        assert_eq!(err.code, IpcErrorCode::PreconditionFailed);
        assert!(err.message.contains("ghost"));
    }

    /// `sites` under the additional default route would mean `everything`;
    /// every other pairing of the two choices reaches the writer.
    #[test]
    fn sites_under_the_additional_default_route_is_refused_before_the_writer() {
        for (mode, protection, refused) in [
            ("prefer-secondary-when-available", "sites", true),
            ("prefer-secondary-when-available", "everything", false),
            ("prefer-secondary-when-available", "off", false),
            ("prefer-primary", "sites", false),
            ("prefer-primary", "everything", false),
            ("prefer-primary", "off", false),
        ] {
            let writer = Arc::new(ScriptedWriter {
                outcome: Mutex::new(Ok(sample_dto())),
                seen_sid: Mutex::new(None),
            });
            let h =
                RoutePolicyUpdateHandler::new(writer.clone() as Arc<dyn RoutePolicyWriter>, None);
            let mut payload = bind_primary_payload("Wi-Fi");
            payload["mode"] = mode.into();
            payload["leak-protection"] = protection.into();
            let outcome = h.handle(&req(payload), &ctx("S-1-5-21-1"));
            if refused {
                let err = outcome.expect_err("refused");
                assert_eq!(err.code, IpcErrorCode::PreconditionFailed);
                assert!(
                    err.message.contains(SITES_NEEDS_MAIN_ROUTE_CODE),
                    "{}",
                    err.message
                );
                assert!(
                    writer.seen_sid.lock().unwrap().is_none(),
                    "{mode} {protection}"
                );
            } else {
                outcome.unwrap_or_else(|e| panic!("{mode} {protection}: {}", e.message));
            }
        }
    }

    /// An `apply-only` change of the default route alone cannot pair with a
    /// stored `sites`.
    #[test]
    fn an_apply_only_mode_change_over_stored_sites_is_refused() {
        let mut stored = sample_dto();
        stored.leak_protection = LeakProtectionDto::Sites;
        let writer = Arc::new(StoringWriter {
            row: Mutex::new(stored),
        });
        let h = RoutePolicyUpdateHandler::new(writer as Arc<dyn RoutePolicyWriter>, None);
        let mut payload = request_json(&sample_dto());
        payload["mode"] = "prefer-secondary-when-available".into();
        payload["apply-only"] = serde_json::json!(["mode"]);
        let err = h
            .handle(&req(payload), &ctx("S-1-5-21-1"))
            .expect_err("refused");
        assert_eq!(err.code, IpcErrorCode::PreconditionFailed);
    }

    #[test]
    fn a_leak_protection_slug_outside_the_three_is_malformed() {
        let writer = Arc::new(ScriptedWriter {
            outcome: Mutex::new(Ok(sample_dto())),
            seen_sid: Mutex::new(None),
        });
        let h = RoutePolicyUpdateHandler::new(writer as Arc<dyn RoutePolicyWriter>, None);
        for bad in [serde_json::json!("on"), serde_json::json!(true)] {
            let mut payload = bind_primary_payload("Wi-Fi");
            payload["leak-protection"] = bad;
            let err = h.handle(&req(payload), &ctx("S")).unwrap_err();
            assert_eq!(err.code, IpcErrorCode::MalformedRequest);
        }
        let mut missing = bind_primary_payload("Wi-Fi");
        missing
            .as_object_mut()
            .expect("object")
            .remove("leak-protection");
        let err = h.handle(&req(missing), &ctx("S")).unwrap_err();
        assert_eq!(
            err.code,
            IpcErrorCode::MalformedRequest,
            "a full replace must not turn protection off by omission"
        );
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
            leak_protection: LeakProtectionDto::Off,
            kill_switch_protocols: 0x7F,
            allow_dns_over_primary: false,
            include_subdomains: false,
            shared_ip_policy: "majority-of-ip".into(),
            resolve_hosts_bypass: true,
            doh_lockdown_enabled: false,
            doh_lockdown_scope: "leak-protection-only".into(),
            doh_lockdown_auto: true,
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
            app_rules_take_all_addresses: false,
            forwarded_outage: String::new(),
            external_address_auto_check: false,
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
            leak_protection: dto.leak_protection,
            kill_switch_protocols: dto.kill_switch_protocols,
            allow_dns_over_primary: dto.allow_dns_over_primary,
            include_subdomains: dto.include_subdomains,
            shared_ip_policy: dto.shared_ip_policy.clone(),
            resolve_hosts_bypass: dto.resolve_hosts_bypass,
            doh_lockdown_enabled: dto.doh_lockdown_enabled,
            doh_lockdown_scope: dto.doh_lockdown_scope.clone(),
            doh_lockdown_auto: dto.doh_lockdown_auto,
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
            app_rules_take_all_addresses: false,
            forwarded_outage: String::new(),
            external_address_auto_check: false,
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
            leak_protection: dto.leak_protection,
            kill_switch_protocols: dto.kill_switch_protocols,
            allow_dns_over_primary: dto.allow_dns_over_primary,
            include_subdomains: dto.include_subdomains,
            shared_ip_policy: dto.shared_ip_policy.clone(),
            resolve_hosts_bypass: dto.resolve_hosts_bypass,
            doh_lockdown_enabled: dto.doh_lockdown_enabled,
            doh_lockdown_scope: dto.doh_lockdown_scope.clone(),
            doh_lockdown_auto: dto.doh_lockdown_auto,
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
            app_rules_take_all_addresses: false,
            forwarded_outage: String::new(),
            external_address_auto_check: false,
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
            leak_protection: LeakProtectionDto::Off,
            kill_switch_protocols: 0x7F,
            allow_dns_over_primary: false,
            include_subdomains: false,
            shared_ip_policy: "majority-of-ip".into(),
            resolve_hosts_bypass: true,
            doh_lockdown_enabled: false,
            doh_lockdown_scope: "leak-protection-only".into(),
            doh_lockdown_auto: true,
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
            app_rules_take_all_addresses: false,
            forwarded_outage: String::new(),
            external_address_auto_check: false,
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
        // What the window read before the tray turned leak protection on.
        let mut stale = request_json(&sample_dto());
        stale["auto-rules-mode"] = serde_json::json!("auto");
        stale["apply-only"] = serde_json::json!(["auto-rules-mode"]);
        stale["binding-source"] = serde_json::json!("user-assigned");
        let mut stored = sample_dto();
        stored.leak_protection = LeakProtectionDto::Everything;

        let merged = apply_only_over_stored(stale, || Some(stored)).expect("merged");
        let req: RoutePolicyUpdateRequest = serde_json::from_value(merged).expect("request");
        assert_eq!(req.auto_rules_mode, "auto");
        assert_eq!(
            req.leak_protection,
            LeakProtectionDto::Everything,
            "the tray's change survives"
        );
        assert_eq!(req.binding_source, BindingSourceDto::UserAssigned);
    }

    #[test]
    fn naming_an_absent_slot_unbinds_it_and_an_unknown_name_is_refused() {
        let mut unbind = request_json(&sample_dto());
        unbind.as_object_mut().expect("object").remove("primary");
        unbind["apply-only"] = serde_json::json!(["primary"]);
        let merged = apply_only_over_stored(unbind, || Some(sample_dto())).expect("merged");
        let req: RoutePolicyUpdateRequest = serde_json::from_value(merged).expect("request");
        assert!(req.primary.is_none());

        let mut typo = request_json(&sample_dto());
        typo["apply-only"] = serde_json::json!(["leak-protect"]);
        let err = apply_only_over_stored(typo, || Some(sample_dto())).expect_err("refused");
        assert_eq!(err.code, IpcErrorCode::MalformedRequest);
    }

    #[test]
    fn with_nothing_stored_an_apply_only_request_writes_whole() {
        let mut first = request_json(&sample_dto());
        first["leak-protection"] = serde_json::json!("everything");
        first["apply-only"] = serde_json::json!(["leak-protection"]);
        let merged = apply_only_over_stored(first.clone(), || None).expect("merged");
        assert_eq!(merged, first);
    }

    /// A writer holding one row; each write takes a moment, as a disk does.
    struct StoringWriter {
        row: Mutex<RoutePolicyDto>,
    }
    impl RoutePolicyWriter for StoringWriter {
        fn update_for_sid(
            &self,
            _sid: &str,
            req: &RoutePolicyUpdateRequest,
        ) -> Result<RoutePolicyDto, RoutePolicyWriteError> {
            std::thread::sleep(std::time::Duration::from_millis(40));
            let mut row = self.row.lock().unwrap();
            row.leak_protection = req.leak_protection;
            row.auto_rules_mode = req.auto_rules_mode.clone();
            Ok(row.clone())
        }
        fn stored_for_sid(&self, _sid: &str) -> Option<RoutePolicyDto> {
            Some(self.row.lock().unwrap().clone())
        }
    }

    #[test]
    fn two_concurrent_partial_updates_keep_both_fields() {
        let writer = Arc::new(StoringWriter {
            row: Mutex::new(sample_dto()),
        });
        let h = Arc::new(RoutePolicyUpdateHandler::new(
            Arc::clone(&writer) as Arc<dyn RoutePolicyWriter>,
            None,
        ));
        let partial = |field: &str, value: serde_json::Value| {
            let mut p = request_json(&sample_dto());
            p[field] = value;
            p["apply-only"] = serde_json::json!([field]);
            p["binding-source"] = serde_json::json!("user-assigned");
            p
        };
        let payloads = [
            partial("leak-protection", serde_json::json!("everything")),
            partial("auto-rules-mode", serde_json::json!("auto")),
        ];
        let threads: Vec<_> = payloads
            .into_iter()
            .map(|payload| {
                let h = Arc::clone(&h);
                std::thread::spawn(move || h.handle(&req(payload), &ctx("S-1-5-21-A")))
            })
            .collect();
        for t in threads {
            t.join().expect("thread").expect("update accepted");
        }
        let row = writer.row.lock().unwrap();
        assert_eq!(
            row.leak_protection,
            LeakProtectionDto::Everything,
            "the first update survives"
        );
        assert_eq!(row.auto_rules_mode, "auto", "the second update survives");
    }

    /// What a client from another build sends: a protection key this service
    /// does not know, beside or instead of the one it does. Applied, the rest
    /// of the request would land with a success while the key the user acted
    /// on was dropped.
    #[test]
    fn a_key_this_service_does_not_know_is_refused_and_nothing_is_written() {
        let mut stored = sample_dto();
        stored.leak_protection = LeakProtectionDto::Everything;
        let writer = Arc::new(StoringWriter {
            row: Mutex::new(stored),
        });
        let h =
            RoutePolicyUpdateHandler::new(Arc::clone(&writer) as Arc<dyn RoutePolicyWriter>, None);
        let mut full = request_json(&sample_dto());
        full["kill-switch-enabled"] = serde_json::json!(false);
        let mut partial = request_json(&sample_dto());
        partial["leak-protection-level"] = serde_json::json!("sites");
        partial["apply-only"] = serde_json::json!(["leak-protection-level"]);
        let mut beside = request_json(&sample_dto());
        beside["kill-switch-block-all"] = serde_json::json!(false);
        beside["auto-rules-mode"] = serde_json::json!("auto");
        beside["apply-only"] = serde_json::json!(["auto-rules-mode"]);
        for (payload, unknown) in [
            (full, "kill-switch-enabled"),
            (partial, "leak-protection-level"),
            (beside, "kill-switch-block-all"),
        ] {
            let err = h
                .handle(&req(payload), &ctx("S-1-5-21-A"))
                .expect_err(unknown);
            assert_eq!(err.code, IpcErrorCode::MalformedRequest, "{unknown}");
            assert!(err.message.contains(unknown), "{}", err.message);
        }
        let row = writer.row.lock().unwrap();
        assert_eq!(row.leak_protection, LeakProtectionDto::Everything);
        assert_eq!(row.auto_rules_mode, "suggest");
    }

    /// A refusal names what the peer sent, but only so much of it.
    #[test]
    fn a_refusal_names_a_bounded_part_of_the_unknown_keys() {
        let mut payload = request_json(&sample_dto());
        for n in 0..100 {
            payload[format!("{}{n}", "x".repeat(500))] = serde_json::json!(true);
        }
        let err = refuse_unknown_keys(&payload).expect_err("refused");
        assert!(err.message.len() < 2_000, "{}", err.message.len());
    }

    /// The stored row carries keys the request does not accept; laying a
    /// partial write over it must not trip on them.
    #[test]
    fn an_apply_only_write_over_a_stored_row_with_snapshot_only_keys_applies() {
        let mut stored = sample_dto();
        stored.doh_lockdown_effective = true;
        stored.secondary_link_provider_apps =
            vec![crate::ipc_handlers::payloads::LinkProviderAppDto {
                exe_path: "C:\\Program Files\\Vpn\\vpn.exe".into(),
                display_name: String::new(),
            }];
        let mut on = request_json(&sample_dto());
        on["leak-protection"] = serde_json::json!("sites");
        on["apply-only"] = serde_json::json!(["leak-protection"]);
        let merged = apply_only_over_stored(on, || Some(stored)).expect("merged");
        let req: RoutePolicyUpdateRequest = serde_json::from_value(merged).expect("request");
        assert_eq!(req.leak_protection, LeakProtectionDto::Sites);
    }
}
