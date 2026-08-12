//! `route.link-provider.set` handler.
//!
//! Replaces the caller's per-SID **link-provider app** set for one route
//! binding role: the executables the user confirmed as establishing and
//! maintaining that link (a VPN client for the secondary role is the common
//! case; a plain Wi-Fi/Ethernet secondary has none). Narrow write on purpose
//! — the VPN onboarding dialog must not read-modify-write the whole route
//! policy (`route.policy.update`) just to record its pick.
//!
//! User-scoped class, same privilege pattern as `RoutePolicyUpdate`. A
//! successful write fires the same post-write recompile hook: the provider
//! set feeds the kill-switch `APP_EXEMPT_BASE` permits, so the exemption must
//! arm without waiting for the next reconnect.

use std::sync::Arc;

use crate::ipc::{
    HandlerOutcome, IpcError, IpcErrorCode, IpcHandler, IpcRequestContext, IpcRequestEnvelope,
};
use crate::ipc_handlers::payloads::{RouteLinkProviderSetRequest, RouteLinkProviderSetResponse};
use crate::ipc_handlers::providers::{
    LinkProviderWriter, RoutePolicyApplyTrigger, RoutePolicyWriteError,
};

/// Binding roles a link-provider set may target today. Free has exactly one
/// secondary; `primary` is accepted for symmetry (Pro grows real multi-binding
/// roles with the binding model).
const ALLOWED_ROLES: [&str; 2] = ["secondary", "primary"];

pub struct RouteLinkProviderSetHandler {
    writer: Arc<dyn LinkProviderWriter>,
    /// Same hook as `RoutePolicyUpdateHandler` — the provider set changes the
    /// kill-switch exemption filters, so a routing-active caller recompiles
    /// immediately. `None` ⇒ persist-only.
    apply_trigger: Option<Arc<dyn RoutePolicyApplyTrigger>>,
}

impl RouteLinkProviderSetHandler {
    pub fn new(
        writer: Arc<dyn LinkProviderWriter>,
        apply_trigger: Option<Arc<dyn RoutePolicyApplyTrigger>>,
    ) -> Self {
        Self {
            writer,
            apply_trigger,
        }
    }
}

impl IpcHandler for RouteLinkProviderSetHandler {
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

        let req: RouteLinkProviderSetRequest = serde_json::from_value(request.payload.clone())
            .map_err(|e| IpcError {
                code: IpcErrorCode::MalformedRequest,
                message: format!("route.link-provider.set payload invalid: {e}"),
                diagnostics_id: None,
            })?;

        if !ALLOWED_ROLES.contains(&req.role.as_str()) {
            return Err(IpcError {
                code: IpcErrorCode::PreconditionFailed,
                message: format!(
                    "unknown link-provider role {:?} (expected one of {:?})",
                    req.role, ALLOWED_ROLES
                ),
                diagnostics_id: None,
            });
        }

        match self
            .writer
            .set_for_sid(ctx.caller_stored(), &req.role, &req.link_provider_apps)
        {
            Ok(stored) => {
                // The provider set feeds the kill-switch APP_EXEMPT_BASE
                // permits — recompile a routing-active caller now so the
                // exemption arms before the client's next connect attempt.
                // Best-effort, like route.policy.update.
                if let Some(trigger) = self.apply_trigger.as_ref() {
                    trigger.on_policy_changed(ctx.caller_stored());
                }
                serde_json::to_value(RouteLinkProviderSetResponse {
                    role: req.role,
                    link_provider_apps: stored,
                })
                .map_err(|e| IpcError {
                    code: IpcErrorCode::Internal,
                    message: format!("route.link-provider.set response serialisation failed: {e}"),
                    diagnostics_id: None,
                })
            }
            Err(e) => Err(map_write_error(e)),
        }
    }
}

fn map_write_error(err: RoutePolicyWriteError) -> IpcError {
    let code = match err {
        RoutePolicyWriteError::EmptySid | RoutePolicyWriteError::Storage(_) => {
            IpcErrorCode::Internal
        }
        _ => IpcErrorCode::PreconditionFailed,
    };
    IpcError {
        code,
        message: err.to_string(),
        diagnostics_id: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::{IpcOperationClass, IPC_PROTOCOL_VERSION};
    use crate::ipc_handlers::payloads::LinkProviderAppDto;
    use nrr_shared::ipc::{IpcClientProfile, IpcOperationName};
    use std::sync::Mutex;

    struct ScriptedWriter {
        outcome: Mutex<Result<Vec<LinkProviderAppDto>, RoutePolicyWriteError>>,
        seen: Mutex<Option<(String, String, Vec<LinkProviderAppDto>)>>,
    }
    impl LinkProviderWriter for ScriptedWriter {
        fn set_for_sid(
            &self,
            sid: &str,
            role: &str,
            apps: &[LinkProviderAppDto],
        ) -> Result<Vec<LinkProviderAppDto>, RoutePolicyWriteError> {
            *self.seen.lock().unwrap() = Some((sid.to_string(), role.to_string(), apps.to_vec()));
            self.outcome.lock().unwrap().clone()
        }
    }

    struct RecordingTrigger {
        fired_for: Mutex<Vec<String>>,
    }
    impl RoutePolicyApplyTrigger for RecordingTrigger {
        fn on_policy_changed(&self, sid: &str) {
            self.fired_for.lock().unwrap().push(sid.to_string());
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
            operation: IpcOperationName::RouteLinkProviderSet,
            operation_class: IpcOperationClass::UserScopedConfiguration,
            confirmation_token: None,
            payload,
        }
    }

    fn app(path: &str) -> LinkProviderAppDto {
        LinkProviderAppDto {
            exe_path: path.to_string(),
            display_name: "client".into(),
        }
    }

    #[test]
    fn success_writes_role_and_apps_fires_trigger_and_echoes_stored_set() {
        let stored = vec![app("C:\\VPN\\client.exe")];
        let writer = Arc::new(ScriptedWriter {
            outcome: Mutex::new(Ok(stored.clone())),
            seen: Mutex::new(None),
        });
        let trigger = Arc::new(RecordingTrigger {
            fired_for: Mutex::new(Vec::new()),
        });
        let h = RouteLinkProviderSetHandler::new(
            Arc::clone(&writer) as Arc<dyn LinkProviderWriter>,
            Some(Arc::clone(&trigger) as Arc<dyn RoutePolicyApplyTrigger>),
        );
        let payload = serde_json::to_value(RouteLinkProviderSetRequest {
            role: "secondary".into(),
            link_provider_apps: stored.clone(),
        })
        .unwrap();
        let value = h.handle(&req(payload), &ctx("S-1-5-21-A")).unwrap();
        let parsed: RouteLinkProviderSetResponse = serde_json::from_value(value).unwrap();
        assert_eq!(parsed.role, "secondary");
        assert_eq!(parsed.link_provider_apps, stored);
        let seen = writer.seen.lock().unwrap().clone().unwrap();
        assert_eq!(seen.0, "S-1-5-21-A");
        assert_eq!(seen.1, "secondary");
        assert_eq!(
            trigger.fired_for.lock().unwrap().as_slice(),
            &["S-1-5-21-A".to_string()],
            "provider-set change must fire the recompile hook (feeds APP_EXEMPT permits)"
        );
    }

    #[test]
    fn default_role_is_secondary_and_empty_list_clears() {
        let writer = Arc::new(ScriptedWriter {
            outcome: Mutex::new(Ok(Vec::new())),
            seen: Mutex::new(None),
        });
        let h = RouteLinkProviderSetHandler::new(
            Arc::clone(&writer) as Arc<dyn LinkProviderWriter>,
            None,
        );
        // Omit both fields — serde defaults must kick in (role = secondary).
        let value = h.handle(&req(serde_json::json!({})), &ctx("S")).unwrap();
        let parsed: RouteLinkProviderSetResponse = serde_json::from_value(value).unwrap();
        assert_eq!(parsed.role, "secondary");
        assert!(parsed.link_provider_apps.is_empty());
        let seen = writer.seen.lock().unwrap().clone().unwrap();
        assert_eq!(seen.1, "secondary");
        assert!(seen.2.is_empty());
    }

    #[test]
    fn unknown_role_is_precondition_failed_before_writer_is_called() {
        let writer = Arc::new(ScriptedWriter {
            outcome: Mutex::new(Ok(Vec::new())),
            seen: Mutex::new(None),
        });
        let h = RouteLinkProviderSetHandler::new(
            Arc::clone(&writer) as Arc<dyn LinkProviderWriter>,
            None,
        );
        let payload = serde_json::to_value(RouteLinkProviderSetRequest {
            role: "tertiary".into(),
            link_provider_apps: Vec::new(),
        })
        .unwrap();
        let err = h.handle(&req(payload), &ctx("S")).unwrap_err();
        assert_eq!(err.code, IpcErrorCode::PreconditionFailed);
        assert!(writer.seen.lock().unwrap().is_none());
    }

    #[test]
    fn empty_sid_is_internal_error_before_writer_is_called() {
        let writer = Arc::new(ScriptedWriter {
            outcome: Mutex::new(Ok(Vec::new())),
            seen: Mutex::new(None),
        });
        let h = RouteLinkProviderSetHandler::new(
            Arc::clone(&writer) as Arc<dyn LinkProviderWriter>,
            None,
        );
        let err = h.handle(&req(serde_json::json!({})), &ctx("")).unwrap_err();
        assert_eq!(err.code, IpcErrorCode::Internal);
        assert!(writer.seen.lock().unwrap().is_none());
    }

    #[test]
    fn storage_error_maps_to_internal_and_does_not_fire_trigger() {
        let writer = Arc::new(ScriptedWriter {
            outcome: Mutex::new(Err(RoutePolicyWriteError::Storage("disk full".into()))),
            seen: Mutex::new(None),
        });
        let trigger = Arc::new(RecordingTrigger {
            fired_for: Mutex::new(Vec::new()),
        });
        let h = RouteLinkProviderSetHandler::new(
            writer as Arc<dyn LinkProviderWriter>,
            Some(Arc::clone(&trigger) as Arc<dyn RoutePolicyApplyTrigger>),
        );
        let err = h
            .handle(&req(serde_json::json!({})), &ctx("S"))
            .unwrap_err();
        assert_eq!(err.code, IpcErrorCode::Internal);
        assert!(err.message.contains("disk full"));
        assert!(trigger.fired_for.lock().unwrap().is_empty());
    }
}
