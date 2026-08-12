//! IPC handlers for the
//! `ServiceStabilityConfigGet` / `ServiceStabilityConfigSet`
//! operations.
//!
//! Mirrors the existing settings-handler pattern in
//! [`super::settings_handlers`] — wire-payload deserialize →
//! provider/writer trait call → wire-response serialize. The two
//! traits live in `providers.rs`; production impls in
//! `production_settings.rs`.
//!
//! `set_by_sid` captures `IpcRequestContext.caller_stored()` for the audit
//! trail.
//!
//! Elevation: the catalogue marks this operation as requiring the service
//! mutation privilege, but the envelope class it travels under does not, and
//! the router gates on the class. Every field here is therefore writable by an
//! ordinary client — which is fine for stability and diagnostics toggles, and
//! is NOT fine for the administrative rules lock. That one field is checked
//! against the caller's elevation inside the Set handler; see
//! `rules_lock_change_is_authorised`.

use std::sync::Arc;

use nrr_shared::ipc_payloads::{
    ServiceStabilityConfigGetRequest, ServiceStabilityConfigSetRequest,
};

use crate::ipc::{
    HandlerOutcome, IpcError, IpcErrorCode, IpcHandler, IpcRequestContext, IpcRequestEnvelope,
};
use crate::ipc_handlers::providers::{
    ServiceStabilityConfigProvider, ServiceStabilityConfigWriter, SettingsWriteError,
};

fn malformed(op: &'static str, e: serde_json::Error) -> IpcError {
    IpcError {
        code: IpcErrorCode::MalformedRequest,
        message: format!("{op} payload invalid: {e}"),
        diagnostics_id: None,
    }
}

fn serialise(op: &'static str, value: impl serde::Serialize) -> HandlerOutcome {
    serde_json::to_value(value).map_err(|e| IpcError {
        code: IpcErrorCode::Internal,
        message: format!("{op} response serialisation failed: {e}"),
        diagnostics_id: None,
    })
}

fn map_settings_write_error(err: SettingsWriteError) -> IpcError {
    let code = match &err {
        SettingsWriteError::Invalid(_) => IpcErrorCode::PreconditionFailed,
        SettingsWriteError::Storage(_) => IpcErrorCode::Internal,
        SettingsWriteError::AccessDenied(_) => IpcErrorCode::Forbidden,
    };
    IpcError {
        code,
        message: err.to_string(),
        diagnostics_id: None,
    }
}

// ── Get ──────────────────────────────────────────────────────────────────────

pub struct ServiceStabilityConfigGetHandler {
    provider: Arc<dyn ServiceStabilityConfigProvider>,
}

impl ServiceStabilityConfigGetHandler {
    pub fn new(provider: Arc<dyn ServiceStabilityConfigProvider>) -> Self {
        Self { provider }
    }
}

impl IpcHandler for ServiceStabilityConfigGetHandler {
    fn handle(&self, request: &IpcRequestEnvelope, _ctx: &IpcRequestContext) -> HandlerOutcome {
        const OP: &str = "settings.service-stability.get";
        let _: ServiceStabilityConfigGetRequest =
            serde_json::from_value(request.payload.clone()).map_err(|e| malformed(OP, e))?;
        serialise(OP, self.provider.get())
    }
}

// ── Set ──────────────────────────────────────────────────────────────────────

pub struct ServiceStabilityConfigSetHandler {
    writer: Arc<dyn ServiceStabilityConfigWriter>,
    /// Reader for the current row, used to tell an actual change of the
    /// administrative rules lock from a client merely echoing it back. `None`
    /// (stub wiring) leaves that check inert — there is no stored lock to
    /// protect when the whole settings subsystem is a stub.
    provider: Option<Arc<dyn ServiceStabilityConfigProvider>>,
}

impl ServiceStabilityConfigSetHandler {
    pub fn new(writer: Arc<dyn ServiceStabilityConfigWriter>) -> Self {
        Self {
            writer,
            provider: None,
        }
    }

    /// Attach the reader so the handler can enforce that only an elevated
    /// caller changes the administrative rules lock.
    #[must_use]
    pub fn with_provider(mut self, provider: Arc<dyn ServiceStabilityConfigProvider>) -> Self {
        self.provider = Some(provider);
        self
    }

    /// The lock is the one field on this row that a restricted user must not
    /// be able to write — otherwise it would be lifted by the very account it
    /// restricts, and the whole feature would be decorative.
    ///
    /// The envelope class this operation travels under does not demand
    /// elevation (every other field here is an ordinary settings toggle), so
    /// the check lives at the field, not at the class: a non-elevated caller
    /// may save anything as long as it leaves the lock where it found it.
    /// That distinction matters because clients read-modify-write the whole
    /// row — refusing every save that merely echoes the current value would
    /// break settings for exactly the users the lock applies to.
    fn rules_lock_change_is_authorised(
        &self,
        requested: Option<bool>,
        caller_is_elevated: bool,
    ) -> bool {
        if caller_is_elevated {
            return true;
        }
        let (Some(requested), Some(provider)) = (requested, self.provider.as_ref()) else {
            return true;
        };
        // A stored `None` means the row has never carried an opinion, so
        // there is nothing yet for a request to contradict.
        match provider.get().allow_user_rule_edits {
            None => true,
            Some(stored) => stored == requested,
        }
    }
}

impl IpcHandler for ServiceStabilityConfigSetHandler {
    fn handle(&self, request: &IpcRequestEnvelope, ctx: &IpcRequestContext) -> HandlerOutcome {
        const OP: &str = "settings.service-stability.set";
        let req: ServiceStabilityConfigSetRequest =
            serde_json::from_value(request.payload.clone()).map_err(|e| malformed(OP, e))?;
        if !self.rules_lock_change_is_authorised(
            req.config.allow_user_rule_edits,
            ctx.caller_is_elevated,
        ) {
            tracing::warn!(
                target: "nrr::stability",
                caller = %ctx.caller_stored(),
                requested = ?req.config.allow_user_rule_edits,
                "refused a non-elevated attempt to change the administrative rules lock",
            );
            return Err(IpcError {
                code: IpcErrorCode::Forbidden,
                message: "changing who may edit routing rules requires an elevated client".into(),
                diagnostics_id: None,
            });
        }
        let sid = if ctx.caller_stored().is_empty() {
            None
        } else {
            Some(ctx.caller_stored())
        };
        // Attribute every stability write BEFORE the storage round-trip so a
        // clobbered toggle is diagnosable from the NDJSON alone: correlate
        // this line (who + what was requested) with the writer's per-field
        // prior→written lines at the same timestamp.
        tracing::info!(
            target: "nrr::stability",
            origin = req.origin.as_deref().unwrap_or("unspecified"),
            requested_enforcement_mode = %req.config.enforcement_mode,
            requested_verbose = req.config.verbose_logging,
            "service-stability set requested",
        );
        // Measure the write end-to-end. `elapsed_ms` here says whether the
        // handler itself was slow or the delay sat in the pipe backlog
        // upstream — a stability reply arriving minutes late shows up as an
        // `unknown correlation id` in the launcher log after the GUI's 30 s
        // deadline. Should stay in low milliseconds now that the resolver
        // reconcile runs async (`apply_async`).
        let started = std::time::Instant::now();
        let outcome = self.writer.set(&req.config, sid);
        tracing::info!(
            target: "nrr::stability",
            origin = req.origin.as_deref().unwrap_or("unspecified"),
            elapsed_ms = started.elapsed().as_millis() as u64,
            ok = outcome.is_ok(),
            "service-stability set completed",
        );
        match outcome {
            Ok(dto) => serialise(OP, dto),
            Err(e) => Err(map_settings_write_error(e)),
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_shared::ipc::{IpcClientProfile, IpcOperationName};
    use nrr_shared::ipc_payloads::ServiceStabilityConfigDto;
    use std::sync::Mutex;

    use crate::ipc::{IpcOperationClass, IpcRequestContext, IpcRequestEnvelope};

    fn ctx() -> IpcRequestContext {
        IpcRequestContext {
            client_profile: IpcClientProfile::GuiInteractive,
            caller_is_elevated: true,
            caller_principal: crate::UserPrincipal::from_windows_sid("S-1-5-21-test").ok(),
        }
    }

    struct FakeProvider {
        config: Mutex<ServiceStabilityConfigDto>,
    }
    impl ServiceStabilityConfigProvider for FakeProvider {
        fn get(&self) -> ServiceStabilityConfigDto {
            self.config.lock().unwrap().clone()
        }
    }
    struct FakeWriter {
        config: Mutex<Option<ServiceStabilityConfigDto>>,
        reject: bool,
    }
    impl ServiceStabilityConfigWriter for FakeWriter {
        fn set(
            &self,
            dto: &ServiceStabilityConfigDto,
            _sid: Option<&str>,
        ) -> Result<ServiceStabilityConfigDto, SettingsWriteError> {
            if self.reject {
                return Err(SettingsWriteError::Invalid(
                    "max_restarts out of range (allowed: 1..=100)".into(),
                ));
            }
            *self.config.lock().unwrap() = Some(dto.clone());
            Ok(dto.clone())
        }
    }

    fn env(payload: serde_json::Value, op: IpcOperationName) -> IpcRequestEnvelope {
        IpcRequestEnvelope {
            protocol_version: 1,
            request_id: "req-ss".into(),
            correlation_id: None,
            operation: op,
            operation_class: IpcOperationClass::ReadSnapshot,
            confirmation_token: None,
            payload,
        }
    }

    #[test]
    fn get_returns_provider_value() {
        let dto = ServiceStabilityConfigDto::default();
        let provider: Arc<dyn ServiceStabilityConfigProvider> = Arc::new(FakeProvider {
            config: Mutex::new(dto.clone()),
        });
        let h = ServiceStabilityConfigGetHandler::new(provider);
        let r = h.handle(
            &env(
                serde_json::json!({}),
                IpcOperationName::ServiceStabilityConfigGet,
            ),
            &ctx(),
        );
        let v = r.expect("ok");
        // Default is Recoverable with documented constants.
        assert_eq!(v["ipc-accept-policy"]["kind"], "recoverable");
        assert_eq!(v["ipc-accept-policy"]["max-restarts"], 20);
    }

    #[test]
    fn set_writes_through_writer() {
        let writer: Arc<dyn ServiceStabilityConfigWriter> = Arc::new(FakeWriter {
            config: Mutex::new(None),
            reject: false,
        });
        let h = ServiceStabilityConfigSetHandler::new(Arc::clone(&writer));
        let payload = serde_json::json!({
            "config": {
                "ipc-accept-policy": {
                    "kind": "recoverable",
                    "max-restarts": 50,
                    "backoff-base-ms": 100,
                    "backoff-cap-ms": 2000
                }
            }
        });
        let r = h.handle(
            &env(payload, IpcOperationName::ServiceStabilityConfigSet),
            &ctx(),
        );
        let v = r.expect("ok");
        assert_eq!(v["ipc-accept-policy"]["max-restarts"], 50);
    }

    #[test]
    fn set_critical_round_trips_without_params() {
        let writer: Arc<dyn ServiceStabilityConfigWriter> = Arc::new(FakeWriter {
            config: Mutex::new(None),
            reject: false,
        });
        let h = ServiceStabilityConfigSetHandler::new(writer);
        let payload = serde_json::json!({
            "config": {
                "ipc-accept-policy": { "kind": "critical" }
            }
        });
        let r = h.handle(
            &env(payload, IpcOperationName::ServiceStabilityConfigSet),
            &ctx(),
        );
        let v = r.expect("ok");
        assert_eq!(v["ipc-accept-policy"]["kind"], "critical");
        assert!(v["ipc-accept-policy"].get("max-restarts").is_none());
    }

    #[test]
    fn set_rejects_invalid_with_precondition_failed() {
        let writer: Arc<dyn ServiceStabilityConfigWriter> = Arc::new(FakeWriter {
            config: Mutex::new(None),
            reject: true,
        });
        let h = ServiceStabilityConfigSetHandler::new(writer);
        let payload = serde_json::json!({
            "config": {
                "ipc-accept-policy": {
                    "kind": "recoverable",
                    "max-restarts": 9_999,
                    "backoff-base-ms": 100,
                    "backoff-cap-ms": 2000
                }
            }
        });
        let r = h.handle(
            &env(payload, IpcOperationName::ServiceStabilityConfigSet),
            &ctx(),
        );
        let err = r.unwrap_err();
        assert_eq!(err.code, IpcErrorCode::PreconditionFailed);
    }

    // ── Administrative rules lock ────────────────────────────────────────

    fn non_elevated_ctx() -> IpcRequestContext {
        IpcRequestContext {
            client_profile: IpcClientProfile::GuiInteractive,
            caller_is_elevated: false,
            caller_principal: crate::UserPrincipal::from_windows_sid("S-1-5-21-KID").ok(),
        }
    }

    fn provider_with_lock(allow: bool) -> Arc<dyn ServiceStabilityConfigProvider> {
        Arc::new(FakeProvider {
            config: Mutex::new(ServiceStabilityConfigDto {
                allow_user_rule_edits: Some(allow),
                ..Default::default()
            }),
        })
    }

    fn set_lock_payload(allow: bool) -> serde_json::Value {
        serde_json::json!({
            "config": {
                "ipc-accept-policy": { "kind": "critical" },
                "allow-user-rule-edits": allow,
            }
        })
    }

    fn handler_with(
        writer: Arc<dyn ServiceStabilityConfigWriter>,
    ) -> ServiceStabilityConfigSetHandler {
        ServiceStabilityConfigSetHandler::new(writer).with_provider(provider_with_lock(false))
    }

    fn recording_writer() -> Arc<FakeWriter> {
        Arc::new(FakeWriter {
            config: Mutex::new(None),
            reject: false,
        })
    }

    /// The account the lock restricts must not be able to lift it. Without
    /// this the whole feature is decorative: the restricted user simply saves
    /// the settings row with the flag flipped.
    #[test]
    fn a_non_elevated_caller_cannot_lift_the_rules_lock() {
        let writer = recording_writer();
        let h = handler_with(Arc::clone(&writer) as Arc<dyn ServiceStabilityConfigWriter>);
        let err = h
            .handle(
                &env(
                    set_lock_payload(true),
                    IpcOperationName::ServiceStabilityConfigSet,
                ),
                &non_elevated_ctx(),
            )
            .expect_err("a restricted user must not be able to unlock");
        assert_eq!(err.code, IpcErrorCode::Forbidden);
        assert!(
            writer.config.lock().unwrap().is_none(),
            "nothing may have reached storage"
        );
    }

    /// Imposing a lock is just as much an administrative act as lifting one.
    #[test]
    fn a_non_elevated_caller_cannot_impose_a_rules_lock_either() {
        let writer: Arc<dyn ServiceStabilityConfigWriter> = Arc::new(FakeWriter {
            config: Mutex::new(None),
            reject: false,
        });
        let h =
            ServiceStabilityConfigSetHandler::new(writer).with_provider(provider_with_lock(true));
        let err = h
            .handle(
                &env(
                    set_lock_payload(false),
                    IpcOperationName::ServiceStabilityConfigSet,
                ),
                &non_elevated_ctx(),
            )
            .expect_err("only an administrator decides this");
        assert_eq!(err.code, IpcErrorCode::Forbidden);
    }

    /// Clients read-modify-write the whole row, so a restricted user's
    /// ordinary settings save echoes the stored lock back. That must keep
    /// working — otherwise the lock would break every other setting for the
    /// users it applies to.
    #[test]
    fn a_non_elevated_caller_may_still_save_unrelated_settings() {
        let writer = recording_writer();
        let h = handler_with(Arc::clone(&writer) as Arc<dyn ServiceStabilityConfigWriter>);
        h.handle(
            &env(
                set_lock_payload(false),
                IpcOperationName::ServiceStabilityConfigSet,
            ),
            &non_elevated_ctx(),
        )
        .expect("echoing the stored value is not a change");
        assert!(writer.config.lock().unwrap().is_some());

        // Omitting the field entirely is the same story.
        let writer2 = recording_writer();
        let h2 = handler_with(Arc::clone(&writer2) as Arc<dyn ServiceStabilityConfigWriter>);
        h2.handle(
            &env(
                serde_json::json!({
                    "config": { "ipc-accept-policy": { "kind": "critical" } }
                }),
                IpcOperationName::ServiceStabilityConfigSet,
            ),
            &non_elevated_ctx(),
        )
        .expect("a save with no opinion on the lock must pass");
        assert!(writer2.config.lock().unwrap().is_some());
    }

    /// The administrator sets and lifts it freely.
    #[test]
    fn an_elevated_caller_may_change_the_rules_lock() {
        let writer = recording_writer();
        let h = handler_with(Arc::clone(&writer) as Arc<dyn ServiceStabilityConfigWriter>);
        let v = h
            .handle(
                &env(
                    set_lock_payload(true),
                    IpcOperationName::ServiceStabilityConfigSet,
                ),
                &ctx(),
            )
            .expect("elevated change must pass");
        assert_eq!(v["allow-user-rule-edits"], true);
    }

    #[test]
    fn malformed_payload_returns_malformed_request() {
        let writer: Arc<dyn ServiceStabilityConfigWriter> = Arc::new(FakeWriter {
            config: Mutex::new(None),
            reject: false,
        });
        let h = ServiceStabilityConfigSetHandler::new(writer);
        let payload = serde_json::json!({
            "config": { "ipc-accept-policy": { "kind": "unknown" } }
        });
        let r = h.handle(
            &env(payload, IpcOperationName::ServiceStabilityConfigSet),
            &ctx(),
        );
        let err = r.unwrap_err();
        assert_eq!(err.code, IpcErrorCode::MalformedRequest);
    }
}
