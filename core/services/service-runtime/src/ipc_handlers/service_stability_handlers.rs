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
//! Elevation: the row is one per machine — enforcement mode, fake-IP, the
//! stop policy and the rules lock apply to every user. The envelope class does
//! not demand elevation, so the Set handler checks the VALUE (see
//! `crate::machine_scoped`): an unelevated save passes only when it leaves the
//! row as stored. An unelevated GUI gets `Forbidden` and the launcher retries
//! through the elevation broker.

use std::sync::Arc;

use nrr_shared::ipc_payloads::{
    ServiceStabilityConfigDto, ServiceStabilityConfigGetRequest, ServiceStabilityConfigSetRequest,
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
    /// machine-wide change from a client merely echoing the row back. `None`
    /// (stub wiring) leaves that check inert — there is no stored row to
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

    /// Attach the reader so the handler can tell a change from an echo.
    #[must_use]
    pub fn with_provider(mut self, provider: Arc<dyn ServiceStabilityConfigProvider>) -> Self {
        self.provider = Some(provider);
        self
    }

    /// Wire names of the fields this request would change. Clients
    /// read-modify-write the whole row, so an unelevated save is normally a
    /// pure echo and must keep passing; anything else is an administrator's
    /// call. A lock of `None` means "leave it alone" and is never a change.
    fn machine_changes(&self, requested: &ServiceStabilityConfigDto) -> Vec<String> {
        let Some(provider) = self.provider.as_ref() else {
            return Vec::new();
        };
        let current = provider.get();
        let (Ok(serde_json::Value::Object(mut want)), Ok(serde_json::Value::Object(have))) = (
            serde_json::to_value(requested),
            serde_json::to_value(&current),
        ) else {
            return vec!["config".to_string()];
        };
        if requested.allow_user_rule_edits.is_none() {
            want.remove(RULES_LOCK_WIRE_KEY);
        }
        want.into_iter()
            .filter(|(key, value)| have.get(key) != Some(value))
            .map(|(key, _)| key)
            .collect()
    }
}

const RULES_LOCK_WIRE_KEY: &str = "allow-user-rule-edits";

impl IpcHandler for ServiceStabilityConfigSetHandler {
    fn handle(&self, request: &IpcRequestEnvelope, ctx: &IpcRequestContext) -> HandlerOutcome {
        const OP: &str = "settings.service-stability.set";
        let req: ServiceStabilityConfigSetRequest =
            serde_json::from_value(request.payload.clone()).map_err(|e| malformed(OP, e))?;
        let changed = if ctx.caller_is_elevated {
            Vec::new()
        } else {
            self.machine_changes(&req.config)
        };
        if changed.iter().any(|key| key == RULES_LOCK_WIRE_KEY) {
            tracing::warn!(
                target: "nrr::stability",
                msg_key = "svcstability-rules-lock-refused",
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
        if !changed.is_empty() {
            tracing::warn!(
                target: "nrr::stability",
                msg_key = "svcstability-machine-change-refused",
                caller = %ctx.caller_stored(),
                fields = %changed.join(", "),
                "refused a non-elevated change of machine-wide service settings",
            );
            return Err(crate::machine_scoped::machine_scoped_refusal(
                "This service setting",
            ));
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
            msg_key = "svcstability-set-requested",
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
            msg_key = "svcstability-set-completed",
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
    use std::sync::Mutex;

    use crate::ipc::{IpcOperationClass, IpcRequestContext, IpcRequestEnvelope};

    fn ctx() -> IpcRequestContext {
        IpcRequestContext {
            client_profile: IpcClientProfile::GuiInteractive,
            caller_is_elevated: true,
            caller_principal: crate::UserPrincipal::from_windows_sid("S-1-5-21-test").ok(),
            caller_pid: None,
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
            caller_pid: None,
        }
    }

    /// The stored row is decoded from the same JSON the tests send, so an
    /// unchanged payload really is an echo field for field.
    fn provider_with_lock(allow: bool) -> Arc<dyn ServiceStabilityConfigProvider> {
        let stored =
            serde_json::from_value(set_lock_payload(allow)["config"].clone()).expect("stored row");
        Arc::new(FakeProvider {
            config: Mutex::new(stored),
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

    /// Enforcement mode, fake-IP and the rest apply to every user of the
    /// machine; one user switching them would switch them for all.
    #[test]
    fn a_non_elevated_caller_cannot_change_a_machine_wide_setting() {
        let writer = recording_writer();
        let h = handler_with(Arc::clone(&writer) as Arc<dyn ServiceStabilityConfigWriter>);
        let mut payload = set_lock_payload(false);
        payload["config"]["enforcement-mode"] = serde_json::json!("reactive");
        let err = h
            .handle(
                &env(payload.clone(), IpcOperationName::ServiceStabilityConfigSet),
                &non_elevated_ctx(),
            )
            .expect_err("switching the enforcement mode is an administrator's call");
        assert_eq!(err.code, IpcErrorCode::Forbidden);
        assert!(writer.config.lock().unwrap().is_none());

        h.handle(
            &env(payload, IpcOperationName::ServiceStabilityConfigSet),
            &ctx(),
        )
        .expect("an elevated caller may change it");
        assert!(writer.config.lock().unwrap().is_some());
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
