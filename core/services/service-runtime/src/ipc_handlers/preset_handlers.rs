//! IPC handlers for preset export/import operations.
//!
//! Currently houses `PresetExportGetHandler`. `PresetImportHandler`
//! lives elsewhere (the import path goes through `MutationSubmit` →
//! `ProductionMutationExecutor`, not a dedicated read-only op).
//! `SettingsExportFullHandler` ships in a follow-up checkbox.

use std::sync::Arc;

use nrr_shared::ipc_payloads::{
    PresetExportGetRequest, PresetExportGetResponse, SettingsExportFullRequest,
    SettingsExportFullResponse,
};

use crate::activation_coordinator::Clock;
use crate::ipc::{
    HandlerOutcome, IpcError, IpcErrorCode, IpcHandler, IpcRequestContext, IpcRequestEnvelope,
};
use crate::production_preset_exporter::{
    encode_file_bytes_b64, PresetExportError, PresetExportSource,
};
use crate::production_settings_exporter::{
    encode_yaml_bytes_b64, format_iso_utc, SettingsExportError, SettingsExportSource,
};

fn malformed(op: &'static str, e: serde_json::Error) -> IpcError {
    IpcError {
        code: IpcErrorCode::MalformedRequest,
        message: format!("{op} payload invalid: {e}"),
        diagnostics_id: None,
    }
}

fn internal(op: &'static str, msg: impl Into<String>) -> IpcError {
    IpcError {
        code: IpcErrorCode::Internal,
        message: format!("{op}: {}", msg.into()),
        diagnostics_id: None,
    }
}

fn precondition(op: &'static str, msg: impl Into<String>) -> IpcError {
    IpcError {
        code: IpcErrorCode::PreconditionFailed,
        message: format!("{op}: {}", msg.into()),
        diagnostics_id: None,
    }
}

fn serialise(op: &'static str, value: impl serde::Serialize) -> HandlerOutcome {
    serde_json::to_value(value).map_err(|e| internal(op, format!("response serialisation: {e}")))
}

/// Handler for `IpcOperationName::PresetExportGet`. Pure read; delegates
/// to a [`PresetExportSource`] for the active-revision → txt projection,
/// then base64-wraps the bytes for the wire response.
pub struct PresetExportGetHandler {
    source: Arc<dyn PresetExportSource>,
}

impl PresetExportGetHandler {
    pub fn new(source: Arc<dyn PresetExportSource>) -> Self {
        Self { source }
    }
}

impl IpcHandler for PresetExportGetHandler {
    fn handle(&self, request: &IpcRequestEnvelope, ctx: &IpcRequestContext) -> HandlerOutcome {
        const OP: &str = "preset.export.get";
        let req: PresetExportGetRequest =
            serde_json::from_value(request.payload.clone()).map_err(|e| malformed(OP, e))?;
        // Export the CALLER's active revision (that's what the
        // service enforces for this user), with read-through to the shared
        // baseline handled by the source. An empty SID (degenerate transport)
        // maps to the baseline sentinel, matching the empty-SID guard in the
        // explain path (`production_diagnostics::load_active_rule_book`).
        let principal = if ctx.caller_stored().is_empty() {
            nrr_storage::BASELINE_PRINCIPAL
        } else {
            ctx.caller_stored()
        };
        let out = self
            .source
            .export_rules_file(principal, req.route, req.include_metadata)
            .map_err(|e| match e {
                PresetExportError::NoActiveRevision => {
                    precondition(OP, "no active revision to export")
                }
                PresetExportError::LockPoisoned => internal(OP, "state DB mutex poisoned"),
                PresetExportError::StorageError(msg) => internal(OP, msg),
                PresetExportError::DecodeError(msg) => internal(OP, msg),
            })?;
        let response = PresetExportGetResponse {
            file_bytes_b64: encode_file_bytes_b64(&out.file_bytes_utf8),
            content_hash: out.content_hash_hex,
        };
        serialise(OP, &response)
    }
}

/// Handler for `IpcOperationName::SettingsExportFull`. Pure read;
/// joins service-owned bindings/behavior with caller-supplied rules-file
/// paths via the [`SettingsExportSource`], emits YAML + SHA-256 hex.
pub struct SettingsExportFullHandler {
    source: Arc<dyn SettingsExportSource>,
    clock: Arc<dyn Clock>,
}

impl SettingsExportFullHandler {
    pub fn new(source: Arc<dyn SettingsExportSource>, clock: Arc<dyn Clock>) -> Self {
        Self { source, clock }
    }
}

impl IpcHandler for SettingsExportFullHandler {
    fn handle(&self, request: &IpcRequestEnvelope, ctx: &IpcRequestContext) -> HandlerOutcome {
        const OP: &str = "settings.export.full";
        let req: SettingsExportFullRequest =
            serde_json::from_value(request.payload.clone()).map_err(|e| malformed(OP, e))?;
        let exported_at_iso = format_iso_utc(self.clock.now_secs());
        let out = self
            .source
            .export_settings(
                ctx.caller_stored(),
                req.rules_file_path_primary.as_deref(),
                req.rules_file_path_secondary.as_deref(),
                &exported_at_iso,
            )
            .map_err(|e| match e {
                SettingsExportError::EmptySid => malformed_msg(OP, "caller SID is empty"),
                SettingsExportError::LockPoisoned => internal(OP, "state DB mutex poisoned"),
                SettingsExportError::StorageError(msg) => internal(OP, msg),
            })?;
        let response = SettingsExportFullResponse {
            yaml_bytes_b64: encode_yaml_bytes_b64(&out.yaml_bytes_utf8),
            content_hash: out.content_hash_hex,
        };
        serialise(OP, &response)
    }
}

fn malformed_msg(op: &'static str, msg: impl Into<String>) -> IpcError {
    IpcError {
        code: IpcErrorCode::MalformedRequest,
        message: format!("{op}: {}", msg.into()),
        diagnostics_id: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::ipc::IpcOperationClass;
    use crate::production_preset_exporter::PresetExportOutput;
    use nrr_shared::ipc::{IpcClientProfile, IpcOperationName};
    use nrr_shared::RouteRole;
    use std::sync::Mutex;

    // ── Test source ──────────────────────────────────────────────────────────

    /// Configurable fake [`PresetExportSource`] that records each call's
    /// `(route, include_metadata)` pair and returns a pre-seeded outcome.
    struct FakeSource {
        outcome: Mutex<Result<PresetExportOutput, PresetExportError>>,
        calls: Mutex<Vec<(String, RouteRole, bool)>>,
    }

    impl FakeSource {
        fn ok(file_bytes: &str, hash: &str) -> Self {
            Self {
                outcome: Mutex::new(Ok(PresetExportOutput {
                    file_bytes_utf8: file_bytes.to_string(),
                    content_hash_hex: hash.to_string(),
                })),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn err(e: PresetExportError) -> Self {
            Self {
                outcome: Mutex::new(Err(e)),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn calls(&self) -> Vec<(String, RouteRole, bool)> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl PresetExportSource for FakeSource {
        fn export_rules_file(
            &self,
            principal: &str,
            route: RouteRole,
            include_metadata: bool,
        ) -> Result<PresetExportOutput, PresetExportError> {
            self.calls
                .lock()
                .unwrap()
                .push((principal.to_string(), route, include_metadata));
            self.outcome.lock().unwrap().clone()
        }
    }

    fn envelope(payload: serde_json::Value) -> IpcRequestEnvelope {
        IpcRequestEnvelope {
            protocol_version: 1,
            request_id: "req-1".into(),
            correlation_id: None,
            operation: IpcOperationName::PresetExportGet,
            operation_class: IpcOperationClass::ReadSnapshot,
            confirmation_token: None,
            payload,
        }
    }

    fn ctx() -> IpcRequestContext {
        IpcRequestContext {
            client_profile: IpcClientProfile::GuiInteractive,
            caller_is_elevated: false,
            caller_principal: crate::UserPrincipal::from_windows_sid("S-1-5-21-test").ok(),
        }
    }

    // ── Tests ────────────────────────────────────────────────────────────────

    #[test]
    fn returns_base64_wrapped_bytes_and_hash() {
        let source = Arc::new(FakeSource::ok(
            "--- Domains\nexample.com\n",
            "deadbeef".repeat(8).as_str(),
        ));
        let handler = PresetExportGetHandler::new(source.clone());
        let envelope = envelope(serde_json::json!({
            "route": "primary",
            "include-metadata": false,
        }));
        let value = handler.handle(&envelope, &ctx()).expect("handler success");
        let parsed: PresetExportGetResponse =
            serde_json::from_value(value).expect("parse response");
        assert_eq!(parsed.content_hash.len(), 64);
        // base64("--- Domains\nexample.com\n") deterministic.
        assert!(
            !parsed.file_bytes_b64.is_empty(),
            "base64 bytes must be non-empty"
        );
        // The caller SID from the envelope context is threaded through.
        assert_eq!(
            source.calls(),
            vec![("S-1-5-21-test".to_string(), RouteRole::Primary, false)]
        );
    }

    #[test]
    fn empty_caller_sid_falls_back_to_baseline_principal() {
        // A degenerate transport with no caller SID maps to the
        // baseline sentinel (the source then read-throughs). Mirrors the
        // empty-SID guard in the explain path.
        let source = Arc::new(FakeSource::ok(
            "--- Domains\nexample.com\n",
            "deadbeef".repeat(8).as_str(),
        ));
        let handler = PresetExportGetHandler::new(source.clone());
        let envelope = envelope(serde_json::json!({
            "route": "primary",
            "include-metadata": false,
        }));
        let mut ctx = ctx();
        ctx.caller_principal = None;
        handler.handle(&envelope, &ctx).expect("handler success");
        assert_eq!(
            source.calls(),
            vec![(
                nrr_storage::BASELINE_PRINCIPAL.to_string(),
                RouteRole::Primary,
                false
            )]
        );
    }

    #[test]
    fn malformed_payload_returns_malformed_request() {
        let source = Arc::new(FakeSource::ok("", ""));
        let handler = PresetExportGetHandler::new(source);
        let envelope = envelope(serde_json::json!({"route": "bogus"}));
        let err = handler
            .handle(&envelope, &ctx())
            .expect_err("handler must reject bogus route");
        assert_eq!(err.code, IpcErrorCode::MalformedRequest);
    }

    #[test]
    fn no_active_revision_maps_to_precondition_failed() {
        let source = Arc::new(FakeSource::err(PresetExportError::NoActiveRevision));
        let handler = PresetExportGetHandler::new(source);
        let envelope = envelope(serde_json::json!({
            "route": "primary",
            "include-metadata": false,
        }));
        let err = handler
            .handle(&envelope, &ctx())
            .expect_err("handler must fail with no active revision");
        assert_eq!(err.code, IpcErrorCode::PreconditionFailed);
        assert!(err.message.contains("no active revision"));
    }

    #[test]
    fn storage_error_maps_to_internal() {
        let source = Arc::new(FakeSource::err(PresetExportError::StorageError(
            "i/o failed".to_string(),
        )));
        let handler = PresetExportGetHandler::new(source);
        let envelope = envelope(serde_json::json!({
            "route": "primary",
            "include-metadata": false,
        }));
        let err = handler
            .handle(&envelope, &ctx())
            .expect_err("handler must fail on storage error");
        assert_eq!(err.code, IpcErrorCode::Internal);
    }

    #[test]
    fn passes_include_metadata_flag_through_to_source() {
        let source = Arc::new(FakeSource::ok(
            "# NetRuleRouter preset \u{2014} version 1\n",
            "deadbeef".repeat(8).as_str(),
        ));
        let handler = PresetExportGetHandler::new(source.clone());
        let envelope = envelope(serde_json::json!({
            "route": "secondary",
            "include-metadata": true,
        }));
        handler.handle(&envelope, &ctx()).expect("ok");
        assert_eq!(
            source.calls(),
            vec![("S-1-5-21-test".to_string(), RouteRole::Secondary, true)]
        );
    }

    // ── SettingsExportFullHandler ────────────────────────────────────────────

    use crate::production_settings_exporter::SettingsExportOutput;

    struct FixedClock(i64);

    impl Clock for FixedClock {
        fn now_secs(&self) -> i64 {
            self.0
        }
    }

    /// Records each call's (sid, primary_path, secondary_path, exported_at_iso)
    /// and returns a pre-seeded outcome.
    struct FakeSettingsSource {
        outcome: Mutex<Result<SettingsExportOutput, SettingsExportError>>,
        #[allow(clippy::type_complexity)]
        calls: Mutex<Vec<(String, Option<String>, Option<String>, String)>>,
    }

    impl FakeSettingsSource {
        fn ok(yaml: &str, hash: &str) -> Self {
            Self {
                outcome: Mutex::new(Ok(SettingsExportOutput {
                    yaml_bytes_utf8: yaml.to_string(),
                    content_hash_hex: hash.to_string(),
                })),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn err(e: SettingsExportError) -> Self {
            Self {
                outcome: Mutex::new(Err(e)),
                calls: Mutex::new(Vec::new()),
            }
        }
    }

    impl SettingsExportSource for FakeSettingsSource {
        fn export_settings(
            &self,
            sid: &str,
            rules_file_path_primary: Option<&str>,
            rules_file_path_secondary: Option<&str>,
            exported_at_iso: &str,
        ) -> Result<SettingsExportOutput, SettingsExportError> {
            self.calls.lock().unwrap().push((
                sid.to_string(),
                rules_file_path_primary.map(str::to_string),
                rules_file_path_secondary.map(str::to_string),
                exported_at_iso.to_string(),
            ));
            self.outcome.lock().unwrap().clone()
        }
    }

    fn settings_envelope(payload: serde_json::Value) -> IpcRequestEnvelope {
        IpcRequestEnvelope {
            protocol_version: 1,
            request_id: "req-2".into(),
            correlation_id: None,
            operation: IpcOperationName::SettingsExportFull,
            operation_class: IpcOperationClass::ReadSnapshot,
            confirmation_token: None,
            payload,
        }
    }

    #[test]
    fn settings_handler_threads_paths_and_clock_through_to_source() {
        let source = Arc::new(FakeSettingsSource::ok(
            "nrr_settings_export:\n",
            "0".repeat(64).as_str(),
        ));
        let clock = Arc::new(FixedClock(1_700_000_000));
        let handler = SettingsExportFullHandler::new(source.clone(), clock);
        let envelope = settings_envelope(serde_json::json!({
            "rules-file-path-primary": "C:\\rules_primary.txt",
            "rules-file-path-secondary": "C:\\rules_secondary.txt",
        }));
        handler.handle(&envelope, &ctx()).expect("ok");
        let calls = source.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "S-1-5-21-test");
        assert_eq!(calls[0].1.as_deref(), Some("C:\\rules_primary.txt"));
        assert_eq!(calls[0].2.as_deref(), Some("C:\\rules_secondary.txt"));
        assert_eq!(calls[0].3, "2023-11-14T22:13:20Z");
    }

    #[test]
    fn settings_handler_empty_payload_routes_none_paths() {
        let source = Arc::new(FakeSettingsSource::ok("yaml", "0".repeat(64).as_str()));
        let clock = Arc::new(FixedClock(0));
        let handler = SettingsExportFullHandler::new(source.clone(), clock);
        let envelope = settings_envelope(serde_json::json!({}));
        handler.handle(&envelope, &ctx()).expect("ok");
        let calls = source.calls.lock().unwrap();
        assert!(calls[0].1.is_none());
        assert!(calls[0].2.is_none());
    }

    #[test]
    fn settings_handler_empty_sid_maps_to_malformed_request() {
        let source = Arc::new(FakeSettingsSource::err(SettingsExportError::EmptySid));
        let clock = Arc::new(FixedClock(0));
        let handler = SettingsExportFullHandler::new(source, clock);
        let envelope = settings_envelope(serde_json::json!({}));
        let err = handler
            .handle(&envelope, &ctx())
            .expect_err("must reject empty SID");
        assert_eq!(err.code, IpcErrorCode::MalformedRequest);
    }

    #[test]
    fn settings_handler_storage_error_maps_to_internal() {
        let source = Arc::new(FakeSettingsSource::err(SettingsExportError::StorageError(
            "boom".to_string(),
        )));
        let clock = Arc::new(FixedClock(0));
        let handler = SettingsExportFullHandler::new(source, clock);
        let envelope = settings_envelope(serde_json::json!({}));
        let err = handler
            .handle(&envelope, &ctx())
            .expect_err("must fail on storage error");
        assert_eq!(err.code, IpcErrorCode::Internal);
    }

    #[test]
    fn settings_handler_emits_base64_wrapped_yaml_and_hash() {
        let source = Arc::new(FakeSettingsSource::ok(
            "nrr_settings_export:\n  version: 1\n",
            "deadbeef".repeat(8).as_str(),
        ));
        let clock = Arc::new(FixedClock(0));
        let handler = SettingsExportFullHandler::new(source, clock);
        let envelope = settings_envelope(serde_json::json!({}));
        let value = handler.handle(&envelope, &ctx()).expect("ok");
        let parsed: SettingsExportFullResponse = serde_json::from_value(value).expect("parse");
        assert_eq!(parsed.content_hash.len(), 64);
        assert!(!parsed.yaml_bytes_b64.is_empty());
    }
}
