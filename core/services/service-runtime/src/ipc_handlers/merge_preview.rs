//! IPC handler for the `RulesMergePreview` read-only op.
//!
//! Thin wrapper over a [`MergePreviewSource`]: resolve the caller's principal
//! (SID with baseline fallback, like `rules.list`/`preset.export.get`),
//! delegate the merge, and serialise the [`MergeResultDto`] into the response.

use std::sync::Arc;

use nrr_shared::ipc_payloads::{MergePreviewRequest, MergePreviewResponse};

use crate::ipc::{
    HandlerOutcome, IpcError, IpcErrorCode, IpcHandler, IpcRequestContext, IpcRequestEnvelope,
};
use crate::production_merge_preview::{MergePreviewError, MergePreviewSource};

const OP: &str = "rules.merge-preview";

fn malformed(e: serde_json::Error) -> IpcError {
    IpcError {
        code: IpcErrorCode::MalformedRequest,
        message: format!("{OP} payload invalid: {e}"),
        diagnostics_id: None,
    }
}

fn internal(msg: impl Into<String>) -> IpcError {
    IpcError {
        code: IpcErrorCode::Internal,
        message: format!("{OP}: {}", msg.into()),
        diagnostics_id: None,
    }
}

fn precondition(msg: impl Into<String>) -> IpcError {
    IpcError {
        code: IpcErrorCode::PreconditionFailed,
        message: format!("{OP}: {}", msg.into()),
        diagnostics_id: None,
    }
}

/// Handler for [`nrr_shared::ipc::IpcOperationName::RulesMergePreview`].
pub struct RulesMergePreviewHandler {
    source: Arc<dyn MergePreviewSource>,
}

impl RulesMergePreviewHandler {
    pub fn new(source: Arc<dyn MergePreviewSource>) -> Self {
        Self { source }
    }
}

impl IpcHandler for RulesMergePreviewHandler {
    fn handle(&self, request: &IpcRequestEnvelope, ctx: &IpcRequestContext) -> HandlerOutcome {
        let req: MergePreviewRequest = if request.payload.is_null() {
            MergePreviewRequest::default()
        } else {
            serde_json::from_value(request.payload.clone()).map_err(malformed)?
        };
        // Merge against the CALLER's active revision (that's what the service
        // enforces for this user); the source read-throughs to the shared
        // baseline. An empty SID (degenerate transport) maps to the baseline
        // sentinel — same guard as the export/explain paths.
        let principal = if ctx.caller_stored().is_empty() {
            nrr_storage::BASELINE_PRINCIPAL
        } else {
            ctx.caller_stored()
        };
        let result = self
            .source
            .merge_preview(
                principal,
                &req.primary_text,
                &req.secondary_text,
                req.policy,
                &req.resolutions,
                req.include_child_processes,
            )
            .map_err(|e| match e {
                MergePreviewError::LockPoisoned => internal("state DB mutex poisoned"),
                MergePreviewError::StorageError(msg) => internal(msg),
                MergePreviewError::ServiceDecodeError(msg) => internal(msg),
                MergePreviewError::FileCanonicalizeRejected(msg) => precondition(msg),
                MergePreviewError::EncodeError(msg) => internal(msg),
            })?;
        serde_json::to_value(MergePreviewResponse { result })
            .map_err(|e| internal(format!("response serialisation: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::ipc::IpcOperationClass;
    use nrr_shared::ipc::{IpcClientProfile, IpcOperationName};
    use nrr_shared::merge_dto::{
        ConflictResolutionDto, MergePolicyDto, MergeResultDto, MergedRuleEntryDto,
    };
    use nrr_shared::rules_json::RuleAction;
    use nrr_shared::RouteRole;
    use std::sync::Mutex;

    /// Records each call and returns a pre-seeded outcome.
    struct FakeSource {
        outcome: Mutex<Result<MergeResultDto, MergePreviewError>>,
        #[allow(clippy::type_complexity)]
        calls: Mutex<Vec<(String, String, String, MergePolicyDto, usize, bool)>>,
    }

    impl FakeSource {
        fn ok(result: MergeResultDto) -> Self {
            Self {
                outcome: Mutex::new(Ok(result)),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn err(e: MergePreviewError) -> Self {
            Self {
                outcome: Mutex::new(Err(e)),
                calls: Mutex::new(Vec::new()),
            }
        }
    }

    impl MergePreviewSource for FakeSource {
        fn merge_preview(
            &self,
            principal: &str,
            primary_text: &str,
            secondary_text: &str,
            policy: MergePolicyDto,
            resolutions: &[ConflictResolutionDto],
            include_child_processes: bool,
        ) -> Result<MergeResultDto, MergePreviewError> {
            self.calls.lock().unwrap().push((
                principal.to_string(),
                primary_text.to_string(),
                secondary_text.to_string(),
                policy,
                resolutions.len(),
                include_child_processes,
            ));
            self.outcome.lock().unwrap().clone()
        }
    }

    fn sample_result() -> MergeResultDto {
        MergeResultDto {
            policy: MergePolicyDto::Union,
            noop: false,
            unresolved: 0,
            file_only: vec![MergedRuleEntryDto {
                value: "example.com".into(),
                type_slug: "domain".into(),
                route: RouteRole::Secondary,
                enabled: true,
                action: RuleAction::Route,
                comment: String::new(),
                origin: nrr_shared::merge_dto::MergeOriginDto::FileOnly,
                was_conflict: false,
            }],
            service_only: Vec::new(),
            conflicts: Vec::new(),
            merged_rules_json: "{\"schema-version\":1,\"primary\":[],\"secondary\":[]}".into(),
        }
    }

    fn envelope(payload: serde_json::Value) -> IpcRequestEnvelope {
        IpcRequestEnvelope {
            protocol_version: 1,
            request_id: "req-merge".into(),
            correlation_id: None,
            operation: IpcOperationName::RulesMergePreview,
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

    #[test]
    fn threads_request_fields_and_returns_result() {
        let source = Arc::new(FakeSource::ok(sample_result()));
        let handler = RulesMergePreviewHandler::new(source.clone());
        let value = handler
            .handle(
                &envelope(serde_json::json!({
                    "primary-text": "--- Domains\nexample.com\n",
                    "secondary-text": "",
                    "policy": "union",
                    "resolutions": [],
                    "include-child-processes": false,
                })),
                &ctx(),
            )
            .expect("handler success");
        let parsed: MergePreviewResponse = serde_json::from_value(value).expect("parse");
        assert_eq!(parsed.result.file_only.len(), 1);
        let calls = source.calls.lock().unwrap();
        assert_eq!(calls[0].0, "S-1-5-21-test");
        assert_eq!(calls[0].1, "--- Domains\nexample.com\n");
        assert_eq!(calls[0].3, MergePolicyDto::Union);
    }

    #[test]
    fn empty_sid_maps_to_baseline_principal() {
        let source = Arc::new(FakeSource::ok(sample_result()));
        let handler = RulesMergePreviewHandler::new(source.clone());
        let mut ctx = ctx();
        ctx.caller_principal = None;
        handler
            .handle(&envelope(serde_json::json!({})), &ctx)
            .expect("handler success");
        assert_eq!(
            source.calls.lock().unwrap()[0].0,
            nrr_storage::BASELINE_PRINCIPAL
        );
    }

    #[test]
    fn null_payload_defaults_to_union_no_resolutions() {
        let source = Arc::new(FakeSource::ok(sample_result()));
        let handler = RulesMergePreviewHandler::new(source.clone());
        handler
            .handle(&envelope(serde_json::Value::Null), &ctx())
            .expect("handler success");
        let calls = source.calls.lock().unwrap();
        assert_eq!(calls[0].3, MergePolicyDto::Union);
        assert_eq!(calls[0].4, 0);
    }

    #[test]
    fn file_rejection_maps_to_precondition_failed() {
        let source = Arc::new(FakeSource::err(
            MergePreviewError::FileCanonicalizeRejected("bad ipv4".into()),
        ));
        let handler = RulesMergePreviewHandler::new(source);
        let err = handler
            .handle(&envelope(serde_json::json!({})), &ctx())
            .expect_err("must fail");
        assert_eq!(err.code, IpcErrorCode::PreconditionFailed);
    }

    #[test]
    fn decode_error_maps_to_internal() {
        let source = Arc::new(FakeSource::err(MergePreviewError::ServiceDecodeError(
            "schema".into(),
        )));
        let handler = RulesMergePreviewHandler::new(source);
        let err = handler
            .handle(&envelope(serde_json::json!({})), &ctx())
            .expect_err("must fail");
        assert_eq!(err.code, IpcErrorCode::Internal);
    }
}
