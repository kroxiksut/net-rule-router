//! `rules.app-path-coverage.get` — what a rule by program path would cover
//! for the caller. Whose folders is taken from the connection, never from the
//! request: an elevated caller reads no more than their own.

use std::sync::Arc;

use nrr_shared::app_path::MAX_PATH_VALUE_BYTES;
use nrr_shared::ipc_payloads::AppPathCoverageRequest;

use crate::app_path_coverage::AppPathCoverage;
use crate::ipc::{
    CheckedIpcHandler, HandlerOutcome, IpcError, IpcErrorCode, IpcRequestContext,
    IpcRequestEnvelope, Prechecked,
};

const OP: &str = "rules.app-path-coverage.get";

/// Longest value read: a path at its bound with room for the rule flags.
const MAX_VALUE_BYTES: usize = MAX_PATH_VALUE_BYTES + 64;

/// Longest route slug read.
const MAX_ROUTE_BYTES: usize = 32;

fn error(code: IpcErrorCode, message: String) -> IpcError {
    IpcError {
        code,
        message,
        diagnostics_id: None,
    }
}

pub struct AppPathCoverageHandler {
    coverage: Arc<AppPathCoverage>,
}

impl AppPathCoverageHandler {
    pub fn new(coverage: Arc<AppPathCoverage>) -> Self {
        Self { coverage }
    }
}

/// The caller and the rule asked about, within bounds.
pub struct CheckedCoverage {
    owner: String,
    request: AppPathCoverageRequest,
}

impl CheckedIpcHandler for AppPathCoverageHandler {
    type Checked = CheckedCoverage;

    fn precheck(
        &self,
        request: &IpcRequestEnvelope,
        ctx: &IpcRequestContext,
    ) -> Result<CheckedCoverage, IpcError> {
        let req: AppPathCoverageRequest =
            serde_json::from_value(request.payload.clone()).map_err(|e| {
                error(
                    IpcErrorCode::MalformedRequest,
                    format!("{OP} payload invalid: {e}"),
                )
            })?;
        if req.value.len() > MAX_VALUE_BYTES || req.route.len() > MAX_ROUTE_BYTES {
            return Err(error(
                IpcErrorCode::MalformedRequest,
                format!("{OP}: value or route past its bound"),
            ));
        }
        // A person's folders: an unattributed connection has none.
        let owner = ctx.caller_stored();
        if owner.is_empty() {
            return Err(error(
                IpcErrorCode::Unauthorized,
                format!("{OP}: this request carries no user identity"),
            ));
        }
        Ok(CheckedCoverage {
            owner: owner.to_owned(),
            request: req,
        })
    }

    fn execute(
        &self,
        checked: Prechecked<CheckedCoverage>,
        _request: &IpcRequestEnvelope,
        _ctx: &IpcRequestContext,
    ) -> HandlerOutcome {
        let CheckedCoverage { owner, request } = checked.into_inner();
        let answer = self.coverage.coverage(&request, &owner);
        serde_json::to_value(answer).map_err(|e| {
            error(
                IpcErrorCode::Internal,
                format!("{OP} serialisation failed: {e}"),
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::{IpcOperationClass, IPC_PROTOCOL_VERSION};
    use nrr_domain::user_principal::UserPrincipal;
    use nrr_platform_api::app_folders::StdProgramFolders;
    use nrr_shared::app_path::PathStyle;
    use nrr_shared::ipc::{IpcClientProfile, IpcOperationName};

    fn ctx(principal: Option<UserPrincipal>) -> IpcRequestContext {
        IpcRequestContext {
            client_profile: IpcClientProfile::GuiInteractive,
            caller_is_elevated: false,
            caller_principal: principal,
            caller_pid: None,
        }
    }

    fn req(payload: serde_json::Value) -> IpcRequestEnvelope {
        IpcRequestEnvelope {
            protocol_version: IPC_PROTOCOL_VERSION,
            request_id: "r-apc".into(),
            correlation_id: None,
            operation: IpcOperationName::RulesAppPathCoverageGet,
            operation_class: IpcOperationClass::ReadSnapshot,
            confirmation_token: None,
            payload,
        }
    }

    fn handler() -> AppPathCoverageHandler {
        let folders = StdProgramFolders::new(PathStyle::Linux);
        AppPathCoverageHandler::new(Arc::new(AppPathCoverage::new(Arc::new(folders), true)))
    }

    #[test]
    fn an_unattributed_or_oversized_request_is_refused_before_the_disk() {
        let ok = serde_json::json!({ "value": "/opt/app/*", "route": "primary" });
        assert!(handler().precheck(&req(ok.clone()), &ctx(None)).is_err());
        let user = ctx(Some(UserPrincipal::from_linux_uid(1000)));
        assert!(handler().precheck(&req(ok), &user).is_ok());
        let huge = serde_json::json!({ "value": "a".repeat(MAX_VALUE_BYTES + 1) });
        assert!(handler().precheck(&req(huge), &user).is_err());
        let broken = serde_json::json!({ "value": 7 });
        assert!(handler().precheck(&req(broken), &user).is_err());
    }
}
