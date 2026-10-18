//! `diagnostics.site-check.{run,result}` — "is it us or the site". Both act
//! for the caller alone, elevated or not: the check runs over the caller's own
//! routes with the caller's own rules, and only the caller reads its result.

use std::sync::Arc;

use nrr_shared::ipc_payloads::{SiteCheckRequest, SiteCheckResultRequest, SITE_CHECK_MAX_HOST_LEN};

use crate::ipc::{
    CheckedIpcHandler, HandlerOutcome, IpcError, IpcErrorCode, IpcHandler, IpcRequestContext,
    IpcRequestEnvelope, Prechecked,
};
use crate::site_check::{normalise_host, SiteChecker, StartRefused};

const OP_RUN: &str = "diagnostics.site-check.run";
const OP_RESULT: &str = "diagnostics.site-check.result";

fn error(code: IpcErrorCode, message: String) -> IpcError {
    IpcError {
        code,
        message,
        diagnostics_id: None,
    }
}

/// A check is a person's: an unattributed connection has no routes to check.
fn principal<'a>(op: &str, ctx: &'a IpcRequestContext) -> Result<&'a str, IpcError> {
    let sid = ctx.caller_stored();
    if sid.is_empty() {
        return Err(error(
            IpcErrorCode::Unauthorized,
            format!("{op}: this request carries no user identity"),
        ));
    }
    Ok(sid)
}

fn decode<T: serde::de::DeserializeOwned + Default>(
    op: &str,
    request: &IpcRequestEnvelope,
) -> Result<T, IpcError> {
    if request.payload.is_null() {
        return Ok(T::default());
    }
    serde_json::from_value(request.payload.clone()).map_err(|e| {
        error(
            IpcErrorCode::MalformedRequest,
            format!("{op} payload invalid: {e}"),
        )
    })
}

fn reply(op: &str, value: impl serde::Serialize) -> HandlerOutcome {
    serde_json::to_value(value).map_err(|e| {
        error(
            IpcErrorCode::Internal,
            format!("{op} serialisation failed: {e}"),
        )
    })
}

pub struct SiteCheckRunHandler {
    checker: Arc<SiteChecker>,
}

impl SiteCheckRunHandler {
    pub fn new(checker: Arc<SiteChecker>) -> Self {
        Self { checker }
    }
}

/// The caller and the host, normalised.
pub struct CheckedSiteCheck {
    principal: String,
    host: String,
}

impl CheckedIpcHandler for SiteCheckRunHandler {
    type Checked = CheckedSiteCheck;

    fn precheck(
        &self,
        request: &IpcRequestEnvelope,
        ctx: &IpcRequestContext,
    ) -> Result<CheckedSiteCheck, IpcError> {
        let req: SiteCheckRequest = decode(OP_RUN, request)?;
        if req.host.len() > SITE_CHECK_MAX_HOST_LEN {
            return Err(error(
                IpcErrorCode::MalformedRequest,
                format!("{OP_RUN}: host longer than {SITE_CHECK_MAX_HOST_LEN} bytes"),
            ));
        }
        let host = normalise_host(&req.host).ok_or_else(|| {
            error(
                IpcErrorCode::MalformedRequest,
                format!("{OP_RUN}: not a host name"),
            )
        })?;
        Ok(CheckedSiteCheck {
            principal: principal(OP_RUN, ctx)?.to_owned(),
            host,
        })
    }

    fn execute(
        &self,
        checked: Prechecked<CheckedSiteCheck>,
        _request: &IpcRequestEnvelope,
        _ctx: &IpcRequestContext,
    ) -> HandlerOutcome {
        let CheckedSiteCheck { principal, host } = checked.into_inner();
        match self.checker.start(&principal, host) {
            Ok(status) => reply(OP_RUN, status),
            Err(StartRefused::Busy) => Err(error(
                IpcErrorCode::BusyConflict,
                format!("{OP_RUN}: a check is still running"),
            )),
            Err(StartRefused::Unavailable) => Err(error(
                IpcErrorCode::ServiceDegraded,
                format!("{OP_RUN}: the check could not be started"),
            )),
        }
    }
}

pub struct SiteCheckResultHandler {
    checker: Arc<SiteChecker>,
}

impl SiteCheckResultHandler {
    pub fn new(checker: Arc<SiteChecker>) -> Self {
        Self { checker }
    }
}

impl IpcHandler for SiteCheckResultHandler {
    fn handle(&self, request: &IpcRequestEnvelope, ctx: &IpcRequestContext) -> HandlerOutcome {
        let _: SiteCheckResultRequest = decode(OP_RESULT, request)?;
        let sid = principal(OP_RESULT, ctx)?;
        reply(OP_RESULT, self.checker.status(sid))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fqdn_cache_lookup::MockFqdnCacheLookup;
    use crate::ipc::{IpcOperationClass, IPC_PROTOCOL_VERSION};
    use crate::path_probe::{MockPathProbe, PathVerdict};
    use crate::production_auto_rule_probe::EgressSources;
    use crate::site_check::{SiteCheckWiring, SiteRoutes};
    use nrr_shared::ipc::{IpcClientProfile, IpcOperationName};
    use nrr_shared::ipc_payloads::SiteCheckStatus;
    use std::net::Ipv4Addr;

    const ALICE: &str = "S-1-5-21-1-2-3-1001";

    struct NoLinks;
    impl EgressSources for NoLinks {
        fn egress_source_ips(&self, _sid: &str) -> (Option<Ipv4Addr>, Option<Ipv4Addr>) {
            (None, None)
        }
    }

    struct MainRoute;
    impl SiteRoutes for MainRoute {
        fn route_for(&self, _: &str, _: &str, _: Option<Ipv4Addr>) -> String {
            "primary".into()
        }
    }

    fn checker() -> Arc<SiteChecker> {
        Arc::new(SiteChecker::new(SiteCheckWiring {
            probe: Arc::new(MockPathProbe::new(PathVerdict::Answered)),
            egress: Arc::new(NoLinks),
            cache: Arc::new(MockFqdnCacheLookup::new()),
            routes: Arc::new(MainRoute),
            engine: None,
            trace: None,
            https: None,
        }))
    }

    fn ctx(sid: Option<&str>) -> IpcRequestContext {
        IpcRequestContext {
            client_profile: IpcClientProfile::GuiInteractive,
            caller_is_elevated: false,
            caller_principal: sid
                .and_then(|s| nrr_domain::user_principal::UserPrincipal::from_windows_sid(s).ok()),
            caller_pid: None,
        }
    }

    fn req(op: IpcOperationName, payload: serde_json::Value) -> IpcRequestEnvelope {
        IpcRequestEnvelope {
            protocol_version: IPC_PROTOCOL_VERSION,
            request_id: "r-sc".into(),
            correlation_id: None,
            operation: op,
            operation_class: IpcOperationClass::UserScopedConfiguration,
            confirmation_token: None,
            payload,
        }
    }

    #[test]
    fn hostile_or_anonymous_requests_are_refused_before_anything_runs() {
        let handler = SiteCheckRunHandler::new(checker());
        let long = "a".repeat(SITE_CHECK_MAX_HOST_LEN + 1);
        for payload in [
            serde_json::json!({ "host": long }),
            serde_json::json!({ "host": "203.0.113.5" }),
            serde_json::json!({ "host": "bad host" }),
            serde_json::json!({ "host": 5 }),
            serde_json::Value::Null,
        ] {
            let err = handler
                .precheck(
                    &req(IpcOperationName::SiteCheckRun, payload),
                    &ctx(Some(ALICE)),
                )
                .err()
                .expect("refused");
            assert_eq!(err.code, IpcErrorCode::MalformedRequest);
        }
        let err = handler
            .precheck(
                &req(
                    IpcOperationName::SiteCheckRun,
                    serde_json::json!({ "host": "site.example" }),
                ),
                &ctx(None),
            )
            .err()
            .expect("refused");
        assert_eq!(err.code, IpcErrorCode::Unauthorized);
    }

    #[test]
    fn the_run_answers_at_once_and_the_result_is_the_callers() {
        let checker = checker();
        let value = SiteCheckRunHandler::new(Arc::clone(&checker))
            .handle(
                &req(
                    IpcOperationName::SiteCheckRun,
                    serde_json::json!({ "host": "Site.Example" }),
                ),
                &ctx(Some(ALICE)),
            )
            .expect("started");
        let started: SiteCheckStatus = serde_json::from_value(value).expect("decode");
        assert_eq!(started.state, "running");
        assert_eq!(started.host, "site.example");

        let result = SiteCheckResultHandler::new(checker);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let value = result
                .handle(
                    &req(
                        IpcOperationName::SiteCheckResultGet,
                        serde_json::Value::Null,
                    ),
                    &ctx(Some(ALICE)),
                )
                .expect("read");
            let status: SiteCheckStatus = serde_json::from_value(value).expect("decode");
            if status.state == "done" {
                assert_eq!(
                    status.report.map(|r| r.verdict).as_deref(),
                    Some("unclear"),
                    "nothing known about the site, nothing claimed"
                );
                break;
            }
            assert!(std::time::Instant::now() < deadline, "never finished");
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(result
            .handle(
                &req(
                    IpcOperationName::SiteCheckResultGet,
                    serde_json::Value::Null
                ),
                &ctx(None),
            )
            .is_err());
    }
}
