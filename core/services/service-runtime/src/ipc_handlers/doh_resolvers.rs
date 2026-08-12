//! `doh.resolvers.get` / `doh.resolvers.set` handlers.
//!
//! Read / replace the SHARED DoH/DoT resolver baseline list (the machine-wide
//! `doh_resolver_entries` table). The list is NOT per-SID: it is a machine fact
//! seeded with public resolvers by country and edited rarely. The set op is
//! privileged (elevation) at the catalog level; a successful replace fires the
//! recompile hook for the active caller so the new resolver set takes effect at
//! once (the resolved IPs feed the DoH-lockdown blocks).

use std::sync::Arc;

use crate::ipc::{
    HandlerOutcome, IpcError, IpcErrorCode, IpcHandler, IpcRequestContext, IpcRequestEnvelope,
};
use crate::ipc_handlers::payloads::{
    DohResolverEntryDto, DohResolversGetResponse, DohResolversSetRequest, DohResolversSetResponse,
};
use crate::ipc_handlers::providers::{RoutePolicyApplyTrigger, RoutePolicyWriteError};

/// Read/replace access to the shared DoH resolver baseline. Production impl wraps
/// `nrr_storage::doh_lockdown::DohResolverEntriesRepository`.
pub trait DohResolverListStore: Send + Sync {
    fn get_all(&self) -> Result<Vec<DohResolverEntryDto>, RoutePolicyWriteError>;
    /// Replace the entire list; returns the stored list after the write.
    fn replace_all(
        &self,
        entries: &[DohResolverEntryDto],
    ) -> Result<Vec<DohResolverEntryDto>, RoutePolicyWriteError>;
}

pub struct DohResolversGetHandler {
    store: Arc<dyn DohResolverListStore>,
}

impl DohResolversGetHandler {
    pub fn new(store: Arc<dyn DohResolverListStore>) -> Self {
        Self { store }
    }
}

impl IpcHandler for DohResolversGetHandler {
    fn handle(&self, _request: &IpcRequestEnvelope, _ctx: &IpcRequestContext) -> HandlerOutcome {
        let resolvers = self.store.get_all().map_err(map_write_error)?;
        serde_json::to_value(DohResolversGetResponse { resolvers }).map_err(|e| IpcError {
            code: IpcErrorCode::Internal,
            message: format!("doh.resolvers.get response serialisation failed: {e}"),
            diagnostics_id: None,
        })
    }
}

pub struct DohResolversSetHandler {
    store: Arc<dyn DohResolverListStore>,
    /// Same hook as `RoutePolicyUpdateHandler` — the resolver set changes the
    /// DoH-lockdown blocks, so a routing-active caller recompiles immediately.
    apply_trigger: Option<Arc<dyn RoutePolicyApplyTrigger>>,
}

impl DohResolversSetHandler {
    pub fn new(
        store: Arc<dyn DohResolverListStore>,
        apply_trigger: Option<Arc<dyn RoutePolicyApplyTrigger>>,
    ) -> Self {
        Self {
            store,
            apply_trigger,
        }
    }
}

impl IpcHandler for DohResolversSetHandler {
    fn handle(&self, request: &IpcRequestEnvelope, ctx: &IpcRequestContext) -> HandlerOutcome {
        let req: DohResolversSetRequest =
            serde_json::from_value(request.payload.clone()).map_err(|e| IpcError {
                code: IpcErrorCode::MalformedRequest,
                message: format!("doh.resolvers.set payload invalid: {e}"),
                diagnostics_id: None,
            })?;
        // Validate every row up front so a single bad entry rejects the whole set
        // (rather than silently dropping it on write). target_kind must be
        // ip|host and the value must parse.
        for e in &req.resolvers {
            if nrr_storage::doh_lockdown::DohTarget::parse(&e.target_kind, &e.target).is_none() {
                return Err(IpcError {
                    code: IpcErrorCode::PreconditionFailed,
                    message: format!(
                        "invalid DoH resolver entry: kind={:?} target={:?} (kind must be ip|host \
                         and target must parse)",
                        e.target_kind, e.target
                    ),
                    diagnostics_id: None,
                });
            }
        }
        match self.store.replace_all(&req.resolvers) {
            Ok(stored) => {
                // The resolver set feeds the DoH-lockdown blocks — recompile a
                // routing-active caller now so the change takes effect. Best-
                // effort, like route.policy.update.
                if let Some(trigger) = self.apply_trigger.as_ref() {
                    if !ctx.caller_stored().is_empty() {
                        trigger.on_policy_changed(ctx.caller_stored());
                    }
                }
                serde_json::to_value(DohResolversSetResponse { resolvers: stored }).map_err(|e| {
                    IpcError {
                        code: IpcErrorCode::Internal,
                        message: format!("doh.resolvers.set response serialisation failed: {e}"),
                        diagnostics_id: None,
                    }
                })
            }
            Err(e) => Err(map_write_error(e)),
        }
    }
}

fn map_write_error(err: RoutePolicyWriteError) -> IpcError {
    IpcError {
        code: IpcErrorCode::Internal,
        message: err.to_string(),
        diagnostics_id: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::{IpcOperationClass, IPC_PROTOCOL_VERSION};
    use nrr_shared::ipc::{IpcClientProfile, IpcOperationName};
    use std::sync::Mutex;

    struct MemStore {
        entries: Mutex<Vec<DohResolverEntryDto>>,
    }
    impl DohResolverListStore for MemStore {
        fn get_all(&self) -> Result<Vec<DohResolverEntryDto>, RoutePolicyWriteError> {
            Ok(self.entries.lock().unwrap().clone())
        }
        fn replace_all(
            &self,
            entries: &[DohResolverEntryDto],
        ) -> Result<Vec<DohResolverEntryDto>, RoutePolicyWriteError> {
            *self.entries.lock().unwrap() = entries.to_vec();
            Ok(entries.to_vec())
        }
    }

    fn ctx(sid: &str) -> IpcRequestContext {
        IpcRequestContext {
            client_profile: IpcClientProfile::GuiInteractive,
            caller_is_elevated: true,
            caller_principal: crate::UserPrincipal::from_windows_sid(sid).ok(),
        }
    }

    fn req(op: IpcOperationName, payload: serde_json::Value) -> IpcRequestEnvelope {
        IpcRequestEnvelope {
            protocol_version: IPC_PROTOCOL_VERSION,
            request_id: "r-1".into(),
            correlation_id: None,
            operation: op,
            operation_class: IpcOperationClass::UserScopedConfiguration,
            confirmation_token: None,
            payload,
        }
    }

    fn entry(kind: &str, target: &str) -> DohResolverEntryDto {
        DohResolverEntryDto {
            target_kind: kind.into(),
            target: target.into(),
            comment: "test".into(),
            enabled: true,
        }
    }

    #[test]
    fn get_returns_stored_list() {
        let store = Arc::new(MemStore {
            entries: Mutex::new(vec![entry("ip", "8.8.8.8")]),
        });
        let h = DohResolversGetHandler::new(store);
        let v = h
            .handle(
                &req(IpcOperationName::DohResolversGet, serde_json::json!({})),
                &ctx("S"),
            )
            .unwrap();
        let parsed: DohResolversGetResponse = serde_json::from_value(v).unwrap();
        assert_eq!(parsed.resolvers.len(), 1);
        assert_eq!(parsed.resolvers[0].target, "8.8.8.8");
    }

    #[test]
    fn set_replaces_validates_and_fires_trigger() {
        struct RecTrigger(Mutex<Vec<String>>);
        impl RoutePolicyApplyTrigger for RecTrigger {
            fn on_policy_changed(&self, sid: &str) {
                self.0.lock().unwrap().push(sid.to_string());
            }
        }
        let store = Arc::new(MemStore {
            entries: Mutex::new(Vec::new()),
        });
        let trigger = Arc::new(RecTrigger(Mutex::new(Vec::new())));
        let h = DohResolversSetHandler::new(
            Arc::clone(&store) as Arc<dyn DohResolverListStore>,
            Some(Arc::clone(&trigger) as Arc<dyn RoutePolicyApplyTrigger>),
        );
        let payload = serde_json::to_value(DohResolversSetRequest {
            resolvers: vec![entry("ip", "1.1.1.1"), entry("host", "dns.google")],
        })
        .unwrap();
        let v = h
            .handle(
                &req(IpcOperationName::DohResolversSet, payload),
                &ctx("S-1-5-21-A"),
            )
            .unwrap();
        let parsed: DohResolversSetResponse = serde_json::from_value(v).unwrap();
        assert_eq!(parsed.resolvers.len(), 2);
        assert_eq!(store.get_all().unwrap().len(), 2);
        assert_eq!(
            trigger.0.lock().unwrap().as_slice(),
            &["S-1-5-21-A".to_string()]
        );
    }

    #[test]
    fn set_rejects_invalid_entry_before_write() {
        let store = Arc::new(MemStore {
            entries: Mutex::new(Vec::new()),
        });
        let h =
            DohResolversSetHandler::new(Arc::clone(&store) as Arc<dyn DohResolverListStore>, None);
        let payload = serde_json::to_value(DohResolversSetRequest {
            resolvers: vec![entry("ip", "not-an-ip")],
        })
        .unwrap();
        let err = h
            .handle(&req(IpcOperationName::DohResolversSet, payload), &ctx("S"))
            .unwrap_err();
        assert_eq!(err.code, IpcErrorCode::PreconditionFailed);
        assert!(
            store.get_all().unwrap().is_empty(),
            "no write on invalid input"
        );
    }
}
