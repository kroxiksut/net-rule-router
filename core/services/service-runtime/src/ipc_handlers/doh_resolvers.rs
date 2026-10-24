//! `doh.resolvers.get` / `doh.resolvers.set` handlers.
//!
//! Read / replace the SHARED DoH/DoT resolver baseline list (the machine-wide
//! `doh_resolver_entries` table). The list is NOT per-SID: it is a machine fact
//! seeded with public resolvers by country and edited rarely. A change needs an
//! administrator, checked by value (`machine_scoped`); a successful replace
//! fires the recompile hook for the active caller so the new resolver set takes
//! effect at once (the resolved IPs feed the DoH-lockdown blocks).

use std::sync::Arc;

use crate::ipc::{
    CheckedIpcHandler, HandlerOutcome, IpcError, IpcErrorCode, IpcHandler, IpcRequestContext,
    IpcRequestEnvelope, Prechecked,
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
    /// `(kind, target)` of every built-in entry, lower-cased.
    seeded: Vec<(String, String)>,
}

impl DohResolversSetHandler {
    pub fn new(
        store: Arc<dyn DohResolverListStore>,
        apply_trigger: Option<Arc<dyn RoutePolicyApplyTrigger>>,
    ) -> Self {
        let seeded = crate::doh_seed::builtin_seed()
            .entries
            .iter()
            .map(|s| entry_key(s.entry.target.kind_str(), &s.entry.target.value_str()))
            .collect();
        Self::with_seeded(store, apply_trigger, seeded)
    }

    /// The handler over an explicit built-in set (tests).
    pub fn with_seeded(
        store: Arc<dyn DohResolverListStore>,
        apply_trigger: Option<Arc<dyn RoutePolicyApplyTrigger>>,
        seeded: Vec<(String, String)>,
    ) -> Self {
        Self {
            store,
            apply_trigger,
            seeded,
        }
    }
}

/// The stored spelling, so `2001:DB8::1` and a v4-mapped form match their row.
fn entry_key(kind: &str, target: &str) -> (String, String) {
    match nrr_storage::doh_lockdown::DohTarget::parse(kind, target) {
        Some(t) => (t.kind_str().to_string(), t.value_str()),
        None => (
            kind.to_ascii_lowercase(),
            target.trim().to_ascii_lowercase(),
        ),
    }
}

/// Built-in entries `current` holds that `wanted` leaves out. The seed is never
/// re-applied, so a list written from a copy that was never read would erase
/// them for every user of the machine; only a caller that says it removed
/// them on purpose may.
fn seeded_entries_dropped(
    seeded: &[(String, String)],
    current: &[DohResolverEntryDto],
    wanted: &[DohResolverEntryDto],
) -> Vec<String> {
    let kept: std::collections::HashSet<(String, String)> = wanted
        .iter()
        .map(|e| entry_key(&e.target_kind, &e.target))
        .collect();
    current
        .iter()
        .filter(|e| {
            let key = entry_key(&e.target_kind, &e.target);
            seeded.contains(&key) && !kept.contains(&key)
        })
        .map(|e| e.target.clone())
        .collect()
}

impl DohResolversSetHandler {
    fn seed_guard(
        &self,
        req: &DohResolversSetRequest,
        current: &[DohResolverEntryDto],
    ) -> Result<(), IpcError> {
        if req.drop_seeded {
            return Ok(());
        }
        let dropped = seeded_entries_dropped(&self.seeded, current, &req.resolvers);
        if dropped.is_empty() {
            return Ok(());
        }
        Err(IpcError {
            code: IpcErrorCode::PreconditionFailed,
            message: format!(
                "the list leaves out {} built-in resolver entries ({}); re-read the list, \
                 or set drop-seeded to remove them on purpose",
                dropped.len(),
                dropped.join(", ")
            ),
            diagnostics_id: None,
        })
    }

    /// The list is shared by every user of this machine. A non-elevated caller
    /// may still SAVE it - clients read-modify-write the whole settings page -
    /// as long as the list comes back unchanged.
    fn gate(&self, req: &DohResolversSetRequest, ctx: &IpcRequestContext) -> Result<(), IpcError> {
        let current = self.store.get_all().map_err(map_write_error)?;
        self.seed_guard(req, &current)?;
        if crate::machine_scoped::machine_scoped_write_allowed(
            &req.resolvers,
            &current,
            ctx.caller_is_elevated,
        ) {
            Ok(())
        } else {
            Err(crate::machine_scoped::machine_scoped_refusal(
                crate::machine_scoped::MachineScopedSetting::DohResolvers,
            ))
        }
    }
}

impl CheckedIpcHandler for DohResolversSetHandler {
    type Checked = DohResolversSetRequest;

    fn precheck(
        &self,
        request: &IpcRequestEnvelope,
        ctx: &IpcRequestContext,
    ) -> Result<Self::Checked, IpcError> {
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
        self.gate(&req, ctx)?;
        Ok(req)
    }

    fn execute(
        &self,
        req: Prechecked<Self::Checked>,
        _request: &IpcRequestEnvelope,
        ctx: &IpcRequestContext,
    ) -> HandlerOutcome {
        // The stored list may have moved since the precheck compared with it.
        self.gate(&req, ctx)?;
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
            caller_pid: None,
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
            entries: Mutex::new(vec![entry("ip", "198.51.100.8")]),
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
        assert_eq!(parsed.resolvers[0].target, "198.51.100.8");
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
            resolvers: vec![
                entry("ip", "198.51.100.1"),
                entry("host", "resolver.example"),
            ],
            drop_seeded: false,
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
            drop_seeded: false,
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

    fn seeded_handler(store: Arc<MemStore>) -> DohResolversSetHandler {
        DohResolversSetHandler::with_seeded(
            store as Arc<dyn DohResolverListStore>,
            None,
            vec![("ip".into(), "198.51.100.8".into())],
        )
    }

    #[test]
    fn a_list_without_a_stored_builtin_entry_is_refused_and_nothing_written() {
        let store = Arc::new(MemStore {
            entries: Mutex::new(vec![
                entry("ip", "198.51.100.8"),
                entry("host", "mine.example"),
            ]),
        });
        let h = seeded_handler(Arc::clone(&store));
        let payload = serde_json::to_value(DohResolversSetRequest {
            resolvers: vec![entry("host", "added.example")],
            drop_seeded: false,
        })
        .unwrap();
        let err = h
            .handle(&req(IpcOperationName::DohResolversSet, payload), &ctx("S"))
            .unwrap_err();
        assert_eq!(err.code, IpcErrorCode::PreconditionFailed);
        assert!(err.message.contains("198.51.100.8"));
        assert_eq!(store.get_all().unwrap().len(), 2, "no write");
    }

    #[test]
    fn a_builtin_entry_removed_on_purpose_goes_and_a_user_entry_may_go_silently() {
        let store = Arc::new(MemStore {
            entries: Mutex::new(vec![
                entry("ip", "198.51.100.8"),
                entry("host", "mine.example"),
            ]),
        });
        let h = seeded_handler(Arc::clone(&store));
        // A user's own entry is not guarded.
        let payload = serde_json::to_value(DohResolversSetRequest {
            resolvers: vec![entry("ip", "198.51.100.8")],
            drop_seeded: false,
        })
        .unwrap();
        h.handle(&req(IpcOperationName::DohResolversSet, payload), &ctx("S"))
            .unwrap();
        assert_eq!(store.get_all().unwrap().len(), 1);
        // The built-in one goes only with the flag.
        let payload = serde_json::to_value(DohResolversSetRequest {
            resolvers: Vec::new(),
            drop_seeded: true,
        })
        .unwrap();
        h.handle(&req(IpcOperationName::DohResolversSet, payload), &ctx("S"))
            .unwrap();
        assert!(store.get_all().unwrap().is_empty());
    }
}
