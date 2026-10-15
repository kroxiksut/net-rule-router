//! `dns.local-suffixes.get` / `dns.local-suffixes.set` handlers.
//!
//! The list of home and local network suffixes is one per machine. Anyone may
//! read it, with what the current network offers and which of the caller's
//! rule hosts each entry covers; a change needs an administrator, checked by
//! value (`machine_scoped`) so an unchanged save never asks for one.

use std::sync::Arc;

use nrr_shared::ipc_payloads::{
    LocalDnsSuffixDto, LocalDnsSuffixesGetRequest, LocalDnsSuffixesGetResponse,
    LocalDnsSuffixesSetRequest, OfferedDnsSuffixDto,
};
use nrr_shared::local_dns_suffixes::{covered_hosts, normalize_list};

use crate::ipc::{
    HandlerOutcome, IpcError, IpcErrorCode, IpcHandler, IpcRequestContext, IpcRequestEnvelope,
};
use crate::ipc_handlers::providers::RoutePolicyWriteError;
use crate::machine_scoped::{
    machine_scoped_refusal, machine_scoped_write_allowed, MachineScopedSetting,
};

/// Read/replace access to the stored list. The production implementation
/// wraps `nrr_storage::local_dns_suffixes` and publishes every write to the
/// DNS guard.
pub trait LocalDnsSuffixStore: Send + Sync {
    fn get_all(&self) -> Result<Vec<String>, RoutePolicyWriteError>;
    /// Replace the whole list with already-normalised entries; returns the
    /// list as stored.
    fn replace_all(&self, suffixes: &[String]) -> Result<Vec<String>, RoutePolicyWriteError>;
}

/// What the read-back adds to the list: the network's offer and the caller's
/// rule hosts, for the per-entry warning.
pub trait LocalDnsSuffixContext: Send + Sync {
    fn offered(&self) -> Vec<OfferedDnsSuffixDto>;
    fn rule_hosts(&self, sid: &str) -> Vec<String>;
}

/// Nothing offered, nothing covered — the shape of a degraded boot.
pub struct NoLocalDnsSuffixContext;

impl LocalDnsSuffixContext for NoLocalDnsSuffixContext {
    fn offered(&self) -> Vec<OfferedDnsSuffixDto> {
        Vec::new()
    }
    fn rule_hosts(&self, _sid: &str) -> Vec<String> {
        Vec::new()
    }
}

fn compose(
    stored: Vec<String>,
    context: &dyn LocalDnsSuffixContext,
    sid: &str,
) -> LocalDnsSuffixesGetResponse {
    let hosts = context.rule_hosts(sid);
    let suffixes: Vec<LocalDnsSuffixDto> = stored
        .into_iter()
        .map(|suffix| {
            let covers_rule_hosts = covered_hosts(&suffix, hosts.iter().map(String::as_str));
            LocalDnsSuffixDto {
                suffix,
                covers_rule_hosts,
            }
        })
        .collect();
    let offered = context
        .offered()
        .into_iter()
        .filter(|offer| suffixes.iter().all(|s| s.suffix != offer.suffix))
        .collect();
    LocalDnsSuffixesGetResponse { suffixes, offered }
}

fn serialise(op: &str, response: &LocalDnsSuffixesGetResponse) -> HandlerOutcome {
    serde_json::to_value(response).map_err(|e| IpcError {
        code: IpcErrorCode::Internal,
        message: format!("{op} response serialisation failed: {e}"),
        diagnostics_id: None,
    })
}

fn map_write_error(err: RoutePolicyWriteError) -> IpcError {
    IpcError {
        code: IpcErrorCode::Internal,
        message: err.to_string(),
        diagnostics_id: None,
    }
}

pub struct LocalDnsSuffixesGetHandler {
    store: Arc<dyn LocalDnsSuffixStore>,
    context: Arc<dyn LocalDnsSuffixContext>,
}

impl LocalDnsSuffixesGetHandler {
    pub fn new(
        store: Arc<dyn LocalDnsSuffixStore>,
        context: Arc<dyn LocalDnsSuffixContext>,
    ) -> Self {
        Self { store, context }
    }
}

impl IpcHandler for LocalDnsSuffixesGetHandler {
    fn handle(&self, request: &IpcRequestEnvelope, ctx: &IpcRequestContext) -> HandlerOutcome {
        let _: LocalDnsSuffixesGetRequest = serde_json::from_value(request.payload.clone())
            .map_err(|e| IpcError {
                code: IpcErrorCode::MalformedRequest,
                message: format!("dns.local-suffixes.get payload invalid: {e}"),
                diagnostics_id: None,
            })?;
        let stored = self.store.get_all().map_err(map_write_error)?;
        serialise(
            "dns.local-suffixes.get",
            &compose(stored, self.context.as_ref(), ctx.caller_stored()),
        )
    }
}

pub struct LocalDnsSuffixesSetHandler {
    store: Arc<dyn LocalDnsSuffixStore>,
    context: Arc<dyn LocalDnsSuffixContext>,
}

impl LocalDnsSuffixesSetHandler {
    pub fn new(
        store: Arc<dyn LocalDnsSuffixStore>,
        context: Arc<dyn LocalDnsSuffixContext>,
    ) -> Self {
        Self { store, context }
    }
}

impl IpcHandler for LocalDnsSuffixesSetHandler {
    fn handle(&self, request: &IpcRequestEnvelope, ctx: &IpcRequestContext) -> HandlerOutcome {
        let req: LocalDnsSuffixesSetRequest = serde_json::from_value(request.payload.clone())
            .map_err(|e| IpcError {
                code: IpcErrorCode::MalformedRequest,
                message: format!("dns.local-suffixes.set payload invalid: {e}"),
                diagnostics_id: None,
            })?;
        // The whole list or nothing: a bad entry names itself and no row moves.
        let wanted = normalize_list(&req.suffixes).map_err(|(index, why)| IpcError {
            code: IpcErrorCode::PreconditionFailed,
            message: format!(
                "invalid network suffix at position {index} ({}): {}",
                why.slug(),
                req.suffixes
                    .get(index)
                    .map(String::as_str)
                    .unwrap_or_default()
            ),
            diagnostics_id: None,
        })?;
        // Shared by every user of this machine: a non-elevated caller may
        // still save it back unchanged.
        let current = self.store.get_all().map_err(map_write_error)?;
        let mut current_sorted = current;
        current_sorted.sort_unstable();
        let mut wanted_sorted = wanted.clone();
        wanted_sorted.sort_unstable();
        if !machine_scoped_write_allowed(&wanted_sorted, &current_sorted, ctx.caller_is_elevated) {
            return Err(machine_scoped_refusal(
                MachineScopedSetting::LocalDnsSuffixes,
            ));
        }
        let stored = self.store.replace_all(&wanted).map_err(map_write_error)?;
        serialise(
            "dns.local-suffixes.set",
            &compose(stored, self.context.as_ref(), ctx.caller_stored()),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::{IpcOperationClass, IPC_PROTOCOL_VERSION};
    use nrr_shared::ipc::{IpcClientProfile, IpcOperationName};
    use std::sync::Mutex;

    struct MemStore(Mutex<Vec<String>>);

    impl LocalDnsSuffixStore for MemStore {
        fn get_all(&self) -> Result<Vec<String>, RoutePolicyWriteError> {
            Ok(self.0.lock().unwrap().clone())
        }
        fn replace_all(&self, suffixes: &[String]) -> Result<Vec<String>, RoutePolicyWriteError> {
            let mut sorted = suffixes.to_vec();
            sorted.sort_unstable();
            *self.0.lock().unwrap() = sorted.clone();
            Ok(sorted)
        }
    }

    struct Context;

    impl LocalDnsSuffixContext for Context {
        fn offered(&self) -> Vec<OfferedDnsSuffixDto> {
            vec![
                OfferedDnsSuffixDto {
                    suffix: "cafe.example".into(),
                    link: "Wi-Fi".into(),
                },
                OfferedDnsSuffixDto {
                    suffix: "lan".into(),
                    link: "Ethernet".into(),
                },
            ]
        }
        fn rule_hosts(&self, _sid: &str) -> Vec<String> {
            vec!["nas.fritz.box".into(), "www.example".into()]
        }
    }

    fn ctx(elevated: bool) -> IpcRequestContext {
        IpcRequestContext {
            client_profile: IpcClientProfile::GuiInteractive,
            caller_is_elevated: elevated,
            caller_principal: crate::UserPrincipal::from_windows_sid("S-1-5-21-10-20-30-1001").ok(),
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

    fn store(entries: &[&str]) -> Arc<MemStore> {
        Arc::new(MemStore(Mutex::new(
            entries.iter().map(|s| (*s).to_string()).collect(),
        )))
    }

    /// The read shows every entry with the rule hosts it covers, and only
    /// the offers the list does not already hold.
    #[test]
    fn get_lists_coverage_and_the_networks_new_offers() {
        let h = LocalDnsSuffixesGetHandler::new(store(&["fritz.box", "lan"]), Arc::new(Context));
        let v = h
            .handle(
                &req(IpcOperationName::LocalDnsSuffixesGet, serde_json::json!({})),
                &ctx(false),
            )
            .unwrap();
        let parsed: LocalDnsSuffixesGetResponse = serde_json::from_value(v).unwrap();
        assert_eq!(parsed.suffixes[0].suffix, "fritz.box");
        assert_eq!(parsed.suffixes[0].covers_rule_hosts, ["nas.fritz.box"]);
        assert!(parsed.suffixes[1].covers_rule_hosts.is_empty());
        assert_eq!(parsed.offered.len(), 1);
        assert_eq!(parsed.offered[0].suffix, "cafe.example");
    }

    /// An administrator's list is normalised and stored whole.
    #[test]
    fn set_normalises_and_replaces() {
        let store = store(&["lan"]);
        let h = LocalDnsSuffixesSetHandler::new(Arc::clone(&store) as _, Arc::new(Context));
        let payload = serde_json::json!({ "suffixes": ["Home.ARPA.", "lan", "LAN"] });
        let v = h
            .handle(
                &req(IpcOperationName::LocalDnsSuffixesSet, payload),
                &ctx(true),
            )
            .unwrap();
        let parsed: LocalDnsSuffixesGetResponse = serde_json::from_value(v).unwrap();
        let names: Vec<&str> = parsed.suffixes.iter().map(|s| s.suffix.as_str()).collect();
        assert_eq!(names, ["home.arpa", "lan"]);
        assert_eq!(store.get_all().unwrap(), ["home.arpa", "lan"]);
    }

    /// A bad entry refuses the whole list before anything is written, and
    /// names its position and reason.
    #[test]
    fn set_refuses_a_malformed_entry_before_writing() {
        let store = store(&["lan"]);
        let h = LocalDnsSuffixesSetHandler::new(Arc::clone(&store) as _, Arc::new(Context));
        let payload = serde_json::json!({ "suffixes": ["home.arpa", "bad label"] });
        let err = h
            .handle(
                &req(IpcOperationName::LocalDnsSuffixesSet, payload),
                &ctx(true),
            )
            .unwrap_err();
        assert_eq!(err.code, IpcErrorCode::PreconditionFailed);
        assert!(err.message.contains("position 1"), "{}", err.message);
        assert!(err.message.contains("bad-label"), "{}", err.message);
        assert_eq!(store.get_all().unwrap(), ["lan"]);
    }

    /// The same list in another order or spelling is not a change.
    #[test]
    fn an_unelevated_echo_in_another_order_passes_the_gate() {
        let store = store(&["fritz.box", "lan"]);
        let h = LocalDnsSuffixesSetHandler::new(Arc::clone(&store) as _, Arc::new(Context));
        let payload = serde_json::json!({ "suffixes": ["LAN", "fritz.box."] });
        assert!(h
            .handle(
                &req(IpcOperationName::LocalDnsSuffixesSet, payload),
                &ctx(false)
            )
            .is_ok());
    }
}
