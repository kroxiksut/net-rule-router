//! `WindowsApiPort` trait + neutral `MockWindowsApi`.
//!
//! Per the policy/mechanism seam, the port DEFINITION (`WindowsApiPort`)
//! and its always-compiled test double (`MockWindowsApi`, plus the deterministic
//! `mock_luid_for_index` helper) are neutral — they reference only `std` and the
//! neutral `error`/`types`/`adapters` value types — so they live in the neutral
//! `nrr-platform-api`. The Windows MECHANISM (`ProductionWindowsApi` + the
//! `production_*` Win32 FFI helpers) stays in `nrr-platform-windows` and
//! re-exports these definitions for source compatibility.
//!
//! All Win32 networking calls are accessed only through `WindowsApiPort`.
//! Business logic in the apply layer never calls Win32 directly. This single
//! seam makes the entire apply layer unit-testable without admin rights or a
//! live Windows installation.

use std::sync::Mutex;

use crate::{
    error::PlatformError,
    types::{RouteEntry, WfpEngineToken, WfpFilterId, WfpFilterRecord, WfpFilterSpec},
};

// ── Trait ─────────────────────────────────────────────────────────────────────

/// Abstraction over all Win32 networking calls used by the apply layer.
///
/// Every method maps to one (or a small group of) Win32 API calls. The
/// signature uses Rust-idiomatic types; the production impl translates
/// them to Win32 structures internally with localized `unsafe { }` blocks.
pub trait WindowsApiPort: Send + Sync {
    // ── IPv4 route table ─────────────────────────────────────────────────────

    /// Enumerate all IPv4 routes that our apply layer is interested in.
    /// Wraps `GetIpForwardTable2(AF_INET, ...)`.
    fn get_ip_forward_table(&self) -> Result<Vec<RouteEntry>, PlatformError>;

    /// Add a single IPv4 route entry.
    /// Wraps `CreateIpForwardEntry2(...)`.
    fn create_ip_forward_entry(&self, entry: &RouteEntry) -> Result<(), PlatformError>;

    /// Delete a single IPv4 route entry.
    /// Wraps `DeleteIpForwardEntry2(...)`.
    fn delete_ip_forward_entry(&self, entry: &RouteEntry) -> Result<(), PlatformError>;

    // ── Adapter enumeration ───────────────────────────────────────────────────

    /// Enumerate all network adapters with their current availability state.
    /// Wraps `GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_GATEWAYS, ...)`.
    ///
    /// Returns info for all adapters including virtual and loopback.
    /// Callers filter via `is_virtual_adapter()` and `classify_availability()`.
    fn get_adapter_infos(&self) -> Result<Vec<crate::adapters::AdapterInfo>, PlatformError>;

    /// All local unicast addresses (IPv4 **and**
    /// IPv6) paired with the interface index that owns each, via
    /// `GetUnicastIpAddressTable`. The connection-egress trace maps a
    /// connection's local (source) address to its egress interface; unlike
    /// [`Self::get_adapter_infos`] (IPv4-only) this also covers IPv6. The
    /// default returns empty (no egress labelling) so non-production doubles
    /// need not implement it; the production impl overrides.
    fn unicast_ip_addresses(&self) -> Result<Vec<(std::net::IpAddr, u32)>, PlatformError> {
        Ok(Vec::new())
    }

    /// String SID of the user owning the active console
    /// session (`WTSGetActiveConsoleSessionId` → `WTSQueryUserToken` →
    /// `GetTokenInformation(TokenUser)`). The service-driven routing scope uses
    /// it to pick the routing user when no GUI/tray is connected (enforce a
    /// managed policy from boot). `None` when there is no interactive console
    /// user or the SID can't be resolved. The default returns `None` so test
    /// doubles need not implement it; the production impl overrides.
    fn active_console_user_sid(&self) -> Option<String> {
        None
    }

    /// Resolve a Windows `IfIndex` to its 64-bit interface LUID
    /// (`NET_LUID.Value`). The kill-switch needs the
    /// LUID — not the `IfIndex` — to pin a
    /// `FWPM_CONDITION_IP_LOCAL_INTERFACE` egress condition on a filter.
    /// Wraps `ConvertInterfaceIndexToLuid`.
    fn interface_luid_for_index(&self, ifindex: u32) -> Result<u64, PlatformError>;

    // ── WFP engine ───────────────────────────────────────────────────────────

    /// Open a dynamic (volatile, non-persistent) WFP engine session.
    /// Wraps `FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &handle)`.
    ///
    /// Lifecycle: open at start of each apply, close at end (`per-apply`
    /// strategy).
    fn wfp_engine_open(&self) -> Result<WfpEngineToken, PlatformError>;

    /// Close a WFP engine session and release the handle.
    /// Wraps `FwpmEngineClose0(handle)`.
    fn wfp_engine_close(&self, token: WfpEngineToken) -> Result<(), PlatformError>;

    /// Begin an explicit WFP transaction (read-write).
    /// Wraps `FwpmTransactionBegin0(handle, 0)`.
    fn wfp_transaction_begin(&self, token: &WfpEngineToken) -> Result<(), PlatformError>;

    /// Commit the current WFP transaction.
    /// Wraps `FwpmTransactionCommit0(handle)`.
    fn wfp_transaction_commit(&self, token: &WfpEngineToken) -> Result<(), PlatformError>;

    /// Abort the current WFP transaction. Called on `Drop` of
    /// `WfpTransactionGuard` if not already committed.
    /// Wraps `FwpmTransactionAbort0(handle)`.
    /// Not failable — abort must always succeed (Win32 contract).
    fn wfp_transaction_abort(&self, token: &WfpEngineToken);

    /// Add a WFP filter within the current transaction.
    /// Wraps `FwpmFilterAdd0(handle, &filter, NULL, &id)`.
    fn wfp_filter_add(
        &self,
        token: &WfpEngineToken,
        spec: &WfpFilterSpec,
    ) -> Result<WfpFilterId, PlatformError>;

    /// Delete a WFP filter by stable key.
    /// Wraps `FwpmFilterDeleteByKey0(handle, &key)`.
    fn wfp_filter_delete(
        &self,
        token: &WfpEngineToken,
        id: WfpFilterId,
    ) -> Result<(), PlatformError>;

    /// Enumerate all WFP filters registered under our provider GUID.
    /// Wraps `FwpmFilterCreateEnumHandle0` + `FwpmFilterEnum0` +
    /// `FwpmFilterDestroyEnumHandle0`.
    fn wfp_enumerate_our_filters(
        &self,
        token: &WfpEngineToken,
    ) -> Result<Vec<WfpFilterRecord>, PlatformError>;
}

// ── Mock implementation ───────────────────────────────────────────────────────

/// Deterministic mock LUID for an `IfIndex` — distinct per index and
/// always non-zero (so the kill-switch's `luid == 0` fail-open guard is
/// not tripped in mock-driven tests). Exposed so cross-crate tests can
/// assert the exact value [`MockWindowsApi::interface_luid_for_index`]
/// returns.
pub fn mock_luid_for_index(ifindex: u32) -> u64 {
    0x4C00_0000_0000_0000 | u64::from(ifindex)
}

/// Test-only mock. Call `set_*` methods to pre-configure responses.
///
/// Always compiled (not `#[cfg(test)]`) so integration tests in other
/// crates can use it.
pub struct MockWindowsApi {
    pub route_table: Mutex<Vec<RouteEntry>>,
    pub wfp_filters: Mutex<Vec<WfpFilterRecord>>,
    pub adapter_infos: Mutex<Vec<crate::adapters::AdapterInfo>>,
    /// If `Some`, all mutable calls return this error.
    pub force_error: Mutex<Option<PlatformError>>,
    /// Filter ids (raw) whose `wfp_filter_add` returns
    /// `FWP_E_CONDITION_NOT_FOUND` (an un-materializable filter) — used to
    /// exercise the best-effort / strict apply policies selectively.
    fail_add_ids: Mutex<std::collections::HashSet<u64>>,
    /// Filter ids (raw) whose `wfp_filter_add` returns an arbitrary
    /// `PlatformError::Win32 { operation, code }` — used to exercise
    /// error-classification seams (e.g. the sub-layer-stage vs
    /// duplicate-filter distinction) without a real WFP engine.
    fail_add_win32: Mutex<Option<(std::collections::HashSet<u64>, &'static str, u32)>>,
    next_engine_token: Mutex<u64>,
    #[allow(dead_code)]
    next_filter_id: Mutex<u64>,
    /// Configurable active console-session SID, for
    /// tests of the service-driven routing gate. `None` (default) mirrors the
    /// trait default ("no console user").
    console_user_sid: Mutex<Option<String>>,
}

// Test-only mock: `Mutex::lock().unwrap()` and similar are acceptable scaffolding.
#[allow(clippy::unwrap_used, clippy::expect_used)]
impl MockWindowsApi {
    pub fn new() -> Self {
        Self {
            route_table: Mutex::new(Vec::new()),
            wfp_filters: Mutex::new(Vec::new()),
            adapter_infos: Mutex::new(Vec::new()),
            force_error: Mutex::new(None),
            fail_add_ids: Mutex::new(std::collections::HashSet::new()),
            fail_add_win32: Mutex::new(None),
            next_engine_token: Mutex::new(1),
            next_filter_id: Mutex::new(1),
            console_user_sid: Mutex::new(None),
        }
    }

    /// Set the SID returned by `active_console_user_sid` — the service-driven
    /// routing gate's fallback when no tray is connected.
    pub fn set_console_user_sid(&self, sid: Option<&str>) {
        *self.console_user_sid.lock().unwrap() = sid.map(|s| s.to_string());
    }

    /// Mark specific filter ids (raw) so their `wfp_filter_add` fails with
    /// `FWP_E_CONDITION_NOT_FOUND` — an un-materializable filter the apply
    /// policy decides to skip (best-effort) or abort on (strict).
    pub fn set_fail_add_unmaterializable(&self, ids: &[u64]) {
        *self.fail_add_ids.lock().unwrap() = ids.iter().copied().collect();
    }

    /// Mark specific filter ids (raw) so their `wfp_filter_add` fails with an
    /// arbitrary `PlatformError::Win32 { operation, code }`. Lets tests drive
    /// the apply layer's error-classification seams — for example
    /// `FwpmSubLayerAdd0` with `FWP_E_ALREADY_EXISTS` (sub-layer stage
    /// failed, batch must abort) versus `FwpmFilterAdd0` with the same code
    /// (duplicate filter, idempotent success). Takes precedence over
    /// `set_fail_add_unmaterializable`.
    pub fn set_fail_add_win32(&self, ids: &[u64], operation: &'static str, code: u32) {
        *self.fail_add_win32.lock().unwrap() =
            Some((ids.iter().copied().collect(), operation, code));
    }

    pub fn set_route_table(&self, routes: Vec<RouteEntry>) {
        *self.route_table.lock().unwrap() = routes;
    }

    pub fn set_adapter_infos(&self, infos: Vec<crate::adapters::AdapterInfo>) {
        *self.adapter_infos.lock().unwrap() = infos;
    }

    pub fn set_force_error(&self, err: Option<PlatformError>) {
        *self.force_error.lock().unwrap() = err;
    }

    fn check_error(&self) -> Result<(), PlatformError> {
        if let Some(e) = &*self.force_error.lock().unwrap() {
            return Err(match e {
                PlatformError::AccessDenied { operation } => {
                    PlatformError::AccessDenied { operation }
                }
                PlatformError::NotYetImplemented { block } => {
                    PlatformError::NotYetImplemented { block }
                }
                PlatformError::Transient { operation, detail } => PlatformError::Transient {
                    operation,
                    detail: detail.clone(),
                },
                PlatformError::Win32 {
                    operation,
                    code,
                    message,
                } => PlatformError::Win32 {
                    operation,
                    code: *code,
                    message: message.clone(),
                },
                PlatformError::StateCorrupted { detail } => PlatformError::StateCorrupted {
                    detail: detail.clone(),
                },
                PlatformError::NotSupported { reason } => PlatformError::NotSupported { reason },
            });
        }
        Ok(())
    }
}

impl Default for MockWindowsApi {
    fn default() -> Self {
        Self::new()
    }
}

// Test-only mock: lock-poisoning `unwrap()` is acceptable scaffolding.
#[allow(clippy::unwrap_used, clippy::expect_used)]
impl WindowsApiPort for MockWindowsApi {
    fn get_ip_forward_table(&self) -> Result<Vec<RouteEntry>, PlatformError> {
        Ok(self.route_table.lock().unwrap().clone())
    }

    fn active_console_user_sid(&self) -> Option<String> {
        self.console_user_sid.lock().unwrap().clone()
    }

    fn create_ip_forward_entry(&self, entry: &RouteEntry) -> Result<(), PlatformError> {
        self.check_error()?;
        self.route_table.lock().unwrap().push(entry.clone());
        Ok(())
    }

    fn get_adapter_infos(&self) -> Result<Vec<crate::adapters::AdapterInfo>, PlatformError> {
        Ok(self.adapter_infos.lock().unwrap().clone())
    }

    fn interface_luid_for_index(&self, ifindex: u32) -> Result<u64, PlatformError> {
        self.check_error()?;
        // Deterministic, non-zero, distinct per ifindex so kill-switch
        // tests get a stable, derivable LUID without a live adapter.
        Ok(mock_luid_for_index(ifindex))
    }

    fn delete_ip_forward_entry(&self, entry: &RouteEntry) -> Result<(), PlatformError> {
        self.check_error()?;
        let mut table = self.route_table.lock().unwrap();
        table.retain(|r| {
            !(r.destination == entry.destination
                && r.prefix_length == entry.prefix_length
                && r.interface_index == entry.interface_index)
        });
        Ok(())
    }

    fn wfp_engine_open(&self) -> Result<WfpEngineToken, PlatformError> {
        self.check_error()?;
        let mut n = self.next_engine_token.lock().unwrap();
        let token = WfpEngineToken { raw: *n };
        *n += 1;
        Ok(token)
    }

    fn wfp_engine_close(&self, _token: WfpEngineToken) -> Result<(), PlatformError> {
        Ok(())
    }

    fn wfp_transaction_begin(&self, _token: &WfpEngineToken) -> Result<(), PlatformError> {
        self.check_error()
    }

    fn wfp_transaction_commit(&self, _token: &WfpEngineToken) -> Result<(), PlatformError> {
        self.check_error()
    }

    fn wfp_transaction_abort(&self, _token: &WfpEngineToken) {
        // no-op in mock
    }

    fn wfp_filter_add(
        &self,
        _token: &WfpEngineToken,
        spec: &WfpFilterSpec,
    ) -> Result<WfpFilterId, PlatformError> {
        self.check_error()?;
        // Mirror the real engine's layer↔condition validation, so a
        // protocol-narrowed packet-layer filter (invalid: no
        // FWPM_CONDITION_IP_PROTOCOL at the IPPACKET layers) fails the same
        // unit test that would otherwise pass while FwpmFilterAdd0 rejects it
        // in production with FWP_E_CONDITION_NOT_FOUND.
        if let Err(reason) = spec.validate_layer_conditions() {
            return Err(PlatformError::Win32 {
                operation: "FwpmFilterAdd0",
                code: crate::error::win32_codes::FWP_E_CONDITION_NOT_FOUND,
                message: format!("Win32 error 0x80320002 — {reason}"),
            });
        }
        let id = spec.id;
        if let Some((ids, operation, code)) = &*self.fail_add_win32.lock().unwrap() {
            if ids.contains(&id.raw) {
                return Err(PlatformError::Win32 {
                    operation,
                    code: *code,
                    message: format!("Win32 error 0x{code:08X}"),
                });
            }
        }
        if self.fail_add_ids.lock().unwrap().contains(&id.raw) {
            return Err(PlatformError::Win32 {
                operation: "FwpmFilterAdd0",
                code: crate::error::win32_codes::FWP_E_CONDITION_NOT_FOUND,
                message: "Win32 error 0x80320002".to_string(),
            });
        }
        self.wfp_filters.lock().unwrap().push(WfpFilterRecord {
            id,
            layer: spec.layer,
            action: spec.action,
            remote_ip: spec.remote_ip,
            remote_port: spec.remote_port,
            weight: spec.weight,
            user_sid: spec.user_sid.clone(),
            app_pattern: spec.app_pattern.clone(),
            local_interface_luid: spec.local_interface_luid,
            remote_subnet: spec.remote_subnet,
            remote_subnet_v6: spec.remote_subnet_v6,
            ip_protocol: spec.ip_protocol,
        });
        Ok(id)
    }

    fn wfp_filter_delete(
        &self,
        _token: &WfpEngineToken,
        id: WfpFilterId,
    ) -> Result<(), PlatformError> {
        self.check_error()?;
        self.wfp_filters.lock().unwrap().retain(|f| f.id != id);
        Ok(())
    }

    fn wfp_enumerate_our_filters(
        &self,
        _token: &WfpEngineToken,
    ) -> Result<Vec<WfpFilterRecord>, PlatformError> {
        Ok(self.wfp_filters.lock().unwrap().clone())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{WfpAction, WfpLayerKey};
    use std::net::Ipv4Addr;

    fn sample_route() -> RouteEntry {
        RouteEntry {
            destination: Ipv4Addr::new(10, 0, 0, 0),
            prefix_length: 24,
            next_hop: Ipv4Addr::new(192, 168, 1, 1),
            interface_index: 5,
            metric: 100,
            is_ours: true,
            table: crate::RouteTableRef::Main,
        }
    }

    fn sample_spec() -> WfpFilterSpec {
        WfpFilterSpec {
            layer: WfpLayerKey::AleAuthConnectV4,
            action: WfpAction::Block,
            remote_ip: Some(Ipv4Addr::new(1, 2, 3, 4)),
            remote_port: None,
            weight: 0x10001,
            id: WfpFilterId { raw: 42 },
            user_sid: None,
            app_pattern: None,
            local_interface_luid: None,
            remote_subnet: None,
            remote_subnet_v6: None,
            ip_protocol: None,
        }
    }

    #[test]
    fn mock_route_table_add_and_delete() {
        let api = MockWindowsApi::new();
        let route = sample_route();
        api.create_ip_forward_entry(&route).unwrap();
        let table = api.get_ip_forward_table().unwrap();
        assert_eq!(table.len(), 1);
        api.delete_ip_forward_entry(&route).unwrap();
        assert!(api.get_ip_forward_table().unwrap().is_empty());
    }

    #[test]
    fn mock_wfp_filter_add_and_delete() {
        let api = MockWindowsApi::new();
        let token = api.wfp_engine_open().unwrap();
        let spec = sample_spec();
        let id = api.wfp_filter_add(&token, &spec).unwrap();
        let filters = api.wfp_enumerate_our_filters(&token).unwrap();
        assert_eq!(filters.len(), 1);
        api.wfp_filter_delete(&token, id).unwrap();
        assert!(api.wfp_enumerate_our_filters(&token).unwrap().is_empty());
        api.wfp_engine_close(token).unwrap();
    }

    #[test]
    fn mock_wfp_filter_add_carries_user_sid_through_to_record() {
        let api = MockWindowsApi::new();
        let token = api.wfp_engine_open().unwrap();
        let mut spec = sample_spec();
        spec.user_sid = Some("S-1-5-21-A".into());
        spec.id = WfpFilterId { raw: 100 };
        api.wfp_filter_add(&token, &spec).unwrap();

        let mut spec_b = sample_spec();
        spec_b.user_sid = Some("S-1-5-21-B".into());
        spec_b.id = WfpFilterId { raw: 101 };
        api.wfp_filter_add(&token, &spec_b).unwrap();

        let mut spec_global = sample_spec();
        spec_global.user_sid = None;
        spec_global.id = WfpFilterId { raw: 102 };
        api.wfp_filter_add(&token, &spec_global).unwrap();

        let filters = api.wfp_enumerate_our_filters(&token).unwrap();
        assert_eq!(filters.len(), 3);
        assert_eq!(
            filters[0].user_sid.as_deref(),
            Some("S-1-5-21-A"),
            "first filter must carry user_sid A"
        );
        assert_eq!(
            filters[1].user_sid.as_deref(),
            Some("S-1-5-21-B"),
            "second filter must carry user_sid B"
        );
        assert!(
            filters[2].user_sid.is_none(),
            "third filter is system-wide (None)"
        );
    }

    #[test]
    fn mock_force_error_propagates_to_mutations() {
        let api = MockWindowsApi::new();
        api.set_force_error(Some(PlatformError::AccessDenied {
            operation: "create_route",
        }));
        let result = api.create_ip_forward_entry(&sample_route());
        assert!(matches!(result, Err(PlatformError::AccessDenied { .. })));
    }
}
