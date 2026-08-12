//! `ProductionWindowsApi` Win32 mechanism backend.
//!
//! ## Design
//!
//! All Win32 networking calls are accessed only through `WindowsApiPort`.
//! Business logic in the apply layer never calls Win32 directly. This
//! single seam makes the entire apply layer unit-testable without admin
//! rights or a live Windows installation.
//!
//! ## Implementations
//!
//! - `ProductionWindowsApi` — calls real Win32 APIs. Only compiled and
//!   used when `cfg(target_os = "windows")`. On non-Windows targets its
//!   methods return `PlatformError::NotSupported` so the workspace still
//!   compiles on Linux / macOS CI runners.
//!
//! The neutral port DEFINITION (`WindowsApiPort`), the always-compiled
//! `MockWindowsApi` test double, and the `mock_luid_for_index` helper live in
//! `nrr-platform-api` and are re-exported below so
//! `nrr_platform_windows::windows_api::*` paths keep resolving unchanged.

pub use nrr_platform_api::windows_api::{mock_luid_for_index, MockWindowsApi, WindowsApiPort};

use crate::{
    error::PlatformError,
    types::{RouteEntry, WfpEngineToken, WfpFilterId, WfpFilterRecord, WfpFilterSpec},
};

// ── Production implementation ─────────────────────────────────────────────────

/// Production implementation: calls real Win32 APIs on Windows.
///
/// On non-Windows targets this struct exists but all methods return
/// `Err(PlatformError::NotSupported)` so that `cargo check --workspace`
/// succeeds on Linux/macOS CI runners.
pub struct ProductionWindowsApi;

impl WindowsApiPort for ProductionWindowsApi {
    fn get_ip_forward_table(&self) -> Result<Vec<RouteEntry>, PlatformError> {
        // Real GetIpForwardTable2 on Windows; stubbed elsewhere via
        // `production_get_ip_forward_table`.
        production_get_ip_forward_table()
    }

    fn create_ip_forward_entry(&self, entry: &RouteEntry) -> Result<(), PlatformError> {
        // Real CreateIpForwardEntry2 on Windows.
        production_create_ip_forward_entry(entry)
    }

    fn delete_ip_forward_entry(&self, entry: &RouteEntry) -> Result<(), PlatformError> {
        // Real DeleteIpForwardEntry2 on Windows.
        production_delete_ip_forward_entry(entry)
    }

    fn get_adapter_infos(&self) -> Result<Vec<crate::adapters::AdapterInfo>, PlatformError> {
        // Real GetAdaptersAddresses path on Windows; unsupported on other
        // targets so cross-platform `cargo check` stays green.
        production_get_adapter_infos()
    }

    fn unicast_ip_addresses(&self) -> Result<Vec<(std::net::IpAddr, u32)>, PlatformError> {
        // Real GetUnicastIpAddressTable on Windows; unsupported elsewhere so
        // cross-platform check stays green.
        production_unicast_ip_addresses()
    }

    fn active_console_user_sid(&self) -> Option<String> {
        // Real WTS/token resolution on Windows; no console-session concept
        // elsewhere, so cross-platform check stays green.
        #[cfg(target_os = "windows")]
        {
            crate::win32_ffi::console_session::active_console_user_sid()
        }
        #[cfg(not(target_os = "windows"))]
        {
            None
        }
    }

    fn interface_luid_for_index(&self, ifindex: u32) -> Result<u64, PlatformError> {
        // Real ConvertInterfaceIndexToLuid on Windows.
        production_interface_luid_for_index(ifindex)
    }

    fn wfp_engine_open(&self) -> Result<WfpEngineToken, PlatformError> {
        production_wfp_engine_open()
    }

    fn wfp_engine_close(&self, token: WfpEngineToken) -> Result<(), PlatformError> {
        production_wfp_engine_close(token)
    }

    fn wfp_transaction_begin(&self, token: &WfpEngineToken) -> Result<(), PlatformError> {
        production_wfp_transaction_begin(token)
    }

    fn wfp_transaction_commit(&self, token: &WfpEngineToken) -> Result<(), PlatformError> {
        production_wfp_transaction_commit(token)
    }

    fn wfp_transaction_abort(&self, token: &WfpEngineToken) {
        production_wfp_transaction_abort(token);
    }

    fn wfp_filter_add(
        &self,
        token: &WfpEngineToken,
        spec: &WfpFilterSpec,
    ) -> Result<WfpFilterId, PlatformError> {
        // Real FwpmFilterAdd0 (with idempotent sub-layer ensure + SDDL
        // user-SID + NT-path app-id) on Windows; stubbed elsewhere via
        // `production_wfp_filter_add`.
        production_wfp_filter_add(token, spec)
    }

    fn wfp_filter_delete(
        &self,
        token: &WfpEngineToken,
        id: WfpFilterId,
    ) -> Result<(), PlatformError> {
        // Real FwpmFilterDeleteByKey0 on Windows.
        production_wfp_filter_delete(token, id)
    }

    fn wfp_enumerate_our_filters(
        &self,
        token: &WfpEngineToken,
    ) -> Result<Vec<WfpFilterRecord>, PlatformError> {
        // Real FwpmFilterCreateEnumHandle0 + FwpmFilterEnum0 +
        // FwpmFilterDestroyEnumHandle0 on Windows.
        production_wfp_enumerate_our_filters(token)
    }
}

// ── Production helpers (cfg-gated by target_os) ──────────────────────────────
//
// `ProductionWindowsApi` trait methods stay
// platform-agnostic at the `impl` site; the real Win32 work lives in
// `crate::win32_ffi`, gated to `cfg(target_os = "windows")`. On
// non-Windows targets these helpers return `PlatformError::NotSupported`
// so the workspace still compiles on Linux / macOS CI runners.

#[cfg(target_os = "windows")]
fn production_get_adapter_infos() -> Result<Vec<crate::adapters::AdapterInfo>, PlatformError> {
    crate::win32_ffi::adapters::enumerate_adapters()
}

#[cfg(not(target_os = "windows"))]
fn production_get_adapter_infos() -> Result<Vec<crate::adapters::AdapterInfo>, PlatformError> {
    Err(PlatformError::NotSupported {
        reason: "GetAdaptersAddresses requires target_os = \"windows\"",
    })
}

#[cfg(target_os = "windows")]
fn production_unicast_ip_addresses() -> Result<Vec<(std::net::IpAddr, u32)>, PlatformError> {
    crate::win32_ffi::unicast::query_unicast_ip_addresses()
}

#[cfg(not(target_os = "windows"))]
fn production_unicast_ip_addresses() -> Result<Vec<(std::net::IpAddr, u32)>, PlatformError> {
    Err(PlatformError::NotSupported {
        reason: "GetUnicastIpAddressTable requires target_os = \"windows\"",
    })
}

#[cfg(target_os = "windows")]
fn production_interface_luid_for_index(ifindex: u32) -> Result<u64, PlatformError> {
    crate::win32_ffi::route_table::interface_luid_for_index(ifindex)
}

#[cfg(not(target_os = "windows"))]
fn production_interface_luid_for_index(_ifindex: u32) -> Result<u64, PlatformError> {
    Err(PlatformError::NotSupported {
        reason: "ConvertInterfaceIndexToLuid requires target_os = \"windows\"",
    })
}

#[cfg(target_os = "windows")]
fn production_get_ip_forward_table() -> Result<Vec<RouteEntry>, PlatformError> {
    crate::win32_ffi::route_table::enumerate_routes()
}

#[cfg(not(target_os = "windows"))]
fn production_get_ip_forward_table() -> Result<Vec<RouteEntry>, PlatformError> {
    Err(PlatformError::NotSupported {
        reason: "GetIpForwardTable2 requires target_os = \"windows\"",
    })
}

#[cfg(target_os = "windows")]
fn production_create_ip_forward_entry(entry: &RouteEntry) -> Result<(), PlatformError> {
    crate::win32_ffi::route_table::add_route(entry)
}

#[cfg(not(target_os = "windows"))]
fn production_create_ip_forward_entry(_entry: &RouteEntry) -> Result<(), PlatformError> {
    Err(PlatformError::NotSupported {
        reason: "CreateIpForwardEntry2 requires target_os = \"windows\"",
    })
}

#[cfg(target_os = "windows")]
fn production_delete_ip_forward_entry(entry: &RouteEntry) -> Result<(), PlatformError> {
    crate::win32_ffi::route_table::delete_route(entry)
}

#[cfg(not(target_os = "windows"))]
fn production_delete_ip_forward_entry(_entry: &RouteEntry) -> Result<(), PlatformError> {
    Err(PlatformError::NotSupported {
        reason: "DeleteIpForwardEntry2 requires target_os = \"windows\"",
    })
}

// ── WFP engine + transaction ───────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn production_wfp_engine_open() -> Result<WfpEngineToken, PlatformError> {
    crate::win32_ffi::wfp_engine::engine_open()
}

#[cfg(not(target_os = "windows"))]
fn production_wfp_engine_open() -> Result<WfpEngineToken, PlatformError> {
    Err(PlatformError::NotSupported {
        reason: "FwpmEngineOpen0 requires target_os = \"windows\"",
    })
}

#[cfg(target_os = "windows")]
fn production_wfp_engine_close(token: WfpEngineToken) -> Result<(), PlatformError> {
    crate::win32_ffi::wfp_engine::engine_close(token)
}

#[cfg(not(target_os = "windows"))]
fn production_wfp_engine_close(_token: WfpEngineToken) -> Result<(), PlatformError> {
    Err(PlatformError::NotSupported {
        reason: "FwpmEngineClose0 requires target_os = \"windows\"",
    })
}

#[cfg(target_os = "windows")]
fn production_wfp_transaction_begin(token: &WfpEngineToken) -> Result<(), PlatformError> {
    crate::win32_ffi::wfp_transaction::transaction_begin(token)
}

#[cfg(not(target_os = "windows"))]
fn production_wfp_transaction_begin(_token: &WfpEngineToken) -> Result<(), PlatformError> {
    Err(PlatformError::NotSupported {
        reason: "FwpmTransactionBegin0 requires target_os = \"windows\"",
    })
}

#[cfg(target_os = "windows")]
fn production_wfp_transaction_commit(token: &WfpEngineToken) -> Result<(), PlatformError> {
    crate::win32_ffi::wfp_transaction::transaction_commit(token)
}

#[cfg(not(target_os = "windows"))]
fn production_wfp_transaction_commit(_token: &WfpEngineToken) -> Result<(), PlatformError> {
    Err(PlatformError::NotSupported {
        reason: "FwpmTransactionCommit0 requires target_os = \"windows\"",
    })
}

#[cfg(target_os = "windows")]
fn production_wfp_transaction_abort(token: &WfpEngineToken) {
    crate::win32_ffi::wfp_transaction::transaction_abort(token);
}

#[cfg(not(target_os = "windows"))]
fn production_wfp_transaction_abort(_token: &WfpEngineToken) {
    // No-op on non-Windows — `abort` is contractually never failable.
}

// ── WFP filter add/delete/enumerate ────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn production_wfp_filter_add(
    token: &WfpEngineToken,
    spec: &WfpFilterSpec,
) -> Result<WfpFilterId, PlatformError> {
    crate::win32_ffi::wfp_filter::add_filter(token, spec)
}

#[cfg(not(target_os = "windows"))]
fn production_wfp_filter_add(
    _token: &WfpEngineToken,
    _spec: &WfpFilterSpec,
) -> Result<WfpFilterId, PlatformError> {
    Err(PlatformError::NotSupported {
        reason: "FwpmFilterAdd0 requires target_os = \"windows\"",
    })
}

#[cfg(target_os = "windows")]
fn production_wfp_filter_delete(
    token: &WfpEngineToken,
    id: WfpFilterId,
) -> Result<(), PlatformError> {
    crate::win32_ffi::wfp_filter::delete_filter(token, id)
}

#[cfg(not(target_os = "windows"))]
fn production_wfp_filter_delete(
    _token: &WfpEngineToken,
    _id: WfpFilterId,
) -> Result<(), PlatformError> {
    Err(PlatformError::NotSupported {
        reason: "FwpmFilterDeleteByKey0 requires target_os = \"windows\"",
    })
}

#[cfg(target_os = "windows")]
fn production_wfp_enumerate_our_filters(
    token: &WfpEngineToken,
) -> Result<Vec<WfpFilterRecord>, PlatformError> {
    crate::win32_ffi::wfp_filter::enumerate_our_filters(token)
}

#[cfg(not(target_os = "windows"))]
fn production_wfp_enumerate_our_filters(
    _token: &WfpEngineToken,
) -> Result<Vec<WfpFilterRecord>, PlatformError> {
    Err(PlatformError::NotSupported {
        reason: "FwpmFilterEnum0 requires target_os = \"windows\"",
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// `get_ip_forward_table` uses real Win32 FFI for IPv4 routes. On
    /// Windows we expect a non-empty table (loopback is always present);
    /// on non-Windows targets we expect `NotSupported`.
    #[test]
    fn production_get_ip_forward_table_real_or_unsupported() {
        let api = ProductionWindowsApi;
        match api.get_ip_forward_table() {
            #[cfg(target_os = "windows")]
            Ok(routes) => {
                assert!(
                    !routes.is_empty(),
                    "Windows kernel always carries at least the loopback route"
                );
            }
            #[cfg(not(target_os = "windows"))]
            Err(PlatformError::NotSupported { .. }) => {}
            other => panic!("unexpected result: {other:?}"),
        }
    }

    /// The full WFP add/delete/enumerate trio is wired to real Win32 FFI.
    /// With a synthesized (invalid) engine token we expect
    /// [`PlatformError::Win32`] from each call.
    ///
    /// `delete_filter` against the null handle returns
    /// `ERROR_INVALID_HANDLE` (6) or a similar transport error on
    /// Windows; on non-Windows targets it returns `NotSupported`. We
    /// only assert that the call does not report an implementation stub.
    #[test]
    fn production_wfp_filter_methods_are_wired_to_real_ffi() {
        let api = ProductionWindowsApi;
        let dummy_token = WfpEngineToken { raw: 0 };

        let del = api.wfp_filter_delete(&dummy_token, WfpFilterId { raw: 0 });
        assert!(
            !matches!(del, Err(PlatformError::NotYetImplemented { .. })),
            "wfp_filter_delete must no longer be a NotYetImplemented stub; got {del:?}"
        );

        let enu = api.wfp_enumerate_our_filters(&dummy_token);
        assert!(
            !matches!(enu, Err(PlatformError::NotYetImplemented { .. })),
            "wfp_enumerate_our_filters must no longer be a NotYetImplemented stub; got {enu:?}"
        );
    }
}
