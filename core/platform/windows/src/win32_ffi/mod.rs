//! Win32 FFI helpers for `ProductionWindowsApi`.
//!
//! All `unsafe { }` Win32 calls live here, partitioned by subsystem:
//! - [`adapters`] — `GetAdaptersAddresses` for IPv4 adapter enumeration
//! - [`route_table`] — `GetIpForwardTable2` /
//!   `CreateIpForwardEntry2` / `DeleteIpForwardEntry2`
//! - [`wfp_engine`] — `FwpmEngineOpen0` / `FwpmEngineClose0`
//! - [`wfp_transaction`] — `FwpmTransactionBegin0` / `Commit0` / `Abort0`
//! - [`wfp_sublayer`] — `FwpmSubLayerAdd0` (idempotent ensure) + the
//!   product-wide `NRR_PROVIDER_GUID` / `NRR_SUBLAYER_GUID` constants
//!   re-projected from [`crate::constants`] into the windows-rs `GUID`
//!   struct.
//! - [`wfp_filter`] — `FwpmFilterAdd0` / `FwpmFilterDeleteByKey0` /
//!   `FwpmFilterCreateEnumHandle0` + `Enum0` + `Destroy*`, including
//!   `FWPM_CONDITION_ALE_APP_ID` (NT-format byte blob) and
//!   `FWPM_CONDITION_ALE_USER_ID` (SDDL-built security descriptor)
//!   condition support.
//! - [`app_id`] — `FwpmGetAppIdFromFileName0` for the user-facing path
//!   → NT-format byte blob conversion that
//!   [`FWPM_CONDITION_ALE_APP_ID`](wfp_filter) requires.
//!
//! ## Invariants (per `lib.rs` `unsafe` policy)
//!
//! - Every `unsafe { }` block is preceded by a `// SAFETY:` comment
//!   that names the invariant being upheld (pointer validity, allocation
//!   ownership, buffer sizing, FFI contract).
//! - Each block stays small (≤ 10 lines where practical).
//! - No business logic inside `unsafe`. Helpers translate Win32 error
//!   codes into [`crate::error::PlatformError`] above the unsafe seam.
//! - Submodules compile only on `cfg(target_os = "windows")`. The
//!   `ProductionWindowsApi` impl in [`crate::windows_api`] returns
//!   `PlatformError::NotSupported` on non-Windows targets so
//!   `cargo check --workspace` succeeds on Linux/macOS CI runners.

#[cfg(target_os = "windows")]
pub mod wide;

#[cfg(target_os = "windows")]
pub mod adapters;

#[cfg(target_os = "windows")]
pub mod route_table;

// Block T (traffic counter) — per-interface octet counters via `GetIfTable2`.
#[cfg(target_os = "windows")]
pub mod interface_counters;

#[cfg(target_os = "windows")]
pub mod unicast;

#[cfg(target_os = "windows")]
pub mod console_session;

#[cfg(target_os = "windows")]
pub mod wfp_engine;

#[cfg(target_os = "windows")]
pub mod wfp_transaction;

#[cfg(target_os = "windows")]
pub mod app_id;

#[cfg(target_os = "windows")]
pub mod wfp_sublayer;

#[cfg(target_os = "windows")]
pub mod wfp_filter;
