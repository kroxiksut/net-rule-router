//! WFP sub-layer registration (`FwpmSubLayerAdd0`).
//!
//! Filters added via [`super::wfp_filter::add_filter`] reference our
//! sub-layer through `FWPM_FILTER0.subLayerKey`. The sub-layer must
//! exist in the engine before any filter can reference it.
//!
//! [`ensure_sublayer`] is idempotent: `FWP_E_ALREADY_EXISTS` (`0x8032_0009`,
//! from the [`win32_codes`](nrr_platform_api::error::win32_codes) SSOT table)
//! is mapped to success so the apply path can call it once per filter
//! batch without first probing for existence. Production callers
//! invoke it inside the same WFP transaction as the subsequent
//! `FwpmFilterAdd0` calls.
//!
//! ⚠ Never re-declare Win32 error codes locally — a plausible NAME on the
//! wrong NUMBER (e.g. `FWP_E_ALREADY_EXISTS` misdeclared as
//! `FWP_E_CALLOUT_NOT_FOUND`'s value) makes the real already-exists code
//! fatal, and the apply layer's duplicate-add handling then converts that
//! into a silent phantom "success" for every filter once the sub-layer
//! exists. Always import codes from `win32_codes`.
//!
//! ## Stable GUIDs
//!
//! The sub-layer and provider GUIDs come from [`crate::constants`] —
//! [`WFP_PROVIDER_GUID`](crate::constants::WFP_PROVIDER_GUID) and
//! [`WFP_SUBLAYER_GUID`](crate::constants::WFP_SUBLAYER_GUID). Both
//! were allocated once and are baked into the binary; reusing the
//! same GUIDs across service restarts is what makes the orphan-cleanup
//! path (`FwpmFilterEnum0` by sub-layer) work after a crash.

#![allow(unsafe_code)]

use std::mem::MaybeUninit;

use windows::core::{GUID, PWSTR};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmSubLayerAdd0, FWPM_DISPLAY_DATA0, FWPM_SUBLAYER0,
};
use windows::Win32::Security::PSECURITY_DESCRIPTOR;

use crate::constants::{
    WFP_PROVIDER_GUID, WFP_SUBLAYER_DESCRIPTION, WFP_SUBLAYER_GUID, WFP_SUBLAYER_NAME,
    WFP_SUBLAYER_WEIGHT,
};
use crate::error::win32_codes::FWP_E_ALREADY_EXISTS;
use crate::error::PlatformError;
use crate::types::WfpEngineToken;

use super::wfp_engine::token_to_handle;

/// Operation name carried by every error this module emits. Load-bearing:
/// `PlatformError::is_sublayer_registration_failure` matches on this exact
/// string to keep sub-layer failures distinguishable from filter-add
/// duplicates in the apply layer.
const ADD_OP: &str = "FwpmSubLayerAdd0";

/// Provider GUID baked into the constants module, re-projected into
/// the windows-rs [`GUID`] struct.
///
/// Filters are added with
/// `providerKey = null` (a non-null key requires a registered BFE provider
/// object, which we do not create) — ownership of our filters is expressed
/// through `subLayerKey = NRR_SUBLAYER_GUID` (drop-event attribution) and the
/// deterministic `filterKey` namespace (enumeration). This constant remains
/// for a future provider registration and as an attribution fallback.
pub const NRR_PROVIDER_GUID: GUID = guid_from_bytes(&WFP_PROVIDER_GUID);

/// Sub-layer GUID baked into the constants module, re-projected into
/// the windows-rs [`GUID`] struct.
pub const NRR_SUBLAYER_GUID: GUID = guid_from_bytes(&WFP_SUBLAYER_GUID);

/// Decode a packed `[u8; 16]` GUID array (constants.rs storage form)
/// into the windows-rs [`GUID`] struct. The byte array stores
/// `data1`/`data2`/`data3` in big-endian textual order, mirroring how
/// the GUIDs are written in the source comment (`{B4E0D8A2-…}`); the
/// `windows::core::GUID` struct stores them as native-endian integers,
/// so the conversion is a `from_be_bytes` triple.
pub(super) const fn guid_from_bytes(b: &[u8; 16]) -> GUID {
    GUID {
        data1: u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
        data2: u16::from_be_bytes([b[4], b[5]]),
        data3: u16::from_be_bytes([b[6], b[7]]),
        data4: [b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]],
    }
}

/// Add our sub-layer to the engine if it isn't already present.
///
/// Idempotent — `FWP_E_ALREADY_EXISTS` is treated as success. Any
/// other Win32 error is propagated as [`PlatformError::Win32`].
///
/// Must be called inside the same WFP transaction as the subsequent
/// [`super::wfp_filter::add_filter`] calls. The production apply path
/// invokes it from `WindowsApiPort::wfp_filter_add` so callers never
/// need to think about ordering.
pub fn ensure_sublayer(token: &WfpEngineToken) -> Result<(), PlatformError> {
    let handle = token_to_handle(token);

    // UTF-16 NUL-terminated display strings. The `FWPM_SUBLAYER0`
    // struct holds raw PWSTR pointers; the backing buffers must
    // outlive the `FwpmSubLayerAdd0` call.
    let mut name_w: Vec<u16> = WFP_SUBLAYER_NAME.encode_utf16().chain([0]).collect();
    let mut desc_w: Vec<u16> = WFP_SUBLAYER_DESCRIPTION.encode_utf16().chain([0]).collect();

    // SAFETY: `FWPM_SUBLAYER0` is `repr(C)` with no enum discriminants
    // that exclude the all-zero pattern. The Win32 documentation
    // explicitly recommends `ZeroMemory` followed by setting required
    // fields — that is exactly what `MaybeUninit::zeroed` does.
    let mut sub: FWPM_SUBLAYER0 = unsafe { MaybeUninit::zeroed().assume_init() };
    sub.subLayerKey = NRR_SUBLAYER_GUID;
    sub.displayData = FWPM_DISPLAY_DATA0 {
        name: PWSTR(name_w.as_mut_ptr()),
        description: PWSTR(desc_w.as_mut_ptr()),
    };
    // Non-persistent sub-layer: bound to the engine session lifetime.
    // Mirrors the per-apply WFP session strategy documented in
    // `crate::constants`.
    sub.flags = 0;
    sub.providerKey = std::ptr::null_mut();
    sub.weight = (WFP_SUBLAYER_WEIGHT & 0xFFFF) as u16;
    // `providerData` left zeroed (no payload).

    // SAFETY: `handle` is valid for the lifetime of `token`. `sub`
    // lives on this stack frame; its PWSTR fields point into
    // `name_w`/`desc_w` Vecs that also live for the duration of the
    // call. `PSECURITY_DESCRIPTOR::default()` is the documented
    // "use default security descriptor" sentinel.
    let code = unsafe { FwpmSubLayerAdd0(handle, &sub, PSECURITY_DESCRIPTOR::default()) };
    if code == 0 || code == FWP_E_ALREADY_EXISTS {
        return Ok(());
    }
    Err(PlatformError::Win32 {
        operation: ADD_OP,
        code,
        message: format!("Win32 error 0x{code:08X}"),
    })
}

#[cfg(test)]
mod tests {
    use super::super::wfp_engine::{engine_close, engine_open};
    use super::*;

    /// The `[u8; 16]` packed form in `constants.rs` and the
    /// windows-rs [`GUID`] struct must agree on byte layout.
    #[test]
    fn sublayer_guid_matches_constants_byte_array() {
        let packed = WFP_SUBLAYER_GUID;
        let g = NRR_SUBLAYER_GUID;
        assert_eq!(
            g.data1.to_be_bytes(),
            [packed[0], packed[1], packed[2], packed[3]]
        );
        assert_eq!(g.data2.to_be_bytes(), [packed[4], packed[5]]);
        assert_eq!(g.data3.to_be_bytes(), [packed[6], packed[7]]);
        assert_eq!(g.data4, packed[8..16]);
    }

    #[test]
    fn provider_guid_matches_constants_byte_array() {
        let packed = WFP_PROVIDER_GUID;
        let g = NRR_PROVIDER_GUID;
        assert_eq!(
            g.data1.to_be_bytes(),
            [packed[0], packed[1], packed[2], packed[3]]
        );
        assert_eq!(g.data2.to_be_bytes(), [packed[4], packed[5]]);
        assert_eq!(g.data3.to_be_bytes(), [packed[6], packed[7]]);
        assert_eq!(g.data4, packed[8..16]);
    }

    /// Smoke test: idempotent add-or-already-exists on a real Windows
    /// host. **Requires administrator privileges** — `FwpmSubLayerAdd0`
    /// returns `ERROR_ACCESS_DENIED` (5) for non-elevated callers.
    ///
    /// Run on demand from an elevated shell:
    /// `cargo test -p nrr-platform-windows -- --ignored`.
    #[test]
    #[ignore = "requires admin: FwpmSubLayerAdd0 returns ERROR_ACCESS_DENIED for non-elevated processes"]
    fn ensure_sublayer_is_idempotent_on_windows() {
        let token = engine_open().expect("FwpmEngineOpen0 must succeed");
        ensure_sublayer(&token).expect("first ensure_sublayer must succeed");
        ensure_sublayer(&token).expect("second ensure_sublayer must also succeed");
        engine_close(token).expect("FwpmEngineClose0 must succeed");
    }
}
