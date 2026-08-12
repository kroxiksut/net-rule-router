//! WFP filter add/delete/enumerate
//! (`FwpmFilterAdd0`, `FwpmFilterDeleteByKey0`,
//! `FwpmFilterCreateEnumHandle0` + `FwpmFilterEnum0` +
//! `FwpmFilterDestroyEnumHandle0`).
//!
//! This is the elevated, transactional surface of the WFP FFI — the
//! point where a [`WfpFilterSpec`] becomes an actual kernel-side filter
//! that classifies connections at the
//! [`FWPM_LAYER_ALE_AUTH_CONNECT_V4`] layer.
//!
//! ## Filter identity (`WfpFilterId` ↔ `GUID`)
//!
//! Win32 keys filters by `filterKey: GUID`. We need a stable, two-way
//! mapping between our `u64` [`WfpFilterId::raw`] and a 128-bit GUID
//! so that enumeration can recover the original id without consulting
//! storage.
//!
//! Layout:
//! ```text
//! data1 = NRR_FILTER_KEY_DATA1   (u32, fixed signature)
//! data2 = NRR_FILTER_KEY_DATA2   (u16, fixed signature)
//! data3 = NRR_FILTER_KEY_DATA3   (u16, fixed signature)
//! data4 = WfpFilterId.raw.to_be_bytes() — 8 bytes, unique per filter
//! ```
//!
//! The fixed 64-bit signature (data1/2/3) is the "namespace marker" the
//! enumeration path matches against to filter out kernel objects that
//! aren't ours. The 64 bits of `data4` give 2^64 distinct filter ids,
//! more than enough for any practical apply plan.
//!
//! ## Conditions
//!
//! Up to six conditions are emitted per filter, matching the optional
//! fields on [`WfpFilterSpec`]:
//!
//! | Field | Filter key | Data type | Match semantics |
//! |-------|-----------|-----------|-----------------|
//! | `remote_ip` | `FWPM_CONDITION_IP_REMOTE_ADDRESS` | `FWP_UINT32` (host order) | exact IPv4 |
//! | `remote_subnet` | `FWPM_CONDITION_IP_REMOTE_ADDRESS` | `FWP_V4_ADDR_MASK` (addr+mask, by pointer) | IPv4 subnet — catch-all kill-switch |
//! | `remote_port` | `FWPM_CONDITION_IP_REMOTE_PORT` | `FWP_UINT16` | exact port |
//! | `app_pattern` | `FWPM_CONDITION_ALE_APP_ID` | `FWP_BYTE_BLOB_TYPE` | NT-format app path blob |
//! | `user_sid` | `FWPM_CONDITION_ALE_USER_ID` | `FWP_SECURITY_DESCRIPTOR_TYPE` | SD whose DACL grants Custom Control to the SID |
//! | `local_interface_luid` | `FWPM_CONDITION_IP_LOCAL_INTERFACE` | `FWP_UINT64` (LUID, by pointer) | exact egress interface — kill-switch |
//!
//! ⚠ The remote-address key MUST be the layer-agnostic
//! `FWPM_CONDITION_IP_REMOTE_ADDRESS` (the layer determines the address
//! width). The `..._V4`/`..._V6`-suffixed GUIDs belong to the IKE/IPsec
//! layers only — at ALE/IPPACKET layers `FwpmFilterAdd0` rejects them with
//! `FWP_E_CONDITION_NOT_FOUND` (0x80320002), which the best-effort apply then
//! silently records as a per-filter skip. Net effect: every filter carrying
//! a remote IP/subnet condition (rule permits, per-dest fail-closed blocks,
//! catch-all exemptions) would be silently dropped if this were regressed.
//!
//! ## Memory ownership during `FwpmFilterAdd0`
//!
//! `FWPM_FILTER0` and its sub-pointers must all stay valid for the
//! duration of the `FwpmFilterAdd0` call. Win32 copies whatever it
//! needs before returning; we free our side immediately after.
//!
//! The pieces are:
//! - **Display strings** (PWSTR pointers in `FWPM_DISPLAY_DATA0`) →
//!   backed by `Vec<u16>` that live for the call.
//! - **Weight** (`FWP_VALUE0.Anonymous.uint64 = *mut u64`) → backed by
//!   a local `u64` on the same stack frame.
//! - **Conditions array** (`*mut FWPM_FILTER_CONDITION0`) → backed by
//!   a local `Vec<FWPM_FILTER_CONDITION0>`.
//! - **app_id blob** (`FWP_BYTE_BLOB { data, size }`) → `data` points
//!   into a local `Vec<u8>` produced by [`super::app_id::app_id_from_path`].
//! - **user_sid SD blob** → produced by
//!   `ConvertStringSecurityDescriptorToSecurityDescriptorW`; Win32
//!   allocates the SD via `LocalAlloc` and we must release it with
//!   `LocalFree` *after* `FwpmFilterAdd0` returns (success or failure).
//!
//! ## Enumeration
//!
//! [`enumerate_our_filters`] walks every filter in the
//! `FWPM_LAYER_ALE_AUTH_CONNECT_V4` layer and keeps only those whose
//! `filterKey` matches the [namespace signature](NRR_FILTER_KEY_DATA1).
//! Filters added by Windows itself or by other products are skipped.
//!
//! Live WFP records carry [`WfpFilterRecord::app_pattern`] and
//! [`WfpFilterRecord::user_sid`] as `None` — the kernel does not retain
//! the user-facing path or the original string SID. Callers cross-
//! reference against `nrr-storage` persisted state if they need those
//! fields back.

#![allow(unsafe_code)]

use std::ffi::c_void;
use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, Ipv6Addr};

use windows::core::{GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::{LocalFree, HANDLE, HLOCAL};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmFilterAdd0, FwpmFilterCreateEnumHandle0, FwpmFilterDeleteByKey0,
    FwpmFilterDestroyEnumHandle0, FwpmFilterEnum0, FwpmFreeMemory0, FWPM_ACTION0,
    FWPM_CONDITION_ALE_APP_ID, FWPM_CONDITION_ALE_USER_ID, FWPM_CONDITION_IP_LOCAL_INTERFACE,
    FWPM_CONDITION_IP_PROTOCOL, FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_CONDITION_IP_REMOTE_PORT,
    FWPM_DISPLAY_DATA0, FWPM_FILTER0, FWPM_FILTER_CONDITION0, FWPM_FILTER_ENUM_TEMPLATE0,
    FWPM_FILTER_FLAGS, FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT, FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_LAYER_OUTBOUND_IPPACKET_V4,
    FWPM_LAYER_OUTBOUND_IPPACKET_V6, FWPM_LAYER_OUTBOUND_TRANSPORT_V4, FWP_ACTION_BLOCK,
    FWP_ACTION_PERMIT, FWP_BYTE_BLOB, FWP_BYTE_BLOB_TYPE, FWP_CONDITION_VALUE0,
    FWP_CONDITION_VALUE0_0, FWP_FILTER_ENUM_TYPE, FWP_MATCH_EQUAL, FWP_SECURITY_DESCRIPTOR_TYPE,
    FWP_UINT16, FWP_UINT32, FWP_UINT64, FWP_UINT8, FWP_V4_ADDR_AND_MASK, FWP_V4_ADDR_MASK,
    FWP_V6_ADDR_AND_MASK, FWP_V6_ADDR_MASK, FWP_VALUE0, FWP_VALUE0_0,
};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::PSECURITY_DESCRIPTOR;

use crate::error::PlatformError;
use crate::types::{
    WfpAction, WfpEngineToken, WfpFilterId, WfpFilterRecord, WfpFilterSpec, WfpLayerKey,
};

use super::wfp_engine::token_to_handle;
use super::wfp_sublayer::{ensure_sublayer, NRR_SUBLAYER_GUID};

const ADD_OP: &str = "FwpmFilterAdd0";
const DELETE_OP: &str = "FwpmFilterDeleteByKey0";
const ENUM_CREATE_OP: &str = "FwpmFilterCreateEnumHandle0";
const ENUM_OP: &str = "FwpmFilterEnum0";
const SDDL_OP: &str = "ConvertStringSecurityDescriptorToSecurityDescriptorW";

/// Namespace signature `data1` — the high 4 bytes of every filterKey
/// GUID we emit. ASCII `"NRRF"` (NetRuleRouter Filter); the enumeration
/// path matches on the full 64-bit (data1, data2, data3) triple to
/// recognise our filters.
const NRR_FILTER_KEY_DATA1: u32 = 0x4E52_5246;
const NRR_FILTER_KEY_DATA2: u16 = 0x0001;
const NRR_FILTER_KEY_DATA3: u16 = 0x4E52;

/// `FwpmFilterEnum0` page size. The Win32 documentation suggests
/// callers tune this to balance memory pressure against the cost of
/// `FwpmFreeMemory0` round-trips. 64 entries per page is a typical
/// compromise — well below the 500-filter transaction cap and small
/// enough to keep peak buffer use modest.
const ENUM_PAGE_SIZE: u32 = 64;

/// `FWP_E_FILTER_NOT_FOUND` (0x80320003). Surfaces from
/// [`FwpmFilterDeleteByKey0`] when a caller tries to delete a filter
/// that was never installed (or was deleted between the apply layer's
/// snapshot and the executing transaction). We surface it as a normal
/// [`PlatformError::Win32`] with this constant in the `code` field; the
/// apply layer recognises it (via `error::classify_win32_error` →
/// `ErrorClass::Idempotent`) and treats "already absent" as a terminal-
/// success state for the delete intent.
///
/// Re-exported from the [`win32_codes`](crate::error::win32_codes) SSOT
/// table. A wrong local value (e.g. `0x80320026`, a different FWP code)
/// would let a delete-of-absent abort slip through the idempotency check —
/// same bug class as the `FWP_E_ALREADY_EXISTS` phantom-filter root cause:
/// never re-declare Win32 codes locally.
pub use crate::error::win32_codes::FWP_E_FILTER_NOT_FOUND;

// ── ID ↔ GUID mapping ────────────────────────────────────────────────────────

/// Map a [`WfpFilterId`] to its stable [`GUID`].
///
/// This is purely deterministic: the same `id` always yields the same
/// GUID, both within a single process and across service restarts.
pub fn filter_id_to_guid(id: WfpFilterId) -> GUID {
    GUID {
        data1: NRR_FILTER_KEY_DATA1,
        data2: NRR_FILTER_KEY_DATA2,
        data3: NRR_FILTER_KEY_DATA3,
        data4: id.raw.to_be_bytes(),
    }
}

/// Inverse of [`filter_id_to_guid`]. Returns `Some(id)` when `guid`
/// carries the namespace signature, `None` otherwise (filter belongs
/// to another product or to the kernel itself).
pub fn filter_id_from_guid(guid: &GUID) -> Option<WfpFilterId> {
    if guid.data1 != NRR_FILTER_KEY_DATA1
        || guid.data2 != NRR_FILTER_KEY_DATA2
        || guid.data3 != NRR_FILTER_KEY_DATA3
    {
        return None;
    }
    Some(WfpFilterId {
        raw: u64::from_be_bytes(guid.data4),
    })
}

// ── Public surface ────────────────────────────────────────────────────────────

/// Add a WFP filter inside the current transaction.
///
/// Side-effect: idempotently ensures the NetRuleRouter sub-layer is
/// present in the engine. Callers don't need to register the sub-layer
/// separately.
///
/// Returns the same [`WfpFilterId`] the caller passed in `spec.id` —
/// the FFI does not surface Win32's runtime `filterId: u64` (which is
/// engine-session-local and not stable across restarts).
pub fn add_filter(
    token: &WfpEngineToken,
    spec: &WfpFilterSpec,
) -> Result<WfpFilterId, PlatformError> {
    // --- 1. Read-only input validation BEFORE any privileged Win32
    // call. `app_id_from_path` and `sddl_for_sid` need only process-
    // local privileges; running them first means callers see
    // structural errors ("file not found", "malformed SID") even on
    // hosts where the subsequent `FwpmSubLayerAdd0` / `FwpmFilterAdd0`
    // would reject for `ERROR_ACCESS_DENIED`.
    let app_id_bytes: Option<Vec<u8>> = match &spec.app_pattern {
        Some(path) => Some(super::app_id::app_id_from_path(std::path::Path::new(path))?),
        None => None,
    };
    // `sd_handle` is Win32-allocated; we must free it with LocalFree
    // before returning, on every path including early errors.
    let mut sd_handle: PSECURITY_DESCRIPTOR = PSECURITY_DESCRIPTOR::default();
    let mut sd_size: u32 = 0;
    if let Some(sid) = &spec.user_sid {
        let (h, size) = sddl_for_sid(sid)?;
        sd_handle = h;
        sd_size = size;
    }

    // --- 2. Privileged step: idempotently ensure the sub-layer. -----
    if let Err(e) = ensure_sublayer(token) {
        free_sd_if_owned(sd_handle);
        return Err(e);
    }
    let handle = token_to_handle(token);

    // --- 3. Display strings (PWSTR-backed UTF-16). -------------------
    let display_name = format!("NetRuleRouter:filter:{:016x}", spec.id.raw);
    let display_desc = format!("NetRuleRouter WFP filter (action={:?})", spec.action);
    let mut name_w: Vec<u16> = display_name.encode_utf16().chain([0]).collect();
    let mut desc_w: Vec<u16> = display_desc.encode_utf16().chain([0]).collect();

    // --- 4. Weight pointer (FWP_UINT64 carries `*mut u64`). ----------
    let mut weight_value: u64 = spec.weight;

    // Egress-interface LUID backing (kill-switch).
    // Like `weight`, the `FWP_UINT64` condition value is a *pointer* to
    // a `u64`, so the backing variable must outlive the FwpmFilterAdd0
    // call. Kept on this stack frame; the condition (if any) borrows it.
    let mut local_iface_value: u64 = spec.local_interface_luid.unwrap_or(0);

    // Remote-subnet backing (catch-all kill-switch). The
    // `FWP_V4_ADDR_MASK` condition value is a *pointer* to an
    // `FWP_V4_ADDR_AND_MASK { addr, mask }` (both host byte order), so the
    // struct must outlive the FwpmFilterAdd0 call.
    let mut subnet_value: FWP_V4_ADDR_AND_MASK = match spec.remote_subnet {
        Some((net, prefix_len)) => FWP_V4_ADDR_AND_MASK {
            addr: u32::from(net),
            mask: prefix_to_mask(prefix_len),
        },
        None => FWP_V4_ADDR_AND_MASK { addr: 0, mask: 0 },
    };

    // IPv6 remote-subnet backing (catch-all kill-switch — Free's only IPv6
    // handling). The `FWP_V6_ADDR_MASK` condition value is a *pointer* to an
    // `FWP_V6_ADDR_AND_MASK { addr: [u8; 16], prefixLength }` (address in
    // network byte order — the raw 16 octets), so the struct must outlive the
    // FwpmFilterAdd0 call. Declared alongside the V4 one, before conditions.
    let mut subnet_value_v6: FWP_V6_ADDR_AND_MASK = match spec.remote_subnet_v6 {
        Some((net, prefix_len)) => FWP_V6_ADDR_AND_MASK {
            addr: net.octets(),
            prefixLength: prefix_len,
        },
        None => FWP_V6_ADDR_AND_MASK {
            addr: [0u8; 16],
            prefixLength: 0,
        },
    };

    // --- 5. Condition sub-buffers. -----------------------------------
    let mut app_id_blob: Option<FWP_BYTE_BLOB> = None;
    if let Some(bytes) = app_id_bytes.as_ref() {
        app_id_blob = Some(FWP_BYTE_BLOB {
            size: bytes.len() as u32,
            data: bytes.as_ptr() as *mut u8,
        });
    }
    let mut sd_blob: Option<FWP_BYTE_BLOB> = None;
    if !sd_handle.0.is_null() {
        sd_blob = Some(FWP_BYTE_BLOB {
            size: sd_size,
            data: sd_handle.0 as *mut u8,
        });
    }

    // --- 4. Conditions array. ----------------------------------------
    // The Vec is the backing storage for `FWPM_FILTER0.filterCondition`.
    // Sub-pointers inside each condition reference variables on this
    // same stack frame; they all outlive the FwpmFilterAdd0 call.
    let mut conditions: Vec<FWPM_FILTER_CONDITION0> = Vec::with_capacity(8);

    if let Some(addr) = spec.remote_ip {
        conditions.push(condition_remote_ip_v4(addr));
    }
    if spec.remote_subnet.is_some() {
        conditions.push(condition_remote_subnet_v4(&mut subnet_value));
    }
    if spec.remote_subnet_v6.is_some() {
        conditions.push(condition_remote_subnet_v6(&mut subnet_value_v6));
    }
    if let Some(port) = spec.remote_port {
        conditions.push(condition_remote_port(port));
    }
    if let Some(blob) = app_id_blob.as_mut() {
        conditions.push(condition_app_id(blob));
    }
    if let Some(blob) = sd_blob.as_mut() {
        conditions.push(condition_user_id(blob));
    }
    if spec.local_interface_luid.is_some() {
        conditions.push(condition_local_interface(&mut local_iface_value));
    }
    if let Some(proto) = spec.ip_protocol {
        conditions.push(condition_ip_protocol(proto));
    }

    // --- 5. Assemble FWPM_FILTER0. -----------------------------------
    let layer_key = match spec.layer {
        WfpLayerKey::AleAuthConnectV4 => FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        WfpLayerKey::OutboundIpPacketV4 => FWPM_LAYER_OUTBOUND_IPPACKET_V4,
        WfpLayerKey::AleAuthConnectV6 => FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        WfpLayerKey::OutboundIpPacketV6 => FWPM_LAYER_OUTBOUND_IPPACKET_V6,
        WfpLayerKey::OutboundTransportV4 => FWPM_LAYER_OUTBOUND_TRANSPORT_V4,
    };
    let action_type = match spec.action {
        WfpAction::Block => FWP_ACTION_BLOCK,
        WfpAction::Permit => FWP_ACTION_PERMIT,
    };

    // SAFETY: `FWPM_FILTER0` is `repr(C)`; zero-init matches the
    // documented Microsoft pattern (`ZeroMemory(&filter, sizeof(...))`
    // before setting required fields). The `Anonymous` union accepts
    // the all-zero pattern as "no rawContext / no providerContextKey".
    let mut filter: FWPM_FILTER0 = unsafe { MaybeUninit::zeroed().assume_init() };
    filter.filterKey = filter_id_to_guid(spec.id);
    filter.displayData = FWPM_DISPLAY_DATA0 {
        name: PWSTR(name_w.as_mut_ptr()),
        description: PWSTR(desc_w.as_mut_ptr()),
    };
    // BLOCK filters are tagged hard (CLEAR_ACTION_RIGHT) so a system
    // soft-permit in a higher/tied sub-layer cannot override our
    // Fail-Closed / kill-switch drops — the standard WFP kill-switch
    // pattern. Our sub-layer sits at the u16 weight ceiling (see
    // `WFP_SUBLAYER_WEIGHT`); the hard-veto flag supplies the authority
    // that weight alone cannot (u16 can never exceed the firewall's
    // 0xFFFF). PERMIT filters stay soft. All filters are non-persistent
    // (bound to the engine session lifetime).
    filter.flags = match spec.action {
        WfpAction::Block => FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT,
        WfpAction::Permit => FWPM_FILTER_FLAGS(0),
    };
    filter.providerKey = std::ptr::null_mut();
    filter.layerKey = layer_key;
    filter.subLayerKey = NRR_SUBLAYER_GUID;
    filter.weight = FWP_VALUE0 {
        r#type: FWP_UINT64,
        Anonymous: FWP_VALUE0_0 {
            uint64: &mut weight_value as *mut u64,
        },
    };
    filter.numFilterConditions = conditions.len() as u32;
    filter.filterCondition = if conditions.is_empty() {
        std::ptr::null_mut()
    } else {
        conditions.as_mut_ptr()
    };
    filter.action = FWPM_ACTION0 {
        r#type: action_type,
        // `Anonymous` union (filterType / calloutKey) left zeroed —
        // BLOCK / PERMIT don't use either.
        ..FWPM_ACTION0::default()
    };
    // `reserved`, `filterId`, `effectiveWeight` left zeroed — output
    // fields the kernel fills in.

    // --- 6. Call FwpmFilterAdd0. -------------------------------------
    // SAFETY: `handle` is a valid open engine handle from
    // `FwpmEngineOpen0`. `filter` is fully populated; every embedded
    // pointer references a buffer owned by this stack frame.
    // `PSECURITY_DESCRIPTOR::default()` is the documented "default SD"
    // sentinel for the API. `None` for the optional runtime-id output
    // means we don't care about the kernel-assigned `u64`.
    let code = unsafe { FwpmFilterAdd0(handle, &filter, PSECURITY_DESCRIPTOR::default(), None) };

    // --- 7. Free SD allocation (if any) regardless of outcome. -------
    if !sd_handle.0.is_null() {
        // SAFETY: `sd_handle.0` was returned by
        // `ConvertStringSecurityDescriptorToSecurityDescriptorW`, which
        // documents LocalAlloc as the allocator and LocalFree as the
        // matching deallocator. The pointer is no longer referenced by
        // anything after FwpmFilterAdd0 returns (Win32 copies what it
        // keeps internally before returning).
        let _ = unsafe { LocalFree(HLOCAL(sd_handle.0)) };
    }

    if code != 0 {
        return Err(PlatformError::Win32 {
            operation: ADD_OP,
            code,
            message: format!("Win32 error 0x{code:08X}"),
        });
    }
    Ok(spec.id)
}

/// Delete a filter previously added under our namespace signature.
///
/// Returns `Ok(())` on success and on `FWP_E_FILTER_NOT_FOUND` is
/// **not** swallowed — the caller (apply layer) decides whether
/// "already absent" is an acceptable terminal state.
pub fn delete_filter(token: &WfpEngineToken, id: WfpFilterId) -> Result<(), PlatformError> {
    let handle = token_to_handle(token);
    let key = filter_id_to_guid(id);
    // SAFETY: `handle` is a valid open engine handle; `&key` is a
    // stack reference whose lifetime exceeds this synchronous call.
    let code = unsafe { FwpmFilterDeleteByKey0(handle, &key) };
    if code == 0 {
        return Ok(());
    }
    Err(PlatformError::Win32 {
        operation: DELETE_OP,
        code,
        message: format!("Win32 error 0x{code:08X}"),
    })
}

/// Enumerate every filter on the `FWPM_LAYER_ALE_AUTH_CONNECT_V4`
/// layer whose `filterKey` matches our namespace signature.
///
/// Filters added by other products or by the system are silently
/// skipped. The returned [`WfpFilterRecord::app_pattern`] and
/// [`WfpFilterRecord::user_sid`] are always `None` — the kernel does
/// not retain the original Win32 path or string SID. Callers cross-
/// reference against persisted state when they need those fields.
pub fn enumerate_our_filters(
    token: &WfpEngineToken,
) -> Result<Vec<WfpFilterRecord>, PlatformError> {
    let handle = token_to_handle(token);
    // Enumerate every layer we ever add filters at. Rule/route filters live
    // at ALE_AUTH_CONNECT_V4; the agnostic per-IP kill-switch pairs live at
    // OUTBOUND_IPPACKET_V4; the protocol-narrowed kill-switch blocks (ICMP/
    // IGMP/GRE/ESP) live at OUTBOUND_TRANSPORT_V4 (the packet layer
    // has no IP_PROTOCOL condition); the IPv6 catch-all kill-switch lives at
    // the two V6 twins. Cleanup, rollback and verify all enumerate through
    // this fn — missing any layer would LEAK that layer's filters across
    // apply cycles.
    let mut out = enumerate_layer(handle, FWPM_LAYER_ALE_AUTH_CONNECT_V4)?;
    out.extend(enumerate_layer(handle, FWPM_LAYER_OUTBOUND_IPPACKET_V4)?);
    out.extend(enumerate_layer(handle, FWPM_LAYER_ALE_AUTH_CONNECT_V6)?);
    out.extend(enumerate_layer(handle, FWPM_LAYER_OUTBOUND_IPPACKET_V6)?);
    out.extend(enumerate_layer(handle, FWPM_LAYER_OUTBOUND_TRANSPORT_V4)?);
    Ok(out)
}

/// Enumerate our filters on a single WFP layer. Inner helper for
/// [`enumerate_our_filters`], which calls it once per layer we use.
fn enumerate_layer(
    handle: HANDLE,
    layer_key: windows::core::GUID,
) -> Result<Vec<WfpFilterRecord>, PlatformError> {
    // Build the enum template: scope to one layer, every action mask,
    // every weight.
    // SAFETY: zero-init is documented sentinel for FWPM_FILTER_ENUM_TEMPLATE0.
    let mut template: FWPM_FILTER_ENUM_TEMPLATE0 = unsafe { MaybeUninit::zeroed().assume_init() };
    template.providerKey = std::ptr::null_mut();
    template.layerKey = layer_key;
    // `FWP_FILTER_ENUM_TYPE(0)` == `FWP_FILTER_ENUM_FULLY_CONTAINED` —
    // covers every filter whose conditions fall under the template.
    template.enumType = FWP_FILTER_ENUM_TYPE(0);
    template.flags = 0;
    template.actionMask = 0xFFFF_FFFF; // any action

    let mut enum_handle = HANDLE::default();
    // SAFETY: `handle` is valid; `template` lives on this stack frame
    // for the duration of the call. `enum_handle` is the output slot.
    let code = unsafe { FwpmFilterCreateEnumHandle0(handle, Some(&template), &mut enum_handle) };
    if code != 0 {
        return Err(PlatformError::Win32 {
            operation: ENUM_CREATE_OP,
            code,
            message: format!("Win32 error 0x{code:08X}"),
        });
    }

    let result = collect_enum_pages(handle, enum_handle);

    // SAFETY: `enum_handle` was returned by
    // `FwpmFilterCreateEnumHandle0`; destroy is the matching teardown.
    // We swallow the result code — destroy failures are advisory only.
    let _ = unsafe { FwpmFilterDestroyEnumHandle0(handle, enum_handle) };

    result
}

/// Inner helper for [`enumerate_our_filters`] — pages through the
/// enum handle until exhausted and projects each row to a
/// `WfpFilterRecord`.
fn collect_enum_pages(
    engine: HANDLE,
    enum_handle: HANDLE,
) -> Result<Vec<WfpFilterRecord>, PlatformError> {
    let mut out: Vec<WfpFilterRecord> = Vec::new();

    loop {
        let mut entries_ptr: *mut *mut FWPM_FILTER0 = std::ptr::null_mut();
        let mut returned: u32 = 0;

        // SAFETY: `enum_handle` is live; Win32 writes a freshly-
        // allocated `*mut *mut FWPM_FILTER0` into `entries_ptr` and
        // the count of returned rows into `returned`.
        let code = unsafe {
            FwpmFilterEnum0(
                engine,
                enum_handle,
                ENUM_PAGE_SIZE,
                &mut entries_ptr,
                &mut returned,
            )
        };
        if code != 0 {
            return Err(PlatformError::Win32 {
                operation: ENUM_OP,
                code,
                message: format!("Win32 error 0x{code:08X}"),
            });
        }
        if returned == 0 || entries_ptr.is_null() {
            // Even an empty page must be freed if non-null.
            if !entries_ptr.is_null() {
                let mut as_void: *mut c_void = entries_ptr.cast();
                // SAFETY: page buffer was Win32-allocated.
                unsafe { FwpmFreeMemory0(&mut as_void) };
            }
            break;
        }

        // SAFETY: `entries_ptr` is non-null and points at an array of
        // `returned` pointers; each pointer references a valid
        // `FWPM_FILTER0` owned by Win32 until `FwpmFreeMemory0`.
        let entries_slice = unsafe { std::slice::from_raw_parts(entries_ptr, returned as usize) };
        for &row_ptr in entries_slice {
            if row_ptr.is_null() {
                continue;
            }
            // SAFETY: row pointer is valid for at least the lifetime
            // of `entries_ptr`'s allocation.
            let row = unsafe { &*row_ptr };
            if let Some(record) = decode_filter_row(row) {
                out.push(record);
            }
        }

        // SAFETY: `entries_ptr` is the Win32 page allocation; free
        // before requesting the next page (or before exiting the loop).
        let mut as_void: *mut c_void = entries_ptr.cast();
        unsafe { FwpmFreeMemory0(&mut as_void) };

        if returned < ENUM_PAGE_SIZE {
            // Partial page → end of enumeration.
            break;
        }
    }

    Ok(out)
}

/// Build an `FWPM_CONDITION_IP_PROTOCOL == proto` condition. The protocol
/// number is an `FWP_UINT8` stored **by value** in the union (unlike the
/// subnet/LUID conditions, which point at stack-frame storage). Used by the
/// multi-protocol kill-switch at the `OUTBOUND_IPPACKET_V4` layer (ICMP=1,
/// IGMP=2, GRE=47, ESP=50) and, where it narrows TCP-vs-UDP, at the ALE layer.
fn condition_ip_protocol(protocol: u8) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_IP_PROTOCOL,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_UINT8,
            Anonymous: FWP_CONDITION_VALUE0_0 { uint8: protocol },
        },
    }
}

/// Project one live `FWPM_FILTER0` into a [`WfpFilterRecord`] when its
/// `filterKey` matches our namespace signature.
fn decode_filter_row(row: &FWPM_FILTER0) -> Option<WfpFilterRecord> {
    let id = filter_id_from_guid(&row.filterKey)?;

    let layer = if row.layerKey == FWPM_LAYER_ALE_AUTH_CONNECT_V4 {
        WfpLayerKey::AleAuthConnectV4
    } else if row.layerKey == FWPM_LAYER_OUTBOUND_IPPACKET_V4 {
        WfpLayerKey::OutboundIpPacketV4
    } else if row.layerKey == FWPM_LAYER_ALE_AUTH_CONNECT_V6 {
        WfpLayerKey::AleAuthConnectV6
    } else if row.layerKey == FWPM_LAYER_OUTBOUND_IPPACKET_V6 {
        WfpLayerKey::OutboundIpPacketV6
    } else if row.layerKey == FWPM_LAYER_OUTBOUND_TRANSPORT_V4 {
        WfpLayerKey::OutboundTransportV4
    } else {
        // Filter on a layer we don't model. Skip rather than fabricate
        // a synthetic layer enum value.
        return None;
    };

    let action = if row.action.r#type == FWP_ACTION_BLOCK {
        WfpAction::Block
    } else if row.action.r#type == FWP_ACTION_PERMIT {
        WfpAction::Permit
    } else {
        return None;
    };

    // Weight: only decode `FWP_UINT64`; everything else collapses to 0.
    let weight = if row.weight.r#type == FWP_UINT64 {
        // SAFETY: `r#type == FWP_UINT64` selects the `uint64: *mut u64`
        // arm; the pointer is Win32-owned and valid while `row` is.
        let p = unsafe { row.weight.Anonymous.uint64 };
        if p.is_null() {
            0
        } else {
            // SAFETY: pointer valid per above.
            unsafe { *p }
        }
    } else {
        0
    };

    // Walk conditions for remote_ip / remote_subnet / remote_port /
    // local-interface LUID. We don't reconstruct app_pattern (no NT-path
    // reversal) or user_sid (skipped — apply layer cross-references storage).
    let decoded = decode_conditions(row);

    Some(WfpFilterRecord {
        id,
        layer,
        action,
        remote_ip: decoded.remote_ip,
        remote_port: decoded.remote_port,
        weight,
        user_sid: None,
        app_pattern: None,
        local_interface_luid: decoded.local_interface_luid,
        remote_subnet: decoded.remote_subnet,
        remote_subnet_v6: decoded.remote_subnet_v6,
        ip_protocol: decoded.ip_protocol,
    })
}

/// Conditions recovered from a live `FWPM_FILTER0` during enumeration.
#[derive(Default)]
struct DecodedConditions {
    remote_ip: Option<Ipv4Addr>,
    remote_port: Option<u16>,
    local_interface_luid: Option<u64>,
    remote_subnet: Option<(Ipv4Addr, u8)>,
    remote_subnet_v6: Option<(Ipv6Addr, u8)>,
    ip_protocol: Option<u8>,
}

fn decode_conditions(row: &FWPM_FILTER0) -> DecodedConditions {
    let mut out = DecodedConditions::default();
    if row.numFilterConditions == 0 || row.filterCondition.is_null() {
        return out;
    }
    // SAFETY: `numFilterConditions` and `filterCondition` are paired;
    // Win32 guarantees `numFilterConditions` valid rows after the base.
    let slice = unsafe {
        std::slice::from_raw_parts(
            row.filterCondition as *const FWPM_FILTER_CONDITION0,
            row.numFilterConditions as usize,
        )
    };
    for cond in slice {
        if cond.fieldKey == FWPM_CONDITION_IP_REMOTE_ADDRESS
            && cond.conditionValue.r#type == FWP_UINT32
        {
            // SAFETY: `r#type == FWP_UINT32` selects the `uint32: u32`
            // arm.
            let host_order = unsafe { cond.conditionValue.Anonymous.uint32 };
            out.remote_ip = Some(Ipv4Addr::from(host_order));
        } else if cond.fieldKey == FWPM_CONDITION_IP_REMOTE_ADDRESS
            && cond.conditionValue.r#type == FWP_V4_ADDR_MASK
        {
            // Same field key as the exact-host arm above, distinguished by
            // value type. SAFETY: `r#type == FWP_V4_ADDR_MASK` selects the
            // `v4AddrMask: *mut FWP_V4_ADDR_AND_MASK` arm; Win32-owned,
            // valid while `row` is.
            let p = unsafe { cond.conditionValue.Anonymous.v4AddrMask };
            if !p.is_null() {
                // SAFETY: pointer valid per above.
                let am = unsafe { *p };
                out.remote_subnet = Some((Ipv4Addr::from(am.addr), mask_to_prefix(am.mask)));
            }
        } else if cond.fieldKey == FWPM_CONDITION_IP_REMOTE_ADDRESS
            && cond.conditionValue.r#type == FWP_V6_ADDR_MASK
        {
            // IPv6 twin of the subnet arm above (catch-all kill-switch). SAFETY:
            // `r#type == FWP_V6_ADDR_MASK` selects the
            // `v6AddrMask: *mut FWP_V6_ADDR_AND_MASK` arm; Win32-owned, valid
            // while `row` is.
            let p = unsafe { cond.conditionValue.Anonymous.v6AddrMask };
            if !p.is_null() {
                // SAFETY: pointer valid per above.
                let am = unsafe { *p };
                out.remote_subnet_v6 = Some((Ipv6Addr::from(am.addr), am.prefixLength));
            }
        } else if cond.fieldKey == FWPM_CONDITION_IP_REMOTE_PORT
            && cond.conditionValue.r#type == FWP_UINT16
        {
            // SAFETY: `r#type == FWP_UINT16` selects the `uint16: u16`
            // arm.
            out.remote_port = Some(unsafe { cond.conditionValue.Anonymous.uint16 });
        } else if cond.fieldKey == FWPM_CONDITION_IP_LOCAL_INTERFACE
            && cond.conditionValue.r#type == FWP_UINT64
        {
            // SAFETY: `r#type == FWP_UINT64` selects the `uint64: *mut u64`
            // arm; the pointer is Win32-owned and valid while `row` is.
            let p = unsafe { cond.conditionValue.Anonymous.uint64 };
            if !p.is_null() {
                // SAFETY: pointer valid per above.
                out.local_interface_luid = Some(unsafe { *p });
            }
        } else if cond.fieldKey == FWPM_CONDITION_IP_PROTOCOL
            && cond.conditionValue.r#type == FWP_UINT8
        {
            // SAFETY: `r#type == FWP_UINT8` selects the `uint8: u8` arm.
            out.ip_protocol = Some(unsafe { cond.conditionValue.Anonymous.uint8 });
        }
    }
    out
}

/// Inverse of [`prefix_to_mask`]: count the leading one-bits of a
/// host-byte-order IPv4 mask. Non-contiguous masks (never emitted by us)
/// fall back to the popcount, which is still a sane prefix length.
fn mask_to_prefix(mask: u32) -> u8 {
    mask.count_ones() as u8
}

// ── Conditions builders ─────────────────────────────────────────────────────

fn condition_remote_ip_v4(addr: Ipv4Addr) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_UINT32,
            // Win32 contract for V4 conditions: host byte order, not network.
            Anonymous: FWP_CONDITION_VALUE0_0 {
                uint32: u32::from(addr),
            },
        },
    }
}

fn condition_remote_port(port: u16) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_IP_REMOTE_PORT,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_UINT16,
            Anonymous: FWP_CONDITION_VALUE0_0 { uint16: port },
        },
    }
}

fn condition_app_id(blob: &mut FWP_BYTE_BLOB) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_ALE_APP_ID,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_BYTE_BLOB_TYPE,
            Anonymous: FWP_CONDITION_VALUE0_0 {
                byteBlob: blob as *mut FWP_BYTE_BLOB,
            },
        },
    }
}

fn condition_user_id(blob: &mut FWP_BYTE_BLOB) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_ALE_USER_ID,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_SECURITY_DESCRIPTOR_TYPE,
            Anonymous: FWP_CONDITION_VALUE0_0 {
                sd: blob as *mut FWP_BYTE_BLOB,
            },
        },
    }
}

/// Match the connection's egress local interface by LUID (kill-switch).
///
/// `FWPM_CONDITION_IP_LOCAL_INTERFACE` is available at the
/// `FWPM_LAYER_ALE_AUTH_CONNECT_V4` layer: at connect time the OS has
/// already done the route lookup, so the local interface the flow would
/// leave on is known. The value type is `FWP_UINT64` — and, exactly
/// like a filter's weight, the union carries a *pointer* to the `u64`,
/// not the value inline. `luid` therefore points at a caller-owned
/// `u64` that must outlive the `FwpmFilterAdd0` call.
fn condition_local_interface(luid: &mut u64) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_IP_LOCAL_INTERFACE,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_UINT64,
            Anonymous: FWP_CONDITION_VALUE0_0 {
                uint64: luid as *mut u64,
            },
        },
    }
}

/// Convert a CIDR prefix length (0–32) to a host-byte-order IPv4 mask.
/// `0 → 0.0.0.0`, `8 → 255.0.0.0`, `32 → 255.255.255.255`. Values above
/// 32 are clamped to a full mask (defensive — the codegen never emits them).
fn prefix_to_mask(prefix_len: u8) -> u32 {
    match prefix_len {
        0 => 0,
        p if p >= 32 => u32::MAX,
        p => u32::MAX << (32 - p),
    }
}

/// Match a remote IPv4 **subnet** (catch-all kill-switch). Same field key as the exact-host condition
/// (`FWPM_CONDITION_IP_REMOTE_ADDRESS`) but an `FWP_V4_ADDR_MASK`
/// value: WFP matches when `(remote & mask) == addr`. The value is a
/// *pointer* to a caller-owned `FWP_V4_ADDR_AND_MASK` that must outlive
/// the `FwpmFilterAdd0` call.
fn condition_remote_subnet_v4(addr_mask: &mut FWP_V4_ADDR_AND_MASK) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_V4_ADDR_MASK,
            Anonymous: FWP_CONDITION_VALUE0_0 {
                v4AddrMask: addr_mask as *mut FWP_V4_ADDR_AND_MASK,
            },
        },
    }
}

/// IPv6 catch-all kill-switch (Free's only IPv6 handling) — match a remote
/// IPv6 **subnet**. The IPv6 twin of [`condition_remote_subnet_v4`], keyed on
/// `FWPM_CONDITION_IP_REMOTE_ADDRESS` with an `FWP_V6_ADDR_MASK` value: WFP
/// matches when the remote address falls in `addr/prefixLength`. The value is a
/// *pointer* to a caller-owned `FWP_V6_ADDR_AND_MASK` that must outlive the
/// `FwpmFilterAdd0` call.
fn condition_remote_subnet_v6(addr_mask: &mut FWP_V6_ADDR_AND_MASK) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_V6_ADDR_MASK,
            Anonymous: FWP_CONDITION_VALUE0_0 {
                v6AddrMask: addr_mask as *mut FWP_V6_ADDR_AND_MASK,
            },
        },
    }
}

// ── SDDL helpers ────────────────────────────────────────────────────────────

/// Release a security-descriptor handle produced by [`sddl_for_sid`].
/// No-op when the handle is null (e.g. when the caller's filter spec
/// had `user_sid = None`).
fn free_sd_if_owned(psd: PSECURITY_DESCRIPTOR) {
    if psd.0.is_null() {
        return;
    }
    // SAFETY: `psd.0` was produced by
    // `ConvertStringSecurityDescriptorToSecurityDescriptorW`, which
    // documents `LocalAlloc` as the allocator and `LocalFree` as the
    // matching deallocator. After this call the pointer is dangling;
    // callers must not reuse it.
    let _ = unsafe { LocalFree(HLOCAL(psd.0)) };
}

/// Convert a string SID like `"S-1-5-21-..."` into a Win32-allocated
/// `PSECURITY_DESCRIPTOR` whose DACL grants `Custom Control` (`CC`) to
/// the SID. Returns the descriptor handle and its byte size; the
/// caller MUST eventually call [`LocalFree`] on the handle.
///
/// The SDDL pattern `"D:(A;;CC;;;<sid>)"` is the canonical form for
/// `FWPM_CONDITION_ALE_USER_ID`: WFP evaluates the DACL against the
/// connection's user token; a matching ACE means "this filter applies".
fn sddl_for_sid(sid: &str) -> Result<(PSECURITY_DESCRIPTOR, u32), PlatformError> {
    // Reject obviously malformed SIDs early so we don't pay the FFI
    // cost on input we can spot is wrong. `ConvertStringSecurityDescriptor…`
    // will catch the rest with `ERROR_INVALID_SID`.
    if !sid.starts_with("S-") {
        return Err(PlatformError::Win32 {
            operation: SDDL_OP,
            code: 0x57, // ERROR_INVALID_PARAMETER
            message: format!("SID does not start with `S-`: {sid:?}"),
        });
    }

    let sddl = format!("D:(A;;CC;;;{sid})");
    let mut sddl_w: Vec<u16> = sddl.encode_utf16().chain([0]).collect();

    let mut psd: PSECURITY_DESCRIPTOR = PSECURITY_DESCRIPTOR::default();
    let mut size: u32 = 0;

    // SAFETY: `sddl_w` is a valid null-terminated UTF-16 string;
    // `PCWSTR` borrows the pointer for the call. `psd`/`size` are
    // output slots Win32 writes on success. On failure both stay
    // unmodified and we don't free anything.
    let r = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl_w.as_mut_ptr()),
            SDDL_REVISION_1,
            &mut psd,
            Some(&mut size),
        )
    };
    if let Err(e) = r {
        return Err(PlatformError::Win32 {
            operation: SDDL_OP,
            code: e.code().0 as u32,
            message: format!("SDDL conversion failed for {sid:?}: {e}"),
        });
    }
    if psd.0.is_null() {
        return Err(PlatformError::Win32 {
            operation: SDDL_OP,
            code: 0,
            message: format!("null SD returned for SID {sid:?}"),
        });
    }
    Ok((psd, size))
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::super::wfp_engine::{engine_close, engine_open};
    use super::super::wfp_transaction::{transaction_abort, transaction_begin, transaction_commit};
    use super::*;
    use crate::types::{WfpAction, WfpLayerKey};

    #[test]
    fn id_to_guid_is_deterministic() {
        let a = filter_id_to_guid(WfpFilterId {
            raw: 0x1234_5678_9ABC_DEF0,
        });
        let b = filter_id_to_guid(WfpFilterId {
            raw: 0x1234_5678_9ABC_DEF0,
        });
        assert_eq!(a, b);
    }

    #[test]
    fn id_guid_roundtrip_preserves_raw() {
        let original = WfpFilterId {
            raw: 0xCAFE_BABE_DEAD_BEEF,
        };
        let g = filter_id_to_guid(original);
        let decoded = filter_id_from_guid(&g).expect("our signature must match");
        assert_eq!(decoded, original);
    }

    #[test]
    fn id_from_guid_rejects_foreign_namespace() {
        // A random GUID that does not carry our (data1, data2, data3)
        // signature must return `None`.
        let foreign = GUID {
            data1: 0xAAAA_BBBB,
            data2: 0xCCCC,
            data3: 0xDDDD,
            data4: [0; 8],
        };
        assert!(filter_id_from_guid(&foreign).is_none());
    }

    #[test]
    fn signature_distinct_from_sublayer_and_provider() {
        // The filter-key signature must not collide with the sub-layer
        // or provider GUID — they're keyed independently in the WFP
        // engine but a collision would still be a smell.
        let g = filter_id_to_guid(WfpFilterId { raw: 0 });
        assert_ne!(g.data1, super::super::wfp_sublayer::NRR_SUBLAYER_GUID.data1);
        assert_ne!(g.data1, super::super::wfp_sublayer::NRR_PROVIDER_GUID.data1);
    }

    /// SDDL produces a non-null, non-empty SD blob for a syntactically
    /// valid SID. We use the well-known "Everyone" SID (`S-1-1-0`) to
    /// avoid taking a dependency on the build agent's local accounts.
    #[test]
    fn sddl_for_well_known_sid_returns_non_empty_blob() {
        let (psd, size) = sddl_for_sid("S-1-1-0").expect("Everyone SID must convert");
        assert!(!psd.0.is_null(), "SD pointer must be non-null on success");
        assert!(size > 0, "SD size must be non-zero on success");
        // SAFETY: psd is Win32-allocated; LocalFree matches LocalAlloc.
        let _ = unsafe { LocalFree(HLOCAL(psd.0)) };
    }

    #[test]
    fn sddl_rejects_obviously_malformed_sid() {
        let err = sddl_for_sid("not-a-sid").expect_err("non-`S-` input must fail");
        match err {
            PlatformError::Win32 { code, .. } => {
                assert_eq!(code, 0x57, "expected ERROR_INVALID_PARAMETER prefilter");
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn prefix_mask_round_trip_for_common_lengths() {
        for (len, mask) in [
            (0u8, 0u32),
            (8, 0xFF00_0000),
            (16, 0xFFFF_0000),
            (24, 0xFFFF_FF00),
            (32, 0xFFFF_FFFF),
        ] {
            assert_eq!(prefix_to_mask(len), mask, "prefix {len} → mask");
            assert_eq!(mask_to_prefix(mask), len, "mask {mask:#010x} → prefix");
        }
        // Clamp: >32 is treated as a full mask.
        assert_eq!(prefix_to_mask(40), u32::MAX);
    }

    /// The remote-subnet condition (catch-all kill-switch)
    /// must carry an `FWP_V4_ADDR_AND_MASK` by pointer, on the same field
    /// key as the exact-host condition but with the mask value type. No
    /// admin needed — only builds the condition struct.
    #[test]
    fn remote_subnet_condition_encodes_addr_and_mask_by_pointer() {
        // 169.254.0.0/16
        let mut am = FWP_V4_ADDR_AND_MASK {
            addr: u32::from(Ipv4Addr::new(169, 254, 0, 0)),
            mask: prefix_to_mask(16),
        };
        let cond = condition_remote_subnet_v4(&mut am);
        assert_eq!(cond.fieldKey, FWPM_CONDITION_IP_REMOTE_ADDRESS);
        assert_eq!(cond.matchType, FWP_MATCH_EQUAL);
        assert_eq!(cond.conditionValue.r#type, FWP_V4_ADDR_MASK);
        // SAFETY: we built this with the FWP_V4_ADDR_MASK arm; pointer
        // references our stack `am`.
        let p = unsafe { cond.conditionValue.Anonymous.v4AddrMask };
        assert!(!p.is_null());
        let read = unsafe { *p };
        assert_eq!(read.addr, u32::from(Ipv4Addr::new(169, 254, 0, 0)));
        assert_eq!(read.mask, 0xFFFF_0000);
    }

    /// The egress-interface condition (kill-switch)
    /// must carry the LUID as a pointer-backed `FWP_UINT64`, mirroring
    /// how a filter's weight is encoded. No admin needed — this only
    /// builds the condition struct, it does not touch the engine.
    #[test]
    fn local_interface_condition_encodes_luid_as_pointer_backed_uint64() {
        let mut luid: u64 = 0x0011_2233_4455_6677;
        let cond = condition_local_interface(&mut luid);
        assert_eq!(cond.fieldKey, FWPM_CONDITION_IP_LOCAL_INTERFACE);
        assert_eq!(cond.matchType, FWP_MATCH_EQUAL);
        assert_eq!(cond.conditionValue.r#type, FWP_UINT64);
        // SAFETY: we just constructed this with the FWP_UINT64 arm; the
        // pointer references our stack `luid`, valid for this scope.
        let p = unsafe { cond.conditionValue.Anonymous.uint64 };
        assert!(!p.is_null(), "uint64 arm must carry a non-null pointer");
        assert_eq!(unsafe { *p }, 0x0011_2233_4455_6677);
    }

    fn sample_spec() -> WfpFilterSpec {
        WfpFilterSpec {
            layer: WfpLayerKey::AleAuthConnectV4,
            action: WfpAction::Block,
            remote_ip: Some(Ipv4Addr::new(203, 0, 113, 17)),
            remote_port: Some(8443),
            weight: 0x0010_0000,
            id: WfpFilterId {
                raw: 0xA5A5_5A5A_F00D_BABE,
            },
            user_sid: None,
            app_pattern: None,
            local_interface_luid: None,
            remote_subnet: None,
            remote_subnet_v6: None,
            ip_protocol: None,
        }
    }

    /// The IPv6 remote-subnet condition (catch-all kill-switch) must carry an
    /// `FWP_V6_ADDR_AND_MASK` by pointer on the `FWPM_CONDITION_IP_REMOTE_ADDRESS`
    /// field with the `FWP_V6_ADDR_MASK` value type. No admin needed — only
    /// builds the condition struct.
    #[test]
    fn remote_subnet_v6_condition_encodes_addr_and_prefix_by_pointer() {
        // fe80::/10
        let net = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0);
        let mut am = FWP_V6_ADDR_AND_MASK {
            addr: net.octets(),
            prefixLength: 10,
        };
        let cond = condition_remote_subnet_v6(&mut am);
        assert_eq!(cond.fieldKey, FWPM_CONDITION_IP_REMOTE_ADDRESS);
        assert_eq!(cond.matchType, FWP_MATCH_EQUAL);
        assert_eq!(cond.conditionValue.r#type, FWP_V6_ADDR_MASK);
        // SAFETY: we built this with the FWP_V6_ADDR_MASK arm; the pointer
        // references our stack `am`.
        let p = unsafe { cond.conditionValue.Anonymous.v6AddrMask };
        assert!(!p.is_null());
        let read = unsafe { *p };
        assert_eq!(Ipv6Addr::from(read.addr), net);
        assert_eq!(read.prefixLength, 10);
    }

    /// Smoke test: add → enumerate → delete round-trip. **Requires
    /// administrator privileges** — `FwpmTransactionBegin0` and
    /// `FwpmFilterAdd0` both demand an elevated token.
    #[test]
    #[ignore = "requires admin: FwpmTransactionBegin0/FwpmFilterAdd0 return ERROR_ACCESS_DENIED for non-elevated processes"]
    fn add_enumerate_delete_round_trip_on_windows() {
        let token = engine_open().expect("FwpmEngineOpen0");
        transaction_begin(&token).expect("FwpmTransactionBegin0");

        let spec = sample_spec();
        let id = add_filter(&token, &spec).expect("add_filter");
        assert_eq!(id, spec.id);

        let listed = enumerate_our_filters(&token).expect("enumerate_our_filters");
        let found = listed.iter().find(|r| r.id == spec.id).cloned();
        assert!(found.is_some(), "filter must appear in enumeration");
        let found = found.unwrap();
        assert_eq!(found.layer, WfpLayerKey::AleAuthConnectV4);
        assert_eq!(found.action, WfpAction::Block);
        assert_eq!(found.remote_ip, spec.remote_ip);
        assert_eq!(found.remote_port, spec.remote_port);
        assert_eq!(found.weight, spec.weight);

        delete_filter(&token, spec.id).expect("delete_filter");
        let listed_after = enumerate_our_filters(&token).expect("enumerate after delete");
        assert!(
            listed_after.iter().all(|r| r.id != spec.id),
            "filter must be gone after delete"
        );

        transaction_commit(&token).expect("FwpmTransactionCommit0");
        engine_close(token).expect("FwpmEngineClose0");
    }

    /// Smoke test: add a filter carrying a `local_interface_luid`
    /// (kill-switch) and assert the LUID round-trips
    /// through enumeration. Requires admin. LUID `1` is the loopback
    /// pseudo-interface on every Windows host, so the value is valid
    /// without depending on the agent's live adapters.
    #[test]
    #[ignore = "requires admin: FwpmFilterAdd0 needs elevation"]
    fn add_filter_with_local_interface_luid_round_trips_on_windows() {
        let token = engine_open().expect("FwpmEngineOpen0");
        transaction_begin(&token).expect("FwpmTransactionBegin0");

        let mut spec = sample_spec();
        spec.id = WfpFilterId {
            raw: 0xA5A5_5A5A_F00D_BAC1,
        };
        spec.local_interface_luid = Some(1);

        let id = add_filter(&token, &spec).expect("add_filter with local_interface_luid");
        assert_eq!(id, spec.id);

        let listed = enumerate_our_filters(&token).expect("enumerate_our_filters");
        let found = listed
            .into_iter()
            .find(|r| r.id == spec.id)
            .expect("filter must appear in enumeration");
        assert_eq!(
            found.local_interface_luid,
            Some(1),
            "egress-interface LUID must round-trip through enumeration"
        );

        delete_filter(&token, spec.id).expect("delete_filter");
        transaction_commit(&token).expect("FwpmTransactionCommit0");
        engine_close(token).expect("FwpmEngineClose0");
    }

    /// Smoke test: add a filter with `app_pattern = kernel32.dll`. The
    /// path must resolve via `FwpmGetAppIdFromFileName0` and the filter
    /// must install cleanly. Requires admin.
    #[test]
    #[ignore = "requires admin: FwpmFilterAdd0 needs elevation"]
    fn add_filter_with_app_pattern_uses_real_blob_on_windows() {
        let token = engine_open().expect("FwpmEngineOpen0");
        transaction_begin(&token).expect("FwpmTransactionBegin0");

        let mut spec = sample_spec();
        spec.id = WfpFilterId {
            raw: 0xA5A5_5A5A_F00D_BABF,
        };
        spec.app_pattern = Some(r"C:\Windows\System32\kernel32.dll".into());

        let res = add_filter(&token, &spec);
        // Roll back either way so we don't leave state behind on test failure paths.
        transaction_abort(&token);
        engine_close(token).expect("FwpmEngineClose0");

        res.expect("add_filter with app_pattern");
    }

    /// Smoke test: add a filter with `user_sid = Everyone` so SDDL
    /// conversion runs end-to-end without depending on a real
    /// per-user SID. Requires admin.
    #[test]
    #[ignore = "requires admin: FwpmFilterAdd0 needs elevation"]
    fn add_filter_with_user_sid_uses_sddl_round_trip_on_windows() {
        let token = engine_open().expect("FwpmEngineOpen0");
        transaction_begin(&token).expect("FwpmTransactionBegin0");

        let mut spec = sample_spec();
        spec.id = WfpFilterId {
            raw: 0xA5A5_5A5A_F00D_BAC0,
        };
        spec.user_sid = Some("S-1-1-0".into()); // Everyone

        let res = add_filter(&token, &spec);
        transaction_abort(&token);
        engine_close(token).expect("FwpmEngineClose0");

        res.expect("add_filter with user_sid");
    }

    /// Path that doesn't exist on disk → `app_id_from_path` returns an
    /// error, which `add_filter` must surface unchanged. No admin needed
    /// because `FwpmGetAppIdFromFileName0` is read-only.
    #[test]
    fn add_filter_with_missing_app_pattern_fails_early_on_windows() {
        let token = engine_open().expect("FwpmEngineOpen0");
        // No transaction — we expect to fail before reaching the
        // privileged code path.
        let mut spec = sample_spec();
        spec.app_pattern = Some(r"C:\NetRuleRouter\does\not\exist\nrr.exe".into());

        let err = add_filter(&token, &spec).expect_err("missing path must fail");
        match err {
            PlatformError::Win32 { code, .. } => {
                assert!(
                    code == 2 || code == 3,
                    "expected ERROR_FILE_NOT_FOUND (2) / ERROR_PATH_NOT_FOUND (3), got {code}"
                );
            }
            other => panic!("unexpected variant: {other:?}"),
        }
        engine_close(token).expect("FwpmEngineClose0");
    }
}
