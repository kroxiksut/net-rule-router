//! Connection observation via WFP `FwpmNetEventSubscribe1` (variant 2).
//!
//! Subscribes to the same WFP engine the apply pipeline drives and receives
//! a [`ConnectionObservation`] for every classified connection — natively
//! carrying the initiating **process image path** (`appId`) and an allow/block
//! **verdict**, neither of which the DNS observer nor a bare ETW-TCPIP trace
//! provides. WFP identifies the flow by image path, not PID, so
//! [`ConnectionObservation::pid`] is `0` here; the process path is the handle.
//!
//! ## How events are generated
//!
//! `FwpmEngineSetOption0(FWPM_ENGINE_COLLECT_NET_EVENTS = 1)` turns on net-event
//! collection; `FWPM_ENGINE_NET_EVENT_MATCH_ANY_KEYWORDS` adds the
//! `CLASSIFY_ALLOW` keyword so *permitted* connections are reported too (drops
//! are reported regardless). The engine then invokes our C-ABI callback on its
//! own worker threads — there is no `ProcessTrace`-style pump to run.
//!
//! **HW-tuning knob (documented risk):** on hosts where the inbox firewall has
//! no permit filter that hard-permits a given flow, `CLASSIFY_ALLOW` events may
//! not fire for it. The fix is to add one low-weight `PERMIT` observe-filter at
//! `ALE_AUTH_CONNECT_V4`/`_V6`; that is deliberately NOT done here so this
//! diagnostic never perturbs the live routing/kill-switch filter set. The
//! `etw_tcpip` backend captures every connect unconditionally as the fallback.
//!
//! All `unsafe` is FFI confined to this file (per the crate's `unsafe` policy);
//! none of it contains business logic.

#![cfg(target_os = "windows")]
#![allow(unsafe_code)]

use std::collections::HashMap;
use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use windows::core::{GUID, PWSTR};
use windows::Win32::Foundation::{LocalFree, HANDLE, HLOCAL};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineClose0, FwpmEngineOpen0, FwpmEngineSetOption0, FwpmFilterGetById0, FwpmFreeMemory0,
    FwpmNetEventSubscribe1, FwpmNetEventUnsubscribe0, FWPM_ENGINE_COLLECT_NET_EVENTS,
    FWPM_ENGINE_NET_EVENT_MATCH_ANY_KEYWORDS, FWPM_FILTER0, FWPM_NET_EVENT2,
    FWPM_NET_EVENT_KEYWORD_CLASSIFY_ALLOW, FWPM_NET_EVENT_SUBSCRIPTION0,
    FWPM_NET_EVENT_TYPE_CLASSIFY_ALLOW, FWPM_NET_EVENT_TYPE_CLASSIFY_DROP, FWP_IP_VERSION_V4,
    FWP_IP_VERSION_V6, FWP_UINT32, FWP_VALUE0, FWP_VALUE0_0,
};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::PSID;
use windows::Win32::System::Rpc::RPC_C_AUTHN_WINNT;

use super::{
    ConnectionObservation, ConnectionObservationSource, ConnectionProgress, ConnectionVerdict,
    TransportProtocol,
};
use crate::error::PlatformError;
use crate::win32_ffi::wfp_sublayer::{NRR_PROVIDER_GUID, NRR_SUBLAYER_GUID};

/// Hard cap on buffered observations between drains — a connection storm
/// cannot grow the buffer without bound (the consumer drains every few s).
const BUFFER_CAP: usize = 8192;

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

type Buffer = Arc<Mutex<Vec<ConnectionObservation>>>;

/// A running WFP net-event subscription. Events arrive on WFP's own threads
/// into [`Self`]'s buffer; [`ConnectionObservationSource::drain`] empties it.
pub struct WfpConnectionObserver {
    buffer: Buffer,
    engine_raw: u64,
    events_raw: u64,
    /// Leaked `Arc<Mutex<…>>` ref handed to the callback; reclaimed on drop.
    ctx: *mut c_void,
    /// Cache of `filter id → (is-an-NRR-filter, decoded NRR spec id)`, resolved
    /// via `FwpmFilterGetById0` in `drain`. One filter drops many connections,
    /// so attribution is a handful of lookups, not one per row. The spec id is
    /// `None` when the filter is foreign or its `filterKey` does not carry our
    /// namespace signature.
    attribution_cache: Mutex<HashMap<u64, (bool, Option<u64>)>>,
}

// The raw handles are owned solely by this struct (closed once, on drop); the
// callback only touches the `Buffer` behind its mutex via `ctx`.
unsafe impl Send for WfpConnectionObserver {}
unsafe impl Sync for WfpConnectionObserver {}

impl ConnectionObservationSource for WfpConnectionObserver {
    fn drain(&self) -> Vec<ConnectionObservation> {
        let mut out = match self.buffer.lock() {
            Ok(mut g) => std::mem::take(&mut *g),
            Err(_) => Vec::new(),
        };
        // Attribute each DROP to NetRuleRouter vs a foreign WFP filter here, off
        // the WFP callback thread — so the trace can say "blocked by another
        // component" and never blame NRR for a firewall / antivirus drop.
        let engine = HANDLE(self.engine_raw as usize as *mut c_void);
        for obs in out.iter_mut() {
            if obs.verdict == ConnectionVerdict::Block {
                if let Some(fid) = obs.drop_filter_id {
                    let owner = self.resolve_owner(engine, fid);
                    obs.blocked_by_nrr = owner.map(|(is_ours, _)| is_ours);
                    obs.nrr_drop_spec_id = owner.and_then(|(_, spec_id)| spec_id);
                }
            }
        }
        out
    }
}

impl WfpConnectionObserver {
    /// Open a WFP engine, enable net-event collection (drops + allows), and
    /// subscribe. Returns an error (and leaves nothing running) on any setup
    /// failure — the caller degrades to no connection observation.
    pub fn start() -> Result<Self, PlatformError> {
        let buffer: Buffer = Arc::new(Mutex::new(Vec::new()));

        // ── Open a dedicated engine session for the subscription lifetime. ──
        let mut engine = HANDLE::default();
        // SAFETY: `FwpmEngineOpen0` writes a valid HANDLE on success; null
        // servername selects the local machine, `RPC_C_AUTHN_WINNT` is the
        // documented auth mode, `None` selects default auth identity/session.
        let code = unsafe {
            FwpmEngineOpen0(
                windows::core::PCWSTR(std::ptr::null()),
                RPC_C_AUTHN_WINNT,
                None,
                None,
                &mut engine,
            )
        };
        if code != 0 {
            return Err(PlatformError::Win32 {
                operation: "FwpmEngineOpen0(conn-observe)",
                code,
                message: format!("Win32 error 0x{code:08X}"),
            });
        }

        // ── Enable net-event collection + ask for CLASSIFY_ALLOW events. ──
        // SAFETY: each call passes a stack `FWP_VALUE0` (UINT32) by const ptr,
        // valid for the call; `engine` is the just-opened handle.
        let opt1 = unsafe { set_uint32_option(engine, FWPM_ENGINE_COLLECT_NET_EVENTS, 1) };
        let opt2 = unsafe {
            set_uint32_option(
                engine,
                FWPM_ENGINE_NET_EVENT_MATCH_ANY_KEYWORDS,
                FWPM_NET_EVENT_KEYWORD_CLASSIFY_ALLOW,
            )
        };
        if opt1 != 0 || opt2 != 0 {
            // SAFETY: `engine` is open and consumed by this close.
            unsafe {
                let _ = FwpmEngineClose0(engine);
            }
            let code = if opt1 != 0 { opt1 } else { opt2 };
            return Err(PlatformError::Win32 {
                operation: "FwpmEngineSetOption0(collect-net-events)",
                code,
                message: format!("Win32 error 0x{code:08X}"),
            });
        }

        // Hand the callback a stable raw pointer to the buffer. One Arc ref is
        // leaked for the subscription's lifetime and reclaimed on drop.
        let ctx = Arc::into_raw(Arc::clone(&buffer)) as *mut c_void;

        let subscription = FWPM_NET_EVENT_SUBSCRIPTION0 {
            enumTemplate: std::ptr::null_mut(),
            flags: 0,
            sessionKey: GUID::zeroed(),
        };
        let mut events_handle = HANDLE::default();
        // SAFETY: `engine` is open; `subscription` is a valid stack struct
        // valid for the call; the callback is a static C-ABI fn; `ctx` is a
        // live leaked Arc ref kept valid until drop.
        let sub = unsafe {
            FwpmNetEventSubscribe1(
                engine,
                &subscription,
                Some(net_event_callback),
                Some(ctx as *const c_void),
                &mut events_handle,
            )
        };
        if sub != 0 {
            // SAFETY: reclaim the leaked Arc ref and close the engine; nothing
            // else holds either.
            unsafe {
                drop(Arc::from_raw(
                    ctx as *const Mutex<Vec<ConnectionObservation>>,
                ));
                let _ = FwpmEngineClose0(engine);
            }
            return Err(PlatformError::Win32 {
                operation: "FwpmNetEventSubscribe1",
                code: sub,
                message: format!("Win32 error 0x{sub:08X}"),
            });
        }

        tracing::info!(
            target: "nrr::conn-observe",
            "WFP net-event connection observer started",
        );
        Ok(Self {
            buffer,
            engine_raw: engine.0 as usize as u64,
            events_raw: events_handle.0 as usize as u64,
            ctx,
            attribution_cache: Mutex::new(HashMap::new()),
        })
    }

    /// Resolve whether WFP filter `fid` belongs to NetRuleRouter, and — when it
    /// does — its decoded NRR codegen spec id. Ownership test:
    /// `subLayerKey == NRR_SUBLAYER_GUID` — every filter we add (rule
    /// permits, kill-switch pins, fail-closed blocks, DoH lockdown) is created
    /// in our sub-layer, while `providerKey` is left null (no BFE provider
    /// object is registered); comparing the null `providerKey` against
    /// [`NRR_PROVIDER_GUID`] alone would misclassify every one of our own
    /// drops as `foreign`, so the provider comparison is kept only as a
    /// forward-compatible fallback. The spec id comes from `filterKey` via
    /// [`filter_id_from_guid`] — `None` when the guid does not carry our
    /// namespace signature (a foreign filter, or one predating the
    /// id-encoding scheme). Cached. Returns `None` when the lookup fails — so
    /// a drop is NEVER falsely attributed to NetRuleRouter. Runs on the
    /// consumer's drain thread, not the WFP callback thread.
    fn resolve_owner(&self, engine: HANDLE, fid: u64) -> Option<(bool, Option<u64>)> {
        if let Ok(cache) = self.attribution_cache.lock() {
            if let Some(v) = cache.get(&fid) {
                return Some(*v);
            }
        }
        let mut filter_ptr: *mut FWPM_FILTER0 = std::ptr::null_mut();
        // SAFETY: `engine` is an open WFP management handle; on success
        // `FwpmFilterGetById0` writes a heap `FWPM_FILTER0` pointer we free below.
        let code = unsafe { FwpmFilterGetById0(engine, fid, &mut filter_ptr) };
        if code != 0 || filter_ptr.is_null() {
            return None;
        }
        // SAFETY: on success `filter_ptr` is a valid `FWPM_FILTER0`; `providerKey`
        // is either null or points to a `GUID` valid for this allocation;
        // `subLayerKey` and `filterKey` are stored by value.
        let (is_ours, filter_key) = unsafe {
            let pk = (*filter_ptr).providerKey;
            let is_ours = (*filter_ptr).subLayerKey == NRR_SUBLAYER_GUID
                || (!pk.is_null() && *pk == NRR_PROVIDER_GUID);
            (is_ours, (*filter_ptr).filterKey)
        };
        // SAFETY: free the buffer WFP allocated; we do not touch `filter_ptr` after.
        unsafe {
            FwpmFreeMemory0(&mut (filter_ptr as *mut c_void));
        }
        let spec_id = crate::win32_ffi::wfp_filter::filter_id_from_guid(&filter_key)
            .map(|id| id.raw)
            .filter(|_| is_ours);
        let result = (is_ours, spec_id);
        if let Ok(mut cache) = self.attribution_cache.lock() {
            cache.insert(fid, result);
        }
        Some(result)
    }
}

impl Drop for WfpConnectionObserver {
    fn drop(&mut self) {
        let engine = HANDLE(self.engine_raw as usize as *mut c_void);
        let events = HANDLE(self.events_raw as usize as *mut c_void);
        // SAFETY: both handles came from successful opens in `start`; we
        // unsubscribe before closing the engine, then reclaim the leaked Arc.
        unsafe {
            let _ = FwpmNetEventUnsubscribe0(engine, events);
            let _ = FwpmEngineClose0(engine);
            drop(Arc::from_raw(
                self.ctx as *const Mutex<Vec<ConnectionObservation>>,
            ));
        }
    }
}

/// Build a `FWP_VALUE0` holding a UINT32 and set it as an engine option.
///
/// # Safety
/// `engine` must be an open WFP engine handle.
unsafe fn set_uint32_option(
    engine: HANDLE,
    option: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_ENGINE_OPTION,
    value: u32,
) -> u32 {
    let v = FWP_VALUE0 {
        r#type: FWP_UINT32,
        Anonymous: FWP_VALUE0_0 { uint32: value },
    };
    FwpmEngineSetOption0(engine, option, &v)
}

/// C-ABI WFP net-event callback. Maps a classified connection (IPv4 or IPv6)
/// into a [`ConnectionObservation`] and buffers it. v6 connections are
/// captured for leak visibility — NRR routes none of them in Free, so their
/// egress resolves as unknown downstream (the v6-leak signal).
unsafe extern "system" fn net_event_callback(context: *mut c_void, event: *const FWPM_NET_EVENT2) {
    if context.is_null() || event.is_null() {
        return;
    }
    let ev = &*event;
    let h = &ev.header;

    let protocol = match h.ipProtocol {
        IPPROTO_TCP => TransportProtocol::Tcp,
        IPPROTO_UDP => TransportProtocol::Udp,
        other => TransportProtocol::Other(other),
    };

    // Addresses by family. WFP stores v4 as a host-order u32 (`Ipv4Addr::from`
    // reads the high byte as the first octet); v6 as a 16-byte array in order.
    let (local_ip, remote_ip): (IpAddr, IpAddr) = if h.ipVersion == FWP_IP_VERSION_V4 {
        (
            IpAddr::V4(Ipv4Addr::from(h.Anonymous1.localAddrV4)),
            IpAddr::V4(Ipv4Addr::from(h.Anonymous2.remoteAddrV4)),
        )
    } else if h.ipVersion == FWP_IP_VERSION_V6 {
        (
            IpAddr::V6(Ipv6Addr::from(h.Anonymous1.localAddrV6.byteArray16)),
            IpAddr::V6(Ipv6Addr::from(h.Anonymous2.remoteAddrV6.byteArray16)),
        )
    } else {
        return;
    };
    let local = SocketAddr::new(local_ip, h.localPort);
    let remote = SocketAddr::new(remote_ip, h.remotePort);

    let verdict = match ev.r#type {
        FWPM_NET_EVENT_TYPE_CLASSIFY_ALLOW => ConnectionVerdict::Permit,
        FWPM_NET_EVENT_TYPE_CLASSIFY_DROP => ConnectionVerdict::Block,
        _ => ConnectionVerdict::Unknown,
    };

    // For a DROP, capture the WFP runtime filter id that dropped it so `drain`
    // can attribute the drop to NetRuleRouter vs a foreign filter. The
    // `classifyDrop` arm of the event union is active only for a
    // CLASSIFY_DROP event; null-guard before deref.
    let drop_filter_id = if ev.r#type == FWPM_NET_EVENT_TYPE_CLASSIFY_DROP {
        // SAFETY: for a CLASSIFY_DROP the union's `classifyDrop` pointer is the
        // active member and points to a valid FWPM_NET_EVENT_CLASSIFY_DROP2 for
        // the callback's duration.
        let drop_ptr = ev.Anonymous.classifyDrop;
        if drop_ptr.is_null() {
            None
        } else {
            Some((*drop_ptr).filterId)
        }
    } else {
        None
    };

    let process_path = decode_app_id(&h.appId);
    let user_sid = decode_sid(h.userId);
    let observed_unix_ms = filetime_to_unix_ms(&h.timeStamp);

    let obs = ConnectionObservation {
        pid: 0, // WFP net events identify by image path, not PID.
        process_path,
        user_sid,
        protocol,
        local,
        remote,
        verdict,
        drop_filter_id,
        blocked_by_nrr: None, // resolved in `drain` (off the WFP callback thread).
        nrr_drop_spec_id: None, // resolved in `drain` (off the WFP callback thread).
        observed_unix_ms,
        // A classify event is the connection itself; WFP reports no later fate.
        progress: ConnectionProgress::Attempt,
    };

    let buffer = &*(context as *const Mutex<Vec<ConnectionObservation>>);
    if let Ok(mut g) = buffer.lock() {
        if g.len() < BUFFER_CAP {
            g.push(obs);
        }
    }
}

/// Decode a WFP `appId` byte blob (a UTF-16LE NT device path) into a `String`.
/// Returns `None` for an empty/absent blob.
///
/// # Safety
/// `blob.data` must point to `blob.size` valid bytes (or be null).
unsafe fn decode_app_id(
    blob: &windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_BYTE_BLOB,
) -> Option<String> {
    if blob.data.is_null() || blob.size < 2 {
        return None;
    }
    let units = blob.size as usize / 2;
    let p = blob.data as *const u16;
    let slice = std::slice::from_raw_parts(p, units);
    // Trim a single trailing NUL if present.
    let end = slice.iter().position(|&u| u == 0).unwrap_or(units);
    if end == 0 {
        return None;
    }
    Some(String::from_utf16_lossy(&slice[..end]))
}

/// Convert a WFP net-event `userId` (a `*mut SID`) to its string form
/// (`S-1-5-…`). Returns `None` for a null SID or on conversion failure.
///
/// # Safety
/// `sid_ptr` must be null or point to a valid `SID` for the call's duration
/// (it is — the pointer is live for the callback invocation).
unsafe fn decode_sid(sid_ptr: *mut windows::Win32::Security::SID) -> Option<String> {
    if sid_ptr.is_null() {
        return None;
    }
    let mut out = PWSTR::null();
    if ConvertSidToStringSidW(PSID(sid_ptr as *mut std::ffi::c_void), &mut out).is_err()
        || out.is_null()
    {
        return None;
    }
    let s = out.to_string().ok();
    // ConvertSidToStringSidW allocates with LocalAlloc; release with LocalFree.
    let _ = LocalFree(HLOCAL(out.0 as *mut std::ffi::c_void));
    s
}

/// Convert a Win32 `FILETIME` (100 ns ticks since 1601-01-01) to Unix
/// milliseconds. Returns `None` for pre-epoch / zero stamps.
fn filetime_to_unix_ms(ft: &windows::Win32::Foundation::FILETIME) -> Option<u64> {
    const EPOCH_DELTA_100NS: u64 = 116_444_736_000_000_000; // 1601→1970 in 100ns
    let ticks = ((ft.dwHighDateTime as u64) << 32) | ft.dwLowDateTime as u64;
    ticks
        .checked_sub(EPOCH_DELTA_100NS)
        .map(|since_epoch_100ns| since_epoch_100ns / 10_000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filetime_converts_to_unix_ms() {
        // 2026-06-26T03:44:50.400Z ≈ 1_782_445_490_400 ms.
        // FILETIME ticks = (unix_ms * 10_000) + EPOCH_DELTA.
        let unix_ms: u64 = 1_782_445_490_400;
        let ticks = unix_ms * 10_000 + 116_444_736_000_000_000;
        let ft = windows::Win32::Foundation::FILETIME {
            dwLowDateTime: (ticks & 0xFFFF_FFFF) as u32,
            dwHighDateTime: (ticks >> 32) as u32,
        };
        assert_eq!(filetime_to_unix_ms(&ft), Some(unix_ms));
    }

    #[test]
    fn zero_filetime_is_none() {
        let ft = windows::Win32::Foundation::FILETIME::default();
        assert_eq!(filetime_to_unix_ms(&ft), None);
    }
}
