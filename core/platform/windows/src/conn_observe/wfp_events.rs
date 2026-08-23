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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use windows::core::{GUID, PWSTR};
use windows::Win32::Foundation::{LocalFree, HANDLE, HLOCAL};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineClose0, FwpmEngineGetOption0, FwpmEngineOpen0, FwpmEngineSetOption0,
    FwpmFilterGetById0, FwpmFreeMemory0, FwpmNetEventSubscribe1, FwpmNetEventUnsubscribe0,
    FWPM_ENGINE_COLLECT_NET_EVENTS, FWPM_ENGINE_NET_EVENT_MATCH_ANY_KEYWORDS, FWPM_FILTER0,
    FWPM_NET_EVENT2, FWPM_NET_EVENT_KEYWORD_CLASSIFY_ALLOW, FWPM_NET_EVENT_SUBSCRIPTION0,
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

/// The machine-wide engine options this process changed, as they were before.
/// Kept outside the observer because putting them back must not depend on who
/// still holds an `Arc` to it at exit: `Drop` on a source the consumer threads
/// still reference never runs, and the setting would outlive the service.
static PRIOR_ENGINE_OPTIONS: OnceLock<(Option<u32>, Option<u32>)> = OnceLock::new();
/// One restore per process, whoever gets there first.
static ENGINE_OPTIONS_RESTORED: AtomicBool = AtomicBool::new(false);

/// File name of the note left beside the filter ledger recording what the
/// engine options held before this process changed them.
///
/// A process that is killed rather than stopped never runs its restore, and the
/// next one cannot know what to put back — the previous value lives only in the
/// memory that just died. Writing it down is what lets `cleanup` and the
/// uninstall sweep undo a change made by an instance that is long gone.
const PRIOR_OPTIONS_FILE: &str = "wfp-engine-options.prior";

fn prior_options_path() -> Option<std::path::PathBuf> {
    nrr_platform_api::paths::production_data_root().map(|root| root.join(PRIOR_OPTIONS_FILE))
}

/// Remember, on disk, what the options held before we touched them.
fn write_prior_options_note(prior: (Option<u32>, Option<u32>)) {
    let Some(path) = prior_options_path() else {
        return;
    };
    let mut body = String::new();
    if let Some(v) = prior.0 {
        body.push_str(&format!("collect={v}\n"));
    }
    if let Some(v) = prior.1 {
        body.push_str(&format!("keywords={v}\n"));
    }
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Err(e) = std::fs::write(&path, body) {
        tracing::warn!(
            target: "nrr::conn-observe",
            error = %e,
            "could not record the previous WFP engine options; a hard kill would leave them changed",
        );
    }
}

/// Read back a note a previous instance left. `None` when there is none.
fn read_prior_options_note() -> Option<(Option<u32>, Option<u32>)> {
    let text = std::fs::read_to_string(prior_options_path()?).ok()?;
    let mut prior = (None, None);
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let Ok(parsed) = value.trim().parse::<u32>() else {
            continue;
        };
        match key.trim() {
            "collect" => prior.0 = Some(parsed),
            "keywords" => prior.1 = Some(parsed),
            _ => {}
        }
    }
    (prior != (None, None)).then_some(prior)
}

fn clear_prior_options_note() {
    if let Some(path) = prior_options_path() {
        let _ = std::fs::remove_file(path);
    }
}

/// Hand the machine-wide Base Filtering Engine options this process changed
/// back to their previous values.
///
/// Call it on the service's stop path: leaving `COLLECT_NET_EVENTS` on makes
/// BFE go on recording every classify for every process on the host, for as
/// long as Windows runs, with nobody left to consume the events. Safe to call
/// repeatedly and from a path that owns no observer — it opens its own
/// short-lived engine handle. A no-op when nothing was changed.
pub fn restore_engine_options() {
    // This process's own change if it made one; otherwise the note a previous
    // instance left before it was killed. The second case is the whole point:
    // `cleanup` and the uninstall sweep run in a fresh process that changed
    // nothing and would otherwise have nothing to put back.
    let prior = PRIOR_ENGINE_OPTIONS
        .get()
        .copied()
        .filter(|p| *p != (None, None))
        .or_else(read_prior_options_note);
    let Some(prior) = prior else {
        return;
    };
    if ENGINE_OPTIONS_RESTORED.swap(true, Ordering::AcqRel) {
        return;
    }
    let mut engine = HANDLE::default();
    // SAFETY: same open as `start`; the handle is closed below on every path.
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
        tracing::warn!(
            target: "nrr::conn-observe",
            code,
            "could not reopen WFP to hand the machine-wide net-event options back",
        );
        return;
    }
    // SAFETY: `engine` is the handle just opened and is closed right after.
    unsafe {
        restore_engine_options_with(engine, prior);
        let _ = FwpmEngineClose0(engine);
    }
    clear_prior_options_note();
}

/// Put both options back over an already-open engine handle.
///
/// # Safety
/// `engine` must be an open WFP management handle.
unsafe fn restore_engine_options_with(engine: HANDLE, prior: (Option<u32>, Option<u32>)) {
    restore_uint32_option(engine, FWPM_ENGINE_COLLECT_NET_EVENTS, prior.0, 1);
    restore_uint32_option(
        engine,
        FWPM_ENGINE_NET_EVENT_MATCH_ANY_KEYWORDS,
        prior.1,
        FWPM_NET_EVENT_KEYWORD_CLASSIFY_ALLOW,
    );
}

/// A running WFP net-event subscription. Events arrive on WFP's own threads
/// into [`Self`]'s buffer; [`ConnectionObservationSource::drain`] empties it.
pub struct WfpConnectionObserver {
    buffer: Buffer,
    engine_raw: u64,
    events_raw: u64,
    /// Leaked `Arc<Mutex<…>>` ref handed to the callback; reclaimed on drop.
    ctx: *mut c_void,
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
        // Attribution memo for THIS batch only. WFP hands out runtime filter ids
        // from a reused pool, and a reconcile retires thousands of filters at a
        // time — a memo that outlived the batch would answer for a filter that
        // no longer exists.
        let mut resolved: HashMap<u64, Option<(bool, Option<u64>)>> = HashMap::new();
        for obs in out.iter_mut() {
            if obs.verdict == ConnectionVerdict::Block {
                if let Some(fid) = obs.drop_filter_id {
                    let owner = *resolved
                        .entry(fid)
                        .or_insert_with(|| resolve_owner(engine, fid));
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
        // Both are MACHINE-WIDE and outlive this process inside the Base
        // Filtering Engine: collection makes BFE record every classify for
        // every process on the host. Read first, so teardown can hand the
        // machine back the way it was found.
        // SAFETY: each call passes a stack `FWP_VALUE0` (UINT32) by const ptr,
        // valid for the call; `engine` is the just-opened handle.
        let (prior_collect, opt1) =
            unsafe { set_uint32_option_restorable(engine, FWPM_ENGINE_COLLECT_NET_EVENTS, 1) };
        let (prior_keywords, opt2) = unsafe {
            set_uint32_option_restorable(
                engine,
                FWPM_ENGINE_NET_EVENT_MATCH_ANY_KEYWORDS,
                FWPM_NET_EVENT_KEYWORD_CLASSIFY_ALLOW,
            )
        };
        let _ = PRIOR_ENGINE_OPTIONS.set((prior_collect, prior_keywords));
        if (prior_collect, prior_keywords) != (None, None) {
            write_prior_options_note((prior_collect, prior_keywords));
        }
        if opt1 != 0 || opt2 != 0 {
            // SAFETY: `engine` is open; undo whatever did take, then close.
            unsafe {
                restore_engine_options_with(engine, (prior_collect, prior_keywords));
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
            // SAFETY: reclaim the leaked Arc ref, put the machine-wide options
            // back and close the engine; nothing else holds either.
            unsafe {
                drop(Arc::from_raw(
                    ctx as *const Mutex<Vec<ConnectionObservation>>,
                ));
                restore_engine_options_with(engine, (prior_collect, prior_keywords));
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
        })
    }
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
/// id-encoding scheme). Returns `None` when the lookup fails — so
/// a drop is NEVER falsely attributed to NetRuleRouter. Runs on the
/// consumer's drain thread, not the WFP callback thread.
fn resolve_owner(engine: HANDLE, fid: u64) -> Option<(bool, Option<u64>)> {
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
    Some((is_ours, spec_id))
}

impl Drop for WfpConnectionObserver {
    fn drop(&mut self) {
        let engine = HANDLE(self.engine_raw as usize as *mut c_void);
        let events = HANDLE(self.events_raw as usize as *mut c_void);
        // Order is load-bearing: stop the callback first, so no event arrives
        // against a half-torn-down subscription; hand the machine-wide options
        // back while there is still a handle to hand them back WITH; close
        // last. Closing first would leave BFE recording every classify on the
        // host for as long as it runs.
        // SAFETY: both handles came from successful opens in `start`; the Arc
        // ref reclaimed last was leaked exactly once, there.
        let prior = PRIOR_ENGINE_OPTIONS.get().copied().unwrap_or((None, None));
        let restore_here =
            prior != (None, None) && !ENGINE_OPTIONS_RESTORED.swap(true, Ordering::AcqRel);
        unsafe {
            let _ = FwpmNetEventUnsubscribe0(engine, events);
            if restore_here {
                restore_engine_options_with(engine, prior);
                clear_prior_options_note();
            }
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

/// Read a UINT32 engine option. `None` when the call fails or the engine
/// answers with another type - an unreadable option is one we must not pretend
/// to know the previous value of.
///
/// # Safety
/// `engine` must be an open WFP management handle.
unsafe fn get_uint32_option(
    engine: HANDLE,
    option: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_ENGINE_OPTION,
) -> Option<u32> {
    let mut value: *mut FWP_VALUE0 = std::ptr::null_mut();
    if FwpmEngineGetOption0(engine, option, &mut value) != 0 || value.is_null() {
        return None;
    }
    let read = if (*value).r#type == FWP_UINT32 {
        Some((*value).Anonymous.uint32)
    } else {
        None
    };
    FwpmFreeMemory0(&mut (value as *mut c_void));
    read
}

/// Set a UINT32 engine option and report what it held before, so the change can
/// be undone. A previous value comes back only when it differs from `value` and
/// the write succeeded: there is nothing to restore when the option already
/// held what we need, and claiming otherwise would have us switch collection
/// off under a product that switched it on.
///
/// # Safety
/// `engine` must be an open WFP management handle.
unsafe fn set_uint32_option_restorable(
    engine: HANDLE,
    option: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_ENGINE_OPTION,
    value: u32,
) -> (Option<u32>, u32) {
    let prior = get_uint32_option(engine, option);
    if prior == Some(value) {
        return (None, 0);
    }
    let code = set_uint32_option(engine, option, value);
    if code != 0 {
        return (None, code);
    }
    (prior, 0)
}

/// Put a machine-wide engine option back, but only while it still holds the
/// value this process wrote: something else may have taken it over since, and
/// overwriting that would break a component we know nothing about.
///
/// # Safety
/// `engine` must be an open WFP management handle.
unsafe fn restore_uint32_option(
    engine: HANDLE,
    option: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_ENGINE_OPTION,
    prior: Option<u32>,
    written: u32,
) {
    let Some(prior) = prior else {
        return;
    };
    if get_uint32_option(engine, option) != Some(written) {
        return;
    }
    let code = set_uint32_option(engine, option, prior);
    if code != 0 {
        tracing::warn!(
            target: "nrr::conn-observe",
            code,
            "could not hand a machine-wide WFP engine option back to its previous value",
        );
    }
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
