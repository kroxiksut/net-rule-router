//! Active reachability probe — the Windows ICMP mechanism backend.
//!
//! The neutral [`ReachabilityProbe`] trait and the two OS-agnostic
//! implementations (a feature-disabled default and a test mock) now live in
//! `nrr-platform-api`; this module holds only the Windows implementation
//! ([`WindowsIcmpProbe`], via `IcmpSendEcho`). The trait + its neutral
//! placeholders are re-exported below so existing
//! `nrr_platform_windows::reachability::*` paths keep resolving unchanged.
//!
//! ## Fail-SAFE direction (implemented here)
//!
//! A probe that CANNOT be run (handle-open failure, send error) returns `true`
//! (reachable). Only a definite *no reply within the timeout* returns `false`.
//! The caller uses a `false` to eventually fail-close (block) the user's traffic,
//! so an indeterminate probe must never be the thing that blocks a working
//! secondary adapter. Transient loss is absorbed by the caller's hysteresis.

#![allow(unsafe_code)]

// The neutral port + OS-agnostic impls live in `nrr-platform-api`.
// Re-export them so consumers (`service-runtime`) keep importing them from here
// unchanged.
pub use nrr_platform_api::reachability::{
    AlwaysReachableProbe, MockReachabilityProbe, ReachabilityProbe,
};

#[cfg(target_os = "windows")]
use std::net::Ipv4Addr;
#[cfg(target_os = "windows")]
use std::time::Duration;

/// Production ICMP-echo probe (`IcmpCreateFile` / `IcmpSendEcho` /
/// `IcmpCloseHandle`).
#[cfg(target_os = "windows")]
#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsIcmpProbe;

#[cfg(target_os = "windows")]
impl ReachabilityProbe for WindowsIcmpProbe {
    fn is_reachable(&self, target: Ipv4Addr, timeout: Duration) -> bool {
        icmp_echo_reachable(target, timeout)
    }
}

/// A tiny fixed request payload — content is irrelevant, only that a reply
/// comes back. 8 bytes keeps the round trip cheap.
#[cfg(target_os = "windows")]
const ICMP_REQUEST_DATA: [u8; 8] = *b"nrr-live";

/// `IP_SUCCESS` from `ipexport.h`. A reply whose `Status` equals this means the
/// target answered; any other status (unreachable, TTL expired, timeout) is not
/// a live answer.
#[cfg(target_os = "windows")]
const IP_SUCCESS: u32 = 0;

#[cfg(target_os = "windows")]
fn icmp_echo_reachable(target: Ipv4Addr, timeout: Duration) -> bool {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::NetworkManagement::IpHelper::{
        IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho, ICMP_ECHO_REPLY,
    };

    // Destination as a Win32 `IPAddr` (u32 whose memory layout IS the four
    // octets in network order). `from_ne_bytes(octets)` yields exactly that.
    let dest: u32 = u32::from_ne_bytes(target.octets());

    // Reply buffer: one `ICMP_ECHO_REPLY` + the echoed data + 8 bytes of room
    // for an ICMP error, per the `IcmpSendEcho` contract.
    let reply_size = std::mem::size_of::<ICMP_ECHO_REPLY>() + ICMP_REQUEST_DATA.len() + 8;
    let mut reply_buf = vec![0u8; reply_size];

    let timeout_ms = timeout.as_millis().clamp(1, u32::MAX as u128) as u32;

    // SAFETY: `IcmpCreateFile` returns an ICMP handle or INVALID_HANDLE_VALUE on
    // failure; we never dereference it, only pass it back to `IcmpSendEcho` /
    // `IcmpCloseHandle`.
    let handle: HANDLE = match unsafe { IcmpCreateFile() } {
        Ok(h) => h,
        // Fail-SAFE: cannot run the probe → treat as reachable (never
        // fail-close on an indeterminate result).
        Err(_) => return true,
    };
    if handle.is_invalid() {
        return true;
    }

    // SAFETY: `handle` is a live ICMP handle; `dest` is a plain in-value;
    // `ICMP_REQUEST_DATA` is a valid readable buffer of `len` bytes; `reply_buf`
    // is a valid writable buffer of `reply_size` bytes living on this frame for
    // the duration of the synchronous call. `requestoptions = None` = defaults.
    let replies = unsafe {
        IcmpSendEcho(
            handle,
            dest,
            ICMP_REQUEST_DATA.as_ptr() as *const std::ffi::c_void,
            ICMP_REQUEST_DATA.len() as u16,
            None,
            reply_buf.as_mut_ptr() as *mut std::ffi::c_void,
            reply_size as u32,
            timeout_ms,
        )
    };

    // SAFETY: closing the handle we opened; ignore the BOOL result.
    unsafe {
        let _ = IcmpCloseHandle(handle);
    }

    if replies == 0 {
        // Definite: no reply within the timeout. THIS is the only path that
        // reports "unreachable"; the caller's hysteresis absorbs transient loss.
        return false;
    }

    // SAFETY: `replies >= 1` means `reply_buf` starts with a populated
    // `ICMP_ECHO_REPLY`; the buffer is at least `size_of::<ICMP_ECHO_REPLY>()`.
    let reply = unsafe { &*(reply_buf.as_ptr() as *const ICMP_ECHO_REPLY) };
    // A non-`IP_SUCCESS` status (e.g. destination unreachable, TTL expired) is
    // not a live answer from the target itself → treat as unreachable.
    reply.Status == IP_SUCCESS
}
