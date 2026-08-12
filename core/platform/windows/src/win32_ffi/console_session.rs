//! Resolve the active console-session user's SID.
//!
//! The service-driven routing scope (`service_stability_config
//! .rule_scope_service_driven`) enforces the active console user's routing
//! policy even when no GUI/tray is connected — including from boot, before the
//! user ever opens the app (the managed/locked-down deployment). With no IPC
//! connection there is no SID in the `ActiveSidRegistry`, so the routing layer
//! asks the OS directly which user owns the physical console session.

#![allow(unsafe_code)]

use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
use windows::Win32::System::RemoteDesktop::{WTSGetActiveConsoleSessionId, WTSQueryUserToken};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// Prefix of a real interactive user's SID (a machine-local or domain
/// account: `S-1-5-21-<authority>-<rid>`). Service accounts — LocalSystem
/// (`S-1-5-18`), LocalService (`-19`), NetworkService (`-20`) — never match, so
/// the console-mode fallback below can safely distinguish "a user is running
/// me" from "I am a service account".
const INTERACTIVE_USER_SID_PREFIX: &str = "S-1-5-21-";

/// String SID (`S-1-5-21-…`) of the user whose routing policy this service
/// should enforce when no GUI/tray is connected: the active physical
/// console-session user (the LocalSystem/SCM path), or — when the service is
/// run as a normal elevated CONSOLE process for debugging — the user running
/// it. `None` when there is genuinely no interactive user (logon screen,
/// headless) or the SID cannot be resolved.
///
/// Best-effort: every failure path returns `None`, so the routing layer
/// degrades to "no console user → clear the table" rather than panicking.
pub fn active_console_user_sid() -> Option<String> {
    if let Some(sid) = active_console_user_sid_via_wts() {
        return Some(sid);
    }
    // `WTSQueryUserToken` is SYSTEM-only, so a service started as a normal
    // ELEVATED CONSOLE process (the debug-run path) always fails the WTS
    // route, which would otherwise mean zero enforcement every tick. In that
    // mode the process runs AS the routing user, so fall back to our OWN
    // token's SID — but ONLY
    // when it is a real interactive user (`S-1-5-21-…`). Under SCM the WTS path
    // above succeeds; if it somehow failed there, our own SID is a service
    // account (`S-1-5-18/19/20`) which is filtered out here, so this fallback
    // can never wrongly enforce a service account's (empty) policy.
    console_fallback_sid(current_process_user_sid())
}

/// The console user via the SYSTEM-only WTS path. `None` when not running as
/// LocalSystem (the call is access-denied) or there is no attached console.
fn active_console_user_sid_via_wts() -> Option<String> {
    // SAFETY: takes no args; returns the active console session id, or
    // 0xFFFFFFFF when no session is currently attached to the console.
    let session_id = unsafe { WTSGetActiveConsoleSessionId() };
    if session_id == 0xFFFF_FFFF {
        return None;
    }
    let mut token = HANDLE::default();
    // SAFETY: `token` is a valid out-param; on success WTSQueryUserToken fills
    // it with a primary token for the session's interactive user.
    if unsafe { WTSQueryUserToken(session_id, &mut token) }.is_err() {
        return None;
    }
    // SAFETY: `token` is the just-opened token, valid until we close it.
    let sid = unsafe { token_user_sid_string(token) };
    // SAFETY: close the token exactly once, regardless of SID outcome.
    let _ = unsafe { CloseHandle(token) };
    sid
}

/// The console-mode fallback decision (pure): a resolved own-process SID is
/// accepted as the routing user only when it is a real interactive user, never
/// a service account. Split out of [`active_console_user_sid`] so the guard —
/// the load-bearing safety rule that keeps the fallback from ever enforcing a
/// service account under SCM — is unit-testable without the Win32 calls.
fn console_fallback_sid(own_process_sid: Option<String>) -> Option<String> {
    match own_process_sid {
        Some(sid) if sid.starts_with(INTERACTIVE_USER_SID_PREFIX) => Some(sid),
        _ => None,
    }
}

/// The SID of the user THIS process runs as (via its own primary token).
/// `None` on any failure.
fn current_process_user_sid() -> Option<String> {
    let mut token = HANDLE::default();
    // SAFETY: `GetCurrentProcess` returns a pseudo-handle; `token` is a valid
    // out-param filled with a query token on success.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.is_err() {
        return None;
    }
    // SAFETY: `token` is the just-opened process token, valid until we close it.
    let sid = unsafe { token_user_sid_string(token) };
    // SAFETY: close the token exactly once, regardless of SID outcome.
    let _ = unsafe { CloseHandle(token) };
    sid
}

/// Extract the user SID (string form) from a primary token. `None` on any
/// failure.
///
/// # Safety
/// `token` must be a valid, open token handle for the duration of the call.
unsafe fn token_user_sid_string(token: HANDLE) -> Option<String> {
    // First call sizes the buffer (expected to fail, filling `needed`).
    let mut needed: u32 = 0;
    let _ = GetTokenInformation(token, TokenUser, None, 0, &mut needed);
    if needed == 0 {
        return None;
    }
    let mut buf = vec![0u8; needed as usize];
    // SAFETY: `buf` is `needed` bytes; on success GetTokenInformation writes a
    // TOKEN_USER whose embedded SID points within `buf`.
    if GetTokenInformation(
        token,
        TokenUser,
        Some(buf.as_mut_ptr() as *mut std::ffi::c_void),
        needed,
        &mut needed,
    )
    .is_err()
    {
        return None;
    }
    // SAFETY: `buf` now holds a TOKEN_USER; `User.Sid` points into `buf` and
    // stays valid while `buf` is alive (for this conversion).
    let token_user = &*(buf.as_ptr() as *const TOKEN_USER);
    let sid = token_user.User.Sid;
    if sid.0.is_null() {
        return None;
    }
    let mut out = PWSTR::null();
    // SAFETY: `sid` is valid (points into live `buf`); ConvertSidToStringSidW
    // allocates the string via LocalAlloc and stores the pointer in `out`.
    if ConvertSidToStringSidW(sid, &mut out).is_err() || out.is_null() {
        return None;
    }
    let s = out.to_string().ok();
    // ConvertSidToStringSidW allocates with LocalAlloc; release with LocalFree.
    let _ = LocalFree(HLOCAL(out.0 as *mut std::ffi::c_void));
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn console_fallback_accepts_only_a_real_interactive_user() {
        // The fallback enforces for the process's own user ONLY when it is a
        // genuine interactive account.
        assert_eq!(
            console_fallback_sid(Some("S-1-5-21-111-222-333-1001".to_string())),
            Some("S-1-5-21-111-222-333-1001".to_string()),
        );
        // Service accounts (SCM path leaked through) are never enforced.
        assert_eq!(console_fallback_sid(Some("S-1-5-18".to_string())), None); // LocalSystem
        assert_eq!(console_fallback_sid(Some("S-1-5-19".to_string())), None); // LocalService
        assert_eq!(console_fallback_sid(Some("S-1-5-20".to_string())), None); // NetworkService
                                                                              // No token resolved → no fallback.
        assert_eq!(console_fallback_sid(None), None);
    }
}
