//! Resolve the SID of the signed-in user whose rules the service enforces.
//!
//! The service-driven routing scope (`service_stability_config
//! .rule_scope_service_driven`) enforces a signed-in user's routing policy with
//! no GUI or tray connected — from boot, before the app is ever opened. The tray
//! is a convenience, not the routing agent, so the service asks the OS which
//! user is at the machine: the console session first, then a remote (RDP)
//! session.

#![allow(unsafe_code)]

use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
use windows::Win32::System::RemoteDesktop::{
    WTSActive, WTSDisconnected, WTSEnumerateSessionsW, WTSFreeMemory, WTSGetActiveConsoleSessionId,
    WTSQueryUserToken, WTS_CONNECTSTATE_CLASS, WTS_CURRENT_SERVER_HANDLE, WTS_SESSION_INFOW,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};

/// Prefix of a real interactive user's SID (a machine-local or domain
/// account: `S-1-5-21-<authority>-<rid>`). Service accounts — LocalSystem
/// (`S-1-5-18`), LocalService (`-19`), NetworkService (`-20`) — never match, so
/// the console-mode fallback below can safely distinguish "a user is running
/// me" from "I am a service account".
const INTERACTIVE_USER_SID_PREFIX: &str = "S-1-5-21-";

/// String SID (`S-1-5-21-…`) of the user whose routing policy this service
/// enforces when no tray is connected: the console-session user, else the one
/// user signed in remotely, else — when the service runs as an elevated console
/// process for debugging — the user running it. `None` when nobody is signed in,
/// when several users are signed in remotely and none is at the console (Free
/// enforces one user; a tray picks among them), or the SID cannot be resolved.
///
/// Best-effort: every failure path returns `None`, so the routing layer
/// degrades to "no routing user → clear the table" rather than panicking.
pub fn interactive_user_sid() -> Option<String> {
    if let Some(sid) = active_console_user_sid_via_wts() {
        return Some(sid);
    }
    if let Some(sid) = remote_user_sid_cached() {
        return Some(sid);
    }
    // `WTSQueryUserToken` is SYSTEM-only, so a service started as an elevated
    // console process (the debug run) fails both WTS paths; it then runs AS the
    // routing user. Under SCM our own SID is a service account, which the guard
    // filters out, so this can never enforce a service account's empty policy.
    console_fallback_sid(current_process_user_sid())
}

/// How long one session enumeration answers. The routing SID is asked on every
/// pass and policy edit; a sign-in re-arms through its own SCM event, so a
/// second of staleness costs nothing.
const REMOTE_LOOKUP_TTL: std::time::Duration = std::time::Duration::from_secs(1);

fn remote_user_sid_cached() -> Option<String> {
    use std::sync::Mutex;
    use std::time::Instant;
    static LAST: Mutex<Option<(Instant, Option<String>)>> = Mutex::new(None);
    let mut last = LAST.lock().unwrap_or_else(|p| p.into_inner());
    if let Some((at, sid)) = last.as_ref() {
        if at.elapsed() < REMOTE_LOOKUP_TTL {
            return sid.clone();
        }
    }
    let sid = remote_user_sid();
    *last = Some((Instant::now(), sid.clone()));
    sid
}

/// The user of the remote sessions, when exactly one user holds them.
fn remote_user_sid() -> Option<String> {
    // SAFETY: takes no args; returns the console session id or 0xFFFFFFFF.
    let console = unsafe { WTSGetActiveConsoleSessionId() };
    let mut info: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
    let mut count: u32 = 0;
    // SAFETY: both out-params are valid; on success `info` points at `count`
    // entries allocated by WTS, released below with WTSFreeMemory.
    if unsafe { WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &mut info, &mut count) }
        .is_err()
        || info.is_null()
    {
        return None;
    }
    // SAFETY: WTS returned `count` contiguous entries at `info`, alive until freed.
    let entries = unsafe { std::slice::from_raw_parts(info, count as usize) };
    let sessions: Vec<(SessionState, Option<String>)> = entries
        .iter()
        // Session 0 hosts services; the console is the path above.
        .filter(|e| e.SessionId != 0 && e.SessionId != console)
        .filter_map(|e| Some((session_state(e.State)?, session_user_sid(e.SessionId))))
        .collect();
    // SAFETY: `info` came from WTSEnumerateSessionsW and is freed exactly once;
    // `entries` is not used past this point.
    unsafe { WTSFreeMemory(info.cast()) };
    sole_session_user(&sessions)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SessionState {
    Active,
    /// Signed in, nobody attached — the user's programs keep running.
    Disconnected,
}

fn session_state(state: WTS_CONNECTSTATE_CLASS) -> Option<SessionState> {
    if state == WTSActive {
        Some(SessionState::Active)
    } else if state == WTSDisconnected {
        Some(SessionState::Disconnected)
    } else {
        None
    }
}

/// The one user to enforce for among non-console sessions: the user of the
/// attached sessions; with none attached, the user whose programs run on
/// disconnected. Two different users at the same level is ambiguous — Free
/// enforces one user, and guessing would route another person's traffic.
fn sole_session_user(sessions: &[(SessionState, Option<String>)]) -> Option<String> {
    for level in [SessionState::Active, SessionState::Disconnected] {
        let mut users = sessions
            .iter()
            .filter(|(state, _)| *state == level)
            .filter_map(|(_, sid)| sid.as_deref())
            .filter(|sid| sid.starts_with(INTERACTIVE_USER_SID_PREFIX));
        if let Some(first) = users.next() {
            return users.all(|sid| sid == first).then(|| first.to_string());
        }
    }
    None
}

fn session_user_sid(session_id: u32) -> Option<String> {
    let mut token = HANDLE::default();
    // SAFETY: `token` is a valid out-param; on success WTSQueryUserToken fills
    // it with a primary token for the session's user.
    if unsafe { WTSQueryUserToken(session_id, &mut token) }.is_err() {
        return None;
    }
    // SAFETY: `token` is the just-opened token, valid until we close it.
    let sid = unsafe { token_user_sid_string(token) };
    // SAFETY: close the token exactly once, regardless of SID outcome.
    let _ = unsafe { CloseHandle(token) };
    sid
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
    session_user_sid(session_id)
}

/// The console-mode fallback decision (pure): a resolved own-process SID is
/// accepted as the routing user only when it is a real interactive user, never
/// a service account. Split out of [`interactive_user_sid`] so the guard —
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
pub(crate) fn current_process_user_sid() -> Option<String> {
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

/// The SID of the user process `pid` runs as. `None` when the process is gone
/// or its token cannot be opened (a protected process, or no rights).
pub fn process_user_sid(pid: u32) -> Option<String> {
    // SAFETY: plain FFI call; a failure returns an error, success a process
    // handle we own and close below.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
    let mut token = HANDLE::default();
    // SAFETY: `process` is the handle just opened; `token` is a valid out-param.
    let sid = if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) }.is_ok() {
        // SAFETY: `token` is the just-opened token, valid until closed here.
        let sid = unsafe { token_user_sid_string(token) };
        // SAFETY: close the token exactly once.
        let _ = unsafe { CloseHandle(token) };
        sid
    } else {
        None
    };
    // SAFETY: close the process handle exactly once.
    let _ = unsafe { CloseHandle(process) };
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

    const ALICE: &str = "S-1-5-21-111-222-333-1001";
    const BOB: &str = "S-1-5-21-111-222-333-1002";

    fn at(state: SessionState, sid: &str) -> (SessionState, Option<String>) {
        (state, Some(sid.to_string()))
    }

    #[test]
    fn one_remote_user_is_the_routing_user() {
        use SessionState::*;
        assert_eq!(
            sole_session_user(&[at(Active, ALICE)]).as_deref(),
            Some(ALICE)
        );
        // Two sessions of the same user are still one user.
        assert_eq!(
            sole_session_user(&[at(Active, ALICE), at(Disconnected, BOB), at(Active, ALICE)])
                .as_deref(),
            Some(ALICE)
        );
    }

    #[test]
    fn an_attached_session_outranks_a_disconnected_one() {
        use SessionState::*;
        assert_eq!(
            sole_session_user(&[at(Disconnected, BOB), at(Active, ALICE)]).as_deref(),
            Some(ALICE)
        );
        assert_eq!(
            sole_session_user(&[at(Disconnected, BOB)]).as_deref(),
            Some(BOB)
        );
    }

    #[test]
    fn two_users_at_one_level_are_nobody() {
        use SessionState::*;
        assert_eq!(
            sole_session_user(&[at(Active, ALICE), at(Active, BOB)]),
            None
        );
        // Ambiguity among attached users is not settled by a disconnected one.
        assert_eq!(
            sole_session_user(&[at(Active, ALICE), at(Active, BOB), at(Disconnected, BOB)]),
            None
        );
    }

    #[test]
    fn service_accounts_and_unresolved_sessions_never_count() {
        use SessionState::*;
        assert_eq!(
            sole_session_user(&[at(Active, "S-1-5-18"), (Active, None)]),
            None
        );
        assert_eq!(
            sole_session_user(&[at(Active, "S-1-5-18"), at(Active, ALICE)]).as_deref(),
            Some(ALICE)
        );
        assert_eq!(sole_session_user(&[]), None);
    }

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
