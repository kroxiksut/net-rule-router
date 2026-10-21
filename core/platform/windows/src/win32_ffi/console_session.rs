//! Resolve the SIDs of the signed-in users whose rules the service enforces.
//!
//! The service-driven routing scope (`service_stability_config
//! .rule_scope_service_driven`) enforces signed-in users' routing policy with
//! no GUI or tray connected — from boot, before the app is ever opened. The tray
//! is a convenience, not the routing agent, so the service asks the OS who is
//! signed in: the console session first, then remote (RDP) sessions.

#![allow(unsafe_code)]

use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
use windows::Win32::System::RemoteDesktop::{
    WTSActive, WTSDisconnected, WTSEnumerateSessionsW, WTSFreeMemory, WTSGetActiveConsoleSessionId,
    WTSQuerySessionInformationW, WTSQueryUserToken, WTSSessionInfo, WTSINFOW,
    WTS_CONNECTSTATE_CLASS, WTS_CURRENT_SERVER_HANDLE, WTS_SESSION_INFOW,
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

/// Every user signed in interactively, console user first, each once: the
/// console session, then attached remote sessions, then disconnected ones (a
/// disconnected user's programs keep running and keep needing their routes).
/// Service accounts never count. The console lookup is live, the session
/// enumeration answers from a short cache. Best-effort: a failed lookup is a
/// user missing from the list, never a panic.
pub fn interactive_user_sids() -> Vec<String> {
    let console = active_console_user_sid_via_wts();
    let remote = remote_sessions_cached();
    let mut users = ordered_session_users(console.as_deref(), &remote);
    if users.is_empty() {
        // `WTSQueryUserToken` is SYSTEM-only, so a service started as an
        // elevated console process (the debug run) fails both WTS paths; it then
        // runs AS the routing user. Under SCM our own SID is a service account,
        // which the guard filters out.
        users.extend(console_fallback_sid(current_process_user_sid()));
    }
    users
}

/// [`interactive_user_sids`], each with when that user signed in (Unix ms;
/// the earliest of their sessions). `None` where the session reports no time.
pub fn interactive_user_sign_ins() -> Vec<(String, Option<u64>)> {
    let users = interactive_user_sids();
    if users.is_empty() {
        return Vec::new();
    }
    let logons = session_logons();
    users
        .into_iter()
        .map(|sid| {
            let at = logons.get(&sid).copied();
            (sid, at)
        })
        .collect()
}

/// Earliest logon time per signed-in user, over every user session.
fn session_logons() -> std::collections::HashMap<String, u64> {
    let mut info: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
    let mut count: u32 = 0;
    let mut logons = std::collections::HashMap::new();
    // SAFETY: both out-params are valid; on success `info` points at `count`
    // entries allocated by WTS, released below with WTSFreeMemory.
    if unsafe { WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &mut info, &mut count) }
        .is_err()
        || info.is_null()
    {
        return logons;
    }
    // SAFETY: WTS returned `count` contiguous entries at `info`, alive until freed.
    let ids: Vec<u32> = unsafe { std::slice::from_raw_parts(info, count as usize) }
        .iter()
        .map(|e| e.SessionId)
        .filter(|id| *id != 0)
        .collect();
    // SAFETY: `info` came from WTSEnumerateSessionsW and is freed exactly once.
    unsafe { WTSFreeMemory(info.cast()) };
    for id in ids {
        let (Some(sid), Some(at)) = (session_user_sid(id), session_logon_unix_ms(id)) else {
            continue;
        };
        logons
            .entry(sid)
            .and_modify(|earliest: &mut u64| *earliest = (*earliest).min(at))
            .or_insert(at);
    }
    logons
}

/// When session `session_id` was logged on, as Unix ms.
fn session_logon_unix_ms(session_id: u32) -> Option<u64> {
    let mut buffer = windows::core::PWSTR::null();
    let mut bytes: u32 = 0;
    // SAFETY: current server, valid out-params; on success `buffer` holds a
    // WTS-allocated `WTSINFOW` of `bytes` bytes, freed below.
    let ok = unsafe {
        WTSQuerySessionInformationW(
            WTS_CURRENT_SERVER_HANDLE,
            session_id,
            WTSSessionInfo,
            &mut buffer,
            &mut bytes,
        )
    };
    if ok.is_err() || buffer.is_null() {
        return None;
    }
    let logon = if (bytes as usize) >= std::mem::size_of::<WTSINFOW>() {
        // SAFETY: the buffer is at least one `WTSINFOW`, as the API documents
        // for this class; read unaligned, as WTS makes no alignment promise.
        Some(unsafe { std::ptr::read_unaligned(buffer.0.cast::<WTSINFOW>()) }.LogonTime)
    } else {
        None
    };
    // SAFETY: the WTS allocation is freed exactly once and not used after.
    unsafe { WTSFreeMemory(buffer.0.cast()) };
    filetime_ticks_to_unix_ms(logon?)
}

/// 100 ns ticks since 1601 as Unix ms; `None` for zero or pre-1970 values.
fn filetime_ticks_to_unix_ms(ticks: i64) -> Option<u64> {
    const UNIX_EPOCH_TICKS: i64 = 116_444_736_000_000_000;
    let since_epoch = ticks.checked_sub(UNIX_EPOCH_TICKS).filter(|t| *t > 0)?;
    u64::try_from(since_epoch / 10_000).ok()
}

/// How long one session enumeration answers. The routing SID is asked on every
/// pass and policy edit; a sign-in re-arms through its own SCM event, so a
/// second of staleness costs nothing.
const REMOTE_LOOKUP_TTL: std::time::Duration = std::time::Duration::from_secs(1);

/// The non-console sessions with their users, from one enumeration per
/// [`REMOTE_LOOKUP_TTL`].
fn remote_sessions_cached() -> Vec<(SessionState, Option<String>)> {
    use std::sync::Mutex;
    use std::time::Instant;
    type Cached = Option<(Instant, Vec<(SessionState, Option<String>)>)>;
    static LAST: Mutex<Cached> = Mutex::new(None);
    let mut last = LAST.lock().unwrap_or_else(|p| p.into_inner());
    if let Some((at, sessions)) = last.as_ref() {
        if at.elapsed() < REMOTE_LOOKUP_TTL {
            return sessions.clone();
        }
    }
    let sessions = remote_sessions();
    *last = Some((Instant::now(), sessions.clone()));
    sessions
}

/// Every non-console user session with its state and user.
fn remote_sessions() -> Vec<(SessionState, Option<String>)> {
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
        return Vec::new();
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
    sessions
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

/// The console user, then the users of attached sessions, then those of
/// disconnected ones; each user once, service accounts never.
fn ordered_session_users(
    console: Option<&str>,
    sessions: &[(SessionState, Option<String>)],
) -> Vec<String> {
    let mut users: Vec<String> = Vec::new();
    let mut push = |sid: &str| {
        if sid.starts_with(INTERACTIVE_USER_SID_PREFIX) && !users.iter().any(|u| u == sid) {
            users.push(sid.to_string());
        }
    };
    if let Some(sid) = console {
        push(sid);
    }
    for level in [SessionState::Active, SessionState::Disconnected] {
        sessions
            .iter()
            .filter(|(state, _)| *state == level)
            .filter_map(|(_, sid)| sid.as_deref())
            .for_each(&mut push);
    }
    users
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
/// a service account. Split out of [`interactive_user_sids`] so the guard —
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
    let sid = process_handle_user_sid(process);
    // SAFETY: close the process handle exactly once.
    let _ = unsafe { CloseHandle(process) };
    sid
}

/// [`process_user_sid`] for a process handle the caller already holds (opened
/// with at least `PROCESS_QUERY_LIMITED_INFORMATION`); the handle stays open.
pub fn process_handle_user_sid(process: HANDLE) -> Option<String> {
    let mut token = HANDLE::default();
    // SAFETY: `process` is a live handle the caller owns; `token` is a valid
    // out-param.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) }.is_err() {
        return None;
    }
    // SAFETY: `token` is the just-opened token, valid until closed here.
    let sid = unsafe { token_user_sid_string(token) };
    // SAFETY: close the token exactly once.
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
    // Words, so the TOKEN_USER (it holds pointers) starts 8-aligned.
    let mut buf = vec![0u64; (needed as usize).div_ceil(8)];
    // SAFETY: `buf` holds at least `needed` bytes and starts 8-aligned; on
    // success GetTokenInformation writes a TOKEN_USER whose embedded SID points
    // within `buf`.
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
    fn a_logon_filetime_converts_to_unix_ms() {
        // 2001-09-09T01:46:40Z = 1_000_000_000_000 ms.
        let ticks = 116_444_736_000_000_000 + 1_000_000_000_000 * 10_000;
        assert_eq!(filetime_ticks_to_unix_ms(ticks), Some(1_000_000_000_000));
        assert_eq!(filetime_ticks_to_unix_ms(0), None);
    }

    const ALICE: &str = "S-1-5-21-111-222-333-1001";
    const BOB: &str = "S-1-5-21-111-222-333-1002";

    fn at(state: SessionState, sid: &str) -> (SessionState, Option<String>) {
        (state, Some(sid.to_string()))
    }

    #[test]
    fn service_accounts_and_unresolved_sessions_never_count() {
        use SessionState::*;
        assert!(ordered_session_users(None, &[at(Active, "S-1-5-18"), (Active, None)]).is_empty());
        assert_eq!(
            ordered_session_users(None, &[at(Active, "S-1-5-18"), at(Active, ALICE)]),
            vec![ALICE.to_string()],
        );
        assert!(ordered_session_users(None, &[]).is_empty());
    }

    #[test]
    fn two_sessions_of_one_user_are_one_user() {
        use SessionState::*;
        assert_eq!(
            ordered_session_users(
                None,
                &[
                    at(Active, ALICE),
                    at(Disconnected, ALICE),
                    at(Active, ALICE)
                ]
            ),
            vec![ALICE.to_string()],
        );
    }

    #[test]
    fn every_signed_in_user_is_listed_console_first_and_once() {
        use SessionState::*;
        const CAROL: &str = "S-1-5-21-111-222-333-1003";
        assert_eq!(
            ordered_session_users(
                Some(CAROL),
                &[
                    at(Disconnected, BOB),
                    at(Active, ALICE),
                    at(Active, CAROL),
                    at(Active, "S-1-5-18"),
                    (Active, None),
                ],
            ),
            vec![CAROL.to_string(), ALICE.to_string(), BOB.to_string()],
        );
        // Two remote users and nobody at the console are both served.
        assert_eq!(
            ordered_session_users(None, &[at(Active, ALICE), at(Active, BOB)]),
            vec![ALICE.to_string(), BOB.to_string()],
        );
        assert!(ordered_session_users(Some("S-1-5-18"), &[]).is_empty());
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
