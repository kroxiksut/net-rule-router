//! Caller identity check for the named pipe.
//!
//! For each accepted pipe connection we determine:
//!
//! 1. the client's process id (`GetNamedPipeClientProcessId`)
//! 2. the client's exe path (`QueryFullProcessImageNameW`)
//! 3. whether the process token is at low integrity (rejected)
//!
//! The exe path's basename is compared (case-insensitive) against a small
//! whitelist:
//!
//! | exe basename | profile |
//! |--------------|---------|
//! | `NetRuleRouter.exe` | `IpcClientProfile::GuiInteractive` |
//! | `NetRuleRouterTray.exe` | `IpcClientProfile::TrayLightweight` |
//! | `nrr-cli.exe` | `IpcClientProfile::AdminConsole` (read/diagnose only) |
//! | anything else | rejected (`UnknownProcess`) |
//!
//! `nrr-service.exe` is also rejected — the service must not talk to
//! itself over the pipe.
//!
//! Token elevation (`caller_is_elevated`) is read from
//! `GetTokenInformation(TokenElevation)` and forwarded to the IPC router
//! so privileged operations correctly enforce admin requirement.

#![cfg(target_os = "windows")]
#![allow(unsafe_code)]

use std::path::PathBuf;

use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, LocalFree, BOOL, HANDLE, HLOCAL};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::{
    GetTokenInformation, TokenElevation, TokenIntegrityLevel, TokenUser, PSID, TOKEN_ELEVATION,
    TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TOKEN_USER,
};
use windows::Win32::System::Pipes::GetNamedPipeClientProcessId;
use windows::Win32::System::Threading::{
    OpenProcess, OpenProcessToken, QueryFullProcessImageNameW, PROCESS_NAME_FORMAT,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

use nrr_shared::ipc::IpcClientProfile;

/// Result of an identity check on an accepted pipe connection.
pub struct ClientIdentity {
    pub profile: IpcClientProfile,
    pub caller_is_elevated: bool,
    pub process_id: u32,
    /// Basename of the connecting client's executable. Retained as part of the
    /// accepted-connection identity record for audit/diagnostics even though no
    /// caller reads it on the success path today.
    #[allow(dead_code)]
    pub exe_basename: String,
    /// String form of the caller's user SID (`S-1-5-21-...`), used to key
    /// per-SID storage and policy application. Extracted via
    /// `GetTokenInformation(TokenUser) + ConvertSidToStringSidW`.
    pub caller_sid: String,
}

/// Why a connection was rejected during identity check.
#[derive(Debug, Clone)]
pub enum ClientRejectReason {
    /// `GetNamedPipeClientProcessId` failed.
    ClientProcessIdFailed { code: u32 },
    /// `OpenProcess` failed (process exited, no rights, etc).
    OpenProcessFailed { code: u32 },
    /// `QueryFullProcessImageNameW` failed.
    QueryImageNameFailed { code: u32 },
    /// Exe basename is not on the whitelist.
    UnknownProcess { exe_basename: String },
    /// Process integrity level is Low (or below) — rejected.
    LowIntegrityLevel,
    /// Token query failed when checking integrity / elevation.
    TokenQueryFailed { code: u32 },
}

impl std::fmt::Display for ClientRejectReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ClientProcessIdFailed { code } => {
                write!(f, "GetNamedPipeClientProcessId failed (0x{code:08X})")
            }
            Self::OpenProcessFailed { code } => {
                write!(f, "OpenProcess failed (0x{code:08X})")
            }
            Self::QueryImageNameFailed { code } => {
                write!(f, "QueryFullProcessImageNameW failed (0x{code:08X})")
            }
            Self::UnknownProcess { exe_basename } => {
                write!(f, "unknown client exe basename: {exe_basename}")
            }
            Self::LowIntegrityLevel => write!(f, "client process is at low integrity level"),
            Self::TokenQueryFailed { code } => {
                write!(f, "token query failed (0x{code:08X})")
            }
        }
    }
}

/// Whitelist mapping from exe basename to client profile.
/// Case-insensitive. `nrr-service.exe` and any other name are rejected
/// (returns `None`).
fn classify_exe_basename(basename: &str) -> Option<IpcClientProfile> {
    let lower = basename.to_ascii_lowercase();
    match lower.as_str() {
        "netrulerouter.exe" => Some(IpcClientProfile::GuiInteractive),
        "netruleroutertray.exe" => Some(IpcClientProfile::TrayLightweight),
        // The administrative console. Admitted so it can collect diagnostics
        // through the same code path the application uses; the profile is what
        // keeps it to reading — it cannot invoke a policy change even by bug.
        "nrr-cli.exe" => Some(IpcClientProfile::AdminConsole),
        // Includes "nrr-service.exe" — explicitly rejected.
        _ => None,
    }
}

/// Public entrypoint: classify a connected pipe handle.
///
/// On success, returns `ClientIdentity`. On failure (Win32 error or
/// unknown process), returns `ClientRejectReason` so the server can
/// decide whether to log/audit and close the handle.
pub fn classify_pipe_client(pipe: HANDLE) -> Result<ClientIdentity, ClientRejectReason> {
    let pid = client_process_id(pipe)?;

    // Open the process for read-only inspection.
    // SAFETY: PROCESS_QUERY_LIMITED_INFORMATION is the minimum right we
    // need; we close the handle in an RAII guard.
    let process = unsafe {
        OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, BOOL(0), pid).map_err(|e| {
            ClientRejectReason::OpenProcessFailed {
                code: e.code().0 as u32,
            }
        })?
    };
    let process_guard = HandleGuard(process);

    let exe_path = query_image_name(process_guard.0)?;
    let basename = exe_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or_default()
        .to_string();

    let profile =
        classify_exe_basename(&basename).ok_or_else(|| ClientRejectReason::UnknownProcess {
            exe_basename: basename.clone(),
        })?;

    // Token integrity + elevation.
    let token = open_process_token(process_guard.0)?;
    let token_guard = HandleGuard(token);

    if is_low_integrity(token_guard.0)? {
        return Err(ClientRejectReason::LowIntegrityLevel);
    }
    let elevated = is_elevated(token_guard.0)?;
    let caller_sid = query_user_sid(token_guard.0)?;

    Ok(ClientIdentity {
        profile,
        caller_is_elevated: elevated,
        process_id: pid,
        exe_basename: basename,
        caller_sid,
    })
}

fn client_process_id(pipe: HANDLE) -> Result<u32, ClientRejectReason> {
    let mut pid: u32 = 0;
    // SAFETY: pipe is a valid named-pipe handle owned by the caller; pid
    // out-pointer is on the stack.
    let ok = unsafe { GetNamedPipeClientProcessId(pipe, &mut pid as *mut u32) };
    if ok.is_err() {
        return Err(ClientRejectReason::ClientProcessIdFailed {
            code: unsafe { windows::Win32::Foundation::GetLastError().0 },
        });
    }
    Ok(pid)
}

fn query_image_name(process: HANDLE) -> Result<PathBuf, ClientRejectReason> {
    let mut buf = vec![0u16; 1024];
    let mut len = buf.len() as u32;
    // SAFETY: buf points at a valid u16 slice, len holds capacity. On
    // success, len receives the actual character count (no null).
    let result = unsafe {
        QueryFullProcessImageNameW(
            process,
            PROCESS_NAME_FORMAT(0),
            PWSTR(buf.as_mut_ptr()),
            &mut len as *mut u32,
        )
    };
    if result.is_err() {
        return Err(ClientRejectReason::QueryImageNameFailed {
            code: unsafe { windows::Win32::Foundation::GetLastError().0 },
        });
    }
    buf.truncate(len as usize);
    let s = String::from_utf16_lossy(&buf);
    Ok(PathBuf::from(s))
}

fn open_process_token(process: HANDLE) -> Result<HANDLE, ClientRejectReason> {
    let mut token = HANDLE::default();
    // SAFETY: process is valid for the duration of this call; token out
    // pointer is on the stack.
    unsafe {
        OpenProcessToken(process, TOKEN_QUERY, &mut token as *mut HANDLE).map_err(|e| {
            ClientRejectReason::TokenQueryFailed {
                code: e.code().0 as u32,
            }
        })?;
    }
    Ok(token)
}

fn is_elevated(token: HANDLE) -> Result<bool, ClientRejectReason> {
    let mut elevation = TOKEN_ELEVATION::default();
    let mut returned = 0u32;
    // SAFETY: TOKEN_ELEVATION is a POD struct; we pass its size and a
    // valid pointer.
    unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned as *mut u32,
        )
        .map_err(|e| ClientRejectReason::TokenQueryFailed {
            code: e.code().0 as u32,
        })?;
    }
    Ok(elevation.TokenIsElevated != 0)
}

fn is_low_integrity(token: HANDLE) -> Result<bool, ClientRejectReason> {
    // First call to determine required size.
    let mut needed = 0u32;
    // SAFETY: nullable buffer, returned size goes to `needed`.
    let _ = unsafe {
        GetTokenInformation(token, TokenIntegrityLevel, None, 0, &mut needed as *mut u32)
    };
    if needed == 0 {
        return Err(ClientRejectReason::TokenQueryFailed {
            code: unsafe { windows::Win32::Foundation::GetLastError().0 },
        });
    }

    // SAFETY: pointer cast to TOKEN_MANDATORY_LABEL is well-defined because
    // the buffer is suitably aligned. Vec<u8>::as_mut_ptr is aligned to 1; the
    // struct requires alignment 8 — Win32 tolerates this for variable-sized
    // structs and returns the SID inline, but we allocate via Box<[u64]> for
    // 8-byte alignment to be safe.
    let mut aligned: Box<[u64]> = vec![0u64; (needed as usize).div_ceil(8)].into_boxed_slice();
    let aligned_ptr = aligned.as_mut_ptr() as *mut u8;
    // SAFETY: aligned_ptr points at `aligned.len() * 8` bytes which is at
    // least `needed`.
    unsafe {
        GetTokenInformation(
            token,
            TokenIntegrityLevel,
            Some(aligned_ptr as *mut _),
            needed,
            &mut needed as *mut u32,
        )
        .map_err(|e| ClientRejectReason::TokenQueryFailed {
            code: e.code().0 as u32,
        })?;
    }

    // Pull out the integrity level: the last sub-authority of the SID.
    // SAFETY: aligned holds a valid TOKEN_MANDATORY_LABEL followed by SID
    // sub-authorities. We use the windows crate helpers to read the SID
    // sub-authority count and the last sub-authority.
    let label = unsafe { &*(aligned_ptr as *const TOKEN_MANDATORY_LABEL) };
    let sid = label.Label.Sid;
    if sid.0.is_null() {
        return Err(ClientRejectReason::TokenQueryFailed { code: 0 });
    }
    // SAFETY: sid is non-null and points at a valid SID structure
    // returned by Win32.
    let rid = unsafe { extract_integrity_rid(sid) };

    // Per WinNT.h:
    //   SECURITY_MANDATORY_UNTRUSTED_RID = 0x0
    //   SECURITY_MANDATORY_LOW_RID       = 0x1000
    //   SECURITY_MANDATORY_MEDIUM_RID    = 0x2000
    //   SECURITY_MANDATORY_HIGH_RID      = 0x3000
    //   SECURITY_MANDATORY_SYSTEM_RID    = 0x4000
    Ok(rid <= 0x1000)
}

/// SAFETY: caller must pass a non-null PSID returned by Win32 that has a
/// valid sub-authority array.
unsafe fn extract_integrity_rid(sid: PSID) -> u32 {
    use windows::Win32::Security::{GetSidSubAuthority, GetSidSubAuthorityCount};
    let count_ptr = GetSidSubAuthorityCount(sid);
    if count_ptr.is_null() {
        return 0;
    }
    let count = *count_ptr;
    if count == 0 {
        return 0;
    }
    let last_index = (count - 1) as u32;
    let rid_ptr = GetSidSubAuthority(sid, last_index);
    if rid_ptr.is_null() {
        return 0;
    }
    *rid_ptr
}

/// Extract the caller's user SID as a string, used to key per-SID storage
/// and policy application.
///
/// Two-call pattern: first `GetTokenInformation(TokenUser, NULL, 0, &needed)`
/// to discover buffer size, then a second call to populate. The
/// `TOKEN_USER` struct's `User.Sid` is a `PSID` pointing into the same
/// buffer; we hand it to `ConvertSidToStringSidW` which allocates the
/// string with `LocalAlloc`, requiring `LocalFree` afterwards.
fn query_user_sid(token: HANDLE) -> Result<String, ClientRejectReason> {
    let mut needed = 0u32;
    // SAFETY: NULL buffer returns required size in `needed` and an error
    // (ERROR_INSUFFICIENT_BUFFER), which we ignore — only `needed` matters.
    let _ = unsafe { GetTokenInformation(token, TokenUser, None, 0, &mut needed as *mut u32) };
    if needed == 0 {
        return Err(ClientRejectReason::TokenQueryFailed {
            code: unsafe { windows::Win32::Foundation::GetLastError().0 },
        });
    }

    // 8-byte aligned buffer to hold TOKEN_USER + embedded SID bytes.
    let mut aligned: Box<[u64]> = vec![0u64; needed as usize / 8 + 1].into_boxed_slice();
    let buf_ptr = aligned.as_mut_ptr() as *mut u8;
    // SAFETY: buf_ptr points at `aligned.len() * 8 >= needed` bytes.
    unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            Some(buf_ptr as *mut _),
            needed,
            &mut needed as *mut u32,
        )
        .map_err(|e| ClientRejectReason::TokenQueryFailed {
            code: e.code().0 as u32,
        })?;
    }

    // SAFETY: TOKEN_USER is at offset 0 of the buffer. `User.Sid` is a
    // PSID pointing into the same buffer at the inline SID bytes.
    let token_user = unsafe { &*(buf_ptr as *const TOKEN_USER) };
    let psid: PSID = token_user.User.Sid;
    if psid.0.is_null() {
        return Err(ClientRejectReason::TokenQueryFailed { code: 0 });
    }

    let mut wide_ptr: PWSTR = PWSTR::null();
    // SAFETY: psid is a non-null PSID we just received from Win32; out
    // pointer receives a LocalAlloc'd UTF-16 string we must free.
    unsafe {
        ConvertSidToStringSidW(psid, &mut wide_ptr as *mut PWSTR).map_err(|e| {
            ClientRejectReason::TokenQueryFailed {
                code: e.code().0 as u32,
            }
        })?;
    }
    if wide_ptr.0.is_null() {
        return Err(ClientRejectReason::TokenQueryFailed { code: 0 });
    }

    // SAFETY: wide_ptr points at a null-terminated UTF-16 string allocated
    // by Win32 via LocalAlloc.
    let s = unsafe { read_pwstr_to_string(wide_ptr) };
    // SAFETY: wide_ptr was returned by ConvertSidToStringSidW which
    // documents LocalFree as the matching deallocation.
    unsafe {
        let _ = LocalFree(HLOCAL(wide_ptr.0 as _));
    }
    Ok(s)
}

/// SAFETY: `p` must be either null or a pointer to a null-terminated
/// UTF-16 string.
unsafe fn read_pwstr_to_string(p: PWSTR) -> String {
    if p.0.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    while *p.0.add(len) != 0 {
        len += 1;
    }
    let slice = std::slice::from_raw_parts(p.0, len);
    String::from_utf16_lossy(slice)
}

/// RAII wrapper that calls `CloseHandle` on drop.
struct HandleGuard(HANDLE);

impl Drop for HandleGuard {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: handle is one of: process handle from OpenProcess,
            // or token handle from OpenProcessToken. Both are closed via
            // CloseHandle.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whitelist_accepts_gui_exe() {
        assert_eq!(
            classify_exe_basename("NetRuleRouter.exe"),
            Some(IpcClientProfile::GuiInteractive)
        );
        assert_eq!(
            classify_exe_basename("netrulerouter.exe"),
            Some(IpcClientProfile::GuiInteractive)
        );
    }

    #[test]
    fn whitelist_accepts_tray_exe() {
        assert_eq!(
            classify_exe_basename("NetRuleRouterTray.exe"),
            Some(IpcClientProfile::TrayLightweight)
        );
    }

    #[test]
    fn whitelist_rejects_service_exe() {
        assert_eq!(classify_exe_basename("nrr-service.exe"), None);
        assert_eq!(classify_exe_basename("NRR-Service.exe"), None);
    }

    #[test]
    fn whitelist_rejects_arbitrary_exe() {
        assert_eq!(classify_exe_basename("powershell.exe"), None);
        assert_eq!(classify_exe_basename("cmd.exe"), None);
        assert_eq!(classify_exe_basename(""), None);
    }

    #[test]
    fn whitelist_is_case_insensitive() {
        assert_eq!(
            classify_exe_basename("NETRULEROUTER.EXE"),
            Some(IpcClientProfile::GuiInteractive)
        );
    }
}
