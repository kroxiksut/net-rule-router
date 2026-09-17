//! Service start-mode reconfiguration and the targeted `SERVICE_START`
//! grant.
//!
//! Two jobs, both reached ONLY through elevated subcommands (`install`,
//! `set-start-auto`, `set-start-demand`; the GUI dispatches them via the
//! session broker — never from the unprivileged GUI directly):
//!
//! 1. [`reconfigure_start_mode`] flips the SCM start type between
//!    `SERVICE_AUTO_START` (start with Windows) and `SERVICE_DEMAND_START`
//!    (start on app launch). [`query_start_mode`] reads it back for the GUI.
//! 2. [`grant_interactive_service_start`] adds a single `SERVICE_START` ACE for
//!    the well-known `INTERACTIVE` group on the service object's DACL, so the
//!    unprivileged launcher can start the service with no UAC prompt in EITHER
//!    start mode. The grant is targeted (one trustee, its default rights plus
//!    `SERVICE_START`) — never a blanket SDDL widening, and `SetEntriesInAclW`
//!    merges it into the existing DACL.
//!
//! The trustee is `INTERACTIVE`, not the console user's own SID: a per-SID
//! grant only ever accumulates — nothing removes it as users come and go — so
//! every account that has ever sat at the console would keep the right
//! permanently. The grant still resolves the console user via WTS
//! ([`console_session_user_sid`]) to retire any such legacy ACE — the
//! LocalSystem-only `WTSQueryUserToken` path is unusable here because these
//! verbs run elevated-as-admin, not as SYSTEM, and the session's logged-on
//! user is also the right principal under over-the-shoulder elevation (the
//! standard user at the console, not the admin whose credentials approved
//! the prompt).

#![allow(unsafe_code)]

use std::ffi::c_void;

use nrr_service_runtime::{ServiceStartMode, SERVICE_NAME};

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{LocalFree, BOOL, HANDLE, HLOCAL};
use windows::Win32::Security::Authorization::{
    SetEntriesInAclW, EXPLICIT_ACCESS_W, GRANT_ACCESS, NO_MULTIPLE_TRUSTEE, REVOKE_ACCESS,
    TRUSTEE_IS_SID, TRUSTEE_IS_USER, TRUSTEE_IS_WELL_KNOWN_GROUP, TRUSTEE_W,
};
use windows::Win32::Security::{
    CreateWellKnownSid, GetSecurityDescriptorDacl, InitializeSecurityDescriptor,
    LookupAccountNameW, SetSecurityDescriptorDacl, WinInteractiveSid, ACE_FLAGS, ACL,
    DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_DESCRIPTOR, SID_NAME_USE,
};
use windows::Win32::System::RemoteDesktop::{
    WTSDomainName, WTSFreeMemory, WTSGetActiveConsoleSessionId, WTSQuerySessionInformationW,
    WTSUserName, WTS_INFO_CLASS,
};
use windows::Win32::System::Services::{
    ChangeServiceConfigW, CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceConfigW,
    QueryServiceObjectSecurity, SetServiceObjectSecurity, ENUM_SERVICE_TYPE, QUERY_SERVICE_CONFIGW,
    SC_HANDLE, SC_MANAGER_CONNECT, SERVICE_AUTO_START, SERVICE_CHANGE_CONFIG, SERVICE_DEMAND_START,
    SERVICE_ERROR, SERVICE_QUERY_CONFIG,
};

/// `SERVICE_NO_CHANGE` — passed to `ChangeServiceConfigW` for every field we
/// are not modifying (we only touch the start type).
const SERVICE_NO_CHANGE: u32 = 0xFFFF_FFFF;
/// `SERVICE_START` access right (Win32 `SERVICE_START = 0x0010`).
const SERVICE_START_RIGHT: u32 = 0x0010;
/// What SCM's default DACL already lets `INTERACTIVE` do: query config and
/// status, enumerate dependents, interrogate, user-defined control, read the
/// descriptor. Restated because `SetEntriesInAclW` keys entries by trustee and
/// `INTERACTIVE` is that very trustee: an entry naming only `SERVICE_START`
/// would replace these, and the unprivileged GUI could not even read status.
const INTERACTIVE_DEFAULT_RIGHTS: u32 = 0x0001 | 0x0004 | 0x0008 | 0x0080 | 0x0100 | READ_CONTROL;
/// Standard rights needed to read + rewrite the service object's DACL.
const READ_CONTROL: u32 = 0x0002_0000;
const WRITE_DAC: u32 = 0x0004_0000;
/// `SECURITY_DESCRIPTOR_REVISION` for `InitializeSecurityDescriptor`.
const SD_REVISION: u32 = 1;
/// No active console session sentinel from `WTSGetActiveConsoleSessionId`.
const WTS_NO_SESSION: u32 = 0xFFFF_FFFF;

/// Errors from the start-mode reconfigure / grant flow. Each carries the Win32
/// error text so the elevated subcommand can print an actionable message.
#[derive(Debug)]
pub enum StartModeError {
    /// `OpenSCManagerW` failed (not elevated / SCM unreachable).
    OpenScm(String),
    /// `OpenServiceW` failed (service not installed / insufficient access).
    OpenService(String),
    /// `ChangeServiceConfigW` failed.
    Change(String),
    /// `QueryServiceConfigW` failed.
    Query(String),
    /// Could not resolve the interactive console user's SID.
    ResolveUser(String),
    /// A DACL read/modify/write step failed.
    Security(String),
}

impl std::fmt::Display for StartModeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OpenScm(s) => write!(f, "open SCM: {s}"),
            Self::OpenService(s) => write!(f, "open service: {s}"),
            Self::Change(s) => write!(f, "change service config: {s}"),
            Self::Query(s) => write!(f, "query service config: {s}"),
            Self::ResolveUser(s) => write!(f, "resolve console user: {s}"),
            Self::Security(s) => write!(f, "service DACL: {s}"),
        }
    }
}

impl std::error::Error for StartModeError {}

/// Null-terminated UTF-16 for the Win32 `*W` APIs.
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// RAII wrapper so every early return closes the handle exactly once.
struct ScHandle(SC_HANDLE);

impl Drop for ScHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: `self.0` was returned by Open{SCManager,Service}W and is
            // closed exactly once (this Drop runs once per wrapper).
            let _ = unsafe { CloseServiceHandle(self.0) };
        }
    }
}

/// Open the SCM and the NetRuleRouter service with `access`. The SCM handle is
/// returned alongside the service handle so both stay alive (and are dropped)
/// for the caller's scope.
fn open_service(access: u32) -> Result<(ScHandle, ScHandle), StartModeError> {
    // SAFETY: local active database; `SC_MANAGER_CONNECT` is the minimum to
    // open a named service. Write accesses downstream require elevation.
    let scm = unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT) }
        .map_err(|e| StartModeError::OpenScm(e.to_string()))?;
    let scm = ScHandle(scm);
    let name = to_wide(SERVICE_NAME);
    // SAFETY: `scm` is a live SCM handle; `name` is a NUL-terminated wide
    // string that outlives the call.
    let svc = unsafe { OpenServiceW(scm.0, PCWSTR(name.as_ptr()), access) }
        .map_err(|e| StartModeError::OpenService(e.to_string()))?;
    Ok((scm, ScHandle(svc)))
}

/// Flip the SCM start type. `WithWindows` → `SERVICE_AUTO_START`,
/// `OnAppLaunch` → `SERVICE_DEMAND_START`. Every other config field is left
/// untouched (`SERVICE_NO_CHANGE` / null). Requires `SERVICE_CHANGE_CONFIG`
/// access → an elevated caller.
pub fn reconfigure_start_mode(mode: ServiceStartMode) -> Result<(), StartModeError> {
    let (_scm, svc) = open_service(SERVICE_CHANGE_CONFIG)?;
    let start_type = match mode {
        ServiceStartMode::WithWindows => SERVICE_AUTO_START,
        ServiceStartMode::OnAppLaunch => SERVICE_DEMAND_START,
    };
    // SAFETY: `svc.0` is a live handle opened with CHANGE_CONFIG; every string
    // arg is null (= "no change") and `lptagid` is None.
    unsafe {
        ChangeServiceConfigW(
            svc.0,
            ENUM_SERVICE_TYPE(SERVICE_NO_CHANGE),
            start_type,
            SERVICE_ERROR(SERVICE_NO_CHANGE),
            PCWSTR::null(),
            PCWSTR::null(),
            None,
            PCWSTR::null(),
            PCWSTR::null(),
            PCWSTR::null(),
            PCWSTR::null(),
        )
    }
    .map_err(|e| StartModeError::Change(e.to_string()))?;
    Ok(())
}

/// Read the current SCM start type back. `SERVICE_DEMAND_START` →
/// `OnAppLaunch`; anything else (`SERVICE_AUTO_START`, boot/system) →
/// `WithWindows`. Needs only `SERVICE_QUERY_CONFIG`, available to
/// authenticated users, so the GUI can show the current mode unelevated.
pub fn query_start_mode() -> Result<ServiceStartMode, StartModeError> {
    let (_scm, svc) = open_service(SERVICE_QUERY_CONFIG)?;
    let mut needed: u32 = 0;
    // First call sizes the buffer: documented to fail with
    // ERROR_INSUFFICIENT_BUFFER while filling `needed`.
    // SAFETY: a None config + 0 size is the canonical sizing call.
    let _ = unsafe { QueryServiceConfigW(svc.0, None, 0, &mut needed) };
    if needed == 0 {
        return Err(StartModeError::Query("zero config size".into()));
    }
    // QUERY_SERVICE_CONFIGW embeds pointer fields → 8-byte alignment. Back it
    // with `u64` words so the cast pointer is correctly aligned.
    let words = needed.div_ceil(8) as usize;
    let mut buf = vec![0u64; words];
    let cfg = buf.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW;
    // SAFETY: `buf` is `needed` bytes (rounded up), 8-aligned; `cfg` is a valid
    // out-param and `needed` matches the buffer size.
    unsafe { QueryServiceConfigW(svc.0, Some(cfg), needed, &mut needed) }
        .map_err(|e| StartModeError::Query(e.to_string()))?;
    // SAFETY: on success `cfg` points at a populated QUERY_SERVICE_CONFIGW.
    let start_type = unsafe { (*cfg).dwStartType };
    Ok(if start_type == SERVICE_DEMAND_START {
        ServiceStartMode::OnAppLaunch
    } else {
        ServiceStartMode::WithWindows
    })
}

/// Query one WTS string property for `session_id` (e.g. the user / domain
/// name), returning an owned `String`. `None` on any failure or empty value.
fn wts_query_session_string(session_id: u32, info_class: WTS_INFO_CLASS) -> Option<String> {
    let mut p = PWSTR::null();
    let mut bytes: u32 = 0;
    // SAFETY: `hserver` = NULL (current server); `p`/`bytes` are valid
    // out-params. On success `p` is a WTS-allocated NUL-terminated wide string.
    let ok = unsafe {
        WTSQuerySessionInformationW(
            HANDLE::default(),
            session_id,
            info_class,
            &mut p,
            &mut bytes,
        )
    };
    if ok.is_err() || p.is_null() {
        return None;
    }
    // SAFETY: `p` is a valid NUL-terminated wide string allocated by WTS.
    let s = unsafe { p.to_string() }.ok().filter(|s| !s.is_empty());
    // SAFETY: free the WTS allocation exactly once.
    unsafe { WTSFreeMemory(p.0 as *mut c_void) };
    s
}

/// Binary SID of the well-known `INTERACTIVE` group (`S-1-5-4`): every session
/// logged on interactively, which is exactly who may launch the app.
fn interactive_group_sid() -> Result<Vec<u8>, StartModeError> {
    let mut len: u32 = 0;
    // Sizing call — a null buffer with a zero length fills `len` and fails.
    // SAFETY: out-params are valid; no buffer is written on the sizing call.
    let _ = unsafe {
        CreateWellKnownSid(
            WinInteractiveSid,
            PSID::default(),
            PSID::default(),
            &mut len,
        )
    };
    if len == 0 {
        return Err(StartModeError::Security(
            "could not size the INTERACTIVE SID".into(),
        ));
    }
    let mut sid = vec![0u8; len as usize];
    // SAFETY: `sid` is `len` bytes, sized by the call above.
    unsafe {
        CreateWellKnownSid(
            WinInteractiveSid,
            PSID::default(),
            PSID(sid.as_mut_ptr() as *mut c_void),
            &mut len,
        )
    }
    .map_err(|e| StartModeError::Security(format!("build INTERACTIVE SID: {e}")))?;
    Ok(sid)
}

/// Resolve the SID (binary form) of the user logged into the active physical
/// console session. Works from a non-SYSTEM elevated process: it reads the
/// session's logged-on account name (not a token) and looks up its SID, so the
/// principal is the interactive user even under over-the-shoulder elevation.
fn console_session_user_sid() -> Result<Vec<u8>, StartModeError> {
    // SAFETY: takes no args; returns the console session id or WTS_NO_SESSION.
    let session_id = unsafe { WTSGetActiveConsoleSessionId() };
    if session_id == WTS_NO_SESSION {
        return Err(StartModeError::ResolveUser(
            "no active console session".into(),
        ));
    }
    let user = wts_query_session_string(session_id, WTSUserName)
        .ok_or_else(|| StartModeError::ResolveUser("console session has no user".into()))?;
    let domain = wts_query_session_string(session_id, WTSDomainName).unwrap_or_default();
    let account = if domain.is_empty() {
        user
    } else {
        format!("{domain}\\{user}")
    };
    lookup_account_sid(&account)
}

/// `LookupAccountNameW` two-call wrapper returning the binary SID for
/// `account` ("DOMAIN\\User" or "User").
fn lookup_account_sid(account: &str) -> Result<Vec<u8>, StartModeError> {
    let acct_w = to_wide(account);
    let mut sid_len: u32 = 0;
    let mut dom_len: u32 = 0;
    let mut sid_use = SID_NAME_USE::default();
    // First call sizes the SID + referenced-domain buffers (expected to fail).
    // SAFETY: `sid = None` + zero lengths is the documented sizing call.
    let _ = unsafe {
        LookupAccountNameW(
            PCWSTR::null(),
            PCWSTR(acct_w.as_ptr()),
            PSID::default(),
            &mut sid_len,
            PWSTR::null(),
            &mut dom_len,
            &mut sid_use,
        )
    };
    if sid_len == 0 {
        return Err(StartModeError::ResolveUser(format!(
            "could not size SID for '{account}'"
        )));
    }
    let mut sid = vec![0u8; sid_len as usize];
    let mut dom = vec![0u16; dom_len.max(1) as usize];
    // SAFETY: both buffers were sized by the first call; all pointers are valid
    // and live for the call.
    unsafe {
        LookupAccountNameW(
            PCWSTR::null(),
            PCWSTR(acct_w.as_ptr()),
            PSID(sid.as_mut_ptr() as *mut c_void),
            &mut sid_len,
            PWSTR(dom.as_mut_ptr()),
            &mut dom_len,
            &mut sid_use,
        )
    }
    .map_err(|e| StartModeError::ResolveUser(format!("lookup '{account}': {e}")))?;
    Ok(sid)
}

/// Add the targeted `SERVICE_START` ACE for `INTERACTIVE` to the service DACL
/// (trustee rationale: module docs above). Idempotent: `SetEntriesInAclW`
/// folds the rights into the trustee's existing entry, so re-running never
/// stacks duplicate ACEs, and re-running on a DACL an earlier version cut
/// down restores the default rights.
///
/// Held in BOTH start modes, not only DemandStart: an operator who stops the
/// service (or whose service stopped on its own) would otherwise find the
/// GUI's own start button dead, with no way back short of an elevated
/// console. Starting an already-AutoStart service is not a privilege worth
/// withholding from whoever is sitting at the machine.
pub fn grant_interactive_service_start() -> Result<(), StartModeError> {
    let sid = interactive_group_sid()?;
    // Best-effort: an installation that predates the `INTERACTIVE` trustee
    // carries a per-user ACE granting the same right. `REVOKE_ACCESS` drops
    // EVERY entry for that trustee, which is the point — the personal grant is
    // exactly what the well-known group replaces.
    let legacy_sid = console_session_user_sid().ok();
    write_service_start_ace(&sid, legacy_sid.as_ref())
}

/// A DACL from `SetEntriesInAclW`, freed on every exit path.
struct DaclGuard(*mut ACL);

impl Drop for DaclGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `self.0` came from SetEntriesInAclW (LocalAlloc).
            let _ = unsafe { LocalFree(HLOCAL(self.0 as *mut c_void)) };
        }
    }
}

/// `old_dacl` plus `SERVICE_START` and the default rights for `sid`, minus
/// every entry for `legacy_sid`. Pure over its inputs so the merge is testable
/// against a synthetic DACL without touching the SCM.
fn merge_start_ace(
    old_dacl: Option<*const ACL>,
    sid: &[u8],
    legacy_sid: Option<&Vec<u8>>,
) -> Result<DaclGuard, StartModeError> {
    // `sid` / `legacy_sid` outlive this function, so the raw pointers stashed
    // in `Trustee.ptstrName` stay valid through the `SetEntriesInAclW` call.
    let mut entries = vec![EXPLICIT_ACCESS_W {
        grfAccessPermissions: SERVICE_START_RIGHT | INTERACTIVE_DEFAULT_RIGHTS,
        // GRANT, not SET: SET replaces the trustee's entry, and this trustee
        // is the `IU` of SCM's default DACL.
        grfAccessMode: GRANT_ACCESS,
        grfInheritance: ACE_FLAGS(0), // NO_INHERITANCE
        Trustee: TRUSTEE_W {
            pMultipleTrustee: std::ptr::null_mut(),
            MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_WELL_KNOWN_GROUP,
            // SAFETY contract: `ptstrName` for TRUSTEE_IS_SID is a PSID cast to
            // PWSTR. `sid` outlives the SetEntriesInAclW call below.
            ptstrName: PWSTR(sid.as_ptr() as *mut u16),
        },
    }];
    if let Some(legacy) = legacy_sid {
        entries.push(EXPLICIT_ACCESS_W {
            grfAccessPermissions: SERVICE_START_RIGHT,
            grfAccessMode: REVOKE_ACCESS,
            grfInheritance: ACE_FLAGS(0),
            Trustee: TRUSTEE_W {
                pMultipleTrustee: std::ptr::null_mut(),
                MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_USER,
                // SAFETY contract: as above; `legacy_sid` outlives the call.
                ptstrName: PWSTR(legacy.as_ptr() as *mut u16),
            },
        });
    }
    let mut new_dacl: *mut ACL = std::ptr::null_mut();
    // SAFETY: `entries` is fully initialised; `old_dacl`, when present, is a
    // valid ACL for the call; `new_dacl` is a valid out-param.
    let rc = unsafe { SetEntriesInAclW(Some(&entries), old_dacl, &mut new_dacl) };
    // `SetEntriesInAclW` returns a WIN32_ERROR (0 == ERROR_SUCCESS).
    if rc.0 != 0 {
        return Err(StartModeError::Security(format!(
            "SetEntriesInAcl failed (win32 {})",
            rc.0
        )));
    }
    Ok(DaclGuard(new_dacl))
}

/// Read the service DACL, add the `SERVICE_START` ACE for `sid`, revoke every
/// entry for `legacy_sid` if one was resolved, and write it back. All buffers
/// are held in scope until `SetServiceObjectSecurity` returns, because the old
/// DACL, the SIDs, and the new DACL are referenced by pointer along the way.
fn write_service_start_ace(sid: &[u8], legacy_sid: Option<&Vec<u8>>) -> Result<(), StartModeError> {
    let (_scm, svc) = open_service(READ_CONTROL | WRITE_DAC)?;

    // ── 1. Read the current self-relative security descriptor (DACL only). ──
    let mut needed: u32 = 0;
    // SAFETY: sizing call — null SD + 0 size fills `needed`.
    let _ = unsafe {
        QueryServiceObjectSecurity(
            svc.0,
            DACL_SECURITY_INFORMATION.0,
            PSECURITY_DESCRIPTOR::default(),
            0,
            &mut needed,
        )
    };
    if needed == 0 {
        return Err(StartModeError::Security("zero DACL size".into()));
    }
    // 8-byte aligned backing store for the self-relative SECURITY_DESCRIPTOR.
    let words = needed.div_ceil(8) as usize;
    let mut sd_buf = vec![0u64; words];
    let cur_sd = PSECURITY_DESCRIPTOR(sd_buf.as_mut_ptr() as *mut c_void);
    // SAFETY: `sd_buf` is `needed` bytes, 8-aligned; `cur_sd` + `needed` match.
    unsafe {
        QueryServiceObjectSecurity(
            svc.0,
            DACL_SECURITY_INFORMATION.0,
            cur_sd,
            needed,
            &mut needed,
        )
    }
    .map_err(|e| StartModeError::Security(format!("query object security: {e}")))?;

    // ── 2. Extract the existing DACL pointer (into `sd_buf`). ──
    let mut dacl_present = BOOL(0);
    let mut old_dacl: *mut ACL = std::ptr::null_mut();
    let mut dacl_defaulted = BOOL(0);
    // SAFETY: `cur_sd` is a valid self-relative SD; out-params are valid.
    unsafe {
        GetSecurityDescriptorDacl(
            cur_sd,
            &mut dacl_present,
            &mut old_dacl,
            &mut dacl_defaulted,
        )
    }
    .map_err(|e| StartModeError::Security(format!("get DACL: {e}")))?;

    let old_dacl_opt: Option<*const ACL> = if old_dacl.is_null() {
        None
    } else {
        Some(old_dacl as *const ACL)
    };
    // `old_dacl` points into `sd_buf`, which lives to the end of this function.
    let new_dacl_guard = merge_start_ace(old_dacl_opt, sid, legacy_sid)?;
    let new_dacl = new_dacl_guard.0;

    // ── 4. Build a fresh absolute SD carrying just the new DACL, write it. ──
    let mut new_sd = SECURITY_DESCRIPTOR::default();
    let new_psd = PSECURITY_DESCRIPTOR(&mut new_sd as *mut _ as *mut c_void);
    // SAFETY: `new_psd` points at a stack SECURITY_DESCRIPTOR we own.
    unsafe { InitializeSecurityDescriptor(new_psd, SD_REVISION) }
        .map_err(|e| StartModeError::Security(format!("init SD: {e}")))?;
    // SAFETY: attach the merged DACL (present=true, defaulted=false). `new_dacl`
    // outlives the SetServiceObjectSecurity call (held by the guard).
    unsafe { SetSecurityDescriptorDacl(new_psd, BOOL(1), Some(new_dacl as *const ACL), BOOL(0)) }
        .map_err(|e| StartModeError::Security(format!("set SD DACL: {e}")))?;
    // SAFETY: `svc.0` opened with WRITE_DAC; `new_psd` is a valid absolute SD.
    unsafe { SetServiceObjectSecurity(svc.0, DACL_SECURITY_INFORMATION, new_psd) }
        .map_err(|e| StartModeError::Security(format!("set object security: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW,
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows::Win32::Security::OBJECT_SECURITY_INFORMATION;

    /// The DACL of `sddl`, as SCM would hand it back for a service, plus the
    /// self-relative descriptor that owns it (leaked: test-lifetime).
    fn dacl_of(sddl: &str) -> (PSECURITY_DESCRIPTOR, *const ACL) {
        let wide = to_wide(sddl);
        let mut sd = PSECURITY_DESCRIPTOR::default();
        // SAFETY: `wide` is NUL-terminated; `sd` receives a LocalAlloc'd
        // descriptor.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(wide.as_ptr()),
                SDDL_REVISION_1,
                &mut sd,
                None,
            )
        }
        .expect("sddl");
        let mut present = BOOL(0);
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut defaulted = BOOL(0);
        // SAFETY: `sd` is a valid descriptor; out-params are valid locals.
        unsafe { GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted) }
            .expect("dacl");
        (sd, dacl as *const ACL)
    }

    fn sddl_of(dacl: *mut ACL) -> String {
        let mut sd = SECURITY_DESCRIPTOR::default();
        let psd = PSECURITY_DESCRIPTOR(&mut sd as *mut _ as *mut c_void);
        // SAFETY: `psd` is a stack descriptor owned here; `dacl` outlives the
        // conversion below.
        unsafe {
            InitializeSecurityDescriptor(psd, SD_REVISION).expect("init");
            SetSecurityDescriptorDacl(psd, BOOL(1), Some(dacl as *const ACL), BOOL(0))
                .expect("set dacl");
        }
        let mut text = PWSTR::null();
        let mut len = 0u32;
        // SAFETY: `psd` is valid; `text` receives a LocalAlloc'd string.
        unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                psd,
                SDDL_REVISION_1,
                OBJECT_SECURITY_INFORMATION(DACL_SECURITY_INFORMATION.0),
                &mut text,
                Some(&mut len),
            )
        }
        .expect("to sddl");
        // SAFETY: `text` is a valid NUL-terminated string from the call above.
        let out = unsafe { text.to_string() }.expect("utf16");
        // SAFETY: LocalAlloc'd by the conversion.
        let _ = unsafe { LocalFree(HLOCAL(text.0 as *mut c_void)) };
        out
    }

    /// SCM's default DACL for a new service, as `sc sdshow` prints it.
    const SCM_DEFAULT: &str = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)";

    #[test]
    fn the_grant_keeps_interactive_readable_and_adds_start() {
        let sid = interactive_group_sid().expect("interactive sid");
        let (_sd, old) = dacl_of(SCM_DEFAULT);
        let merged = merge_start_ace(Some(old), &sid, None).expect("merge");
        let text = sddl_of(merged.0);
        // LC (query status) is what the GUI's badge needs; RP is SERVICE_START.
        assert!(text.contains("CCLCSWRPLOCRRC;;;IU)"), "{text}");
        assert!(
            text.contains(";;;SY)") && text.contains(";;;BA)") && text.contains(";;;SU)"),
            "{text}"
        );
    }

    #[test]
    fn re_running_the_grant_repairs_a_dacl_cut_down_to_start_only() {
        let sid = interactive_group_sid().expect("interactive sid");
        let (_sd, old) = dacl_of("D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;RP;;;IU)");
        let merged = merge_start_ace(Some(old), &sid, None).expect("merge");
        let text = sddl_of(merged.0);
        assert!(text.contains("CCLCSWRPLOCRRC;;;IU)"), "{text}");
        assert_eq!(text.matches(";;;IU)").count(), 1, "{text}");
    }
}
