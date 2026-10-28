//! The tray started in a user's own session, as one notice about a site.
//!
//! The service runs as LocalSystem: whatever it starts, it starts with that
//! trust in the user's name. So it starts only the tray beside its own binary,
//! and only while no account outside SYSTEM, Administrators and
//! TrustedInstaller could have replaced that file or planted one beside it,
//! judging that on it and every folder above it held open from the check until
//! it has started, with the token and environment of the user the event is
//! about.
#![allow(unsafe_code)]

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use nrr_platform_api::session_notice::{
    notice_site_argument, SiteNoticeLauncher, SiteNoticeRefused,
};
use nrr_shared::product_identity::BinaryRole;
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::{
    GetTokenInformation, TokenElevationType, TokenElevationTypeFull, TOKEN_ELEVATION_TYPE,
};
use windows::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
use windows::Win32::System::RemoteDesktop::WTSQueryUserToken;
use windows::Win32::System::Threading::{
    CreateProcessAsUserW, CREATE_UNICODE_ENVIRONMENT, PROCESS_INFORMATION, STARTUPINFOW,
};

use crate::trusted_location::{hold_chain, untrusted_writer_of, HeldChain};

/// [`SiteNoticeLauncher`] that starts the tray beside this binary.
pub struct WindowsSiteNotice {
    tray: Option<PathBuf>,
}

impl WindowsSiteNotice {
    pub fn beside_this_binary() -> Self {
        let tray = std::env::current_exe().ok().and_then(|exe| {
            exe.parent()
                .map(|dir| dir.join(BinaryRole::Tray.windows_file_name()))
        });
        Self { tray }
    }
}

/// The tray and every folder above it, held so that until it has started
/// nothing can rewrite it, move it aside, or rename or replace a folder on its
/// path.
#[derive(Debug)]
pub struct PinnedTray {
    held: HeldChain,
}

impl PinnedTray {
    /// Where the tray really is, every link resolved: the path judged and the
    /// one started.
    #[must_use]
    pub fn path(&self) -> &Path {
        self.held.path()
    }
}

fn pin_tray(tray: &Path) -> Result<PinnedTray, SiteNoticeRefused> {
    // Resolved first, so a short name or a link in the install path costs no
    // notice; the chain is then opened refusing any link, and judged on what
    // it holds.
    let resolved = std::fs::canonicalize(tray).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => SiteNoticeRefused::NotFound,
        _ => SiteNoticeRefused::Failed(format!("resolve {}: {e}", tray.display())),
    })?;
    if !std::fs::metadata(&resolved).is_ok_and(|m| m.is_file()) {
        return Err(SiteNoticeRefused::NotFound);
    }
    match hold_chain(&resolved) {
        Ok(Some(held)) => Ok(PinnedTray { held }),
        Ok(None) => Err(SiteNoticeRefused::NotFound),
        Err(why) => Err(SiteNoticeRefused::UntrustedLocation(why)),
    }
}

/// `tray`, held with its folders, when it is there and only trusted accounts
/// could change it, put a file beside it or replace a folder above it.
pub fn verified_tray(tray: &Path) -> Result<PinnedTray, SiteNoticeRefused> {
    let pinned = pin_tray(tray)?;
    match untrusted_writer_of(&pinned.held) {
        Ok(None) => Ok(pinned),
        Ok(Some(who)) => Err(SiteNoticeRefused::UntrustedLocation(who)),
        // A folder whose permissions cannot be read is not one we trust.
        Err(error) => Err(SiteNoticeRefused::UntrustedLocation(error)),
    }
}

impl SiteNoticeLauncher for WindowsSiteNotice {
    fn show_site_notice(&self, sid: &str, host: &str) -> Result<(), SiteNoticeRefused> {
        let argument = notice_site_argument(host).ok_or(SiteNoticeRefused::BadHost)?;
        let tray = verified_tray(self.tray.as_deref().ok_or(SiteNoticeRefused::NotFound)?)?;
        let session = crate::win32_ffi::console_session::attached_session_of(sid)
            .ok_or(SiteNoticeRefused::NoSession)?;
        start_in_session(session, sid, &tray, &argument)
    }
}

fn wide(text: &OsStr) -> Vec<u16> {
    text.encode_wide().chain(std::iter::once(0)).collect()
}

/// `\\?\C:\…` → `C:\…`: the form a command line's first argument takes.
fn plain(path: &Path) -> &OsStr {
    let text = path.as_os_str();
    match text.to_str().and_then(|t| t.strip_prefix(r"\\?\")) {
        Some(rest) if !rest.starts_with("UNC\\") => OsStr::new(rest),
        _ => text,
    }
}

/// A token handle, closed on drop.
struct OwnedToken(HANDLE);

impl Drop for OwnedToken {
    fn drop(&mut self) {
        // SAFETY: the handle came from WTSQueryUserToken and is closed once.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

fn session_token(session: u32, sid: &str) -> Result<OwnedToken, SiteNoticeRefused> {
    let mut raw = HANDLE::default();
    // SAFETY: `raw` is a valid out-param; on success it holds the primary
    // token of the session's user, owned by the guard below.
    unsafe { WTSQueryUserToken(session, &mut raw) }
        .map_err(|e| SiteNoticeRefused::Failed(format!("no token for the session: {e}")))?;
    let token = OwnedToken(raw);
    check_token(token.0, sid)?;
    Ok(token)
}

/// The token must be `sid`'s own — a session id can be freed and given to
/// someone else between the lookup and here — and never the elevated half of
/// an administrator's pair.
fn check_token(token: HANDLE, sid: &str) -> Result<(), SiteNoticeRefused> {
    // SAFETY: `token` is a live token handle the caller holds.
    let owner = unsafe { crate::win32_ffi::console_session::token_user_sid_string(token) }
        .ok_or_else(|| SiteNoticeRefused::Failed("the session's token names no user".into()))?;
    if !owner.eq_ignore_ascii_case(sid) {
        return Err(SiteNoticeRefused::NoSession);
    }
    let mut kind = TOKEN_ELEVATION_TYPE::default();
    let mut written = 0u32;
    // SAFETY: the buffer is one TOKEN_ELEVATION_TYPE of exactly the size passed.
    unsafe {
        GetTokenInformation(
            token,
            TokenElevationType,
            Some(std::ptr::from_mut(&mut kind).cast()),
            std::mem::size_of::<TOKEN_ELEVATION_TYPE>() as u32,
            &mut written,
        )
    }
    .map_err(|e| SiteNoticeRefused::Failed(format!("read the token's elevation: {e}")))?;
    if kind == TokenElevationTypeFull {
        return Err(SiteNoticeRefused::Failed(
            "the session's token is elevated".into(),
        ));
    }
    Ok(())
}

/// The user's own environment block, destroyed on drop. Never absent: without
/// it the child gets the service's variables, and a null token gives the
/// system's — either way a temp folder other users share.
struct UserEnvironment(*mut core::ffi::c_void);

impl UserEnvironment {
    fn of(token: HANDLE) -> Result<Self, SiteNoticeRefused> {
        if token.is_invalid() {
            return Err(SiteNoticeRefused::Failed(
                "no token for the environment".into(),
            ));
        }
        let mut block: *mut core::ffi::c_void = std::ptr::null_mut();
        // SAFETY: `token` is live; on success `block` is ours until dropped.
        unsafe { CreateEnvironmentBlock(&mut block, token, false) }
            .map_err(|e| SiteNoticeRefused::Failed(format!("no environment for the user: {e}")))?;
        if block.is_null() {
            return Err(SiteNoticeRefused::Failed(
                "no environment for the user".into(),
            ));
        }
        Ok(Self(block))
    }
}

impl Drop for UserEnvironment {
    fn drop(&mut self) {
        // SAFETY: the block came from CreateEnvironmentBlock and is freed once.
        let _ = unsafe { DestroyEnvironmentBlock(self.0) };
    }
}

fn start_in_session(
    session: u32,
    sid: &str,
    tray: &PinnedTray,
    argument: &str,
) -> Result<(), SiteNoticeRefused> {
    let token = session_token(session, sid)?;
    let environment = UserEnvironment::of(token.0)?;

    let program = plain(tray.path());
    let application = wide(program);
    let mut command_line =
        wide(format!("\"{}\" {argument}", Path::new(program).display()).as_ref());
    let directory = tray.path().parent().map(|d| wide(plain(d)));
    let mut desktop = wide(OsStr::new("winsta0\\default"));
    let startup = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        lpDesktop: PWSTR(desktop.as_mut_ptr()),
        ..Default::default()
    };
    let mut process = PROCESS_INFORMATION::default();
    // Windows starts a program only by name, never from a handle; the held
    // chain keeps that name leading to the judged file until the call returns.
    // SAFETY: every string is NUL-terminated and outlives the call; the
    // command-line buffer is writable as the API requires; the token and the
    // environment block are live until their guards drop after it. No handle
    // is inherited.
    let started = unsafe {
        CreateProcessAsUserW(
            token.0,
            PCWSTR(application.as_ptr()),
            PWSTR(command_line.as_mut_ptr()),
            None,
            None,
            false,
            CREATE_UNICODE_ENVIRONMENT,
            Some(environment.0.cast_const()),
            directory
                .as_ref()
                .map_or(PCWSTR::null(), |d| PCWSTR(d.as_ptr())),
            &startup,
            &mut process,
        )
    };
    if started.is_ok() {
        // SAFETY: both handles were returned by the call above; closed once.
        unsafe {
            let _ = CloseHandle(process.hThread);
            let _ = CloseHandle(process.hProcess);
        }
    }
    started.map_err(|e| SiteNoticeRefused::Failed(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Between the check and the start nothing may put another program, or a
    /// moved-aside one, where the checked tray was.
    #[test]
    fn a_tray_cannot_be_swapped_while_it_is_being_started() {
        let dir = tempfile::tempdir().expect("temp dir");
        let tray = dir.path().join(BinaryRole::Tray.windows_file_name());
        std::fs::write(&tray, b"MZ").expect("write");
        let pinned = pin_tray(&tray).expect("pinned");
        let canonical = std::fs::canonicalize(&tray).expect("canonical");
        assert_eq!(plain(pinned.path()), plain(&canonical));
        assert!(
            std::fs::write(&tray, b"planted").is_err(),
            "overwritten while held"
        );
        assert!(
            std::fs::rename(&tray, dir.path().join("aside.exe")).is_err(),
            "moved aside while held"
        );
        let moved = dir.path().with_extension("moved");
        assert!(
            std::fs::rename(dir.path(), &moved).is_err(),
            "its folder moved while held"
        );
        drop(pinned);
        std::fs::write(&tray, b"MZ again").expect("released after the start");
    }

    /// A token of whoever holds the session now, not the user the event is
    /// about, never starts anything.
    #[test]
    fn a_token_of_another_user_is_refused() {
        use windows::Win32::Security::TOKEN_QUERY;
        use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
        let mut token = HANDLE::default();
        // SAFETY: pseudo-handle of this process; `token` is closed below.
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }
            .expect("own token");
        let other = "S-1-5-21-1-2-3-4242";
        let verdict = check_token(token, other);
        let own = crate::win32_ffi::console_session::current_process_user_sid().expect("own SID");
        let own_verdict = check_token(token, &own);
        // SAFETY: closed once.
        let _ = unsafe { CloseHandle(token) };
        assert_eq!(verdict, Err(SiteNoticeRefused::NoSession));
        assert_ne!(
            own_verdict,
            Err(SiteNoticeRefused::NoSession),
            "the user's own token is theirs"
        );
    }

    /// Without the user's own block the child would get the system's
    /// variables, whose temp folder other users share.
    #[test]
    fn no_user_environment_is_a_refusal_not_the_systems() {
        assert!(UserEnvironment::of(HANDLE::default()).is_err());
    }

    /// A tray any user could replace would run with the service's trust in
    /// the user's session: it is never started.
    #[test]
    fn a_tray_in_a_folder_users_can_write_is_refused() {
        let dir = tempfile::tempdir().expect("temp dir");
        let tray = dir.path().join(BinaryRole::Tray.windows_file_name());
        std::fs::write(&tray, b"MZ").expect("write");
        match verified_tray(&tray) {
            Err(SiteNoticeRefused::UntrustedLocation(who)) => assert!(!who.is_empty()),
            other => panic!("planted tray accepted: {other:?}"),
        }
    }

    #[test]
    fn a_tray_that_is_not_there_is_not_found() {
        let dir = tempfile::tempdir().expect("temp dir");
        let verdict = verified_tray(&dir.path().join("NetRuleRouterTray.exe"));
        assert!(
            matches!(verdict, Err(SiteNoticeRefused::NotFound)),
            "{verdict:?}"
        );
    }

    /// A binary only administrators can change is accepted: the check does
    /// not refuse everything.
    #[test]
    fn a_binary_only_administrators_can_change_is_accepted() {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        let notepad = Path::new(&root).join("System32").join("notepad.exe");
        assert!(
            verified_tray(&notepad).is_ok(),
            "{:?}",
            verified_tray(&notepad)
        );
    }

    #[test]
    fn a_hostile_host_never_reaches_the_command_line() {
        let launcher = WindowsSiteNotice {
            tray: Some(PathBuf::from(r"C:\nowhere\NetRuleRouterTray.exe")),
        };
        assert_eq!(
            launcher.show_site_notice("S-1-5-21-1-2-3-1001", "a.example\" --qml=x"),
            Err(SiteNoticeRefused::BadHost)
        );
    }
}
