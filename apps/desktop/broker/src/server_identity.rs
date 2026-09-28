//! Is the process serving the broker pipe the broker this launcher started?
//!
//! The pipe name is on the elevation command line before the user answers the
//! prompt, so a process of the same user can take it first. The real broker
//! then fails to start and the squatter would answer every call. The launcher
//! closes that gap before its first byte — the nonce included — by checking
//! that the server is an elevated copy of its own executable.

use std::path::{Path, PathBuf};

/// What the OS reports about the server end of the pipe. Each query can fail
/// on its own; the Win32 code is kept for the message.
#[derive(Debug)]
pub struct ServerFacts {
    pub pid: u32,
    pub image: Result<PathBuf, u32>,
    pub elevated: Result<bool, u32>,
    /// String SID owning the pipe object — its creator's default owner.
    pub pipe_owner: Result<String, u32>,
}

/// Owners only an elevated administrator or the system can give an object:
/// a non-elevated token holds Administrators as deny-only and cannot assign it.
const ELEVATED_OWNERS: &[&str] = &["S-1-5-18", "S-1-5-32-544"];

/// Why the pipe server is not our broker, or `None` when it is.
///
/// `own_exe` is the launcher's executable: the broker is that same binary
/// started elevated, so any other image — or ours without elevation — is not
/// it. When the server process cannot be opened at all — a standard user whose
/// prompt was answered with another account's credentials — the pipe's owner
/// stands in for the elevation read.
pub fn impostor_reason(own_exe: &Path, server: &ServerFacts) -> Option<String> {
    let pid = server.pid;
    if let Ok(image) = &server.image {
        if !same_path(own_exe, image) {
            return Some(format!(
                "the broker pipe is served by process {pid} running {}, not {}",
                image.display(),
                own_exe.display()
            ));
        }
    }
    match (&server.image, &server.elevated) {
        (Ok(_), Ok(true)) => None,
        (Ok(_), Ok(false)) => Some(format!(
            "the broker pipe is served by process {pid}, which is not elevated"
        )),
        (Err(code), _) | (_, Err(code)) if is_access_denied(*code) => {
            elevated_owner_reason(pid, &server.pipe_owner)
        }
        (Err(code), _) | (_, Err(code)) => Some(format!(
            "could not inspect broker pipe server process {pid} (Win32 0x{code:08X})"
        )),
    }
}

fn elevated_owner_reason(pid: u32, pipe_owner: &Result<String, u32>) -> Option<String> {
    match pipe_owner {
        Ok(sid) if ELEVATED_OWNERS.iter().any(|o| o.eq_ignore_ascii_case(sid)) => None,
        Ok(sid) => Some(format!(
            "broker pipe server process {pid} cannot be inspected and its pipe is owned by \
             {sid}, not by an administrator"
        )),
        Err(code) => Some(format!(
            "broker pipe server process {pid} cannot be inspected, nor its pipe's owner \
             (Win32 0x{code:08X})"
        )),
    }
}

/// `ERROR_ACCESS_DENIED`, bare or wrapped as an HRESULT.
fn is_access_denied(code: u32) -> bool {
    code == 5 || code == 0x8007_0005
}

/// Path equality as Windows sees it: one separator, no verbatim prefix, and
/// case-insensitive, since both sides may come from different APIs.
fn same_path(left: &Path, right: &Path) -> bool {
    comparable(left) == comparable(right)
}

fn comparable(path: &Path) -> String {
    let text = path.to_string_lossy();
    let text = text.strip_prefix(r"\\?\").unwrap_or(&text);
    if cfg!(windows) {
        text.replace('/', "\\").to_lowercase()
    } else {
        text.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OWN: &str = r"C:\Program Files\NetRuleRouter\NetRuleRouter.exe";
    const USER: &str = "S-1-5-21-1-2-3-1001";
    const ADMINS: &str = "S-1-5-32-544";
    const DENIED: u32 = 5;

    fn facts(image: Result<&str, u32>, elevated: Result<bool, u32>) -> ServerFacts {
        ServerFacts {
            pid: 4242,
            image: image.map(PathBuf::from),
            elevated,
            pipe_owner: Ok(USER.to_string()),
        }
    }

    fn owned_by(mut facts: ServerFacts, owner: Result<&str, u32>) -> ServerFacts {
        facts.pipe_owner = owner.map(str::to_string);
        facts
    }

    #[test]
    fn an_elevated_copy_of_our_own_binary_is_the_broker() {
        assert_eq!(
            impostor_reason(Path::new(OWN), &facts(Ok(OWN), Ok(true))),
            None
        );
    }

    #[test]
    fn another_binary_is_refused_even_when_elevated() {
        let reason = impostor_reason(
            Path::new(OWN),
            &facts(Ok(r"C:\Users\Public\squatter.exe"), Ok(true)),
        );
        assert!(reason.is_some_and(|r| r.contains("squatter.exe")));
    }

    /// The same user can start our binary at will; only UAC can elevate it.
    #[test]
    fn our_own_binary_without_elevation_is_refused() {
        assert!(impostor_reason(Path::new(OWN), &facts(Ok(OWN), Ok(false))).is_some());
        let admin_owned = owned_by(facts(Ok(OWN), Ok(false)), Ok(ADMINS));
        assert!(
            impostor_reason(Path::new(OWN), &admin_owned).is_some(),
            "a readable 'not elevated' is final; the owner is only a fallback"
        );
    }

    #[test]
    fn a_server_that_cannot_be_inspected_fails_closed() {
        assert!(impostor_reason(Path::new(OWN), &facts(Err(6), Ok(true))).is_some());
        assert!(impostor_reason(Path::new(OWN), &facts(Ok(OWN), Err(6))).is_some());
    }

    /// Another account's elevated process cannot be opened by a standard user;
    /// only an elevated administrator could have made Administrators the owner.
    #[test]
    fn an_unopenable_server_is_accepted_only_behind_an_administrator_owned_pipe() {
        let unopenable = || facts(Err(DENIED), Err(DENIED));
        assert_eq!(
            impostor_reason(Path::new(OWN), &owned_by(unopenable(), Ok(ADMINS))),
            None
        );
        assert_eq!(
            impostor_reason(Path::new(OWN), &owned_by(unopenable(), Ok("S-1-5-18"))),
            None
        );
        assert!(impostor_reason(Path::new(OWN), &owned_by(unopenable(), Ok(USER))).is_some());
        assert!(impostor_reason(Path::new(OWN), &owned_by(unopenable(), Err(DENIED))).is_some());
        let hresult = owned_by(facts(Ok(OWN), Err(0x8007_0005)), Ok(ADMINS));
        assert_eq!(impostor_reason(Path::new(OWN), &hresult), None);
    }

    #[test]
    fn a_foreign_image_is_refused_whatever_owns_the_pipe() {
        let foreign = owned_by(
            facts(Ok(r"C:\Users\Public\squatter.exe"), Err(DENIED)),
            Ok(ADMINS),
        );
        assert!(impostor_reason(Path::new(OWN), &foreign).is_some());
    }

    #[cfg(windows)]
    #[test]
    fn spelling_differences_of_the_same_path_are_not_a_mismatch() {
        let verbatim = r"\\?\c:\program files\netrulerouter\NETRULEROUTER.EXE";
        assert_eq!(
            impostor_reason(Path::new(OWN), &facts(Ok(verbatim), Ok(true))),
            None
        );
        let slashes = "C:/Program Files/NetRuleRouter/NetRuleRouter.exe";
        assert_eq!(
            impostor_reason(Path::new(OWN), &facts(Ok(slashes), Ok(true))),
            None
        );
    }

    /// The tray starts its broker from its own binary; the GUI's broker is not
    /// the tray's.
    #[test]
    fn a_sibling_product_binary_is_not_our_broker() {
        let tray = r"C:\Program Files\NetRuleRouter\NetRuleRouterTray.exe";
        assert!(impostor_reason(Path::new(OWN), &facts(Ok(tray), Ok(true))).is_some());
    }
}
