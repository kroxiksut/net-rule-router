//! Cross-platform spawn plumbing for the elevated broker: session-nonce
//! generation, the token-file handoff, and the one-shot UAC elevation.
//!
//! Elevation is delegated to PowerShell `Start-Process -Verb RunAs` (same
//! idiom the project already uses for the service installer and the old
//! one-shot path) so this crate needs no `unsafe` to raise the UAC prompt.
//! Unlike the retired one-shot mutation path, the spawn is NOT `-Wait`:
//! the broker is long-lived and must outlive the `Start-Process` call.
//!
//! ## Nonce secrecy
//!
//! The 256-bit session nonce never appears on the command line (which a
//! same-user process could observe). It is written to a token file in the
//! per-user temp directory and the broker deletes it immediately after
//! reading. The command line carries only the non-secret pipe name, the
//! parent PID, the client SID, and the token-file path.

use std::io;
use std::path::{Path, PathBuf};

/// Outcome of attempting to spawn the elevated broker.
#[derive(Debug)]
pub enum SpawnOutcome {
    /// The elevated process was launched. The caller must still confirm
    /// readiness by connecting to the broker pipe.
    Launched,
    /// The user dismissed the UAC prompt (or PowerShell refused to
    /// elevate). The caller surfaces a localizable "needs administrator".
    Declined,
    /// Local plumbing failure (could not even launch PowerShell).
    Failed(String),
}

/// Generate the 256-bit session nonce as lowercase hex.
pub fn generate_nonce() -> Result<String, io::Error> {
    random_hex(32)
}

/// Generate a short random suffix for the per-session pipe name. The pipe
/// name is not secret; this only avoids collisions with a stale broker.
pub fn generate_pipe_suffix() -> Result<String, io::Error> {
    random_hex(4)
}

fn random_hex(n_bytes: usize) -> Result<String, io::Error> {
    let mut buf = vec![0u8; n_bytes];
    getrandom::getrandom(&mut buf).map_err(|e| io::Error::other(format!("getrandom: {e}")))?;
    let mut s = String::with_capacity(n_bytes * 2);
    for b in buf {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    Ok(s)
}

/// Directory the broker uses for its temp artefacts (token file). Created
/// on demand; lives under the per-user temp root so default ACLs already
/// keep other interactive users out.
///
/// On Windows the root is the one the shell names, not `%TEMP%`: the elevated
/// broker inherits this user's environment, and a planted `%TEMP%` would point
/// an administrator's read and delete at a directory of the user's choosing.
pub fn broker_temp_dir() -> PathBuf {
    handoff::dir()
}

/// Write the nonce to a freshly named token file and return its path. The
/// caller passes the path to the broker; the broker reads and deletes it.
pub fn write_token_file(launcher_pid: u32, suffix: &str, nonce: &str) -> io::Result<PathBuf> {
    use std::io::Write;

    let dir = broker_temp_dir();
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("broker-{launcher_pid}-{suffix}.token"));
    // `create_new`, not a plain write: the directory is the user's own temp
    // root, readable by exactly the process class this nonce is meant to keep
    // out. A file already sitting at this name is not ours — writing into it
    // would hand the nonce to whoever placed it and keep their ACL. Failing is
    // the right answer; the suffix is random, so a collision means someone is
    // waiting for us.
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?;
    file.write_all(nonce.as_bytes())?;
    Ok(path)
}

/// Read and consume (delete) the nonce token file. Called by the ELEVATED
/// broker on a path inside a directory its unprivileged user controls, so a
/// link swapped in while the UAC prompt is up must not turn this into an
/// administrator's read or delete elsewhere. Deletion is best-effort.
pub fn read_and_delete_token_file(path: &Path) -> io::Result<String> {
    if !is_token_file_path(path) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("not a broker token file: {}", path.display()),
        ));
    }
    let nonce = handoff::take(path)?.trim().to_string();
    if nonce.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "broker token file was empty",
        ));
    }
    Ok(nonce)
}

/// Whether `path` has the shape [`write_token_file`] gives it. Narrows what a
/// redirected path could ever name to a token-shaped file in our directory.
fn is_token_file_path(path: &Path) -> bool {
    let named = path
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.starts_with("broker-") && n.ends_with(".token"));
    let in_our_dir = path.parent().and_then(Path::file_name) == broker_temp_dir().file_name();
    path.is_absolute() && named && in_our_dir
}

#[cfg(windows)]
mod handoff {
    use std::io;
    use std::path::{Path, PathBuf};

    /// Falls back to `%TEMP%` only when the shell cannot name the folder at
    /// all — a machine in that state has no better answer to offer.
    pub fn dir() -> PathBuf {
        nrr_platform_windows::pinned_file::handoff_dir().unwrap_or_else(|_| {
            std::env::temp_dir().join(nrr_shared::product_identity::PRODUCT_NAME)
        })
    }

    pub fn take(path: &Path) -> io::Result<String> {
        let root = nrr_platform_windows::pinned_file::user_temp_root()
            .unwrap_or_else(|_| std::env::temp_dir());
        nrr_platform_windows::pinned_file::take(&root, path)
    }
}

#[cfg(not(windows))]
mod handoff {
    use std::io;
    use std::path::{Path, PathBuf};

    pub fn dir() -> PathBuf {
        std::env::temp_dir().join(nrr_shared::product_identity::PRODUCT_NAME)
    }

    pub fn take(path: &Path) -> io::Result<String> {
        for p in [path.parent().unwrap_or(path), path] {
            if std::fs::symlink_metadata(p)?.file_type().is_symlink() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("token path is a link: {}", p.display()),
                ));
            }
        }
        let text = std::fs::read_to_string(path)?;
        let _ = std::fs::remove_file(path);
        Ok(text)
    }
}

/// Spawn the elevated broker via PowerShell `Start-Process -Verb RunAs`
/// (no `-Wait`). Returns [`SpawnOutcome::Launched`] when the elevation
/// succeeded, [`SpawnOutcome::Declined`] when the UAC prompt was dismissed,
/// and [`SpawnOutcome::Failed`] when PowerShell itself could not run.
/// Elevation is a Windows path: the broker exists to answer a UAC prompt, and
/// there is no cross-platform meaning for this call. On other systems the
/// elevated verb goes through `platform-api::elevation` instead.
#[cfg(windows)]
pub fn spawn_elevated_broker(exe: &Path, argv: &[String]) -> SpawnOutcome {
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};

    let command = nrr_platform_windows::elevation::start_elevated_script(exe, argv);
    // Absolute, never the bare name: this process RAISES the UAC prompt, and a
    // bare name resolves against a PATH any process of this user can prepend to.
    let mut cmd = Command::new(nrr_platform_windows::system_shell::system_powershell());
    cmd.args(["-NoProfile", "-NonInteractive", "-Command", &command])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    match cmd.status() {
        Ok(status) if status.success() => SpawnOutcome::Launched,
        // Non-zero exit overwhelmingly means the user dismissed UAC.
        Ok(_) => SpawnOutcome::Declined,
        Err(e) => SpawnOutcome::Failed(format!("spawn powershell: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_is_64_hex_chars() {
        let n = generate_nonce().expect("nonce");
        assert_eq!(n.len(), 64);
        assert!(n.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn two_nonces_differ() {
        assert_ne!(generate_nonce().unwrap(), generate_nonce().unwrap());
    }

    #[test]
    fn a_path_not_shaped_like_a_token_is_refused_untouched() {
        let dir = broker_temp_dir();
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("broker-shape-test.txt");
        std::fs::write(&path, "nonce").unwrap();
        assert!(read_and_delete_token_file(&path).is_err());
        assert!(path.exists(), "a refused path must not be deleted");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn token_file_round_trips_and_deletes() {
        let pid = std::process::id();
        let suffix = "testsuffix";
        let nonce = "abc123";
        let path = write_token_file(pid, suffix, nonce).expect("write token");
        assert!(path.exists());
        let read = read_and_delete_token_file(&path).expect("read token");
        assert_eq!(read, nonce);
        assert!(!path.exists(), "token file must be deleted after read");
    }

    #[test]
    fn empty_token_file_is_rejected() {
        let dir = broker_temp_dir();
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("broker-empty-test.token");
        std::fs::write(&path, "   ").unwrap();
        let result = read_and_delete_token_file(&path);
        assert!(result.is_err());
        assert!(!path.exists());
    }
}
