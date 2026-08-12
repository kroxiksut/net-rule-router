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
use std::process::{Command, Stdio};

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
pub fn broker_temp_dir() -> PathBuf {
    std::env::temp_dir().join("NetRuleRouter")
}

/// Write the nonce to a freshly named token file and return its path. The
/// caller passes the path to the broker; the broker reads and deletes it.
pub fn write_token_file(launcher_pid: u32, suffix: &str, nonce: &str) -> io::Result<PathBuf> {
    let dir = broker_temp_dir();
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("broker-{launcher_pid}-{suffix}.token"));
    std::fs::write(&path, nonce)?;
    Ok(path)
}

/// Read and consume (delete) the nonce token file. Called by the broker on
/// startup. Deletion is best-effort — a leftover empty file is harmless.
pub fn read_and_delete_token_file(path: &Path) -> io::Result<String> {
    let nonce = std::fs::read_to_string(path)?.trim().to_string();
    let _ = std::fs::remove_file(path);
    if nonce.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "broker token file was empty",
        ));
    }
    Ok(nonce)
}

/// Spawn the elevated broker via PowerShell `Start-Process -Verb RunAs`
/// (no `-Wait`). Returns [`SpawnOutcome::Launched`] when the elevation
/// succeeded, [`SpawnOutcome::Declined`] when the UAC prompt was dismissed,
/// and [`SpawnOutcome::Failed`] when PowerShell itself could not run.
pub fn spawn_elevated_broker(exe: &Path, argv: &[String]) -> SpawnOutcome {
    let exe_ps = ps_single_quote(&exe.to_string_lossy());
    let arg_list = argv
        .iter()
        .map(|a| ps_single_quote(a))
        .collect::<Vec<_>>()
        .join(",");
    // `-Wait` is deliberately absent: the broker must survive this call.
    // `$ErrorActionPreference='Stop'` + `-NonInteractive` makes a declined
    // UAC (ERROR_CANCELLED) surface as a non-zero PowerShell exit code.
    let command = format!(
        "$ErrorActionPreference='Stop'; \
         Start-Process -FilePath {exe_ps} -ArgumentList @({arg_list}) -Verb RunAs"
    );
    let mut cmd = Command::new("powershell");
    cmd.args(["-NoProfile", "-NonInteractive", "-Command", &command])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    match cmd.status() {
        Ok(status) if status.success() => SpawnOutcome::Launched,
        // Non-zero exit overwhelmingly means the user dismissed UAC.
        Ok(_) => SpawnOutcome::Declined,
        Err(e) => SpawnOutcome::Failed(format!("spawn powershell: {e}")),
    }
}

/// Quote a string as a PowerShell single-quoted literal (doubling embedded
/// single quotes). Prevents injection through the `-Command` string.
fn ps_single_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
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
    fn ps_single_quote_doubles_embedded_quotes() {
        assert_eq!(ps_single_quote("C:/a/b.exe"), "'C:/a/b.exe'");
        assert_eq!(ps_single_quote("it's"), "'it''s'");
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
