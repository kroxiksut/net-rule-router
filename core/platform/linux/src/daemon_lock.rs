//! One daemon per machine, decided before either touches the socket.
//!
//! A second `nrr-serviced run` used to unlink the live socket and bind its own:
//! the first daemon kept serving an anonymous inode, and two enforcement loops
//! rewrote one nft table. systemd guarantees one instance per unit, not one
//! per machine — a daemon started from a shell is outside that.
//!
//! Two checks, because each covers a hole in the other: an `flock` on a
//! private file beside the socket (released by the kernel however the holder
//! dies), and a connect to the socket (a live listener whose lock file was
//! removed still answers). Neither can be faked by another account: both live
//! in a directory only root can write, and a lock file anyone else could have
//! opened is refused rather than trusted.

#![cfg(target_os = "linux")]

use std::fs::{File, OpenOptions, TryLockError};
use std::io;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

/// Held for the daemon's lifetime; dropping it (or dying) releases the claim.
#[derive(Debug)]
pub struct DaemonLock {
    _file: File,
}

#[derive(Debug)]
pub enum DaemonLockError {
    /// A live daemon holds the lock, or answers on the socket.
    Held {
        detail: String,
    },
    /// The lock file is not one only this account could have opened, so a
    /// lock on it proves nothing and a lock held on it may be a stranger's.
    Untrusted {
        path: PathBuf,
        detail: String,
    },
    Io {
        path: PathBuf,
        error: io::Error,
    },
}

impl std::fmt::Display for DaemonLockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Held { detail } => write!(f, "another daemon is running: {detail}"),
            Self::Untrusted { path, detail } => write!(
                f,
                "refusing the instance lock {}: {detail}; remove it and start again",
                path.display()
            ),
            Self::Io { path, error } => write!(f, "{}: {error}", path.display()),
        }
    }
}

impl std::error::Error for DaemonLockError {}

/// The lock file that guards `socket`: same directory, same stem.
pub fn lock_path_for(socket: &Path) -> PathBuf {
    socket.with_extension("lock")
}

impl DaemonLock {
    /// Claim the machine for the daemon that serves `socket`.
    pub fn acquire(socket: &Path) -> Result<Self, DaemonLockError> {
        let path = lock_path_for(socket);
        let io_err = |error| DaemonLockError::Io {
            path: path.clone(),
            error,
        };
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(io_err)?;
        }
        // Refuse to follow a planted link to somewhere else.
        if std::fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_symlink()) {
            return Err(DaemonLockError::Untrusted {
                path,
                detail: "it is a symbolic link".to_owned(),
            });
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&path)
            .map_err(io_err)?;
        let meta = file.metadata().map_err(io_err)?;
        if let Some(detail) = untrusted_reason(&meta, effective_uid()) {
            return Err(DaemonLockError::Untrusted { path, detail });
        }
        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                return Err(DaemonLockError::Held {
                    detail: format!("{} is locked", path.display()),
                })
            }
            Err(TryLockError::Error(error)) => return Err(DaemonLockError::Io { path, error }),
        }
        if UnixStream::connect(socket).is_ok() {
            return Err(DaemonLockError::Held {
                detail: format!("{} answers", socket.display()),
            });
        }
        Ok(Self { _file: file })
    }
}

/// Why a lock file cannot be trusted, if it cannot.
fn untrusted_reason(meta: &std::fs::Metadata, euid: u32) -> Option<String> {
    if !meta.is_file() {
        return Some("it is not a regular file".to_owned());
    }
    if meta.uid() != euid {
        return Some(format!("it belongs to uid {}, not {euid}", meta.uid()));
    }
    let mode = meta.permissions().mode() & 0o777;
    (mode & 0o077 != 0).then(|| format!("its mode {mode:o} lets other accounts open it"))
}

#[allow(unsafe_code)]
fn effective_uid() -> u32 {
    // SAFETY: `geteuid` takes no arguments, cannot fail, and touches no memory.
    unsafe { libc::geteuid() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    fn socket_in(dir: &tempfile::TempDir) -> PathBuf {
        dir.path().join("service-v1.sock")
    }

    #[test]
    fn a_second_claim_is_refused_while_the_first_is_held() {
        let dir = tempfile::tempdir().expect("temp dir");
        let socket = socket_in(&dir);
        let first = DaemonLock::acquire(&socket).expect("first claim");
        assert!(matches!(
            DaemonLock::acquire(&socket),
            Err(DaemonLockError::Held { .. })
        ));
        // Positive control: released, it can be claimed again.
        drop(first);
        DaemonLock::acquire(&socket).expect("claim after release");
    }

    /// A daemon whose lock file was deleted is still alive on its socket.
    #[test]
    fn a_live_listener_is_refused_even_without_its_lock() {
        let dir = tempfile::tempdir().expect("temp dir");
        let socket = socket_in(&dir);
        let listener = UnixListener::bind(&socket).expect("bind");
        assert!(matches!(
            DaemonLock::acquire(&socket),
            Err(DaemonLockError::Held { .. })
        ));
        // A stale socket file with nobody behind it is not a daemon.
        drop(listener);
        assert!(socket.exists());
        DaemonLock::acquire(&socket).expect("claim over a stale socket");
    }

    /// A lock file other accounts can open is one a stranger may be holding.
    #[test]
    fn a_lock_file_others_could_open_is_refused() {
        let dir = tempfile::tempdir().expect("temp dir");
        let socket = socket_in(&dir);
        let path = lock_path_for(&socket);
        std::fs::write(&path, b"").expect("plant");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).expect("chmod");
        assert!(matches!(
            DaemonLock::acquire(&socket),
            Err(DaemonLockError::Untrusted { .. })
        ));

        std::fs::remove_file(&path).expect("remove");
        std::os::unix::fs::symlink(dir.path().join("elsewhere"), &path).expect("link");
        assert!(matches!(
            DaemonLock::acquire(&socket),
            Err(DaemonLockError::Untrusted { .. })
        ));
    }

    #[test]
    fn another_owner_is_named_as_the_reason() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("f");
        std::fs::write(&path, b"").expect("file");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        let meta = std::fs::metadata(&path).expect("stat");
        assert_eq!(untrusted_reason(&meta, meta.uid()), None);
        assert!(untrusted_reason(&meta, meta.uid().wrapping_add(1))
            .is_some_and(|r| r.contains("belongs to uid")));
    }
}
