//! Linux mechanism behind the single-instance port: a datagram socket bound at
//! `<runtime dir>/<key>.sock`.
//!
//! A bound socket is held by the kernel for exactly as long as a descriptor for
//! it is open, so the claim ends when the owner dies, kill -9 included. It lives
//! in the user's private runtime directory (`$XDG_RUNTIME_DIR`: 0700, wiped by
//! logind at logout) rather than in the abstract namespace, which is
//! machine-wide and has no permissions: any local user could bind our name
//! first and keep our GUI "already running" forever.
//!
//! A file can be deleted while its socket lives on, the incident `flock` was
//! rejected for. Two checks keep that from making a second primary: a name that
//! is taken is probed with `connect` (a live socket answers, a leftover file
//! refuses), and a successful bind looks for another live socket at the same
//! path in `/proc/net/unix` — trusted only when nobody else could ever have
//! bound there.

#![cfg(target_os = "linux")]

use std::fs::File;
use std::io::{self, ErrorKind};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};

use nrr_platform_api::error::PlatformError;
use nrr_platform_api::single_instance::{SingleInstanceClaim, SingleInstancePort};

/// Binds `<user runtime dir>/<key>.sock`.
#[derive(Debug, Default)]
pub struct LinuxSingleInstance;

impl SingleInstancePort for LinuxSingleInstance {
    fn claim(&self, key: &str) -> Result<Option<Box<dyn SingleInstanceClaim>>, PlatformError> {
        let dir = nrr_platform_api::paths::ensure_user_runtime_dir().map_err(|e| {
            failure(
                "single-instance runtime dir",
                nrr_platform_api::paths::user_runtime_dir(),
                &e,
            )
        })?;
        claim_in(&dir, key)
    }
}

/// Holding the socket IS the claim. The file goes with it, but only if the path
/// still names our socket: after a deletion it may be another owner's.
struct SocketClaim {
    _socket: UnixDatagram,
    path: PathBuf,
    node: (u64, u64),
}

impl SingleInstanceClaim for SocketClaim {}

impl Drop for SocketClaim {
    fn drop(&mut self) {
        if node_at(&self.path) == Some(self.node) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

fn claim_in(dir: &Path, key: &str) -> Result<Option<Box<dyn SingleInstanceClaim>>, PlatformError> {
    if key.is_empty() || key.starts_with('.') || key.contains(['/', '\0']) {
        return Err(PlatformError::Transient {
            operation: "single-instance key",
            detail: format!("{key:?} is not a plain file name"),
        });
    }
    let path = dir.join(format!("{key}.sock"));
    let fail = |operation: &'static str| {
        let path = &path;
        move |e: io::Error| failure(operation, path, &e)
    };

    // Everything below trusts that only this user can create names here.
    nrr_platform_api::paths::ensure_private_dir(dir)
        .map_err(fail("single-instance runtime dir"))?;
    // Serialises launches: two of them reclaiming the same leftover file would
    // otherwise each unlink the other's fresh socket.
    let serial = File::open(dir).map_err(fail("single-instance serialise"))?;
    serial.lock().map_err(fail("single-instance serialise"))?;

    for _ in 0..2 {
        match UnixDatagram::bind(&path) {
            Ok(socket) => {
                let node = node_at(&path)
                    .ok_or_else(|| io::Error::from(ErrorKind::NotFound))
                    .map_err(fail("single-instance bind"))?;
                if listing_is_trusted(dir)
                    && another_socket_is_bound_at(&path).map_err(fail("single-instance probe"))?
                {
                    // The owner's file was deleted under it; ours goes, it stays.
                    let _ = std::fs::remove_file(&path);
                    return Ok(None);
                }
                return Ok(Some(Box::new(SocketClaim {
                    _socket: socket,
                    path,
                    node,
                })));
            }
            Err(e) if e.kind() == ErrorKind::AddrInUse => {
                if owner_answers(&path).map_err(fail("single-instance probe"))? {
                    return Ok(None);
                }
                remove_leftover(&path).map_err(fail("single-instance reclaim"))?;
            }
            Err(e) => return Err(fail("single-instance bind")(e)),
        }
    }
    Err(failure(
        "single-instance bind",
        &path,
        &io::Error::from(ErrorKind::AddrInUse),
    ))
}

/// A live socket accepts the connection; a file whose socket is gone refuses it.
fn owner_answers(path: &Path) -> io::Result<bool> {
    let probe = UnixDatagram::unbound()?;
    match probe.connect(path) {
        Ok(()) => Ok(true),
        Err(e) if matches!(e.kind(), ErrorKind::ConnectionRefused | ErrorKind::NotFound) => {
            Ok(false)
        }
        Err(e) => Err(e),
    }
}

/// Unlinks a dead socket file of ours. Anything else under our name is not ours
/// to delete: the caller reports it and the launcher falls back.
fn remove_leftover(path: &Path) -> io::Result<()> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    if !meta.file_type().is_socket() || meta.uid() != effective_uid() {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "the name is taken by something that is not our socket",
        ));
    }
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

/// `/proc/net/unix` names bound paths but not who bound them, so an entry proves
/// a live owner only where nobody but us could ever have created that path: a
/// private directory inside another private one (`/run/user/<uid>`). Under a
/// shared parent (`/tmp`) someone could have bound there before the directory
/// was ours, and trusting the listing would hand them the veto the abstract
/// name gave.
fn listing_is_trusted(dir: &Path) -> bool {
    let Some(parent) = dir.parent() else {
        return false;
    };
    std::fs::symlink_metadata(parent).is_ok_and(|meta| {
        meta.is_dir() && meta.uid() == effective_uid() && meta.mode() & 0o077 == 0
    })
}

fn another_socket_is_bound_at(path: &Path) -> io::Result<bool> {
    let table = std::fs::read("/proc/net/unix")?;
    Ok(bound_count(&table, path) > 1)
}

/// Sockets bound at `path` in a `/proc/net/unix` table. The path is the last
/// field and may hold spaces, so a line is matched on its tail.
fn bound_count(table: &[u8], path: &Path) -> usize {
    use std::os::unix::ffi::OsStrExt;
    let mut tail = Vec::with_capacity(path.as_os_str().len() + 1);
    tail.push(b' ');
    tail.extend_from_slice(path.as_os_str().as_bytes());
    table
        .split(|&b| b == b'\n')
        .filter(|line| line.ends_with(&tail))
        .count()
}

fn node_at(path: &Path) -> Option<(u64, u64)> {
    std::fs::symlink_metadata(path)
        .ok()
        .map(|meta| (meta.dev(), meta.ino()))
}

fn failure(operation: &'static str, path: impl AsRef<Path>, e: &io::Error) -> PlatformError {
    PlatformError::Transient {
        operation,
        detail: format!("{}: {e}", path.as_ref().display()),
    }
}

#[allow(unsafe_code)]
fn effective_uid() -> u32 {
    // SAFETY: `geteuid` takes no arguments, cannot fail, and touches no memory.
    unsafe { libc::geteuid() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    use std::os::unix::net::{SocketAddr, UnixListener};
    use std::time::{Duration, Instant};

    fn private_dir(parent: &Path, name: &str) -> PathBuf {
        let dir = parent.join(name);
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .expect("create private dir");
        dir
    }

    /// A runtime directory inside a private parent, as `/run/user/<uid>` is.
    fn runtime_dir() -> (tempfile::TempDir, PathBuf) {
        let base = tempfile::tempdir().expect("tempdir");
        std::fs::set_permissions(base.path(), std::fs::Permissions::from_mode(0o700))
            .expect("chmod");
        let dir = private_dir(base.path(), "rt");
        (base, dir)
    }

    fn claim_within(
        dir: &Path,
        key: &str,
        budget: Duration,
    ) -> Option<Box<dyn SingleInstanceClaim>> {
        let deadline = Instant::now() + budget;
        loop {
            match claim_in(dir, key).expect("claim succeeds") {
                Some(claim) => return Some(claim),
                None if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
                None => return None,
            }
        }
    }

    #[test]
    fn second_claim_of_the_same_key_is_refused_while_the_first_is_held() {
        let (_base, dir) = runtime_dir();
        let first = claim_in(&dir, "gui").expect("claim succeeds");
        assert!(first.is_some(), "an unclaimed key must be claimable");
        let second = claim_in(&dir, "gui").expect("claim succeeds");
        assert!(second.is_none(), "a held key must refuse a second claim");
        drop(first);
        assert!(
            !dir.join("gui.sock").exists(),
            "releasing the claim removes its own file"
        );
        // A `Command::spawn` in a parallel test forks this process and can hold
        // a copy of the descriptor until its exec; production never forks it.
        let third = claim_within(&dir, "gui", Duration::from_secs(2));
        assert!(third.is_some(), "releasing the claim must free the key");
    }

    /// The hijack this mechanism replaced: another user binding our old
    /// abstract name no longer has any say over our claim.
    #[test]
    fn a_squatted_abstract_name_does_not_block_the_claim() {
        let (_base, dir) = runtime_dir();
        let key = format!("squat-{}", std::process::id());
        let name = format!("netrulerouter.{}.{key}", effective_uid());
        let addr = SocketAddr::from_abstract_name(name.as_bytes()).expect("abstract name");
        let _squatter = UnixListener::bind_addr(&addr).expect("squatter binds the old name");
        let claim = claim_in(&dir, &key).expect("claim succeeds");
        assert!(
            claim.is_some(),
            "a squatted abstract name must not block us"
        );
    }

    #[test]
    fn a_stale_socket_file_is_reclaimed() {
        let (_base, dir) = runtime_dir();
        let path = dir.join("tray.sock");
        drop(UnixDatagram::bind(&path).expect("previous owner binds"));
        assert!(path.exists(), "a dead owner leaves its file behind");
        let claim = claim_in(&dir, "tray").expect("claim succeeds");
        assert!(
            claim.is_some(),
            "a file with no live socket must be reclaimed"
        );
    }

    /// The incident a lock file could not survive: the owner's file deleted
    /// while it runs must not make the next launch a second primary.
    #[test]
    fn deleting_the_socket_file_does_not_make_a_second_primary() {
        let (_base, dir) = runtime_dir();
        let _primary = claim_in(&dir, "gui")
            .expect("claim succeeds")
            .expect("primary");
        std::fs::remove_file(dir.join("gui.sock")).expect("the user deletes the file");
        let second = claim_in(&dir, "gui").expect("claim succeeds");
        assert!(second.is_none(), "the primary still holds the socket");
        assert!(
            !dir.join("gui.sock").exists(),
            "the refused claim leaves no file of its own"
        );
    }

    #[test]
    fn a_runtime_dir_open_to_other_users_is_refused() {
        let base = tempfile::tempdir().expect("tempdir");
        let dir = base.path().join("rt");
        std::fs::create_dir(&dir).expect("create");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).expect("chmod");
        assert!(claim_in(&dir, "gui").is_err());
        assert!(!dir.join("gui.sock").exists(), "nothing is bound in it");
    }

    #[test]
    fn a_runtime_dir_owned_by_someone_else_is_refused() {
        // `/` is root's and 0755: refused for its owner or, as root, its mode.
        assert!(claim_in(Path::new("/"), "gui").is_err());
    }

    #[test]
    fn a_name_taken_by_something_that_is_not_a_socket_is_left_alone() {
        let (_base, dir) = runtime_dir();
        let path = dir.join("gui.sock");
        std::fs::write(&path, b"not a socket").expect("plant a file");
        assert!(claim_in(&dir, "gui").is_err(), "reported, not deleted");
        assert!(path.is_file(), "the file is not ours to remove");
    }

    #[test]
    fn a_shared_parent_makes_the_listing_untrusted() {
        let base = tempfile::tempdir().expect("tempdir");
        std::fs::set_permissions(base.path(), std::fs::Permissions::from_mode(0o1777))
            .expect("chmod");
        let dir = private_dir(base.path(), "rt");
        assert!(!listing_is_trusted(&dir));
        let (_private, trusted) = runtime_dir();
        assert!(listing_is_trusted(&trusted));
    }

    #[test]
    fn keys_that_are_not_plain_names_are_refused() {
        let (_base, dir) = runtime_dir();
        for key in ["", ".", "..", "../gui", "a/b", ".hidden"] {
            assert!(claim_in(&dir, key).is_err(), "{key:?} must be refused");
        }
    }

    #[test]
    fn the_listing_is_matched_on_the_whole_path() {
        let table = b"Num       RefCount Protocol Flags    Type St Inode Path\n\
            0000000000000000: 00000002 00000000 00010000 0002 01 16085 /run/user/1000/netrulerouter/gui.sock\n\
            0000000000000000: 00000002 00000000 00010000 0002 01  8904 /run/user/1000/netrulerouter/gui.sock\n\
            0000000000000000: 00000002 00000000 00010000 0002 01  8905 /run/user/1000/netrulerouter/xgui.sock\n\
            0000000000000000: 00000003 00000000 00000000 0001 03 17162\n";
        let path = Path::new("/run/user/1000/netrulerouter/gui.sock");
        assert_eq!(bound_count(table, path), 2);
        assert_eq!(bound_count(table, Path::new("/run/user/1000/tray.sock")), 0);
    }
}
