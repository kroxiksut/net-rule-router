//! Linux IPC caller-identity via `SO_PEERCRED`. The Linux analog
//! of the Windows named-pipe identity check
//! (`core/services/windows-service/named_pipe_identity.rs`,
//! [`classify_pipe_client`]).
//!
//! When the future `linux-service` daemon accepts an `AF_UNIX` connection on
//! `/run/netrulerouter/service-v1.sock`, it must answer the same question the
//! Windows pipe server answers for each accepted handle: *who is calling, and
//! are they privileged?* On Windows that means `GetNamedPipeClientProcessId` →
//! `OpenProcess` → exe-basename whitelist + token integrity + elevation +
//! user SID. On Linux the kernel hands the same identity down atomically at
//! connect time through the `SO_PEERCRED` socket option, which yields the
//! peer's `pid` / `uid` / `gid` in one call — no `OpenProcess` race window
//! between accept and inspection.
//!
//! ## Model differences from Windows (honest capability inversions)
//!
//! - **No exe-basename whitelist.** The Windows pipe accepts only
//!   `NetRuleRouter.exe` / `NetRuleRouterTray.exe`. On Linux the connecting
//!   *executable* is not part of the peer credential, and the `0700`
//!   `RuntimeDirectory=netrulerouter` (systemd) already restricts who can even
//!   reach the socket to processes running as a permitted user. So this module
//!   resolves identity but never rejects on an exe basis — the socket
//!   directory permissions are the gate, not a per-connection allowlist.
//! - **Elevation = `uid == 0` (root).** The Windows flag reads
//!   `TokenElevation`; the Linux analog is "is the caller root". The GUI runs
//!   non-root and reaches privileged operations through the root service
//!   authorized by polkit (see [`crate::elevation`]), so this flag is parity
//!   information for the IPC router, not the sole authorization gate.
//! - **Identity → `UserPrincipal`.** The uid maps to the same per-principal
//!   partition key the rest of the stack uses, via
//!   [`UserPrincipal::from_linux_uid`] (`unix:uid:<n>`), the counterpart of
//!   Windows' `caller_sid` (`S-1-5-…`).
//!
//! `#[cfg(target_os = "linux")]`: `SO_PEERCRED` and `struct ucred` are a
//! Linux-specific socket feature (the BSD/macOS analog is `LOCAL_PEERCRED` /
//! `getpeereid`), so — like [`crate::key_store`] and [`crate::systemd`] — the
//! module is compiled and unit-tested on Linux (WSL2) only.

#![cfg(target_os = "linux")]
// Localized: the single `getsockopt(SO_PEERCRED)` FFI call in
// `read_peer_cred_fd` is the only `unsafe` in this module. There is no stable
// `std` API for peer credentials; libc's `getsockopt` is the idiomatic route.
#![allow(unsafe_code)]

use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;

use nrr_platform_api::enforcement::UserPrincipal;

/// Peer credentials of a connected `AF_UNIX` client, read via `SO_PEERCRED`.
/// The kernel captures these at `connect(2)` time, so they identify the
/// process that actually opened the connection (not whoever holds the fd now).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCred {
    /// The connecting process id.
    pub pid: i32,
    /// The connecting process's effective user id.
    pub uid: u32,
    /// The connecting process's effective group id.
    pub gid: u32,
}

impl PeerCred {
    /// Whether the caller is root (`uid == 0`) — the Linux analog of a Windows
    /// elevated token. See the module doc for why this is parity information,
    /// not the sole authorization gate.
    pub fn is_root(&self) -> bool {
        self.uid == 0
    }

    /// Map the caller uid to the per-principal partition key
    /// (`unix:uid:<n>`), the Linux counterpart of the Windows `caller_sid`.
    /// Infallible: [`UserPrincipal::from_linux_uid`] cannot collide with the
    /// reserved baseline sentinel.
    pub fn to_principal(&self) -> UserPrincipal {
        UserPrincipal::from_linux_uid(self.uid)
    }
}

/// The Linux counterpart of the Windows `ClientIdentity`: the resolved,
/// authorization-relevant identity of an accepted `AF_UNIX` client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnixClientIdentity {
    /// The per-principal key policy and storage partition off (`unix:uid:<n>`).
    /// Analog of Windows `caller_sid` threaded through `UserPrincipal`.
    pub principal: UserPrincipal,
    /// `true` when the caller is root — analog of Windows `caller_is_elevated`.
    pub caller_is_elevated: bool,
    /// The connecting process id, retained for audit/diagnostics (analog of
    /// Windows `process_id`).
    pub pid: i32,
    /// The raw caller uid, retained alongside [`Self::principal`] for logging.
    pub uid: u32,
    /// The raw caller gid, retained for audit/diagnostics.
    pub gid: u32,
}

/// Classify a connected `AF_UNIX` stream into a [`UnixClientIdentity`], the
/// Linux analog of [`classify_pipe_client`]. Reads the peer credentials via
/// [`read_peer_cred`] and resolves them to a [`UserPrincipal`]. Unlike the
/// Windows path this never rejects on an exe basis (the `0700` socket
/// directory is the gate); it only fails if the kernel refuses the
/// credential read (a genuine `getsockopt` error).
pub fn classify_unix_client(stream: &UnixStream) -> io::Result<UnixClientIdentity> {
    let cred = read_peer_cred(stream)?;
    Ok(UnixClientIdentity {
        principal: cred.to_principal(),
        caller_is_elevated: cred.is_root(),
        pid: cred.pid,
        uid: cred.uid,
        gid: cred.gid,
    })
}

/// Read the peer credentials of a connected `AF_UNIX` stream via
/// `getsockopt(SO_PEERCRED)`. Mirrors `classify_pipe_client`'s
/// `GetNamedPipeClientProcessId` + token inspection, but the kernel returns
/// pid/uid/gid atomically at connect time.
pub fn read_peer_cred(stream: &UnixStream) -> io::Result<PeerCred> {
    read_peer_cred_fd(stream.as_raw_fd())
}

/// The `getsockopt(SO_PEERCRED)` core, split out on the raw fd so it can be
/// exercised against any connected `AF_UNIX` fd (e.g. a `socketpair`).
fn read_peer_cred_fd(fd: RawFd) -> io::Result<PeerCred> {
    // `struct ucred { pid_t pid; uid_t uid; gid_t gid; }`.
    let mut ucred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `fd` is a valid connected AF_UNIX socket for the borrow that
    // produced it; `ucred` and `len` are stack out-params sized exactly to
    // `struct ucred`. `getsockopt` writes at most `len` bytes into `ucred` and
    // updates `len` to the number written.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut ucred as *mut libc::ucred).cast::<libc::c_void>(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(PeerCred {
        pid: ucred.pid,
        uid: ucred.uid,
        gid: ucred.gid,
    })
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Our own effective uid, for asserting the peer-cred read reflects the
    /// running test process. Wraps the one-line libc call the test needs.
    fn own_uid() -> u32 {
        // SAFETY: `geteuid` takes no arguments and cannot fail.
        unsafe { libc::geteuid() }
    }

    /// Unique temp dir with best-effort cleanup on drop — same hand-rolled
    /// idiom as `key_store`/`autostart`, so the crate keeps zero dev-deps.
    struct TempDir(PathBuf);
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn temp_dir() -> TempDir {
        static N: AtomicU32 = AtomicU32::new(0);
        let mut p = std::env::temp_dir();
        p.push(format!(
            "nrr-peercred-test-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).expect("create temp dir");
        TempDir(p)
    }

    #[test]
    fn socketpair_peer_cred_is_the_test_process() {
        let (a, b) = UnixStream::pair().expect("socketpair");
        let ca = read_peer_cred(&a).expect("peer cred a");
        let cb = read_peer_cred(&b).expect("peer cred b");
        // Both ends belong to this process → same identity on both sides.
        assert_eq!(ca.uid, own_uid());
        assert_eq!(cb.uid, own_uid());
        assert_eq!(ca.uid, cb.uid);
        // The pid is a real, positive process id.
        assert!(ca.pid > 0);
    }

    #[test]
    fn accepted_connection_credentials_match_the_connecting_process() {
        let dir = temp_dir();
        let sock = dir.0.join("peercred-test.sock");
        let listener = UnixListener::bind(&sock).expect("bind");

        let mut client = UnixStream::connect(&sock).expect("connect");
        let (mut server, _addr) = listener.accept().expect("accept");

        // Read the accepted side's credentials — this is exactly what the
        // daemon does for each accepted connection.
        let cred = read_peer_cred(&server).expect("peer cred");
        assert_eq!(cred.uid, own_uid());
        assert!(cred.pid > 0);

        // Sanity: the channel actually carries bytes both ways.
        client.write_all(b"ping").expect("write");
        let mut buf = [0u8; 4];
        server.read_exact(&mut buf).expect("read");
        assert_eq!(&buf, b"ping");
    }

    #[test]
    fn classify_resolves_uid_to_a_unix_principal() {
        let (a, _b) = UnixStream::pair().expect("socketpair");
        let id = classify_unix_client(&a).expect("classify");

        assert_eq!(id.uid, own_uid());
        assert_eq!(id.principal, UserPrincipal::from_linux_uid(own_uid()));
        // The stored form is the reserved `unix:uid:<n>` scheme, never the
        // baseline sentinel.
        assert_eq!(id.principal.as_stored(), format!("unix:uid:{}", own_uid()));
        assert!(!id.principal.is_baseline());
    }

    #[test]
    fn elevation_flag_tracks_root() {
        // A non-root test run sees `caller_is_elevated == false`; a root run
        // (CI as root, or `sudo cargo test`) sees `true`. Either way the flag
        // must equal `uid == 0`, which is the invariant we pin here rather
        // than a fixed boolean.
        let (a, _b) = UnixStream::pair().expect("socketpair");
        let id = classify_unix_client(&a).expect("classify");
        assert_eq!(id.caller_is_elevated, own_uid() == 0);

        // Unit-level check of the mapping independent of the ambient uid.
        let root = PeerCred {
            pid: 1,
            uid: 0,
            gid: 0,
        };
        let user = PeerCred {
            pid: 2,
            uid: 1000,
            gid: 1000,
        };
        assert!(root.is_root());
        assert!(!user.is_root());
    }
}
