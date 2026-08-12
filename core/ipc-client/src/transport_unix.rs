//! Unix `AF_UNIX` transport primitive for the IPC client.
//!
//! The Windows client opens the service's named pipe (`transport::connect`)
//! and wraps the overlapped handle in `PipeIo` to obtain `Read`/`Write`. On
//! Unix the mechanism is an `AF_UNIX` stream socket:
//! `std::os::unix::net::UnixStream` already implements `Read + Write + Send`,
//! so the shared wire codec (`crate::wire`) drives it directly — no adapter,
//! no overlapped I/O, no `SendableHandle`. The framing (4-byte BE length +
//! UTF-8 JSON, capped at `IPC_MAX_MESSAGE_BYTES`) is byte-for-byte the same
//! as the Windows path; only the byte carrier differs.
//!
//! Scope: transport primitive only. The full reconnect state machine (a Unix
//! sibling of `NamedPipeIpcClient`) lives in `crate::client_unix`.
//! Server-side peer-credential identity (`SO_PEERCRED` → uid) is a
//! `linux-service` concern, not a client one.

#![cfg(unix)]

use std::io;
use std::os::unix::net::UnixStream;
use std::path::Path;

use nrr_shared::ipc_transport::SERVICE_ENDPOINT_ADDRESS;

/// Connect to the service's canonical `AF_UNIX` endpoint
/// ([`SERVICE_ENDPOINT_ADDRESS`], e.g. `/run/netrulerouter/service-v1.sock`).
/// Mirrors the Windows `transport::connect`, which opens the named pipe. The
/// returned `UnixStream` is `Read + Write + Send`, so the wire codec consumes
/// it with no adapter.
pub fn connect() -> io::Result<UnixStream> {
    connect_to(SERVICE_ENDPOINT_ADDRESS)
}

/// Connect to an arbitrary `AF_UNIX` path. Split out from [`connect`] so unit
/// tests can round-trip against a temp-path listener without the root-owned
/// production socket under `/run/netrulerouter/`.
pub fn connect_to<P: AsRef<Path>>(path: P) -> io::Result<UnixStream> {
    UnixStream::connect(path)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{read_frame, write_frame};
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::thread;

    #[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    struct Ping {
        op: String,
        n: u32,
    }

    #[test]
    fn wire_codec_round_trips_over_af_unix_socketpair() {
        // A connected AF_UNIX pair with no filesystem path — proves the shared
        // wire codec drives a real Unix socket in both directions.
        let (mut a, mut b) = UnixStream::pair().expect("socketpair");
        let msg = Ping {
            op: "health".into(),
            n: 7,
        };
        write_frame(&mut a, &msg).expect("write");
        let got: Ping = read_frame(&mut b).expect("read");
        assert_eq!(got, msg);
    }

    /// Unique temp socket path with best-effort cleanup on drop, so parallel
    /// test runs never collide on a stale path.
    struct TempSock(PathBuf);
    impl Drop for TempSock {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    fn temp_sock_path() -> TempSock {
        static N: AtomicU32 = AtomicU32::new(0);
        let mut p = std::env::temp_dir();
        p.push(format!(
            "nrr-ipc-test-{}-{}.sock",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_file(&p); // clear any stale socket from a crashed run
        TempSock(p)
    }

    #[test]
    fn connect_to_reaches_a_listener_and_frames_round_trip() {
        let sock = temp_sock_path();
        let listener = UnixListener::bind(&sock.0).expect("bind listener");
        // Server: accept one connection and echo the request frame back.
        let server = thread::spawn(move || {
            let (mut conn, _addr) = listener.accept().expect("accept");
            let req: Ping = read_frame(&mut conn).expect("server read");
            write_frame(&mut conn, &req).expect("server write");
        });

        let mut client = connect_to(&sock.0).expect("client connect");
        let msg = Ping {
            op: "negotiate".into(),
            n: 1,
        };
        write_frame(&mut client, &msg).expect("client write");
        let echoed: Ping = read_frame(&mut client).expect("client read");
        assert_eq!(echoed, msg);

        server.join().expect("server thread");
    }
}
