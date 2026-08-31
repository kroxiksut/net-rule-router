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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

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

/// A stream whose reads have a deadline and can be abandoned.
///
/// `UnixStream::set_read_timeout` alone is not enough: a timeout mid-frame
/// tears down a connection that was merely slow, and a 60-second timeout makes
/// shutdown wait out the whole window. This wrapper sets a SHORT socket
/// timeout and turns each expiry into a decision — keep waiting, or give up
/// because the caller asked to stop or the real deadline passed. A `read` that
/// times out has consumed nothing, so retrying is safe; the framing code above
/// never sees the expiry at all.
pub struct TimedStream {
    inner: UnixStream,
    abort: Arc<AtomicBool>,
    read_deadline: Duration,
    /// Set while the caller is only LOOKING for a frame rather than waiting
    /// for one it asked for. The first read then gives up quickly; once a byte
    /// has arrived the full deadline applies again, because abandoning a frame
    /// half-read would desynchronise the stream.
    probe_deadline: Option<Duration>,
    /// Bytes read since `begin_probe`. Non-zero means a frame is in progress.
    probe_bytes: u64,
}

/// How long one socket read waits before the wrapper reconsiders. Short enough
/// that shutdown is prompt, long enough to cost nothing while idle.
const READ_TICK: Duration = Duration::from_millis(200);

impl TimedStream {
    /// Wrap `stream`; `abort` ends a wait early, `read_deadline` caps the total
    /// wait for one read.
    pub fn new(
        stream: UnixStream,
        abort: Arc<AtomicBool>,
        read_deadline: Duration,
    ) -> io::Result<Self> {
        stream.set_read_timeout(Some(READ_TICK))?;
        Ok(Self {
            inner: stream,
            abort,
            read_deadline,
            probe_deadline: None,
            probe_bytes: 0,
        })
    }

    /// Look for a server-initiated frame without committing to a long wait.
    ///
    /// `within` bounds only the wait for the FIRST byte; once bytes are
    /// arriving the ordinary deadline takes over so a frame is never torn.
    /// Ends at [`end_probe`](Self::end_probe).
    pub fn begin_probe(&mut self, within: Duration) {
        self.probe_deadline = Some(within);
        self.probe_bytes = 0;
    }

    /// Leave probe mode; subsequent reads wait the full deadline.
    pub fn end_probe(&mut self) {
        self.probe_deadline = None;
        self.probe_bytes = 0;
    }
}

impl io::Read for TimedStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let wait = match self.probe_deadline {
            Some(short) if self.probe_bytes == 0 => short,
            _ => self.read_deadline,
        };
        let deadline = Instant::now() + wait;
        loop {
            match io::Read::read(&mut self.inner, buf) {
                Ok(n) => {
                    self.probe_bytes += n as u64;
                    return Ok(n);
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    if self.abort.load(Ordering::Relaxed) {
                        return Err(io::Error::new(io::ErrorKind::TimedOut, "read cancelled"));
                    }
                    if Instant::now() >= deadline {
                        return Err(io::Error::new(io::ErrorKind::TimedOut, "read timed out"));
                    }
                }
                Err(e) => return Err(e),
            }
        }
    }
}

impl io::Write for TimedStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        io::Write::write(&mut self.inner, buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        io::Write::flush(&mut self.inner)
    }
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
    fn a_waiting_read_gives_up_when_the_abort_flag_is_raised() {
        use std::io::Read as _;
        // Nothing is ever written on the peer, so the read can only end by
        // giving up — which is exactly the shutdown path.
        let (client, _server) = UnixStream::pair().expect("socketpair");
        let abort = Arc::new(AtomicBool::new(false));
        let mut timed = TimedStream::new(client, Arc::clone(&abort), Duration::from_secs(60))
            .expect("wrap stream");
        let flag = Arc::clone(&abort);
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(150));
            flag.store(true, Ordering::Relaxed);
        });
        let mut buf = [0u8; 4];
        let err = timed.read(&mut buf).expect_err("read must not succeed");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn a_read_that_outlives_its_deadline_reports_a_timeout() {
        use std::io::Read as _;
        let (client, _server) = UnixStream::pair().expect("socketpair");
        let mut timed = TimedStream::new(
            client,
            Arc::new(AtomicBool::new(false)),
            Duration::from_millis(120),
        )
        .expect("wrap stream");
        let mut buf = [0u8; 4];
        let err = timed.read(&mut buf).expect_err("read must not succeed");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
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
