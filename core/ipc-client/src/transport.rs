//! Windows pipe handle Read/Write adapter.
//!
//! Mirrors `nrr-windows-service::named_pipe_server::PipeIo` (the server
//! end). Same wire codec drives both ends through `Read`/`Write`.
//!
//! ## Overlapped I/O
//!
//! Both client and server pipes are created with
//! `FILE_FLAG_OVERLAPPED`. The reason is server-side correctness:
//! `handle_connection` uses two threads (reader subthread + main
//! worker), so without overlapped I/O the kernel serialises I/O on the
//! single pipe handle — `ReadFile` (waiting for next request) blocks
//! `WriteFile` (sending response to current request), and we deadlock.
//!
//! With overlapped handles we pass an `OVERLAPPED` with a per-PipeIo
//! auto-reset event to each ReadFile/WriteFile call, then block on
//! the event via `GetOverlappedResult(..., bWait=true)`. The API is
//! still synchronous from the caller's perspective (`Read`/`Write`
//! traits) but the kernel does NOT serialise.

#![cfg(target_os = "windows")]
#![allow(unsafe_code)]

use std::io::{self, Read, Write};
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use windows::core::PCWSTR;
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_IO_PENDING, ERROR_PIPE_BUSY, GENERIC_READ, GENERIC_WRITE,
    HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_FLAG_OVERLAPPED, FILE_SHARE_NONE, OPEN_EXISTING,
};
use windows::Win32::System::Pipes::{PeekNamedPipe, WaitNamedPipeW};
use windows::Win32::System::Threading::{CreateEventW, WaitForSingleObject};
use windows::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};

/// How often a waiting read looks up from the event to check the deadline and
/// the abort flag. Short enough that "reconnect" feels immediate, long enough
/// that an idle wait costs nothing.
const WAIT_TICK_MS: u32 = 200;

use crate::PIPE_NAME;

/// Open a connection to the service's named pipe. Returns the handle on
/// success; caller owns it and must close via `close_pipe` (or via
/// `PipeIo::Drop`).
///
/// The handle is opened with `FILE_FLAG_OVERLAPPED` so that concurrent
/// read/write from different threads doesn't serialise at the kernel
/// I/O lock. The client is single-threaded today but uniform overlapped
/// mode lets `PipeIo` use one I/O path for both client and server.
pub fn connect() -> Result<HANDLE, u32> {
    let wide: Vec<u16> = PIPE_NAME.encode_utf16().chain(std::iter::once(0)).collect();

    // `ERROR_PIPE_BUSY` means every server instance is taken right now, which
    // on a machine with several NRR surfaces is ordinary, not a failure. The
    // documented answer is `WaitNamedPipe` and one more attempt; without it
    // the connect fell through to the reconnect backoff and the window sat
    // "disconnected" while the service was healthy.
    match open_pipe(&wide) {
        Err(code) if code == ERROR_PIPE_BUSY.0 => {
            // SAFETY: `wide` is null-terminated UTF-16; the call only waits.
            unsafe {
                let _ = WaitNamedPipeW(PCWSTR(wide.as_ptr()), PIPE_BUSY_WAIT_MS);
            }
            open_pipe(&wide)
        }
        other => other,
    }
}

/// How long to wait for a free pipe instance before retrying the open. Short:
/// a server instance frees up as soon as any other client finishes a request,
/// and the reconnect backoff is still there for the case where none does.
const PIPE_BUSY_WAIT_MS: u32 = 2_000;

fn open_pipe(wide: &[u16]) -> Result<HANDLE, u32> {
    // SAFETY: wide is null-terminated UTF-16; flags follow the
    // documented Win32 contract for opening a duplex named pipe with
    // overlapped I/O. With `FILE_FLAG_OVERLAPPED` every subsequent
    // `ReadFile` / `WriteFile` MUST supply an `OVERLAPPED` structure
    // — see `PipeIo` for how that is enforced.
    let result: windows::core::Result<HANDLE> = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            GENERIC_READ.0 | GENERIC_WRITE.0,
            FILE_SHARE_NONE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED,
            None,
        )
    };

    match result {
        Ok(h) if !h.is_invalid() => Ok(h),
        Ok(_) => Err(0),
        Err(e) => Err(win32_code(&e)),
    }
}

/// The Win32 code behind a windows-rs error — the same unwrap the SCM probe
/// needs, for the same reason: `Error::code()` is an HRESULT and Win32
/// failures arrive wrapped by `HRESULT::from_win32`.
fn win32_code(err: &windows::core::Error) -> u32 {
    let hr = err.code().0 as u32;
    if hr & 0xFFFF_0000 == 0x8007_0000 {
        hr & 0xFFFF
    } else {
        hr
    }
}

/// Close a connected pipe handle. Idempotent for an already-closed handle.
pub fn close_pipe(handle: HANDLE) {
    if !handle.is_invalid() {
        // SAFETY: handle came from CreateFileW above; matching close is
        // CloseHandle.
        unsafe {
            let _ = CloseHandle(handle);
        }
    }
}

/// `Read`/`Write` adapter over a pipe handle opened with
/// `FILE_FLAG_OVERLAPPED`. Each call to read/write submits an overlapped
/// I/O and waits on a per-PipeIo auto-reset event. The handle is *not*
/// closed on drop — the IPC client owns the lifecycle and reuses the
/// handle across many requests within a single connection. The event,
/// however, IS closed on drop because it is exclusive to this PipeIo.
pub struct PipeIo {
    pub handle: HANDLE,
    event: HANDLE,
    /// How long one read or write may wait for the kernel to complete it.
    /// `None` = wait forever, which is what the code did unconditionally: a
    /// service that accepted a request and then never answered parked the
    /// worker thread for the life of the process, with the status still
    /// reading `Connected` and "reconnect" doing nothing.
    io_timeout: Option<Duration>,
    /// Consulted while waiting. `true` means the client wants out (shutdown or
    /// a forced reconnect), so the pending I/O is cancelled instead of being
    /// waited out to the deadline.
    abort: Option<Arc<AtomicBool>>,
}

impl PipeIo {
    /// Create a `PipeIo` adapter for an overlapped pipe handle. Allocates
    /// a per-instance auto-reset event used by every read / write call.
    pub fn new(handle: HANDLE) -> io::Result<Self> {
        // SAFETY: parameters follow the documented Win32 contract;
        // bManualReset=false, bInitialState=false yield an auto-reset
        // event that starts unsignaled. The returned handle is owned by
        // this PipeIo and closed on drop.
        let event = unsafe { CreateEventW(None, false, false, PCWSTR::null()) }
            .map_err(|e: windows::core::Error| io::Error::from_raw_os_error(e.code().0))?;
        if event.is_invalid() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            handle,
            event,
            io_timeout: None,
            abort: None,
        })
    }

    /// Give reads and writes a deadline. Without one a half-open pipe is
    /// indistinguishable from a slow service, forever.
    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) {
        self.io_timeout = timeout;
    }

    /// Flag that, once set, makes a waiting read give up and cancel its I/O.
    pub fn set_abort_flag(&mut self, abort: Arc<AtomicBool>) {
        self.abort = Some(abort);
    }

    fn aborted(&self) -> bool {
        self.abort
            .as_ref()
            .is_some_and(|f| f.load(Ordering::Relaxed))
    }

    /// Wait for one overlapped operation, honouring the deadline and the abort
    /// flag. On give-up the I/O is cancelled AND drained: leaving a cancelled
    /// operation attached to the OVERLAPPED (which lives on the caller's stack)
    /// would let the kernel write into freed memory.
    fn wait_overlapped(&self, overlapped: &mut OVERLAPPED, bytes: &mut u32) -> io::Result<()> {
        let deadline = self.io_timeout.map(|t| Instant::now() + t);
        loop {
            // SAFETY: `event` is this PipeIo's own auto-reset event, still open.
            let wait = unsafe { WaitForSingleObject(self.event, WAIT_TICK_MS) };
            if wait == WAIT_OBJECT_0 {
                // SAFETY: the operation completed; `overlapped` is still alive.
                unsafe {
                    return GetOverlappedResult(self.handle, overlapped, bytes, false)
                        .map_err(|e| io::Error::from_raw_os_error(e.code().0));
                }
            }
            if wait != WAIT_TIMEOUT {
                return Err(io::Error::last_os_error());
            }
            let expired = deadline.is_some_and(|d| Instant::now() >= d);
            if !expired && !self.aborted() {
                continue;
            }
            // SAFETY: cancelling our own pending operation on our own handle,
            // then waiting for it to finish unwinding before the OVERLAPPED
            // goes out of scope.
            unsafe {
                let _ = CancelIoEx(self.handle, Some(overlapped as *const OVERLAPPED));
                let _ = GetOverlappedResult(self.handle, overlapped, bytes, true);
            }
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                if expired {
                    "pipe read timed out"
                } else {
                    "pipe read cancelled"
                },
            ));
        }
    }
}

impl PipeIo {
    /// Bytes already delivered to this end of the pipe and not yet read.
    ///
    /// The client is a single-reader design: the request loop owns the pipe
    /// and only reads while one of its own requests is in flight. Server-
    /// initiated frames (push events for a live subscription) therefore sit
    /// unread in the pipe buffer whenever the client is idle. Peeking is what
    /// lets the idle loop notice them without a blocking read that would stall
    /// the next outgoing request.
    ///
    /// Returns 0 when nothing is buffered. A peek failure is reported to the
    /// caller rather than swallowed: on a dead pipe it is the same signal a
    /// failed read would give.
    pub fn peek_available(&self) -> io::Result<u32> {
        let mut available: u32 = 0;
        // SAFETY: handle is a valid pipe handle owned by this PipeIo. All
        // optional out-parameters we do not need are passed as None; only
        // `available` is written, and it outlives the call.
        unsafe {
            PeekNamedPipe(
                self.handle,
                None,
                0,
                None,
                Some(&mut available as *mut u32),
                None,
            )
            .map_err(|e: windows::core::Error| io::Error::from_raw_os_error(e.code().0))?;
        }
        Ok(available)
    }
}

impl Drop for PipeIo {
    fn drop(&mut self) {
        if !self.event.is_invalid() {
            // SAFETY: event handle came from CreateEventW above.
            unsafe {
                let _ = CloseHandle(self.event);
            }
        }
    }
}

impl Read for PipeIo {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // SAFETY: OVERLAPPED is zeroed; we set hEvent to our owned event
        // before submitting the call. The kernel writes completion data
        // back into this OVERLAPPED struct asynchronously, so it must
        // live until GetOverlappedResult returns.
        let mut overlapped: OVERLAPPED = unsafe { MaybeUninit::zeroed().assume_init() };
        overlapped.hEvent = self.event;
        let read_result = unsafe { ReadFile(self.handle, Some(buf), None, Some(&mut overlapped)) };
        let mut bytes_read: u32 = 0;
        match read_result {
            Ok(()) => {
                // Completed synchronously. Fetch byte count without
                // blocking — `bWait = false` because OVERLAPPED is
                // already populated.
                unsafe {
                    GetOverlappedResult(self.handle, &overlapped, &mut bytes_read, false)
                        .map_err(|e| io::Error::from_raw_os_error(e.code().0))?;
                }
                Ok(bytes_read as usize)
            }
            Err(_) => {
                let last = unsafe { GetLastError().0 };
                if last == ERROR_IO_PENDING.0 {
                    // Pending — wait for completion, but never past the
                    // deadline and never through a shutdown.
                    self.wait_overlapped(&mut overlapped, &mut bytes_read)?;
                    Ok(bytes_read as usize)
                } else {
                    Err(io::Error::from_raw_os_error(last as i32))
                }
            }
        }
    }
}

impl Write for PipeIo {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // SAFETY: same lifetime contract as `read` above.
        let mut overlapped: OVERLAPPED = unsafe { MaybeUninit::zeroed().assume_init() };
        overlapped.hEvent = self.event;
        let write_result =
            unsafe { WriteFile(self.handle, Some(buf), None, Some(&mut overlapped)) };
        let mut bytes_written: u32 = 0;
        match write_result {
            Ok(()) => {
                unsafe {
                    GetOverlappedResult(self.handle, &overlapped, &mut bytes_written, false)
                        .map_err(|e| io::Error::from_raw_os_error(e.code().0))?;
                }
                Ok(bytes_written as usize)
            }
            Err(_) => {
                let last = unsafe { GetLastError().0 };
                if last == ERROR_IO_PENDING.0 {
                    // Same deadline and cancellation as a read. A write blocks
                    // just as forever when the peer accepted the pipe and
                    // stopped reading it — a server refusing this client leaves
                    // exactly that state, and the unconditional wait that used
                    // to be here is where the worker thread got stuck with
                    // shutdown already signalled.
                    self.wait_overlapped(&mut overlapped, &mut bytes_written)?;
                    Ok(bytes_written as usize)
                } else {
                    Err(io::Error::from_raw_os_error(last as i32))
                }
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        // Deliberately a no-op.
        //
        // On a named pipe `FlushFileBuffers` is not "push the bytes out" — the
        // write already did that — it BLOCKS until the peer has read them, with
        // no timeout and no way to cancel. A service that accepts the pipe and
        // then refuses this client never reads, so the call parked the worker
        // thread for the life of the process: shutdown was signalled and the
        // thread never came back to see it.
        //
        // The barrier exists for a caller that writes a frame and immediately
        // closes the handle (the broker, which keeps its own `PipeIo`). This
        // client holds its handle for the whole connection, so it has nothing
        // to wait for.
        Ok(())
    }
}

/// `HANDLE` newtype that is `Send`. The client moves pipe handles
/// between the request thread (which originated them via `connect()`)
/// and the background reader thread; ownership is exclusive at any
/// given moment.
pub struct SendableHandle(pub HANDLE);

// SAFETY: HANDLE wraps *mut c_void. The client never shares a handle
// concurrently between threads — ownership is moved, not aliased.
unsafe impl Send for SendableHandle {}
