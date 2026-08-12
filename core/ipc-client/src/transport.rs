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

use windows::core::PCWSTR;
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_IO_PENDING, GENERIC_READ, GENERIC_WRITE, HANDLE,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FlushFileBuffers, ReadFile, WriteFile, FILE_FLAG_OVERLAPPED, FILE_SHARE_NONE,
    OPEN_EXISTING,
};
use windows::Win32::System::Pipes::PeekNamedPipe;
use windows::Win32::System::Threading::CreateEventW;
use windows::Win32::System::IO::{GetOverlappedResult, OVERLAPPED};

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
        Err(e) => Err(e.code().0 as u32),
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
        Ok(Self { handle, event })
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
                    // Pending — wait for completion via the event.
                    unsafe {
                        GetOverlappedResult(self.handle, &overlapped, &mut bytes_read, true)
                            .map_err(|e| io::Error::from_raw_os_error(e.code().0))?;
                    }
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
                    unsafe {
                        GetOverlappedResult(self.handle, &overlapped, &mut bytes_written, true)
                            .map_err(|e| io::Error::from_raw_os_error(e.code().0))?;
                    }
                    Ok(bytes_written as usize)
                } else {
                    Err(io::Error::from_raw_os_error(last as i32))
                }
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        // SAFETY: handle is valid.
        unsafe { FlushFileBuffers(self.handle) }
            .map_err(|e: windows::core::Error| io::Error::from_raw_os_error(e.code().0))
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
