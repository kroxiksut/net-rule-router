//! All Win32 / `unsafe` for the broker channel, localized to this module.
//!
//! Provides, for the **server** (elevated broker):
//! - [`create_owner_restricted_pipe`] — `CreateNamedPipeW` whose DACL
//!   grants only the launcher's user SID, with a medium-IL label so the
//!   non-elevated launcher can reach it.
//! - [`accept_with_parent_watch`] — overlapped `ConnectNamedPipe` waited
//!   alongside the parent-process handle, so the broker wakes the instant
//!   the launcher dies.
//! - [`client_process_id`] / [`pipe_client_user_sid`] — identify the
//!   connected client for the PID + SID owner checks.
//!
//! and for the **client** (launcher):
//! - [`connect_pipe`] — `CreateFileW` against the broker pipe.
//! - [`current_process_user_sid`] — the launcher's own SID (sent to the
//!   broker so it can pin the DACL + the accept-time identity check).
//!
//! plus [`PipeIo`], the overlapped `Read`/`Write` adapter shared by both
//! ends (mirrors `nrr-ipc-client::transport::PipeIo`).

#![cfg(target_os = "windows")]
#![allow(unsafe_code)]

use std::io::{self, Read, Write};
use std::mem::MaybeUninit;
use std::ptr;
use std::time::{Duration, Instant};

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, BOOL, GENERIC_READ, GENERIC_WRITE, HANDLE, HLOCAL,
    WAIT_OBJECT_0,
};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{
    GetTokenInformation, TokenUser, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES, TOKEN_QUERY,
    TOKEN_USER,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FlushFileBuffers, ReadFile, WriteFile, FILE_FLAG_OVERLAPPED, FILE_SHARE_NONE,
    OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
    PIPE_READMODE_MESSAGE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_MESSAGE, PIPE_UNLIMITED_INSTANCES,
    PIPE_WAIT,
};
use windows::Win32::System::Threading::{
    CreateEventW, GetCurrentProcess, OpenProcess, OpenProcessToken, WaitForMultipleObjects,
    INFINITE, PROCESS_ACCESS_RIGHTS, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};

/// Generic `SYNCHRONIZE` (0x0010_0000) access right — enough to wait on a
/// process handle for termination. Not re-exported as a named constant by
/// the `windows` crate's process module, so spelled out here.
const SYNCHRONIZE: u32 = 0x0010_0000;

/// `ERROR_PIPE_CONNECTED` (535) — a client raced ahead and is already
/// attached. Both the bare Win32 code and its `HRESULT` form are checked
/// because the `windows` crate surfaces either depending on the call.
const ERR_PIPE_CONNECTED: u32 = 535;
const ERR_PIPE_CONNECTED_HRESULT: u32 = 0x8007_0217;
/// `ERROR_IO_PENDING` (997) — overlapped op in progress; wait on the event.
const ERR_IO_PENDING: u32 = 997;
const ERR_IO_PENDING_HRESULT: u32 = 0x8007_03E5;

const PIPE_BUFFER_SIZE: u32 = 64 * 1024;

/// Win32 failure with the call context and the OS error code.
#[derive(Debug)]
pub struct WinError {
    pub context: &'static str,
    pub code: u32,
}

impl std::fmt::Display for WinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} failed (0x{:08X})", self.context, self.code)
    }
}

impl std::error::Error for WinError {}

fn last_error() -> u32 {
    // SAFETY: GetLastError reads thread-local Win32 error state.
    unsafe { GetLastError().0 }
}

/// RAII wrapper that closes a `HANDLE` on drop. Used for process and token
/// handles obtained during identity checks.
pub struct OwnedHandle(pub HANDLE);

impl OwnedHandle {
    pub fn raw(&self) -> HANDLE {
        self.0
    }

    /// Consume the wrapper WITHOUT closing the handle, returning the raw
    /// `HANDLE`. The caller takes over the close responsibility (e.g. via
    /// [`disconnect_and_close`]). Prevents a double close.
    pub fn into_raw(self) -> HANDLE {
        let h = self.0;
        std::mem::forget(self);
        h
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: handle came from OpenProcess / OpenProcessToken /
            // CreateNamedPipeW; the matching free is CloseHandle.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

// SAFETY: an `OwnedHandle` owns its kernel handle exclusively; it is moved
// between threads (broker accept loop), never aliased concurrently.
unsafe impl Send for OwnedHandle {}

// ── Owner-restricted pipe creation (server side) ──────────────────────────────

/// Build the SDDL for the broker pipe: the launcher's user SID gets
/// generic read+write, a medium-integrity no-write-up label keeps the
/// non-elevated (medium-IL) launcher able to reach a pipe created by the
/// elevated (high-IL) broker while excluding Low/AppContainer callers.
/// No other principal is granted — strict owner restriction.
fn broker_pipe_sddl(client_sid: &str) -> Result<String, WinError> {
    // `client_sid` comes from our own GetTokenInformation, but validate the
    // shape defensively before splicing it into the SDDL string.
    if !client_sid.starts_with("S-1-") || client_sid.contains([')', '(', ';']) {
        return Err(WinError {
            context: "broker_pipe_sddl: malformed client SID",
            code: 0,
        });
    }
    Ok(format!("D:(A;;GRGW;;;{client_sid})S:(ML;;NW;;;ME)"))
}

/// Create one broker pipe instance with an owner-restricted DACL. The pipe
/// uses `FILE_FLAG_OVERLAPPED` so the accept can be waited alongside the
/// parent handle. Returns the owning handle.
pub fn create_owner_restricted_pipe(
    pipe_name: &str,
    client_sid: &str,
    first_instance: bool,
) -> Result<OwnedHandle, WinError> {
    let sddl = broker_pipe_sddl(client_sid)?;
    let sddl_wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();

    // SAFETY: sddl_wide is a valid null-terminated UTF-16 buffer; sd_out
    // receives a LocalAlloc'd descriptor we free via LocalFree below.
    let mut sd_out: PSECURITY_DESCRIPTOR = PSECURITY_DESCRIPTOR(ptr::null_mut());
    let conv = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl_wide.as_ptr()),
            SDDL_REVISION_1,
            &mut sd_out as *mut _,
            None,
        )
    };
    if conv.is_err() || sd_out.0.is_null() {
        return Err(WinError {
            context: "ConvertStringSecurityDescriptorToSecurityDescriptorW",
            code: last_error(),
        });
    }
    // Free the descriptor once CreateNamedPipeW has consumed it (it copies
    // the descriptor into the kernel object), regardless of success.
    let _sd_guard = LocalFreeGuard(sd_out.0);

    let attrs = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd_out.0,
        bInheritHandle: BOOL(0),
    };

    let name_wide: Vec<u16> = pipe_name.encode_utf16().chain(std::iter::once(0)).collect();
    // `PIPE_REJECT_REMOTE_CLIENTS` blocks any over-the-network connection.
    // First instance uses default open mode; the `first_instance` flag is
    // reserved for callers that want FILE_FLAG_FIRST_PIPE_INSTANCE to fail
    // fast on a name squatted by another process (off here to keep the
    // re-create-per-accept loop simple; the random suffix already guards
    // against a stale broker).
    let _ = first_instance;
    // SAFETY: name_wide is null-terminated UTF-16; attrs points at a valid
    // SECURITY_ATTRIBUTES whose descriptor stays alive until after this call
    // (freed by _sd_guard at end of scope). Buffer sizes are the same as the
    // service pipe.
    let pipe = unsafe {
        CreateNamedPipeW(
            PCWSTR(name_wide.as_ptr()),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_UNLIMITED_INSTANCES,
            PIPE_BUFFER_SIZE,
            PIPE_BUFFER_SIZE,
            0,
            Some(&attrs as *const _),
        )
    };
    if pipe.is_invalid() {
        return Err(WinError {
            context: "CreateNamedPipeW",
            code: last_error(),
        });
    }
    Ok(OwnedHandle(pipe))
}

/// Frees a LocalAlloc'd security descriptor on drop.
struct LocalFreeGuard(*mut std::ffi::c_void);
impl Drop for LocalFreeGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: pointer came from ConvertStringSecurityDescriptor...W,
            // whose documented free is LocalFree.
            unsafe {
                let _ = LocalFree(HLOCAL(self.0));
            }
        }
    }
}

// ── Parent-watched accept (server side) ───────────────────────────────────────

/// Outcome of waiting for a client on a pipe instance while also watching
/// the parent launcher process.
pub enum AcceptResult {
    /// A client connected; the pipe is ready for one request/response.
    Connected,
    /// The parent launcher process exited — the broker must shut down.
    ParentExited,
    /// A transient failure; the caller closes the instance and loops.
    Failed(WinError),
}

/// Open the parent launcher process for liveness waiting (`SYNCHRONIZE`).
pub fn open_parent_process(parent_pid: u32) -> Result<OwnedHandle, WinError> {
    // SAFETY: SYNCHRONIZE is the only right requested; the returned handle
    // is owned and closed by OwnedHandle::drop.
    let handle = unsafe { OpenProcess(PROCESS_ACCESS_RIGHTS(SYNCHRONIZE), BOOL(0), parent_pid) }
        .map_err(|e| WinError {
            context: "OpenProcess(parent)",
            code: e.code().0 as u32,
        })?;
    Ok(OwnedHandle(handle))
}

/// Wait for a client to connect to `pipe`, while also watching `parent`.
/// Returns [`AcceptResult::ParentExited`] the moment the launcher dies, so
/// the elevated broker never outlives its non-elevated owner.
pub fn accept_with_parent_watch(pipe: HANDLE, parent: HANDLE) -> AcceptResult {
    // SAFETY: auto-reset event, starts unsignaled; owned and closed below.
    let connect_event = match unsafe { CreateEventW(None, false, false, PCWSTR::null()) } {
        Ok(h) if !h.is_invalid() => h,
        _ => {
            return AcceptResult::Failed(WinError {
                context: "CreateEventW(connect)",
                code: last_error(),
            })
        }
    };
    // SAFETY: zeroed OVERLAPPED with our owned event; lives on this stack
    // frame and is not referenced by the kernel after we cancel+drain below.
    let mut overlapped: OVERLAPPED = unsafe { MaybeUninit::zeroed().assume_init() };
    overlapped.hEvent = connect_event;

    // SAFETY: pipe is a valid overlapped pipe handle; overlapped is valid.
    let connect_result = unsafe { ConnectNamedPipe(pipe, Some(&mut overlapped)) };
    let result = match connect_result {
        Ok(()) => AcceptResult::Connected,
        Err(e) => {
            let code = e.code().0 as u32;
            if code == ERR_PIPE_CONNECTED || code == ERR_PIPE_CONNECTED_HRESULT {
                AcceptResult::Connected
            } else if code == ERR_IO_PENDING || code == ERR_IO_PENDING_HRESULT {
                wait_connect_or_parent(pipe, &mut overlapped, connect_event, parent)
            } else {
                AcceptResult::Failed(WinError {
                    context: "ConnectNamedPipe",
                    code,
                })
            }
        }
    };

    // SAFETY: connect_event was created above; close exactly once.
    unsafe {
        let _ = CloseHandle(connect_event);
    }
    result
}

fn wait_connect_or_parent(
    pipe: HANDLE,
    overlapped: &mut OVERLAPPED,
    connect_event: HANDLE,
    parent: HANDLE,
) -> AcceptResult {
    let handles = [connect_event, parent];
    // SAFETY: both handles are valid; we do not request wait-all.
    let wait = unsafe { WaitForMultipleObjects(&handles, BOOL(0), INFINITE) };
    if wait == WAIT_OBJECT_0 {
        // Connect completed.
        let mut transferred: u32 = 0;
        // SAFETY: overlapped was populated by the completed ConnectNamedPipe.
        match unsafe { GetOverlappedResult(pipe, overlapped, &mut transferred, false) } {
            Ok(()) => AcceptResult::Connected,
            Err(e) => AcceptResult::Failed(WinError {
                context: "GetOverlappedResult(connect)",
                code: e.code().0 as u32,
            }),
        }
    } else if wait.0 == WAIT_OBJECT_0.0 + 1 {
        // Parent exited. Cancel the pending connect and DRAIN it so the
        // kernel no longer references `overlapped` before this frame returns.
        // SAFETY: pipe + overlapped are valid; bWait=true blocks until the
        // cancelled I/O is fully torn down.
        unsafe {
            let _ = CancelIoEx(pipe, Some(overlapped));
            let mut n: u32 = 0;
            let _ = GetOverlappedResult(pipe, overlapped, &mut n, true);
        }
        AcceptResult::ParentExited
    } else {
        AcceptResult::Failed(WinError {
            context: "WaitForMultipleObjects(accept)",
            code: last_error(),
        })
    }
}

/// Disconnect and close a pipe instance after a request/response round.
pub fn disconnect_and_close(pipe: HANDLE) {
    // SAFETY: pipe came from CreateNamedPipeW; both calls match it.
    unsafe {
        let _ = DisconnectNamedPipe(pipe);
        let _ = CloseHandle(pipe);
    }
}

// ── Caller identity (server side) ─────────────────────────────────────────────

/// PID of the process connected to `pipe`.
pub fn client_process_id(pipe: HANDLE) -> Result<u32, WinError> {
    let mut pid: u32 = 0;
    // SAFETY: pipe is a valid connected pipe handle; pid out-pointer is on
    // the stack.
    let ok = unsafe { GetNamedPipeClientProcessId(pipe, &mut pid as *mut u32) };
    if ok.is_err() {
        return Err(WinError {
            context: "GetNamedPipeClientProcessId",
            code: last_error(),
        });
    }
    Ok(pid)
}

/// String SID of the user that owns the process connected to `pipe`.
pub fn pipe_client_user_sid(pipe: HANDLE) -> Result<String, WinError> {
    let pid = client_process_id(pipe)?;
    // SAFETY: minimal query right; handle owned by OwnedHandle.
    let process =
        unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, BOOL(0), pid) }.map_err(|e| {
            WinError {
                context: "OpenProcess(client)",
                code: e.code().0 as u32,
            }
        })?;
    let process = OwnedHandle(process);
    let token = open_process_token(process.raw())?;
    query_user_sid(token.raw())
}

/// The current process's own user SID (launcher side: sent to the broker
/// for the DACL + identity pin).
pub fn current_process_user_sid() -> Result<String, WinError> {
    // SAFETY: GetCurrentProcess returns a pseudo-handle that need not be
    // closed; OpenProcessToken yields a real token handle we own.
    let token = open_process_token(unsafe { GetCurrentProcess() })?;
    query_user_sid(token.raw())
}

fn open_process_token(process: HANDLE) -> Result<OwnedHandle, WinError> {
    let mut token = HANDLE::default();
    // SAFETY: process is valid for the call; token out-pointer is on stack.
    unsafe {
        OpenProcessToken(process, TOKEN_QUERY, &mut token as *mut HANDLE).map_err(|e| {
            WinError {
                context: "OpenProcessToken",
                code: e.code().0 as u32,
            }
        })?;
    }
    Ok(OwnedHandle(token))
}

fn query_user_sid(token: HANDLE) -> Result<String, WinError> {
    let mut needed = 0u32;
    // SAFETY: NULL buffer returns the required size in `needed`.
    let _ = unsafe { GetTokenInformation(token, TokenUser, None, 0, &mut needed as *mut u32) };
    if needed == 0 {
        return Err(WinError {
            context: "GetTokenInformation(TokenUser size)",
            code: last_error(),
        });
    }
    // 8-byte aligned backing buffer for TOKEN_USER + the inline SID bytes.
    let mut aligned: Box<[u64]> = vec![0u64; needed as usize / 8 + 1].into_boxed_slice();
    let buf_ptr = aligned.as_mut_ptr() as *mut u8;
    // SAFETY: buf_ptr addresses at least `needed` bytes.
    unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            Some(buf_ptr as *mut _),
            needed,
            &mut needed as *mut u32,
        )
        .map_err(|e| WinError {
            context: "GetTokenInformation(TokenUser)",
            code: e.code().0 as u32,
        })?;
    }
    // SAFETY: TOKEN_USER is at offset 0; User.Sid points into the same buffer.
    let token_user = unsafe { &*(buf_ptr as *const TOKEN_USER) };
    let psid: PSID = token_user.User.Sid;
    if psid.0.is_null() {
        return Err(WinError {
            context: "TokenUser.User.Sid was null",
            code: 0,
        });
    }
    let mut wide_ptr: PWSTR = PWSTR::null();
    // SAFETY: psid is a valid PSID from Win32; out-pointer receives a
    // LocalAlloc'd UTF-16 string we free below.
    unsafe {
        ConvertSidToStringSidW(psid, &mut wide_ptr as *mut PWSTR).map_err(|e| WinError {
            context: "ConvertSidToStringSidW",
            code: e.code().0 as u32,
        })?;
    }
    if wide_ptr.0.is_null() {
        return Err(WinError {
            context: "ConvertSidToStringSidW returned null",
            code: 0,
        });
    }
    // SAFETY: wide_ptr is a null-terminated UTF-16 string from Win32.
    let s = unsafe { read_pwstr(wide_ptr) };
    // SAFETY: matching free for ConvertSidToStringSidW is LocalFree.
    unsafe {
        let _ = LocalFree(HLOCAL(wide_ptr.0 as _));
    }
    Ok(s)
}

/// SAFETY: `p` must be null or a null-terminated UTF-16 string.
unsafe fn read_pwstr(p: PWSTR) -> String {
    if p.0.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    while *p.0.add(len) != 0 {
        len += 1;
    }
    let slice = std::slice::from_raw_parts(p.0, len);
    String::from_utf16_lossy(slice)
}

// ── Client connect (launcher side) ────────────────────────────────────────────

/// Connect to the broker pipe with retry up to `timeout`. The broker may
/// not have created its first instance yet (UAC just dismissed, process
/// starting), so transient `ERROR_FILE_NOT_FOUND` / `ERROR_PIPE_BUSY` are
/// retried. Returns the connected handle on success.
pub fn connect_pipe(pipe_name: &str, timeout: Duration) -> Result<OwnedHandle, WinError> {
    let wide: Vec<u16> = pipe_name.encode_utf16().chain(std::iter::once(0)).collect();
    let deadline = Instant::now() + timeout;
    let mut last_code: u32;
    loop {
        // SAFETY: wide is null-terminated UTF-16; overlapped flag matches the
        // PipeIo read/write contract.
        let result = unsafe {
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
            Ok(h) if !h.is_invalid() => return Ok(OwnedHandle(h)),
            Ok(_) => last_code = 0,
            Err(e) => last_code = e.code().0 as u32,
        }
        if Instant::now() >= deadline {
            return Err(WinError {
                context: "CreateFileW(broker pipe)",
                code: last_code,
            });
        }
        std::thread::sleep(Duration::from_millis(40));
    }
}

// ── Overlapped Read/Write adapter (both ends) ─────────────────────────────────

/// `Read`/`Write` over a pipe handle opened with `FILE_FLAG_OVERLAPPED`.
/// Mirrors `nrr-ipc-client::transport::PipeIo`. The handle is NOT closed on
/// drop — the caller owns its lifecycle (server: `disconnect_and_close`;
/// client: the `OwnedHandle`). The per-instance event IS closed on drop.
pub struct PipeIo {
    handle: HANDLE,
    event: HANDLE,
}

impl PipeIo {
    pub fn new(handle: HANDLE) -> io::Result<Self> {
        // SAFETY: auto-reset event, starts unsignaled; owned + closed on drop.
        let event = unsafe { CreateEventW(None, false, false, PCWSTR::null()) }
            .map_err(|e: windows::core::Error| io::Error::from_raw_os_error(e.code().0))?;
        if event.is_invalid() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { handle, event })
    }
}

impl Drop for PipeIo {
    fn drop(&mut self) {
        if !self.event.is_invalid() {
            // SAFETY: event came from CreateEventW above.
            unsafe {
                let _ = CloseHandle(self.event);
            }
        }
    }
}

impl Read for PipeIo {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // SAFETY: zeroed OVERLAPPED with our owned event; it must outlive the
        // GetOverlappedResult call below, which it does (same stack frame).
        let mut overlapped: OVERLAPPED = unsafe { MaybeUninit::zeroed().assume_init() };
        overlapped.hEvent = self.event;
        let read_result = unsafe { ReadFile(self.handle, Some(buf), None, Some(&mut overlapped)) };
        let mut bytes: u32 = 0;
        match read_result {
            Ok(()) => {
                // SAFETY: overlapped is populated; bWait=false (already done).
                unsafe {
                    GetOverlappedResult(self.handle, &overlapped, &mut bytes, false)
                        .map_err(|e| io::Error::from_raw_os_error(e.code().0))?;
                }
                Ok(bytes as usize)
            }
            Err(_) => {
                let last = last_error();
                if last == ERR_IO_PENDING {
                    // SAFETY: wait for completion via the event.
                    unsafe {
                        GetOverlappedResult(self.handle, &overlapped, &mut bytes, true)
                            .map_err(|e| io::Error::from_raw_os_error(e.code().0))?;
                    }
                    Ok(bytes as usize)
                } else {
                    Err(io::Error::from_raw_os_error(last as i32))
                }
            }
        }
    }
}

impl Write for PipeIo {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // SAFETY: same lifetime contract as `read`.
        let mut overlapped: OVERLAPPED = unsafe { MaybeUninit::zeroed().assume_init() };
        overlapped.hEvent = self.event;
        let write_result =
            unsafe { WriteFile(self.handle, Some(buf), None, Some(&mut overlapped)) };
        let mut bytes: u32 = 0;
        match write_result {
            Ok(()) => {
                // SAFETY: overlapped populated; bWait=false.
                unsafe {
                    GetOverlappedResult(self.handle, &overlapped, &mut bytes, false)
                        .map_err(|e| io::Error::from_raw_os_error(e.code().0))?;
                }
                Ok(bytes as usize)
            }
            Err(_) => {
                let last = last_error();
                if last == ERR_IO_PENDING {
                    // SAFETY: wait for completion via the event.
                    unsafe {
                        GetOverlappedResult(self.handle, &overlapped, &mut bytes, true)
                            .map_err(|e| io::Error::from_raw_os_error(e.code().0))?;
                    }
                    Ok(bytes as usize)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sddl_grants_only_client_sid_and_medium_label() {
        let sddl = broker_pipe_sddl("S-1-5-21-100-200-300-1001").expect("sddl");
        assert_eq!(
            sddl,
            "D:(A;;GRGW;;;S-1-5-21-100-200-300-1001)S:(ML;;NW;;;ME)"
        );
    }

    #[test]
    fn sddl_rejects_injection_attempts() {
        assert!(broker_pipe_sddl("S-1-5-21);(A;;GA;;;WD").is_err());
        assert!(broker_pipe_sddl("not-a-sid").is_err());
        assert!(broker_pipe_sddl("S-1-5-(evil)").is_err());
    }

    #[test]
    fn current_process_sid_is_well_formed() {
        let sid = current_process_user_sid().expect("own sid");
        assert!(sid.starts_with("S-1-"), "got {sid}");
    }

    #[test]
    fn owner_restricted_pipe_can_be_created_with_own_sid() {
        let sid = current_process_user_sid().expect("own sid");
        let name = format!(r"\\.\pipe\NetRuleRouter\broker-test-{}", std::process::id());
        let pipe = create_owner_restricted_pipe(&name, &sid, true).expect("create pipe");
        // Drop closes it; creating proves the SDDL converts + CreateNamedPipeW
        // accepts the descriptor.
        drop(pipe);
    }

    /// End-to-end over a REAL named pipe (no elevation, no service): proves
    /// the owner-restricted pipe + parent-watched accept + PID/SID identity
    /// checks + the length-prefixed JSON frame codec all agree across a
    /// genuine client/server boundary. The client connects from the SAME
    /// process, so PID and SID match (exactly the same-account self-elevation
    /// case the broker is built for).
    #[test]
    fn end_to_end_owner_checks_and_frame_round_trip() {
        use std::thread;

        use nrr_ipc_client::wire::{read_frame, write_frame};

        use crate::protocol::{BrokerRequest, BrokerResponse, BROKER_PING};

        let own_sid = current_process_user_sid().expect("own sid");
        let own_pid = std::process::id();
        let pipe_name = format!(r"\\.\pipe\NetRuleRouter\broker-e2e-{own_pid}");
        let nonce = "e2e-nonce-deadbeef".to_string();

        let sid_for_srv = own_sid.clone();
        let name_for_srv = pipe_name.clone();
        let nonce_srv = nonce.clone();
        let server = thread::spawn(move || {
            // Watch our own process — it never exits during the test, so only
            // the client connection fires the accept.
            let parent = open_parent_process(std::process::id()).expect("parent self");
            let pipe = create_owner_restricted_pipe(&name_for_srv, &sid_for_srv, false)
                .expect("create pipe");
            match accept_with_parent_watch(pipe.raw(), parent.raw()) {
                AcceptResult::Connected => {}
                AcceptResult::ParentExited => panic!("unexpected ParentExited during accept"),
                AcceptResult::Failed(e) => panic!("accept failed: {e}"),
            }
            // Owner check #1: connecting PID is us.
            assert_eq!(
                client_process_id(pipe.raw()).expect("pid"),
                std::process::id()
            );
            // Owner check #2: connecting SID is us.
            assert_eq!(pipe_client_user_sid(pipe.raw()).expect("sid"), sid_for_srv);
            // Frame round trip + owner check #3 (nonce).
            let mut io = PipeIo::new(pipe.raw()).expect("server io");
            let req: BrokerRequest = read_frame(&mut io).expect("read request");
            assert_eq!(req.nonce, nonce_srv);
            assert_eq!(req.operation, BROKER_PING);
            write_frame(
                &mut io,
                &BrokerResponse::ok(serde_json::json!({"pong": true})),
            )
            .expect("write response");
            disconnect_and_close(pipe.into_raw());
        });

        // Client side (same process). connect_pipe retries until the server
        // has created its first instance.
        let handle = connect_pipe(&pipe_name, Duration::from_secs(5)).expect("client connect");
        let mut io = PipeIo::new(handle.raw()).expect("client io");
        let request = BrokerRequest {
            nonce: nonce.clone(),
            operation: BROKER_PING.to_string(),
            payload: serde_json::json!({}),
            timeout_ms: 1000,
        };
        write_frame(&mut io, &request).expect("write request");
        let response: BrokerResponse = read_frame(&mut io).expect("read response");
        assert!(response.ok, "ping should succeed");

        server.join().expect("server thread joined cleanly");
    }
}
