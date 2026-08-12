//! Connection observation via the `Microsoft-Windows-Kernel-Network` ETW
//! provider — the guaranteed-capture fallback backend.
//!
//! Where [`super::wfp_events`] depends on WFP emitting `CLASSIFY_ALLOW` net
//! events (which need a permit filter to fire), the kernel TCP/IP provider
//! emits a **connect** event for *every* outbound TCP connection from *every*
//! process unconditionally — no filter, no engine option. So this backend is
//! the safety net when the WFP backend can't see permitted flows on a given
//! host. It is a near-copy of the proven [`super::super::dns_observe::etw`]
//! session scaffold (StartTraceW / EnableTraceEx2 / OpenTraceW / ProcessTrace +
//! an `EVENT_RECORD` C callback); only the provider GUID, the event id, and the
//! payload parse differ.
//!
//! It yields PID + 5-tuple (no process image path, no SID, no allow/block
//! verdict — those are WFP's). The local (source) address in the connect event
//! is the egress interface's address, which is exactly what
//! [`super::egress`] needs.
//!
//! ## Verification status
//!
//! Like the DNS observer, the live ETW path is not unit-testable without a
//! Windows session emitting traffic; the payload parse ([`parse_tcp_connect_v4`])
//! IS unit-tested. NOT yet hardware-verified.

#![cfg(target_os = "windows")]
#![allow(unsafe_code)]

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use windows::core::{GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, GetLastError, FALSE, WIN32_ERROR};
use windows::Win32::System::Diagnostics::Etw::{
    CloseTrace, ControlTraceW, EnableTraceEx2, OpenTraceW, ProcessTrace, StartTraceW,
    CONTROLTRACE_HANDLE, ENABLE_TRACE_PARAMETERS, EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_RECORD,
    EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES,
    EVENT_TRACE_REAL_TIME_MODE, PROCESSTRACE_HANDLE, PROCESS_TRACE_MODE_EVENT_RECORD,
    PROCESS_TRACE_MODE_REAL_TIME, TRACE_LEVEL_INFORMATION, WNODE_FLAG_TRACED_GUID,
};
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
};

use super::{
    ConnectionObservation, ConnectionObservationSource, ConnectionProgress, ConnectionVerdict,
    TransportProtocol,
};
use crate::error::PlatformError;

/// `Microsoft-Windows-Kernel-Network` provider GUID.
const KERNEL_NETWORK_PROVIDER: GUID = GUID::from_u128(0x7dd42a49_5329_4832_8dfd_43d979153a88);

/// Keywords: collect IPv4 + IPv6 TCP/IP events
/// (`KERNEL_NETWORK_KEYWORD_IPV4` | `_IPV6`).
const KEYWORD_IPV4: u64 = 0x10;
const KEYWORD_IPV6: u64 = 0x20;

/// Event ids for "TCP connection attempted" (outbound connect SYN). The IPv4 id
/// (12) is stable; the IPv6 id (28) is per the Kernel-Network manifest but NOT
/// hardware-verified. The payload parse length-guards, so a wrong id simply
/// yields no IPv6 connects — never garbage — and never affects IPv4.
const EVENT_ID_TCP_CONNECT_V4: u16 = 12;
const EVENT_ID_TCP_CONNECT_V6: u16 = 28;

/// Event ids for "connection torn down in order" and "segment sent again".
/// Both share the connect payload layout (the `TcpIp_TypeGroup1` shape), so the
/// same parsers read them. They answer "does this peer work over this link?" —
/// a resend means it was not acknowledging, an orderly close means it carried
/// traffic. Per-connection, not per-segment: the data-path cost is the same
/// order as connects, unlike `datasent`/`datarecv`, which are deliberately NOT
/// subscribed. Same caveat as the IPv6 connect id — manifest-derived, not
/// hardware-verified; a wrong id yields no events rather than garbage.
const EVENT_ID_TCP_DISCONNECT_V4: u16 = 13;
const EVENT_ID_TCP_DISCONNECT_V6: u16 = 29;
const EVENT_ID_TCP_RETRANSMIT_V4: u16 = 14;
const EVENT_ID_TCP_RETRANSMIT_V6: u16 = 30;

/// Hard cap on buffered observations between drains.
const BUFFER_CAP: usize = 8192;

type Buffer = Arc<Mutex<Vec<ConnectionObservation>>>;

/// A running real-time ETW consumer for kernel TCP/IP connect events.
pub struct EtwKernelNetworkObserver {
    buffer: Buffer,
    session_name: Vec<u16>,
    control_handle: CONTROLTRACE_HANDLE,
    process_handle: PROCESSTRACE_HANDLE,
    stop_flag: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

// Handles owned solely by this struct; the callback only touches the buffer.
unsafe impl Send for EtwKernelNetworkObserver {}
unsafe impl Sync for EtwKernelNetworkObserver {}

impl ConnectionObservationSource for EtwKernelNetworkObserver {
    fn drain(&self) -> Vec<ConnectionObservation> {
        match self.buffer.lock() {
            Ok(mut g) => std::mem::take(&mut *g),
            Err(_) => Vec::new(),
        }
    }
}

/// Allocate + initialize an `EVENT_TRACE_PROPERTIES` buffer for the real-time
/// session `session_name`, reserving room for the struct, the logger name, AND
/// a log-file-name region so the kernel's Query/Stop writeback cannot overrun
/// it. Same defect class + fix as the DNS observer: never reuse one buffer
/// across `ControlTraceW(STOP)` and `StartTraceW`.
fn alloc_trace_props(session_name: &[u16]) -> Vec<u8> {
    const LOGFILE_PAD_CHARS: usize = 1024;
    let name_bytes = std::mem::size_of_val(session_name);
    let pad_bytes = LOGFILE_PAD_CHARS * std::mem::size_of::<u16>();
    let props_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + name_bytes + pad_bytes;
    let mut buf: Vec<u8> = vec![0u8; props_size];
    // SAFETY: `buf` is `props_size` bytes, ≥ size_of::<EVENT_TRACE_PROPERTIES>().
    let props = buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
    unsafe {
        (*props).Wnode.BufferSize = props_size as u32;
        (*props).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        (*props).Wnode.ClientContext = 1; // QPC clock
        (*props).LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        (*props).LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;
    }
    buf
}

impl EtwKernelNetworkObserver {
    /// Start a real-time ETW session, enable the Kernel-Network provider for
    /// IPv4, and spawn the `ProcessTrace` worker. Returns an error (and starts
    /// nothing) on any setup failure — the caller degrades to no observation.
    pub fn start() -> Result<Self, PlatformError> {
        let buffer: Buffer = Arc::new(Mutex::new(Vec::new()));
        let session_name = wide("NrrConnObserve");

        // TWO independent buffers so the STOP writeback cannot corrupt the
        // pristine StartTraceW buffer (same defect + fix as the DNS observer).
        // Both sized by `alloc_trace_props`.
        let mut stop_buf = alloc_trace_props(&session_name);
        let mut props_buf = alloc_trace_props(&session_name);
        let props = props_buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;

        let mut control_handle = CONTROLTRACE_HANDLE::default();
        // SAFETY: stop any stale same-named session, then start fresh; the
        // buffers and `session_name` outlive both calls.
        unsafe {
            let _ = ControlTraceW(
                CONTROLTRACE_HANDLE::default(),
                PCWSTR(session_name.as_ptr()),
                stop_buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES,
                EVENT_TRACE_CONTROL_STOP,
            );
            let start = StartTraceW(&mut control_handle, PCWSTR(session_name.as_ptr()), props);
            if start != WIN32_ERROR(0) {
                return Err(PlatformError::Win32 {
                    operation: "StartTraceW(NrrConnObserve)",
                    code: start.0,
                    message: "failed to start conn-observe ETW session".into(),
                });
            }
        }

        let enable_params = ENABLE_TRACE_PARAMETERS {
            Version: 2, // ENABLE_TRACE_PARAMETERS_VERSION_2
            ..Default::default()
        };
        // SAFETY: `control_handle` is the just-started session; provider GUID is
        // static; keyword limits to IPv4; `enable_params` outlives the call.
        let enable = unsafe {
            EnableTraceEx2(
                control_handle,
                &KERNEL_NETWORK_PROVIDER,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
                TRACE_LEVEL_INFORMATION as u8,
                KEYWORD_IPV4 | KEYWORD_IPV6,
                0,
                0,
                Some(&enable_params),
            )
        };
        if enable != WIN32_ERROR(0) {
            // SAFETY: tear the session down on enable failure.
            unsafe {
                let _ = ControlTraceW(
                    control_handle,
                    PCWSTR(session_name.as_ptr()),
                    props,
                    EVENT_TRACE_CONTROL_STOP,
                );
            }
            return Err(PlatformError::Win32 {
                operation: "EnableTraceEx2(Kernel-Network)",
                code: enable.0,
                message: "failed to enable Kernel-Network ETW provider".into(),
            });
        }

        let mut logfile = EVENT_TRACE_LOGFILEW {
            LoggerName: PWSTR(session_name.as_ptr() as *mut u16),
            ..Default::default()
        };
        logfile.Anonymous1.ProcessTraceMode =
            PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.Anonymous2.EventRecordCallback = Some(event_record_callback);
        // Hand the callback a stable raw pointer to the buffer; reclaimed on drop.
        let ctx = Arc::into_raw(Arc::clone(&buffer)) as *mut std::ffi::c_void;
        logfile.Context = ctx;

        // SAFETY: `logfile` is fully initialised; the callback is a static fn.
        let process_handle = unsafe { OpenTraceW(&mut logfile) };
        if process_handle.Value == u64::MAX {
            let err = unsafe { GetLastError() };
            // SAFETY: reclaim the leaked Arc ref and stop the session.
            unsafe {
                drop(Arc::from_raw(
                    ctx as *const Mutex<Vec<ConnectionObservation>>,
                ));
                let _ = ControlTraceW(
                    control_handle,
                    PCWSTR(session_name.as_ptr()),
                    props,
                    EVENT_TRACE_CONTROL_STOP,
                );
            }
            return Err(PlatformError::Win32 {
                operation: "OpenTraceW(NrrConnObserve)",
                code: err.0,
                message: "failed to open conn-observe ETW trace".into(),
            });
        }

        let stop_flag = Arc::new(AtomicBool::new(false));
        let worker = {
            let handle = process_handle;
            std::thread::Builder::new()
                .name("nrr-conn-etw".into())
                .spawn(move || {
                    // SAFETY: `handle` is a valid real-time trace handle until
                    // `CloseTrace` in `Drop` makes `ProcessTrace` return.
                    let _ = unsafe { ProcessTrace(&[handle], None, None) };
                })
                .map_err(|e| PlatformError::Win32 {
                    operation: "spawn(nrr-conn-etw)",
                    code: 0,
                    message: e.to_string(),
                })?
        };

        tracing::info!(
            target: "nrr::conn-observe",
            "Kernel-Network ETW connection observer started",
        );
        Ok(Self {
            buffer,
            session_name,
            control_handle,
            process_handle,
            stop_flag,
            worker: Some(worker),
        })
    }
}

impl Drop for EtwKernelNetworkObserver {
    fn drop(&mut self) {
        self.stop_flag.store(true, Ordering::SeqCst);
        let mut props_buf = alloc_trace_props(&self.session_name);
        let props = props_buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
        // SAFETY: stop the session + close the trace → ProcessTrace returns and
        // the worker exits; mirrors the DNS observer's teardown. `props_buf` is
        // adequately sized for the kernel's Stop writeback (alloc_trace_props).
        unsafe {
            let _ = ControlTraceW(
                self.control_handle,
                PCWSTR(self.session_name.as_ptr()),
                props,
                EVENT_TRACE_CONTROL_STOP,
            );
            let _ = CloseTrace(self.process_handle);
        }
        if let Some(w) = self.worker.take() {
            let _ = w.join();
        }
    }
}

/// Which of the subscribed events this record is: `(is_v6, progress)`, or
/// `None` for every other id the provider emits.
fn classify_event(event_id: u16) -> Option<(bool, ConnectionProgress)> {
    match event_id {
        EVENT_ID_TCP_CONNECT_V4 => Some((false, ConnectionProgress::Attempt)),
        EVENT_ID_TCP_CONNECT_V6 => Some((true, ConnectionProgress::Attempt)),
        EVENT_ID_TCP_DISCONNECT_V4 => Some((false, ConnectionProgress::ClosedInOrder)),
        EVENT_ID_TCP_DISCONNECT_V6 => Some((true, ConnectionProgress::ClosedInOrder)),
        EVENT_ID_TCP_RETRANSMIT_V4 => Some((false, ConnectionProgress::Retransmit)),
        EVENT_ID_TCP_RETRANSMIT_V6 => Some((true, ConnectionProgress::Retransmit)),
        _ => None,
    }
}

/// C-ABI ETW record callback. Parses the subscribed TCP events into a
/// [`ConnectionObservation`] and buffers it.
unsafe extern "system" fn event_record_callback(record: *mut EVENT_RECORD) {
    if record.is_null() {
        return;
    }
    let rec = &*record;
    let event_id = rec.EventHeader.EventDescriptor.Id;
    let Some((is_v6, progress)) = classify_event(event_id) else {
        return;
    };
    let ctx = rec.UserContext as *const Mutex<Vec<ConnectionObservation>>;
    if ctx.is_null() {
        return;
    }
    let buffer = &*ctx;

    let data = rec.UserData as *const u8;
    let len = rec.UserDataLength as usize;
    if data.is_null() {
        return;
    }
    let bytes = std::slice::from_raw_parts(data, len);
    let parsed = if is_v6 {
        parse_tcp_connect_v6(bytes).map(|(pid, l, r)| (pid, SocketAddr::V6(l), SocketAddr::V6(r)))
    } else {
        parse_tcp_connect_v4(bytes).map(|(pid, l, r)| (pid, SocketAddr::V4(l), SocketAddr::V4(r)))
    };
    let Some((pid, local, remote)) = parsed else {
        return;
    };

    // Resolve PID → image path here, while the process is (almost always) still
    // alive — the buffer is drained ~5 s later, by which point a short-lived
    // process may have exited. Done BEFORE taking the buffer lock so the syscall
    // never runs under it. Skipped for progress events: they never become trace
    // rows, so the `OpenProcess` round-trip would buy nothing.
    let process_path = if progress == ConnectionProgress::Attempt {
        resolve_process_path(pid)
    } else {
        None
    };
    // Stamped here, in the ETW callback: the buffer is drained on a timer, so a
    // record left unstamped would carry the DRAIN time and every connection of
    // the interval would collapse onto one instant. The kernel connect event
    // itself carries no usable timestamp field.
    let observed_unix_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_millis() as u64);
    if let Ok(mut g) = buffer.lock() {
        if g.len() < BUFFER_CAP {
            g.push(ConnectionObservation {
                pid,
                process_path,
                user_sid: None,
                protocol: TransportProtocol::Tcp,
                local,
                remote,
                verdict: ConnectionVerdict::Unknown, // kernel connect carries no verdict.
                drop_filter_id: None,                // ETW connects are not drops.
                blocked_by_nrr: None,
                nrr_drop_spec_id: None,
                observed_unix_ms,
                progress,
            });
        }
    }
}

/// Resolve a connect event's PID to the owning process's full image path.
///
/// The Kernel-Network ETW `connect` event carries only the PID; the image path
/// is looked up separately via `OpenProcess` + `QueryFullProcessImageNameW`.
/// Best-effort — returns `None` for PID 0, a process that has already exited,
/// or a protected/System PID `OpenProcess` cannot open. The trace row then
/// shows the "?" sentinel, exactly as before this resolver existed.
fn resolve_process_path(pid: u32) -> Option<String> {
    if pid == 0 {
        return None;
    }
    // SAFETY: `OpenProcess` with QUERY_LIMITED rights on a (live) PID; the
    // returned handle is closed on every path before returning.
    // `QueryFullProcessImageNameW` writes at most `size` UTF-16 code units into
    // `buf` and updates `size` to the count written (excluding the NUL).
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid).ok()?;
        if handle.is_invalid() {
            return None;
        }
        let mut buf = [0u16; 260]; // MAX_PATH — Win32 image paths fit.
        let mut size = buf.len() as u32;
        let query = QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            PWSTR(buf.as_mut_ptr()),
            &mut size,
        );
        let _ = CloseHandle(handle);
        query.ok()?;
        if size == 0 {
            return None;
        }
        Some(String::from_utf16_lossy(&buf[..size as usize]))
    }
}

/// Parse the payload of `Microsoft-Windows-Kernel-Network` event 12 (TCP IPv4
/// connect). Returns `(pid, local = source addr:port, remote = dest addr:port)`.
///
/// Leading fixed layout (stable across Windows versions; the pointer-sized
/// `connid` that varies x86/x64 sits *after* these fields, so it never shifts
/// them): `u32 pid; u32 size; u32 daddr; u32 saddr; u16 dport; u16 sport; …`.
/// Addresses are stored as IPv4 in network byte order (read the 4 bytes as
/// octets); ports are network byte order (big-endian).
fn parse_tcp_connect_v4(d: &[u8]) -> Option<(u32, SocketAddrV4, SocketAddrV4)> {
    if d.len() < 20 {
        return None;
    }
    let pid = u32::from_le_bytes([d[0], d[1], d[2], d[3]]);
    let daddr = Ipv4Addr::new(d[8], d[9], d[10], d[11]);
    let saddr = Ipv4Addr::new(d[12], d[13], d[14], d[15]);
    let dport = u16::from_be_bytes([d[16], d[17]]);
    let sport = u16::from_be_bytes([d[18], d[19]]);
    let local = SocketAddrV4::new(saddr, sport);
    let remote = SocketAddrV4::new(daddr, dport);
    Some((pid, local, remote))
}

/// Parse the payload of `Microsoft-Windows-Kernel-Network` event 28 (TCP IPv6
/// connect). Same leading layout as v4 but with 16-byte addresses:
/// `u32 pid; u32 size; u8[16] daddr; u8[16] saddr; u16 dport; u16 sport; …`.
/// Addresses are the 16 octets in order; ports are network byte order.
fn parse_tcp_connect_v6(d: &[u8]) -> Option<(u32, SocketAddrV6, SocketAddrV6)> {
    if d.len() < 44 {
        return None;
    }
    let pid = u32::from_le_bytes([d[0], d[1], d[2], d[3]]);
    let daddr = Ipv6Addr::from(<[u8; 16]>::try_from(&d[8..24]).ok()?);
    let saddr = Ipv6Addr::from(<[u8; 16]>::try_from(&d[24..40]).ok()?);
    let dport = u16::from_be_bytes([d[40], d[41]]);
    let sport = u16::from_be_bytes([d[42], d[43]]);
    let local = SocketAddrV6::new(saddr, sport, 0, 0);
    let remote = SocketAddrV6::new(daddr, dport, 0, 0);
    Some((pid, local, remote))
}

/// NUL-terminated UTF-16 from a `&str`.
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_connect_payload() {
        // pid=4242, size=0, daddr=188.40.167.82, saddr=10.8.0.6,
        // dport=443 (0x01BB), sport=50000 (0xC350) — both network order.
        let mut d = vec![0u8; 24];
        d[0..4].copy_from_slice(&4242u32.to_le_bytes());
        d[8..12].copy_from_slice(&[188, 40, 167, 82]); // daddr
        d[12..16].copy_from_slice(&[10, 8, 0, 6]); // saddr
        d[16..18].copy_from_slice(&443u16.to_be_bytes()); // dport
        d[18..20].copy_from_slice(&50000u16.to_be_bytes()); // sport

        let (pid, local, remote) = parse_tcp_connect_v4(&d).expect("parse");
        assert_eq!(pid, 4242);
        assert_eq!(local, SocketAddrV4::new(Ipv4Addr::new(10, 8, 0, 6), 50000));
        assert_eq!(
            remote,
            SocketAddrV4::new(Ipv4Addr::new(188, 40, 167, 82), 443)
        );
    }

    #[test]
    fn rejects_short_payload() {
        assert!(parse_tcp_connect_v4(&[0u8; 8]).is_none());
        assert!(parse_tcp_connect_v6(&[0u8; 20]).is_none());
    }

    #[test]
    fn parses_v6_connect_payload() {
        // pid=7, daddr=2001:db8::1, saddr=fe80::2, dport=443, sport=50000.
        let mut d = vec![0u8; 48];
        d[0..4].copy_from_slice(&7u32.to_le_bytes());
        let daddr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let saddr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);
        d[8..24].copy_from_slice(&daddr.octets());
        d[24..40].copy_from_slice(&saddr.octets());
        d[40..42].copy_from_slice(&443u16.to_be_bytes());
        d[42..44].copy_from_slice(&50000u16.to_be_bytes());

        let (pid, local, remote) = parse_tcp_connect_v6(&d).expect("parse");
        assert_eq!(pid, 7);
        assert_eq!(local, SocketAddrV6::new(saddr, 50000, 0, 0));
        assert_eq!(remote, SocketAddrV6::new(daddr, 443, 0, 0));
    }
}
