//! `Microsoft-Windows-DNS-Client` ETW observer.
//!
//! A real-time ETW consumer that subscribes to the DNS-Client provider
//! (`{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}`) and buffers every completed
//! A-record resolution (event 3008) as a [`DnsObservation`]. Pure
//! user-mode — no kernel callout driver, no DNS-config change, no port-53
//! binding.
//!
//! ## Verification status
//!
//! **This module is NOT unit-tested and has NOT been verified on hardware.**
//! Real-time ETW consumption (`ProcessTrace` on a dedicated thread + a
//! C callback parsing the manifest event payload) cannot be exercised
//! without a live Windows session emitting DNS traffic. The surrounding
//! pipeline (`DnsObservationConsumer` → cache → route codegen) IS tested
//! via [`super::MockDnsObservationSource`]. Treat [`EtwDnsObserver`] as the
//! one brick proven only by a `/run` smoke test.
//!
//! ## Graceful degradation
//!
//! Every failure path returns an `Err`/logs and yields no observations —
//! the service keeps running, only suffix/zone routing is degraded. The
//! trace session is stopped + closed on drop.
//!
//! ## Payload parsing
//!
//! Event 3008 carries `QueryName` (UTF-16 string) followed by fixed-size
//! fields and a `QueryResults` (UTF-16 string) listing the answers. Rather
//! than depend on TDH schema walking, we extract the two UTF-16 strings
//! from `UserData` directly and scan `QueryResults` for dotted-quad IPv4
//! tokens. This is the pragmatic approach common to ETW DNS monitors; it
//! is tolerant of the extra type-prefix decoration Windows adds to the
//! results string.

#![cfg(target_os = "windows")]
#![allow(unsafe_code)]

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use windows::core::{GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::{GetLastError, WIN32_ERROR};
use windows::Win32::System::Diagnostics::Etw::{
    CloseTrace, ControlTraceW, EnableTraceEx2, OpenTraceW, ProcessTrace, StartTraceW,
    CONTROLTRACE_HANDLE, ENABLE_TRACE_PARAMETERS, EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_RECORD,
    EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES,
    EVENT_TRACE_REAL_TIME_MODE, PROCESSTRACE_HANDLE, PROCESS_TRACE_MODE_EVENT_RECORD,
    PROCESS_TRACE_MODE_REAL_TIME, TRACE_LEVEL_INFORMATION, WNODE_FLAG_TRACED_GUID,
};

use super::{DnsObservation, DnsObservationSource};
use crate::error::PlatformError;

/// `Microsoft-Windows-DNS-Client` provider GUID.
const DNS_CLIENT_PROVIDER: GUID = GUID::from_u128(0x1c95126e_7eea_49a9_a3fe_a378b03ddb4d);

/// Event id for "DNS query completed".
const EVENT_ID_QUERY_COMPLETED: u16 = 3008;

/// Shared buffer of observations, drained by the consumer. The ETW
/// callback (a C ABI fn with no closure capture) reaches it through the
/// `EVENT_RECORD.UserContext` pointer set on `OpenTraceW`.
type Buffer = Arc<Mutex<Vec<DnsObservation>>>;

/// A running real-time ETW consumer for DNS-Client events.
pub struct EtwDnsObserver {
    buffer: Buffer,
    session_name: Vec<u16>,
    control_handle: CONTROLTRACE_HANDLE,
    process_handle: PROCESSTRACE_HANDLE,
    stop_flag: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

// The handles are owned solely by this struct, which serialises access; the
// background thread only calls `ProcessTrace` (blocking) and the callback
// only touches the `Buffer` behind its mutex.
unsafe impl Send for EtwDnsObserver {}
unsafe impl Sync for EtwDnsObserver {}

impl DnsObservationSource for EtwDnsObserver {
    fn drain(&self) -> Vec<DnsObservation> {
        match self.buffer.lock() {
            Ok(mut g) => std::mem::take(&mut *g),
            Err(_) => Vec::new(),
        }
    }
}

/// Allocate + initialize an `EVENT_TRACE_PROPERTIES` buffer for the real-time
/// session `session_name`, reserving room for the struct, the logger name, AND
/// a log-file-name region. The kernel writes name regions back into the buffer
/// on Query/Stop, so a buffer sized only for struct+name is overrun when
/// `ControlTraceW(STOP)` finds a stale session — which then makes the following
/// `StartTraceW` fail with `ERROR_BAD_LENGTH` (0x18). Always give the STOP call
/// and the StartTraceW call SEPARATE buffers; never reuse one across both.
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

impl EtwDnsObserver {
    /// Start a real-time ETW session, enable the DNS-Client provider, and
    /// spawn the `ProcessTrace` worker. Returns an error (and starts
    /// nothing) on any setup failure — the caller degrades to no
    /// observation.
    pub fn start() -> Result<Self, PlatformError> {
        let buffer: Buffer = Arc::new(Mutex::new(Vec::new()));
        let session_name = wide("NrrDnsObserve");

        // ── Allocate TWO independent EVENT_TRACE_PROPERTIES buffers. The
        // kernel writes the stale session's full properties back into the
        // buffer handed to ControlTraceW(STOP); reusing that same buffer for
        // StartTraceW then passes a mutated/over-stuffed struct and StartTraceW
        // fails with ERROR_BAD_LENGTH (0x18) whenever a stale session was
        // present. So STOP gets its own scratch buffer and StartTraceW a
        // pristine one, both sized by `alloc_trace_props` to absorb the
        // kernel's writeback. ──
        let mut stop_buf = alloc_trace_props(&session_name);
        let mut props_buf = alloc_trace_props(&session_name);
        let props = props_buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;

        let mut control_handle = CONTROLTRACE_HANDLE::default();
        // SAFETY: `session_name` outlives both calls; `stop_buf` / `props_buf`
        // are independently owned, adequately sized, and live to fn end.
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
                    operation: "StartTraceW(NrrDnsObserve)",
                    code: start.0,
                    message: "failed to start DNS-observe ETW session".into(),
                });
            }
        }

        // ── Enable the DNS-Client provider on the session. ──
        let enable_params = ENABLE_TRACE_PARAMETERS {
            Version: 2, // ENABLE_TRACE_PARAMETERS_VERSION_2
            ..Default::default()
        };
        let enable = unsafe {
            EnableTraceEx2(
                control_handle,
                &DNS_CLIENT_PROVIDER,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
                TRACE_LEVEL_INFORMATION as u8,
                0,
                0,
                0,
                Some(&enable_params),
            )
        };
        if enable != WIN32_ERROR(0) {
            unsafe {
                let _ = ControlTraceW(
                    control_handle,
                    PCWSTR(session_name.as_ptr()),
                    props,
                    EVENT_TRACE_CONTROL_STOP,
                );
            }
            return Err(PlatformError::Win32 {
                operation: "EnableTraceEx2(DNS-Client)",
                code: enable.0,
                message: "failed to enable DNS-Client ETW provider".into(),
            });
        }

        // ── Open the trace for real-time consumption. The buffer pointer
        // is threaded to the C callback via the logfile Context. ──
        let mut logfile = EVENT_TRACE_LOGFILEW {
            LoggerName: PWSTR(session_name.as_ptr() as *mut u16),
            ..Default::default()
        };
        logfile.Anonymous1.ProcessTraceMode =
            PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.Anonymous2.EventRecordCallback = Some(event_record_callback);
        // Hand the callback a stable raw pointer to the buffer. The Arc is
        // kept alive by `self.buffer`; we leak one ref for the callback's
        // lifetime and reclaim it on drop.
        let ctx = Arc::into_raw(Arc::clone(&buffer)) as *mut std::ffi::c_void;
        logfile.Context = ctx;

        let process_handle = unsafe { OpenTraceW(&mut logfile) };
        // OpenTraceW returns INVALID_PROCESSTRACE_HANDLE (u64::MAX on the
        // wire) on failure.
        if process_handle.Value == u64::MAX {
            let err = unsafe { GetLastError() };
            unsafe {
                drop(Arc::from_raw(ctx as *const Mutex<Vec<DnsObservation>>));
                let _ = ControlTraceW(
                    control_handle,
                    PCWSTR(session_name.as_ptr()),
                    props,
                    EVENT_TRACE_CONTROL_STOP,
                );
            }
            return Err(PlatformError::Win32 {
                operation: "OpenTraceW(NrrDnsObserve)",
                code: err.0,
                message: "failed to open DNS-observe ETW trace".into(),
            });
        }

        // ── Spawn the blocking ProcessTrace pump on its own thread. ──
        let stop_flag = Arc::new(AtomicBool::new(false));
        let worker = {
            let handle = process_handle;
            std::thread::Builder::new()
                .name("nrr-dns-etw".into())
                .spawn(move || {
                    // ProcessTrace blocks until the session stops / trace
                    // closes. Return value ignored — shutdown is driven by
                    // `CloseTrace` in `Drop`.
                    let _ = unsafe { ProcessTrace(&[handle], None, None) };
                })
                .map_err(|e| PlatformError::Win32 {
                    operation: "spawn(nrr-dns-etw)",
                    code: 0,
                    message: e.to_string(),
                })?
        };

        tracing::info!(
            target: "nrr::dns-observe",
            "DNS-Client ETW observer started",
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

impl Drop for EtwDnsObserver {
    fn drop(&mut self) {
        self.stop_flag.store(true, Ordering::SeqCst);
        // Stop the session and close the trace → ProcessTrace returns and
        // the worker thread exits.
        let mut props_buf = alloc_trace_props(&self.session_name);
        let props = props_buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
        // SAFETY: stop the session + close the trace → ProcessTrace returns and
        // the worker exits. `props_buf` is adequately sized for the kernel's
        // Stop writeback (see `alloc_trace_props`).
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

/// C-ABI ETW record callback. Extracts event 3008's query name + results
/// and pushes a [`DnsObservation`] when at least one IPv4 was answered.
unsafe extern "system" fn event_record_callback(record: *mut EVENT_RECORD) {
    if record.is_null() {
        return;
    }
    let rec = &*record;
    if rec.EventHeader.EventDescriptor.Id != EVENT_ID_QUERY_COMPLETED {
        return;
    }
    // Reconstruct the buffer handle (borrow, do NOT drop — ownership stays
    // with the observer's Arc).
    let ctx = rec.UserContext as *const Mutex<Vec<DnsObservation>>;
    if ctx.is_null() {
        return;
    }
    let buffer = &*ctx;

    let data = rec.UserData as *const u8;
    let len = rec.UserDataLength as usize;
    if data.is_null() || len < 2 {
        return;
    }
    let bytes = std::slice::from_raw_parts(data, len);

    // Field layout for event 3008: QueryName (UTF-16, NUL-terminated),
    // then fixed fields, then QueryResults (UTF-16, NUL-terminated). We
    // read the first UTF-16 string as the name and the LAST UTF-16 string
    // as the results, which is robust to the intervening fixed fields.
    let (hostname, after) = match read_utf16z(bytes, 0) {
        Some(v) => v,
        None => return,
    };
    let results = read_last_utf16z(bytes, after).unwrap_or_default();
    let ipv4s = parse_ipv4_tokens(&results);
    if ipv4s.is_empty() {
        return;
    }
    let canonical = super::super::dns::canonicalize_hostname(&hostname);
    if canonical.is_empty() {
        return;
    }
    if let Ok(mut g) = buffer.lock() {
        // Bound the buffer so a runaway DNS storm between drains cannot
        // grow it without limit (the consumer drains every few seconds).
        if g.len() < 4096 {
            g.push(DnsObservation {
                hostname: canonical,
                ipv4s,
            });
        }
    }
}

/// Read a NUL-terminated UTF-16 string starting at `off`. Returns the
/// decoded string and the byte offset just past its terminator.
fn read_utf16z(bytes: &[u8], off: usize) -> Option<(String, usize)> {
    let mut units: Vec<u16> = Vec::new();
    let mut i = off;
    while i + 1 < bytes.len() {
        let u = u16::from_le_bytes([bytes[i], bytes[i + 1]]);
        i += 2;
        if u == 0 {
            return Some((String::from_utf16_lossy(&units), i));
        }
        units.push(u);
    }
    if units.is_empty() {
        None
    } else {
        Some((String::from_utf16_lossy(&units), i))
    }
}

/// Read the LAST NUL-terminated UTF-16 string in `bytes[from..]`. The
/// results string is the final field of event 3008.
fn read_last_utf16z(bytes: &[u8], from: usize) -> Option<String> {
    let mut last: Option<String> = None;
    let mut i = from;
    while i + 1 < bytes.len() {
        if let Some((s, next)) = read_utf16z(bytes, i) {
            if !s.is_empty() {
                last = Some(s);
            }
            if next <= i {
                break;
            }
            i = next;
        } else {
            break;
        }
    }
    last
}

/// Scan a DNS-results string for dotted-quad IPv4 tokens. Windows decorates
/// results with type prefixes / semicolons (e.g. `"type:  5 ...;1.2.3.4;"`);
/// we just collect every substring that parses as an `Ipv4Addr`.
fn parse_ipv4_tokens(results: &str) -> Vec<Ipv4Addr> {
    let mut out: Vec<Ipv4Addr> = Vec::new();
    for token in results.split(|c: char| !(c.is_ascii_digit() || c == '.')) {
        if token.is_empty() {
            continue;
        }
        if let Ok(ip) = token.parse::<Ipv4Addr>() {
            if !out.contains(&ip) {
                out.push(ip);
            }
        }
    }
    out
}

/// NUL-terminated UTF-16 from a `&str`.
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ipv4_tokens_extracts_dotted_quads() {
        let ips = parse_ipv4_tokens("type:  1 93.184.216.34;type:  1 93.184.216.35;");
        assert_eq!(
            ips,
            vec![
                Ipv4Addr::new(93, 184, 216, 34),
                Ipv4Addr::new(93, 184, 216, 35)
            ]
        );
    }

    #[test]
    fn parse_ipv4_tokens_ignores_ipv6_and_garbage() {
        // IPv6 tokens contain ':' / hex → not dotted-quad → skipped.
        let ips = parse_ipv4_tokens("::ffff:abcd;not-an-ip;10.0.0.1;");
        assert_eq!(ips, vec![Ipv4Addr::new(10, 0, 0, 1)]);
    }

    #[test]
    fn read_utf16z_roundtrips() {
        let mut bytes: Vec<u8> = Vec::new();
        for u in "host.example.com".encode_utf16() {
            bytes.extend_from_slice(&u.to_le_bytes());
        }
        bytes.extend_from_slice(&0u16.to_le_bytes());
        let (s, off) = read_utf16z(&bytes, 0).unwrap();
        assert_eq!(s, "host.example.com");
        assert_eq!(off, bytes.len());
    }
}
