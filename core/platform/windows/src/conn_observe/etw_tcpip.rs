//! Connection observation via the `Microsoft-Windows-Kernel-Network` ETW
//! provider — the guaranteed-capture fallback backend.
//!
//! Where [`super::wfp_events`] depends on WFP emitting `CLASSIFY_ALLOW` net
//! events (which need a permit filter to fire), the kernel TCP/IP provider
//! emits a **connect** event for *every* outbound TCP connection from *every*
//! process unconditionally — no filter, no engine option. So this backend is
//! the safety net when the WFP backend can't see permitted flows on a given
//! host. The session itself is [`crate::etw_session`]; only the provider, the
//! event ids and the payload parse live here.
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
use std::sync::{Arc, Mutex};

use windows::core::{GUID, PWSTR};
use windows::Win32::Foundation::{CloseHandle, FALSE};
use windows::Win32::System::Diagnostics::Etw::{EVENT_RECORD, TRACE_LEVEL_INFORMATION};
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
};

use super::{
    ConnectionObservation, ConnectionObservationSource, ConnectionProgress, ConnectionVerdict,
    TransportProtocol,
};
use crate::error::PlatformError;
use crate::etw_session::{
    callback_context, user_data, ProviderEnable, RealtimeSession, SessionClock, SessionConfig,
};

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
    session: RealtimeSession,
}

impl ConnectionObservationSource for EtwKernelNetworkObserver {
    fn drain(&self) -> Vec<ConnectionObservation> {
        match self.buffer.lock() {
            Ok(mut g) => std::mem::take(&mut *g),
            Err(_) => Vec::new(),
        }
    }
}

impl EtwKernelNetworkObserver {
    /// Start a real-time ETW session, enable the Kernel-Network provider for
    /// IPv4 + IPv6, and spawn the pump. Returns an error (and starts nothing)
    /// on any setup failure — the caller degrades to no observation.
    pub fn start() -> Result<Self, PlatformError> {
        let buffer: Buffer = Arc::new(Mutex::new(Vec::new()));
        let session = RealtimeSession::start(
            &SessionConfig {
                name: "NrrConnObserve",
                thread_name: "nrr-conn-etw",
                clock: SessionClock::PerformanceCounter,
                flush_timer_secs: 0,
            },
            &ProviderEnable {
                guid: KERNEL_NETWORK_PROVIDER,
                level: TRACE_LEVEL_INFORMATION as u8,
                keywords: KEYWORD_IPV4 | KEYWORD_IPV6,
                enable_property: 0,
            },
            event_record_callback,
            Arc::clone(&buffer),
        )?;
        tracing::info!(
            target: "nrr::conn-observe",
            msg_key = "win-etw-conn-observer-started",
            "Kernel-Network ETW connection observer started",
        );
        Ok(Self { buffer, session })
    }

    /// Stop the trace session and join the pump, without waiting for `Drop`:
    /// the consumer threads hold their own `Arc` to this source, and one still
    /// referenced at exit is never dropped (see [`RealtimeSession::stop`]).
    pub fn shutdown(&self) {
        self.session.stop();
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
    let Some(buffer) = callback_context::<Mutex<Vec<ConnectionObservation>>>(rec) else {
        return;
    };
    let Some(bytes) = user_data(rec) else {
        return;
    };
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_connect_payload() {
        // pid=4242, size=0, daddr=23.10.20.162, saddr=10.8.0.6,
        // dport=443 (0x01BB), sport=50000 (0xC350) — both network order.
        let mut d = vec![0u8; 24];
        d[0..4].copy_from_slice(&4242u32.to_le_bytes());
        d[8..12].copy_from_slice(&[23, 10, 20, 162]); // daddr
        d[12..16].copy_from_slice(&[10, 8, 0, 6]); // saddr
        d[16..18].copy_from_slice(&443u16.to_be_bytes()); // dport
        d[18..20].copy_from_slice(&50000u16.to_be_bytes()); // sport

        let (pid, local, remote) = parse_tcp_connect_v4(&d).expect("parse");
        assert_eq!(pid, 4242);
        assert_eq!(local, SocketAddrV4::new(Ipv4Addr::new(10, 8, 0, 6), 50000));
        assert_eq!(
            remote,
            SocketAddrV4::new(Ipv4Addr::new(23, 10, 20, 162), 443)
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
