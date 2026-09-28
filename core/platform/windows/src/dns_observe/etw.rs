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
//! trace session ([`crate::etw_session`]) is stopped + closed on drop.
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
use std::sync::{Arc, Mutex};

use windows::core::GUID;
use windows::Win32::System::Diagnostics::Etw::{EVENT_RECORD, TRACE_LEVEL_INFORMATION};

use super::{DnsObservation, DnsObservationSource};
use crate::error::PlatformError;
use crate::etw_session::{
    callback_context, user_data, ProviderEnable, RealtimeSession, SessionClock, SessionConfig,
};

/// `Microsoft-Windows-DNS-Client` provider GUID.
const DNS_CLIENT_PROVIDER: GUID = GUID::from_u128(0x1c95126e_7eea_49a9_a3fe_a378b03ddb4d);

/// Event id for "DNS query completed".
const EVENT_ID_QUERY_COMPLETED: u16 = 3008;

/// Shared buffer of observations, drained by the consumer. The ETW
/// callback (a C ABI fn with no closure capture) reaches it through the
/// session context.
type Buffer = Arc<Mutex<Vec<DnsObservation>>>;

/// A running real-time ETW consumer for DNS-Client events. The session stops
/// when this is dropped.
pub struct EtwDnsObserver {
    buffer: Buffer,
    _session: RealtimeSession,
}

impl DnsObservationSource for EtwDnsObserver {
    fn drain(&self) -> Vec<DnsObservation> {
        match self.buffer.lock() {
            Ok(mut g) => std::mem::take(&mut *g),
            Err(_) => Vec::new(),
        }
    }
}

impl EtwDnsObserver {
    /// Start a real-time ETW session, enable the DNS-Client provider, and
    /// spawn the pump. Returns an error (and starts nothing) on any setup
    /// failure — the caller degrades to no observation.
    pub fn start() -> Result<Self, PlatformError> {
        let buffer: Buffer = Arc::new(Mutex::new(Vec::new()));
        let session = RealtimeSession::start(
            &SessionConfig {
                name: "NrrDnsObserve",
                thread_name: "nrr-dns-etw",
                clock: SessionClock::PerformanceCounter,
                flush_timer_secs: 0,
            },
            &ProviderEnable {
                guid: DNS_CLIENT_PROVIDER,
                level: TRACE_LEVEL_INFORMATION as u8,
                keywords: 0,
                enable_property: 0,
            },
            event_record_callback,
            Arc::clone(&buffer),
        )?;
        tracing::info!(
            target: "nrr::dns-observe",
            msg_key = "win-etw-dns-observer-started",
            "DNS-Client ETW observer started",
        );
        Ok(Self {
            buffer,
            _session: session,
        })
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
    // Borrowed: the session owns the reference.
    let Some(buffer) = callback_context::<Mutex<Vec<DnsObservation>>>(rec) else {
        return;
    };
    let Some(bytes) = user_data(rec).filter(|b| b.len() >= 2) else {
        return;
    };

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ipv4_tokens_extracts_dotted_quads() {
        let ips = parse_ipv4_tokens("type:  1 23.10.20.138;type:  1 23.10.20.139;");
        assert_eq!(
            ips,
            vec![
                Ipv4Addr::new(23, 10, 20, 138),
                Ipv4Addr::new(23, 10, 20, 139)
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
