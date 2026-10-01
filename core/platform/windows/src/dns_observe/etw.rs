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
//! The payload parse is unit-tested on constructed payloads; the live session
//! is NOT hardware-verified. Real-time ETW consumption cannot be exercised
//! without a live Windows session emitting DNS traffic. The surrounding
//! pipeline (`DnsObservationConsumer` → cache → route codegen) IS tested
//! via [`super::MockDnsObservationSource`].
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
//! than depend on TDH schema walking, we locate the two UTF-16 strings in
//! `UserData` directly and scan `QueryResults` for dotted-quad IPv4 tokens
//! in place — the callback runs once per resolution on the machine. It is
//! tolerant of the type-prefix decoration Windows adds to the results.

#![cfg(target_os = "windows")]
#![allow(unsafe_code)]

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use windows::core::GUID;
use windows::Win32::System::Diagnostics::Etw::{EVENT_RECORD, TRACE_LEVEL_INFORMATION};

use super::{DnsObservation, DnsObservationSource};
use crate::error::PlatformError;
use crate::etw_session::{
    callback_context, user_data, BufferSizing, ProviderEnable, RealtimeSession, SessionClock,
    SessionConfig,
};

/// `Microsoft-Windows-DNS-Client` provider GUID.
const DNS_CLIENT_PROVIDER: GUID = GUID::from_u128(0x1c95126e_7eea_49a9_a3fe_a378b03ddb4d);

/// Event id for "DNS query completed".
const EVENT_ID_QUERY_COMPLETED: u16 = 3008;

/// Every event the observer consumes. Both the session's event-id filter and
/// the callback read this one table: the provider's other events (query
/// start, cache lookups, per-server sends) would otherwise fill the buffers
/// the completions then miss.
const SUBSCRIBED_EVENT_IDS: [u16; 1] = [EVENT_ID_QUERY_COMPLETED];

/// A completion is a few hundred bytes, so about a hundred fit a 32 KiB
/// buffer; at most 1 MiB of nonpaged memory absorbs a resolution storm of
/// a few thousand before ETW drops any.
const SESSION_BUFFERS: BufferSizing = BufferSizing {
    buffer_kb: 32,
    min_buffers: 4,
    max_buffers: 32,
};

/// A completion must reach the consumer before the program connects to the
/// answer; on a quiet machine a buffer would otherwise sit half full.
const SESSION_FLUSH_SECS: u32 = 1;

/// Shared buffer of observations, drained by the consumer. The ETW
/// callback (a C ABI fn with no closure capture) reaches it through the
/// session context.
type Buffer = Arc<Mutex<Vec<DnsObservation>>>;

/// A running real-time ETW consumer for DNS-Client events. The session stops
/// when this is dropped.
pub struct EtwDnsObserver {
    buffer: Buffer,
    session: RealtimeSession,
}

impl DnsObservationSource for EtwDnsObserver {
    fn drain(&self) -> Vec<DnsObservation> {
        self.report_losses();
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
                flush_timer_secs: SESSION_FLUSH_SECS,
                buffers: Some(SESSION_BUFFERS),
            },
            &ProviderEnable {
                guid: DNS_CLIENT_PROVIDER,
                level: TRACE_LEVEL_INFORMATION as u8,
                // Every keyword: the event-id filter is what narrows the feed.
                keywords: 0,
                enable_property: 0,
                event_ids: &SUBSCRIBED_EVENT_IDS,
            },
            event_record_callback,
            Arc::clone(&buffer),
        )?;
        tracing::info!(
            target: "nrr::dns-observe",
            msg_key = "win-etw-dns-observer-started",
            "DNS-Client ETW observer started",
        );
        Ok(Self { buffer, session })
    }

    /// A lost completion is a name whose addresses never reach the routes;
    /// a session that lost some says so, rate-limited.
    fn report_losses(&self) {
        let Some(lost) = self.session.losses_to_report() else {
            return;
        };
        tracing::warn!(
            target: "nrr::dns-observe",
            msg_key = "win-etw-dns-events-lost",
            events = lost.events,
            buffers = lost.realtime_buffers,
            "DNS-Client ETW session lost events; some resolutions went unobserved",
        );
    }
}

/// Whether the callback consumes this event id; anything else reaches it
/// only when the provider refused the filter.
fn is_subscribed(event_id: u16) -> bool {
    SUBSCRIBED_EVENT_IDS.contains(&event_id)
}

/// C-ABI ETW record callback. Extracts event 3008's query name + results
/// and pushes a [`DnsObservation`] when at least one IPv4 was answered.
unsafe extern "system" fn event_record_callback(record: *mut EVENT_RECORD) {
    if record.is_null() {
        return;
    }
    let rec = &*record;
    if !is_subscribed(rec.EventHeader.EventDescriptor.Id) {
        return;
    }
    // Borrowed: the session owns the reference.
    let Some(buffer) = callback_context::<Mutex<Vec<DnsObservation>>>(rec) else {
        return;
    };
    let Some(observation) = user_data(rec).and_then(parse_query_completed) else {
        return;
    };
    if let Ok(mut g) = buffer.lock() {
        // Bound the buffer so a runaway DNS storm between drains cannot
        // grow it without limit (the consumer drains every few seconds).
        if g.len() < 4096 {
            g.push(observation);
        }
    }
}

/// The observation event 3008 carries, or `None` when it answered no IPv4.
///
/// Layout: `QueryName` (UTF-16, NUL-terminated), fixed fields, then
/// `QueryResults` (UTF-16, NUL-terminated). The name is the first string and
/// the results the LAST non-empty one, which is robust to the fixed fields in
/// between. Scanned in place: the only allocations are the hostname and the
/// address list of an observation that is returned.
fn parse_query_completed(bytes: &[u8]) -> Option<DnsObservation> {
    let units = Utf16Le(bytes);
    let n = units.len();
    let name_end = (0..n).find(|&i| units.at(i) == 0).unwrap_or(n);
    let results_from = (name_end + 1).min(n);

    let mut end = n;
    while end > results_from && units.at(end - 1) == 0 {
        end -= 1;
    }
    let mut start = end;
    while start > results_from && units.at(start - 1) != 0 {
        start -= 1;
    }
    let ipv4s = ipv4_tokens((start..end).map(|i| units.at(i)));
    if ipv4s.is_empty() {
        return None;
    }
    // The canonical form drops trailing dots, so a name of dots alone is none.
    if (0..name_end).all(|i| units.at(i) == u16::from(b'.')) {
        return None;
    }
    Some(DnsObservation {
        hostname: canonical_hostname((0..name_end).map(|i| units.at(i)), name_end),
        ipv4s,
    })
}

/// A little-endian UTF-16 payload read unit by unit; a trailing odd byte
/// belongs to no unit.
#[derive(Clone, Copy)]
struct Utf16Le<'a>(&'a [u8]);

impl Utf16Le<'_> {
    fn len(self) -> usize {
        self.0.len() / 2
    }

    fn at(self, i: usize) -> u16 {
        u16::from_le_bytes([self.0[2 * i], self.0[2 * i + 1]])
    }
}

/// What `canonicalize_hostname` makes of the lossy-decoded name, built in one
/// allocation.
fn canonical_hostname(units: impl Iterator<Item = u16>, unit_count: usize) -> String {
    let mut name = String::with_capacity(unit_count);
    name.extend(char::decode_utf16(units).map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER)));
    let kept = name.trim_end_matches('.').len();
    name.truncate(kept);
    name.make_ascii_lowercase();
    name
}

/// Every distinct dotted-quad IPv4 in a DNS-results string, in order. Windows
/// decorates results with type prefixes and semicolons
/// (`"type:  5 ...;192.0.2.1;"`); a token is a maximal run of ASCII digits and
/// dots.
fn ipv4_tokens(units: impl Iterator<Item = u16>) -> Vec<Ipv4Addr> {
    // "255.255.255.255": anything longer is no address.
    const MAX_TOKEN: usize = 15;
    let mut out: Vec<Ipv4Addr> = Vec::new();
    let mut token = [0u8; MAX_TOKEN];
    let mut len = 0usize;
    let mut overlong = false;
    let mut flush = |token: &[u8], overlong: bool| {
        if token.is_empty() || overlong {
            return;
        }
        let parsed = std::str::from_utf8(token)
            .ok()
            .and_then(|t| t.parse::<Ipv4Addr>().ok());
        if let Some(ip) = parsed {
            if !out.contains(&ip) {
                out.push(ip);
            }
        }
    };
    for unit in units {
        match u8::try_from(unit) {
            Ok(b) if b.is_ascii_digit() || b == b'.' => {
                if len < MAX_TOKEN {
                    token[len] = b;
                    len += 1;
                } else {
                    overlong = true;
                }
            }
            _ => {
                flush(&token[..len], overlong);
                len = 0;
                overlong = false;
            }
        }
    }
    flush(&token[..len], overlong);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alloc_count::allocations_during;

    fn utf16z(s: &str) -> Vec<u8> {
        s.encode_utf16()
            .chain(std::iter::once(0))
            .flat_map(u16::to_le_bytes)
            .collect()
    }

    /// An event 3008 payload: the name, fixed fields, then the results.
    fn payload(name: &str, results: &str) -> Vec<u8> {
        let mut d = utf16z(name);
        d.extend_from_slice(&1u32.to_le_bytes()); // QueryType
        d.extend_from_slice(&0x6000u64.to_le_bytes()); // QueryOptions
        d.extend_from_slice(&0u32.to_le_bytes()); // QueryStatus
        d.extend(utf16z(results));
        d
    }

    /// The parse that decoded every string, kept as the oracle the in-place
    /// scan must agree with.
    mod reference {
        use super::super::*;

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

        pub(super) fn parse(bytes: &[u8]) -> Option<DnsObservation> {
            if bytes.len() < 2 {
                return None;
            }
            let (hostname, after) = read_utf16z(bytes, 0)?;
            let results = read_last_utf16z(bytes, after).unwrap_or_default();
            let ipv4s = parse_ipv4_tokens(&results);
            if ipv4s.is_empty() {
                return None;
            }
            let canonical = crate::dns::canonicalize_hostname(&hostname);
            if canonical.is_empty() {
                return None;
            }
            Some(DnsObservation {
                hostname: canonical,
                ipv4s,
            })
        }
    }

    fn golden_payloads() -> Vec<Vec<u8>> {
        let mut out = vec![
            payload(
                "Host.Example.COM.",
                "type:  5 cdn.example.net;192.0.2.10;192.0.2.11;192.0.2.10;",
            ),
            payload("a.example", "::ffff:c000:22c;not-an-ip;198.51.100.7;"),
            payload("v6only.example", "2001:db8::1;2001:db8::2;"),
            payload("...", "192.0.2.1;"),
            payload("", "192.0.2.1;"),
            payload("xn--d1acufc.example", "203.0.113.255;999.1.1.1;1.2.3.4.5;"),
            payload("long.example", "192.0.2.1234567890123;0192.0.2.1;192.0.2.3"),
            payload("\u{0445}\u{043e}\u{0441}\u{0442}.example", "192.0.2.4"),
            payload("empty.example", ""),
            utf16z("unterminated.example")[..40].to_vec(),
            vec![0, 0],
            vec![0x41],
        ];
        // A zero-padded tail with an odd byte, a trailing string that is not
        // the results, and a lone surrogate inside the answer.
        let mut tail = payload("tail.example", "192.0.2.5;");
        tail.extend_from_slice(&[0, 0, 0, 0, 7]);
        out.push(tail);
        let mut shadowed = payload("shadow.example", "192.0.2.6;");
        shadowed.extend(utf16z("x"));
        out.push(shadowed);
        let mut surrogate = utf16z("s.example");
        let answer = "192.0.2.7"
            .encode_utf16()
            .chain([0xD800])
            .chain("192.0.2.8;".encode_utf16());
        for u in answer {
            surrogate.extend_from_slice(&u.to_le_bytes());
        }
        surrogate.extend_from_slice(&[0, 0]);
        out.push(surrogate);
        out
    }

    #[test]
    fn the_session_filter_admits_exactly_what_the_callback_consumes() {
        let consumed: Vec<u16> = (0..=u16::MAX).filter(|&id| is_subscribed(id)).collect();
        assert_eq!(consumed, SUBSCRIBED_EVENT_IDS.to_vec());
        assert_eq!(consumed, vec![EVENT_ID_QUERY_COMPLETED]);
    }

    #[test]
    fn golden_payloads_parse_as_expected() {
        let got: Vec<_> = golden_payloads()
            .iter()
            .map(|p| parse_query_completed(p))
            .collect();
        let ip = |d| Ipv4Addr::new(192, 0, 2, d);
        let obs = |h: &str, ipv4s: Vec<Ipv4Addr>| {
            Some(DnsObservation {
                hostname: h.into(),
                ipv4s,
            })
        };
        assert_eq!(got[0], obs("host.example.com", vec![ip(10), ip(11)]));
        assert_eq!(
            got[1],
            obs("a.example", vec![Ipv4Addr::new(198, 51, 100, 7)])
        );
        assert_eq!(got[2], None);
        assert_eq!(got[3], None);
        assert_eq!(got[4], None);
        assert_eq!(
            got[5],
            obs("xn--d1acufc.example", vec![Ipv4Addr::new(203, 0, 113, 255)])
        );
        assert_eq!(got[6], obs("long.example", vec![ip(3)]));
        assert_eq!(
            got[7],
            obs("\u{0445}\u{043e}\u{0441}\u{0442}.example", vec![ip(4)])
        );
        assert_eq!(got[8], None);
        assert_eq!(got[9], None);
        assert_eq!(got[10], None);
        assert_eq!(got[11], None);
        assert_eq!(got[12], obs("tail.example", vec![ip(5)]));
        assert_eq!(got[13], None, "the last string is the results field");
        assert_eq!(got[14], obs("s.example", vec![ip(7), ip(8)]));
    }

    #[test]
    fn agrees_with_the_reference_parse() {
        for p in golden_payloads() {
            assert_eq!(parse_query_completed(&p), reference::parse(&p), "{p:?}");
        }
        // Deterministic noise over the alphabet a results string is made of.
        let alphabet: Vec<u16> = "0123456789.;: typeAZ\u{0}\u{044f}"
            .encode_utf16()
            .chain([0xD800])
            .collect();
        let mut state = 0x2545_f491_4f6c_dd1du64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..5000 {
            let len = (next() % 96) as usize;
            let mut d = Vec::with_capacity(2 * len + 1);
            for _ in 0..len {
                let u = alphabet[(next() % alphabet.len() as u64) as usize];
                d.extend_from_slice(&u.to_le_bytes());
            }
            if next() & 1 == 1 {
                d.push(b'1');
            }
            assert_eq!(parse_query_completed(&d), reference::parse(&d), "{d:?}");
        }
    }

    #[test]
    fn an_answered_event_allocates_its_observation_only() {
        let answered = payload(
            "www.example.com",
            "type:  5 edge.example.net;192.0.2.10;192.0.2.11;",
        );
        let unanswered = payload("www.example.com", "type:  28 2001:db8::1;");
        let mut out = None;
        let now = allocations_during(|| out = parse_query_completed(&answered));
        assert!(out.is_some());
        // The hostname and the address list.
        assert_eq!(now, 2);
        assert_eq!(
            allocations_during(|| {
                std::hint::black_box(parse_query_completed(&unanswered));
            }),
            0
        );
        // Positive control: the decode-every-string parse is what was measured.
        let before = allocations_during(|| {
            std::hint::black_box(reference::parse(&answered));
        });
        assert!(before >= 8, "the reference parse allocated {before} times");
    }
}
