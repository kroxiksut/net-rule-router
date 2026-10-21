//! `Microsoft-Windows-DNS-Client` ETW observer.
//!
//! A real-time ETW consumer that subscribes to the DNS-Client provider
//! (`{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}`) and buffers every completed
//! A/AAAA resolution (event 3008) as a [`DnsObservation`]. Pure
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
//! `UserData` directly and scan `QueryResults` for address tokens in place —
//! the callback runs once per resolution on the machine. The walk itself is
//! [`parse_query_completed`] in `nrr-platform-api`, tested and fuzzed on every
//! host.

#![cfg(target_os = "windows")]
#![allow(unsafe_code)]

use std::sync::{Arc, Mutex};

use windows::core::GUID;
use windows::Win32::System::Diagnostics::Etw::{EVENT_RECORD, TRACE_LEVEL_INFORMATION};

use super::{parse_query_completed, DnsObservation, DnsObservationSource};
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
/// Each observation with the pid of the program that asked, named at drain.
type Buffer = Arc<Mutex<Vec<(u32, DnsObservation)>>>;

/// A running real-time ETW consumer for DNS-Client events. The session stops
/// when this is dropped.
pub struct EtwDnsObserver {
    buffer: Buffer,
    session: RealtimeSession,
}

impl DnsObservationSource for EtwDnsObserver {
    fn is_feeding(&self) -> bool {
        self.session.pump_alive()
    }

    fn drain(&self) -> Vec<DnsObservation> {
        self.report_losses();
        let batch = match self.buffer.lock() {
            Ok(mut g) => std::mem::take(&mut *g),
            Err(_) => Vec::new(),
        };
        // One token read per distinct program per drain, on the consumer's
        // thread — never in the ETW callback.
        let mut owners: std::collections::HashMap<u32, Option<String>> =
            std::collections::HashMap::new();
        batch
            .into_iter()
            .map(|(pid, mut observation)| {
                if pid != 0 {
                    observation.owner = owners
                        .entry(pid)
                        .or_insert_with(|| crate::win32_ffi::console_session::process_user_sid(pid))
                        .clone();
                }
                observation
            })
            .collect()
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
/// and pushes a [`DnsObservation`] when at least one address was answered.
unsafe extern "system" fn event_record_callback(record: *mut EVENT_RECORD) {
    if record.is_null() {
        return;
    }
    let rec = &*record;
    if !is_subscribed(rec.EventHeader.EventDescriptor.Id) {
        return;
    }
    // Borrowed: the session owns the reference.
    let Some(buffer) = callback_context::<Mutex<Vec<(u32, DnsObservation)>>>(rec) else {
        return;
    };
    let Some(observation) = user_data(rec).and_then(parse_query_completed) else {
        return;
    };
    if let Ok(mut g) = buffer.lock() {
        // Bound the buffer so a runaway DNS storm between drains cannot
        // grow it without limit (the consumer drains every few seconds).
        if g.len() < 4096 {
            g.push((rec.EventHeader.ProcessId, observation));
        }
    }
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

    #[test]
    fn the_session_filter_admits_exactly_what_the_callback_consumes() {
        let consumed: Vec<u16> = (0..=u16::MAX).filter(|&id| is_subscribed(id)).collect();
        assert_eq!(consumed, SUBSCRIBED_EVENT_IDS.to_vec());
        assert_eq!(consumed, vec![EVENT_ID_QUERY_COMPLETED]);
    }

    /// The parse runs in the ETW callback, once per resolution on the machine.
    #[test]
    fn an_answered_event_allocates_its_observation_only() {
        let answered = payload(
            "www.example.com",
            "type:  5 edge.example.net;::ffff:192.0.2.10;192.0.2.11;",
        );
        let answered_v6 = payload("www.example.com", "type:  28 2001:db8::1;");
        let unanswered = payload("www.example.com", "type:  5 edge.example.net;");
        let mut out = None;
        // The hostname and one address list each.
        assert_eq!(
            allocations_during(|| out = parse_query_completed(&answered)),
            2
        );
        assert!(out.is_some());
        assert_eq!(
            allocations_during(|| out = parse_query_completed(&answered_v6)),
            2
        );
        assert!(out.is_some());
        assert_eq!(
            allocations_during(|| {
                std::hint::black_box(parse_query_completed(&unanswered));
            }),
            0
        );
    }
}
