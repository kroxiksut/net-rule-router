//! Passive DNS-resolution observation.
//!
//! Suffix / zone rules (`*.example.com`, `.ru`) match an open-ended set of
//! sub-hostnames that cannot be enumerated ahead of time — there is no API
//! that lists "every host under example.com". The only way to learn the
//! IPs behind such a rule is to **observe** the DNS resolutions the machine
//! actually makes and react to the ones that match a rule.
//!
//! This module is the passive observation port. The production
//! implementation (`etw::EtwDnsObserver`, Windows-only) subscribes to the
//! `Microsoft-Windows-DNS-Client` ETW provider — pure user-mode, no kernel
//! callout driver, no DNS-config change, no port-53 binding. It buffers
//! every completed A-record resolution; a service-runtime consumer drains
//! the buffer, keeps the ones that match an active suffix/zone/exact rule,
//! and writes them to the FQDN cache so the existing route/WFP codegen can
//! fan them out.
//!
//! **Honest limit:** DNS-over-HTTPS performed *inside* an application (a
//! browser's own DoH resolver) bypasses the Windows DNS Client and is not
//! observed. Resolutions via the OS resolver — the path the large majority
//! of apps take — are observed. This is an inherent limit of any
//! non-driver approach.

use std::net::Ipv4Addr;
use std::sync::Mutex;

/// One observed DNS resolution: a queried hostname and the IPv4 addresses
/// it resolved to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsObservation {
    /// Canonical (lower-cased, no trailing dot) queried hostname.
    pub hostname: String,
    /// IPv4 addresses the query resolved to. Never empty (an empty answer
    /// is not surfaced as an observation).
    pub ipv4s: Vec<Ipv4Addr>,
}

/// A source of passively-observed DNS resolutions. The consumer polls
/// [`Self::drain`] periodically; the source buffers events between drains.
pub trait DnsObservationSource: Send + Sync {
    /// Remove and return all observations buffered since the last drain.
    /// Returns an empty vector when nothing was observed.
    fn drain(&self) -> Vec<DnsObservation>;
}

/// In-memory scripted source for tests (and for non-Windows builds, where
/// it simply never produces anything). Push observations with
/// [`Self::push`]; the consumer drains them.
#[derive(Default)]
pub struct MockDnsObservationSource {
    buffered: Mutex<Vec<DnsObservation>>,
}

// Test/dev double: `lock().unwrap()` poisoning is acceptable scaffolding.
#[allow(clippy::unwrap_used, clippy::expect_used)]
impl MockDnsObservationSource {
    pub fn new() -> Self {
        Self::default()
    }

    /// Buffer an observation for the next drain.
    pub fn push(&self, hostname: &str, ipv4s: Vec<Ipv4Addr>) {
        self.buffered.lock().unwrap().push(DnsObservation {
            hostname: hostname.to_string(),
            ipv4s,
        });
    }
}

#[allow(clippy::unwrap_used, clippy::expect_used)]
impl DnsObservationSource for MockDnsObservationSource {
    fn drain(&self) -> Vec<DnsObservation> {
        std::mem::take(&mut *self.buffered.lock().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_buffers_and_drains_once() {
        let src = MockDnsObservationSource::new();
        src.push("a.example.com", vec![Ipv4Addr::new(1, 2, 3, 4)]);
        src.push("b.example.com", vec![Ipv4Addr::new(5, 6, 7, 8)]);
        let first = src.drain();
        assert_eq!(first.len(), 2);
        assert_eq!(first[0].hostname, "a.example.com");
        // Drained — a second drain is empty.
        assert!(src.drain().is_empty());
    }
}
