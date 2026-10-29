//! Route changes this process made itself, so their echo in the OS change feed
//! does not start the network-change pause.
//!
//! A pass that writes routes hears each write back as a route notice. Treated
//! as news, every pass that writes starts the next pause, and a real change
//! arriving meanwhile waits behind our own. The writer notes a change before
//! making it; the observer consumes the matching notice instead of reporting
//! it. Matching is by content, so someone else removing our route is still
//! reported.

use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::error::PlatformError;
use crate::types::RouteEntry;

/// How long a noted change waits for its notice. Notices arrive in
/// milliseconds; past this, a matching notice is more likely someone else's.
pub const ECHO_WAIT: Duration = Duration::from_secs(5);

/// Noted changes kept at once; the oldest goes first. A pass writing more
/// than this at once still has its last writes recognised.
const PENDING_CAP: usize = 4096;

/// One route change as both the writer and the OS notice can name it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RouteChangeKey {
    pub destination: IpAddr,
    pub prefix_length: u8,
    pub interface_index: u32,
    pub removed: bool,
}

impl RouteChangeKey {
    #[must_use]
    pub fn of(entry: &RouteEntry, removed: bool) -> Self {
        Self {
            destination: entry.destination,
            prefix_length: entry.prefix_length,
            interface_index: entry.interface_index,
            removed,
        }
    }
}

/// Changes noted and not yet heard back.
#[derive(Debug, Default)]
pub struct OwnRouteWrites {
    pending: Mutex<VecDeque<(RouteChangeKey, Instant)>>,
}

impl OwnRouteWrites {
    /// `key` is about to be made by this process.
    pub fn expect(&self, key: RouteChangeKey, now: Instant) {
        let mut pending = self.lock();
        drop_expired(&mut pending, now);
        if pending.len() >= PENDING_CAP {
            pending.pop_front();
        }
        pending.push_back((key, now));
    }

    /// The write of `key` failed: no notice will come for it.
    pub fn withdraw(&self, key: RouteChangeKey) {
        let mut pending = self.lock();
        if let Some(at) = pending.iter().rposition(|(noted, _)| *noted == key) {
            pending.remove(at);
        }
    }

    /// Whether a notice of `key` is the echo of a change noted here; an echo
    /// is consumed, so a second identical notice is reported.
    pub fn take_echo(&self, key: RouteChangeKey, now: Instant) -> bool {
        let mut pending = self.lock();
        drop_expired(&mut pending, now);
        match pending.iter().position(|(noted, _)| *noted == key) {
            Some(at) => {
                pending.remove(at);
                true
            }
            None => false,
        }
    }

    /// Make the change `write` makes, noted as `key` while it is made.
    pub fn noted(
        &self,
        key: RouteChangeKey,
        write: impl FnOnce() -> Result<(), PlatformError>,
    ) -> Result<(), PlatformError> {
        self.expect(key, Instant::now());
        let result = write();
        if result.is_err() {
            self.withdraw(key);
        }
        result
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, VecDeque<(RouteChangeKey, Instant)>> {
        self.pending.lock().unwrap_or_else(|p| p.into_inner())
    }
}

fn drop_expired(pending: &mut VecDeque<(RouteChangeKey, Instant)>, now: Instant) {
    while pending
        .front()
        .is_some_and(|(_, at)| now.saturating_duration_since(*at) >= ECHO_WAIT)
    {
        pending.pop_front();
    }
}

/// The ledger the platform's route writers and change observers share.
pub fn process_route_writes() -> &'static OwnRouteWrites {
    static LEDGER: OnceLock<OwnRouteWrites> = OnceLock::new();
    LEDGER.get_or_init(OwnRouteWrites::default)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn key(last: u8, removed: bool) -> RouteChangeKey {
        RouteChangeKey {
            destination: IpAddr::V4(Ipv4Addr::new(203, 0, 113, last)),
            prefix_length: 32,
            interface_index: 7,
            removed,
        }
    }

    /// Someone else removing the route we just added is news, and so is a
    /// second notice our one write cannot explain.
    #[test]
    fn only_the_change_we_made_is_our_echo_and_only_once() {
        let writes = OwnRouteWrites::default();
        let now = Instant::now();
        writes.expect(key(1, false), now);
        assert!(
            !writes.take_echo(key(1, true), now),
            "a removal we did not make"
        );
        assert!(!writes.take_echo(key(2, false), now), "another route");
        assert!(writes.take_echo(key(1, false), now));
        assert!(!writes.take_echo(key(1, false), now), "one write, one echo");
    }

    /// A noted change whose notice never came does not swallow a later,
    /// unrelated one for good.
    #[test]
    fn a_noted_change_stops_matching_once_its_notice_is_overdue() {
        let writes = OwnRouteWrites::default();
        let now = Instant::now();
        writes.expect(key(1, false), now);
        assert!(!writes.take_echo(key(1, false), now + ECHO_WAIT));
    }

    /// A write the OS refused makes no notice; the same change made by
    /// someone else right after is reported.
    #[test]
    fn a_refused_write_expects_no_echo() {
        let writes = OwnRouteWrites::default();
        let refused = writes.noted(key(1, false), || {
            Err(PlatformError::Transient {
                operation: "add a route",
                detail: "refused".into(),
            })
        });
        assert!(refused.is_err());
        assert!(!writes.take_echo(key(1, false), Instant::now()));
        assert!(writes.noted(key(1, false), || Ok(())).is_ok());
        assert!(writes.take_echo(key(1, false), Instant::now()));
    }

    #[test]
    fn the_ledger_is_bounded() {
        let writes = OwnRouteWrites::default();
        let now = Instant::now();
        for n in 0..PENDING_CAP + 10 {
            let mut k = key(1, false);
            k.interface_index = u32::try_from(n).unwrap_or(u32::MAX);
            writes.expect(k, now);
        }
        assert_eq!(writes.lock().len(), PENDING_CAP);
    }
}
