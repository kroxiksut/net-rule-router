//! A wall-clock budget for a [`DnsResolverPort`] call.
//!
//! The platform resolvers answer synchronously and cannot be cancelled: the
//! Win32 `DnsQuery_W` returns when the OS is done with it, and a stub resolver
//! still owes its own retries. A caller on the DNS datapath cannot afford that
//! — one dead upstream would hold a listener worker for as long as the OS
//! feels like retrying.
//!
//! So the budget is a decorator, not a resolver trait method: the *policy*
//! (how long a caller waits) is neutral and tested once here, while the
//! *mechanism* (how a name is actually resolved) stays per-OS. The query runs
//! on a detached thread; past the budget the caller gets
//! [`DnsResolverError::Timeout`] and the thread finishes into a dropped
//! channel. `max_in_flight` bounds how many such threads may exist at once, so
//! a resolver that stops answering under a query storm cannot spawn without
//! limit — over the cap a call fails fast instead.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::dns::{
    canonicalize_hostname, AddressFamily, DnsResolverError, DnsResolverPort, ResolvedRecord,
};

/// Default caller budget. Sized against the intercept path: the hosts-bypass
/// direct query already spends up to 1.5 s before falling back to the system
/// resolver, and both together must stay under the listener's 3 s per-query
/// budget.
pub const DEFAULT_RESOLVE_BUDGET: Duration = Duration::from_millis(1200);

/// Default cap on queries the decorator may have outstanding. Above the eight
/// listener workers plus the seeder and refresh callers, so it is reached only
/// when queries are actually piling up unanswered.
pub const DEFAULT_MAX_IN_FLIGHT: usize = 32;

/// Stack for a detached query thread: a resolver call plus its answer buffer,
/// not the 1 MiB default a thread-per-query would otherwise reserve.
const QUERY_THREAD_STACK: usize = 256 * 1024;

/// Gives every [`DnsResolverPort::resolve`] call a deadline of its own.
///
/// Wrap the platform resolver in the composition root; everything downstream
/// keeps talking to a plain `DnsResolverPort`.
pub struct BudgetedDnsResolver {
    inner: Arc<dyn DnsResolverPort>,
    budget: Duration,
    max_in_flight: usize,
    in_flight: Arc<AtomicUsize>,
    /// At the cap right now. Keeps the log to one line per episode instead of
    /// one per refused query — a storm is exactly when a log must stay readable.
    saturated: AtomicBool,
}

impl BudgetedDnsResolver {
    #[must_use]
    pub fn new(inner: Arc<dyn DnsResolverPort>) -> Self {
        Self {
            inner,
            budget: DEFAULT_RESOLVE_BUDGET,
            max_in_flight: DEFAULT_MAX_IN_FLIGHT,
            in_flight: Arc::new(AtomicUsize::new(0)),
            saturated: AtomicBool::new(false),
        }
    }

    #[must_use]
    pub fn with_budget(mut self, budget: Duration) -> Self {
        self.budget = budget;
        self
    }

    #[must_use]
    pub fn with_max_in_flight(mut self, max_in_flight: usize) -> Self {
        self.max_in_flight = max_in_flight.max(1);
        self
    }

    /// Queries currently outstanding, the ones nobody waits for any more
    /// included.
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::Relaxed)
    }
}

impl DnsResolverPort for BudgetedDnsResolver {
    fn resolve(
        &self,
        hostname: &str,
        family: AddressFamily,
    ) -> Result<ResolvedRecord, DnsResolverError> {
        let canonical = canonicalize_hostname(hostname);
        let Some(permit) = Permit::acquire(&self.in_flight, self.max_in_flight) else {
            if !self.saturated.swap(true, Ordering::AcqRel) {
                tracing::warn!(
                    target: "nrr::dns-resolver",
                    outstanding = self.max_in_flight,
                    "every resolver slot is held by a query the OS has not answered — refusing new ones until one returns",
                );
            }
            return Err(DnsResolverError::Timeout {
                hostname: canonical,
            });
        };
        if self.saturated.swap(false, Ordering::AcqRel) {
            tracing::info!(
                target: "nrr::dns-resolver",
                outstanding = self.in_flight(),
                "resolver slots free again",
            );
        }

        let (tx, rx) = mpsc::sync_channel(1);
        let inner = Arc::clone(&self.inner);
        let asked = canonical.clone();
        let spawned = thread::Builder::new()
            .name("nrr-dns-query".to_owned())
            .stack_size(QUERY_THREAD_STACK)
            .spawn(move || {
                // Held by the query, not by the caller: the slot frees when the
                // OS finally lets go, which is what the cap counts.
                let _permit = permit;
                let _ = tx.send(inner.resolve(&asked, family));
            });
        if spawned.is_err() {
            return Err(DnsResolverError::Network {
                hostname: canonical,
                code: 0,
            });
        }

        match rx.recv_timeout(self.budget) {
            Ok(result) => result,
            Err(RecvTimeoutError::Timeout) => {
                tracing::debug!(
                    target: "nrr::dns-resolver",
                    host = %canonical,
                    budget_ms = self.budget.as_millis() as u64,
                    "resolver did not answer within its budget — releasing the caller",
                );
                Err(DnsResolverError::Timeout {
                    hostname: canonical,
                })
            }
            // The query thread died without sending: report transient rather
            // than authoritative, so nothing is cached as "does not exist".
            Err(RecvTimeoutError::Disconnected) => Err(DnsResolverError::Network {
                hostname: canonical,
                code: 0,
            }),
        }
    }
}

/// One outstanding query. Releases its slot on drop — in the query thread,
/// after the resolver returns.
struct Permit {
    counter: Arc<AtomicUsize>,
}

impl Permit {
    fn acquire(counter: &Arc<AtomicUsize>, max: usize) -> Option<Self> {
        let mut current = counter.load(Ordering::Relaxed);
        loop {
            if current >= max {
                return None;
            }
            match counter.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    return Some(Self {
                        counter: Arc::clone(counter),
                    })
                }
                Err(actual) => current = actual,
            }
        }
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::AcqRel);
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Instant;

    use super::*;

    /// Answers after `delay`, so a test can make the resolver slower than the
    /// budget without a network.
    struct SleepyResolver {
        delay: Duration,
    }

    impl DnsResolverPort for SleepyResolver {
        fn resolve(
            &self,
            hostname: &str,
            _family: AddressFamily,
        ) -> Result<ResolvedRecord, DnsResolverError> {
            thread::sleep(self.delay);
            Ok(ResolvedRecord {
                canonical_hostname: hostname.to_owned(),
                addresses: vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7))],
                ttl_seconds: Some(60),
            })
        }
    }

    fn sleepy(delay: Duration) -> Arc<dyn DnsResolverPort> {
        Arc::new(SleepyResolver { delay })
    }

    #[test]
    fn an_answer_inside_the_budget_is_returned_unchanged() {
        let resolver =
            BudgetedDnsResolver::new(sleepy(Duration::ZERO)).with_budget(Duration::from_secs(2));

        let record = resolver
            .resolve("Example.COM.", AddressFamily::Ipv4)
            .unwrap();

        assert_eq!(record.canonical_hostname, "example.com");
        assert_eq!(
            record.addresses,
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7))]
        );
    }

    #[test]
    fn a_resolver_slower_than_the_budget_releases_the_caller() {
        let resolver = BudgetedDnsResolver::new(sleepy(Duration::from_secs(5)))
            .with_budget(Duration::from_millis(150));

        let started = Instant::now();
        let answer = resolver.resolve("example.com", AddressFamily::Ipv4);

        assert!(matches!(answer, Err(DnsResolverError::Timeout { .. })));
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "caller waited {:?}, budget was 150 ms",
            started.elapsed()
        );
    }

    #[test]
    fn queries_past_the_cap_fail_without_asking() {
        let resolver = BudgetedDnsResolver::new(sleepy(Duration::from_secs(5)))
            .with_budget(Duration::from_millis(100))
            .with_max_in_flight(1);

        // Fills the single slot; its thread is still asking afterwards.
        assert!(matches!(
            resolver.resolve("first.example", AddressFamily::Ipv4),
            Err(DnsResolverError::Timeout { .. })
        ));

        let started = Instant::now();
        let answer = resolver.resolve("second.example", AddressFamily::Ipv4);

        assert!(matches!(answer, Err(DnsResolverError::Timeout { .. })));
        assert!(
            started.elapsed() < Duration::from_millis(100),
            "a capped call waited {:?} instead of failing fast",
            started.elapsed()
        );
    }

    #[test]
    fn a_slot_is_returned_once_the_query_ends() {
        let resolver = BudgetedDnsResolver::new(sleepy(Duration::from_millis(200)))
            .with_budget(Duration::from_millis(20))
            .with_max_in_flight(1);

        assert!(matches!(
            resolver.resolve("slow.example", AddressFamily::Ipv4),
            Err(DnsResolverError::Timeout { .. })
        ));
        assert_eq!(resolver.in_flight(), 1);

        thread::sleep(Duration::from_millis(400));

        assert_eq!(resolver.in_flight(), 0);

        // The freed slot is available again: the next query takes it rather
        // than failing at the cap.
        assert!(matches!(
            resolver.resolve("next.example", AddressFamily::Ipv4),
            Err(DnsResolverError::Timeout { .. })
        ));
        assert_eq!(resolver.in_flight(), 1);
    }
}
