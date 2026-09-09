//! Ask the machine's LOCAL resolvers before calling a name non-existent.
//!
//! ## The gap
//!
//! Our resolver picks one upstream and stands by its answer, and "no such name"
//! is an answer. So a host that exists only inside a corporate network is asked
//! of a public resolver, comes back as non-existent, and the application is told
//! so — while the resolver that knows it sits on another interface, unasked.
//!
//! Windows itself does not behave this way: with several interfaces it asks
//! more than one server before giving up. Redirecting every name to ourselves
//! took that away, and this puts it back.
//!
//! ## Why only private servers, and only on "no such name"
//!
//! A public resolver has nothing to add to another public resolver's
//! non-existence — the same global data answers both. A resolver on a private
//! address is different in kind: it is the one that can hold a namespace nobody
//! outside the network has heard of.
//!
//! And only on a clean non-existence. A timeout or a transport failure is
//! already retried by the layers below, and re-asking there would multiply
//! waiting rather than add knowledge.
//!
//! ## What it costs
//!
//! Nothing on the answered path, which is nearly all of it: the extra query
//! happens only for names that would have failed anyway. A machine with no
//! private resolver besides the one already used pays nothing at all — there is
//! nobody to ask.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use nrr_platform_api::dns::{SystemDnsServersPort, UpstreamDnsCandidate};

use crate::dns_resolver::{ResolveError, ResolvedA, UpstreamResolver};
use crate::dns_resolver_ports::DirectUdpUpstreamResolver;

/// How many private resolvers are tried before giving up. A machine has one or
/// two; the bound only stops a pathological configuration from turning one
/// failed lookup into a dozen queries.
const MAX_FALLBACK_SERVERS: usize = 2;

/// Wraps an upstream so a clean "no such name" is re-asked of the machine's
/// private resolvers.
pub struct LocalNamespaceFallbackResolver {
    inner: Arc<dyn UpstreamResolver>,
    servers: Arc<dyn SystemDnsServersPort>,
    timeout: Duration,
    /// Servers already asked by `inner`, so the fallback never repeats a
    /// question that was just answered. Empty means "unknown", and then a
    /// repeat is possible but harmless.
    already_asked: Vec<Ipv4Addr>,
}

impl LocalNamespaceFallbackResolver {
    pub fn new(
        inner: Arc<dyn UpstreamResolver>,
        servers: Arc<dyn SystemDnsServersPort>,
        timeout: Duration,
    ) -> Self {
        Self {
            inner,
            servers,
            timeout,
            already_asked: Vec::new(),
        }
    }

    /// Name the server the wrapped upstream uses, so it is not asked twice.
    #[must_use]
    pub fn already_asked(mut self, servers: Vec<Ipv4Addr>) -> Self {
        self.already_asked = servers;
        self
    }

    fn fallback_servers(&self) -> Vec<Ipv4Addr> {
        self.servers
            .upstream_candidates_v4()
            .into_iter()
            .map(|c: UpstreamDnsCandidate| c.server)
            .filter(|s| is_private_resolver(*s))
            .filter(|s| !self.already_asked.contains(s))
            .take(MAX_FALLBACK_SERVERS)
            .collect()
    }
}

impl UpstreamResolver for LocalNamespaceFallbackResolver {
    fn resolve_a(&self, hostname: &str) -> Result<ResolvedA, ResolveError> {
        let first = self.inner.resolve_a(hostname);
        // Only a clean non-existence is worth a second opinion. Everything else
        // either succeeded or is being retried below us.
        if !matches!(first, Err(ResolveError::NoRecords)) {
            return first;
        }
        for server in self.fallback_servers() {
            let direct = DirectUdpUpstreamResolver::new(
                SocketAddr::from((server, 53)),
                self.timeout,
                // One attempt: this is already the second opinion, and a private
                // resolver that does not answer promptly has nothing to add.
                1,
            );
            if let Ok(resolved) = direct.resolve_a(hostname) {
                if !resolved.addresses.is_empty() {
                    tracing::info!(
                        target: "nrr::dns-resolver",
                        host = %hostname,
                        server = %server,
                        "a resolver on this machine knows a name the upstream called non-existent",
                    );
                    return Ok(resolved);
                }
            }
        }
        first
    }
}

/// Is this a resolver that can hold a namespace the public internet has never
/// heard of?
///
/// Private space only. A resolver reachable from anywhere answers from the same
/// global data as the one already asked, so re-asking it adds latency and no
/// knowledge.
#[must_use]
pub fn is_private_resolver(server: Ipv4Addr) -> bool {
    let [a, b, _, _] = server.octets();
    if server.is_loopback() || server.is_unspecified() {
        return false;
    }
    match a {
        10 => true,
        172 => (16..=31).contains(&b),
        192 => b == 168,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct Fixed(Result<ResolvedA, ResolveError>, Mutex<u32>);
    impl UpstreamResolver for Fixed {
        fn resolve_a(&self, _hostname: &str) -> Result<ResolvedA, ResolveError> {
            *self.1.lock().unwrap() += 1;
            self.0.clone()
        }
    }

    struct Servers(Vec<Ipv4Addr>);
    impl SystemDnsServersPort for Servers {
        fn upstream_candidates_v4(&self) -> Vec<UpstreamDnsCandidate> {
            self.0
                .iter()
                .map(|s| UpstreamDnsCandidate::new(None, *s))
                .collect()
        }
    }

    fn corp() -> Ipv4Addr {
        Ipv4Addr::new(192, 168, 0, 53)
    }

    /// The whole point: only a resolver that can know something the public one
    /// cannot is worth a second question.
    #[test]
    fn only_a_private_resolver_is_worth_asking_again() {
        for private in [
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(172, 16, 0, 1),
            Ipv4Addr::new(172, 31, 255, 254),
            corp(),
        ] {
            assert!(is_private_resolver(private), "{private}");
        }
        for public in [
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(8, 8, 8, 8),
            Ipv4Addr::new(172, 15, 0, 1),
            Ipv4Addr::new(172, 32, 0, 1),
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::UNSPECIFIED,
        ] {
            assert!(!is_private_resolver(public), "{public}");
        }
    }

    /// A successful answer must not cost a single extra query.
    #[test]
    fn an_answered_name_never_reaches_the_fallback() {
        let inner = Arc::new(Fixed(
            Ok(ResolvedA {
                addresses: vec![Ipv4Addr::new(23, 10, 20, 138)],
                ttl_seconds: 60,
            }),
            Mutex::new(0),
        ));
        let r = LocalNamespaceFallbackResolver::new(
            inner,
            Arc::new(Servers(vec![corp()])),
            Duration::from_millis(1),
        );
        assert!(r.resolve_a("host.example").is_ok());
    }

    /// A transport failure is retried by the layers below; re-asking here would
    /// multiply the wait and learn nothing.
    #[test]
    fn a_transport_failure_is_not_a_second_opinion_case() {
        let inner = Arc::new(Fixed(
            Err(ResolveError::Unavailable("timeout".into())),
            Mutex::new(0),
        ));
        let r = LocalNamespaceFallbackResolver::new(
            inner,
            Arc::new(Servers(vec![corp()])),
            Duration::from_millis(1),
        );
        assert!(matches!(
            r.resolve_a("host.example"),
            Err(ResolveError::Unavailable(_))
        ));
    }

    /// Nothing private to ask: the original answer stands, with no delay spent
    /// discovering that.
    #[test]
    fn a_machine_with_only_public_resolvers_answers_as_before() {
        let inner = Arc::new(Fixed(Err(ResolveError::NoRecords), Mutex::new(0)));
        let r = LocalNamespaceFallbackResolver::new(
            inner,
            Arc::new(Servers(vec![Ipv4Addr::new(1, 1, 1, 1)])),
            Duration::from_millis(1),
        );
        assert!(matches!(
            r.resolve_a("host.example"),
            Err(ResolveError::NoRecords)
        ));
    }

    /// The server the wrapped upstream already used is not asked again.
    #[test]
    fn the_server_already_asked_is_excluded() {
        let inner = Arc::new(Fixed(Err(ResolveError::NoRecords), Mutex::new(0)));
        let r = LocalNamespaceFallbackResolver::new(
            inner,
            Arc::new(Servers(vec![corp(), Ipv4Addr::new(10, 0, 0, 1)])),
            Duration::from_millis(1),
        )
        .already_asked(vec![corp()]);
        assert_eq!(r.fallback_servers(), vec![Ipv4Addr::new(10, 0, 0, 1)]);
    }

    /// The bound holds however many resolvers the machine lists.
    #[test]
    fn the_number_of_second_opinions_is_bounded() {
        let many: Vec<Ipv4Addr> = (1..=8).map(|i| Ipv4Addr::new(10, 0, 0, i)).collect();
        let inner = Arc::new(Fixed(Err(ResolveError::NoRecords), Mutex::new(0)));
        let r = LocalNamespaceFallbackResolver::new(
            inner,
            Arc::new(Servers(many)),
            Duration::from_millis(1),
        );
        assert_eq!(r.fallback_servers().len(), MAX_FALLBACK_SERVERS);
    }
}
