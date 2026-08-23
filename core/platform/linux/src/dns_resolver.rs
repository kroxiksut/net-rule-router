//! The Linux [`DnsResolverPort`]: a stub resolver over UDP, with the TCP retry
//! the protocol requires.
//!
//! ## Why not `getaddrinfo`
//!
//! The product does not need an address — it needs an address AND how long it
//! stays valid. `getaddrinfo` answers the first and discards the second, and a
//! cache without TTLs either pins a stale address or re-asks constantly. The
//! Windows side gets TTLs from `DnsQuery_W`; here they come from reading the
//! answer ourselves.
//!
//! ## Servers
//!
//! Taken from `/etc/resolv.conf`, in file order — the same list the C library
//! would use, including the `127.0.0.53` stub that systemd-resolved installs
//! there. Following the machine's own configuration is what keeps split-DNS and
//! VPN-pushed resolvers working; picking a public server instead would quietly
//! bypass both.

#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

use nrr_platform_api::dns::{
    DnsResolverError, DnsResolverPort, ResolvedRecord, SystemDnsServersPort, UpstreamDnsCandidate,
};

use crate::dns_message::{
    canonical_name, decode_response, encode_query, DnsAnswer, DnsDecodeError,
};

/// How long one server gets to answer before the next is tried. Short on
/// purpose: this runs on a service tick with several names to refresh, and a
/// resolver that is not answering must not hold the tick.
const QUERY_TIMEOUT: Duration = Duration::from_secs(2);

/// A datagram answer larger than this cannot arrive; the server sets TC instead
/// and we re-ask over TCP.
const MAX_DATAGRAM: usize = 512;

/// Where the machine's resolvers are configured.
pub const RESOLV_CONF: &str = "/etc/resolv.conf";

/// The IPv4 nameservers from `/etc/resolv.conf`.
#[derive(Debug, Clone, Default)]
pub struct ResolvConfDnsServers;

impl SystemDnsServersPort for ResolvConfDnsServers {
    fn upstream_candidates_v4(&self) -> Vec<UpstreamDnsCandidate> {
        let text = std::fs::read_to_string(RESOLV_CONF).unwrap_or_default();
        parse_nameservers(&text)
            .into_iter()
            // The file says nothing about interfaces, and inventing one would
            // send a query out a link the machine did not choose.
            .map(|server| UpstreamDnsCandidate::new(None, server))
            .collect()
    }
}

/// Read the `nameserver` lines of a `resolv.conf`. Pure, so its tests run
/// anywhere.
#[must_use]
pub fn parse_nameservers(text: &str) -> Vec<Ipv4Addr> {
    let mut servers = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        let Some(rest) = line.strip_prefix("nameserver") else {
            continue;
        };
        // IPv6 nameservers are skipped rather than mis-parsed: this resolver
        // asks for A records, and the transport it asks over is v4.
        if let Ok(server) = rest.trim().parse::<Ipv4Addr>() {
            if !servers.contains(&server) {
                servers.push(server);
            }
        }
    }
    servers
}

/// Resolves A records by asking the machine's configured servers directly.
pub struct LinuxDnsResolver {
    servers: Box<dyn SystemDnsServersPort>,
    timeout: Duration,
    /// Transaction ids are sequential from a per-process starting point rather
    /// than random: the id is a check that a datagram answers OUR question, and
    /// the real defence against a forged answer is that we also compare the
    /// question and the peer address.
    next_id: AtomicU16,
}

impl Default for LinuxDnsResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl LinuxDnsResolver {
    #[must_use]
    pub fn new() -> Self {
        Self::with_servers(Box::new(ResolvConfDnsServers))
    }

    #[must_use]
    pub fn with_servers(servers: Box<dyn SystemDnsServersPort>) -> Self {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos() as u16)
            .unwrap_or(1);
        Self {
            servers,
            timeout: QUERY_TIMEOUT,
            next_id: AtomicU16::new(seed),
        }
    }

    /// Shorten or lengthen the per-server wait. Used by the live test, which
    /// must not hold a suite for two seconds per unreachable server.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    fn ask(&self, server: Ipv4Addr, canonical: &str) -> Result<DnsAnswer, DnsResolverError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let query = encode_query(id, canonical).ok_or_else(|| DnsResolverError::InvalidName {
            name: canonical.to_owned(),
        })?;
        let target = SocketAddr::new(server.into(), 53);

        match self.ask_udp(target, &query, id, canonical) {
            // The answer did not fit in a datagram. The protocol's own remedy is
            // to ask again over TCP; treating TC as a failure would make every
            // large record set unresolvable.
            Err(UdpFailure::Truncated) => self.ask_tcp(target, &query, id, canonical),
            Err(UdpFailure::Failed(e)) => Err(e),
            Ok(answer) => Ok(answer),
        }
    }

    fn ask_udp(
        &self,
        target: SocketAddr,
        query: &[u8],
        id: u16,
        canonical: &str,
    ) -> Result<DnsAnswer, UdpFailure> {
        let socket =
            UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).map_err(|e| net_error(e, canonical))?;
        socket
            .set_read_timeout(Some(self.timeout))
            .map_err(|e| net_error(e, canonical))?;
        // Connected UDP: the kernel then drops datagrams from anyone else, which
        // is the cheapest half of not believing a forged answer.
        socket
            .connect(target)
            .map_err(|e| net_error(e, canonical))?;
        socket.send(query).map_err(|e| net_error(e, canonical))?;

        let mut buffer = [0u8; MAX_DATAGRAM];
        let read = socket
            .recv(&mut buffer)
            .map_err(|e| timeout_or_net(e, canonical))?;
        interpret(&buffer[..read], id, canonical)
    }

    fn ask_tcp(
        &self,
        target: SocketAddr,
        query: &[u8],
        id: u16,
        canonical: &str,
    ) -> Result<DnsAnswer, DnsResolverError> {
        let mut stream = TcpStream::connect_timeout(&target, self.timeout)
            .map_err(|e| plain_net(e, canonical))?;
        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(|e| plain_net(e, canonical))?;
        // Over TCP a message is length-prefixed; without the prefix the server
        // waits for bytes that never come and the query times out.
        let length = u16::try_from(query.len()).map_err(|_| DnsResolverError::InvalidName {
            name: canonical.to_owned(),
        })?;
        stream
            .write_all(&length.to_be_bytes())
            .and_then(|()| stream.write_all(query))
            .map_err(|e| plain_net(e, canonical))?;

        let mut prefix = [0u8; 2];
        stream
            .read_exact(&mut prefix)
            .map_err(|e| plain_timeout_or_net(e, canonical))?;
        let mut body = vec![0u8; usize::from(u16::from_be_bytes(prefix))];
        stream
            .read_exact(&mut body)
            .map_err(|e| plain_timeout_or_net(e, canonical))?;

        match interpret(&body, id, canonical) {
            Ok(answer) => Ok(answer),
            // A server that sets TC on a TCP answer is broken; there is no
            // further transport to escalate to.
            Err(UdpFailure::Truncated) => Err(DnsResolverError::Refused {
                hostname: canonical.to_owned(),
                code: 0,
            }),
            Err(UdpFailure::Failed(e)) => Err(e),
        }
    }
}

/// What went wrong with a datagram attempt: a truncation is a instruction to
/// retry differently, everything else is a failure to report.
enum UdpFailure {
    Truncated,
    Failed(DnsResolverError),
}

fn interpret(message: &[u8], id: u16, canonical: &str) -> Result<DnsAnswer, UdpFailure> {
    match decode_response(message, id, canonical) {
        Ok(answer) => Ok(answer),
        Err(DnsDecodeError::TruncatedByServer) => Err(UdpFailure::Truncated),
        // Everything else means this datagram does not answer our question: a
        // stray reply, a forgery, a malformed message. Reported as a soft
        // failure so the caller retries rather than caching a wrong answer.
        Err(other) => Err(UdpFailure::Failed(DnsResolverError::Refused {
            hostname: canonical.to_owned(),
            code: decode_code(&other),
        })),
    }
}

/// A stable number per decode failure, so a log or a report can tell them apart
/// without carrying the error type across the port boundary.
fn decode_code(error: &DnsDecodeError) -> u32 {
    match error {
        DnsDecodeError::Truncated => 1,
        DnsDecodeError::WrongTransaction { .. } => 2,
        DnsDecodeError::WrongQuestion { .. } => 3,
        DnsDecodeError::NotAResponse => 4,
        DnsDecodeError::TruncatedByServer => 5,
        DnsDecodeError::MalformedName => 6,
    }
}

fn net_error(e: std::io::Error, hostname: &str) -> UdpFailure {
    UdpFailure::Failed(plain_net(e, hostname))
}

fn timeout_or_net(e: std::io::Error, hostname: &str) -> UdpFailure {
    UdpFailure::Failed(plain_timeout_or_net(e, hostname))
}

fn plain_net(e: std::io::Error, hostname: &str) -> DnsResolverError {
    DnsResolverError::Network {
        hostname: hostname.to_owned(),
        code: e.raw_os_error().unwrap_or(0) as u32,
    }
}

fn plain_timeout_or_net(e: std::io::Error, hostname: &str) -> DnsResolverError {
    match e.kind() {
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
            DnsResolverError::Timeout {
                hostname: hostname.to_owned(),
            }
        }
        _ => plain_net(e, hostname),
    }
}

impl DnsResolverPort for LinuxDnsResolver {
    fn resolve_a(&self, hostname: &str) -> Result<ResolvedRecord, DnsResolverError> {
        let canonical = canonical_name(hostname);
        if canonical.is_empty() || canonical.contains('\0') {
            return Err(DnsResolverError::InvalidName { name: canonical });
        }
        let servers = self.servers.upstream_candidates_v4();
        if servers.is_empty() {
            return Err(DnsResolverError::UnsupportedPlatform {
                reason: "no IPv4 nameserver is configured in /etc/resolv.conf",
            });
        }

        let mut last = DnsResolverError::Timeout {
            hostname: canonical.clone(),
        };
        for candidate in servers {
            match self.ask(candidate.server, &canonical) {
                Ok(DnsAnswer::Addresses { addresses, min_ttl }) => {
                    return Ok(ResolvedRecord {
                        canonical_hostname: canonical,
                        addresses,
                        ttl_seconds: Some(min_ttl),
                    })
                }
                // Authoritative answers end the search: asking the next server
                // would turn one server's "this does not exist" into a shopping
                // trip for one that disagrees.
                Ok(DnsAnswer::NxDomain) | Ok(DnsAnswer::NoAddresses) => {
                    return Err(DnsResolverError::NxDomain {
                        hostname: canonical,
                    })
                }
                Ok(DnsAnswer::Refused) => {
                    last = DnsResolverError::Refused {
                        hostname: canonical.clone(),
                        code: 5,
                    }
                }
                Ok(DnsAnswer::ServerFailure { rcode }) => {
                    last = DnsResolverError::Refused {
                        hostname: canonical.clone(),
                        code: u32::from(rcode),
                    }
                }
                Err(e) => last = e,
            }
        }
        Err(last)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nameservers_are_read_in_file_order_without_duplicates() {
        let text = "\
# Generated by NetworkManager
nameserver 127.0.0.53
nameserver 192.168.1.1  # the router
nameserver 127.0.0.53
nameserver fe80::1
options edns0
";
        assert_eq!(
            parse_nameservers(text),
            vec![Ipv4Addr::new(127, 0, 0, 53), Ipv4Addr::new(192, 168, 1, 1)],
        );
    }

    #[test]
    fn a_file_without_nameservers_yields_none() {
        assert!(parse_nameservers("search lan\noptions ndots:1\n").is_empty());
    }

    /// A machine with no resolver configured is not a machine where DNS failed —
    /// it is one where the question cannot be asked, and the caller decides what
    /// that means rather than retrying a timeout forever.
    #[test]
    fn no_configured_server_is_reported_as_unsupported_not_as_a_timeout() {
        struct NoServers;
        impl SystemDnsServersPort for NoServers {
            fn upstream_candidates_v4(&self) -> Vec<UpstreamDnsCandidate> {
                Vec::new()
            }
        }
        let resolver = LinuxDnsResolver::with_servers(Box::new(NoServers));

        assert!(matches!(
            resolver.resolve_a("example.com"),
            Err(DnsResolverError::UnsupportedPlatform { .. })
        ));
    }

    #[test]
    fn a_name_that_cannot_be_asked_about_is_rejected_before_any_socket() {
        let resolver = LinuxDnsResolver::new();

        assert!(matches!(
            resolver.resolve_a("  "),
            Err(DnsResolverError::InvalidName { .. })
        ));
        assert!(matches!(
            resolver.resolve_a("bad\0name"),
            Err(DnsResolverError::InvalidName { .. })
        ));
    }
}
