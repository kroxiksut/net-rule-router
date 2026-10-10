//! "Does this address answer over THIS link?" — one bounded TCP connect with
//! the socket pinned to the link.
//!
//! Binding a source address is not enough here: Linux picks the egress
//! interface by destination, so a host whose route points at the tunnel would
//! leave through the tunnel with the main link's address on it, and the answer
//! would be about the wrong path. `SO_BINDTODEVICE` restricts the route lookup
//! to the named link; the source bind keeps the address consistent with it.
//!
//! The link is named by the address it carries, because that is what the
//! neutral probe hands over.

use std::net::Ipv4Addr;
#[cfg(target_os = "linux")]
use std::time::Duration;

/// What one connect attempt established.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkProbeOutcome {
    /// The connection completed over the requested link.
    Connected,
    /// Refused, reset or silent past the timeout: evidence the host does not
    /// answer that way.
    NoAnswer,
    /// The attempt never ran — no such link, a socket the kernel refused, a
    /// zero budget. Not evidence either way.
    NotRun,
}

/// The link carrying `source` among `(name, ipv4 addresses)` pairs.
pub fn link_carrying<'a, I>(links: I, source: Ipv4Addr) -> Option<&'a str>
where
    I: IntoIterator<Item = (&'a str, &'a [Ipv4Addr])>,
{
    links
        .into_iter()
        .find(|(_, addresses)| addresses.contains(&source))
        .map(|(name, _)| name)
}

/// Only a refusal, a reset or a timeout says the host did not answer;
/// anything else means the probe did not measure the path.
pub fn outcome_of_connect_error(kind: std::io::ErrorKind) -> LinkProbeOutcome {
    use std::io::ErrorKind;
    match kind {
        ErrorKind::TimedOut
        | ErrorKind::WouldBlock
        | ErrorKind::ConnectionRefused
        | ErrorKind::ConnectionReset
        | ErrorKind::ConnectionAborted => LinkProbeOutcome::NoAnswer,
        _ => LinkProbeOutcome::NotRun,
    }
}

/// Connect to `target:port` over the link that carries `source`.
#[cfg(target_os = "linux")]
pub fn connect_over_link(
    target: Ipv4Addr,
    port: u16,
    source: Ipv4Addr,
    timeout: Duration,
) -> LinkProbeOutcome {
    match socket_over_link(target, port, source, timeout) {
        Ok(_) => LinkProbeOutcome::Connected,
        Err(outcome) => outcome,
    }
}

/// [`connect_over_link`], keeping the connected socket for a caller that has
/// more to say over it (a TLS hello).
#[cfg(target_os = "linux")]
pub fn socket_over_link(
    target: Ipv4Addr,
    port: u16,
    source: Ipv4Addr,
    timeout: Duration,
) -> Result<socket2::Socket, LinkProbeOutcome> {
    let addresses = crate::adapters_addr::unicast_addresses_by_interface();
    let Some(link) = link_carrying(
        addresses
            .iter()
            .map(|(name, a)| (name.as_str(), a.v4.as_slice())),
        source,
    ) else {
        return Err(LinkProbeOutcome::NotRun);
    };
    socket_bound(target, port, source, link, timeout)
}

/// [`connect_over_link`] with the link already named.
#[cfg(target_os = "linux")]
pub fn connect_bound(
    target: Ipv4Addr,
    port: u16,
    source: Ipv4Addr,
    link: &str,
    timeout: Duration,
) -> LinkProbeOutcome {
    match socket_bound(target, port, source, link, timeout) {
        Ok(_) => LinkProbeOutcome::Connected,
        Err(outcome) => outcome,
    }
}

#[cfg(target_os = "linux")]
fn socket_bound(
    target: Ipv4Addr,
    port: u16,
    source: Ipv4Addr,
    link: &str,
    timeout: Duration,
) -> Result<socket2::Socket, LinkProbeOutcome> {
    use socket2::{Domain, Protocol, Socket, Type};

    // A zero budget reports as a timeout, which would read as silence.
    if timeout.is_zero() {
        return Err(LinkProbeOutcome::NotRun);
    }
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))
        .map_err(|_| LinkProbeOutcome::NotRun)?;
    nrr_platform_api::own_traffic::mark_own_socket(&socket);
    socket
        .bind_device(Some(link.as_bytes()))
        .map_err(|_| LinkProbeOutcome::NotRun)?;
    socket
        .bind(&std::net::SocketAddr::from((source, 0)).into())
        .map_err(|_| LinkProbeOutcome::NotRun)?;
    socket
        .connect_timeout(&std::net::SocketAddr::from((target, port)).into(), timeout)
        .map_err(|e| outcome_of_connect_error(e.kind()))?;
    Ok(socket)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_link_is_found_by_the_address_it_carries() {
        let eth = [Ipv4Addr::new(192, 0, 2, 10)];
        let tun = [
            Ipv4Addr::new(198, 51, 100, 7),
            Ipv4Addr::new(198, 51, 100, 8),
        ];
        let links = [("eth0", &eth[..]), ("tun0", &tun[..])];
        assert_eq!(
            link_carrying(links, Ipv4Addr::new(198, 51, 100, 8)),
            Some("tun0")
        );
        assert_eq!(
            link_carrying(links, Ipv4Addr::new(192, 0, 2, 10)),
            Some("eth0")
        );
        assert_eq!(link_carrying(links, Ipv4Addr::new(203, 0, 113, 1)), None);
    }

    /// An unreachable network is not a silent host: calling it one would hand
    /// the suggestion engine evidence nothing measured.
    #[test]
    fn only_refusal_reset_or_timeout_count_as_no_answer() {
        use std::io::ErrorKind;
        for kind in [
            ErrorKind::TimedOut,
            ErrorKind::ConnectionRefused,
            ErrorKind::ConnectionReset,
        ] {
            assert_eq!(outcome_of_connect_error(kind), LinkProbeOutcome::NoAnswer);
        }
        for kind in [
            ErrorKind::NetworkUnreachable,
            ErrorKind::PermissionDenied,
            ErrorKind::AddrNotAvailable,
        ] {
            assert_eq!(outcome_of_connect_error(kind), LinkProbeOutcome::NotRun);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_zero_budget_does_not_run() {
        assert_eq!(
            connect_bound(
                Ipv4Addr::LOCALHOST,
                9,
                Ipv4Addr::LOCALHOST,
                "lo",
                Duration::ZERO
            ),
            LinkProbeOutcome::NotRun
        );
    }

    /// Over loopback: a listener answers, a closed port refuses. Skipped where
    /// the kernel will not let this process bind a device.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_pinned_connect_tells_an_answer_from_a_refusal() {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("listen");
        let open = listener.local_addr().expect("addr").port();
        let budget = Duration::from_secs(2);
        let answered = connect_bound(Ipv4Addr::LOCALHOST, open, Ipv4Addr::LOCALHOST, "lo", budget);
        if answered == LinkProbeOutcome::NotRun {
            eprintln!("skipping: SO_BINDTODEVICE is not permitted here");
            return;
        }
        assert_eq!(answered, LinkProbeOutcome::Connected);

        let closed = {
            let probe = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("listen");
            probe.local_addr().expect("addr").port()
        };
        assert_eq!(
            connect_bound(
                Ipv4Addr::LOCALHOST,
                closed,
                Ipv4Addr::LOCALHOST,
                "lo",
                budget
            ),
            LinkProbeOutcome::NoAnswer
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn an_address_no_link_carries_does_not_run() {
        assert_eq!(
            connect_over_link(
                Ipv4Addr::new(192, 0, 2, 1),
                443,
                Ipv4Addr::new(203, 0, 113, 254),
                Duration::from_millis(300)
            ),
            LinkProbeOutcome::NotRun
        );
    }
}
