//! Thin UDP transport for the external-address probe.
//!
//! Portable by construction: `std::net` only. There is no per-OS mechanism to
//! hide behind a port trait here — the same twenty bytes go out of the same
//! socket API on Windows, Linux and macOS — so this module is the whole
//! implementation rather than a seam.
//!
//! The decisive property is `UdpSocket::bind((local_ipv4, 0))`: binding the
//! probe socket to ONE adapter's own source address makes the reflexive
//! address that comes back describe THAT adapter. Showing an external address
//! *per adapter* is the entire point of the feature, and an HTTP "what is my
//! IP" call cannot be source-bound without dragging in an HTTP client.
//!
//! Timing is bounded from two sides: each attempt has its own read timeout,
//! and the batch has a wall-clock budget it never exceeds — the caller is a
//! synchronous request handler, so "slow" must degrade to "unavailable"
//! rather than to "the window is frozen".

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, ToSocketAddrs, UdpSocket};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use super::{stun, ExternalIpProbeOutcome};

/// Public STUN endpoints, tried in order.
///
/// It is a list rather than a single host on purpose: these are third-party
/// services nobody here controls, and one of them disappearing, moving or
/// rate-limiting must degrade to "try the next one" instead of to "the feature
/// is broken". Hostnames (not literal addresses) keep the list verifiable and
/// let the operators move their anycast estate.
pub const STUN_SERVERS: [&str; 3] = [
    "stun.l.google.com:19302",
    "stun.cloudflare.com:3478",
    "stun1.l.google.com:19302",
];

/// How long one request/response exchange may take.
pub const ATTEMPT_TIMEOUT: Duration = Duration::from_millis(1_500);

/// How many servers are actually contacted before giving up. Two is enough to
/// survive a single dead endpoint without turning a refresh into a stall.
pub const MAX_ATTEMPTS: usize = 2;

/// Hard wall-clock ceiling on a whole batch, whatever the workers are doing.
/// Comfortably inside the request deadline the IPC client applies to the
/// refresh call, leaving room for the adapter enumeration itself.
pub const PROBE_BUDGET: Duration = Duration::from_millis(3_200);

/// Probe several adapters at once, one worker per source address, and return
/// one outcome per input in the same order.
///
/// Workers are deliberately **not** joined. A worker can block inside the OS
/// resolver or a socket call for longer than any timeout we set on the socket
/// itself; detaching them means the caller returns on the budget no matter
/// what, and a straggler simply finds the receiver gone when it finishes.
/// Anything that has not reported by the deadline is `Unreachable`, which is
/// exactly what the user should be told about it.
#[must_use]
pub fn probe_external_ipv4_batch(sources: &[Ipv4Addr]) -> Vec<ExternalIpProbeOutcome> {
    let mut outcomes = vec![ExternalIpProbeOutcome::Unreachable; sources.len()];
    if sources.is_empty() {
        return outcomes;
    }

    let deadline = Instant::now()
        .checked_add(PROBE_BUDGET)
        .unwrap_or_else(Instant::now);
    let (sender, receiver) = mpsc::channel();
    let mut workers = 0usize;

    for (index, source) in sources.iter().copied().enumerate() {
        let sender = sender.clone();
        let spawned = thread::Builder::new()
            .name("nrr-extip-probe".to_string())
            .spawn(move || {
                // The receiver may already be gone; that is the normal
                // "budget expired" path and needs no handling.
                let _ = sender.send((index, probe_one(source)));
            });
        match spawned {
            Ok(_detached) => workers += 1,
            Err(error) => {
                tracing::debug!(
                    target: "nrr::interfaces",
                    error = %error,
                    "external-address probe worker not started",
                );
            }
        }
    }
    // Drop the template so the channel closes once every worker is done.
    drop(sender);

    let mut collected = 0usize;
    while collected < workers {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let Ok((index, outcome)) = receiver.recv_timeout(remaining) else {
            break;
        };
        if let Some(slot) = outcomes.get_mut(index) {
            *slot = outcome;
        }
        collected += 1;
    }

    outcomes
}

/// Probe one source address: walk the server list until something answers,
/// spending at most [`MAX_ATTEMPTS`] network round-trips and never outliving
/// [`PROBE_BUDGET`].
fn probe_one(source: Ipv4Addr) -> ExternalIpProbeOutcome {
    let deadline = Instant::now()
        .checked_add(PROBE_BUDGET)
        .unwrap_or_else(Instant::now);
    let mut locally_blocked = false;
    let mut attempts = 0usize;

    for server in STUN_SERVERS {
        if attempts >= MAX_ATTEMPTS || Instant::now() >= deadline {
            break;
        }
        // A name that will not resolve costs no network wait, so it does not
        // consume one of the attempts — the next server gets it instead.
        let Some(target) = resolve_ipv4(server) else {
            tracing::debug!(
                target: "nrr::interfaces",
                server,
                source = %source,
                "external-address probe: server name did not resolve to IPv4",
            );
            continue;
        };
        // RFC 2544 benchmark space (198.18.0.0/15) can never host a public
        // server: an answer there means the resolution was intercepted or
        // synthesised on this machine. Waiting on it wastes the attempt.
        if is_benchmark_range(*target.ip()) {
            tracing::warn!(
                target: "nrr::interfaces",
                server,
                resolved = %target.ip(),
                source = %source,
                "external-address probe: server resolved into the 198.18.0.0/15 benchmark range — poisoned or locally intercepted answer, skipping",
            );
            continue;
        }
        attempts += 1;

        match attempt(source, target, deadline) {
            Ok(Some(address)) => {
                tracing::info!(
                    target: "nrr::interfaces",
                    server,
                    source = %source,
                    "external-address probe: reflexive address obtained",
                );
                return ExternalIpProbeOutcome::Resolved(address);
            }
            Ok(None) => {
                tracing::debug!(
                    target: "nrr::interfaces",
                    server,
                    resolved = %target.ip(),
                    source = %source,
                    "external-address probe: no answer within the attempt window",
                );
            }
            Err(error) => {
                // A local packet filter refusing our own datagram is reported
                // as "blocked", which is a different story for the user than
                // "the server never answered".
                if error.kind() == io::ErrorKind::PermissionDenied {
                    locally_blocked = true;
                }
                tracing::debug!(
                    target: "nrr::interfaces",
                    server,
                    error = %error,
                    "external-address probe attempt failed",
                );
            }
        }
    }

    let outcome = if locally_blocked {
        ExternalIpProbeOutcome::LocallyBlocked
    } else {
        ExternalIpProbeOutcome::Unreachable
    };
    // Info, not debug: a failed user-initiated probe is exactly what a
    // triage of "the GUI shows no external address" needs to see in the
    // operational log at the default filter.
    tracing::info!(
        target: "nrr::interfaces",
        source = %source,
        attempts,
        outcome = ?outcome,
        "external-address probe: finished without a reflexive address",
    );
    outcome
}

/// `true` for 198.18.0.0/15 (RFC 2544 device-benchmark space). Public
/// services are never legitimately hosted there, so a resolution landing in
/// it is a poisoned or locally rewritten answer by definition.
fn is_benchmark_range(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 198 && (octets[1] & 0xFE) == 18
}

/// One request/response exchange. `Ok(None)` means "no usable answer in time",
/// `Err` means the local stack refused to play.
fn attempt(
    source: Ipv4Addr,
    server: SocketAddrV4,
    deadline: Instant,
) -> io::Result<Option<Ipv4Addr>> {
    let socket = UdpSocket::bind(SocketAddrV4::new(source, 0))?;
    // Pinning the peer makes the kernel drop datagrams from anywhere else and
    // surfaces an ICMP port-unreachable as an error instead of a silent wait.
    socket.connect(SocketAddr::V4(server))?;

    let mut transaction_id: stun::TransactionId = [0u8; 12];
    // `getrandom::Error` is `no_std` and does not implement `std::error::Error`,
    // so it is carried across as text rather than as a source.
    getrandom::fill(&mut transaction_id)
        .map_err(|error| io::Error::other(format!("transaction id unavailable: {error}")))?;
    socket.send(&stun::build_binding_request(&transaction_id))?;

    let attempt_deadline = Instant::now()
        .checked_add(ATTEMPT_TIMEOUT)
        .map_or(deadline, |until| until.min(deadline));
    let mut buffer = [0u8; 1024];

    loop {
        let remaining = attempt_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(None);
        }
        socket.set_read_timeout(Some(remaining))?;

        match socket.recv(&mut buffer) {
            Ok(read) => {
                let Some(datagram) = buffer.get(..read) else {
                    return Ok(None);
                };
                if let Some(address) = stun::parse_binding_response(datagram, &transaction_id) {
                    return Ok(Some(address));
                }
                // Something that is not our answer: keep waiting inside this
                // attempt's budget instead of burning the next attempt.
            }
            Err(error) if is_timeout(&error) => return Ok(None),
            Err(error) => return Err(error),
        }
    }
}

fn resolve_ipv4(server: &str) -> Option<SocketAddrV4> {
    server
        .to_socket_addrs()
        .ok()?
        .find_map(|address| match address {
            SocketAddr::V4(v4) => Some(v4),
            SocketAddr::V6(_) => None,
        })
}

fn is_timeout(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_list_is_usable_and_diverse() {
        assert!(
            STUN_SERVERS.len() >= MAX_ATTEMPTS,
            "the list must be able to feed every attempt a distinct server"
        );
        for server in STUN_SERVERS {
            let (host, port) = server
                .rsplit_once(':')
                .expect("every entry is host:port so ToSocketAddrs accepts it");
            assert!(!host.is_empty());
            assert!(
                port.parse::<u16>().is_ok_and(|p| p > 0),
                "{server} must carry a usable port"
            );
        }
        // Registrable domain (last two labels) stands in for "who runs it".
        let operators = STUN_SERVERS
            .iter()
            .filter_map(|server| server.rsplit_once(':').map(|(host, _)| host))
            .map(|host| host.rsplit('.').take(2).collect::<Vec<_>>().join("."))
            .collect::<std::collections::BTreeSet<_>>();
        assert!(
            operators.len() > 1,
            "a single operator's outage must not take the feature down"
        );
    }

    #[test]
    fn attempt_budget_fits_inside_the_wall_clock_budget() {
        assert!(
            ATTEMPT_TIMEOUT
                .checked_mul(u32::try_from(MAX_ATTEMPTS).expect("small count"))
                .is_some_and(|total| total <= PROBE_BUDGET),
            "every attempt must be able to run to completion inside the budget"
        );
        assert!(
            PROBE_BUDGET < Duration::from_secs(5),
            "the budget must stay inside the refresh request deadline"
        );
    }

    #[test]
    fn empty_input_never_touches_the_network() {
        assert!(probe_external_ipv4_batch(&[]).is_empty());
    }

    #[test]
    fn timeout_kinds_are_recognised_as_no_answer() {
        assert!(is_timeout(&io::Error::from(io::ErrorKind::WouldBlock)));
        assert!(is_timeout(&io::Error::from(io::ErrorKind::TimedOut)));
        assert!(!is_timeout(&io::Error::from(
            io::ErrorKind::PermissionDenied
        )));
    }
}
