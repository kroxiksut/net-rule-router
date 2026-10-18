//! The head of a site's HTTPS answer, read over the route's own socket.
//!
//! The connection is the one the path probe makes, bound to the source address
//! of the route the user's rules give the name, so the request never leaves by
//! another link. The certificate is verified against the Mozilla roots: a
//! chain that does not verify means something on this route answers in the
//! site's place (an antivirus inspecting encrypted traffic, a filter), and that
//! is reported rather than read past. Only the head is read, never the body.

use std::io::{ErrorKind, Read, Write};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::pki_types::ServerName;

use super::http_answer::{parse_head, HeadError, MAX_HEAD_BYTES};
use super::{HeadFailure, HttpsHead};
use crate::path_probe::PathProbe;

/// [`HttpsHead`] over rustls, connecting through the path probe's mechanism.
pub struct RustlsHttpsHead {
    probe: Arc<dyn PathProbe>,
    config: Arc<rustls::ClientConfig>,
}

impl RustlsHttpsHead {
    /// `None` when no TLS configuration can be built; the check then reports
    /// that it did not read the answer.
    pub fn new(probe: Arc<dyn PathProbe>) -> Option<Self> {
        let roots = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .ok()?
            .with_root_certificates(roots)
            .with_no_client_auth();
        Some(Self {
            probe,
            config: Arc::new(config),
        })
    }
}

/// An I/O error rustls raised because the certificate did not verify.
fn untrusted(error: &std::io::Error) -> bool {
    error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
        .is_some_and(|e| {
            matches!(
                e,
                rustls::Error::InvalidCertificate(_) | rustls::Error::NoCertificatesPresented
            )
        })
}

/// Bound the next read or write by what is left of `deadline`, at most
/// `timeout`; `false` once nothing is left.
fn bound_step(socket: &std::net::TcpStream, deadline: Instant, timeout: Duration) -> bool {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return false;
    }
    let step = left.min(timeout);
    socket.set_read_timeout(Some(step)).is_ok() && socket.set_write_timeout(Some(step)).is_ok()
}

fn failure_of(error: &std::io::Error) -> HeadFailure {
    if untrusted(error) {
        HeadFailure::Untrusted
    } else {
        HeadFailure::NoAnswer
    }
}

impl HttpsHead for RustlsHttpsHead {
    fn fetch(
        &self,
        target: Ipv4Addr,
        server_name: &str,
        source: Ipv4Addr,
        request: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, HeadFailure> {
        if timeout.is_zero() {
            return Err(HeadFailure::NoAnswer);
        }
        let name =
            ServerName::try_from(server_name.to_owned()).map_err(|_| HeadFailure::NoAnswer)?;
        let socket = self
            .probe
            .connect_stream(target, 443, source, timeout)
            .map_err(|_| HeadFailure::NoAnswer)?;
        // The whole exchange, handshake included, fits in three steps' worth.
        let deadline = Instant::now() + timeout * 3;
        let connection = rustls::ClientConnection::new(Arc::clone(&self.config), name)
            .map_err(|_| HeadFailure::NoAnswer)?;
        let mut tls = rustls::StreamOwned::new(connection, socket);
        if !bound_step(&tls.sock, deadline, timeout) {
            return Err(HeadFailure::NoAnswer);
        }
        tls.write_all(request).map_err(|e| failure_of(&e))?;
        let mut head = Vec::with_capacity(1024);
        let mut chunk = [0u8; 2048];
        loop {
            if !matches!(parse_head(&head), Err(HeadError::Incomplete)) {
                break;
            }
            if !bound_step(&tls.sock, deadline, timeout) {
                break;
            }
            match tls.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    let room = MAX_HEAD_BYTES.saturating_sub(head.len());
                    head.extend_from_slice(&chunk[..n.min(room)]);
                    if head.len() >= MAX_HEAD_BYTES {
                        break;
                    }
                }
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                // A close without the TLS goodbye still ends the head.
                Err(e) if e.kind() == ErrorKind::UnexpectedEof => break,
                Err(e) if head.is_empty() => return Err(failure_of(&e)),
                Err(_) => break,
            }
        }
        if head.is_empty() {
            Err(HeadFailure::NoAnswer)
        } else {
            Ok(head)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::path_probe::SystemPathProbe;

    #[test]
    fn a_configuration_is_built_from_the_bundled_roots() {
        assert!(RustlsHttpsHead::new(Arc::new(SystemPathProbe)).is_some());
    }

    #[test]
    fn a_certificate_error_is_told_apart_from_silence() {
        let bad = std::io::Error::new(
            ErrorKind::InvalidData,
            rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer),
        );
        assert_eq!(failure_of(&bad), HeadFailure::Untrusted);
        let reset = std::io::Error::new(ErrorKind::ConnectionReset, "reset");
        assert_eq!(failure_of(&reset), HeadFailure::NoAnswer);
    }

    /// A real site answers through the real roots. Needs the internet:
    /// `cargo test -p nrr-service-runtime -- --ignored live_https`.
    #[test]
    #[ignore = "needs the internet"]
    fn live_https_head_reads_a_status_line() {
        use std::net::ToSocketAddrs;
        let name = "www.wikipedia.org";
        let target = (name, 443)
            .to_socket_addrs()
            .expect("resolve")
            .find_map(|a| match a {
                std::net::SocketAddr::V4(v4) => Some(*v4.ip()),
                std::net::SocketAddr::V6(_) => None,
            })
            .expect("an IPv4 address");
        let head = RustlsHttpsHead::new(Arc::new(SystemPathProbe)).expect("config");
        let request = super::super::http_answer::request_for(name).expect("request");
        let source = std::net::UdpSocket::bind("0.0.0.0:0")
            .and_then(|s| s.connect((target, 443)).map(|()| s))
            .and_then(|s| s.local_addr())
            .map(|a| match a.ip() {
                std::net::IpAddr::V4(v4) => v4,
                std::net::IpAddr::V6(_) => Ipv4Addr::UNSPECIFIED,
            })
            .expect("a local address");
        let bytes = head
            .fetch(target, name, source, &request, Duration::from_secs(5))
            .expect("an answer");
        assert!(
            parse_head(&bytes).is_ok(),
            "{}",
            String::from_utf8_lossy(&bytes)
        );
    }
}
