//! The operational-log trail of connections the service tore down.
//!
//! The summary lines carry counters only; this module adds the per-connection
//! lines that answer "did the service cut this connection?". Field names are
//! the ones the log's privacy classifier already knows (`remote`, `host`,
//! `image`), so the address, hostname and process are redacted in the same
//! modes as the `connobs-*` lines.

use std::net::Ipv4Addr;

use nrr_platform_api::fake_ip::stale_flows::EstablishedFlow;

/// Connections written one by one per batch; the rest are counted. A reset
/// storm must not turn the size-capped log into a list of sockets.
pub const MAX_LOGGED_FLOWS: usize = 50;

/// Why a batch was torn down; stable slugs shown in the line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResetCause {
    /// The host is routed by a rule that was just applied.
    RoutedHost,
    /// The site a suggestion was offered next to.
    Anchor,
    /// The address became enforced by this activation.
    NewDestination,
    /// The additional link just became usable.
    TunnelCameUp,
    /// A destination pin dropped this socket or a sibling of it.
    PinDrop,
    /// The destination left the plan while steered onto the additional link.
    LeftTunnel,
}

impl ResetCause {
    #[must_use]
    pub fn slug(self) -> &'static str {
        match self {
            Self::RoutedHost => "routed-host",
            Self::Anchor => "anchor",
            Self::NewDestination => "new-destination",
            Self::TunnelCameUp => "tunnel-came-up",
            Self::PinDrop => "pin-drop",
            Self::LeftTunnel => "left-tunnel",
        }
    }
}

/// How many of `total` connections get their own line.
#[must_use]
pub fn lines_for(total: usize) -> (usize, usize) {
    let shown = total.min(MAX_LOGGED_FLOWS);
    (shown, total - shown)
}

/// Write one line per reset connection, up to [`MAX_LOGGED_FLOWS`], then one
/// line counting the rest. `host_and_cause` names the host behind a remote
/// address (when known) and the cause for that connection. `sid` is the rule
/// owner; `None` takes each connection's own owner.
pub fn log_reset_flows<'a>(
    sid: Option<&str>,
    flows: &[EstablishedFlow],
    host_and_cause: impl Fn(Ipv4Addr) -> (Option<&'a str>, ResetCause),
) {
    let (shown, omitted) = lines_for(flows.len());
    for flow in &flows[..shown] {
        let (host, cause) = host_and_cause(*flow.remote.ip());
        tracing::info!(
            target: "nrr::flow-reset",
            msg_key = "flowreset-connection",
            sid = sid.or(flow.owner.as_deref()).unwrap_or("?"),
            remote = %flow.remote,
            local_port = flow.local.port(),
            image = flow.image.as_deref().unwrap_or("?"),
            pid = flow.pid.unwrap_or(0),
            host = host.unwrap_or("?"),
            cause = cause.slug(),
            "reset a live connection",
        );
    }
    if omitted > 0 {
        tracing::info!(
            target: "nrr::flow-reset",
            msg_key = "flowreset-connections-omitted",
            sid = sid.unwrap_or("?"),
            omitted,
            shown,
            "more connections were reset in this batch than are listed",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_small_batch_is_listed_whole() {
        assert_eq!(lines_for(0), (0, 0));
        assert_eq!(lines_for(MAX_LOGGED_FLOWS), (MAX_LOGGED_FLOWS, 0));
    }

    #[test]
    fn a_storm_is_capped_and_the_rest_counted() {
        assert_eq!(lines_for(MAX_LOGGED_FLOWS + 7), (MAX_LOGGED_FLOWS, 7));
        assert_eq!(
            lines_for(10_000),
            (MAX_LOGGED_FLOWS, 10_000 - MAX_LOGGED_FLOWS)
        );
    }

    fn flow(port: u16) -> EstablishedFlow {
        EstablishedFlow {
            local: std::net::SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), port),
            remote: std::net::SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 3389),
            owner: Some("S-1-5-21-1-2-3-1001".into()),
            pid: Some(4242),
            image: Some("client.example.exe".into()),
        }
    }

    fn logged(flows: &[EstablishedFlow]) -> Vec<serde_json::Value> {
        use tracing_subscriber::layer::SubscriberExt;

        let dir = tempfile::TempDir::new().expect("temp dir");
        let writer = std::sync::Arc::new(nrr_diagnostics::LogWriter::open(
            nrr_diagnostics::LogWriterConfig::new(dir.path()),
        ));
        let subscriber =
            tracing_subscriber::registry().with(nrr_diagnostics::NdjsonTracingLayer::new(writer));
        tracing::subscriber::with_default(subscriber, || {
            log_reset_flows(Some("S-1-5-21-1-2-3-1001"), flows, |_| {
                (Some("host.example"), ResetCause::RoutedHost)
            });
        });
        let mut lines = Vec::new();
        for entry in std::fs::read_dir(dir.path()).expect("logs dir") {
            let text = std::fs::read_to_string(entry.expect("entry").path()).expect("read");
            lines.extend(
                text.lines()
                    .map(|l| serde_json::from_str(l).expect("ndjson")),
            );
        }
        lines
    }

    #[test]
    fn a_line_carries_the_connection_with_address_host_and_image_redacted() {
        let lines = logged(&[flow(50_000)]);
        assert_eq!(lines.len(), 1);
        let payload = &lines[0]["payload"];
        assert_eq!(lines[0]["message_key"], "diag.event.flowreset-connection");
        // The default mode masks address, host and image; the rest stays readable.
        for key in ["remote", "host", "image"] {
            assert_eq!(
                payload[key],
                nrr_diagnostics::logs::privacy::REDACTED,
                "{key}"
            );
        }
        assert_eq!(payload["local_port"], 50_000);
        assert_eq!(payload["pid"], 4242);
        assert_eq!(payload["cause"], "routed-host");
    }

    #[test]
    fn a_storm_writes_the_cap_and_one_overflow_line() {
        let flows: Vec<_> = (0..MAX_LOGGED_FLOWS as u16 + 5)
            .map(|i| flow(50_000 + i))
            .collect();
        let lines = logged(&flows);
        let of = |key: &str| {
            lines
                .iter()
                .filter(|l| l["message_key"] == format!("diag.event.{key}"))
                .count()
        };
        assert_eq!(of("flowreset-connection"), MAX_LOGGED_FLOWS);
        assert_eq!(of("flowreset-connections-omitted"), 1);
        let more = lines
            .iter()
            .find(|l| l["message_key"] == "diag.event.flowreset-connections-omitted")
            .expect("overflow line");
        assert_eq!(more["payload"]["omitted"], 5);
    }
}
