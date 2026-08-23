//! The IPv6 route table, in the service log.
//!
//! The product routes IPv4 and closes IPv6 while the protection is on, so the
//! v6 table is never something we write. It is, however, the first thing any
//! IPv6 report needs: whether the machine has a v6 default route at all, and
//! whether the tunnel carries one, decides whether a v6 complaint is a leak, a
//! misconfiguration, or nothing. Asking the user for a screenshot of
//! `route print -6` answers that once; a line in the log answers it for every
//! report, including the ones exported from an archive days later.
//!
//! Logged on a CHANGE, not on a tick: the table is stable for hours at a time,
//! and a repeated dump would be pure archive-cap burn.

use std::sync::Mutex;

use nrr_platform_api::route_table::RouteTablePort;
use nrr_platform_api::types::Ipv6RouteRow;

/// Cap on rows written in one line. A machine with more v6 routes than this has
/// a story the count alone tells; the line stays readable.
const MAX_ROWS_LOGGED: usize = 64;

/// Remembers the last table it wrote so an unchanged one stays quiet.
#[derive(Default)]
pub struct Ipv6RouteTableLog {
    last: Mutex<Option<String>>,
}

impl Ipv6RouteTableLog {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Read the v6 table and log it if it differs from the last one logged.
    /// `reason` names what prompted the read ("boot", "network-change").
    /// Returns whether a line was written.
    pub fn log_if_changed(&self, api: &dyn RouteTablePort, reason: &str) -> bool {
        let rows = match api.get_ipv6_forward_table() {
            Ok(rows) => rows,
            Err(err) => {
                // Not an error worth alarming about: a platform that cannot
                // enumerate v6 is exactly as informative as an empty table.
                tracing::debug!(
                    target: "nrr::routes-v6",
                    reason,
                    error = ?err,
                    "IPv6 route table unavailable on this platform",
                );
                return false;
            }
        };
        self.log_rows_if_changed(&rows, reason)
    }

    /// The half that decides and writes, without the port — the same call the
    /// fetch above makes once it has rows.
    pub fn log_rows_if_changed(&self, rows: &[Ipv6RouteRow], reason: &str) -> bool {
        let rendered = render(rows);
        {
            let mut last = self.last.lock().unwrap_or_else(|p| p.into_inner());
            if last.as_deref() == Some(rendered.as_str()) {
                return false;
            }
            *last = Some(rendered.clone());
        }
        // `has_global` is the question the table is read for: without a global
        // route, IPv6 cannot leave the link, and every "it went out over IPv6"
        // report about this machine is answered before it is investigated.
        tracing::info!(
            target: "nrr::routes-v6",
            reason,
            routes = rows.len(),
            has_global = has_global_route(rows),
            table = %rendered,
            "IPv6 route table",
        );
        true
    }
}

/// Does any row carry traffic off the link — a default route or a global
/// unicast prefix? Link-local, loopback and multicast rows never do.
#[must_use]
pub fn has_global_route(rows: &[Ipv6RouteRow]) -> bool {
    rows.iter().any(|r| {
        let seg = r.destination.segments()[0];
        let link_local = (seg & 0xffc0) == 0xfe80;
        let multicast = (seg & 0xff00) == 0xff00;
        let loopback = r.destination.is_loopback();
        let unspecified_default = r.destination.is_unspecified() && r.prefix_length == 0;
        unspecified_default || !(link_local || multicast || loopback)
    })
}

/// One compact line: `dest/prefix via next-hop if=N metric=M`, comma-separated.
fn render(rows: &[Ipv6RouteRow]) -> String {
    let mut out = String::new();
    for (i, r) in rows.iter().take(MAX_ROWS_LOGGED).enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        out.push_str(&format!(
            "{}/{} via {} if={} metric={}",
            r.destination, r.prefix_length, r.next_hop, r.interface_index, r.metric
        ));
    }
    if rows.len() > MAX_ROWS_LOGGED {
        out.push_str(&format!(", …+{}", rows.len() - MAX_ROWS_LOGGED));
    }
    out
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    fn row(dest: &str, prefix: u8) -> Ipv6RouteRow {
        Ipv6RouteRow {
            destination: dest.parse().expect("v6 literal"),
            prefix_length: prefix,
            next_hop: Ipv6Addr::UNSPECIFIED,
            interface_index: 5,
            metric: 256,
        }
    }

    #[test]
    fn a_link_local_only_table_has_no_way_off_the_link() {
        // The shape of every machine we have looked at so far: link-local
        // addresses, multicast, loopback — and nothing that can leave.
        let rows = vec![
            row("::1", 128),
            row("fe80::", 64),
            row("fe80::bbe2:6463:b692:8283", 128),
            row("ff00::", 8),
        ];
        assert!(!has_global_route(&rows));
    }

    #[test]
    fn a_default_route_or_a_global_prefix_counts() {
        assert!(has_global_route(&[row("::", 0)]));
        assert!(has_global_route(&[row("2001:db8::", 32)]));
    }

    #[test]
    fn an_unchanged_table_is_logged_once() {
        let rows = vec![row("fe80::", 64)];
        let log = Ipv6RouteTableLog::new();
        assert!(
            log.log_rows_if_changed(&rows, "boot"),
            "first read always writes"
        );
        assert!(
            !log.log_rows_if_changed(&rows, "network-change"),
            "an unchanged table must not be written again"
        );
        let changed = vec![row("fe80::", 64), row("::", 0)];
        assert!(
            log.log_rows_if_changed(&changed, "network-change"),
            "a table that gained a default route is news"
        );
    }
}
