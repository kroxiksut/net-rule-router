//! One row per dropped connection where two sources describe it.
//!
//! A socket-table source lists a connection whose packets a filter drops as
//! one more open socket, verdict unknown, while the drop report names the same
//! connection with its verdict. Kept, the pair reads as two connections, one
//! of them apparently fine. The drop report wins and takes the program from
//! the socket row when it could not name one itself.

use std::collections::HashMap;
use std::net::SocketAddr;

use nrr_platform_api::conn_observe::{
    ConnectionObservation, ConnectionProgress, ConnectionVerdict, TransportProtocol,
};

/// How long a drop report still claims its connection's socket row. The
/// socket table is polled every few seconds and lists a socket once; a drop
/// report drained one poll ahead of its socket is the case this covers.
const PAIRING_WINDOW_MS: u64 = 30_000;
const MAX_REMEMBERED_DROPS: usize = 4096;

type FlowKey = (TransportProtocol, SocketAddr, SocketAddr);

#[derive(Default)]
pub(super) struct DropSocketPairing {
    /// Connections a drop report named recently, with when.
    recent_drops: HashMap<FlowKey, u64>,
}

fn key(obs: &ConnectionObservation) -> FlowKey {
    (obs.protocol, obs.local, obs.remote)
}

fn is_drop(obs: &ConnectionObservation) -> bool {
    obs.progress == ConnectionProgress::Attempt && obs.verdict == ConnectionVerdict::Block
}

fn is_socket_row(obs: &ConnectionObservation) -> bool {
    obs.progress == ConnectionProgress::Attempt && obs.verdict == ConnectionVerdict::Unknown
}

impl DropSocketPairing {
    /// `batch` with every socket row a drop report also names folded into
    /// that report, in the batch's order.
    pub(super) fn pair(
        &mut self,
        batch: &[ConnectionObservation],
        now_ms: u64,
    ) -> Vec<ConnectionObservation> {
        let fresh = |at: u64| now_ms.saturating_sub(at) < PAIRING_WINDOW_MS;
        if self.recent_drops.len() >= MAX_REMEMBERED_DROPS {
            self.recent_drops.retain(|_, at| fresh(*at));
            if self.recent_drops.len() >= MAX_REMEMBERED_DROPS {
                self.recent_drops.clear();
            }
        }
        let mut in_batch: HashMap<FlowKey, Option<&ConnectionObservation>> = HashMap::new();
        for obs in batch.iter().filter(|o| is_drop(o)) {
            in_batch.entry(key(obs)).or_insert(None);
        }
        for obs in batch.iter().filter(|o| is_socket_row(o)) {
            if let Some(slot) = in_batch.get_mut(&key(obs)) {
                if slot.is_none() {
                    *slot = Some(obs);
                }
            }
        }
        let mut out = Vec::with_capacity(batch.len());
        for obs in batch {
            let k = key(obs);
            if is_drop(obs) {
                self.recent_drops.insert(k, now_ms);
                let mut obs = obs.clone();
                if let Some(Some(socket)) = in_batch.get(&k) {
                    if obs.process_path.is_none() {
                        obs.process_path.clone_from(&socket.process_path);
                        obs.pid = socket.pid;
                    }
                    if obs.user_sid.is_none() {
                        obs.user_sid.clone_from(&socket.user_sid);
                    }
                }
                out.push(obs);
            } else {
                let claimed = is_socket_row(obs)
                    && (in_batch.contains_key(&k)
                        || self.recent_drops.get(&k).is_some_and(|at| fresh(*at)));
                if !claimed {
                    out.push(obs.clone());
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn row(verdict: ConnectionVerdict, remote_last: u8) -> ConnectionObservation {
        ConnectionObservation {
            pid: 0,
            process_path: None,
            user_sid: None,
            protocol: TransportProtocol::Tcp,
            local: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 40000),
            remote: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, remote_last)), 443),
            verdict,
            drop_filter_id: None,
            blocked_by_nrr: None,
            nrr_drop_spec_id: None,
            observed_unix_ms: None,
            progress: ConnectionProgress::Attempt,
        }
    }

    fn socket_row(remote_last: u8) -> ConnectionObservation {
        ConnectionObservation {
            pid: 42,
            process_path: Some("/usr/bin/browser".into()),
            user_sid: Some("uid:1000".into()),
            ..row(ConnectionVerdict::Unknown, remote_last)
        }
    }

    fn drop_row(remote_last: u8) -> ConnectionObservation {
        ConnectionObservation {
            blocked_by_nrr: Some(true),
            nrr_drop_spec_id: Some(7),
            ..row(ConnectionVerdict::Block, remote_last)
        }
    }

    #[test]
    fn a_socket_row_and_its_drop_become_one_drop_naming_the_program() {
        let mut pairing = DropSocketPairing::default();
        let out = pairing.pair(&[socket_row(1), drop_row(1), socket_row(2)], 1_000);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].verdict, ConnectionVerdict::Block);
        assert_eq!(out[0].process_path.as_deref(), Some("/usr/bin/browser"));
        assert_eq!(out[0].pid, 42);
        assert_eq!(out[0].user_sid.as_deref(), Some("uid:1000"));
        assert_eq!(out[1].remote, socket_row(2).remote);
    }

    #[test]
    fn a_drop_report_keeps_the_program_it_named_itself() {
        let mut pairing = DropSocketPairing::default();
        let mut drop = drop_row(1);
        drop.process_path = Some("/usr/bin/curl".into());
        drop.pid = 7;
        let out = pairing.pair(&[drop, socket_row(1)], 1_000);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].process_path.as_deref(), Some("/usr/bin/curl"));
        assert_eq!(out[0].pid, 7);
    }

    #[test]
    fn a_socket_row_one_drain_behind_its_drop_is_still_folded() {
        let mut pairing = DropSocketPairing::default();
        assert_eq!(pairing.pair(&[drop_row(1)], 1_000).len(), 1);
        assert!(pairing.pair(&[socket_row(1)], 3_000).is_empty());
        assert_eq!(
            pairing
                .pair(&[socket_row(1)], 1_000 + PAIRING_WINDOW_MS)
                .len(),
            1,
            "past the window it is a new connection on the same ports"
        );
    }

    #[test]
    fn rows_no_drop_names_pass_through_untouched() {
        let mut pairing = DropSocketPairing::default();
        let mut udp = socket_row(1);
        udp.protocol = TransportProtocol::Udp;
        let batch = [udp.clone(), drop_row(1)];
        let out = pairing.pair(&batch, 1_000);
        assert_eq!(out.len(), 2, "another protocol is another connection");
        assert_eq!(out[0], udp);
    }
}
