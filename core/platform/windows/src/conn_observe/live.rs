//! Windows [`LiveConnectionSource`]: the IPv4 and IPv6 TCP connection tables
//! with owning process ids, read the same way the flow owner and the
//! stale-flow reset read them, so there is one notion of "an established
//! connection".

#![allow(unsafe_code)]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use nrr_platform_api::conn_observe::live::{LiveConnection, LiveConnectionSource};
use windows::Win32::NetworkManagement::IpHelper::MIB_TCP_STATE_ESTAB;

use crate::flow_owner::read_tcp_owner_pid_table;

#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsLiveConnections;

impl WindowsLiveConnections {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl LiveConnectionSource for WindowsLiveConnections {
    fn established(&self) -> Vec<LiveConnection> {
        let mut rows: Vec<(u32, IpAddr)> = Vec::new();
        if let Some(buffer) = read_tcp_owner_pid_table() {
            for row in crate::flow_owner::tcp_rows(&buffer) {
                if row.dwState == MIB_TCP_STATE_ESTAB.0 as u32 {
                    rows.push((
                        row.dwOwningPid,
                        IpAddr::V4(Ipv4Addr::from(u32::from_be(row.dwRemoteAddr))),
                    ));
                }
            }
        }
        if let Some(buffer) = crate::flow_owner::read_tcp6_owner_pid_table() {
            for row in crate::flow_owner::tcp6_rows(&buffer) {
                if row.dwState == MIB_TCP_STATE_ESTAB.0 as u32 {
                    rows.push((
                        row.dwOwningPid,
                        IpAddr::V6(Ipv6Addr::from(row.ucRemoteAddr)),
                    ));
                }
            }
        }
        connections_of(
            rows,
            crate::app_path_resolver::image_name_for_pid,
            crate::win32_ffi::console_session::process_user_sid,
        )
    }
}

/// Listed connections with program and owner, each looked up once per process
/// in this pass. A protected process whose token cannot be read has no owner;
/// its connection is still listed.
fn connections_of(
    rows: Vec<(u32, IpAddr)>,
    name_of: impl Fn(u32) -> Option<String>,
    owner_of: impl Fn(u32) -> Option<String>,
) -> Vec<LiveConnection> {
    let mut seen: HashMap<u32, Option<(String, Option<String>)>> = HashMap::new();
    rows.into_iter()
        .map(|(pid, remote)| (pid, remote.to_canonical()))
        .filter(|(_, remote)| !remote.is_loopback() && !remote.is_unspecified())
        .filter_map(|(pid, remote)| {
            let (process_path, owner) = seen
                .entry(pid)
                .or_insert_with(|| name_of(pid).map(|name| (name, owner_of(pid))))
                .clone()?;
            Some(LiveConnection {
                process_path,
                remote,
                owner,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::net::TcpStream;

    #[test]
    fn each_connection_carries_its_processes_owner_looked_up_once() {
        use std::cell::Cell;
        let owner_calls = Cell::new(0);
        let remote = |d| IpAddr::V4(Ipv4Addr::new(203, 0, 113, d));
        let rows = vec![
            (10, remote(1)),
            (10, remote(2)),
            (11, remote(3)),
            (12, remote(4)),
        ];
        let out = connections_of(
            rows,
            |pid| (pid != 12).then(|| format!("p{pid}.exe")),
            |pid| {
                owner_calls.set(owner_calls.get() + 1);
                (pid == 10).then(|| "S-1-5-19".to_string())
            },
        );
        assert_eq!(out.len(), 3, "an unnamed program is left out");
        assert_eq!(out[0].owner.as_deref(), Some("S-1-5-19"));
        assert_eq!(out[1].owner.as_deref(), Some("S-1-5-19"));
        assert_eq!(
            out[2].owner, None,
            "an unreadable token leaves only that one unowned"
        );
        assert_eq!(out[2].process_path, "p11.exe");
        assert_eq!(
            owner_calls.get(),
            2,
            "one token read per named process, none for an unnamed one"
        );
    }

    /// A program's IPv6 connection is listed like its IPv4 one, and a
    /// dual-stack socket's v4-mapped peer as the IPv4 address the store keeps;
    /// a loopback peer in either spelling is not.
    #[test]
    fn an_ipv6_peer_is_listed_and_a_mapped_one_reads_as_ipv4() {
        let v6: IpAddr = "2001:db8::7".parse().expect("v6");
        let mapped: IpAddr = "::ffff:203.0.113.9".parse().expect("mapped");
        let rows = vec![
            (10, v6),
            (10, mapped),
            (10, IpAddr::V6(Ipv6Addr::LOCALHOST)),
            (10, "::ffff:127.0.0.1".parse().expect("mapped loopback")),
        ];
        let out = connections_of(rows, |_| Some("p.exe".to_string()), |_| None);
        let remotes: Vec<IpAddr> = out.iter().map(|c| c.remote).collect();
        assert_eq!(remotes, vec![v6, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))]);
    }

    /// A connection this test process holds must be listed under its own
    /// image name. Loopback is left out by design, so the check is that the
    /// read works and never names a loopback peer.
    #[test]
    fn the_table_reads_and_leaves_loopback_out() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
        let _client = TcpStream::connect(listener.local_addr().expect("addr")).expect("connect");
        let _server = listener.accept().expect("accept");
        let live = WindowsLiveConnections::new().established();
        assert!(live.iter().all(|c| !c.remote.is_loopback()));
        assert!(live.iter().all(|c| !c.process_path.is_empty()));
        assert!(
            live.iter().any(|c| c.owner.is_some()),
            "a readable process names its account"
        );
    }
}
