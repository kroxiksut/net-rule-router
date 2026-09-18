//! Windows [`LiveConnectionSource`]: the IPv4 TCP connection table with owning
//! process ids, read the same way the flow owner and the stale-flow reset read
//! it, so there is one notion of "an established connection".

#![allow(unsafe_code)]

use std::collections::HashMap;
use std::net::Ipv4Addr;

use nrr_platform_api::conn_observe::live::{LiveConnection, LiveConnectionSource};
use windows::Win32::NetworkManagement::IpHelper::{
    MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, MIB_TCP_STATE_ESTAB,
};

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
        let Some(buffer) = read_tcp_owner_pid_table() else {
            return Vec::new();
        };
        let mut rows: Vec<(u32, Ipv4Addr)> = Vec::new();
        // SAFETY: `read_tcp_owner_pid_table` fills the buffer with a valid
        // `MIB_TCPTABLE_OWNER_PID`; its `dwNumEntries` header is followed by that
        // many contiguous rows, and only those rows are read.
        unsafe {
            let table = buffer.as_ptr().cast::<MIB_TCPTABLE_OWNER_PID>();
            let count = (*table).dwNumEntries as usize;
            let first = std::ptr::addr_of!((*table).table).cast::<MIB_TCPROW_OWNER_PID>();
            for i in 0..count {
                let row = &*first.add(i);
                if row.dwState == MIB_TCP_STATE_ESTAB.0 as u32 {
                    rows.push((
                        row.dwOwningPid,
                        Ipv4Addr::from(u32::from_be(row.dwRemoteAddr)),
                    ));
                }
            }
        }
        let mut names: HashMap<u32, Option<String>> = HashMap::new();
        rows.into_iter()
            .filter(|(_, remote)| !remote.is_loopback() && !remote.is_unspecified())
            .filter_map(|(pid, remote)| {
                let name = names
                    .entry(pid)
                    .or_insert_with(|| crate::app_path_resolver::image_name_for_pid(pid))
                    .clone()?;
                Some(LiveConnection {
                    process_path: name,
                    remote,
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::net::TcpStream;

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
    }
}
