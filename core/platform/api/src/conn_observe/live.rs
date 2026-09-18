//! Outbound TCP connections that are open right now, with the program holding
//! each.
//!
//! The observation sources report a connection once, when it opens. A
//! destination an application rule learnt that way ages out after a fixed
//! window even while the program still holds the connection, and its route is
//! withdrawn from under a live session: a messenger keeping one connection for
//! hours loses it at the window's edge. Asking which connections are still
//! established lets the store keep exactly those destinations fresh, and no
//! others.

use std::net::Ipv4Addr;
use std::sync::Mutex;

/// One established outbound IPv4 TCP connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveConnection {
    /// The owning program, as a path or a file name.
    pub process_path: String,
    pub remote: Ipv4Addr,
}

pub trait LiveConnectionSource: Send + Sync {
    /// Connections established right now whose owning program is known. A
    /// connection whose owner cannot be named is left out: an address
    /// attributed to nobody refreshes nothing.
    fn established(&self) -> Vec<LiveConnection>;
}

/// A platform that cannot list its connections: nothing stays fresh on this
/// account, which is the behaviour without the port.
#[derive(Debug, Default)]
pub struct NoopLiveConnectionSource;

impl LiveConnectionSource for NoopLiveConnectionSource {
    fn established(&self) -> Vec<LiveConnection> {
        Vec::new()
    }
}

/// Test double whose answer can be changed between calls.
#[derive(Debug, Default)]
pub struct MockLiveConnectionSource {
    connections: Mutex<Vec<LiveConnection>>,
}

impl MockLiveConnectionSource {
    pub fn set(&self, connections: Vec<LiveConnection>) {
        *self.connections.lock().unwrap_or_else(|p| p.into_inner()) = connections;
    }
}

impl LiveConnectionSource for MockLiveConnectionSource {
    fn established(&self) -> Vec<LiveConnection> {
        self.connections
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }
}
