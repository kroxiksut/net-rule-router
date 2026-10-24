//! Connected UDP sockets to DNS upstreams, kept for reuse between forwarded
//! queries. A fresh socket per query cost bind + mark + connect on every DNS
//! request of the machine; a reply is matched by id and question anyway, so a
//! reused socket is safe against late answers to an earlier query.
//!
//! A socket comes back only after a matching reply: one that errored or timed
//! out is dropped. Short lifetime and use caps keep the source port moving and
//! bound how long a socket outlives a route change that would have picked
//! another source address.

use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

const MAX_IDLE_TOTAL: usize = 16;
const MAX_IDLE_PER_UPSTREAM: usize = 4;
const MAX_USES: u32 = 64;
const MAX_AGE: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct UpstreamKey {
    pub bind: Option<IpAddr>,
    pub server: SocketAddr,
}

struct Idle {
    key: UpstreamKey,
    sock: UdpSocket,
    born: Instant,
    uses: u32,
}

pub(crate) struct UpstreamSockets {
    idle: Mutex<Vec<Idle>>,
}

static SHARED: UpstreamSockets = UpstreamSockets::new();

/// The process-wide pool the listener and the resolver share.
pub(crate) fn shared() -> &'static UpstreamSockets {
    &SHARED
}

/// A socket on loan. Dropped without [`Lease::release`], it is closed.
pub(crate) struct Lease<'a> {
    pool: &'a UpstreamSockets,
    key: UpstreamKey,
    sock: UdpSocket,
    born: Instant,
    uses: u32,
}

impl Lease<'_> {
    pub(crate) fn socket(&self) -> &UdpSocket {
        &self.sock
    }

    /// The exchange got its reply: the socket may serve the next query.
    pub(crate) fn release(self) {
        self.pool.put_back(self, Instant::now());
    }
}

impl UpstreamSockets {
    pub(crate) const fn new() -> Self {
        Self {
            idle: Mutex::new(Vec::new()),
        }
    }

    /// An idle socket for `key`, or a new one from `open` (which binds,
    /// marks and connects it).
    pub(crate) fn checkout<E>(
        &self,
        key: UpstreamKey,
        open: impl FnOnce() -> Result<UdpSocket, E>,
    ) -> Result<Lease<'_>, E> {
        self.checkout_at(key, Instant::now(), open)
    }

    fn checkout_at<E>(
        &self,
        key: UpstreamKey,
        now: Instant,
        open: impl FnOnce() -> Result<UdpSocket, E>,
    ) -> Result<Lease<'_>, E> {
        let reused = {
            let mut idle = self.idle.lock().unwrap_or_else(PoisonError::into_inner);
            idle.retain(|entry| now.saturating_duration_since(entry.born) < MAX_AGE);
            idle.iter()
                .rposition(|entry| entry.key == key)
                .map(|at| idle.swap_remove(at))
        };
        if let Some(entry) = reused {
            return Ok(Lease {
                pool: self,
                key,
                sock: entry.sock,
                born: entry.born,
                uses: entry.uses,
            });
        }
        Ok(Lease {
            pool: self,
            key,
            sock: open()?,
            born: now,
            uses: 0,
        })
    }

    fn put_back(&self, lease: Lease<'_>, now: Instant) {
        let uses = lease.uses.saturating_add(1);
        if uses >= MAX_USES || now.saturating_duration_since(lease.born) >= MAX_AGE {
            return;
        }
        let mut idle = self.idle.lock().unwrap_or_else(PoisonError::into_inner);
        let same = idle.iter().filter(|entry| entry.key == lease.key).count();
        if same >= MAX_IDLE_PER_UPSTREAM || idle.len() >= MAX_IDLE_TOTAL {
            return;
        }
        idle.push(Idle {
            key: lease.key,
            sock: lease.sock,
            born: lease.born,
            uses,
        });
    }

    #[cfg(test)]
    fn idle_count(&self) -> usize {
        self.idle
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn key(port: u16) -> UpstreamKey {
        UpstreamKey {
            bind: None,
            server: SocketAddr::from(([127, 0, 0, 1], port)),
        }
    }

    fn open_counting(opened: &Cell<usize>) -> std::io::Result<UdpSocket> {
        opened.set(opened.get() + 1);
        UdpSocket::bind("127.0.0.1:0")
    }

    #[test]
    fn a_released_socket_serves_the_next_query_to_the_same_upstream() {
        let pool = UpstreamSockets::new();
        let opened = Cell::new(0);
        let first = pool
            .checkout(key(53), || open_counting(&opened))
            .expect("open");
        let port = first.socket().local_addr().expect("addr").port();
        first.release();
        let second = pool
            .checkout(key(53), || open_counting(&opened))
            .expect("reuse");
        assert_eq!(opened.get(), 1);
        assert_eq!(second.socket().local_addr().expect("addr").port(), port);
    }

    #[test]
    fn a_socket_dropped_after_an_error_is_never_handed_out_again() {
        let pool = UpstreamSockets::new();
        let opened = Cell::new(0);
        drop(
            pool.checkout(key(53), || open_counting(&opened))
                .expect("open"),
        );
        assert_eq!(pool.idle_count(), 0);
        let _again = pool
            .checkout(key(53), || open_counting(&opened))
            .expect("open");
        assert_eq!(opened.get(), 2);
    }

    #[test]
    fn another_upstream_or_source_never_gets_the_socket() {
        let pool = UpstreamSockets::new();
        let opened = Cell::new(0);
        pool.checkout(key(53), || open_counting(&opened))
            .expect("open")
            .release();
        let _other = pool
            .checkout(key(54), || open_counting(&opened))
            .expect("open");
        let bound = UpstreamKey {
            bind: Some(IpAddr::from([127, 0, 0, 1])),
            ..key(53)
        };
        let _bound = pool
            .checkout(bound, || open_counting(&opened))
            .expect("open");
        assert_eq!(opened.get(), 3);
        assert_eq!(pool.idle_count(), 1);
    }

    #[test]
    fn an_old_socket_is_retired_instead_of_reused() {
        let pool = UpstreamSockets::new();
        let opened = Cell::new(0);
        let start = Instant::now();
        pool.checkout_at(key(53), start, || open_counting(&opened))
            .expect("open")
            .release();
        let _fresh = pool
            .checkout_at(key(53), start + MAX_AGE, || open_counting(&opened))
            .expect("open");
        assert_eq!(opened.get(), 2);
        assert_eq!(pool.idle_count(), 0);
    }

    #[test]
    fn a_socket_retires_after_its_use_budget() {
        let pool = UpstreamSockets::new();
        let opened = Cell::new(0);
        let now = Instant::now();
        for _ in 0..MAX_USES {
            let lease = pool
                .checkout_at(key(53), now, || open_counting(&opened))
                .expect("lease");
            pool.put_back(lease, now);
        }
        assert_eq!(opened.get(), 1);
        assert_eq!(pool.idle_count(), 0);
    }

    #[test]
    fn idle_sockets_per_upstream_are_capped() {
        let pool = UpstreamSockets::new();
        let opened = Cell::new(0);
        let leases: Vec<_> = (0..MAX_IDLE_PER_UPSTREAM + 2)
            .map(|_| {
                pool.checkout(key(53), || open_counting(&opened))
                    .expect("open")
            })
            .collect();
        for lease in leases {
            lease.release();
        }
        assert_eq!(pool.idle_count(), MAX_IDLE_PER_UPSTREAM);
    }
}
