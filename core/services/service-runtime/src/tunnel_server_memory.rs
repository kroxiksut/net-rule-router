//! The tunnel servers this machine has seen, kept past a dropped tunnel and a
//! restart.
//!
//! While a tunnel is down nothing live names its server: the host route is
//! gone and so is the link. A blanket block armed then, or a network rule
//! routed over that server, would seal the reconnect that ends the outage. So
//! every server seen is remembered, and the memory answers until the tunnel
//! states it again.
//!
//! The store is the state database's `vpn_bootstrap_endpoints` table, written
//! and read through [`persistence_over`] by every platform — the route
//! coordinator takes the pair as its callbacks, [`TunnelServerMemory`] wraps
//! it for the platforms that plan without one.

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use crate::route_coordinator::{ServerIpLoaderFn, ServerIpPersistFn};

/// Servers held in memory. The store keeps the same number per source.
const MAX_REMEMBERED: usize = 32;

/// The write and read halves of the persisted server set, over one state
/// connection. A failed write is logged and dropped: the live set still
/// protects this run.
#[must_use]
pub fn persistence_over(
    conn: Arc<Mutex<rusqlite::Connection>>,
) -> (ServerIpPersistFn, ServerIpLoaderFn) {
    let load = persisted_servers(Arc::clone(&conn));
    let persist: ServerIpPersistFn = Arc::new(move |ips: &[Ipv4Addr]| {
        let guard = conn.lock().unwrap_or_else(|p| p.into_inner());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX));
        if let Err(e) =
            nrr_storage::vpn_bootstrap_endpoints::VpnBootstrapEndpointsRepository::new(&guard)
                .upsert_observed(ips, now)
        {
            tracing::warn!(
                target: "nrr::route-coordinator",
                msg_key = "svc-persid-vpn-bootstrap-persist-failed",
                error = %e,
                "failed to persist observed VPN bootstrap server IPs — continuing",
            );
        }
    });
    (persist, load)
}

/// The read half alone, for a reader that must see every write as it lands
/// (the network screen), not a copy held since the first read.
#[must_use]
pub fn persisted_servers(conn: Arc<Mutex<rusqlite::Connection>>) -> ServerIpLoaderFn {
    Arc::new(move || {
        let guard = conn.lock().unwrap_or_else(|p| p.into_inner());
        nrr_storage::vpn_bootstrap_endpoints::VpnBootstrapEndpointsRepository::new(&guard)
            .load_ips()
            .unwrap_or_default()
    })
}

/// Remembered servers for a planner without a route coordinator.
///
/// The persisted set is read once; afterwards the memory answers from what it
/// holds and writes only a server it has not held, so a steady pass costs no
/// storage at all.
pub struct TunnelServerMemory {
    persist: ServerIpPersistFn,
    load: ServerIpLoaderFn,
    /// Newest first. `None` until the persisted set has been read.
    held: Mutex<Option<Vec<Ipv4Addr>>>,
}

impl TunnelServerMemory {
    #[must_use]
    pub fn new(persist: ServerIpPersistFn, load: ServerIpLoaderFn) -> Self {
        Self {
            persist,
            load,
            held: Mutex::new(None),
        }
    }

    /// The memory over the state database.
    #[must_use]
    pub fn over_state_db(conn: Arc<Mutex<rusqlite::Connection>>) -> Self {
        let (persist, load) = persistence_over(conn);
        Self::new(persist, load)
    }

    /// Note the servers a pass saw live. Only ones not already held reach the
    /// store, outside the memory's lock.
    pub fn observe(&self, live: &[Ipv4Addr]) {
        if live.is_empty() {
            return;
        }
        let fresh = {
            let mut guard = self.held.lock().unwrap_or_else(|p| p.into_inner());
            let held = guard.get_or_insert_with(|| (self.load)());
            let mut fresh: Vec<Ipv4Addr> = Vec::new();
            for ip in live {
                if !held.contains(ip) && !fresh.contains(ip) {
                    fresh.push(*ip);
                }
            }
            if !fresh.is_empty() {
                let older = std::mem::replace(held, fresh.clone());
                held.extend(older);
                held.truncate(MAX_REMEMBERED);
            }
            fresh
        };
        if !fresh.is_empty() {
            (self.persist)(&fresh);
        }
    }

    /// Every server held: persisted by an earlier run, or seen since.
    #[must_use]
    pub fn remembered(&self) -> Vec<Ipv4Addr> {
        self.held
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get_or_insert_with(|| (self.load)())
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(last: u8) -> Ipv4Addr {
        Ipv4Addr::new(203, 0, 113, last)
    }

    type Writes = Arc<Mutex<Vec<Vec<Ipv4Addr>>>>;

    fn recording(persisted: Vec<Ipv4Addr>) -> (TunnelServerMemory, Writes, Arc<Mutex<usize>>) {
        let writes = Arc::new(Mutex::new(Vec::new()));
        let loads = Arc::new(Mutex::new(0));
        let (w, l) = (Arc::clone(&writes), Arc::clone(&loads));
        let memory = TunnelServerMemory::new(
            Arc::new(move |ips: &[Ipv4Addr]| w.lock().expect("lock").push(ips.to_vec())),
            Arc::new(move || {
                *l.lock().expect("lock") += 1;
                persisted.clone()
            }),
        );
        (memory, writes, loads)
    }

    #[test]
    fn the_persisted_set_is_read_once_and_answers_while_nothing_is_live() {
        let (memory, writes, loads) = recording(vec![ip(7)]);
        assert_eq!(memory.remembered(), vec![ip(7)]);
        assert_eq!(memory.remembered(), vec![ip(7)]);
        memory.observe(&[]);
        assert_eq!(*loads.lock().expect("lock"), 1);
        assert!(writes.lock().expect("lock").is_empty());
    }

    #[test]
    fn only_a_server_not_yet_held_is_written() {
        let (memory, writes, _) = recording(vec![ip(7)]);
        memory.observe(&[ip(7)]);
        memory.observe(&[ip(7), ip(9), ip(9)]);
        memory.observe(&[ip(9)]);
        assert_eq!(*writes.lock().expect("lock"), vec![vec![ip(9)]]);
        assert_eq!(memory.remembered(), vec![ip(9), ip(7)]);
    }

    #[test]
    fn the_memory_is_bounded_and_keeps_the_newest() {
        let (memory, _, _) = recording(Vec::new());
        for last in 0..=40u8 {
            memory.observe(&[ip(last)]);
        }
        let held = memory.remembered();
        assert_eq!(held.len(), MAX_REMEMBERED);
        assert_eq!(held.first(), Some(&ip(40)));
        assert!(!held.contains(&ip(0)));
    }

    /// Through the real table: what one run observes, the next one remembers.
    #[test]
    fn a_server_survives_a_restart_through_the_state_database() {
        use nrr_storage::{open_connection, repository::MigrationRunner, SqliteMigrationRunner};
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("nrr_service_state.db");
        let open = || {
            let runner = SqliteMigrationRunner::for_state_db(open_connection(&path).expect("open"));
            runner.run_pending_migrations().expect("migrate");
            Arc::new(Mutex::new(runner.into_connection()))
        };

        let first_run = TunnelServerMemory::over_state_db(open());
        first_run.observe(&[ip(7)]);
        drop(first_run);

        let next_run = TunnelServerMemory::over_state_db(open());
        assert_eq!(next_run.remembered(), vec![ip(7)]);
    }
}
