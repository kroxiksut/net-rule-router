//! The tunnel servers each user's links have shown, kept past a dropped tunnel
//! and a restart.
//!
//! While a tunnel is down nothing live names its server: the host route is
//! gone and so is the link. A blanket block armed then, or a network rule
//! routed over that server, would seal the reconnect that ends the outage. So
//! every server seen is remembered, and the memory answers until the tunnel
//! states it again. A server belongs to the user whose links showed it: one
//! user's tunnel must not open a hole in, or withdraw a route from, another
//! user's plan.
//!
//! The store is the state database's `vpn_bootstrap_endpoints` table.
//! [`TunnelServerMemory`] keeps it per user for the platforms that plan
//! per user; [`persistence_over`] is the machine-wide pair the Windows route
//! coordinator takes as its callbacks.

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use nrr_storage::vpn_bootstrap_endpoints::{VpnBootstrapEndpointsRepository, MACHINE_SCOPE};

use crate::route_coordinator::{ServerIpLoaderFn, ServerIpPersistFn};

/// Servers held in memory per user. The store keeps the same number per
/// owner and source.
const MAX_REMEMBERED: usize = 32;

/// Users whose servers the memory holds at once; the least recently added
/// gives way. Far above the people one machine serves.
const MAX_OWNERS: usize = 64;

/// Writes the servers one user's links showed.
pub type PrincipalServersPersistFn = Arc<dyn Fn(&str, &[Ipv4Addr]) + Send + Sync>;

/// Reads the servers remembered for one user.
pub type PrincipalServersLoadFn = Arc<dyn Fn(&str) -> Vec<Ipv4Addr> + Send + Sync>;

fn persist_for(conn: &Mutex<rusqlite::Connection>, sid: &str, ips: &[Ipv4Addr]) {
    let guard = conn.lock().unwrap_or_else(|p| p.into_inner());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX));
    if let Err(e) = VpnBootstrapEndpointsRepository::new(&guard).upsert_observed(sid, ips, now) {
        tracing::warn!(
            target: "nrr::route-coordinator",
            msg_key = "svc-persid-vpn-bootstrap-persist-failed",
            error = %e,
            "failed to persist observed VPN bootstrap server IPs — continuing",
        );
    }
}

fn load_for(conn: &Mutex<rusqlite::Connection>, sid: &str) -> Vec<Ipv4Addr> {
    let guard = conn.lock().unwrap_or_else(|p| p.into_inner());
    VpnBootstrapEndpointsRepository::new(&guard)
        .load_ips(sid)
        .unwrap_or_default()
}

/// The write and read halves of the machine-wide server set, over one state
/// connection. A failed write is logged and dropped: the live set still
/// protects this run.
#[must_use]
pub fn persistence_over(
    conn: Arc<Mutex<rusqlite::Connection>>,
) -> (ServerIpPersistFn, ServerIpLoaderFn) {
    let reader = Arc::clone(&conn);
    let persist: ServerIpPersistFn =
        Arc::new(move |ips: &[Ipv4Addr]| persist_for(&conn, MACHINE_SCOPE, ips));
    let load: ServerIpLoaderFn = Arc::new(move || load_for(&reader, MACHINE_SCOPE));
    (persist, load)
}

/// The read half alone, per user, for a reader that must see every write as
/// it lands (the network screen), not a copy held since the first read.
#[must_use]
pub fn persisted_servers_by_principal(
    conn: Arc<Mutex<rusqlite::Connection>>,
) -> PrincipalServersLoadFn {
    Arc::new(move |sid: &str| load_for(&conn, sid))
}

/// Remembered servers for a planner without a route coordinator, one set per
/// user.
///
/// A user's persisted set is read once; afterwards the memory answers from
/// what it holds and writes only a server it has not held, so a steady pass
/// costs no storage at all.
pub struct TunnelServerMemory {
    persist: PrincipalServersPersistFn,
    load: PrincipalServersLoadFn,
    /// Per user, newest first. A user is absent until first asked about.
    held: Mutex<Vec<(String, Vec<Ipv4Addr>)>>,
}

impl TunnelServerMemory {
    #[must_use]
    pub fn new(persist: PrincipalServersPersistFn, load: PrincipalServersLoadFn) -> Self {
        Self {
            persist,
            load,
            held: Mutex::new(Vec::new()),
        }
    }

    /// The memory over the state database.
    #[must_use]
    pub fn over_state_db(conn: Arc<Mutex<rusqlite::Connection>>) -> Self {
        let writer = Arc::clone(&conn);
        Self::new(
            Arc::new(move |sid: &str, ips: &[Ipv4Addr]| persist_for(&writer, sid, ips)),
            persisted_servers_by_principal(conn),
        )
    }

    /// `sid`'s held set, read from the store on first use. Past the owner cap
    /// the first-held owner gives way and is read again if it returns.
    fn set_of<'a>(
        &self,
        held: &'a mut Vec<(String, Vec<Ipv4Addr>)>,
        sid: &str,
    ) -> &'a mut Vec<Ipv4Addr> {
        if let Some(at) = held.iter().position(|(owner, _)| owner == sid) {
            return &mut held[at].1;
        }
        if held.len() >= MAX_OWNERS {
            held.remove(0);
        }
        held.push((sid.to_owned(), (self.load)(sid)));
        let last = held.len() - 1;
        &mut held[last].1
    }

    /// Note the servers a pass saw live on `sid`'s links. Only ones not
    /// already held reach the store, outside the memory's lock.
    pub fn observe(&self, sid: &str, live: &[Ipv4Addr]) {
        if live.is_empty() {
            return;
        }
        let fresh = {
            let mut guard = self.held.lock().unwrap_or_else(|p| p.into_inner());
            let held = self.set_of(&mut guard, sid);
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
            (self.persist)(sid, &fresh);
        }
    }

    /// Every server held for `sid`: persisted by an earlier run, or seen since.
    #[must_use]
    pub fn remembered(&self, sid: &str) -> Vec<Ipv4Addr> {
        let mut guard = self.held.lock().unwrap_or_else(|p| p.into_inner());
        self.set_of(&mut guard, sid).clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE: &str = "uid:1000";
    const BOB: &str = "uid:1001";

    fn ip(last: u8) -> Ipv4Addr {
        Ipv4Addr::new(203, 0, 113, last)
    }

    type Writes = Arc<Mutex<Vec<(String, Vec<Ipv4Addr>)>>>;

    fn recording(persisted: Vec<Ipv4Addr>) -> (TunnelServerMemory, Writes, Arc<Mutex<usize>>) {
        let writes: Writes = Arc::new(Mutex::new(Vec::new()));
        let loads = Arc::new(Mutex::new(0));
        let (w, l) = (Arc::clone(&writes), Arc::clone(&loads));
        let memory = TunnelServerMemory::new(
            Arc::new(move |sid: &str, ips: &[Ipv4Addr]| {
                w.lock().expect("lock").push((sid.to_owned(), ips.to_vec()));
            }),
            Arc::new(move |_: &str| {
                *l.lock().expect("lock") += 1;
                persisted.clone()
            }),
        );
        (memory, writes, loads)
    }

    #[test]
    fn the_persisted_set_is_read_once_and_answers_while_nothing_is_live() {
        let (memory, writes, loads) = recording(vec![ip(7)]);
        assert_eq!(memory.remembered(ALICE), vec![ip(7)]);
        assert_eq!(memory.remembered(ALICE), vec![ip(7)]);
        memory.observe(ALICE, &[]);
        assert_eq!(*loads.lock().expect("lock"), 1);
        assert!(writes.lock().expect("lock").is_empty());
    }

    #[test]
    fn only_a_server_not_yet_held_is_written() {
        let (memory, writes, _) = recording(vec![ip(7)]);
        memory.observe(ALICE, &[ip(7)]);
        memory.observe(ALICE, &[ip(7), ip(9), ip(9)]);
        memory.observe(ALICE, &[ip(9)]);
        assert_eq!(
            *writes.lock().expect("lock"),
            vec![(ALICE.to_owned(), vec![ip(9)])]
        );
        assert_eq!(memory.remembered(ALICE), vec![ip(9), ip(7)]);
    }

    #[test]
    fn the_memory_is_bounded_and_keeps_the_newest() {
        let (memory, _, _) = recording(Vec::new());
        for last in 0..=40u8 {
            memory.observe(ALICE, &[ip(last)]);
        }
        let held = memory.remembered(ALICE);
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
        first_run.observe(ALICE, &[ip(7)]);
        drop(first_run);

        let next_run = TunnelServerMemory::over_state_db(open());
        assert_eq!(next_run.remembered(ALICE), vec![ip(7)]);
    }

    /// One user's tunnel server is not another's: it would open a hole in
    /// their guard and withdraw routes the other user's rules need.
    #[test]
    fn a_users_server_is_not_remembered_for_another_user() {
        use nrr_storage::{open_connection, repository::MigrationRunner, SqliteMigrationRunner};
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("nrr_service_state.db");
        let open = || {
            let runner = SqliteMigrationRunner::for_state_db(open_connection(&path).expect("open"));
            runner.run_pending_migrations().expect("migrate");
            Arc::new(Mutex::new(runner.into_connection()))
        };

        let first_run = TunnelServerMemory::over_state_db(open());
        first_run.observe(ALICE, &[ip(7)]);
        assert!(first_run.remembered(BOB).is_empty());
        drop(first_run);

        let next_run = TunnelServerMemory::over_state_db(open());
        assert!(next_run.remembered(BOB).is_empty());
        assert_eq!(next_run.remembered(ALICE), vec![ip(7)]);
    }

    /// The Windows coordinator's pair keeps the machine-wide set, apart from
    /// every user's.
    #[test]
    fn the_machine_wide_pair_does_not_read_a_users_servers() {
        use nrr_storage::{open_connection, repository::MigrationRunner, SqliteMigrationRunner};
        let dir = tempfile::tempdir().expect("temp dir");
        let runner = SqliteMigrationRunner::for_state_db(
            open_connection(&dir.path().join("nrr_service_state.db")).expect("open"),
        );
        runner.run_pending_migrations().expect("migrate");
        let conn = Arc::new(Mutex::new(runner.into_connection()));

        TunnelServerMemory::over_state_db(Arc::clone(&conn)).observe(ALICE, &[ip(7)]);
        let (persist, load) = persistence_over(Arc::clone(&conn));
        assert!(load().is_empty());
        persist(&[ip(9)]);
        assert_eq!(load(), vec![ip(9)]);
        assert_eq!(persisted_servers_by_principal(conn)(ALICE), vec![ip(7)]);
    }
}
