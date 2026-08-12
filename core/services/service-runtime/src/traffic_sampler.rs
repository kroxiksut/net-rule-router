//! Block T (traffic counter) — service-side sampler.
//!
//! Owns the [`TrafficAccountant`] and the [`SqliteTrafficStore`], and on each
//! supervisor tick: reads per-interface octet counters, buckets each interface
//! by route role via [`categorize`], folds the reset-aware deltas into both the
//! day's persisted ledger and the in-memory session totals, and persists the
//! resume-safe cursors.
//!
//! # Role mapping
//!
//! The current primary/secondary adapter **friendly names** (`RouteBindingRecord.
//! display_name`, which equals the `GetIfTable2` `Alias`) are passed into
//! [`tick`](TrafficSampler::tick); the sampler never re-derives them, keeping the
//! name-heal / route-binding concerns in the caller.
//!
//! # Concurrency
//!
//! Single-owner (`&mut self` for `tick`). The supervisor wraps the whole sampler
//! in an `Arc<Mutex<…>>` so the IPC handler's read methods
//! ([`today_totals`](TrafficSampler::today_totals) /
//! [`session_totals`](TrafficSampler::session_totals)) share the one SQLite
//! connection without a second handle.

use std::collections::HashMap;
use std::sync::Arc;

use nrr_domain::traffic_accountant::{
    categorize, tunnel_overlap_adjust, CountingToggles, InterfaceFacts, RoleAssignment,
    TrafficAccountant, TrafficCategory, TrafficSample,
};
use nrr_platform_api::{InterfaceCounterSource, InterfaceType};
use nrr_storage::{
    SqliteTrafficStore, StorageResult, TrafficCursorRow, TrafficDayRow, TrafficTotalRow,
};

/// Per-adapter session accumulator (since the additional adapter's current
/// session began).
#[derive(Clone, Debug)]
struct SessionEntry {
    display_name: String,
    category: TrafficCategory,
    in_bytes: u64,
    out_bytes: u64,
}

/// One row of session-scoped totals, for the "session" display period. A
/// session is the LIFETIME OF THE ADDITIONAL (secondary) ADAPTER, not of the
/// service: it starts from zero when the adapter comes up (comparable to the
/// numbers a VPN client shows for its own connection), freezes when the
/// adapter goes away, and restarts from zero on the next bring-up.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrafficSessionRow {
    pub adapter_key: String,
    pub display_name: String,
    /// `TrafficCategory` slug.
    pub role: String,
    pub in_bytes: u64,
    pub out_bytes: u64,
}

/// Drives the traffic ledger from live interface counters.
pub struct TrafficSampler {
    source: Arc<dyn InterfaceCounterSource>,
    store: SqliteTrafficStore,
    accountant: TrafficAccountant,
    session: HashMap<String, SessionEntry>,
    /// Whether the additional adapter is currently up — the session gate. Off
    /// means the session rows are a frozen snapshot of the last session (or
    /// empty when none happened yet).
    session_active: bool,
}

impl TrafficSampler {
    /// Builds a sampler, priming the accountant cursors from persisted state so
    /// accounting resumes across a service restart (capturing traffic during
    /// downtime when no adapter reset intervened).
    pub fn new(
        source: Arc<dyn InterfaceCounterSource>,
        store: SqliteTrafficStore,
    ) -> StorageResult<Self> {
        let mut accountant = TrafficAccountant::new();
        for c in store.all_cursors()? {
            accountant.prime(&c.adapter_key, c.last_in, c.last_out);
        }
        Ok(Self {
            source,
            store,
            accountant,
            session: HashMap::new(),
            session_active: false,
        })
    }

    /// One sampling tick. A counter-read failure is swallowed (skip the tick) so
    /// a transient platform error never tears down the supervisor loop.
    pub fn tick(
        &mut self,
        primary_name: Option<&str>,
        secondary_name: Option<&str>,
        toggles: CountingToggles,
        day: i64,
        now_ms: i64,
    ) -> StorageResult<()> {
        let counters = match self.source.read_counters() {
            Ok(c) => c,
            Err(_) => return Ok(()),
        };
        let roles = RoleAssignment {
            primary_name,
            secondary_name,
        };

        // Session edge detection: the "session" period is the additional
        // adapter's lifetime. Bring-up restarts the session ledger from zero
        // (comparable to a VPN client's own per-connection numbers); teardown
        // freezes it as the last session's snapshot.
        let secondary_present = secondary_name
            .is_some_and(|name| counters.iter().any(|c| c.stable_name == name && c.is_up));
        if secondary_present && !self.session_active {
            self.session.clear();
        }
        self.session_active = secondary_present;

        // Bucket each interface, capturing the display name alongside the sample.
        // Also remember whether THIS TICK's secondary is a tunnel — the
        // double-counting subtraction below is gated on it, not on a cached
        // assumption, since a role/adapter swap can change it tick to tick.
        let mut named_samples: Vec<(String, TrafficSample)> = Vec::new();
        let mut secondary_is_tunnel = false;
        for c in &counters {
            let facts = InterfaceFacts {
                stable_name: &c.stable_name,
                is_loopback: matches!(c.interface_type, InterfaceType::Loopback),
                is_tunnel: c.is_tunnel,
                is_virtual: c.is_virtual,
            };
            if secondary_name == Some(c.stable_name.as_str()) {
                secondary_is_tunnel = facts.is_tunnel;
            }
            let Some(category) = categorize(facts, roles, toggles) else {
                continue;
            };
            self.store
                .upsert_identity(&c.stable_name, &c.display_name, now_ms)?;
            named_samples.push((
                c.display_name.clone(),
                TrafficSample {
                    stable_name: c.stable_name.clone(),
                    category,
                    in_octets: c.in_octets,
                    out_octets: c.out_octets,
                },
            ));
        }

        let samples: Vec<TrafficSample> = named_samples.iter().map(|(_, s)| s.clone()).collect();
        let mut deltas = self.accountant.ingest(&samples);

        // Block T Feature 1 — eliminate tunnel double-counting: what counts
        // as VPN traffic must not also count in the primary channel. Only
        // meaningful when BOTH a primary and a (tunnel) secondary delta
        // landed THIS TICK; `tunnel_overlap_adjust` itself no-ops when the
        // secondary is not a tunnel (a genuine second physical adapter is
        // independent traffic, not encapsulated inside the primary's flow).
        // Applied here — before `accumulate`/session folding — so the day
        // ledger, session totals, all-time totals, and CSV export are all
        // automatically consistent with the adjusted primary numbers.
        if let Some((sec_in, sec_out)) = deltas
            .iter()
            .find(|d| d.category == TrafficCategory::Secondary)
            .map(|d| (d.in_delta, d.out_delta))
        {
            if let Some(pri) = deltas
                .iter_mut()
                .find(|d| d.category == TrafficCategory::Primary)
            {
                let (adj_in, adj_out) = tunnel_overlap_adjust(
                    pri.in_delta,
                    pri.out_delta,
                    sec_in,
                    sec_out,
                    secondary_is_tunnel,
                );
                pri.in_delta = adj_in;
                pri.out_delta = adj_out;
            }
        }

        self.store.accumulate(day, &deltas)?;

        // Session accumulation, carrying the display name. Gated on an active
        // session: with the additional adapter down the rows stay a frozen
        // snapshot instead of silently absorbing primary-only traffic.
        if self.session_active {
            for d in &deltas {
                let display = named_samples
                    .iter()
                    .find(|(_, s)| s.stable_name == d.stable_name)
                    .map(|(n, _)| n.clone())
                    .unwrap_or_else(|| d.stable_name.clone());
                let e = self
                    .session
                    .entry(d.stable_name.clone())
                    .or_insert(SessionEntry {
                        display_name: display.clone(),
                        category: d.category,
                        in_bytes: 0,
                        out_bytes: 0,
                    });
                e.display_name = display;
                e.category = d.category;
                e.in_bytes = e.in_bytes.saturating_add(d.in_delta);
                e.out_bytes = e.out_bytes.saturating_add(d.out_delta);
            }
        }

        // Persist resume-safe cursors for the adapters sampled this tick.
        let cursors: Vec<TrafficCursorRow> = samples
            .iter()
            .filter_map(|s| {
                self.accountant
                    .cursor(&s.stable_name)
                    .map(|(last_in, last_out)| TrafficCursorRow {
                        adapter_key: s.stable_name.clone(),
                        last_in,
                        last_out,
                    })
            })
            .collect();
        self.store.set_cursors(&cursors, now_ms)?;
        Ok(())
    }

    /// Persisted daily totals for `day` (the "today" display period).
    pub fn today_totals(&self, day: i64) -> StorageResult<Vec<TrafficDayRow>> {
        self.store.totals_for_day(day)
    }

    /// Whether an additional-adapter session is live right now. False means
    /// [`session_totals`](Self::session_totals) is the frozen snapshot of the
    /// last session, or empty when none happened since service start.
    pub fn session_active(&self) -> bool {
        self.session_active
    }

    /// In-memory totals for the current (or last) additional-adapter session,
    /// role/adapter-ordered.
    pub fn session_totals(&self) -> Vec<TrafficSessionRow> {
        let mut rows: Vec<TrafficSessionRow> = self
            .session
            .iter()
            .map(|(k, e)| TrafficSessionRow {
                adapter_key: k.clone(),
                display_name: e.display_name.clone(),
                role: e.category.slug().to_string(),
                in_bytes: e.in_bytes,
                out_bytes: e.out_bytes,
            })
            .collect();
        rows.sort_by(|a, b| a.role.cmp(&b.role).then(a.adapter_key.cmp(&b.adapter_key)));
        rows
    }

    /// All-time totals per adapter+role (bounded by the retention sweep) — the
    /// "grand total" context line next to the per-session display period.
    pub fn all_time_totals(&self) -> StorageResult<Vec<TrafficTotalRow>> {
        self.store.all_time_totals()
    }

    /// Ledger rows across an inclusive day range — feeds the CSV export.
    pub fn export_range(&self, from_day: i64, to_day: i64) -> StorageResult<Vec<TrafficDayRow>> {
        self.store.rows_in_range(from_day, to_day)
    }

    /// Retention sweep — drops daily rows older than `cutoff_day`.
    pub fn prune_before(&self, cutoff_day: i64) -> StorageResult<u64> {
        self.store.prune_before(cutoff_day)
    }

    /// Block T Feature 2 — records the last observed local + external address
    /// for an adapter. Write path from a USER-REQUESTED external-IP probe
    /// only (never from the routine sampling tick above); delegates straight
    /// to the store, sharing this sampler's single connection to
    /// `nrr_traffic_stats.db` rather than opening a second one.
    pub fn record_adapter_address(
        &self,
        adapter_key: &str,
        local_ip: &str,
        external_ip: &str,
        observed_at_ms: i64,
    ) -> StorageResult<()> {
        self.store
            .upsert_adapter_address(adapter_key, local_ip, Some(external_ip), observed_at_ms)
    }

    /// All persisted adapter address observations — feeds the
    /// `traffic-stats.get` response join.
    pub fn adapter_addresses(&self) -> StorageResult<Vec<nrr_storage::AdapterAddressRow>> {
        self.store.all_adapter_addresses()
    }

    /// Resets all traffic data (persisted ledger + session + cursors) on an
    /// explicit user "reset statistics" action.
    pub fn clear(&mut self) -> StorageResult<()> {
        self.session.clear();
        self.accountant = TrafficAccountant::new();
        self.store.clear()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_platform_api::{InterfaceCounters, MockInterfaceCounterSource};
    use nrr_storage::repository::MigrationRunner;
    use nrr_storage::{open_connection, SqliteMigrationRunner};

    fn counters(
        name: &str,
        itype: InterfaceType,
        is_virtual: bool,
        in_o: u64,
        out_o: u64,
    ) -> InterfaceCounters {
        InterfaceCounters {
            stable_name: name.to_string(),
            display_name: name.to_string(),
            interface_type: itype,
            is_virtual,
            // Mirrors the OLD (pre-strengthening) derivation these fixtures
            // were written against: the tests below only ever simulate a
            // tunnel via `InterfaceType::Tunnel`, never via a name/description
            // heuristic — that heuristic is unit-tested at the pure
            // `nrr_platform_api::adapters::text_indicates_vpn_tunnel` level.
            is_tunnel: matches!(itype, InterfaceType::Tunnel),
            is_up: true,
            in_octets: in_o,
            out_octets: out_o,
        }
    }

    fn open_store(dir: &tempfile::TempDir) -> SqliteTrafficStore {
        let path = dir.path().join("nrr_traffic_stats.db");
        let conn = open_connection(&path).expect("open");
        let runner = SqliteMigrationRunner::for_traffic_db(conn);
        runner.run_pending_migrations().expect("migrate");
        SqliteTrafficStore::new(runner.into_connection())
    }

    fn all_on() -> CountingToggles {
        CountingToggles {
            count_loopback: true,
            count_virtual: true,
        }
    }

    #[test]
    fn tick_buckets_by_role_and_persists() {
        let dir = tempfile::tempdir().expect("dir");
        let src = Arc::new(MockInterfaceCounterSource::new());
        let store = open_store(&dir);
        let mut sampler =
            TrafficSampler::new(Arc::clone(&src) as Arc<dyn InterfaceCounterSource>, store)
                .expect("new");

        // First tick primes cursors (no delta lands in the ledger).
        src.set(vec![
            counters("Ethernet", InterfaceType::Ethernet, false, 1000, 500),
            counters("WireGuard", InterfaceType::Tunnel, false, 200, 100),
        ]);
        sampler
            .tick(Some("Ethernet"), Some("WireGuard"), all_on(), 20000, 1)
            .expect("tick1");
        assert!(sampler.today_totals(20000).expect("t").is_empty());

        // Second tick lands deltas bucketed by role.
        src.set(vec![
            counters("Ethernet", InterfaceType::Ethernet, false, 1600, 800),
            counters("WireGuard", InterfaceType::Tunnel, false, 260, 130),
        ]);
        sampler
            .tick(Some("Ethernet"), Some("WireGuard"), all_on(), 20000, 2)
            .expect("tick2");

        let rows = sampler.today_totals(20000).expect("totals");
        let pri = rows.iter().find(|r| r.role == "primary").expect("pri");
        let sec = rows.iter().find(|r| r.role == "secondary").expect("sec");
        // Block T Feature 1 — WireGuard is a tunnel secondary, so its 60/30
        // delta is subtracted out of the primary's raw 600/300 delta before
        // it lands in the day ledger (its encrypted flow physically
        // re-appears on the Ethernet counter — see `tunnel_overlap_adjust`).
        assert_eq!((pri.in_bytes, pri.out_bytes), (540, 270));
        assert_eq!((sec.in_bytes, sec.out_bytes), (60, 30));
    }

    #[test]
    fn tick_does_not_subtract_a_physical_secondary() {
        // A second PHYSICAL NIC (not a VPN) — its traffic is genuinely
        // independent of the primary's, so no subtraction must apply even
        // though a secondary delta lands the same tick.
        let dir = tempfile::tempdir().expect("dir");
        let src = Arc::new(MockInterfaceCounterSource::new());
        let store = open_store(&dir);
        let mut sampler =
            TrafficSampler::new(Arc::clone(&src) as Arc<dyn InterfaceCounterSource>, store)
                .expect("new");

        src.set(vec![
            counters("Ethernet", InterfaceType::Ethernet, false, 1000, 500),
            counters("Ethernet 2", InterfaceType::Ethernet, false, 200, 100),
        ]);
        sampler
            .tick(Some("Ethernet"), Some("Ethernet 2"), all_on(), 1, 1)
            .expect("t1");
        src.set(vec![
            counters("Ethernet", InterfaceType::Ethernet, false, 1600, 800),
            counters("Ethernet 2", InterfaceType::Ethernet, false, 260, 130),
        ]);
        sampler
            .tick(Some("Ethernet"), Some("Ethernet 2"), all_on(), 1, 2)
            .expect("t2");

        let rows = sampler.today_totals(1).expect("totals");
        let pri = rows.iter().find(|r| r.role == "primary").expect("pri");
        let sec = rows.iter().find(|r| r.role == "secondary").expect("sec");
        assert_eq!(
            (pri.in_bytes, pri.out_bytes),
            (600, 300),
            "second physical adapter must not be subtracted from the primary"
        );
        assert_eq!((sec.in_bytes, sec.out_bytes), (60, 30));
    }

    #[test]
    fn tick_subtracts_by_the_facts_is_tunnel_flag_not_the_raw_interface_type() {
        // The strengthened classification: a real TAP-Windows adapter often
        // reports its raw MIB type as plain Ethernet (see
        // `nrr_platform_api::adapters::text_indicates_vpn_tunnel`), so the
        // gate must key off `InterfaceCounters::is_tunnel` — set directly
        // here, bypassing the `counters()` fixture's itype-derived default —
        // not off `interface_type` alone.
        let dir = tempfile::tempdir().expect("dir");
        let src = Arc::new(MockInterfaceCounterSource::new());
        let store = open_store(&dir);
        let mut sampler =
            TrafficSampler::new(Arc::clone(&src) as Arc<dyn InterfaceCounterSource>, store)
                .expect("new");

        fn tap_like(name: &str, in_o: u64, out_o: u64) -> InterfaceCounters {
            InterfaceCounters {
                stable_name: name.to_string(),
                display_name: name.to_string(),
                interface_type: InterfaceType::Ethernet, // raw type under-detects
                is_virtual: false,
                is_tunnel: true, // strengthened text-based classification caught it
                is_up: true,
                in_octets: in_o,
                out_octets: out_o,
            }
        }

        src.set(vec![
            counters("Ethernet", InterfaceType::Ethernet, false, 1000, 500),
            tap_like("TAP-Windows Adapter V9", 200, 100),
        ]);
        sampler
            .tick(
                Some("Ethernet"),
                Some("TAP-Windows Adapter V9"),
                all_on(),
                1,
                1,
            )
            .expect("t1");
        src.set(vec![
            counters("Ethernet", InterfaceType::Ethernet, false, 1600, 800),
            tap_like("TAP-Windows Adapter V9", 260, 130),
        ]);
        sampler
            .tick(
                Some("Ethernet"),
                Some("TAP-Windows Adapter V9"),
                all_on(),
                1,
                2,
            )
            .expect("t2");

        let rows = sampler.today_totals(1).expect("totals");
        let pri = rows.iter().find(|r| r.role == "primary").expect("pri");
        assert_eq!(
            (pri.in_bytes, pri.out_bytes),
            (540, 270),
            "a raw-Ethernet-typed but is_tunnel=true secondary must still trigger subtraction"
        );
    }

    #[test]
    fn session_stays_empty_without_the_additional_adapter() {
        let dir = tempfile::tempdir().expect("dir");
        let src = Arc::new(MockInterfaceCounterSource::new());
        let store = open_store(&dir);
        let mut sampler =
            TrafficSampler::new(Arc::clone(&src) as Arc<dyn InterfaceCounterSource>, store)
                .expect("new");

        src.set(vec![counters(
            "Ethernet",
            InterfaceType::Ethernet,
            false,
            0,
            0,
        )]);
        sampler
            .tick(Some("Ethernet"), None, all_on(), 1, 1)
            .expect("t1");
        src.set(vec![counters(
            "Ethernet",
            InterfaceType::Ethernet,
            false,
            250,
            90,
        )]);
        sampler
            .tick(Some("Ethernet"), None, all_on(), 1, 2)
            .expect("t2");

        assert!(!sampler.session_active());
        assert!(
            sampler.session_totals().is_empty(),
            "no additional adapter ever came up, so there is no session to show"
        );
        // The day ledger still counted the primary traffic.
        let rows = sampler.today_totals(1).expect("totals");
        assert_eq!(rows.len(), 1);
        assert_eq!((rows[0].in_bytes, rows[0].out_bytes), (250, 90));
    }

    #[test]
    fn session_tracks_the_additional_adapter_lifetime() {
        let dir = tempfile::tempdir().expect("dir");
        let src = Arc::new(MockInterfaceCounterSource::new());
        let store = open_store(&dir);
        let mut sampler =
            TrafficSampler::new(Arc::clone(&src) as Arc<dyn InterfaceCounterSource>, store)
                .expect("new");

        // Primary-only warm-up: counts into the day, not into any session.
        src.set(vec![counters(
            "Ethernet",
            InterfaceType::Ethernet,
            false,
            0,
            0,
        )]);
        sampler
            .tick(Some("Ethernet"), Some("WireGuard"), all_on(), 1, 1)
            .expect("t1");
        src.set(vec![counters(
            "Ethernet",
            InterfaceType::Ethernet,
            false,
            100,
            40,
        )]);
        sampler
            .tick(Some("Ethernet"), Some("WireGuard"), all_on(), 1, 2)
            .expect("t2");
        assert!(!sampler.session_active());
        assert!(sampler.session_totals().is_empty());

        // The additional adapter comes up: a session starts from zero and
        // counts BOTH roles from that moment.
        src.set(vec![
            counters("Ethernet", InterfaceType::Ethernet, false, 100, 40),
            counters("WireGuard", InterfaceType::Tunnel, false, 0, 0),
        ]);
        sampler
            .tick(Some("Ethernet"), Some("WireGuard"), all_on(), 1, 3)
            .expect("t3");
        // Block T Feature 1 — WireGuard is a tunnel secondary, so its delta is
        // subtracted from the primary's delta this tick (its encrypted flow
        // physically re-appears on the Ethernet counter — see
        // `tunnel_overlap_adjust`). Raw Ethernet reading is 560/230 above the
        // t3 cursor; after subtracting WireGuard's 500/200 the net primary
        // session delta is the small overhead residue, 60/30 — chosen so this
        // test's pre-existing assertions keep reading the same numbers while
        // now exercising the subtraction path end-to-end.
        src.set(vec![
            counters("Ethernet", InterfaceType::Ethernet, false, 660, 270),
            counters("WireGuard", InterfaceType::Tunnel, false, 500, 200),
        ]);
        sampler
            .tick(Some("Ethernet"), Some("WireGuard"), all_on(), 1, 4)
            .expect("t4");
        assert!(sampler.session_active());
        let s = sampler.session_totals();
        let pri = s.iter().find(|r| r.role == "primary").expect("primary");
        let sec = s.iter().find(|r| r.role == "secondary").expect("secondary");
        assert_eq!(
            (pri.in_bytes, pri.out_bytes),
            (60, 30),
            "primary session total is net of the tunnel-overlap subtraction"
        );
        assert_eq!((sec.in_bytes, sec.out_bytes), (500, 200));

        // Adapter goes away: the snapshot freezes, primary keeps flowing only
        // into the day ledger.
        src.set(vec![counters(
            "Ethernet",
            InterfaceType::Ethernet,
            false,
            700,
            300,
        )]);
        sampler
            .tick(Some("Ethernet"), Some("WireGuard"), all_on(), 1, 5)
            .expect("t5");
        assert!(!sampler.session_active());
        let frozen = sampler.session_totals();
        let pri = frozen.iter().find(|r| r.role == "primary").expect("pri");
        assert_eq!(
            (pri.in_bytes, pri.out_bytes),
            (60, 30),
            "session rows freeze when the adapter goes away"
        );

        // Next bring-up starts a NEW session from zero.
        src.set(vec![
            counters("Ethernet", InterfaceType::Ethernet, false, 700, 300),
            counters("WireGuard", InterfaceType::Tunnel, false, 10, 5),
        ]);
        sampler
            .tick(Some("Ethernet"), Some("WireGuard"), all_on(), 1, 6)
            .expect("t6");
        assert!(sampler.session_active());
        let s2 = sampler.session_totals();
        assert!(
            s2.iter().all(|r| r.in_bytes <= 10 && r.out_bytes <= 5),
            "new session restarts from zero: {s2:?}"
        );
    }

    #[test]
    fn toggles_off_exclude_loopback_and_virtual() {
        let dir = tempfile::tempdir().expect("dir");
        let src = Arc::new(MockInterfaceCounterSource::new());
        let store = open_store(&dir);
        let mut sampler =
            TrafficSampler::new(Arc::clone(&src) as Arc<dyn InterfaceCounterSource>, store)
                .expect("new");
        let off = CountingToggles {
            count_loopback: false,
            count_virtual: false,
        };
        src.set(vec![
            counters("Loopback", InterfaceType::Loopback, false, 10, 10),
            counters("Hyper-V", InterfaceType::Ethernet, true, 10, 10),
            counters("Ethernet", InterfaceType::Ethernet, false, 10, 10),
        ]);
        sampler.tick(Some("Ethernet"), None, off, 1, 1).expect("t1");
        src.set(vec![
            counters("Loopback", InterfaceType::Loopback, false, 500, 500),
            counters("Hyper-V", InterfaceType::Ethernet, true, 500, 500),
            counters("Ethernet", InterfaceType::Ethernet, false, 60, 30),
        ]);
        sampler.tick(Some("Ethernet"), None, off, 1, 2).expect("t2");

        let rows = sampler.today_totals(1).expect("totals");
        assert_eq!(rows.len(), 1, "only the primary is counted");
        assert_eq!(rows[0].role, "primary");
    }

    #[test]
    fn resume_primes_from_persisted_cursor() {
        let dir = tempfile::tempdir().expect("dir");
        let src = Arc::new(MockInterfaceCounterSource::new());

        // First sampler establishes a cursor at 1000/500.
        {
            let store = open_store(&dir);
            let mut sampler =
                TrafficSampler::new(Arc::clone(&src) as Arc<dyn InterfaceCounterSource>, store)
                    .expect("new");
            src.set(vec![counters(
                "Ethernet",
                InterfaceType::Ethernet,
                false,
                1000,
                500,
            )]);
            sampler
                .tick(Some("Ethernet"), None, all_on(), 5, 1)
                .expect("t1");
        }

        // A fresh sampler on the same DB resumes; the next reading's delta is
        // computed against the persisted cursor (captures "downtime" traffic).
        let path = dir.path().join("nrr_traffic_stats.db");
        let conn = open_connection(&path).expect("reopen");
        let store = SqliteTrafficStore::new(conn);
        let mut sampler =
            TrafficSampler::new(Arc::clone(&src) as Arc<dyn InterfaceCounterSource>, store)
                .expect("new2");
        src.set(vec![counters(
            "Ethernet",
            InterfaceType::Ethernet,
            false,
            1400,
            700,
        )]);
        sampler
            .tick(Some("Ethernet"), None, all_on(), 5, 2)
            .expect("t2");

        let rows = sampler.today_totals(5).expect("totals");
        assert_eq!(rows.len(), 1);
        assert_eq!((rows[0].in_bytes, rows[0].out_bytes), (400, 200));
    }

    #[test]
    fn role_swap_reattributes_going_forward() {
        let dir = tempfile::tempdir().expect("dir");
        let src = Arc::new(MockInterfaceCounterSource::new());
        let store = open_store(&dir);
        let mut sampler =
            TrafficSampler::new(Arc::clone(&src) as Arc<dyn InterfaceCounterSource>, store)
                .expect("new");

        src.set(vec![counters("Wg", InterfaceType::Tunnel, false, 0, 0)]);
        // Wg starts as secondary.
        sampler
            .tick(Some("Eth"), Some("Wg"), all_on(), 1, 1)
            .expect("t1");
        src.set(vec![counters("Wg", InterfaceType::Tunnel, false, 100, 100)]);
        sampler
            .tick(Some("Eth"), Some("Wg"), all_on(), 1, 2)
            .expect("t2");
        // Now Wg becomes primary (roles swapped).
        src.set(vec![counters("Wg", InterfaceType::Tunnel, false, 300, 100)]);
        sampler
            .tick(Some("Wg"), Some("Eth"), all_on(), 1, 3)
            .expect("t3");

        let rows = sampler.today_totals(1).expect("totals");
        let sec = rows.iter().find(|r| r.role == "secondary").expect("sec");
        let pri = rows.iter().find(|r| r.role == "primary").expect("pri");
        assert_eq!((sec.in_bytes, sec.out_bytes), (100, 100));
        assert_eq!((pri.in_bytes, pri.out_bytes), (200, 0));
    }

    #[test]
    fn record_and_read_adapter_addresses() {
        let dir = tempfile::tempdir().expect("dir");
        let src = Arc::new(MockInterfaceCounterSource::new());
        let store = open_store(&dir);
        let sampler =
            TrafficSampler::new(Arc::clone(&src) as Arc<dyn InterfaceCounterSource>, store)
                .expect("new");

        assert!(sampler.adapter_addresses().expect("empty").is_empty());
        sampler
            .record_adapter_address("Ethernet", "192.168.1.5", "203.0.113.7", 1000)
            .expect("record");
        let all = sampler.adapter_addresses().expect("all");
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].adapter_key, "Ethernet");
        assert_eq!(all[0].local_ip, "192.168.1.5");
        assert_eq!(all[0].external_ip.as_deref(), Some("203.0.113.7"));
    }

    #[test]
    fn clear_resets_everything() {
        let dir = tempfile::tempdir().expect("dir");
        let src = Arc::new(MockInterfaceCounterSource::new());
        let store = open_store(&dir);
        let mut sampler =
            TrafficSampler::new(Arc::clone(&src) as Arc<dyn InterfaceCounterSource>, store)
                .expect("new");
        src.set(vec![counters(
            "Ethernet",
            InterfaceType::Ethernet,
            false,
            0,
            0,
        )]);
        sampler
            .tick(Some("Ethernet"), None, all_on(), 1, 1)
            .expect("t1");
        src.set(vec![counters(
            "Ethernet",
            InterfaceType::Ethernet,
            false,
            100,
            40,
        )]);
        sampler
            .tick(Some("Ethernet"), None, all_on(), 1, 2)
            .expect("t2");

        sampler.clear().expect("clear");
        assert!(sampler.today_totals(1).expect("t").is_empty());
        assert!(sampler.session_totals().is_empty());
    }
}
