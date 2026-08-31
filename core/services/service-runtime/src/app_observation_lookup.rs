//! App-routing via observation — narrow lookup port + in-memory
//! store, the application-rule analogue of [`crate::fqdn_cache_lookup`].
//!
//! ## Why
//!
//! An `Application` rule means "route everything this app connects to through
//! the additional adapter". We learn those destinations the same way the DNS
//! path learns a hostname's IPs — by observation. The connection observer
//! ([`nrr_platform_api::conn_observe`]) reports which remote IPs each
//! process connected to; [`crate::conn_observation_consumer`] records them
//! here, and [`crate::wfp_codegen`] reads them to emit one secondary `/32`
//! filter per observed IP — exactly the mechanism `ExactFqdn` rules use.
//!
//! ## In-memory by design (v1)
//!
//! Unlike the FQDN cache (persisted in SQLite), this store is in-memory:
//! observations rebuild as the app reconnects after a service restart —
//! the same warm-up the DNS cache has, so there is no schema/migration cost.
//! A persistent store is a later enhancement, not a correctness requirement.
//!
//! ## Matching
//!
//! Apps are keyed by the **lowercased file name** of the process image
//! (`C:\Program Files\…\chrome.exe` → `chrome.exe`). The rule's app pattern
//! (`chrome.exe`) is matched the same way. Glob patterns (`*vpn*.exe`) match
//! against every observed process name and union their IPs.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use crate::bounded_set::BoundedRecentSet;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex, OnceLock};

/// How recently an app's destination must have been SEEN to keep producing a
/// route and filters. The same window every other enforcement view uses
/// ([`crate::fqdn_cache_lookup::ENFORCEMENT_CONFIRMATION_WINDOW`]): the FQDN
/// side already ages its addresses through it, while an app-observed pin used
/// to stand until the LRU cap or a restart — a P2P session left its last peers
/// enforced for the life of the process. An address that ages out loses only
/// its own `/32`; the app touching it again relearns it within a tick (the
/// first contact drops on the per-app block, which is what teaches it).
pub const APP_PIN_FRESHNESS_WINDOW: Duration =
    crate::fqdn_cache_lookup::ENFORCEMENT_CONFIRMATION_WINDOW;

/// Max distinct IPs retained per app — bounds the codegen fan-out (mirrors
/// [`crate::wfp_codegen::PER_HOSTNAME_IP_CAP`] in spirit). A busy browser can
/// touch thousands of IPs; we keep the most-recently-observed up to this cap.
pub const APP_IP_CAP: usize = 256;

/// Destinations the census remembers, with the processes seen using them.
///
/// Deliberately NOT [`APP_IP_CAP`]: that one bounds how many host routes a rule
/// may fan out to, this one bounds *evidence*. A browser passes the route cap
/// long before it stops being worth knowing that it, too, uses an address — and
/// the whole point of the census is to answer for exactly such a process.
pub const CENSUS_IP_CAP: usize = 8192;

/// Distinct process names kept per destination. The census only ever answers
/// "is anybody here who is not one of these rules?", so a handful is enough and
/// an unbounded list would be a leak with no reader.
pub const CENSUS_KEYS_PER_IP: usize = 4;

/// How many withdrawn `(app, ip)` pairs are remembered. Bounded for the same
/// reason as everything else learned from traffic: a machine that runs for
/// weeks and keeps hitting new conflicts would otherwise grow this forever. Far
/// above any plausible number of live conflicts, so an eviction here means the
/// pair stopped being contested long ago.
pub const RETRACTED_CAP: usize = 4096;

/// Cap on the "seen since the last flush" ledger. A flush drains it, so this
/// only has to survive one interval; the bound is for the case where nothing
/// flushes at all (no application rules) and observations keep arriving.
pub const SEEN_SINCE_FLUSH_CAP: usize = 4096;

/// Narrow read-only port the WFP codegen consumes for `Application` rules.
///
/// `&self` so the port can be shared via `Arc` across threads; the codegen
/// issues one query per app rule.
pub trait AppObservationLookup: Send + Sync {
    /// Remote IPv4 addresses the process named `app` has been observed
    /// connecting to. `app` is matched case-insensitively against the
    /// observed process image's **file name**. Returns empty when nothing
    /// has been observed yet (cold start / observer off).
    fn ips_for_app(&self, app: &str) -> Vec<Ipv4Addr>;

    /// Has a process none of `friendly` names been seen using `ip`?
    ///
    /// A host route moves every process that talks to the address, so an
    /// application rule may only claim a destination nobody else is using.
    /// The default answers "nobody else" — an implementation without a census
    /// behaves exactly as before one existed.
    fn destination_used_outside(&self, _friendly: &[String], _ip: Ipv4Addr) -> bool {
        false
    }
}

/// File name of the running executable, lower-cased.
///
/// The relay dials an application's destinations over the tunnel on the
/// application's behalf, so this process appearing on an address is the
/// mechanism working, never somebody else using it. Both the census and the
/// collateral check read the same value from here.
pub fn own_process_key() -> &'static str {
    static OWN: OnceLock<String> = OnceLock::new();
    OWN.get_or_init(|| {
        std::env::current_exe()
            .ok()
            .map(|p| app_key(&p.to_string_lossy()))
            .unwrap_or_default()
    })
}

/// Reduce a process path or rule pattern to the one key both sides of a match
/// are compared on — see [`nrr_shared::app_identity::app_match_key`].
pub fn app_key(raw: &str) -> String {
    nrr_shared::app_identity::app_match_key(raw)
}

/// In-memory app→IP observation store. Shared via `Arc`: the observation
/// consumer writes through [`record`](Self::record); the codegen reads
/// through the [`AppObservationLookup`] impl.
pub struct AppObservationStore {
    inner: Mutex<HashMap<String, BoundedRecentSet<Ipv4Addr>>>,
    /// Who has been seen using each destination — the evidence a pin is
    /// weighed against before it is emitted.
    census: Mutex<CensusIndex>,
    /// `(app, ip)` pairs withdrawn because the host route they produced was
    /// carrying somebody else's traffic. Sticky, but bounded: the app will
    /// touch the address again within seconds, and without this the pair would
    /// be relearned immediately and the two processes would take the address
    /// from each other in a loop. Bounded because
    /// the app will touch the address again within seconds, and without this
    /// the pair would be relearned immediately and the two processes would take
    /// the address from each other in a loop.
    retracted: Mutex<BoundedRecentSet<(String, Ipv4Addr)>>,
    /// `(app, ip)` pairs actually seen since the last persistence pass. The
    /// store also holds addresses re-seeded from previous sessions and ones
    /// last used hours ago; persisting those again would stamp them as
    /// confirmed now, and the freshness window they are supposed to age out of
    /// would never expire.
    seen_since_flush: Mutex<BoundedRecentSet<(String, Ipv4Addr)>>,
    /// Last sighting per `(app, ip)` — what [`APP_PIN_FRESHNESS_WINDOW`] is
    /// measured against. Maintained alongside `inner`; a missing stamp is
    /// treated as fresh (unknown age fails toward protection) and restamped.
    last_seen: Mutex<HashMap<(String, Ipv4Addr), Instant>>,
    pin_ttl: Duration,
    clock: Arc<dyn Fn() -> Instant + Send + Sync>,
    cap_per_app: usize,
}

impl Default for AppObservationStore {
    fn default() -> Self {
        Self::with_cap(APP_IP_CAP)
    }
}

impl AppObservationStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_cap(cap_per_app: usize) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            census: Mutex::new(CensusIndex::default()),
            retracted: Mutex::new(BoundedRecentSet::new(RETRACTED_CAP)),
            seen_since_flush: Mutex::new(BoundedRecentSet::new(SEEN_SINCE_FLUSH_CAP)),
            last_seen: Mutex::new(HashMap::new()),
            pin_ttl: APP_PIN_FRESHNESS_WINDOW,
            clock: Arc::new(Instant::now),
            cap_per_app,
        }
    }

    /// Override the freshness window. Builder-style; production keeps the
    /// shared [`APP_PIN_FRESHNESS_WINDOW`] default.
    pub fn with_pin_ttl(mut self, ttl: Duration) -> Self {
        self.pin_ttl = ttl;
        self
    }

    /// Replace the clock, so a test can cross the freshness window without
    /// sleeping. Always compiled (test_support style); no production caller.
    pub fn with_clock(mut self, clock: Arc<dyn Fn() -> Instant + Send + Sync>) -> Self {
        self.clock = clock;
        self
    }

    /// Record that `process_path` connected to `ip`. No-op for non-routable
    /// IPs (loopback / unspecified / link-local) — they are never routed and
    /// would only pollute the set. At the per-app cap the least recently seen
    /// address gives way, so an app that migrates to new destinations gets them
    /// routed instead of being frozen on its first 256.
    /// Returns `true` when `ip` was **newly** observed for this app — the
    /// caller uses that to trigger a route recompute so the new destination is
    /// routed promptly.
    /// Take the destinations of `app_pattern` seen since the previous call.
    /// Draining is the point: a destination reported once must not be reported
    /// as freshly confirmed on every later pass.
    pub fn take_seen_since_flush(&self, app_pattern: &str) -> std::collections::HashSet<Ipv4Addr> {
        if app_key(app_pattern).is_empty() {
            return std::collections::HashSet::new();
        }
        let mut ledger = self
            .seen_since_flush
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        // `pattern_matches`, not string equality: a glob rule covers every
        // process it names, exactly as `ips_for_app` unions them.
        let mine: Vec<(String, Ipv4Addr)> = ledger
            .iter()
            .filter(|(app, _)| pattern_matches(app_pattern, app))
            .cloned()
            .collect();
        for pair in &mine {
            ledger.remove(pair);
        }
        mine.into_iter().map(|(_, ip)| ip).collect()
    }

    pub fn record(&self, process_path: &str, ip: Ipv4Addr) -> bool {
        if is_unroutable(ip) {
            return false;
        }
        let key = app_key(process_path);
        if key.is_empty() {
            return false;
        }
        if self
            .retracted
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .contains(&(key.clone(), ip))
        {
            return false;
        }
        let seen = {
            let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            let set = g
                .entry(key.clone())
                .or_insert_with(|| BoundedRecentSet::new(self.cap_per_app));
            set.observe(ip)
        };
        {
            let mut stamps = self.last_seen.lock().unwrap_or_else(|p| p.into_inner());
            stamps.insert((key.clone(), ip), (self.clock)());
            if let Some(old) = seen.evicted {
                stamps.remove(&(key.clone(), old));
            }
        }
        self.seen_since_flush
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .observe((key, ip));
        if let Some(old) = seen.evicted {
            tracing::debug!(
                target: "nrr::app-observations",
                evicted = %old,
                admitted = %ip,
                "per-app destination cap reached; the least recently seen address gave way",
            );
        }
        seen.is_new
    }

    /// Pre-load `pairs` (rule app pattern → destination) carried over from an
    /// earlier session, returning how many were admitted.
    ///
    /// Identical admission rules to [`record`](Self::record) — unroutable
    /// addresses and a full per-app set are rejected the same way — so a
    /// pre-loaded destination is indistinguishable from one this session
    /// observed. The point of pre-loading is precisely that: an application the
    /// rule book routes over the additional link can only be put on that link by
    /// a host route derived from a known destination, so without this the app's
    /// first contact with every address is refused once per session while the
    /// observation catches up.
    ///
    /// Keys are the rule's own app pattern, which is exactly what
    /// [`ips_for_app`](AppObservationLookup::ips_for_app) is later queried with,
    /// so the set round-trips without re-deriving anything.
    pub fn seed_many(&self, pairs: &[(String, Ipv4Addr)]) -> usize {
        pairs
            .iter()
            .filter(|(app, ip)| self.record(app, *ip))
            .count()
    }

    /// Which applications have `ip` in their observed set.
    ///
    /// The reverse of [`ips_for_app`](AppObservationLookup::ips_for_app), and
    /// the question the collateral check asks: a host route derived from this
    /// address moves EVERY process, so when a different process is seen using
    /// it, the owner has to be named before the pin can be withdrawn. Cheap —
    /// the map holds one entry per application a rule names.
    #[must_use]
    pub fn apps_for_ip(&self, ip: Ipv4Addr) -> Vec<String> {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .filter(|(_, ips)| ips.contains(&ip))
            .map(|(app, _)| app.clone())
            .collect()
    }

    /// Withdraw `ip` from `app`'s observed set and refuse to learn it again
    /// this session. Returns `true` when the pair was actually present.
    ///
    /// The route this address produced is machine-wide; the moment it is seen
    /// moving a process the rule never named, it is doing more harm than the
    /// rule is worth. The application loses the destination — its own traffic
    /// there falls back to the main link — which is the lesser cost: an
    /// application rule may not quietly overrule where everything else goes.
    pub fn retract(&self, app: &str, ip: Ipv4Addr) -> bool {
        let key = app_key(app);
        if key.is_empty() {
            return false;
        }
        let removed = self
            .inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get_mut(&key)
            .is_some_and(|set| set.remove(&ip));
        self.last_seen
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&(key.clone(), ip));
        self.retracted
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .observe((key, ip));
        removed
    }

    /// Note that `process_path` was seen talking to `ip`.
    ///
    /// Separate from [`record`](Self::record) on purpose, and fed only from
    /// live observation: `record` is also called by the cross-session warm load
    /// with RULE PATTERNS as keys, and a pattern is not a process — letting one
    /// into the census would have a rule vouching for itself.
    pub fn note_process_destination(&self, process_path: &str, ip: Ipv4Addr) {
        if is_unroutable(ip) {
            return;
        }
        let key = app_key(process_path);
        if key.is_empty() || key == own_process_key() {
            return;
        }
        let mut g = self.census.lock().unwrap_or_else(|p| p.into_inner());
        match g.seen.get_mut(&ip) {
            Some(keys) => {
                if keys.len() < CENSUS_KEYS_PER_IP && !keys.iter().any(|k| k == &key) {
                    keys.push(key);
                }
            }
            None => {
                g.seen.insert(ip, vec![key]);
                g.order.push_back(ip);
                while g.order.len() > CENSUS_IP_CAP {
                    if let Some(evicted) = g.order.pop_front() {
                        g.seen.remove(&evicted);
                    }
                }
            }
        }
    }

    /// Has a process that none of `friendly` names been seen using `ip`?
    ///
    /// `friendly` is every application pattern the rule set routes over the
    /// additional link, not just the rule being compiled: two applications may
    /// legitimately share a destination, and a route serves them both the same
    /// way, so that is not collateral.
    ///
    /// `false` when nothing is known about the address. An unobserved address
    /// is not evidence of exclusivity — it is the absence of evidence, and the
    /// withdrawal path covers the case where the other process shows up later.
    #[must_use]
    pub fn destination_used_outside(&self, friendly: &[String], ip: Ipv4Addr) -> bool {
        let g = self.census.lock().unwrap_or_else(|p| p.into_inner());
        let Some(keys) = g.seen.get(&ip) else {
            return false;
        };
        keys.iter().any(|seen| {
            !friendly
                .iter()
                .any(|pattern| pattern_matches(pattern, seen))
        })
    }

    /// Number of apps with at least one observation (diagnostics / tests).
    pub fn app_count(&self) -> usize {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    /// Drop `name`'s entries whose last sighting fell outside the freshness
    /// window. An entry with no stamp is restamped now — unknown age fails
    /// toward protection, mirroring the FQDN cache's rule. Lock order is
    /// `inner` → `last_seen`, the only place both are held together.
    fn prune_stale(&self, g: &mut HashMap<String, BoundedRecentSet<Ipv4Addr>>, name: &str) {
        let now = (self.clock)();
        let Some(cutoff) = now.checked_sub(self.pin_ttl) else {
            return;
        };
        let Some(set) = g.get_mut(name) else {
            return;
        };
        let mut stamps = self.last_seen.lock().unwrap_or_else(|p| p.into_inner());
        let mut stale: Vec<Ipv4Addr> = Vec::new();
        for ip in set.iter() {
            match stamps.get(&(name.to_string(), *ip)) {
                Some(t) if *t < cutoff => stale.push(*ip),
                Some(_) => {}
                None => {
                    stamps.insert((name.to_string(), *ip), now);
                }
            }
        }
        for ip in stale {
            set.remove(&ip);
            stamps.remove(&(name.to_string(), ip));
            tracing::debug!(
                target: "nrr::app-observations",
                app = name,
                destination = %ip,
                "destination aged out of the freshness window — its route and pin lapse with it",
            );
        }
    }
}

/// Destinations mapped to the processes seen using them, FIFO-bounded.
#[derive(Default)]
struct CensusIndex {
    seen: HashMap<Ipv4Addr, Vec<String>>,
    /// Insertion order, so the bound evicts the oldest destination in O(1)
    /// instead of scanning for a victim.
    order: VecDeque<Ipv4Addr>,
}

impl AppObservationLookup for AppObservationStore {
    fn ips_for_app(&self, app: &str) -> Vec<Ipv4Addr> {
        let key = app_key(app);
        if key.is_empty() {
            return Vec::new();
        }
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        // Glob pattern (e.g. `*vpn*.exe`) → union the IPs of every observed
        // process whose name matches; exact name → a single lookup. Stale
        // sightings are pruned first, so what enforcement reads is only what
        // was seen inside the freshness window.
        let mut v: Vec<Ipv4Addr> = if key.contains('*') {
            let names: Vec<String> = g
                .keys()
                .filter(|name| glob_match(&key, name))
                .cloned()
                .collect();
            let mut set: HashSet<Ipv4Addr> = HashSet::new();
            for name in names {
                self.prune_stale(&mut g, &name);
                if let Some(ips) = g.get(&name) {
                    set.extend(ips.iter().copied());
                }
            }
            set.into_iter().collect()
        } else {
            self.prune_stale(&mut g, &key);
            match g.get(&key) {
                Some(set) => set.iter().copied().collect(),
                None => Vec::new(),
            }
        };
        // Deterministic order so codegen filter ids/weights are stable across
        // applies for the same observed set.
        v.sort();
        v
    }

    fn destination_used_outside(&self, friendly: &[String], ip: Ipv4Addr) -> bool {
        AppObservationStore::destination_used_outside(self, friendly, ip)
    }
}

/// Does the rule pattern `pattern` name the observed process `key`?
///
/// The one place this question is answered, so the census, the collateral check
/// and the codegen cannot drift into disagreeing about what a rule covers.
#[must_use]
pub fn pattern_matches(pattern: &str, key: &str) -> bool {
    let p = app_key(pattern);
    if p.contains('*') {
        glob_match(&p, key)
    } else {
        p == key
    }
}

/// Minimal glob match: `*` matches any (possibly empty) run of characters; no
/// other metacharacters. Both sides are already lowercased file names.
fn glob_match(pattern: &str, name: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == name; // no wildcard
    }
    // First segment is an anchored prefix.
    let Some(mut rest) = name.strip_prefix(parts[0]) else {
        return false;
    };
    let last_idx = parts.len() - 1;
    for (i, seg) in parts.iter().enumerate().skip(1) {
        if seg.is_empty() {
            continue;
        }
        if i == last_idx {
            // Final segment is an anchored suffix of what remains.
            if !rest.ends_with(seg) {
                return false;
            }
        } else {
            match rest.find(seg) {
                Some(idx) => rest = &rest[idx + seg.len()..],
                None => return false,
            }
        }
    }
    true
}

/// Process-wide singleton observation store.
///
/// The connection-observation consumer (writer) and the per-SID apply
/// orchestrator (reader) live in different runtime build functions and would
/// otherwise need the store threaded through several layers. The service is a
/// single process and the observed app→IP map is process-global state, so a
/// `OnceLock` singleton is the pragmatic wiring: both sides call
/// [`global_app_observations`] and share one store. Tests construct
/// [`AppObservationStore`] / [`MockAppObservationLookup`] directly and never
/// touch this global, so it stays clean under `cargo test`.
static GLOBAL_APP_OBSERVATIONS: OnceLock<Arc<AppObservationStore>> = OnceLock::new();

/// The process-wide observed app→IP store. First call creates it; later calls
/// return the same `Arc`.
pub fn global_app_observations() -> Arc<AppObservationStore> {
    GLOBAL_APP_OBSERVATIONS
        .get_or_init(|| Arc::new(AppObservationStore::new()))
        .clone()
}

/// IPs the kill-switch / routing must never touch — loopback, unspecified,
/// link-local, broadcast. Mirrors the codegen's exemption intent. The fake-IP
/// pool is equally out: a virtual address observed as an app's destination is
/// our own TUN terminating the flow, and mirroring it as a per-IP route/filter
/// would steer pool traffic onto a physical adapter, away from the TUN.
fn is_unroutable(ip: Ipv4Addr) -> bool {
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_multicast()
        || nrr_platform_api::fake_ip::FakeIpPoolConfig::is_default_pool_addr(std::net::IpAddr::V4(
            ip,
        ))
}

/// Test-only [`AppObservationLookup`] backed by a pre-canned map. Always
/// compiled (not `#[cfg(test)]`) so other crates' tests share the fixture.
#[derive(Default)]
pub struct MockAppObservationLookup {
    inner: Mutex<HashMap<String, Vec<Ipv4Addr>>>,
    /// Destinations the test declares to be in use by somebody the rule set
    /// does not name.
    used_outside: Mutex<HashSet<Ipv4Addr>>,
}

#[allow(clippy::unwrap_used)]
impl MockAppObservationLookup {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `ips` as the observed set for `app`. Last write wins.
    pub fn set_ips(&self, app: &str, ips: Vec<Ipv4Addr>) {
        self.inner.lock().unwrap().insert(app_key(app), ips);
    }

    /// Declare `ip` to be in use by a process no application rule names.
    pub fn set_used_outside(&self, ip: Ipv4Addr) {
        self.used_outside.lock().unwrap().insert(ip);
    }
}

#[allow(clippy::unwrap_used)]
impl AppObservationLookup for MockAppObservationLookup {
    fn ips_for_app(&self, app: &str) -> Vec<Ipv4Addr> {
        self.inner
            .lock()
            .unwrap()
            .get(&app_key(app))
            .cloned()
            .unwrap_or_default()
    }

    fn destination_used_outside(&self, _friendly: &[String], ip: Ipv4Addr) -> bool {
        self.used_outside.lock().unwrap().contains(&ip)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    fn addr(last: u8) -> Ipv4Addr {
        Ipv4Addr::new(203, 0, 113, last)
    }

    fn friendly(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn an_address_nobody_has_been_seen_using_is_not_shared() {
        // Absence of evidence is not evidence of company: an unobserved
        // address still gets its route, and the withdrawal path covers the
        // case where somebody turns up later.
        let store = AppObservationStore::new();
        assert!(!store.destination_used_outside(&friendly(&["assistant.exe"]), addr(10)));
    }

    #[test]
    fn a_process_no_rule_names_makes_a_destination_shared() {
        let store = AppObservationStore::new();
        store.note_process_destination(r"C:\Program Files\Chrome\chrome.exe", addr(10));
        assert!(store.destination_used_outside(&friendly(&["assistant.exe"]), addr(10)));
    }

    #[test]
    fn two_routed_applications_may_share_a_destination() {
        // A route serves both the same way, so this is not collateral.
        let store = AppObservationStore::new();
        store.note_process_destination("assistant.exe", addr(10));
        store.note_process_destination("claude.exe", addr(10));
        assert!(
            !store.destination_used_outside(&friendly(&["assistant.exe", "claude.exe"]), addr(10))
        );
        // …but a third, unnamed one does make it shared.
        store.note_process_destination("chrome.exe", addr(10));
        assert!(
            store.destination_used_outside(&friendly(&["assistant.exe", "claude.exe"]), addr(10))
        );
    }

    #[test]
    fn a_glob_rule_vouches_for_every_process_it_matches() {
        let store = AppObservationStore::new();
        store.note_process_destination("codex.exe", addr(10));
        store.note_process_destination("codex-helper.exe", addr(10));
        assert!(!store.destination_used_outside(&friendly(&["codex*.exe"]), addr(10)));
    }

    #[test]
    fn our_own_process_is_never_somebody_else() {
        // The relay dials an application's destinations over the tunnel on its
        // behalf; counting that would withdraw every pin the moment it worked.
        let store = AppObservationStore::new();
        store.note_process_destination(own_process_key(), addr(10));
        assert!(!store.destination_used_outside(&friendly(&["assistant.exe"]), addr(10)));
    }

    #[test]
    fn the_census_is_bounded_and_drops_the_oldest_destination() {
        let store = AppObservationStore::new();
        let ip_of = |n: u32| Ipv4Addr::from(0x0b00_0000u32 + n);
        for n in 0..(CENSUS_IP_CAP as u32 + 1) {
            store.note_process_destination("chrome.exe", ip_of(n));
        }
        // The first one was evicted; the newest survived.
        assert!(!store.destination_used_outside(&friendly(&["assistant.exe"]), ip_of(0)));
        assert!(store
            .destination_used_outside(&friendly(&["assistant.exe"]), ip_of(CENSUS_IP_CAP as u32)));
    }

    #[test]
    fn names_kept_per_destination_are_bounded() {
        let store = AppObservationStore::new();
        for n in 0..(CENSUS_KEYS_PER_IP + 3) {
            store.note_process_destination(&format!("proc{n}.exe"), addr(10));
        }
        // Still answers, and the answer is still "somebody else".
        assert!(store.destination_used_outside(&friendly(&["assistant.exe"]), addr(10)));
    }

    #[test]
    fn unroutable_destinations_never_enter_the_census() {
        let store = AppObservationStore::new();
        let loopback = Ipv4Addr::new(127, 0, 0, 1);
        store.note_process_destination("chrome.exe", loopback);
        assert!(!store.destination_used_outside(&friendly(&["assistant.exe"]), loopback));
    }

    #[test]
    fn apps_for_ip_names_every_owner_of_a_destination() {
        let store = AppObservationStore::new();
        store.record(r"C:\apps\alpha.exe", addr(10));
        store.record("beta.exe", addr(10));
        store.record("beta.exe", addr(11));

        let mut owners = store.apps_for_ip(addr(10));
        owners.sort();
        assert_eq!(owners, vec!["alpha".to_string(), "beta".to_string()]);
        assert_eq!(store.apps_for_ip(addr(11)), vec!["beta".to_string()]);
        assert!(store.apps_for_ip(addr(12)).is_empty());
    }

    #[test]
    fn a_retracted_destination_is_dropped_and_never_relearned() {
        let store = AppObservationStore::new();
        store.record("alpha.exe", addr(10));
        store.record("alpha.exe", addr(11));

        assert!(store.retract("alpha.exe", addr(10)));
        assert_eq!(store.ips_for_app("alpha.exe"), vec![addr(11)]);

        // The application keeps using the address; the pin must not come back.
        assert!(!store.record("alpha.exe", addr(10)));
        assert_eq!(store.ips_for_app("alpha.exe"), vec![addr(11)]);
        // Nor may the cross-session warm load reintroduce it.
        assert_eq!(store.seed_many(&[("alpha.exe".to_string(), addr(10))]), 0);
    }

    #[test]
    fn retraction_binds_to_one_app_not_to_the_address() {
        let store = AppObservationStore::new();
        store.record("alpha.exe", addr(10));
        store.record("beta.exe", addr(10));

        store.retract("alpha.exe", addr(10));

        assert!(store.ips_for_app("alpha.exe").is_empty());
        assert_eq!(store.ips_for_app("beta.exe"), vec![addr(10)]);
        // Beta is still free to re-confirm it.
        assert!(!store.record("beta.exe", addr(10)));
        assert_eq!(store.ips_for_app("beta.exe"), vec![addr(10)]);
    }

    #[test]
    fn retracting_something_absent_is_harmless_and_still_sticks() {
        let store = AppObservationStore::new();
        assert!(!store.retract("alpha.exe", addr(10)));
        assert!(!store.record("alpha.exe", addr(10)));
        assert!(store.ips_for_app("alpha.exe").is_empty());
    }

    use super::*;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr::new(a, b, c, d)
    }

    #[test]
    fn app_key_takes_lowercased_file_name() {
        assert_eq!(app_key("C:\\Program Files\\Foo\\Chrome.exe"), "chrome");
        assert_eq!(app_key("/usr/bin/Firefox"), "firefox");
        assert_eq!(app_key("CHROME.EXE"), "chrome");
        assert_eq!(app_key("  notepad.exe  "), "notepad");
    }

    #[test]
    fn record_and_lookup_round_trip_sorted() {
        let store = AppObservationStore::new();
        store.record("C:\\x\\chrome.exe", ip(203, 0, 113, 9));
        store.record("chrome.exe", ip(203, 0, 113, 1));
        // Same app, different path casing → same key.
        let ips = store.ips_for_app("CHROME.EXE");
        assert_eq!(ips, vec![ip(203, 0, 113, 1), ip(203, 0, 113, 9)]);
    }

    #[test]
    fn unroutable_ips_are_ignored() {
        let store = AppObservationStore::new();
        store.record("app.exe", ip(127, 0, 0, 1)); // loopback
        store.record("app.exe", ip(169, 254, 0, 5)); // link-local
        store.record("app.exe", ip(0, 0, 0, 0)); // unspecified
        store.record("app.exe", ip(8, 8, 8, 8)); // routable
        assert_eq!(store.ips_for_app("app.exe"), vec![ip(8, 8, 8, 8)]);
    }

    #[test]
    fn fake_pool_destinations_are_ignored() {
        // An app observed connecting to a virtual pool address must not gain a
        // per-IP route/filter mirror — that would steer the flow onto a
        // physical adapter instead of the TUN that terminates it.
        let store = AppObservationStore::new();
        assert!(!store.record("chrome.exe", ip(198, 18, 0, 35)));
        assert!(!store.record("chrome.exe", ip(198, 19, 200, 8)));
        assert!(
            store.record("chrome.exe", ip(198, 20, 0, 1)),
            "outside pool"
        );
        assert_eq!(store.ips_for_app("chrome.exe"), vec![ip(198, 20, 0, 1)]);
    }

    #[test]
    fn the_cap_evicts_the_oldest_rather_than_freezing_the_set() {
        // A cap that refuses new addresses freezes the set: an application that
        // migrates to new servers keeps the destinations of a previous session
        // and never gets the current ones routed until the service restarts.
        let store = AppObservationStore::with_cap(2);
        store.record("a.exe", ip(1, 1, 1, 1));
        store.record("a.exe", ip(2, 2, 2, 2));
        store.record("a.exe", ip(3, 3, 3, 3));

        let live = store.ips_for_app("a.exe");
        assert_eq!(live.len(), 2, "the bound still holds");
        assert!(!live.contains(&ip(1, 1, 1, 1)), "the oldest gave way");
        assert!(live.contains(&ip(3, 3, 3, 3)), "the newest was admitted");
    }

    /// Test clock: a base instant plus a shared, advanceable offset — crossing
    /// the freshness window without sleeping.
    fn test_clock() -> (Arc<Mutex<Duration>>, Arc<dyn Fn() -> Instant + Send + Sync>) {
        let base = Instant::now();
        let offset = Arc::new(Mutex::new(Duration::ZERO));
        let o = Arc::clone(&offset);
        #[allow(clippy::unwrap_used)]
        let clock: Arc<dyn Fn() -> Instant + Send + Sync> =
            Arc::new(move || base + *o.lock().unwrap());
        (offset, clock)
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn a_destination_outside_the_freshness_window_stops_enforcing() {
        // The P2P shape: peers observed hours ago must not keep a standing
        // route/pin for the life of the process — the FQDN side already ages
        // through this very window.
        let (offset, clock) = test_clock();
        let store = AppObservationStore::new().with_clock(clock);
        store.record("torrent.exe", ip(203, 0, 113, 1));
        *offset.lock().unwrap() = APP_PIN_FRESHNESS_WINDOW + Duration::from_secs(60);
        store.record("torrent.exe", ip(203, 0, 113, 2));

        assert_eq!(
            store.ips_for_app("torrent.exe"),
            vec![ip(203, 0, 113, 2)],
            "only the recently-seen destination still enforces"
        );
        // Aged out means learnable again — the next sighting is NEW, so it
        // triggers the recompute that restores the route.
        assert!(store.record("torrent.exe", ip(203, 0, 113, 1)));
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn a_re_observed_destination_rides_the_window_forward() {
        let (offset, clock) = test_clock();
        let store = AppObservationStore::new().with_clock(clock);
        store.record("chat.exe", ip(203, 0, 113, 1));
        // Keep touching it just inside the window, twice over.
        *offset.lock().unwrap() = APP_PIN_FRESHNESS_WINDOW - Duration::from_secs(60);
        store.record("chat.exe", ip(203, 0, 113, 1));
        *offset.lock().unwrap() = 2 * APP_PIN_FRESHNESS_WINDOW - Duration::from_secs(120);
        assert_eq!(
            store.ips_for_app("chat.exe"),
            vec![ip(203, 0, 113, 1)],
            "a live destination is never aged out"
        );
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn a_glob_rule_prunes_stale_destinations_of_every_process_it_names() {
        let (offset, clock) = test_clock();
        let store = AppObservationStore::new().with_clock(clock);
        store.record("myvpnclient.exe", ip(203, 0, 113, 1));
        *offset.lock().unwrap() = APP_PIN_FRESHNESS_WINDOW + Duration::from_secs(60);
        store.record("openvpn.exe", ip(203, 0, 113, 2));
        assert_eq!(store.ips_for_app("*vpn*.exe"), vec![ip(203, 0, 113, 2)]);
    }

    #[test]
    fn re_observing_an_address_keeps_it_from_being_evicted() {
        // Freshness is by LAST sighting, not first: an address the app still
        // uses must not be evicted by one it touched once.
        let store = AppObservationStore::with_cap(2);
        store.record("a.exe", ip(1, 1, 1, 1));
        store.record("a.exe", ip(2, 2, 2, 2));
        store.record("a.exe", ip(1, 1, 1, 1)); // still in use
        store.record("a.exe", ip(3, 3, 3, 3));

        let live = store.ips_for_app("a.exe");
        assert!(live.contains(&ip(1, 1, 1, 1)), "recently used survives");
        assert!(!live.contains(&ip(2, 2, 2, 2)), "the stale one gave way");
    }

    #[test]
    fn unknown_app_is_empty() {
        let store = AppObservationStore::new();
        assert!(store.ips_for_app("nothing.exe").is_empty());
    }

    #[test]
    fn record_returns_true_only_for_newly_observed_ips() {
        // Drives the conn-observe re-apply trigger (1b): recompute only when a
        // genuinely new destination appears, not on every duplicate tick.
        let store = AppObservationStore::new();
        assert!(store.record("chrome.exe", ip(8, 8, 8, 8)), "first = new");
        assert!(
            !store.record("chrome.exe", ip(8, 8, 8, 8)),
            "duplicate = not new"
        );
        assert!(store.record("chrome.exe", ip(1, 1, 1, 1)), "other ip = new");
        assert!(
            !store.record("app.exe", ip(127, 0, 0, 1)),
            "unroutable = not new"
        );
    }

    #[test]
    fn glob_pattern_unions_matching_processes() {
        let store = AppObservationStore::new();
        store.record("myvpnclient.exe", ip(203, 0, 113, 1));
        store.record("openvpn.exe", ip(203, 0, 113, 2));
        store.record("chrome.exe", ip(8, 8, 8, 8));
        // `*vpn*.exe` matches both vpn processes (union), not chrome.
        assert_eq!(
            store.ips_for_app("*vpn*.exe"),
            vec![ip(203, 0, 113, 1), ip(203, 0, 113, 2)]
        );
        // exact lookup still works.
        assert_eq!(store.ips_for_app("chrome.exe"), vec![ip(8, 8, 8, 8)]);
    }

    #[test]
    fn glob_match_basics() {
        assert!(glob_match("*vpn*.exe", "myvpnclient.exe"));
        assert!(glob_match("chrome.*", "chrome.exe"));
        assert!(glob_match("*.exe", "anything.exe"));
        assert!(glob_match("*", "whatever"));
        assert!(glob_match("exact.exe", "exact.exe"));
        assert!(!glob_match("*vpn*.exe", "chrome.exe"));
        assert!(!glob_match("chrome.exe", "firefox.exe"));
        assert!(!glob_match("a*b", "axc"));
    }

    #[test]
    fn mock_round_trips() {
        let m = MockAppObservationLookup::new();
        m.set_ips("chrome.exe", vec![ip(1, 2, 3, 4)]);
        assert_eq!(m.ips_for_app("C:\\path\\Chrome.exe"), vec![ip(1, 2, 3, 4)]);
        assert!(m.ips_for_app("other.exe").is_empty());
    }
}
