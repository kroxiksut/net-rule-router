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
//!
//! A rule by path (`c:\apps\tool\*`, `/opt/app/`) keeps its own bucket under
//! its canonical spelling: a connection is recorded there too when its full
//! image path lies where the rule names, at the rule's own place or at the
//! real one behind a link ([`AppObservationLookup::note_path_places`]). Only
//! paths a plan has asked about are matched, so a book without path rules pays
//! nothing for them.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use crate::bounded_set::BoundedRecentSet;
use nrr_platform_api::conn_observe::live::LiveConnection;
use nrr_shared::app_path::{AppPath, PathStyle};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

/// How recently an app's destination must have been SEEN to keep producing a
/// route and filters. Shares the window every other enforcement view uses
/// ([`crate::fqdn_cache_lookup::ENFORCEMENT_CONFIRMATION_WINDOW`]) rather than
/// standing until the LRU cap or a restart — without it, a P2P session would
/// keep its last peers enforced for the life of the process. An address that
/// ages out loses only its own `/32`; the app touching it again relearns it
/// within a tick (the first contact drops on the per-app block, which is what
/// teaches it).
pub const APP_PIN_FRESHNESS_WINDOW: Duration =
    crate::fqdn_cache_lookup::ENFORCEMENT_CONFIRMATION_WINDOW;

/// Max distinct IPs retained per app — bounds the codegen fan-out (mirrors
/// [`crate::wfp_codegen::PER_HOSTNAME_IP_CAP`] in spirit). A busy browser can
/// touch thousands of IPs; we keep the most-recently-observed up to this cap.
pub const APP_IP_CAP: usize = 256;

/// Applications kept, each with up to [`APP_IP_CAP`] destinations. Observation
/// records every process on the machine, not only those a rule names; this is
/// far above what a desktop runs, so the one that gives way has gone quiet.
pub const APP_KEY_CAP: usize = 1024;

/// Destinations the census remembers, with the processes seen using them.
///
/// Deliberately NOT [`APP_IP_CAP`]: that one bounds how many host routes a rule
/// may fan out to, this one bounds *evidence*. A browser passes the route cap
/// long before it stops being worth knowing that it, too, uses an address — and
/// the whole point of the census is to answer for exactly such a process.
pub const CENSUS_IP_CAP: usize = 8192;

/// Distinct processes kept per destination. The census only ever answers
/// "is anybody here who is not one of these rules?", so a handful is enough and
/// an unbounded list would be a leak with no reader.
pub const CENSUS_KEYS_PER_IP: usize = 4;

/// Longest image path the census keeps whole, so a rule by path can tell its
/// own programs from a namesake elsewhere. A longer one is kept by name, which
/// no path rule claims.
pub const CENSUS_IMAGE_MAX_BYTES: usize = nrr_shared::app_path::MAX_PATH_VALUE_BYTES;

/// Rules by path whose places are remembered at once; past it the memory
/// starts over and each is relearnt from its spelling on the next ask.
pub const PATH_PATTERN_CAP: usize = 256;

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

    /// `principal`'s own observations, where they are kept per user; `None`
    /// means this lookup answers for everyone.
    fn for_principal(&self, _principal: &str) -> Option<Arc<dyn AppObservationLookup>> {
        None
    }

    /// Where the rule by path spelled `key` really is: `places` (its own and
    /// the real one behind links) are where the programs whose connections
    /// its bucket collects live. The default keeps nothing; a path rule then
    /// matches only where it is spelled.
    fn note_path_places(&self, _key: &str, _places: &[AppPath]) {}
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

/// Whether a rule pattern names programs by path: it starts at a drive, a
/// share or `/`. A name never does — a program's canonical name is a file
/// name.
#[must_use]
pub fn is_path_pattern(pattern: &str) -> bool {
    let bytes = pattern.trim().as_bytes();
    matches!(bytes, [b'/', ..] | [b'\\', b'\\', ..])
        || matches!(bytes, [drive, b':', b'\\' | b'/', ..] if drive.is_ascii_alphabetic())
}

/// Turns an image path the OS reported in another spelling (on Windows the
/// kernel's `\device\...` form a dropped connection is named in) into the one
/// rules by path are written in; `None` when it cannot.
pub type ImageNormalizer = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

/// The key a rule pattern's observations are kept under: a name reduces to
/// [`app_key`], a path stays as the rule spells it, so `c:\apps\*` never
/// collapses onto the name `*`. For a process image use [`app_key`].
#[must_use]
pub fn observation_key(pattern: &str) -> String {
    if is_path_pattern(pattern) {
        pattern.trim().to_string()
    } else {
        app_key(pattern)
    }
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
    /// carrying somebody else's traffic. Sticky, but bounded: without this,
    /// the app would touch the address again within seconds, the pair would
    /// be relearned immediately, and the two processes would take the address
    /// from each other in a loop.
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
    /// Last sighting per application, picking who gives way at `app_cap`.
    /// Taken only while `inner` is held.
    app_recency: Mutex<AppRecency>,
    app_cap: usize,
    app_cap_logged: AtomicBool,
    /// Moves whenever something a plan reads from here changes membership — not
    /// on a restamp, whose only effect is through time.
    generation: AtomicU64,
    /// The patterns a plan has asked about. Every program's connections are
    /// recorded, but only the ones an application rule names change a plan;
    /// counting the rest would make every browser tab look like new policy.
    watched: Mutex<Vec<String>>,
    /// Set where each user's traffic follows their own routes: observations
    /// then live in one store per user, and this one holds none itself.
    per_principal: Option<PrincipalAppObservations>,
    /// How this platform spells the paths rules and images use.
    path_style: PathStyle,
    /// Rules by path a plan has asked about, each with the places its programs
    /// live at. Never held while another lock of this store is taken.
    path_places: Mutex<HashMap<String, Vec<AppPath>>>,
    image_normalizer: OnceLock<ImageNormalizer>,
}

/// Sighting order of applications as a counter, so a sighting costs one map
/// write and only an eviction scans.
#[derive(Default)]
struct AppRecency {
    tick: u64,
    last: HashMap<String, u64>,
}

impl AppRecency {
    fn touch(&mut self, app: &str) {
        self.tick += 1;
        match self.last.get_mut(app) {
            Some(at) => *at = self.tick,
            None => {
                self.last.insert(app.to_string(), self.tick);
            }
        }
    }

    fn take_least_recent(&mut self) -> Option<String> {
        let victim = self
            .last
            .iter()
            .min_by_key(|(_, at)| **at)
            .map(|(app, _)| app.clone())?;
        self.last.remove(&victim);
        Some(victim)
    }
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
            app_recency: Mutex::new(AppRecency::default()),
            app_cap: APP_KEY_CAP,
            app_cap_logged: AtomicBool::new(false),
            generation: AtomicU64::new(0),
            watched: Mutex::new(Vec::new()),
            per_principal: None,
            path_style: nrr_domain::rules_file::HostPlatform::compiled().path_style(),
            path_places: Mutex::new(HashMap::new()),
            image_normalizer: OnceLock::new(),
        }
    }

    /// How images reported in another spelling are read for rules by path.
    /// Only the first call counts.
    pub fn set_image_normalizer(&self, normalize: ImageNormalizer) {
        let _ = self.image_normalizer.set(normalize);
    }

    /// `image` in the spelling rules by path are written in.
    fn path_image<'a>(&self, image: &'a str) -> std::borrow::Cow<'a, str> {
        if is_path_pattern(image) {
            return std::borrow::Cow::Borrowed(image);
        }
        match self
            .image_normalizer
            .get()
            .and_then(|normalize| normalize(image))
        {
            Some(normal) => std::borrow::Cow::Owned(normal),
            None => std::borrow::Cow::Borrowed(image),
        }
    }

    /// Read paths as `style` spells them instead of as this platform does, so
    /// a test of another platform's paths runs on any host.
    #[must_use]
    pub fn with_path_style(mut self, style: PathStyle) -> Self {
        self.path_style = style;
        self
    }

    /// A store that keeps each user's observations apart (see
    /// [`PrincipalAppObservations`]).
    #[must_use]
    pub fn per_principal() -> Self {
        Self {
            per_principal: Some(PrincipalAppObservations::new()),
            ..Self::new()
        }
    }

    /// The store a connection owned by `owner` is recorded in: this one, or,
    /// kept per user, the owner's own. `None` for a connection whose owner is
    /// unknown in a per-user store: attributed to nobody, it teaches nothing.
    pub fn scope_for(self: &Arc<Self>, owner: Option<&str>) -> Option<Arc<Self>> {
        match (self.per_principal.as_ref(), owner) {
            (None, _) => Some(Arc::clone(self)),
            (Some(stores), Some(owner)) if !owner.is_empty() => Some(stores.for_principal(owner)),
            (Some(_), _) => None,
        }
    }

    /// Whether observations are kept per user (see [`Self::per_principal`]).
    #[must_use]
    pub fn keeps_per_principal(&self) -> bool {
        self.per_principal.is_some()
    }

    #[cfg(test)]
    fn with_app_cap(mut self, cap: usize) -> Self {
        self.app_cap = cap.max(1);
        self
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
        if observation_key(app_pattern).is_empty() {
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
        // Kept per user, an address is recorded through `scope_for`, never here.
        if self.per_principal.is_some() || is_unroutable(ip) {
            return false;
        }
        let key = app_key(process_path);
        if key.is_empty() {
            return false;
        }
        let buckets = self.path_buckets_of(process_path);
        let mut is_new = self.record_key(key, ip);
        for bucket in buckets {
            is_new |= self.record_key(bucket, ip);
        }
        is_new
    }

    /// Record `ip` under the bucket `key`: a program's name, or a rule path.
    fn record_key(&self, key: String, ip: Ipv4Addr) -> bool {
        if self
            .retracted
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .contains(&(key.clone(), ip))
        {
            return false;
        }
        let (seen, dropped_app) = {
            let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            let mut recency = self.app_recency.lock().unwrap_or_else(|p| p.into_inner());
            let dropped_app = if !g.contains_key(&key) && g.len() >= self.app_cap {
                recency
                    .take_least_recent()
                    .and_then(|app| g.remove(&app).map(|set| (app, set)))
            } else {
                None
            };
            recency.touch(&key);
            let set = g
                .entry(key.clone())
                .or_insert_with(|| BoundedRecentSet::new(self.cap_per_app));
            (set.observe(ip), dropped_app)
        };
        {
            let mut stamps = self.last_seen.lock().unwrap_or_else(|p| p.into_inner());
            stamps.insert((key.clone(), ip), (self.clock)());
            if let Some(old) = seen.evicted {
                stamps.remove(&(key.clone(), old));
            }
            if let Some((app, ips)) = &dropped_app {
                for old in ips.iter() {
                    stamps.remove(&(app.clone(), *old));
                }
            }
        }
        if dropped_app.is_some() && !self.app_cap_logged.swap(true, Ordering::Relaxed) {
            tracing::info!(
                target: "nrr::app-observations",
                msg_key = "app-observations-app-cap",
                cap = self.app_cap,
                "application observation cap reached; the least recently seen application gives way",
            );
        }
        let membership_changed = seen.is_new || seen.evicted.is_some();
        if (membership_changed && self.planned(&key))
            || dropped_app
                .as_ref()
                .is_some_and(|(app, _)| self.planned(app))
        {
            self.generation.fetch_add(1, Ordering::Relaxed);
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
    ///
    /// Kept per user, remembered destinations are seeded into their owner's
    /// store through [`scope_for`](Self::scope_for); here they have no owner
    /// and teach nothing.
    pub fn seed_many(&self, pairs: &[(String, Ipv4Addr)]) -> usize {
        if self.per_principal.is_some() {
            return 0;
        }
        pairs
            .iter()
            .filter(|(app, ip)| {
                // A remembered path rule's key is its bucket, not a process.
                if is_path_pattern(app) {
                    !is_unroutable(*ip) && self.record_key(observation_key(app), *ip)
                } else {
                    self.record(app, *ip)
                }
            })
            .count()
    }

    /// Restamp the destinations a program is still connected to.
    ///
    /// Observation reports a connection once, when it opens, so a program that
    /// holds one connection for longer than the freshness window would lose its
    /// route from under that connection. Only pairs already held are touched: an
    /// open connection keeps a learnt destination alive but never teaches a new
    /// one, and a pair withdrawn as collateral is no longer held, so it stays
    /// withdrawn. Returns how many pairs were refreshed.
    pub fn refresh_live(&self, live: &[LiveConnection]) -> usize {
        if let Some(stores) = self.per_principal.as_ref() {
            return stores.refresh_live(live);
        }
        let now = (self.clock)();
        let mut refreshed: HashSet<(String, Ipv4Addr)> = HashSet::new();
        // Asked before `inner` is taken: the path memory is never held under it.
        let buckets: Vec<Vec<String>> = live
            .iter()
            .map(|connection| self.path_buckets_of(&connection.process_path))
            .collect();
        {
            let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            let mut stamps = self.last_seen.lock().unwrap_or_else(|p| p.into_inner());
            for (connection, paths) in live.iter().zip(&buckets) {
                let key = app_key(&connection.process_path);
                if key.is_empty() {
                    continue;
                }
                for (name, set) in g.iter_mut() {
                    let covers = if is_path_pattern(name) {
                        paths.contains(name)
                    } else {
                        pattern_matches(name, &key)
                    };
                    if covers && set.contains(&connection.remote) {
                        set.observe(connection.remote);
                        stamps.insert((name.clone(), connection.remote), now);
                        refreshed.insert((name.clone(), connection.remote));
                    }
                }
            }
            // A program holding its connections is in use, not quiet.
            let mut recency = self.app_recency.lock().unwrap_or_else(|p| p.into_inner());
            for (name, _) in &refreshed {
                recency.touch(name);
            }
        }
        let mut seen = self
            .seen_since_flush
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        for pair in &refreshed {
            seen.observe(pair.clone());
        }
        refreshed.len()
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
        let key = observation_key(app);
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
        if removed {
            self.generation.fetch_add(1, Ordering::Relaxed);
        }
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
        let name = app_key(process_path);
        if name.is_empty() || name == own_process_key() {
            return;
        }
        // The image itself, so a rule by path can claim its own programs.
        let key = if process_path.len() <= CENSUS_IMAGE_MAX_BYTES {
            process_path.trim().to_string()
        } else {
            name
        };
        // The census only matters to a plan for an address a planned
        // application's set holds; asked before the census lock, never under it.
        let pinned = self
            .inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .any(|(app, set)| set.contains(&ip) && self.planned(app));
        let mut g = self.census.lock().unwrap_or_else(|p| p.into_inner());
        match g.seen.get_mut(&ip) {
            Some(keys) => {
                if keys.len() < CENSUS_KEYS_PER_IP && !keys.iter().any(|k| k == &key) {
                    keys.push(key);
                    if pinned {
                        self.generation.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            None => {
                if pinned {
                    self.generation.fetch_add(1, Ordering::Relaxed);
                }
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
                .any(|pattern| self.names_process(pattern, seen))
        })
    }

    /// Whether the rule `pattern` names the process whose image is
    /// `process_path`: by name, or by where the image lies.
    #[must_use]
    pub fn names_process(&self, pattern: &str, process_path: &str) -> bool {
        if is_path_pattern(pattern) {
            let image = self.path_image(process_path);
            self.places_of(pattern.trim())
                .iter()
                .any(|place| place.match_image(&image).is_some())
        } else {
            pattern_matches(pattern, &app_key(process_path))
        }
    }

    /// The places the rule path spelled `key` collects from: the ones a plan
    /// noted, else the spelling itself.
    fn places_of(&self, key: &str) -> Vec<AppPath> {
        let known = self
            .path_places
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(key)
            .cloned();
        known.unwrap_or_else(|| AppPath::parse(key, self.path_style).into_iter().collect())
    }

    /// The rule paths a plan asked about whose places hold `image`.
    fn path_buckets_of(&self, image: &str) -> Vec<String> {
        if self
            .path_places
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_empty()
        {
            return Vec::new();
        }
        let image = self.path_image(image);
        let image = image.as_ref();
        let places = self.path_places.lock().unwrap_or_else(|p| p.into_inner());
        places
            .iter()
            .filter(|(_, at)| at.iter().any(|place| place.match_image(image).is_some()))
            .map(|(key, _)| key.clone())
            .collect()
    }

    /// Start matching images for the rule path `key`, at its own spelling
    /// until a plan says where it really is.
    fn watch_path(&self, key: &str) {
        let mut places = self.path_places.lock().unwrap_or_else(|p| p.into_inner());
        if places.contains_key(key) {
            return;
        }
        if places.len() >= PATH_PATTERN_CAP {
            places.clear();
        }
        let literal: Vec<AppPath> = AppPath::parse(key, self.path_style).into_iter().collect();
        places.insert(key.to_string(), literal);
    }

    /// Where the rule path `key` collects from: its own spelling and the
    /// places a plan found for it (a handful at most).
    fn set_path_places(&self, key: &str, noted: &[AppPath]) {
        let key = key.trim();
        if !is_path_pattern(key) {
            return;
        }
        let mut at: Vec<AppPath> = AppPath::parse(key, self.path_style).into_iter().collect();
        for place in noted.iter().take(4) {
            if place.style() == self.path_style && !at.contains(place) {
                at.push(place.clone());
            }
        }
        let mut places = self.path_places.lock().unwrap_or_else(|p| p.into_inner());
        if !places.contains_key(key) && places.len() >= PATH_PATTERN_CAP {
            places.clear();
        }
        places.insert(key.to_string(), at);
    }

    /// Moves whenever something a plan has read from here changes, so a pass can
    /// tell "nothing here is new" without reading it.
    #[must_use]
    pub fn generation(&self) -> u64 {
        let own = self.generation.load(Ordering::Relaxed);
        match self.per_principal.as_ref() {
            Some(stores) => own.wrapping_add(stores.generation()),
            None => own,
        }
    }

    /// Whether `key` is a program some plan has asked about.
    fn planned(&self, key: &str) -> bool {
        self.watched
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .any(|pattern| pattern_matches(pattern, key))
    }

    /// Remember that a plan reads `key`. The first ask is itself a change: what
    /// the store already holds for the pattern has not reached any plan yet.
    fn watch(&self, key: &str) {
        let mut watched = self.watched.lock().unwrap_or_else(|p| p.into_inner());
        if !watched.iter().any(|known| known == key) {
            watched.push(key.to_string());
            self.generation.fetch_add(1, Ordering::Relaxed);
        }
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
        if is_path_pattern(app) {
            let key = observation_key(app);
            self.watch(&key);
            self.watch_path(&key);
            let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            self.prune_stale(&mut g, &key);
            let mut v: Vec<Ipv4Addr> = g
                .get(&key)
                .map(|set| set.iter().copied().collect())
                .unwrap_or_default();
            v.sort();
            return v;
        }
        let key = app_key(app);
        if key.is_empty() {
            return Vec::new();
        }
        self.watch(&key);
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        // Glob pattern (e.g. `*vpn*.exe`) → union the IPs of every observed
        // process whose name matches; exact name → a single lookup. Stale
        // sightings are pruned first, so what enforcement reads is only what
        // was seen inside the freshness window.
        let mut v: Vec<Ipv4Addr> = if key.contains('*') {
            let names: Vec<String> = g
                .keys()
                // A rule path's bucket repeats its programs' own; a mask over
                // names must not reach programs through a folder's spelling.
                .filter(|name| !is_path_pattern(name) && glob_match(&key, name))
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

    fn for_principal(&self, principal: &str) -> Option<Arc<dyn AppObservationLookup>> {
        let stores = self.per_principal.as_ref()?;
        Some(stores.for_principal(principal) as Arc<dyn AppObservationLookup>)
    }

    fn note_path_places(&self, key: &str, places: &[AppPath]) {
        self.set_path_places(key, places);
    }
}

/// Does the rule pattern `pattern` name the observed process `key`?
///
/// The one place this question is answered, so the census, the collateral check
/// and the codegen cannot drift into disagreeing about what a rule covers.
#[must_use]
pub fn pattern_matches(pattern: &str, key: &str) -> bool {
    // A rule path names its own bucket only; its last segment is no name.
    if is_path_pattern(pattern) {
        return pattern.trim() == key;
    }
    if is_path_pattern(key) {
        return false;
    }
    let p = app_key(pattern);
    if p.contains('*') {
        glob_match(&p, key)
    } else {
        p == key
    }
}

/// `*` is the only metacharacter here; `?` stays literal, as it always has.
fn glob_match(pattern: &str, name: &str) -> bool {
    nrr_shared::glob::glob_match(pattern, name)
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

/// Most users a machine keeps separate observations for; past it the least
/// recently created store gives way. Far above the people one machine serves.
pub const PRINCIPAL_STORE_CAP: usize = 64;

/// One [`AppObservationStore`] per user, for a platform that routes each
/// user's traffic by their own table: an address one user's program used says
/// nothing about another user's plan, and must not move their traffic.
#[derive(Default)]
pub struct PrincipalAppObservations {
    stores: Mutex<Vec<(String, Arc<AppObservationStore>)>>,
    /// Bumped when a store is created or dropped, so [`Self::generation`]
    /// moves even when the stores' own counters sum to an earlier value.
    membership: AtomicU64,
}

impl PrincipalAppObservations {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// `principal`'s store, created on first use.
    pub fn for_principal(&self, principal: &str) -> Arc<AppObservationStore> {
        let mut stores = self.stores.lock().unwrap_or_else(|p| p.into_inner());
        if let Some((_, store)) = stores.iter().find(|(p, _)| p == principal) {
            return Arc::clone(store);
        }
        if stores.len() >= PRINCIPAL_STORE_CAP {
            stores.remove(0);
        }
        let store = Arc::new(AppObservationStore::new());
        stores.push((principal.to_owned(), Arc::clone(&store)));
        self.membership.fetch_add(1, Ordering::Relaxed);
        store
    }

    /// Every store made so far, by principal.
    pub fn all(&self) -> Vec<(String, Arc<AppObservationStore>)> {
        self.stores
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    /// Moves whenever any user's store changes what a plan reads.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.all()
            .iter()
            .map(|(_, store)| store.generation())
            .fold(self.membership.load(Ordering::Relaxed), u64::wrapping_add)
    }

    /// Restamp each user's destinations from the connections their own
    /// programs hold open. A connection with no known owner restamps nothing.
    pub fn refresh_live(&self, live: &[LiveConnection]) -> usize {
        let mut refreshed = 0;
        for (principal, store) in self.all() {
            let mine: Vec<LiveConnection> = live
                .iter()
                .filter(|connection| connection.owner.as_deref() == Some(principal.as_str()))
                .cloned()
                .collect();
            if !mine.is_empty() {
                refreshed += store.refresh_live(&mine);
            }
        }
        refreshed
    }
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
        self.inner.lock().unwrap().insert(observation_key(app), ips);
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
            .get(&observation_key(app))
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

    /// Kept per user, Alice's browser teaches Alice's plan only: Bob's rule
    /// for the same program never sees her destinations.
    #[test]
    fn each_users_program_destinations_stay_in_that_users_plan() {
        use super::{AppObservationLookup, AppObservationStore, LiveConnection};
        use std::sync::Arc;
        let store = Arc::new(AppObservationStore::per_principal());
        let alice = store.scope_for(Some("uid:1000")).expect("owner known");
        assert!(alice.record("/usr/bin/firefox", addr(10)));
        // An owner the table could not name teaches nobody.
        assert!(store.scope_for(None).is_none());
        assert!(!store.record("/usr/bin/firefox", addr(11)));

        let plan_of = |principal: &str| {
            store
                .for_principal(principal)
                .expect("kept per user")
                .ips_for_app("firefox")
        };
        assert_eq!(plan_of("uid:1000"), vec![addr(10)]);
        assert!(
            plan_of("uid:1001").is_empty(),
            "another user's plan must not route Alice's destinations"
        );

        // A held connection refreshes its owner's destinations only.
        let held = LiveConnection {
            process_path: "/usr/bin/firefox".into(),
            remote: addr(10),
            owner: Some("uid:1001".into()),
        };
        assert_eq!(store.refresh_live(&[held]), 0);
    }

    /// Kept per user, a remembered destination with no owner teaches nobody,
    /// not even a store made later.
    #[test]
    fn ownerless_seeds_reach_no_users_store() {
        use super::{AppObservationLookup, AppObservationStore};
        use std::sync::Arc;
        let store = Arc::new(AppObservationStore::per_principal());
        assert!(store.keeps_per_principal());
        assert_eq!(store.seed_many(&[("firefox".to_string(), addr(10))]), 0);
        let later = store.scope_for(Some("uid:1000")).expect("owner known");
        assert!(later.ips_for_app("firefox").is_empty());
        assert!(!later.keeps_per_principal());
    }

    /// The single shared store keeps today's behaviour: every scope is itself.
    #[test]
    fn a_shared_store_scopes_to_itself() {
        use super::AppObservationStore;
        use std::sync::Arc;
        let store = Arc::new(AppObservationStore::new());
        let scoped = store.scope_for(None).expect("shared");
        assert!(Arc::ptr_eq(&store, &scoped));
        assert!(super::AppObservationLookup::for_principal(store.as_ref(), "uid:1000").is_none());
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
        store.note_process_destination("helper.exe", addr(10));
        assert!(
            !store.destination_used_outside(&friendly(&["assistant.exe", "helper.exe"]), addr(10))
        );
        // …but a third, unnamed one does make it shared.
        store.note_process_destination("chrome.exe", addr(10));
        assert!(
            store.destination_used_outside(&friendly(&["assistant.exe", "helper.exe"]), addr(10))
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

    /// Every process on the machine is recorded, so the number of
    /// applications is bounded too; the one seen least recently gives way,
    /// together with its freshness stamps.
    #[test]
    fn past_the_app_cap_the_least_recently_seen_application_gives_way() {
        let store = AppObservationStore::new().with_app_cap(2);
        store.record("first.exe", addr(1));
        store.record("second.exe", addr(2));
        store.record("first.exe", addr(3));
        store.record("third.exe", addr(4));

        assert_eq!(store.app_count(), 2);
        assert!(store.ips_for_app("second.exe").is_empty());
        assert_eq!(store.ips_for_app("first.exe"), vec![addr(1), addr(3)]);
        assert_eq!(store.ips_for_app("third.exe"), vec![addr(4)]);
        let stamps = store.last_seen.lock().unwrap_or_else(|p| p.into_inner());
        assert!(!stamps.keys().any(|(app, _)| app == "second.exe"));
    }

    #[test]
    fn under_the_app_cap_every_application_is_kept() {
        let store = AppObservationStore::new().with_app_cap(2);
        store.record("first.exe", addr(1));
        store.record("second.exe", addr(2));
        store.record("second.exe", addr(3));
        assert_eq!(store.app_count(), 2);
        assert_eq!(store.ips_for_app("first.exe"), vec![addr(1)]);
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
        store.record("app.exe", ip(198, 51, 100, 8)); // routable
        assert_eq!(store.ips_for_app("app.exe"), vec![ip(198, 51, 100, 8)]);
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
        store.record("a.exe", ip(198, 51, 100, 1));
        store.record("a.exe", ip(198, 51, 100, 2));
        store.record("a.exe", ip(198, 51, 100, 3));

        let live = store.ips_for_app("a.exe");
        assert_eq!(live.len(), 2, "the bound still holds");
        assert!(!live.contains(&ip(198, 51, 100, 1)), "the oldest gave way");
        assert!(
            live.contains(&ip(198, 51, 100, 3)),
            "the newest was admitted"
        );
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

    fn live(process_path: &str, remote: Ipv4Addr) -> LiveConnection {
        LiveConnection {
            process_path: process_path.to_string(),
            remote,
            owner: None,
        }
    }

    /// The messenger shape: one connection opened once and held for longer than
    /// the window. Observation never sees it again, so without the live refresh
    /// its route was withdrawn from under the open session.
    #[allow(clippy::unwrap_used)]
    #[test]
    fn a_connection_held_open_keeps_its_destination_past_the_window() {
        let (offset, clock) = test_clock();
        let store = AppObservationStore::new().with_clock(clock);
        store.record(r"C:\Apps\Messenger.exe", ip(203, 0, 113, 7));
        store.record("messenger.exe", ip(203, 0, 113, 8));

        *offset.lock().unwrap() = APP_PIN_FRESHNESS_WINDOW - Duration::from_secs(60);
        assert_eq!(
            store.refresh_live(&[live("messenger.exe", ip(203, 0, 113, 7))]),
            1
        );
        *offset.lock().unwrap() = APP_PIN_FRESHNESS_WINDOW + Duration::from_secs(60);

        assert_eq!(
            store.ips_for_app("messenger.exe"),
            vec![ip(203, 0, 113, 7)],
            "the held destination stays; the one nobody holds ages out as before"
        );
    }

    #[test]
    fn a_live_connection_never_teaches_a_destination() {
        let store = AppObservationStore::new();
        store.record("messenger.exe", ip(203, 0, 113, 7));
        assert_eq!(
            store.refresh_live(&[
                live("messenger.exe", ip(203, 0, 113, 9)),
                live("browser.exe", ip(203, 0, 113, 7)),
            ]),
            0
        );
        assert_eq!(store.ips_for_app("messenger.exe"), vec![ip(203, 0, 113, 7)]);
        assert!(store.ips_for_app("browser.exe").is_empty());
    }

    #[test]
    fn a_withdrawn_destination_stays_withdrawn_while_connected() {
        let store = AppObservationStore::new();
        store.record("messenger.exe", ip(203, 0, 113, 7));
        assert!(store.retract("messenger.exe", ip(203, 0, 113, 7)));
        assert_eq!(
            store.refresh_live(&[live("messenger.exe", ip(203, 0, 113, 7))]),
            0
        );
        assert!(store.ips_for_app("messenger.exe").is_empty());
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn a_glob_rule_keeps_the_live_destination_of_a_process_it_names() {
        let (offset, clock) = test_clock();
        let store = AppObservationStore::new().with_clock(clock);
        store.seed_many(&[("*vpn*.exe".to_string(), ip(203, 0, 113, 1))]);
        *offset.lock().unwrap() = APP_PIN_FRESHNESS_WINDOW - Duration::from_secs(60);
        assert_eq!(
            store.refresh_live(&[live("myvpnclient.exe", ip(203, 0, 113, 1))]),
            1
        );
        *offset.lock().unwrap() = APP_PIN_FRESHNESS_WINDOW + Duration::from_secs(60);
        assert_eq!(store.ips_for_app("*vpn*.exe"), vec![ip(203, 0, 113, 1)]);
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
        store.record("a.exe", ip(198, 51, 100, 1));
        store.record("a.exe", ip(198, 51, 100, 2));
        store.record("a.exe", ip(198, 51, 100, 1)); // still in use
        store.record("a.exe", ip(198, 51, 100, 3));

        let live = store.ips_for_app("a.exe");
        assert!(
            live.contains(&ip(198, 51, 100, 1)),
            "recently used survives"
        );
        assert!(
            !live.contains(&ip(198, 51, 100, 2)),
            "the stale one gave way"
        );
    }

    #[test]
    fn unknown_app_is_empty() {
        let store = AppObservationStore::new();
        assert!(store.ips_for_app("nothing.exe").is_empty());
    }

    /// Every program's connections are recorded, but only what a plan reads may
    /// move the generation — otherwise any browser tab re-plans the policy.
    #[test]
    fn only_what_a_plan_reads_moves_the_generation() {
        let store = AppObservationStore::new();
        let start = store.generation();
        store.record("browser.example", ip(198, 51, 100, 8));
        store.note_process_destination("browser.example", ip(198, 51, 100, 8));
        assert_eq!(store.generation(), start, "an unruled program moved it");

        let _ = store.ips_for_app("client.example");
        let watched = store.generation();
        assert_ne!(watched, start, "the first ask is new input for the plan");

        store.record("client.example", ip(198, 51, 100, 9));
        assert_ne!(
            store.generation(),
            watched,
            "a ruled program's new address did not move it"
        );

        let before_census = store.generation();
        store.note_process_destination("other.example", ip(198, 51, 100, 9));
        assert_ne!(
            store.generation(),
            before_census,
            "a stranger on a pinned address did not move it"
        );
    }

    #[test]
    fn record_returns_true_only_for_newly_observed_ips() {
        // Drives the conn-observe re-apply trigger (1b): recompute only when a
        // genuinely new destination appears, not on every duplicate tick.
        let store = AppObservationStore::new();
        assert!(
            store.record("chrome.exe", ip(198, 51, 100, 8)),
            "first = new"
        );
        assert!(
            !store.record("chrome.exe", ip(198, 51, 100, 8)),
            "duplicate = not new"
        );
        assert!(
            store.record("chrome.exe", ip(198, 51, 100, 1)),
            "other ip = new"
        );
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
        store.record("chrome.exe", ip(198, 51, 100, 8));
        // `*vpn*.exe` matches both vpn processes (union), not chrome.
        assert_eq!(
            store.ips_for_app("*vpn*.exe"),
            vec![ip(203, 0, 113, 1), ip(203, 0, 113, 2)]
        );
        // exact lookup still works.
        assert_eq!(store.ips_for_app("chrome.exe"), vec![ip(198, 51, 100, 8)]);
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
        m.set_ips("chrome.exe", vec![ip(192, 0, 2, 4)]);
        assert_eq!(m.ips_for_app("Chrome.EXE"), vec![ip(192, 0, 2, 4)]);
        assert!(m.ips_for_app("other.exe").is_empty());
        // A rule by path keeps its own key: a folder is not the name of its
        // last part.
        m.set_ips(r"c:\apps\tool\*", vec![ip(192, 0, 2, 5)]);
        assert_eq!(m.ips_for_app(r"c:\apps\tool\*"), vec![ip(192, 0, 2, 5)]);
        assert!(m.ips_for_app("*").is_empty());
    }

    fn windows_store() -> AppObservationStore {
        AppObservationStore::new().with_path_style(nrr_shared::app_path::PathStyle::Windows)
    }

    /// A rule by folder learns from the programs in that folder only; a
    /// program of the same name elsewhere teaches its name rule, not the
    /// folder's.
    #[test]
    fn a_folder_rule_learns_from_the_programs_inside_it_only() {
        let store = windows_store();
        let folder = r"c:\apps\tool\*";
        assert!(store.ips_for_app(folder).is_empty(), "the plan asks first");
        assert!(store.record(r"C:\Apps\Tool\v2\tool.exe", ip(203, 0, 113, 1)));
        store.record(r"C:\Other\tool.exe", ip(203, 0, 113, 2));
        assert_eq!(store.ips_for_app(folder), vec![ip(203, 0, 113, 1)]);
        assert_eq!(
            store.ips_for_app("tool.exe"),
            vec![ip(203, 0, 113, 1), ip(203, 0, 113, 2)]
        );
        // "This folder only" leaves the version folder below it out.
        let flat = r"c:\apps\tool\";
        assert!(store.ips_for_app(flat).is_empty());
        store.record(r"C:\Apps\Tool\v2\tool.exe", ip(203, 0, 113, 3));
        assert!(store.ips_for_app(flat).is_empty());
    }

    /// A mask over names never reaches programs through a folder's spelling:
    /// `*tool*` names programs called like that, not those of `c:\tools\`.
    #[test]
    fn a_name_mask_does_not_match_a_folders_bucket() {
        let store = windows_store();
        let _ = store.ips_for_app(r"c:\tools\*");
        store.record(r"C:\Tools\a.exe", ip(203, 0, 113, 9));
        assert_eq!(store.ips_for_app(r"c:\tools\*"), vec![ip(203, 0, 113, 9)]);
        assert!(store.ips_for_app("*tool*").is_empty());
        assert!(!pattern_matches("*", r"c:\tools\*"));
    }

    /// The census asks where a program lives: the folder rule's own programs
    /// are friends, a namesake elsewhere is somebody else.
    #[test]
    fn the_census_tells_a_folders_program_from_its_namesake() {
        let store = windows_store();
        let folder = r"c:\apps\tool\*".to_string();
        let _ = store.ips_for_app(&folder);
        let shared = ip(203, 0, 113, 20);
        store.note_process_destination(r"C:\Apps\Tool\tool.exe", shared);
        assert!(!store.destination_used_outside(std::slice::from_ref(&folder), shared));
        store.note_process_destination(r"C:\Elsewhere\tool.exe", shared);
        assert!(store.destination_used_outside(std::slice::from_ref(&folder), shared));
        assert!(
            !store.destination_used_outside(&["tool.exe".to_string()], shared),
            "a name rule covers both"
        );
    }

    /// A dropped connection names its program in the kernel's spelling; the
    /// platform's reading of it is what a folder rule matches.
    #[test]
    fn an_image_in_another_spelling_is_read_for_folder_rules() {
        let store = windows_store();
        store.set_image_normalizer(std::sync::Arc::new(|image: &str| {
            image
                .strip_prefix(r"\device\harddiskvolume3\")
                .map(|rest| format!(r"C:\{rest}"))
        }));
        let folder = r"c:\apps\tool\*";
        let _ = store.ips_for_app(folder);
        store.record(
            r"\device\harddiskvolume3\apps\tool\tool.exe",
            ip(203, 0, 113, 30),
        );
        assert_eq!(store.ips_for_app(folder), vec![ip(203, 0, 113, 30)]);
    }

    /// Remembered destinations of a rule by path go back into its own bucket.
    #[test]
    fn a_remembered_folder_rule_destination_is_seeded_into_its_bucket() {
        let store = windows_store();
        let folder = r"c:\apps\tool\*".to_string();
        assert_eq!(store.seed_many(&[(folder.clone(), ip(203, 0, 113, 40))]), 1);
        assert_eq!(store.ips_for_app(&folder), vec![ip(203, 0, 113, 40)]);
        assert!(store.ips_for_app("*").is_empty());
    }

    #[test]
    fn a_rule_path_is_told_from_a_name() {
        for path in [r"c:\apps\*", r"\\server\share\x.exe", "/opt/app/", "D:/x"] {
            assert!(is_path_pattern(path), "{path}");
            assert_eq!(observation_key(path), path);
        }
        for name in ["chrome.exe", "*vpn*", "", r"\device\x.exe", "C:x"] {
            assert!(!is_path_pattern(name), "{name}");
        }
    }
}
