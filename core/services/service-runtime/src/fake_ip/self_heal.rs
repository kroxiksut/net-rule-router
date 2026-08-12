//! Block D (fake-IP) — VPN self-heal.
//!
//! A VPN client resolves its own server's hostname, gets a fake address like
//! every other in-scope host, and connects to it — so its control channel rides
//! the relay out the primary. It works, but the client shows no real remote
//! address and pays an extra hop for no benefit (the tunnel is exactly the kind
//! of traffic fake-IP has nothing to route per-hostname).
//!
//! We cannot decide this at DNS time: on Windows the system DNS client
//! (`dnscache`, inside `svchost`) issues the query, so the resolver never sees
//! which process asked. But the RELAY does — when a flow is opened we hold its
//! four-tuple, and the OS connection table names the owning process. So the fix
//! lives here: when a relayed flow is owned by a VPN client, the server's
//! hostname is added to a runtime exclusion set and the OS DNS cache is flushed,
//! so the client's NEXT resolution returns the real address and it connects
//! directly. Self-healing on the second connection; nothing severs mid-flow.
//!
//! Everything is best-effort. A failed owner lookup, a full work queue, or a
//! failed flush all just leave the flow relaying as before — self-heal never
//! affects routing correctness, only convenience.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};

use nrr_platform_api::hosts_file::normalize_hostname;
use nrr_platform_api::vpn_discovery::looks_like_vpn;
use nrr_platform_api::FlowOwnerLookup;

use super::stack::FlowObserver;

/// A shared, session-scoped set of hostnames the answerers must keep on their
/// REAL address even though fake-IP is on. Populated at runtime (currently by
/// the VPN self-heal); consulted by both the rule-host and direct-host
/// answerers before they allocate a fake address.
///
/// In-memory only, by design: on a service restart the set is empty again and
/// the self-heal re-detects the VPN's flow and re-excludes its server, which is
/// exactly the "heals on the next connection" contract.
#[derive(Debug, Default)]
pub struct RuntimeHostExclusions {
    hosts: Mutex<HashSet<String>>,
}

impl RuntimeHostExclusions {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// True when `host` (or a parent domain it falls under) is excluded.
    #[must_use]
    pub fn contains(&self, host: &str) -> bool {
        let key = normalize_hostname(host);
        if key.is_empty() {
            return false;
        }
        let hosts = self.hosts.lock().unwrap_or_else(|p| p.into_inner());
        if hosts.contains(&key) {
            return true;
        }
        // A parent-domain exclusion covers its subdomains (mirrors the scope's
        // user-exclusion semantics), so excluding `vpn.example` also spares
        // `gw1.vpn.example`.
        key.match_indices('.').any(|(i, _)| {
            let parent = &key[i + 1..];
            !parent.is_empty() && hosts.contains(parent)
        })
    }

    /// Add `host` to the exclusion set. Returns `true` when it was newly added
    /// (so the caller can flush DNS only on a real change).
    pub fn insert(&self, host: &str) -> bool {
        let key = normalize_hostname(host);
        if key.is_empty() {
            return false;
        }
        self.hosts
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(key)
    }

    /// Number of excluded hostnames (diagnostics / tests).
    #[must_use]
    pub fn len(&self) -> usize {
        self.hosts.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// What one probe concluded — and, with it, whether the host is worth probing
/// again. The distinction matters: an inconclusive probe (the connection-table
/// row vanished before it was read, or the service could not open the process)
/// must NOT retire the host, or one unlucky first flow silently disables the
/// heal for that host for the rest of the session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HealVerdict {
    /// A new exclusion was installed and DNS was flushed.
    Excluded,
    /// Decided, with nothing to do: the owner is not a VPN client, the host is
    /// shared platform infrastructure, it is not a hostname at all, or it was
    /// already excluded. Re-probing would reach the same answer.
    Settled,
    /// Nothing could be decided — the owner is unknown. The host stays eligible
    /// for the next flow that opens against it.
    Inconclusive,
}

/// Look up the owner of one relayed flow and, if it is a VPN client, exclude
/// `hostname` from fake-IP and flush DNS. Synchronous and dependency-injected —
/// the worker thread and the tests both drive this one function, so the decision
/// is provable without threads or a network.
///
/// `confirmed` carries the executables the user pointed at in onboarding; a flow
/// owned by one of them heals even when its file name holds no VPN keyword, and
/// the keyword heuristic stays as the fallback for the un-onboarded case.
pub fn probe_and_heal(
    owner_lookup: &dyn FlowOwnerLookup,
    confirmed: &crate::vpn_client_registry::ConfirmedVpnClients,
    exclusions: &RuntimeHostExclusions,
    flush: &(dyn Fn() + Send + Sync),
    client: SocketAddr,
    fake: SocketAddr,
    hostname: &str,
) -> HealVerdict {
    // A bare address is not a name, so there is nothing for the answerers to
    // keep on its "real" address and nothing a DNS flush could change. The relay
    // reaches this function with a literal for its in-tunnel rescue (a VPN
    // client that bound its in-tunnel socket to our adapter dials e.g.
    // directly) — healing that address would exclude the client's
    // own TUNNEL endpoint instead of its server, burn the one-shot probe slot
    // for the session, and flush the OS resolver cache in the middle of a VPN
    // reconnect.
    if hostname.parse::<std::net::IpAddr>().is_ok() {
        tracing::debug!(
            target: "nrr::fake-ip",
            hostname,
            "relayed flow targets a literal address, not a name — nothing for the self-heal to exclude",
        );
        return HealVerdict::Settled;
    }
    let Some(image) = owner_lookup.owner_image_name(client, fake) else {
        return HealVerdict::Inconclusive;
    };
    if !confirmed.matches_image(&image) && !looks_like_vpn(&image) {
        tracing::debug!(
            target: "nrr::fake-ip",
            hostname,
            image = %image,
            "relayed flow is not a VPN client — leaving it on the relay",
        );
        return HealVerdict::Settled;
    }
    if is_platform_infrastructure(hostname) {
        // A VPN client observed through the relay can touch third-party
        // platform hosts (e.g. a Google API endpoint used for its own
        // config/telemetry); excluding those from fake-IP for the whole
        // session would be wrong — only its tunnel endpoint deserves the
        // exclusion.
        tracing::info!(
            target: "nrr::fake-ip",
            hostname,
            image = %image,
            "relayed VPN-client flow targets shared platform infrastructure — NOT excluding it from fake-IP",
        );
        return HealVerdict::Settled;
    }
    if !exclusions.insert(hostname) {
        // Already excluded — an earlier flow (or the persisted seed) healed it.
        return HealVerdict::Settled;
    }
    flush();
    tracing::info!(
        target: "nrr::fake-ip",
        hostname,
        image = %image,
        "a VPN client is reaching its server through the relay — excluding the server from fake-IP and flushing DNS so it reconnects directly",
    );
    HealVerdict::Excluded
}

/// App-platform / telemetry zones a VPN client routinely contacts that can
/// never BE its tunnel endpoint: nobody hosts an arbitrary TCP/UDP service
/// under these operators' API domains. Curated data, same spirit as
/// `DEFAULT_VPN_EXEMPT_PATTERNS` — kept deliberately short and obvious; a
/// miss just means the host stays on the relay (safe), while a false
/// exclusion silently rips a shared host out of fake-IP for everyone.
const PLATFORM_INFRASTRUCTURE_SUFFIXES: &[&str] = &[
    "googleapis.com",
    "gstatic.com",
    "google-analytics.com",
    "app-measurement.com",
    "firebaseio.com",
    "crashlytics.com",
    "doubleclick.net",
    "sentry.io",
    "segment.io",
    "segment.com",
    "appsflyer.com",
    "adjust.com",
    "onesignal.com",
    "microsoft.com",
    "windows.com",
    "apple.com",
    "icloud.com",
];

/// True when `hostname` equals one of the platform zones or sits under one.
///
/// `pub(crate)` because the companion-domain learner needs the SAME list: a
/// telemetry or app-platform host that shows up alongside a routed site must
/// never be suggested as one of that site's companions, for exactly the reason
/// it is not a VPN endpoint here — it belongs to everybody, so pinning it to one
/// site's route would drag unrelated traffic along. One list, two consumers.
pub(crate) fn is_platform_infrastructure(hostname: &str) -> bool {
    let key = normalize_hostname(hostname);
    if key.is_empty() {
        return false;
    }
    PLATFORM_INFRASTRUCTURE_SUFFIXES.iter().any(|suffix| {
        key == *suffix
            || key
                .strip_suffix(suffix)
                .is_some_and(|prefix| prefix.ends_with('.'))
    })
}

/// One unit of self-heal work handed from the poll loop to the worker.
struct HealJob {
    client: SocketAddr,
    fake: SocketAddr,
    hostname: String,
}

/// Production [`FlowObserver`]: off-loads each freshly opened flow to a single
/// background worker that runs [`probe_and_heal`]. The poll loop only does a
/// cheap channel send, so a slow connection-table read never stalls the stack.
///
/// The worker de-duplicates by hostname, so a browsing session probes each
/// distinct host at most once, and the bounded queue drops work under a burst
/// rather than growing without limit (a dropped probe just means the host is
/// re-examined the next time it opens a flow).
pub struct VpnSelfHealObserver {
    tx: SyncSender<HealJob>,
}

/// Callback invoked with the hostname of each NEWLY installed exclusion, so
/// the caller can persist it — without persistence every service session
/// would pay one failed VPN connect to re-learn the same server.
pub type HealPersistFn = Arc<dyn Fn(&str) + Send + Sync>;

impl VpnSelfHealObserver {
    /// Bound on the hand-off queue. A VPN reconnect opens a handful of flows;
    /// this covers a burst while capping the memory an unresponsive worker can
    /// pin. Overflow is dropped (best-effort).
    const QUEUE_DEPTH: usize = 64;

    /// How many times one hostname may be probed before it is retired. Only
    /// INCONCLUSIVE probes consume an attempt (a decided host is retired at
    /// once), so this bounds the cost of a host whose owner never resolves —
    /// three chances is enough for the client's reconnect to be caught while
    /// keeping a scan from re-reading the connection table indefinitely.
    const MAX_INCONCLUSIVE_PROBES: u8 = 3;

    /// Ceiling on the per-hostname probe ledger. A long browsing session touches
    /// thousands of names; at the cap the ledger is cleared rather than grown —
    /// the worst effect is that a few hosts are probed once more.
    const LEDGER_CAPACITY: usize = 4096;

    #[must_use]
    pub fn new(
        owner_lookup: Arc<dyn FlowOwnerLookup>,
        confirmed: Arc<crate::vpn_client_registry::ConfirmedVpnClients>,
        exclusions: Arc<RuntimeHostExclusions>,
        flush: Arc<dyn Fn() + Send + Sync>,
        persist: Option<HealPersistFn>,
    ) -> Self {
        let (tx, rx) = sync_channel::<HealJob>(Self::QUEUE_DEPTH);
        std::thread::spawn(move || {
            // Per-hostname probe ledger for this stack lifetime. A host is
            // retired the moment a probe DECIDES it (healed, or provably not a
            // VPN client's); an inconclusive probe — the owner could not be
            // named — leaves it eligible, because the very first flow to a host
            // is the one most likely to race the connection table.
            let mut attempts: HashMap<String, u8> = HashMap::new();
            while let Ok(job) = rx.recv() {
                let key = normalize_hostname(&job.hostname);
                if key.is_empty() {
                    continue;
                }
                if attempts.len() >= Self::LEDGER_CAPACITY {
                    attempts.clear();
                }
                match attempts.get(&key) {
                    Some(&count) if count >= Self::MAX_INCONCLUSIVE_PROBES => continue,
                    _ => {}
                }
                let verdict = probe_and_heal(
                    owner_lookup.as_ref(),
                    confirmed.as_ref(),
                    exclusions.as_ref(),
                    flush.as_ref(),
                    job.client,
                    job.fake,
                    &job.hostname,
                );
                match verdict {
                    HealVerdict::Excluded => {
                        attempts.insert(key, Self::MAX_INCONCLUSIVE_PROBES);
                        if let Some(persist) = persist.as_ref() {
                            persist(&job.hostname);
                        }
                    }
                    HealVerdict::Settled => {
                        attempts.insert(key, Self::MAX_INCONCLUSIVE_PROBES);
                    }
                    HealVerdict::Inconclusive => {
                        let entry = attempts.entry(key).or_insert(0);
                        *entry = entry.saturating_add(1);
                    }
                }
            }
        });
        Self { tx }
    }
}

impl FlowObserver for VpnSelfHealObserver {
    fn on_flow_opened(&self, client: SocketAddr, fake: SocketAddr, hostname: &str) {
        // A literal address has nothing to heal (see `probe_and_heal`), and the
        // in-tunnel rescue produces one per flow — declining here keeps those
        // out of the queue instead of letting them crowd out real hostnames,
        // and spares the poll thread the string allocation below.
        if hostname.parse::<std::net::IpAddr>().is_ok() {
            return;
        }
        // Best-effort: drop on a full queue or a dead worker rather than block
        // the poll loop. A dropped probe is retried on the host's next flow.
        match self.tx.try_send(HealJob {
            client,
            fake,
            hostname: hostname.to_string(),
        }) {
            Ok(()) | Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vpn_client_registry::ConfirmedVpnClients;
    use nrr_platform_api::MockFlowOwnerLookup;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn addr(s: &str) -> SocketAddr {
        s.parse().expect("addr")
    }

    /// The common case in these tests: the user has confirmed nothing, so the
    /// keyword heuristic alone decides.
    fn no_confirmations() -> ConfirmedVpnClients {
        ConfirmedVpnClients::new()
    }

    #[test]
    fn exclusions_cover_subdomains_and_normalize() {
        let ex = RuntimeHostExclusions::new();
        assert!(ex.insert("VPN.Example.COM."));
        assert!(ex.contains("vpn.example.com"));
        // A subdomain of an excluded host is covered.
        assert!(ex.contains("gw1.vpn.example.com"));
        // An unrelated host is not.
        assert!(!ex.contains("example.com"));
        // Re-inserting the same host is not a new change.
        assert!(!ex.insert("vpn.example.com"));
        assert_eq!(ex.len(), 1);
    }

    #[test]
    fn a_vpn_owned_flow_excludes_the_host_and_flushes() {
        let owner = MockFlowOwnerLookup::new();
        let client = addr("10.0.0.2:51000");
        let fake = addr("198.18.0.7:443");
        owner.set_owner(client, fake, "wireguard.exe");
        let ex = RuntimeHostExclusions::new();
        let flushes = Arc::new(AtomicU32::new(0));
        let flush = {
            let flushes = Arc::clone(&flushes);
            move || {
                flushes.fetch_add(1, Ordering::SeqCst);
            }
        };

        let confirmed = no_confirmations();
        let healed = probe_and_heal(
            &owner,
            &confirmed,
            &ex,
            &flush,
            client,
            fake,
            "vpn.example.com",
        );
        assert_eq!(healed, HealVerdict::Excluded, "a VPN-owned flow must heal");
        assert!(ex.contains("vpn.example.com"));
        assert_eq!(flushes.load(Ordering::SeqCst), 1);

        // A second flow to the already-excluded host does not flush again.
        let again = probe_and_heal(
            &owner,
            &confirmed,
            &ex,
            &flush,
            client,
            fake,
            "vpn.example.com",
        );
        assert_eq!(again, HealVerdict::Settled);
        assert_eq!(flushes.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_user_confirmed_client_heals_even_without_a_vpn_keyword_in_its_name() {
        // The keyword heuristic misses a client whose file name says nothing
        // about tunnels; the user's own confirmation does not.
        let owner = MockFlowOwnerLookup::new();
        let client = addr("10.0.0.2:51000");
        let fake = addr("198.18.0.21:443");
        owner.set_owner(client, fake, "hm.exe");
        let confirmed = ConfirmedVpnClients::new();
        confirmed.publish("S-1-5-21-1", &[r"C:\Apps\hm.exe".to_string()]);
        let ex = RuntimeHostExclusions::new();
        let flushes = Arc::new(AtomicU32::new(0));
        let flush = {
            let flushes = Arc::clone(&flushes);
            move || {
                flushes.fetch_add(1, Ordering::SeqCst);
            }
        };

        assert_eq!(
            probe_and_heal(
                &owner,
                &confirmed,
                &ex,
                &flush,
                client,
                fake,
                "gw.example.net"
            ),
            HealVerdict::Excluded
        );
        assert!(ex.contains("gw.example.net"));
        assert_eq!(flushes.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_literal_destination_is_never_healed_or_flushed() {
        // The in-tunnel rescue hands the observer the VPN's own tunnel
        // address. Excluding it from fake-IP is meaningless — it was never a
        // name — and a DNS flush here would land in the middle of the
        // client's reconnect.
        let owner = MockFlowOwnerLookup::new();
        let client = addr("10.0.0.2:51000");
        let tunnel = addr("10.117.0.1:80");
        owner.set_owner(client, tunnel, "hidemy.name vpn 3.0.exe");
        let ex = RuntimeHostExclusions::new();
        let flush = || panic!("must not flush the OS resolver cache for a literal address");

        assert_eq!(
            probe_and_heal(
                &owner,
                &no_confirmations(),
                &ex,
                &flush,
                client,
                tunnel,
                "10.117.0.1"
            ),
            HealVerdict::Settled
        );
        assert!(ex.is_empty());
    }

    #[test]
    fn a_non_vpn_flow_is_left_alone() {
        let owner = MockFlowOwnerLookup::new();
        let client = addr("10.0.0.2:51000");
        let fake = addr("198.18.0.9:443");
        owner.set_owner(client, fake, "chrome.exe");
        let ex = RuntimeHostExclusions::new();
        let flush = || panic!("must not flush for a non-VPN flow");

        let healed = probe_and_heal(
            &owner,
            &no_confirmations(),
            &ex,
            &flush,
            client,
            fake,
            "chatgpt.com",
        );
        assert_eq!(healed, HealVerdict::Settled);
        assert!(ex.is_empty());
    }

    #[test]
    fn a_vpn_flow_to_platform_infrastructure_is_not_excluded() {
        // A VPN client fetching a shared platform host (e.g. a Google API
        // used for its own config/telemetry) through the relay must not rip
        // that host out of fake-IP or trigger a DNS flush.
        let owner = MockFlowOwnerLookup::new();
        let client = addr("10.0.0.2:51000");
        let fake = addr("198.18.0.11:443");
        owner.set_owner(client, fake, "hidemy.name vpn 3.0.exe");
        let ex = RuntimeHostExclusions::new();
        let flush = || panic!("must not flush for platform infrastructure");

        let healed = probe_and_heal(
            &owner,
            &no_confirmations(),
            &ex,
            &flush,
            client,
            fake,
            "firebaseremoteconfig.googleapis.com",
        );
        assert_eq!(healed, HealVerdict::Settled);
        assert!(ex.is_empty());
    }

    #[test]
    fn platform_infrastructure_matches_suffix_not_substring() {
        assert!(is_platform_infrastructure("googleapis.com"));
        assert!(is_platform_infrastructure(
            "Firebaseremoteconfig.GoogleAPIs.com."
        ));
        // Suffix must sit on a label boundary: a registrable domain that
        // merely ends with the same letters is NOT platform infrastructure.
        assert!(!is_platform_infrastructure("mygoogleapis.com"));
        assert!(!is_platform_infrastructure("vpn.example.com"));
        assert!(!is_platform_infrastructure(""));
    }

    #[test]
    fn an_unknown_owner_leaves_the_host_eligible_for_another_probe() {
        let owner = MockFlowOwnerLookup::new(); // no entries → None
        let ex = RuntimeHostExclusions::new();
        let flush = || panic!("must not flush when the owner is unknown");
        let healed = probe_and_heal(
            &owner,
            &no_confirmations(),
            &ex,
            &flush,
            addr("10.0.0.2:51000"),
            addr("198.18.0.7:443"),
            "chatgpt.com",
        );
        // NOT `Settled`: the connection-table row can vanish before it is read,
        // and one unlucky first flow must not retire the host for the session.
        assert_eq!(healed, HealVerdict::Inconclusive);
        assert!(ex.is_empty());
    }
}
