//! The local DNS resolver on Linux: the neutral assembly
//! (`nrr_service_runtime::dns_stack`) over whichever mechanism writes the
//! machine's `resolv.conf`.
//!
//! Where no mechanism can be used, nothing here arms and the DoH lockdown
//! stays forced: without our listener answering, the canary that turns browser
//! DoH off is never served.

#![cfg(target_os = "linux")]

use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::time::Duration;

use nrr_platform_api::dns::{DnsResolverPort, SystemDnsServersPort, UpstreamDnsCandidate};
use nrr_platform_api::network_change::{
    NetworkChangeCallback, NetworkChangeObserver, NetworkChangeSubscription,
};
use nrr_platform_linux::dns_redirect::{
    clear_every_redirect, detect_capture_method, DnsCaptureMethod, DnsCaptureParts,
    DnsCaptureSelector, DnsFiles, SystemDnsCommands,
};
use nrr_service_runtime::dns_resolver_service::{
    ArmRefusal, DnsResolverController, DnsResolverFactory,
};
use nrr_service_runtime::dns_stack::{DnsStackInputs, DnsStackPlatform};
use nrr_service_runtime::dns_upstream::{UdpUpstreamProbe, UpstreamDnsPool};

/// Can the machine's DNS be taken over, as found at start-up. The resolver
/// asks again on every arm; this answer gates what has no resolver to re-arm.
#[derive(Clone)]
pub(crate) enum DnsCapture {
    Via(Arc<CaptureMechanism>),
    /// No `resolv.conf` to point anywhere: the machine's DNS is left alone.
    Unavailable,
}

impl DnsCapture {
    pub(crate) fn answers_dns(&self) -> bool {
        matches!(self, Self::Via(_))
    }

    /// Whether systemd-resolved holds the machine's DNS cache, the one cache
    /// the service can flush.
    pub(crate) fn caches_in_resolved(&self) -> bool {
        matches!(self, Self::Via(m) if matches!(m.method, DnsCaptureMethod::Resolved))
    }
}

/// One set of mechanism parts per process: the resolver arms through them and
/// the service's own lookups read the servers they follow.
pub(crate) struct CaptureMechanism {
    selector: DnsCaptureSelector<SystemDnsCommands>,
    method: DnsCaptureMethod,
    parts: DnsCaptureParts,
    /// Follows the mechanism the resolver last armed through.
    servers: Arc<FollowingServers>,
}

impl CaptureMechanism {
    fn new(method: DnsCaptureMethod, files: DnsFiles) -> Self {
        let selector = DnsCaptureSelector::new(method, SystemDnsCommands, files);
        let parts = selector.parts(method);
        let servers = Arc::new(FollowingServers::new(Arc::clone(&parts.servers)));
        Self {
            selector,
            method,
            parts,
            servers,
        }
    }
}

/// Undo what a previous run left behind, then decide what this run can do.
/// The cleanup runs whatever the answer: a crashed run's redirect must not
/// outlive it even if the machine has since been reconfigured.
pub(crate) fn prepare_dns_capture(data_dir: &Path) -> DnsCapture {
    let files = DnsFiles::system(data_dir);
    if let Err(e) = clear_every_redirect(SystemDnsCommands, &files) {
        tracing::warn!(
            target: "nrr::dns-resolver",
            msg_key = "linux-svc-dns-redirect-undo-failed",
            error = %e,
            "could not undo a previous run's DNS redirect",
        );
    }
    match detect_capture_method(&SystemDnsCommands, &files) {
        Some(method) => {
            tracing::info!(
                target: "nrr::dns-resolver",
                msg_key = "linux-svc-dns-mechanism-available",
                mechanism = method.name(),
                "the local DNS resolver can arm through this machine's DNS mechanism",
            );
            DnsCapture::Via(Arc::new(CaptureMechanism::new(method, files)))
        }
        None => {
            tracing::warn!(
                target: "nrr::dns-resolver",
                msg_key = "linux-svc-dns-mechanism-unavailable",
                "no DNS mechanism this service can point at its listener; the local DNS resolver stays off and browser DoH stays blocked",
            );
            DnsCapture::Unavailable
        }
    }
}

/// The same undo, for the unit's stop hook and `uninstall`: the process that
/// set it up may have died without restoring.
pub(crate) fn clear_dns_redirect(data_dir: &Path) -> Result<(), String> {
    clear_every_redirect(SystemDnsCommands, &DnsFiles::system(data_dir)).map_err(|e| e.to_string())
}

/// The process-wide upstream choice: it outlives resolver restarts.
fn upstream_dns_pool(
    servers: Arc<dyn nrr_platform_api::dns::SystemDnsServersPort>,
) -> Arc<UpstreamDnsPool> {
    static POOL: std::sync::OnceLock<Arc<UpstreamDnsPool>> = std::sync::OnceLock::new();
    Arc::clone(POOL.get_or_init(|| {
        let pool = UpstreamDnsPool::new(servers, Arc::new(UdpUpstreamProbe::default()));
        // A corporate tunnel's resolver answers for its own names only. The
        // routing pass publishes the tunnels and their networks.
        pool.follow_foreign_tunnels(nrr_service_runtime::foreign_tunnels::global_foreign_tunnels());
        Arc::new(pool)
    }))
}

/// Run after every routing pass: re-selects the upstream, off the pass's
/// thread, when the pass moved the foreign tunnels. Nothing per query.
pub(crate) fn upstream_follower(
    capture: &DnsCapture,
    controller: Arc<DnsResolverController>,
) -> Option<Arc<dyn Fn() + Send + Sync>> {
    let DnsCapture::Via(mechanism) = capture else {
        return None;
    };
    let pool = upstream_dns_pool(Arc::clone(&mechanism.servers) as _);
    Some(Arc::new(move || {
        let controller = Arc::clone(&controller);
        pool.note_excluded_change_in_background(move |upstream| {
            controller.note_upstream_present(upstream.is_some());
            controller.tick();
        });
    }))
}

/// The servers of whichever mechanism the resolver was last armed through, so
/// the upstream pool and the service's own lookups follow a change of mechanism.
struct FollowingServers {
    current: RwLock<Arc<dyn SystemDnsServersPort>>,
    /// Told when `follow` moves to another mechanism: a cache over this port
    /// would otherwise keep the old mechanism's list until the next change.
    switched: Mutex<Vec<(u64, NetworkChangeCallback)>>,
    next_subscriber: AtomicU64,
}

impl FollowingServers {
    fn new(servers: Arc<dyn SystemDnsServersPort>) -> Self {
        Self {
            current: RwLock::new(servers),
            switched: Mutex::new(Vec::new()),
            next_subscriber: AtomicU64::new(0),
        }
    }

    fn current(&self) -> Arc<dyn SystemDnsServersPort> {
        Arc::clone(&self.current.read().unwrap_or_else(|p| p.into_inner()))
    }

    fn follow(&self, servers: Arc<dyn SystemDnsServersPort>) {
        {
            let mut current = self.current.write().unwrap_or_else(|p| p.into_inner());
            if std::ptr::addr_eq(Arc::as_ptr(&current), Arc::as_ptr(&servers)) {
                return;
            }
            *current = servers;
        }
        // Called outside both locks: a callback may read this port.
        let callbacks: Vec<NetworkChangeCallback> = self
            .switched
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .map(|(_, callback)| Arc::clone(callback))
            .collect();
        for callback in callbacks {
            callback();
        }
    }
}

impl SystemDnsServersPort for FollowingServers {
    fn upstream_candidates_v4(&self) -> Vec<UpstreamDnsCandidate> {
        self.current().upstream_candidates_v4()
    }

    fn upstream_candidates_v4_within(&self, budget: Duration) -> Vec<UpstreamDnsCandidate> {
        self.current().upstream_candidates_v4_within(budget)
    }

    fn upstream_candidates_v6(&self) -> Vec<nrr_platform_api::dns::UpstreamDnsServer> {
        self.current().upstream_candidates_v6()
    }

    fn upstream_candidates_v4_per_link(&self) -> Vec<UpstreamDnsCandidate> {
        self.current().upstream_candidates_v4_per_link()
    }

    fn upstream_candidates_v6_per_link(&self) -> Vec<nrr_platform_api::dns::UpstreamDnsServer> {
        self.current().upstream_candidates_v6_per_link()
    }

    fn report_all_unreachable(&self, servers: &[UpstreamDnsCandidate]) {
        self.current().report_all_unreachable(servers);
    }
}

/// The network-change feed plus a change of mechanism: to a cache over
/// [`FollowingServers`] a switch from NetworkManager to a plain file is as much
/// a change as a new link. Fails only when the network feed does.
struct NetworkOrMechanismChange<'a> {
    network: &'a dyn NetworkChangeObserver,
    mechanism: &'a Arc<FollowingServers>,
}

impl NetworkChangeObserver for NetworkOrMechanismChange<'_> {
    fn subscribe(
        &self,
        on_change: NetworkChangeCallback,
    ) -> Result<NetworkChangeSubscription, nrr_platform_api::error::PlatformError> {
        let network = self.network.subscribe(Arc::clone(&on_change))?;
        let id = self
            .mechanism
            .next_subscriber
            .fetch_add(1, Ordering::Relaxed);
        self.mechanism
            .switched
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push((id, on_change));
        Ok(NetworkChangeSubscription::new(Box::new(
            MechanismSubscription {
                _network: network,
                following: Arc::downgrade(self.mechanism),
                id,
            },
        )))
    }
}

struct MechanismSubscription {
    _network: NetworkChangeSubscription,
    following: Weak<FollowingServers>,
    id: u64,
}

impl Drop for MechanismSubscription {
    fn drop(&mut self) {
        if let Some(following) = self.following.upgrade() {
            following
                .switched
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .retain(|(id, _)| *id != self.id);
        }
    }
}

/// One mechanism's build, kept until a re-arm finds another mechanism.
struct ArmedThrough {
    method: DnsCaptureMethod,
    build: DnsResolverFactory,
    prepare: Arc<dyn Fn() -> Result<(), nrr_platform_api::error::PlatformError> + Send + Sync>,
}

/// The resolver controller with its factory, when the machine allows one.
///
/// Every (re)arm asks the machine for its mechanism again: an arm follows a
/// stop or a dead resolver, whose redirect is already undone, so the answer is
/// about the machine and not about us.
pub(crate) fn resolver_controller(
    capture: &DnsCapture,
    inputs: DnsStackInputs,
) -> Option<Arc<DnsResolverController>> {
    let DnsCapture::Via(mechanism) = capture else {
        return None;
    };
    let mechanism = Arc::clone(mechanism);
    let sign_in_probe = inputs.signed_in.clone();
    let servers = Arc::clone(&mechanism.servers);
    let pool = upstream_dns_pool(Arc::clone(&servers) as _);
    let armed = Mutex::new(armed_through(
        mechanism.method,
        mechanism.parts.clone(),
        &inputs,
        &servers,
        &pool,
    ));
    let factory: DnsResolverFactory = Arc::new(move || {
        let selector = &mechanism.selector;
        let (method, _) = selector.redetect();
        let mut armed = armed.lock().unwrap_or_else(|p| p.into_inner());
        if armed.method != method {
            tracing::info!(
                target: "nrr::dns-resolver",
                msg_key = "linux-svc-dns-mechanism-changed",
                from = armed.method.name(),
                to = method.name(),
                "the machine's DNS mechanism changed; the local resolver arms through the new one",
            );
            *armed = armed_through(method, selector.parts(method), &inputs, &servers, &pool);
        }
        if let Err(e) = (armed.prepare)() {
            tracing::warn!(
                target: "nrr::dns-resolver",
                msg_key = "linux-svc-dns-listener-prepare-failed",
                error = %e,
                "the DNS listener's address could not be prepared; the local resolver stays off",
            );
            return Err(ArmRefusal::Unavailable);
        }
        (armed.build)()
    });
    let controller = Arc::new(DnsResolverController::new());
    controller.set_factory(factory);
    if let Some(probe) = sign_in_probe {
        controller.set_sign_in_probe(probe);
    }
    Some(controller)
}

fn armed_through(
    method: DnsCaptureMethod,
    parts: DnsCaptureParts,
    inputs: &DnsStackInputs,
    servers: &Arc<FollowingServers>,
    pool: &Arc<UpstreamDnsPool>,
) -> ArmedThrough {
    servers.follow(Arc::clone(&parts.servers));
    let scopes = Arc::clone(&parts.scopes);
    let platform = DnsStackPlatform {
        // The answer path reads it per NXDOMAIN and one read can be `nmcli` or
        // `resolvectl`. Per mechanism, so a change of mechanism reads afresh;
        // the pool keeps following the uncached port. The DNS-config feed
        // catches a domain a VPN client pushes after its link is already up.
        system_dns: nrr_service_runtime::dns_stack::cached_system_dns(
            Arc::clone(&parts.servers),
            &nrr_platform_linux::network_change::LinuxNetworkChangeObserver,
            &nrr_platform_linux::dns_config_change::LinuxDnsConfigChangeObserver::default(),
        ),
        upstream_pool: Arc::clone(pool),
        redirect: parts.redirect,
        listen_addr: parts.listener,
        // Every claim with the kind of link behind it; the neutral stack
        // decides which ones the redirect honours.
        claimed_namespaces: Arc::new(move || {
            use nrr_platform_api::route_table::RouteTablePort;
            let api = nrr_platform_linux::LinuxApi;
            // No route table, no uplink to tell apart: nothing reads as foreign.
            let (adapters, routes) = match api.get_ip_forward_table() {
                Ok(routes) => (api.get_adapter_infos().unwrap_or_default(), routes),
                Err(_) => (Vec::new(), Vec::new()),
            };
            // Our own links as the route coordinator last named them.
            let ours = nrr_service_runtime::foreign_tunnels::global_foreign_tunnels().own_links();
            nrr_platform_api::dns_scope::classify_claims(
                scopes.dns_scopes(),
                &adapters,
                &routes,
                &ours,
            )
        }),
        network_changes: Arc::new(nrr_platform_linux::network_change::LinuxNetworkChangeObserver),
        // A VPN's domain reaches the DNS manager after its link is up.
        dns_config_changes: Arc::new(
            nrr_platform_linux::dns_config_change::LinuxDnsConfigChangeObserver::default(),
        ),
    };
    ArmedThrough {
        method,
        build: nrr_service_runtime::dns_stack::build_dns_resolver_factory(inputs.clone(), platform),
        // The listener binds the mechanism's address, so it is readied before
        // every build — including a rebuild after something removed it.
        prepare: parts.prepare,
    }
}

/// The resolver the service itself uses to look names up: the mechanism's own
/// servers under the redirect, since `/etc/resolv.conf` then leads to us.
///
/// Built once and shared: reading those servers can start a child process, so
/// the list is kept until the network, the DNS configuration or the mechanism
/// changes rather than re-read per name. It keeps a cache of its own rather than the
/// listener's `system_dns`: it is needed whenever `capture` answers DNS,
/// including runs where `resolver_controller` is `None`.
pub(crate) fn service_dns_resolver(
    capture: &DnsCapture,
) -> Arc<nrr_platform_linux::dns_resolver::LinuxDnsResolver> {
    use nrr_platform_linux::dns_resolver::LinuxDnsResolver;

    let DnsCapture::Via(mechanism) = capture else {
        return Arc::new(LinuxDnsResolver::new());
    };
    let servers = cached_service_servers(
        Arc::clone(&mechanism.servers) as _,
        &NetworkOrMechanismChange {
            network: &nrr_platform_linux::network_change::LinuxNetworkChangeObserver,
            mechanism: &mechanism.servers,
        },
        &nrr_platform_linux::dns_config_change::LinuxDnsConfigChangeObserver::default(),
    );
    Arc::new(LinuxDnsResolver::with_servers(Box::new(servers)))
}

/// How long one direct query to the chosen upstream may take before the
/// hosts-honouring path answers instead. Matches the other platform.
const HOSTS_BYPASS_QUERY_TIMEOUT: Duration = Duration::from_millis(1500);

/// The resolver behind the per-user `resolve_hosts_bypass` setting, for rule
/// hosts: the seeder, the refresh and the history import.
///
/// Bypass on: the host is asked of the upstream the pool chose, over a raw
/// socket, so a hosts-file pin never costs a rule its routable address. Bypass
/// off: `/etc/hosts` answers first, as the C library would. With no mechanism
/// there is no chosen upstream, and both postures read the file first.
pub(crate) fn rule_host_resolver(
    capture: &DnsCapture,
    servers: Arc<nrr_platform_linux::dns_resolver::LinuxDnsResolver>,
    bypass_enabled: Arc<dyn Fn() -> bool + Send + Sync>,
    egress: Arc<dyn nrr_service_runtime::dns_egress::DnsEgressPolicy>,
) -> Arc<dyn DnsResolverPort> {
    use nrr_platform_linux::dns_resolver::HostsFileFirstResolver;
    use nrr_service_runtime::dns_resolver_ports::HostsBypassDnsResolver;

    let system: Arc<dyn DnsResolverPort> = Arc::new(HostsFileFirstResolver::new(servers as _));
    let upstream: Arc<dyn Fn() -> Option<SocketAddr> + Send + Sync> = match capture {
        DnsCapture::Via(mechanism) => {
            let pool = upstream_dns_pool(Arc::clone(&mechanism.servers) as _);
            Arc::new(move || pool.current_or_select())
        }
        DnsCapture::Unavailable => Arc::new(|| None),
    };
    Arc::new(
        HostsBypassDnsResolver::new(system, bypass_enabled, upstream, HOSTS_BYPASS_QUERY_TIMEOUT)
            .with_hosts(Arc::new(
                nrr_platform_api::hosts_file::OsHostsFileReader::new(),
            ))
            .with_egress(egress),
    )
}

/// Same helper and same two feeds as the listener's own `system_dns` cache
/// (`armed_through`): a server pushed by DHCP or by a VPN client after its
/// link is already up reaches the service's own lookups without waiting for a
/// network-change event.
fn cached_service_servers(
    raw: Arc<dyn SystemDnsServersPort>,
    network: &dyn nrr_platform_api::network_change::NetworkChangeObserver,
    dns_config: &dyn nrr_platform_api::dns_config_change::DnsConfigChangeObserver,
) -> Arc<dyn SystemDnsServersPort> {
    nrr_service_runtime::dns_stack::cached_system_dns(raw, network, dns_config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_platform_api::dns_config_change::DnsConfigChangeObserver;
    use nrr_platform_api::error::PlatformError;
    use nrr_platform_api::network_change::{
        NetworkChangeCallback, NetworkChangeObserver, NetworkChangeSubscription,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingServers {
        calls: AtomicUsize,
        answer: Vec<UpstreamDnsCandidate>,
    }

    impl CountingServers {
        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl SystemDnsServersPort for CountingServers {
        fn upstream_candidates_v4(&self) -> Vec<UpstreamDnsCandidate> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.answer.clone()
        }
    }

    /// Hands the test the callback the OS would call.
    #[derive(Default)]
    struct ManualObserver(Mutex<Option<NetworkChangeCallback>>);

    impl ManualObserver {
        fn fire(&self) {
            let callback = self.0.lock().expect("observer").clone();
            if let Some(callback) = callback {
                callback();
            }
        }
    }

    impl NetworkChangeObserver for ManualObserver {
        fn subscribe(
            &self,
            on_change: NetworkChangeCallback,
        ) -> Result<NetworkChangeSubscription, PlatformError> {
            *self.0.lock().expect("observer") = Some(on_change);
            Ok(NetworkChangeSubscription::inert())
        }
    }

    impl DnsConfigChangeObserver for ManualObserver {
        fn subscribe(
            &self,
            on_change: NetworkChangeCallback,
        ) -> Result<NetworkChangeSubscription, PlatformError> {
            NetworkChangeObserver::subscribe(self, on_change)
        }
    }

    /// A server pushed by DHCP or a VPN client with no link event must still
    /// reach the service's own lookups: the DNS-config feed alone re-reads it.
    #[test]
    fn a_dns_config_change_reaches_the_services_own_lookups() {
        let inner = Arc::new(CountingServers {
            calls: AtomicUsize::new(0),
            answer: vec![UpstreamDnsCandidate::new(
                None,
                std::net::Ipv4Addr::new(192, 0, 2, 53),
            )],
        });
        let network = ManualObserver::default();
        let dns_config = ManualObserver::default();
        let servers = cached_service_servers(Arc::clone(&inner) as _, &network, &dns_config);

        assert_eq!(servers.upstream_candidates_v4().len(), 1);
        assert_eq!(inner.calls(), 1, "one warm-up enumeration");

        assert_eq!(servers.upstream_candidates_v4().len(), 1);
        assert_eq!(inner.calls(), 1, "cached: no event since the warm-up");

        dns_config.fire();
        assert_eq!(servers.upstream_candidates_v4().len(), 1);
        assert_eq!(inner.calls(), 2, "the DNS-config feed alone re-read it");
    }

    fn counting(server: std::net::Ipv4Addr) -> Arc<CountingServers> {
        Arc::new(CountingServers {
            calls: AtomicUsize::new(0),
            answer: vec![UpstreamDnsCandidate::new(None, server)],
        })
    }

    fn addresses(servers: &dyn SystemDnsServersPort) -> Vec<std::net::Ipv4Addr> {
        servers
            .upstream_candidates_v4()
            .into_iter()
            .map(|c| c.server)
            .collect()
    }

    /// NetworkManager's device servers must not outlive a switch to a plain
    /// file: the switch alone re-reads, with no network or DNS-config event.
    #[test]
    fn a_change_of_mechanism_re_reads_the_services_own_servers() {
        let manager = counting(std::net::Ipv4Addr::new(192, 0, 2, 53));
        let file = counting(std::net::Ipv4Addr::new(198, 51, 100, 53));
        let following = Arc::new(FollowingServers::new(Arc::clone(&manager) as _));
        let network = ManualObserver::default();
        let servers = cached_service_servers(
            Arc::clone(&following) as _,
            &NetworkOrMechanismChange {
                network: &network,
                mechanism: &following,
            },
            &nrr_platform_api::dns_config_change::NoopDnsConfigChangeObserver,
        );

        assert_eq!(
            addresses(&*servers),
            manager.answer.iter().map(|c| c.server).collect::<Vec<_>>()
        );
        following.follow(Arc::clone(&manager) as _);
        assert_eq!(addresses(&*servers).len(), 1);
        assert_eq!(
            manager.calls(),
            1,
            "re-arming the same mechanism is no change"
        );

        following.follow(Arc::clone(&file) as _);
        assert_eq!(
            addresses(&*servers),
            vec![std::net::Ipv4Addr::new(198, 51, 100, 53)]
        );
        assert_eq!(file.calls(), 1);
        assert_eq!(manager.calls(), 1);

        // The network feed still works through the combined observer.
        network.fire();
        assert_eq!(addresses(&*servers).len(), 1);
        assert_eq!(file.calls(), 2);
    }
}
