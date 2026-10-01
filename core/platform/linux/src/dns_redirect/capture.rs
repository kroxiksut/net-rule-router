//! Which mechanism takes the machine's DNS, asked again on every arm, and the
//! cleanup that undoes any of them.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use nrr_platform_api::dns::{SystemDnsServersPort, UpstreamDnsCandidate};
use nrr_platform_api::dns_redirect::{
    DnsNamespaceExemption, RedirectHandle, RedirectState, SystemDnsRedirectPort,
};
use nrr_platform_api::dns_scope::{InterfaceDnsScope, InterfaceDnsScopePort};
use nrr_platform_api::error::PlatformError;

use super::network_manager::{
    clear_network_manager_redirect, network_manager_redirect_available, NetworkManagerDnsRedirect,
    NetworkManagerDnsScopes, NetworkManagerDnsServers,
};
use super::resolv_conf::{restore_system_file, ResolvConfFileRedirect, ResolvConfFileServers};
use super::resolvconf::{
    clear_resolvconf_redirect, resolvconf_redirect_available, ResolvconfDnsRedirect,
    ResolvconfDnsServers,
};
use super::{
    clear_orphan_redirect, resolv_conf_names_resolved_stub, resolved_carries_programs, DnsCommands,
    DnsFiles, ResolvedDnsRedirect, ResolvedDnsScopes, ResolvedDnsServers, LISTENER_ADDR,
    LOOPBACK_LISTENER_ADDR,
};

/// Who writes `/etc/resolv.conf`, and so where our listener goes in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnsCaptureMethod {
    /// systemd-resolved in stub or static mode.
    Resolved,
    /// NetworkManager, with nothing between it and the file.
    NetworkManager,
    /// Debian's resolvconf or openresolv.
    Resolvconf,
    /// Nobody: the file is replaced and put back.
    ResolvConfFile,
}

impl DnsCaptureMethod {
    /// Where the listener binds for this mechanism.
    pub fn listener(self) -> SocketAddr {
        match self {
            Self::Resolved => LISTENER_ADDR,
            Self::NetworkManager | Self::Resolvconf | Self::ResolvConfFile => {
                LOOPBACK_LISTENER_ADDR
            }
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Resolved => "systemd-resolved",
            Self::NetworkManager => "NetworkManager",
            Self::Resolvconf => "resolvconf",
            Self::ResolvConfFile => "resolv.conf",
        }
    }
}

/// The most specific mechanism first: each later one would also "work" on a
/// machine an earlier one manages, and be overwritten by it.
///
/// A file pointing at resolved's stub means resolved even while resolved does
/// not answer yet: taking that file over instead would replace resolved's
/// symlink and forward to its stub, i.e. to ourselves. The redirect then
/// fails until resolved is up, and the resolver's re-arm retries it.
pub fn detect_capture_method(
    commands: &dyn DnsCommands,
    files: &DnsFiles,
) -> Option<DnsCaptureMethod> {
    let resolved = match resolved_carries_programs(commands) {
        Some(carries) => carries,
        None => resolv_conf_names_resolved_stub(files),
    };
    if resolved {
        Some(DnsCaptureMethod::Resolved)
    } else if network_manager_redirect_available(commands, files) {
        Some(DnsCaptureMethod::NetworkManager)
    } else if resolvconf_redirect_available(commands, files) {
        Some(DnsCaptureMethod::Resolvconf)
    } else if std::fs::metadata(&files.resolv_conf).is_ok() {
        Some(DnsCaptureMethod::ResolvConfFile)
    } else {
        None
    }
}

/// The mechanism, asked again on every (re)arm. The answer at start-up can be
/// wrong for good: early in boot resolved may not answer yet and
/// NetworkManager may not run yet, and a redirect through the wrong mechanism
/// fails, or loses the VPN's domains, until the next restart.
pub struct DnsCaptureSelector<C: DnsCommands + Clone + 'static> {
    commands: C,
    files: DnsFiles,
    current: Mutex<DnsCaptureMethod>,
}

impl<C: DnsCommands + Clone + 'static> DnsCaptureSelector<C> {
    pub fn new(method: DnsCaptureMethod, commands: C, files: DnsFiles) -> Self {
        Self {
            commands,
            files,
            current: Mutex::new(method),
        }
    }

    /// The mechanism the machine has now, and whether it differs from the last
    /// answer. Nothing detectable keeps the last one: a gap in what the machine
    /// reports is no reason to drop a mechanism that worked. Ask only while no
    /// redirect of ours stands, or it answers about our own change.
    pub fn redetect(&self) -> (DnsCaptureMethod, bool) {
        let mut current = self.current.lock().unwrap_or_else(|p| p.into_inner());
        let previous = *current;
        if let Some(found) = detect_capture_method(&self.commands, &self.files) {
            *current = found;
        }
        (*current, *current != previous)
    }

    pub fn parts(&self, method: DnsCaptureMethod) -> DnsCaptureParts {
        dns_capture_parts(method, self.commands.clone(), self.files.clone())
    }
}

/// Everything the neutral resolver needs from one mechanism. Clones share the
/// same instances.
#[derive(Clone)]
pub struct DnsCaptureParts {
    pub redirect: Arc<dyn SystemDnsRedirectPort>,
    /// The machine's own servers, never read through the file we redirect.
    pub servers: Arc<dyn SystemDnsServersPort>,
    /// Namespaces the machine's connections claim.
    pub scopes: Arc<dyn InterfaceDnsScopePort>,
    pub listener: SocketAddr,
    /// Readies the listener's address before each bind.
    pub prepare: Arc<dyn Fn() -> Result<(), PlatformError> + Send + Sync>,
}

pub fn dns_capture_parts<C: DnsCommands + Clone + 'static>(
    method: DnsCaptureMethod,
    commands: C,
    files: DnsFiles,
) -> DnsCaptureParts {
    let ready: Arc<dyn Fn() -> Result<(), PlatformError> + Send + Sync> = Arc::new(|| Ok(()));
    match method {
        DnsCaptureMethod::Resolved => {
            let redirect = Arc::new(ResolvedDnsRedirect::new(
                commands.clone(),
                files.resolved_taken_file(),
            ));
            let link = Arc::clone(&redirect);
            DnsCaptureParts {
                redirect,
                servers: Arc::new(ResolvedDnsServers(commands.clone())),
                scopes: Arc::new(ResolvedDnsScopes(commands)),
                listener: method.listener(),
                prepare: Arc::new(move || link.prepare_link()),
            }
        }
        DnsCaptureMethod::NetworkManager => {
            let next: NextMechanism = Arc::new(OnceLock::new());
            DnsCaptureParts {
                redirect: Arc::new(NetworkManagerOrNext {
                    network_manager: NetworkManagerDnsRedirect::new(
                        commands.clone(),
                        files.clone(),
                    ),
                    commands: commands.clone(),
                    files,
                    next: Arc::clone(&next),
                }),
                servers: Arc::new(FollowingNext {
                    own: NetworkManagerDnsServers(commands.clone()),
                    next: Arc::clone(&next),
                }),
                scopes: Arc::new(FollowingNext {
                    own: NetworkManagerDnsScopes(commands),
                    next,
                }),
                listener: method.listener(),
                prepare: ready,
            }
        }
        DnsCaptureMethod::Resolvconf => {
            let servers = Arc::new(ResolvconfDnsServers {
                files: files.clone(),
            });
            DnsCaptureParts {
                redirect: Arc::new(ResolvconfDnsRedirect::new(commands, files)),
                servers: Arc::clone(&servers) as _,
                scopes: servers,
                listener: method.listener(),
                prepare: ready,
            }
        }
        DnsCaptureMethod::ResolvConfFile => {
            let servers = Arc::new(ResolvConfFileServers {
                files: files.clone(),
            });
            DnsCaptureParts {
                redirect: Arc::new(ResolvConfFileRedirect::new(files)),
                servers: Arc::clone(&servers) as _,
                scopes: servers,
                listener: method.listener(),
                prepare: ready,
            }
        }
    }
}

/// The mechanism that took over from NetworkManager, once it did.
type NextMechanism = Arc<OnceLock<(DnsCaptureMethod, DnsCaptureParts)>>;

/// NetworkManager, or the mechanism after it once NetworkManager is found
/// not to write the file from its global DNS (`dns=none`,
/// `rc-manager=unmanaged`): re-writing a drop-in it ignores changes nothing.
/// The switch holds for the life of these parts. Every later mechanism
/// listens on the same loopback address, so the listener keeps its socket.
struct NetworkManagerOrNext<C: DnsCommands + Clone + 'static> {
    network_manager: NetworkManagerDnsRedirect<C>,
    commands: C,
    files: DnsFiles,
    next: NextMechanism,
}

impl<C: DnsCommands + Clone + 'static> NetworkManagerOrNext<C> {
    fn next(&self) -> Option<&Arc<dyn SystemDnsRedirectPort>> {
        self.next.get().map(|(_, parts)| &parts.redirect)
    }

    fn active(&self) -> &dyn SystemDnsRedirectPort {
        match self.next() {
            Some(next) => next.as_ref(),
            None => &self.network_manager,
        }
    }

    fn switch_to_next(&self) -> &Arc<dyn SystemDnsRedirectPort> {
        let (method, parts) = self.next.get_or_init(|| {
            let method = if resolvconf_redirect_available(&self.commands, &self.files) {
                DnsCaptureMethod::Resolvconf
            } else {
                DnsCaptureMethod::ResolvConfFile
            };
            tracing::warn!(
                target: "nrr::dns-resolver",
                msg_key = "linux-svc-dns-mechanism-changed",
                from = DnsCaptureMethod::NetworkManager.name(),
                to = method.name(),
                "NetworkManager keeps our DNS drop-in but does not write resolv.conf from it; \
                 the local resolver arms through the next mechanism",
            );
            (
                method,
                dns_capture_parts(method, self.commands.clone(), self.files.clone()),
            )
        });
        debug_assert_eq!(
            method.listener(),
            DnsCaptureMethod::NetworkManager.listener()
        );
        &parts.redirect
    }
}

impl<C: DnsCommands + Clone + 'static> SystemDnsRedirectPort for NetworkManagerOrNext<C> {
    fn redirect_to(&self, listener: SocketAddr) -> Result<RedirectHandle, PlatformError> {
        if let Some(next) = self.next() {
            return next.redirect_to(listener);
        }
        let handle = self.network_manager.redirect_to(listener)?;
        if self.network_manager.writes_listener(listener) {
            return Ok(handle);
        }
        self.network_manager.restore(&handle)?;
        self.switch_to_next().redirect_to(listener)
    }

    fn restore(&self, handle: &RedirectHandle) -> Result<(), PlatformError> {
        self.active().restore(handle)
    }

    fn verify(&self, handle: &RedirectHandle) -> Result<RedirectState, PlatformError> {
        self.active().verify(handle)
    }

    fn inspect(&self, handle: &RedirectHandle) -> Result<RedirectState, PlatformError> {
        self.active().inspect(handle)
    }

    fn flush_cache(&self) -> Result<(), PlatformError> {
        self.active().flush_cache()
    }

    fn exempt_namespaces(
        &self,
        exemptions: &[DnsNamespaceExemption],
    ) -> Result<usize, PlatformError> {
        self.active().exempt_namespaces(exemptions)
    }

    fn keep_short_names(
        &self,
        claimed: &[DnsNamespaceExemption],
        extra: &dyn Fn() -> Vec<String>,
    ) -> Result<(), PlatformError> {
        self.active().keep_short_names(claimed, extra)
    }
}

/// NetworkManager's servers or scopes until the next mechanism takes over,
/// then that mechanism's: with `dns=none` the file, not the devices, holds
/// the servers the machine used.
struct FollowingNext<P> {
    own: P,
    next: NextMechanism,
}

impl<P: SystemDnsServersPort> SystemDnsServersPort for FollowingNext<P> {
    fn upstream_candidates_v4(&self) -> Vec<UpstreamDnsCandidate> {
        match self.next.get() {
            Some((_, parts)) => parts.servers.upstream_candidates_v4(),
            None => self.own.upstream_candidates_v4(),
        }
    }

    fn upstream_candidates_v4_within(&self, budget: Duration) -> Vec<UpstreamDnsCandidate> {
        match self.next.get() {
            Some((_, parts)) => parts.servers.upstream_candidates_v4_within(budget),
            None => self.own.upstream_candidates_v4_within(budget),
        }
    }

    fn report_all_unreachable(&self, servers: &[UpstreamDnsCandidate]) {
        match self.next.get() {
            Some((_, parts)) => parts.servers.report_all_unreachable(servers),
            None => self.own.report_all_unreachable(servers),
        }
    }
}

impl<P: InterfaceDnsScopePort> InterfaceDnsScopePort for FollowingNext<P> {
    fn dns_scopes(&self) -> Vec<InterfaceDnsScope> {
        match self.next.get() {
            Some((_, parts)) => parts.scopes.dns_scopes(),
            None => self.own.dns_scopes(),
        }
    }
}

/// Undo whatever any mechanism left behind. Every mechanism, not the one this
/// run would pick: the machine may have changed between runs, and each
/// cleanup acts only on a trace of its own. Run at start-up, by the unit's
/// stop hook and by `uninstall`.
pub fn clear_every_redirect<C: DnsCommands + Clone>(
    commands: C,
    files: &DnsFiles,
) -> Result<(), PlatformError> {
    let results = [
        clear_orphan_redirect(commands.clone(), files.resolved_taken_file()),
        clear_network_manager_redirect(&commands, files),
        clear_resolvconf_redirect(&commands, files),
        restore_system_file(files),
    ];
    results
        .into_iter()
        .collect::<Result<Vec<()>, _>>()
        .map(|_| ())
}
