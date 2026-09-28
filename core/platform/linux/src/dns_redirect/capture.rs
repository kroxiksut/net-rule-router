//! Which mechanism takes the machine's DNS, decided once at start-up, and the
//! cleanup that undoes any of them.

use std::net::SocketAddr;
use std::sync::Arc;

use nrr_platform_api::dns::SystemDnsServersPort;
use nrr_platform_api::dns_redirect::SystemDnsRedirectPort;
use nrr_platform_api::dns_scope::InterfaceDnsScopePort;
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

/// Everything the neutral resolver needs from one mechanism.
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
        DnsCaptureMethod::NetworkManager => DnsCaptureParts {
            redirect: Arc::new(NetworkManagerDnsRedirect::new(commands.clone(), files)),
            servers: Arc::new(NetworkManagerDnsServers(commands.clone())),
            scopes: Arc::new(NetworkManagerDnsScopes(commands)),
            listener: method.listener(),
            prepare: ready,
        },
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
