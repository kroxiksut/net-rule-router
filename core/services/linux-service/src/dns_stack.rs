//! The local DNS resolver on Linux: the neutral assembly
//! (`nrr_service_runtime::dns_stack`) over systemd-resolved.
//!
//! Where resolved does not stand between programs and DNS, nothing here arms
//! and the DoH lockdown stays forced: without our listener answering, the
//! canary that turns browser DoH off is never served.

#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use nrr_platform_linux::dns_redirect::{
    clear_orphan_redirect, resolved_redirect_available, ResolvedDnsRedirect, ResolvedDnsScopes,
    ResolvedDnsServers, SystemResolvedCommands, LISTENER_ADDR,
};
use nrr_service_runtime::dns_resolver_service::{DnsResolverController, DnsResolverFactory};
use nrr_service_runtime::dns_stack::{DnsStackInputs, DnsStackPlatform};
use nrr_service_runtime::dns_upstream::{UdpUpstreamProbe, UpstreamDnsPool};

/// Can the machine's DNS be taken over, decided once at start-up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DnsCapture {
    /// systemd-resolved carries the machine's lookups; our link can sit in it.
    Resolved,
    /// No mechanism this build knows: the machine's DNS is left alone.
    Unavailable,
}

impl DnsCapture {
    pub(crate) fn answers_dns(self) -> bool {
        self == Self::Resolved
    }
}

/// Where the links whose `~.` we hold are written down.
fn taken_file(data_dir: &Path) -> PathBuf {
    data_dir.join("dns-catch-all-taken")
}

/// Undo what a previous run left behind, then decide what this run can do.
/// The cleanup runs whatever the answer: a crashed run's link must not outlive
/// it even if resolved has since been reconfigured.
pub(crate) fn prepare_dns_capture(data_dir: &Path) -> DnsCapture {
    if let Err(e) = clear_orphan_redirect(SystemResolvedCommands, taken_file(data_dir)) {
        tracing::warn!(
            target: "nrr::dns-resolver",
            error = %e,
            "could not undo a previous run's DNS redirect",
        );
    }
    if resolved_redirect_available(&SystemResolvedCommands) {
        tracing::info!(
            target: "nrr::dns-resolver",
            "systemd-resolved carries this machine's lookups; the local DNS resolver can arm",
        );
        DnsCapture::Resolved
    } else {
        tracing::warn!(
            target: "nrr::dns-resolver",
            "systemd-resolved does not carry this machine's lookups; the local DNS resolver stays off and browser DoH stays blocked",
        );
        DnsCapture::Unavailable
    }
}

/// The same undo, for the unit's stop hook: the process that set it up may
/// have died without restoring.
pub(crate) fn clear_dns_redirect(data_dir: &Path) -> Result<(), String> {
    clear_orphan_redirect(SystemResolvedCommands, taken_file(data_dir)).map_err(|e| e.to_string())
}

/// The process-wide upstream choice: it outlives resolver restarts.
fn upstream_dns_pool() -> Arc<UpstreamDnsPool> {
    static POOL: std::sync::OnceLock<Arc<UpstreamDnsPool>> = std::sync::OnceLock::new();
    Arc::clone(POOL.get_or_init(|| {
        Arc::new(UpstreamDnsPool::new(
            Arc::new(ResolvedDnsServers(SystemResolvedCommands)),
            Arc::new(UdpUpstreamProbe::default()),
        ))
    }))
}

/// The resolver controller with its factory, when the machine allows one.
pub(crate) fn resolver_controller(
    capture: DnsCapture,
    data_dir: &Path,
    inputs: DnsStackInputs,
) -> Option<Arc<DnsResolverController>> {
    if !capture.answers_dns() {
        return None;
    }
    let redirect = Arc::new(ResolvedDnsRedirect::new(
        SystemResolvedCommands,
        taken_file(data_dir),
    ));
    let platform = DnsStackPlatform {
        system_dns: Arc::new(ResolvedDnsServers(SystemResolvedCommands)),
        upstream_pool: upstream_dns_pool(),
        redirect: Arc::clone(&redirect) as _,
        listen_addr: LISTENER_ADDR,
        claimed_namespaces: Arc::new(|| {
            use nrr_platform_api::dns_scope::{is_actionable_scope, InterfaceDnsScopePort};
            ResolvedDnsScopes(SystemResolvedCommands)
                .dns_scopes()
                .into_iter()
                .filter(is_actionable_scope)
                .map(
                    |scope| nrr_platform_api::dns_redirect::DnsNamespaceExemption {
                        suffix: scope.suffix,
                        servers: scope.servers,
                    },
                )
                .collect()
        }),
    };
    let build: DnsResolverFactory =
        nrr_service_runtime::dns_stack::build_dns_resolver_factory(inputs, platform);
    // The listener binds the link's address, so the link exists before every
    // build — including a rebuild after something removed it.
    let factory: DnsResolverFactory = Arc::new(move || {
        if let Err(e) = redirect.prepare_link() {
            tracing::warn!(
                target: "nrr::dns-resolver",
                error = %e,
                "the DNS link could not be prepared; the local resolver stays off",
            );
            return None;
        }
        build()
    });
    let controller = Arc::new(DnsResolverController::new());
    controller.set_factory(factory);
    Some(controller)
}

/// The resolver the service itself uses to look names up: resolved's
/// per-link servers under the redirect, since `/etc/resolv.conf` then names
/// resolved, which forwards to us.
pub(crate) fn service_dns_resolver(
    capture: DnsCapture,
) -> nrr_platform_linux::dns_resolver::LinuxDnsResolver {
    match capture {
        DnsCapture::Resolved => nrr_platform_linux::dns_resolver::LinuxDnsResolver::with_servers(
            Box::new(ResolvedDnsServers(SystemResolvedCommands)),
        ),
        DnsCapture::Unavailable => nrr_platform_linux::dns_resolver::LinuxDnsResolver::new(),
    }
}
