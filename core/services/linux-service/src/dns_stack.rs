//! The local DNS resolver on Linux: the neutral assembly
//! (`nrr_service_runtime::dns_stack`) over whichever mechanism writes the
//! machine's `resolv.conf`.
//!
//! Where no mechanism can be used, nothing here arms and the DoH lockdown
//! stays forced: without our listener answering, the canary that turns browser
//! DoH off is never served.

#![cfg(target_os = "linux")]

use std::path::Path;
use std::sync::Arc;

use nrr_platform_linux::dns_redirect::{
    clear_every_redirect, detect_capture_method, dns_capture_parts, DnsCaptureMethod, DnsFiles,
    SystemDnsCommands,
};
use nrr_service_runtime::dns_resolver_service::{DnsResolverController, DnsResolverFactory};
use nrr_service_runtime::dns_stack::{DnsStackInputs, DnsStackPlatform};
use nrr_service_runtime::dns_upstream::{UdpUpstreamProbe, UpstreamDnsPool};

/// Can the machine's DNS be taken over, decided once at start-up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DnsCapture {
    Via(DnsCaptureMethod),
    /// No `resolv.conf` to point anywhere: the machine's DNS is left alone.
    Unavailable,
}

impl DnsCapture {
    pub(crate) fn answers_dns(self) -> bool {
        matches!(self, Self::Via(_))
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
            DnsCapture::Via(method)
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
        Arc::new(UpstreamDnsPool::new(
            servers,
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
    let DnsCapture::Via(method) = capture else {
        return None;
    };
    let parts = dns_capture_parts(method, SystemDnsCommands, DnsFiles::system(data_dir));
    let scopes = Arc::clone(&parts.scopes);
    let platform = DnsStackPlatform {
        system_dns: Arc::clone(&parts.servers),
        upstream_pool: upstream_dns_pool(Arc::clone(&parts.servers)),
        redirect: parts.redirect,
        listen_addr: parts.listener,
        claimed_namespaces: Arc::new(move || {
            use nrr_platform_api::dns_scope::is_actionable_scope;
            scopes
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
    // The listener binds the mechanism's address, so it is readied before
    // every build — including a rebuild after something removed it.
    let prepare = parts.prepare;
    let factory: DnsResolverFactory = Arc::new(move || {
        if let Err(e) = prepare() {
            tracing::warn!(
                target: "nrr::dns-resolver",
                msg_key = "linux-svc-dns-listener-prepare-failed",
                error = %e,
                "the DNS listener's address could not be prepared; the local resolver stays off",
            );
            return None;
        }
        build()
    });
    let controller = Arc::new(DnsResolverController::new());
    controller.set_factory(factory);
    Some(controller)
}

/// The resolver the service itself uses to look names up: the mechanism's own
/// servers under the redirect, since `/etc/resolv.conf` then leads to us.
pub(crate) fn service_dns_resolver(
    capture: DnsCapture,
    data_dir: &Path,
) -> nrr_platform_linux::dns_resolver::LinuxDnsResolver {
    match capture {
        DnsCapture::Via(method) => {
            let parts = dns_capture_parts(method, SystemDnsCommands, DnsFiles::system(data_dir));
            nrr_platform_linux::dns_resolver::LinuxDnsResolver::with_servers(Box::new(
                SharedServers(parts.servers),
            ))
        }
        DnsCapture::Unavailable => nrr_platform_linux::dns_resolver::LinuxDnsResolver::new(),
    }
}

struct SharedServers(Arc<dyn nrr_platform_api::dns::SystemDnsServersPort>);

impl nrr_platform_api::dns::SystemDnsServersPort for SharedServers {
    fn upstream_candidates_v4(&self) -> Vec<nrr_platform_api::dns::UpstreamDnsCandidate> {
        self.0.upstream_candidates_v4()
    }
}
