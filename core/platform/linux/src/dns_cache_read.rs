//! Linux OS resolver-cache **read** seam (design + stub).
//!
//! The neutral port lives in [`nrr_platform_api::dns::DnsCacheReadPort`]; this
//! backend is the Linux analog of
//! `nrr_platform_windows::dns::WindowsDnsCacheRead`.
//!
//! ## Why it is a stub for now
//!
//! Unlike Windows, Linux has no single always-on OS resolver cache:
//!
//! - Plain glibc (`nss_dns`) does **not** cache — each lookup hits the wire (or
//!   `/etc/hosts`), so there is nothing to snapshot and the observer sees every
//!   query anyway; the "hidden by the OS cache" failure mode does not
//!   arise. Returning an empty snapshot is correct here.
//! - `systemd-resolved` (the common modern default) *does* cache. Its cache is
//!   readable over D-Bus (`org.freedesktop.resolve1`,
//!   `Manager.ResolveHostname`) or, more coarsely, via `resolvectl statistics`
//!   / `resolvectl query`. There is no public "dump the whole cache" call, so
//!   the eventual real impl mirrors the Windows two-step: enumerate candidate
//!   names (from our own rule set / recent observations) and issue cache-favouring
//!   `ResolveHostname` calls with `SD_RESOLVED_NO_NETWORK`.
//! - `dnsmasq` / `unbound` caches are process-local and only exposed through
//!   their own control channels (`unbound-control dump_cache`), so they are
//!   out of scope for a generic backend.
//!
//! Because there is no universal mechanism and it needs a real resolved host to
//! verify, this returns an empty snapshot (same effect as
//! [`nrr_platform_api::dns::NoopDnsCacheRead`]) until the systemd-resolved
//! D-Bus path is implemented. It compiles on every target (pure
//! `std` over the api trait), so it links into `service-runtime` now.

use nrr_platform_api::dns::{DnsCacheReadError, DnsCacheReadPort, OsCachedResolution};

/// Linux stub of [`DnsCacheReadPort`]. Returns an empty snapshot until the
/// systemd-resolved D-Bus mechanism lands (see module docs). Selected by the
/// consumer under `#[cfg(target_os = "linux")]` where Windows selects
/// `nrr_platform_windows::WindowsDnsCacheRead`.
#[derive(Debug, Default, Clone, Copy)]
pub struct LinuxDnsCacheRead;

impl LinuxDnsCacheRead {
    pub const fn new() -> Self {
        Self
    }
}

impl DnsCacheReadPort for LinuxDnsCacheRead {
    fn read_resolver_cache(&self) -> Result<Vec<OsCachedResolution>, DnsCacheReadError> {
        // Empty is the correct answer for the glibc-no-cache case and a safe
        // placeholder for the systemd-resolved case: the DNS observer still
        // learns hosts, so seeding just does not augment it yet on Linux.
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_cache_read_returns_empty_snapshot() {
        assert_eq!(
            LinuxDnsCacheRead::new().read_resolver_cache(),
            Ok(Vec::new())
        );
    }
}
