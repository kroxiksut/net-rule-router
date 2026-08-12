//! Windows OS resolver-cache flush
//! (`DnsFlushResolverCache`, `dnsapi.dll`).
//!
//! ## Why
//!
//! Suffix/zone enforcement learns hostnames only from live DNS traffic
//! (ETW `Microsoft-Windows-DNS-Client` event 3008). A name resolved
//! before the service started — or before a fail-closed block-all
//! armed — is served from the OS resolver cache without a wire query,
//! so the observer never sees it, the FQDN cache never learns it, and
//! its permit filter is never built (e.g. `ya.ru` with a
//! `zone ru → primary` rule and working DNS, yet no permit — it was
//! simply absent from the FQDN cache because Windows answered it from
//! the local resolver cache). Flushing at those boundaries forces the
//! next lookup back onto the wire.
//!
//! ## FFI
//!
//! `DnsFlushResolverCache` is exported by `dnsapi.dll` but absent from
//! the public SDK headers (and from the `windows` crate metadata), so
//! we declare it directly. It is the exact call `ipconfig /flushdns`
//! makes, stable since Windows 2000: no parameters, returns a `BOOL`.

#![allow(unsafe_code)]

use nrr_platform_api::dns::{DnsCacheControlPort, DnsCacheFlushError};

#[link(name = "dnsapi")]
extern "system" {
    /// Undocumented but long-stable `dnsapi.dll` export used by
    /// `ipconfig /flushdns`. Returns non-zero on success.
    fn DnsFlushResolverCache() -> i32;
}

/// Production [`DnsCacheControlPort`] backed by `dnsapi.dll`.
///
/// Stateless; safe to share via `Arc<dyn DnsCacheControlPort>`.
#[derive(Debug, Default)]
pub struct WindowsDnsCacheControl;

impl WindowsDnsCacheControl {
    pub const fn new() -> Self {
        Self
    }
}

impl DnsCacheControlPort for WindowsDnsCacheControl {
    fn flush_resolver_cache(&self) -> Result<(), DnsCacheFlushError> {
        // SAFETY: the function takes no arguments and touches no
        // caller-owned memory; the only contract is that `dnsapi.dll`
        // is present, which the crate already requires for `DnsQuery_W`.
        let ok = unsafe { DnsFlushResolverCache() };
        if ok != 0 {
            Ok(())
        } else {
            // The export reports only a boolean; no extended code.
            Err(DnsCacheFlushError::Failed { code: 0 })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// HW-adjacent sanity: flushing the real resolver cache succeeds on
    /// any Windows box (admin not required for a flush).
    #[test]
    fn flush_resolver_cache_succeeds_on_windows() {
        WindowsDnsCacheControl::new()
            .flush_resolver_cache()
            .expect("DnsFlushResolverCache must succeed");
    }
}
