//! DNS resolver subsystem.
//!
//! Neutral definitions ([`DnsResolverPort`], [`ResolvedRecord`],
//! [`DnsResolverError`], [`MockDnsResolver`]) live in
//! `nrr_platform_api::dns` and are re-exported here unchanged. The
//! real Windows implementation backed by `DnsQuery_W` lives in
//! [`win32_dns`].
//!
//! [`build_dns_refresh_task`]: nrr_service_runtime::service_tasks::build_dns_refresh_task

#[cfg(target_os = "windows")]
pub mod win32_dns;
#[cfg(target_os = "windows")]
pub mod win32_dns_cache;
#[cfg(target_os = "windows")]
pub mod win32_dns_cache_read;

#[cfg(target_os = "windows")]
pub use win32_dns::WindowsDnsResolver;
#[cfg(target_os = "windows")]
pub use win32_dns_cache::WindowsDnsCacheControl;
#[cfg(target_os = "windows")]
pub use win32_dns_cache_read::WindowsDnsCacheRead;

pub use nrr_platform_api::dns::*;
