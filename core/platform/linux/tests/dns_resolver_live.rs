//! One live test against the real mechanism: a name the machine's own resolver
//! knows must come back with addresses AND a TTL.
//!
//! Needs no root, but does need working DNS. Without it — no nameserver in
//! `/etc/resolv.conf`, or nothing answering — the test skips loudly rather than
//! failing: an offline build machine is not a broken resolver.

#![cfg(target_os = "linux")]
#![allow(clippy::expect_used)]

use std::time::Duration;

use nrr_platform_api::dns::{DnsResolverError, DnsResolverPort};
use nrr_platform_linux::dns_resolver::{parse_nameservers, LinuxDnsResolver, RESOLV_CONF};

/// A name that exists for as long as the internet does, and is not a service
/// anyone would notice one query to.
const KNOWN_NAME: &str = "example.com";

fn has_a_nameserver() -> bool {
    std::fs::read_to_string(RESOLV_CONF)
        .map(|text| !parse_nameservers(&text).is_empty())
        .unwrap_or(false)
}

#[test]
fn a_known_name_resolves_with_a_ttl() {
    if !has_a_nameserver() {
        eprintln!("SKIPPED dns_resolver_live: no IPv4 nameserver in {RESOLV_CONF}");
        return;
    }
    let resolver = LinuxDnsResolver::new().with_timeout(Duration::from_secs(3));

    let record = match resolver.resolve_a(KNOWN_NAME) {
        Ok(record) => record,
        Err(DnsResolverError::Timeout { .. }) | Err(DnsResolverError::Network { .. }) => {
            eprintln!("SKIPPED dns_resolver_live: the configured nameserver did not answer");
            return;
        }
        Err(other) => panic!("the resolver failed on a name that exists: {other:?}"),
    };

    assert_eq!(record.canonical_hostname, KNOWN_NAME);
    assert!(
        !record.addresses.is_empty(),
        "an Ok result must carry addresses — an empty answer is an NxDomain",
    );
    // A TTL must be REPORTED — that is the whole reason this resolver exists
    // rather than `getaddrinfo`. Its value may legitimately be zero: a caching
    // stub (systemd-resolved, the WSL NAT resolver) counts the remaining life of
    // its own entry down to nothing and hands that on. The store floors the
    // refresh cadence, so a zero is honest data rather than a busy loop.
    assert!(
        record.ttl_seconds.is_some(),
        "no TTL came back at all — the answer was read as if it had none",
    );
}

/// The distinction the cache depends on: a name that does not exist is an
/// authoritative answer worth remembering, not a failure worth retrying.
#[test]
fn a_name_that_does_not_exist_comes_back_as_nxdomain() {
    if !has_a_nameserver() {
        eprintln!("SKIPPED dns_resolver_live: no IPv4 nameserver in {RESOLV_CONF}");
        return;
    }
    let resolver = LinuxDnsResolver::new().with_timeout(Duration::from_secs(3));

    // `.invalid` is reserved by RFC 2606 precisely so it can never resolve.
    match resolver.resolve_a("nrr-does-not-exist.invalid") {
        Err(DnsResolverError::NxDomain { .. }) => {}
        Err(DnsResolverError::Timeout { .. }) | Err(DnsResolverError::Network { .. }) => {
            eprintln!("SKIPPED dns_resolver_live: the configured nameserver did not answer");
        }
        other => panic!("a reserved non-existent name must be NxDomain, got {other:?}"),
    }
}
