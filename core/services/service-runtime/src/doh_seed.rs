//! built-in DoH/DoT resolver seed list.
//!
//! Parses the checked-in `configs/doh-dot-resolvers.seed.json` (embedded at build
//! time) into [`DohResolverEntry`]s to pre-fill the shared `doh_resolver_entries`
//! baseline on first run. Each JSON row carries a provider, country, a
//! comma-separated `ipv4` list and an optional comma-separated `hostname` list;
//! every IP becomes an `Ip` entry and every hostname a `Host` entry, all enabled,
//! with the comment `"<provider> (<country>)"`. Malformed rows are skipped — the
//! seed is best-effort and must never block service start.

use nrr_storage::doh_lockdown::{DohResolverEntry, DohTarget};

/// The checked-in seed, embedded at build time (single source of truth with the
/// research-collected list). Path is relative to this source file.
const SEED_JSON: &str = include_str!("../../../../configs/doh-dot-resolvers.seed.json");

/// Parse the embedded seed into resolver entries (all enabled). De-duplicates by
/// `(kind, value)` so a shared IP across providers yields one entry. Returns an
/// empty vec if the JSON is unexpectedly malformed (best-effort).
pub fn builtin_seed() -> Vec<DohResolverEntry> {
    parse_seed(SEED_JSON)
}

fn parse_seed(json: &str) -> Vec<DohResolverEntry> {
    let Ok(root) = serde_json::from_str::<serde_json::Value>(json) else {
        return Vec::new();
    };
    let Some(resolvers) = root.get("resolvers").and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    let mut out: Vec<DohResolverEntry> = Vec::new();
    let mut seen: std::collections::HashSet<(String, String)> = std::collections::HashSet::new();
    for row in resolvers {
        let provider = row.get("provider").and_then(|v| v.as_str()).unwrap_or("");
        let country = row.get("country").and_then(|v| v.as_str()).unwrap_or("");
        let comment = if country.is_empty() {
            provider.to_string()
        } else {
            format!("{provider} ({country})")
        };
        let mut push = |target: DohTarget| {
            let key = (target.kind_str().to_string(), target.value_str());
            if seen.insert(key) {
                out.push(DohResolverEntry {
                    target,
                    comment: comment.clone(),
                    enabled: true,
                });
            }
        };
        if let Some(ipv4) = row.get("ipv4").and_then(|v| v.as_str()) {
            for ip in ipv4.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                if let Some(t) = DohTarget::parse("ip", ip) {
                    push(t);
                }
            }
        }
        if let Some(hostname) = row.get("hostname").and_then(|v| v.as_str()) {
            for host in hostname.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                if let Some(t) = DohTarget::parse("host", host) {
                    push(t);
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn builtin_seed_parses_and_covers_major_resolvers() {
        let seed = builtin_seed();
        // The embedded list is substantial (50+ resolvers, many with 2 IPs).
        assert!(seed.len() > 40, "seed unexpectedly small: {}", seed.len());
        // Google 8.8.8.8 and Yandex 77.88.8.8 must be present as IP entries.
        assert!(seed
            .iter()
            .any(|e| e.target == DohTarget::Ip(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(seed
            .iter()
            .any(|e| e.target == DohTarget::Ip(Ipv4Addr::new(77, 88, 8, 8))));
        // dns.google present as a host entry.
        assert!(seed
            .iter()
            .any(|e| e.target == DohTarget::Host("dns.google".into())));
        // Every entry is enabled by default.
        assert!(seed.iter().all(|e| e.enabled));
    }

    #[test]
    fn parse_seed_dedupes_shared_ips() {
        // Cloudflare 1.1.1.1 appears in several rows (base + Mozilla TRR); the
        // (kind, value) dedup must collapse it to one entry.
        let seed = builtin_seed();
        let count = seed
            .iter()
            .filter(|e| e.target == DohTarget::Ip(Ipv4Addr::new(1, 1, 1, 1)))
            .count();
        assert_eq!(count, 1, "shared IP must be deduped");
    }

    #[test]
    fn malformed_json_yields_empty() {
        assert!(parse_seed("not json").is_empty());
        assert!(parse_seed("{}").is_empty());
    }
}
