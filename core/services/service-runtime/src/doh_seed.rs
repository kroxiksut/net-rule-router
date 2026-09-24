//! built-in DoH/DoT resolver seed list.
//!
//! Parses the checked-in `configs/doh-dot-resolvers.seed.json` (embedded at build
//! time) into [`DohResolverEntry`]s to pre-fill the shared `doh_resolver_entries`
//! baseline on first run. Each JSON row carries a provider, country, a
//! comma-separated `ipv4` list and an optional comma-separated `hostname` list;
//! every IP becomes an `Ip` entry and every hostname a `Host` entry, all enabled,
//! with the comment `"<provider> (<country>)"`. Malformed rows are skipped — the
//! seed is best-effort and must never block service start.

use std::sync::Mutex;

use nrr_storage::doh_lockdown::{DohResolverEntriesRepository, DohResolverEntry, DohTarget};
use rusqlite::Connection;

/// The checked-in seed, embedded at build time (single source of truth with the
/// research-collected list). Path is relative to this source file.
const SEED_JSON: &str = include_str!("../../../../configs/doh-dot-resolvers.seed.json");

/// Pre-fill the shared resolver baseline on first run. A no-op once the list
/// has entries, so user edits survive; best-effort, because a failed seed must
/// not stop the service.
pub fn seed_shared_baseline(conn: &Mutex<Connection>) {
    let Ok(guard) = conn.lock() else {
        return;
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    match DohResolverEntriesRepository::new(&guard).seed_if_empty(&builtin_seed(), now) {
        Ok(n) if n > 0 => tracing::info!(
            target: "nrr::doh",
            seeded = n,
            "seeded the DoH/DoT resolver baseline on first run",
        ),
        Ok(_) => {}
        Err(e) => tracing::warn!(
            target: "nrr::doh",
            error = %e,
            "DoH resolver seed failed (non-fatal)",
        ),
    }
}

/// The enabled HOST entries of the baseline. The lockdown blocks by address and
/// reads host entries through the FQDN cache, so a platform whose DNS observer
/// never sees these names must resolve them itself.
pub fn enabled_resolver_hosts(conn: &Mutex<Connection>) -> Vec<String> {
    let Ok(guard) = conn.lock() else {
        return Vec::new();
    };
    DohResolverEntriesRepository::new(&guard)
        .load_all()
        .unwrap_or_default()
        .into_iter()
        .filter(|e| e.enabled)
        .filter_map(|e| match e.target {
            DohTarget::Host(host) => Some(host),
            DohTarget::Ip(_) => None,
        })
        .collect()
}

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
        let seed = parse_seed(
            r#"{"resolvers": [
                {"provider": "A", "ipv4": "192.0.2.1,192.0.2.2"},
                {"provider": "B", "ipv4": "192.0.2.1", "hostname": "dns.example"}
            ]}"#,
        );
        let count = seed
            .iter()
            .filter(|e| e.target == DohTarget::Ip(Ipv4Addr::new(192, 0, 2, 1)))
            .count();
        assert_eq!(count, 1, "shared IP must be deduped");
        assert_eq!(seed.len(), 3);
    }

    /// Firefox's default resolver is not on 1.1.1.1; blocking only that pair
    /// leaves the browser on DoH.
    #[test]
    fn builtin_seed_blocks_firefox_default_resolver_by_address() {
        let seed = builtin_seed();
        for ip in [
            Ipv4Addr::new(172, 64, 41, 4),
            Ipv4Addr::new(162, 159, 61, 4),
        ] {
            assert!(
                seed.iter().any(|e| e.target == DohTarget::Ip(ip)),
                "{ip} missing"
            );
        }
    }

    #[test]
    fn malformed_json_yields_empty() {
        assert!(parse_seed("not json").is_empty());
        assert!(parse_seed("{}").is_empty());
    }
}
