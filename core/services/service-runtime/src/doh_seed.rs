//! built-in DoH/DoT resolver seed list.
//!
//! Parses the checked-in `configs/doh-dot-resolvers.seed.json` (embedded at build
//! time) into [`SeedEntry`]s for the shared `doh_resolver_entries` baseline. Each
//! JSON row carries a provider, country, comma-separated `ipv4` and optional
//! `ipv6` lists and an optional comma-separated `hostname` list; every address
//! becomes an `Ip` entry and every hostname a `Host` entry, all enabled, with the
//! comment `"<provider> (<country>)"`. `seed-version` and the per-row `since` /
//! per-field `<field>-since` say which version introduced an entry, so an
//! existing install receives only what is new; `retired` rows with `retired-in`
//! name entries a later version withdrew. Malformed rows are skipped — the seed
//! is best-effort and must never block service start.

use std::collections::HashMap;
use std::sync::Mutex;

use nrr_storage::doh_lockdown::{
    DohResolverEntriesRepository, DohResolverEntry, DohTarget, RetiredSeedEntry, SeedApplied,
    SeedEntry,
};
use rusqlite::Connection;

/// The checked-in seed, embedded at build time (single source of truth with the
/// research-collected list). Path is relative to this source file.
const SEED_JSON: &str = include_str!("../../../../configs/doh-dot-resolvers.seed.json");

/// The parsed built-in seed.
#[derive(Clone, Debug, Default)]
pub struct BuiltinSeed {
    pub version: u32,
    pub entries: Vec<SeedEntry>,
    pub retired: Vec<RetiredSeedEntry>,
}

/// Bring the shared resolver baseline up to the built-in seed: everything on
/// first run, afterwards only entries newer than the version last applied, so
/// user edits and deletions survive. Best-effort: a failed seed must not stop
/// the service.
pub fn seed_shared_baseline(conn: &Mutex<Connection>) {
    let Ok(guard) = conn.lock() else {
        return;
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let seed = builtin_seed();
    let repo = DohResolverEntriesRepository::new(&guard);
    let first_run = matches!(repo.load_all().as_deref(), Ok([]));
    match repo.apply_seed(&seed.entries, &seed.retired, seed.version, now) {
        Ok(SeedApplied { inserted, .. }) if inserted > 0 && first_run => tracing::info!(
            target: "nrr::doh",
            msg_key = "doh-baseline-seeded",
            seeded = inserted,
            "seeded the DoH/DoT resolver baseline on first run",
        ),
        Ok(SeedApplied { inserted, removed }) => {
            if inserted > 0 {
                tracing::info!(
                    target: "nrr::doh",
                    msg_key = "doh-baseline-seed-updated",
                    added = inserted,
                    version = seed.version,
                    "added new built-in entries to the DoH/DoT resolver baseline",
                );
            }
            if removed > 0 {
                tracing::info!(
                    target: "nrr::doh",
                    msg_key = "doh-baseline-seed-retired",
                    removed,
                    version = seed.version,
                    "removed withdrawn built-in entries from the DoH/DoT resolver baseline",
                );
            }
        }
        Err(e) => tracing::warn!(
            target: "nrr::doh",
            msg_key = "doh-baseline-seed-failed",
            error = %e,
            "DoH resolver seed failed (non-fatal)",
        ),
    }
}

/// The enabled HOST entries of the baseline. The lockdown blocks by address and
/// reads host entries through the FQDN cache, so a platform whose DNS observer
/// never sees these names must resolve them itself.
///
/// No caller yet; kept on purpose for the Linux service to resolve resolver
/// hosts itself.
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

/// Parse the embedded seed (all entries enabled). De-duplicates by
/// `(kind, value)` so a shared address across providers yields one entry.
/// Empty if the JSON is unexpectedly malformed (best-effort).
pub fn builtin_seed() -> BuiltinSeed {
    parse_seed(SEED_JSON)
}

fn parse_seed(json: &str) -> BuiltinSeed {
    let Ok(root) = serde_json::from_str::<serde_json::Value>(json) else {
        return BuiltinSeed::default();
    };
    let Some(resolvers) = root.get("resolvers").and_then(|v| v.as_array()) else {
        return BuiltinSeed::default();
    };
    let mut out: Vec<SeedEntry> = Vec::new();
    let mut index: HashMap<(&'static str, String), usize> = HashMap::new();
    for row in resolvers {
        let row_since = version_of(row.get("since")).unwrap_or(1);
        for (target, since, comment) in row_targets(row, row_since) {
            let key = (target.kind_str(), target.value_str());
            match index.get(&key) {
                // The earliest offer counts: an install that took it then
                // must not get it back after deleting it.
                Some(&i) => out[i].since = out[i].since.min(since),
                None => {
                    index.insert(key, out.len());
                    out.push(SeedEntry {
                        entry: DohResolverEntry {
                            target,
                            comment,
                            enabled: true,
                        },
                        since,
                    });
                }
            }
        }
    }
    let mut retired: Vec<RetiredSeedEntry> = Vec::new();
    for row in root
        .get("retired")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
    {
        let Some(retired_in) = version_of(row.get("retired-in")) else {
            continue;
        };
        for (target, _, comment) in row_targets(row, retired_in) {
            // Still offered by a live row: withdrawing it would undo the offer.
            if index.contains_key(&(target.kind_str(), target.value_str())) {
                continue;
            }
            retired.push(RetiredSeedEntry {
                target,
                comment,
                retired_in,
            });
        }
    }
    // An entry newer than the declared version would be offered again on
    // every start; the version covers everything the file introduces.
    let declared = version_of(root.get("seed-version")).unwrap_or(1);
    let version = out
        .iter()
        .map(|s| s.since)
        .chain(retired.iter().map(|r| r.retired_in))
        .fold(declared, u32::max);
    BuiltinSeed {
        version,
        entries: out,
        retired,
    }
}

fn version_of(v: Option<&serde_json::Value>) -> Option<u32> {
    v.and_then(serde_json::Value::as_u64)
        .and_then(|n| u32::try_from(n).ok())
}

/// Every target a seed row names, with the version of its field and the
/// comment `"<provider> (<country>)"` it is stored under.
fn row_targets(
    row: &serde_json::Value,
    row_since: u32,
) -> impl Iterator<Item = (DohTarget, u32, String)> + '_ {
    let provider = row.get("provider").and_then(|v| v.as_str()).unwrap_or("");
    let country = row.get("country").and_then(|v| v.as_str()).unwrap_or("");
    let comment = if country.is_empty() {
        provider.to_string()
    } else {
        format!("{provider} ({country})")
    };
    // A dual-stack browser reaches the same resolver over either family, so an
    // IPv4-only list leaves it on DoH.
    [("ipv4", "ip"), ("ipv6", "ip"), ("hostname", "host")]
        .into_iter()
        .filter_map(move |(field, kind)| {
            let list = row.get(field).and_then(|v| v.as_str())?;
            let since = version_of(row.get(format!("{field}-since").as_str())).unwrap_or(row_since);
            Some((list, kind, since))
        })
        .flat_map(move |(list, kind, since)| {
            let comment = comment.clone();
            list.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .filter_map(move |value| {
                    DohTarget::parse(kind, value).map(|t| (t, since, comment.clone()))
                })
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn v4(a: u8, b: u8, c: u8, d: u8) -> DohTarget {
        DohTarget::Ip(IpAddr::V4(Ipv4Addr::new(a, b, c, d)))
    }

    fn has(seed: &BuiltinSeed, target: &DohTarget) -> bool {
        seed.entries.iter().any(|s| &s.entry.target == target)
    }

    fn since_of(seed: &BuiltinSeed, target: &DohTarget) -> Option<u32> {
        seed.entries
            .iter()
            .find(|s| &s.entry.target == target)
            .map(|s| s.since)
    }

    #[test]
    fn builtin_seed_parses_and_covers_major_resolvers() {
        let seed = builtin_seed();
        // The embedded list is substantial (50+ resolvers, many with 2 IPs).
        assert!(
            seed.entries.len() > 40,
            "seed unexpectedly small: {}",
            seed.entries.len()
        );
        assert!(has(&seed, &v4(8, 8, 8, 8)));
        assert!(has(&seed, &v4(77, 88, 8, 8)));
        assert!(has(&seed, &DohTarget::Host("dns.google".into())));
        assert!(seed.entries.iter().all(|s| s.entry.enabled));
    }

    /// The declared version must cover every entry the file introduces, or a
    /// forgotten bump would hide new rows from existing installs.
    #[test]
    fn builtin_seed_version_matches_its_newest_entry() {
        let root: serde_json::Value = serde_json::from_str(SEED_JSON).expect("seed json");
        let declared = root["seed-version"].as_u64().expect("seed-version");
        let seed = builtin_seed();
        let newest = seed.entries.iter().map(|s| s.since).max().expect("entries");
        assert_eq!(u64::from(newest), declared);
        assert_eq!(seed.version, newest);
        // Everything the first release shipped is version 1.
        assert_eq!(since_of(&seed, &v4(8, 8, 8, 8)), Some(1));
        assert_eq!(
            since_of(&seed, &DohTarget::Host("dns.google".into())),
            Some(1)
        );
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
            .entries
            .iter()
            .filter(|s| s.entry.target == v4(192, 0, 2, 1))
            .count();
        assert_eq!(count, 1, "shared IP must be deduped");
        assert_eq!(seed.entries.len(), 3);
        assert_eq!(seed.version, 1, "no version declared means version 1");
    }

    #[test]
    fn parse_seed_reads_row_and_field_versions() {
        let seed = parse_seed(
            r#"{"seed-version": 3, "resolvers": [
                {"provider": "A", "ipv4": "192.0.2.1", "ipv6": "2001:db8::1", "ipv6-since": 2, "hostname": "a.example"},
                {"provider": "B", "since": 3, "ipv4": "192.0.2.2"},
                {"provider": "C", "since": 3, "ipv4": "192.0.2.1"}
            ]}"#,
        );
        assert_eq!(seed.version, 3);
        assert_eq!(
            since_of(&seed, &v4(192, 0, 2, 1)),
            Some(1),
            "earliest offer wins"
        );
        let v6 = DohTarget::Ip(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)));
        assert_eq!(since_of(&seed, &v6), Some(2));
        assert_eq!(
            since_of(&seed, &DohTarget::Host("a.example".into())),
            Some(1)
        );
        assert_eq!(since_of(&seed, &v4(192, 0, 2, 2)), Some(3));
    }

    #[test]
    fn parse_seed_reads_retired_rows() {
        let seed = parse_seed(
            r#"{"seed-version": 2, "resolvers": [
                {"provider": "A", "country": "XX", "ipv4": "192.0.2.1"}
            ], "retired": [
                {"provider": "B", "country": "XX", "ipv4": "192.0.2.9", "retired-in": 3},
                {"provider": "A", "country": "XX", "ipv4": "192.0.2.1", "retired-in": 3},
                {"provider": "C", "ipv4": "192.0.2.8"}
            ]}"#,
        );
        assert_eq!(
            seed.retired,
            [RetiredSeedEntry {
                target: v4(192, 0, 2, 9),
                comment: "B (XX)".into(),
                retired_in: 3,
            }],
            "a live address and a row without retired-in are not retired"
        );
        assert_eq!(seed.version, 3, "a withdrawal is a version too");
    }

    /// Operator-published addresses the third version corrects.
    #[test]
    fn builtin_seed_v3_carries_the_published_addresses() {
        let seed = builtin_seed();
        for ip in [
            // dismail.de fdns1
            Ipv4Addr::new(116, 203, 32, 217),
            // DNS4EU: the second IPv4 of every variant
            Ipv4Addr::new(86, 54, 11, 201),
            Ipv4Addr::new(86, 54, 11, 212),
            Ipv4Addr::new(86, 54, 11, 213),
            Ipv4Addr::new(86, 54, 11, 211),
            Ipv4Addr::new(86, 54, 11, 200),
            // Mullvad base and extended profiles
            Ipv4Addr::new(194, 242, 2, 4),
            Ipv4Addr::new(194, 242, 2, 5),
        ] {
            assert_eq!(
                since_of(&seed, &DohTarget::Ip(IpAddr::V4(ip))),
                Some(3),
                "{ip}"
            );
        }
        // Offered since the first version, under the other dismail row.
        assert_eq!(since_of(&seed, &v4(159, 69, 114, 157)), Some(1));
        let stale = v4(80, 241, 218, 68);
        assert!(!has(&seed, &stale));
        assert_eq!(
            seed.retired,
            [RetiredSeedEntry {
                target: stale,
                comment: "dismail.de fdns2 (DE)".into(),
                retired_in: 3,
            }]
        );
        let unfiltered = seed
            .entries
            .iter()
            .find(|s| s.entry.target == v4(194, 242, 2, 2))
            .expect("mullvad unfiltered");
        assert_eq!(
            unfiltered.entry.comment,
            "Mullvad DNS (unfiltered) (global)"
        );
    }

    #[test]
    fn an_entry_newer_than_the_declared_version_raises_it() {
        let seed = parse_seed(
            r#"{"seed-version": 1, "resolvers": [{"provider": "A", "since": 2, "ipv4": "192.0.2.1"}]}"#,
        );
        assert_eq!(seed.version, 2);
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
            assert!(has(&seed, &DohTarget::Ip(IpAddr::V4(ip))), "{ip} missing");
        }
    }

    /// The operators' published IPv6 addresses of the largest resolvers are in
    /// the seed, or a dual-stack browser keeps DoH through them.
    #[test]
    fn builtin_seed_carries_ipv6_resolver_addresses() {
        let seed = builtin_seed();
        for ip in [
            Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888),
            Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8844),
            Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111),
            Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1001),
            Ipv6Addr::new(0x2620, 0xfe, 0, 0, 0, 0, 0, 0xfe),
            Ipv6Addr::new(0x2620, 0xfe, 0, 0, 0, 0, 0, 0x9),
            Ipv6Addr::new(0x2a10, 0x50c0, 0, 0, 0, 0, 0xad1, 0xff),
        ] {
            let target = DohTarget::Ip(IpAddr::V6(ip));
            assert_eq!(since_of(&seed, &target), Some(2), "{ip} missing");
        }
        let v6_rows = seed
            .entries
            .iter()
            .filter(|s| matches!(s.entry.target, DohTarget::Ip(IpAddr::V6(_))))
            .count();
        assert!(v6_rows > 40, "IPv6 seed unexpectedly small: {v6_rows}");
    }

    #[test]
    fn parse_seed_reads_the_ipv6_list() {
        let seed = parse_seed(
            r#"{"resolvers": [
                {"provider": "A", "ipv4": "192.0.2.1", "ipv6": "2001:db8::1, 2001:db8::2"}
            ]}"#,
        );
        assert_eq!(seed.entries.len(), 3);
        assert!(has(
            &seed,
            &DohTarget::Ip(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)))
        ));
    }

    #[test]
    fn malformed_json_yields_empty() {
        assert!(parse_seed("not json").entries.is_empty());
        assert!(parse_seed("{}").entries.is_empty());
    }

    fn state_conn() -> Mutex<Connection> {
        use nrr_storage::migration::SqliteMigrationRunner;
        use nrr_storage::repository::MigrationRunner;
        let runner =
            SqliteMigrationRunner::for_state_db(Connection::open_in_memory().expect("in-memory"));
        runner.run_pending_migrations().expect("migrate");
        Mutex::new(runner.into_connection())
    }

    fn loaded(conn: &Mutex<Connection>) -> Vec<DohResolverEntry> {
        let guard = conn.lock().expect("lock");
        DohResolverEntriesRepository::new(&guard)
            .load_all()
            .expect("load")
    }

    fn applied(conn: &Mutex<Connection>) -> Option<u32> {
        let guard = conn.lock().expect("lock");
        DohResolverEntriesRepository::new(&guard)
            .applied_seed_version()
            .expect("version")
    }

    #[test]
    fn a_fresh_database_gets_the_whole_builtin_seed() {
        let conn = state_conn();
        seed_shared_baseline(&conn);
        assert_eq!(loaded(&conn).len(), builtin_seed().entries.len());
        assert_eq!(applied(&conn), Some(builtin_seed().version));
    }

    /// An install seeded with version 1, where the user deleted a row, gets
    /// the version-2 addresses at the next start and not the deleted row.
    #[test]
    fn an_install_seeded_at_v1_receives_v2_rows_but_not_its_deleted_row() {
        let conn = state_conn();
        let seed = builtin_seed();
        assert!(seed.version >= 2);
        let v1: Vec<SeedEntry> = seed
            .entries
            .iter()
            .filter(|s| s.since == 1)
            .cloned()
            .collect();
        let deleted = v4(8, 8, 8, 8);
        {
            let guard = conn.lock().expect("lock");
            let repo = DohResolverEntriesRepository::new(&guard);
            repo.apply_seed(&v1, &[], 1, 1).expect("v1 seed");
            let mut rows = repo.load_all().expect("load");
            rows.retain(|e| e.target != deleted);
            repo.replace_all(&rows, 2).expect("user deletes a row");
        }

        seed_shared_baseline(&conn);
        let after = loaded(&conn);
        assert!(
            after.iter().all(|e| e.target != deleted),
            "deleted row came back"
        );
        for s in seed.entries.iter().filter(|s| s.since > 1) {
            assert!(
                after.iter().any(|e| e.target == s.entry.target),
                "{:?} missing",
                s.entry.target
            );
        }
        assert_eq!(after.len(), seed.entries.len() - 1);
        assert_eq!(applied(&conn), Some(seed.version));

        seed_shared_baseline(&conn);
        assert_eq!(loaded(&conn), after, "a second run changes nothing");
    }

    /// An install at version 2 — withdrawn address included, as it was seeded —
    /// gains exactly the version-3 entries and loses the withdrawn one.
    #[test]
    fn an_install_at_v2_gets_exactly_the_v3_changes() {
        let conn = state_conn();
        let seed = builtin_seed();
        assert_eq!(seed.version, 3);
        let mut v2: Vec<SeedEntry> = seed
            .entries
            .iter()
            .filter(|s| s.since <= 2)
            .cloned()
            .collect();
        v2.extend(seed.retired.iter().map(|r| SeedEntry {
            entry: DohResolverEntry {
                target: r.target.clone(),
                comment: r.comment.clone(),
                enabled: true,
            },
            since: 1,
        }));
        {
            let guard = conn.lock().expect("lock");
            DohResolverEntriesRepository::new(&guard)
                .apply_seed(&v2, &[], 2, 1)
                .expect("v2 seed");
        }
        let before = loaded(&conn);

        seed_shared_baseline(&conn);
        let after = loaded(&conn);
        let added: Vec<&DohTarget> = after
            .iter()
            .map(|e| &e.target)
            .filter(|t| !before.iter().any(|b| &b.target == *t))
            .collect();
        let mut expected: Vec<&DohTarget> = seed
            .entries
            .iter()
            .filter(|s| s.since == 3)
            .map(|s| &s.entry.target)
            .collect();
        let key = |t: &&DohTarget| (t.kind_str(), t.value_str());
        let mut added = added;
        added.sort_by_key(key);
        expected.sort_by_key(key);
        assert_eq!(added, expected);
        for r in &seed.retired {
            assert!(
                after.iter().all(|e| e.target != r.target),
                "{:?} kept",
                r.target
            );
        }
        assert_eq!(after.len(), seed.entries.len());
        assert_eq!(applied(&conn), Some(3));
    }

    /// A withdrawn address the user relabelled is theirs now and stays.
    #[test]
    fn a_relabelled_withdrawn_address_survives_the_upgrade() {
        let conn = state_conn();
        let seed = builtin_seed();
        let stale = seed
            .retired
            .first()
            .expect("a retired entry")
            .target
            .clone();
        {
            let guard = conn.lock().expect("lock");
            let repo = DohResolverEntriesRepository::new(&guard);
            let mut rows: Vec<DohResolverEntry> = seed
                .entries
                .iter()
                .filter(|s| s.since <= 2)
                .map(|s| s.entry.clone())
                .collect();
            rows.push(DohResolverEntry {
                target: stale.clone(),
                comment: "my own".into(),
                enabled: true,
            });
            repo.apply_seed(&[], &[], 2, 1).expect("mark v2");
            repo.replace_all(&rows, 1).expect("user list");
        }
        seed_shared_baseline(&conn);
        assert!(loaded(&conn).iter().any(|e| e.target == stale));
    }
}
