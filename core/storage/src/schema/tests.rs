use super::*;
use nrr_domain::decision_lookup::{CacheEntryState, LookupDirection};

// ── DiagnosticFlags ───────────────────────────────────────────────────────

#[test]
fn diagnostic_flags_to_db_from_db_roundtrip() {
    let flags = DiagnosticFlags::AMBIGUOUS | DiagnosticFlags::CONFLICTING;
    assert_eq!(DiagnosticFlags::from_db(flags.to_db()), flags);
}

#[test]
fn diagnostic_flags_empty_is_zero() {
    assert_eq!(DiagnosticFlags::empty().to_db(), 0i64);
    assert_eq!(DiagnosticFlags::from_db(0), DiagnosticFlags::empty());
}

#[test]
fn diagnostic_flags_all_bits_roundtrip() {
    let all = DiagnosticFlags::AMBIGUOUS
        | DiagnosticFlags::CONFLICTING
        | DiagnosticFlags::STALE
        | DiagnosticFlags::NEGATIVE_CACHED
        | DiagnosticFlags::LOOKUP_FAILED
        | DiagnosticFlags::UNSUPPORTED_ADDR_FAM;
    assert_eq!(DiagnosticFlags::from_db(all.to_db()), all);
}

#[test]
fn diagnostic_flags_unknown_bits_truncated() {
    // Bit 7 is not defined; from_db should drop it silently.
    let raw: i64 = 0b1000_0000;
    assert_eq!(DiagnosticFlags::from_db(raw), DiagnosticFlags::empty());
}

// ── FreshnessStateDb ──────────────────────────────────────────────────────

const FRESHNESS_VARIANTS: &[(FreshnessStateDb, &str, CacheEntryState)] = &[
    (FreshnessStateDb::Fresh, "fresh", CacheEntryState::Fresh),
    (
        FreshnessStateDb::StaleUsable,
        "stale_usable",
        CacheEntryState::StaleUsable,
    ),
    (
        FreshnessStateDb::StaleNotUsable,
        "stale_not_usable",
        CacheEntryState::StaleNotUsable,
    ),
    (
        FreshnessStateDb::Conflicting,
        "conflicting",
        CacheEntryState::Conflicting,
    ),
    (
        FreshnessStateDb::NegativeCached,
        "negative_cached",
        CacheEntryState::NegativeCached,
    ),
];

#[test]
fn freshness_state_as_str_matches_expected() {
    for &(variant, expected_str, _) in FRESHNESS_VARIANTS {
        assert_eq!(variant.as_str(), expected_str);
    }
}

#[test]
fn freshness_state_from_str_roundtrip() {
    for &(variant, s, _) in FRESHNESS_VARIANTS {
        let back =
            FreshnessStateDb::from_str(s).unwrap_or_else(|| panic!("from_str({s:?}) must succeed"));
        assert_eq!(back, variant);
    }
}

#[test]
fn freshness_state_from_str_unknown_returns_none() {
    assert!(FreshnessStateDb::from_str("missing").is_none());
    assert!(FreshnessStateDb::from_str("FRESH").is_none());
    assert!(FreshnessStateDb::from_str("").is_none());
}

#[test]
fn freshness_state_to_domain_is_correct() {
    for &(variant, _, ref expected_domain) in FRESHNESS_VARIANTS {
        assert_eq!(variant.to_domain(), *expected_domain);
    }
}

#[test]
fn freshness_state_from_domain_roundtrip() {
    for &(expected_variant, _, ref domain) in FRESHNESS_VARIANTS {
        let back = FreshnessStateDb::from_domain(domain)
            .unwrap_or_else(|| panic!("from_domain({domain:?}) must succeed"));
        assert_eq!(back, expected_variant);
    }
}

#[test]
fn freshness_state_missing_has_no_db_form() {
    assert!(FreshnessStateDb::from_domain(&CacheEntryState::Missing).is_none());
}

// ── LookupDirection TEXT helpers ──────────────────────────────────────────

#[test]
fn lookup_direction_str_roundtrip() {
    let cases = [
        (LookupDirection::HostnameToIp, "hostname_to_ip"),
        (LookupDirection::IpToHostname, "ip_to_hostname"),
        (LookupDirection::Both, "both"),
    ];
    for (dir, expected) in &cases {
        assert_eq!(lookup_direction_as_str(dir), *expected);
        let back = lookup_direction_from_str(expected)
            .unwrap_or_else(|| panic!("from_str({expected:?}) must succeed"));
        assert_eq!(&back, dir);
    }
}

#[test]
fn lookup_direction_unknown_returns_none() {
    assert!(lookup_direction_from_str("HostnameToIp").is_none());
    assert!(lookup_direction_from_str("").is_none());
}

// ── DDL execution against in-memory SQLite ────────────────────────────────

fn open_memory_db() -> rusqlite::Connection {
    let conn = rusqlite::Connection::open_in_memory().expect("in-memory SQLite must open");
    conn.execute_batch("PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;")
        .expect("pragmas");
    conn
}

#[test]
fn cache_db_v1_ddl_executes_without_error() {
    let conn = open_memory_db();
    for stmt in CACHE_DB_V1_DDL {
        conn.execute_batch(stmt)
            .unwrap_or_else(|e| panic!("DDL failed: {e}\nSQL: {stmt}"));
    }
}

#[test]
fn cache_db_v1_ddl_is_idempotent() {
    let conn = open_memory_db();
    // Run twice — CREATE IF NOT EXISTS must be safe.
    for _ in 0..2 {
        for stmt in CACHE_DB_V1_DDL {
            conn.execute_batch(stmt)
                .unwrap_or_else(|e| panic!("DDL failed on second run: {e}"));
        }
    }
}

#[test]
fn cache_db_all_expected_tables_exist() {
    let conn = open_memory_db();
    for stmt in CACHE_DB_V1_DDL {
        conn.execute_batch(stmt).expect("DDL");
    }
    let expected_tables = [
        "hostnames",
        "ip_addresses",
        "hostname_ip_resolutions",
        "lookup_events",
        "negative_cache",
        "cache_metadata",
    ];
    for table in &expected_tables {
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                rusqlite::params![table],
                |row| row.get(0),
            )
            .unwrap_or_else(|e| panic!("table check failed for {table}: {e}"));
        assert_eq!(count, 1, "table {table} must exist after DDL");
    }
}

#[test]
fn cache_db_foreign_keys_enforced() {
    let conn = open_memory_db();
    for stmt in CACHE_DB_V1_DDL {
        conn.execute_batch(stmt).expect("DDL");
    }
    // Inserting a resolution with a non-existent hostname_id must fail.
    let result = conn.execute(
        "INSERT INTO hostname_ip_resolutions
             (hostname_id, ip_id, source, resolved_at, expires_at, freshness_state)
             VALUES (9999, 9999, 'dns', 0, 0, 'fresh')",
        [],
    );
    assert!(
        result.is_err(),
        "foreign key violation must be rejected when foreign_keys = ON"
    );
}

#[test]
fn cache_db_cache_metadata_singleton_enforced() {
    let conn = open_memory_db();
    for stmt in CACHE_DB_V1_DDL {
        conn.execute_batch(stmt).expect("DDL");
    }
    conn.execute(
        "INSERT INTO cache_metadata (id, schema_version, created_at, cache_generation)
             VALUES (1, 1, 0, 0)",
        [],
    )
    .expect("first insert");
    let result = conn.execute(
        "INSERT INTO cache_metadata (id, schema_version, created_at, cache_generation)
             VALUES (2, 1, 0, 0)",
        [],
    );
    assert!(result.is_err(), "cache_metadata must allow only id=1");
}

#[test]
fn cache_db_resolution_unique_constraint() {
    let conn = open_memory_db();
    for stmt in CACHE_DB_V1_DDL {
        conn.execute_batch(stmt).expect("DDL");
    }
    // Seed required parent rows.
    conn.execute(
        "INSERT INTO hostnames (canonical_host, first_seen_at, last_seen_at)
             VALUES ('example.com', 0, 0)",
        [],
    )
    .expect("hostname");
    conn.execute(
            "INSERT INTO ip_addresses (address_family, canonical_ip, ipv4_packed, first_seen_at, last_seen_at)
             VALUES ('ipv4', '1.2.3.4', 16909060, 0, 0)",
            [],
        )
        .expect("ip");
    conn.execute(
        "INSERT INTO hostname_ip_resolutions
             (hostname_id, ip_id, source, resolved_at, expires_at, freshness_state)
             VALUES (1, 1, 'dns', 0, 0, 'fresh')",
        [],
    )
    .expect("first resolution");
    // Inserting the same (hostname_id, ip_id, source) again must fail.
    let result = conn.execute(
        "INSERT INTO hostname_ip_resolutions
             (hostname_id, ip_id, source, resolved_at, expires_at, freshness_state)
             VALUES (1, 1, 'dns', 100, 200, 'fresh')",
        [],
    );
    assert!(
        result.is_err(),
        "duplicate (hostname_id, ip_id, source) must be rejected"
    );
}

#[test]
fn state_db_v1_ddl_executes_without_error() {
    let conn = open_memory_db();
    for stmt in STATE_DB_V1_DDL {
        conn.execute_batch(stmt)
            .unwrap_or_else(|e| panic!("state DDL failed: {e}\nSQL: {stmt}"));
    }
}

#[test]
fn state_db_all_expected_tables_exist() {
    let conn = open_memory_db();
    for stmt in STATE_DB_V1_DDL {
        conn.execute_batch(stmt).expect("state DDL");
    }
    for table in &["active_revision", "last_known_good", "integrity_log"] {
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                rusqlite::params![table],
                |row| row.get(0),
            )
            .unwrap_or_else(|e| panic!("table check failed for {table}: {e}"));
        assert_eq!(count, 1, "table {table} must exist after state DDL");
    }
}
