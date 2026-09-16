use super::*;
use nrr_platform_api::hosts_file::HostsPin;
use std::collections::HashMap;
use std::net::Ipv4Addr;

fn row(rule_type: &str, match_value: &str) -> RuleRowEntry {
    RuleRowEntry {
        id: "R-1".into(),
        rule_type: rule_type.into(),
        match_value: match_value.into(),
        target_route: "primary".into(),
        comment: None,
        enabled: true,
        validation_status: "ok".into(),
        validation_message_key: None,
        main_route: None,
        hosts_override: None,
        origin: None,
        pinned_destinations: None,
        pinned_destinations_total: None,
    }
}

fn resp(rows: Vec<RuleRowEntry>) -> RulesListResponse {
    RulesListResponse {
        rows,
        supported_rule_types: rule_type_slugs(),
        active_revision_id: Some("rev-1".into()),
    }
}

fn hosts_map() -> HashMap<String, HostsPin> {
    let mut m = HashMap::new();
    m.insert(
        "ads.example.com".into(),
        HostsPin {
            ip: Ipv4Addr::LOCALHOST,
            blocking: true,
        },
    );
    m.insert(
        "mirror.example.com".into(),
        HostsPin {
            ip: Ipv4Addr::new(203, 0, 113, 7),
            blocking: false,
        },
    );
    m
}

#[test]
fn blocking_entry_annotates_domain_row() {
    let mut r = resp(vec![row("domain", "ads.example.com")]);
    annotate_hosts_overrides(&mut r, &hosts_map());
    let ov = r.rows[0].hosts_override.as_ref().expect("annotated");
    assert!(ov.blocking);
    assert_eq!(ov.ip, "127.0.0.1");
}

#[test]
fn redirect_entry_carries_real_ip() {
    let mut r = resp(vec![row("domain", "mirror.example.com")]);
    annotate_hosts_overrides(&mut r, &hosts_map());
    let ov = r.rows[0].hosts_override.as_ref().expect("annotated");
    assert!(!ov.blocking);
    assert_eq!(ov.ip, "203.0.113.7");
}

#[test]
fn matching_is_case_insensitive_and_dot_tolerant() {
    let mut r = resp(vec![row("domain", "ADS.Example.COM.")]);
    annotate_hosts_overrides(&mut r, &hosts_map());
    assert!(r.rows[0].hosts_override.is_some());
}

#[test]
fn non_matching_and_non_domain_rows_are_untouched() {
    let mut r = resp(vec![
        row("domain", "not-in-hosts.example.com"), // no hosts entry
        row("domain", "*.example.com"),            // suffix wildcard — skipped
        row("zone", "ads.example.com"),            // zone type — skipped
        row("exact-ip", "127.0.0.1"),              // IP rule — skipped
        row("application", "browser.exe"),         // app rule — skipped
    ]);
    annotate_hosts_overrides(&mut r, &hosts_map());
    for row in &r.rows {
        assert!(
            row.hosts_override.is_none(),
            "row {} annotated",
            row.match_value
        );
    }
}

#[test]
fn empty_hosts_map_is_a_noop() {
    let mut r = resp(vec![row("domain", "ads.example.com")]);
    annotate_hosts_overrides(&mut r, &HashMap::new());
    assert!(r.rows[0].hosts_override.is_none());
}

#[test]
fn provider_annotate_uses_injected_reader() {
    use nrr_platform_api::hosts_file::StaticHostsFileReader;
    let reader = Arc::new(StaticHostsFileReader::from_pairs([(
        "ads.example.com",
        Ipv4Addr::LOCALHOST,
    )]));
    // The DB connection is never touched by `annotate`, so a throwaway
    // in-memory connection is fine for exercising the reader path.
    let conn = Arc::new(Mutex::new(
        rusqlite::Connection::open_in_memory().expect("open in-memory"),
    ));
    let provider = ProductionRulesSnapshotProvider::with_hosts_reader(conn, reader);
    let mut r = resp(vec![row("domain", "ads.example.com")]);
    provider.annotate(&mut r, "");
    assert!(
        r.rows[0]
            .hosts_override
            .as_ref()
            .expect("annotated")
            .blocking
    );
}
