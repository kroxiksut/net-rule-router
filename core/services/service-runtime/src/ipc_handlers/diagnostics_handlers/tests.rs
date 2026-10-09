use super::*;
// Private to the archive module; its naming and pruning tests live here.
use super::archive::{
    format_timestamp_for_filename, prune_old_archives, sanitize_for_filename, unique_archive_path,
};
use crate::ipc_handlers::test_fakes::{FakeAdapters, FakeRoutePolicy};
use nrr_diagnostics::audit::alert::InMemorySecurityAlertsRepository;
use nrr_shared::ipc::{IpcClientProfile, IpcOperationName};
use std::net::IpAddr;

fn fake_adapters() -> Arc<dyn AdaptersSnapshotProvider> {
    Arc::new(FakeAdapters::empty())
}

fn fake_route_policy() -> Arc<dyn RoutePolicyProvider> {
    Arc::new(FakeRoutePolicy::default())
}

// ── CacheClearHandler (two-target split) ─────────────────────────

/// A real temp-file `SqliteCacheStore` — the trait has ~15 methods, so a
/// hand fake is disproportionate; a migrated temp DB is honest and cheap.
/// Returns the store plus the `TempDir` guard (drop = cleanup).
fn temp_cache() -> (
    tempfile::TempDir,
    Arc<Mutex<dyn nrr_storage::repository::CacheRepository + Send>>,
) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("nrr_fqdn_ip_cache.db");
    let conn = nrr_storage::migration::open_connection(&path).expect("open");
    let runner = nrr_storage::migration::SqliteMigrationRunner::for_cache_db(conn);
    use nrr_storage::repository::MigrationRunner as _;
    runner.run_pending_migrations().expect("migrate");
    let store = nrr_storage::store::SqliteCacheStore::new(
        runner.into_connection(),
        nrr_storage::FreshnessThresholds::default_production(),
    );
    (dir, Arc::new(Mutex::new(store)))
}

fn cache_clear(handler: &CacheClearHandler, payload: serde_json::Value) -> CacheClearResponse {
    let env = IpcRequestEnvelope {
        protocol_version: crate::ipc::IPC_PROTOCOL_VERSION,
        request_id: "r".into(),
        correlation_id: None,
        operation: IpcOperationName::CacheClear,
        operation_class: crate::ipc::IpcOperationClass::DiagnosticQuery,
        confirmation_token: None,
        payload,
    };
    let ctx = IpcRequestContext {
        client_profile: IpcClientProfile::GuiInteractive,
        caller_is_elevated: false,
        caller_principal: None,
        caller_pid: None,
    };
    let value = handler.handle(&env, &ctx).expect("cache.clear ok");
    serde_json::from_value(value).expect("decode CacheClearResponse")
}

// ── ConnTraceEntriesListHandler ──────────────────────────────────

fn conn_trace_list(handler: &ConnTraceEntriesListHandler) -> ConnTraceEntriesListResponse {
    let env = IpcRequestEnvelope {
        protocol_version: crate::ipc::IPC_PROTOCOL_VERSION,
        request_id: "r".into(),
        correlation_id: None,
        operation: IpcOperationName::ConnTraceEntriesList,
        operation_class: crate::ipc::IpcOperationClass::DiagnosticQuery,
        confirmation_token: None,
        payload: serde_json::Value::Null,
    };
    let ctx = IpcRequestContext {
        client_profile: IpcClientProfile::GuiInteractive,
        caller_is_elevated: false,
        caller_principal: None,
        caller_pid: None,
    };
    let value = handler
        .handle(&env, &ctx)
        .expect("conn-trace.entries.list ok");
    serde_json::from_value(value).expect("decode ConnTraceEntriesListResponse")
}

/// One observed connection, enough to prove a page is (or is not) served.
fn trace_row() -> crate::conn_observation_consumer::ConnectionTraceRecord {
    use nrr_platform_api::conn_observe::egress::{EgressInterface, EgressRole};
    use nrr_platform_api::conn_observe::{ConnectionVerdict, TransportProtocol};
    crate::conn_observation_consumer::ConnectionTraceRecord {
        process_path: Some(r"\device\hd\chrome.exe".into()),
        user_sid: None,
        protocol: TransportProtocol::Tcp,
        local: "192.0.2.10:52000".parse().expect("local"),
        remote: "198.51.100.7:443".parse().expect("remote"),
        egress: EgressInterface {
            ifindex: 7,
            role: EgressRole::Primary,
        },
        verdict: ConnectionVerdict::Permit,
        blocked_by_nrr: None,
        nrr_drop_spec_id: None,
        nrr_block_reason: None,
        observed_unix_ms: Some(1_757_000_000_000),
        remote_names: None,
    }
}

/// The switch is the user's own "do not show me this"; it must silence the
/// VIEWER without silencing the observation the rest of the service reads.
/// The enabled case is the positive control: without it, a handler that
/// simply never answers would pass.
#[test]
fn conn_trace_gui_switch_gates_the_answer_not_the_ring() {
    let ring = Arc::new(crate::conn_observation_consumer::ConnectionTraceRing::new(
        8,
    ));
    ring.mark_observer_active();
    ring.push(trace_row());

    let hidden = ConnTraceEntriesListHandler::new(Arc::clone(&ring)).with_gui_stream_gate(
        crate::ipc_handlers::test_fakes::FakeConnTraceGui::showing(false),
    );
    let resp = conn_trace_list(&hidden);
    assert!(resp.page.items.is_empty(), "the switch is off");
    assert!(
        !resp.gui_stream_enabled,
        "and the viewer says why it is empty"
    );
    assert!(
        resp.observer_active,
        "the observer keeps running — app-routing and the learners read it"
    );
    assert_eq!(ring.len(), 1, "the ring is untouched by the switch");

    let shown = ConnTraceEntriesListHandler::new(Arc::clone(&ring)).with_gui_stream_gate(
        crate::ipc_handlers::test_fakes::FakeConnTraceGui::showing(true),
    );
    let resp = conn_trace_list(&shown);
    assert_eq!(
        resp.page.items.len(),
        1,
        "switched on, the same row is served"
    );
    assert!(resp.gui_stream_enabled);
}

/// An empty page means two different things, and the viewer can only tell
/// them apart if the answer carries the observer's state. Both directions
/// are asserted: without the positive control, a field wired to a constant
/// `false` would pass the first half on its own.
#[test]
fn conn_trace_reports_whether_the_observer_is_running() {
    let ring = Arc::new(crate::conn_observation_consumer::ConnectionTraceRing::new(
        8,
    ));
    let handler = ConnTraceEntriesListHandler::new(Arc::clone(&ring));

    let idle = conn_trace_list(&handler);
    assert!(idle.page.items.is_empty());
    assert!(
        !idle.observer_active,
        "nothing has started the observer yet"
    );

    ring.mark_observer_active();
    let watching = conn_trace_list(&handler);
    assert!(
        watching.observer_active,
        "an empty ring under a running observer means 'nothing happened yet'"
    );
}

/// The name is resolved as the row enters the ring and served with it; a row
/// recorded before any name was known still renders, address only.
#[test]
fn conn_trace_rows_carry_the_names_seen_for_their_remote() {
    use crate::conn_trace_names::{AddressNameSource, ConnTraceNamer};
    let ring = Arc::new(crate::conn_observation_consumer::ConnectionTraceRing::new(
        8,
    ));
    ring.push(trace_row());

    let names = Arc::new(crate::observed_host_names::ObservedHostNames::new());
    names.record("a.cdn.site.example", &["198.51.100.7".parse().expect("ip")]);
    assert!(ring.attach_namer(Arc::new(ConnTraceNamer::new(vec![
        names as Arc<dyn AddressNameSource>
    ]))));
    ring.push(trace_row());

    let resp = conn_trace_list(&ConnTraceEntriesListHandler::new(Arc::clone(&ring)));
    assert_eq!(resp.page.items.len(), 2);
    let (newest, oldest) = (&resp.page.items[0], &resp.page.items[1]);
    assert_eq!(newest.remote_hosts, vec!["a.cdn.site.example"]);
    assert_eq!(newest.remote_host_count, 1);
    assert_eq!(
        newest.remote_host_floor, "site.example",
        "the GUI may shorten to *.site.example, no further"
    );
    assert!(!newest.remote_fake_ip);
    assert_eq!(newest.remote, "198.51.100.7:443", "the address stays");
    assert!(oldest.remote_hosts.is_empty());
    assert_eq!(oldest.remote_host_count, 0);
    assert!(oldest.remote_host_floor.is_empty());
}

/// A virtual address is named by the pool and says so; once its binding is
/// recycled the row still says it is virtual rather than going blank.
#[test]
fn conn_trace_rows_name_virtual_addresses_from_the_pool() {
    use crate::conn_trace_names::ConnTraceNamer;
    use crate::dns_resolver::FakeIpAnswerer;
    use nrr_platform_api::fake_ip::{FakeIpPoolConfig, FakeIpScope};
    let assembly = crate::fake_ip::FakeIpAssembly::new(
        FakeIpScope::enabled(Vec::<String>::new()),
        FakeIpPoolConfig::default(),
    );
    let fake = assembly
        .answerer()
        .fake_answer("app.example")
        .expect("in scope")[0];
    let recycled = std::net::Ipv4Addr::from(u32::from(fake) + 1);

    let ring = Arc::new(crate::conn_observation_consumer::ConnectionTraceRing::new(
        8,
    ));
    assert!(ring.attach_namer(Arc::new(
        ConnTraceNamer::new(Vec::new()).with_fake_ip_pool(assembly.binding_view())
    )));
    for ip in [recycled, fake] {
        let mut row = trace_row();
        row.remote = std::net::SocketAddr::new(ip.into(), 443);
        ring.push(row);
    }

    let resp = conn_trace_list(&ConnTraceEntriesListHandler::new(Arc::clone(&ring)));
    let (named, bare) = (&resp.page.items[0], &resp.page.items[1]);
    assert_eq!(named.remote_hosts, vec!["app.example"]);
    assert!(named.remote_fake_ip);
    assert!(bare.remote_hosts.is_empty());
    assert!(bare.remote_fake_ip, "recycled, yet still marked virtual");
}

/// A conn-trace handler whose expectation reads `book`, over `remotes`
/// (newest last, so the page lists them in reverse).
fn conn_trace_with_book(
    book: nrr_domain::canonical::CanonicalRuleBook,
    remotes: &[&str],
) -> ConnTraceEntriesListResponse {
    use crate::fqdn_cache_lookup::MockFqdnCacheLookup;
    use crate::per_sid_orchestrator::ActiveRulesSnapshot;

    struct BookRules(nrr_domain::canonical::CanonicalRuleBook);
    impl RulesProvider for BookRules {
        fn active_rules(&self) -> Option<ActiveRulesSnapshot> {
            Some(ActiveRulesSnapshot {
                rule_book: self.0.clone(),
                behavior_mode: nrr_domain::RouteBehaviorMode::PreferPrimary,
            })
        }
    }

    let ring = Arc::new(crate::conn_observation_consumer::ConnectionTraceRing::new(
        8,
    ));
    for remote in remotes {
        let mut row = trace_row();
        row.remote = remote.parse().expect("remote");
        ring.push(row);
    }
    let handler = ConnTraceEntriesListHandler::new(ring).with_route_expectation(
        Arc::new(BookRules(book)),
        Arc::new(MockFqdnCacheLookup::new()),
        Arc::new(|| Some("S-1-5-21-T".to_string())),
    );
    conn_trace_list(&handler)
}

fn route_rule(
    id: &str,
    m: nrr_domain::canonical::CanonicalAddressMatch,
) -> nrr_domain::canonical::CanonicalRule {
    nrr_domain::canonical::CanonicalRule {
        id: nrr_domain::RuleId(id.into()),
        enabled: true,
        address_match: Some(m),
        app_match: None,
        comment: String::new(),
        action: nrr_domain::RuleAction::Route,
        origin: None,
    }
}

fn subnet_match(net: &str) -> nrr_domain::canonical::CanonicalAddressMatch {
    nrr_domain::canonical::CanonicalAddressMatch::Subnet(
        nrr_shared::ip_block::IpBlock::parse(net).expect("test network literal"),
    )
}

/// What enforcement carries decides what the trace expects: on a platform
/// that routes no networks, a network rule expects nothing.
fn expected_for_network(label: &str) -> (&'static str, String) {
    if crate::wfp_codegen::current_rule_shape_support().network_destination {
        ("secondary", label.to_string())
    } else {
        ("", String::new())
    }
}

/// A flow into a network the additional link carries is expected there, so
/// the GUI can flag one that left over the main link.
#[test]
fn conn_trace_expects_a_secondary_subnet_on_the_secondary() {
    use nrr_domain::canonical::{CanonicalAddressMatch, CanonicalRuleBook, CanonicalRuleSet};
    let book = CanonicalRuleBook {
        primary: CanonicalRuleSet::from_rules(vec![
            route_rule(
                "p-ip",
                CanonicalAddressMatch::ExactIp("198.51.100.9".parse().expect("ip")),
            ),
            route_rule("p-net", subnet_match("198.51.100.128/25")),
        ]),
        secondary: CanonicalRuleSet::from_rules(vec![
            route_rule("s-net", subnet_match("198.51.100.0/24")),
            route_rule(
                "s-range",
                CanonicalAddressMatch::ip_range(
                    nrr_shared::ip_block::IpRange::parse("203.0.113.10-203.0.113.20")
                        .expect("test range literal"),
                ),
            ),
        ]),
    };
    let resp = conn_trace_with_book(
        book,
        &[
            "198.51.100.7:443",
            "198.51.100.9:443",
            "198.51.100.200:443",
            "203.0.113.15:443",
            "192.0.2.80:443",
        ],
    );
    let rows: Vec<(&str, &str, &str)> = resp
        .page
        .items
        .iter()
        .map(|r| {
            (
                r.remote.as_str(),
                r.expected_route.as_str(),
                r.rule_host.as_str(),
            )
        })
        .collect();
    let (subnet_route, subnet_label) = expected_for_network("198.51.100.0/24");
    let (range_route, range_label) = expected_for_network("203.0.113.10-203.0.113.20");
    assert_eq!(
        rows,
        vec![
            ("192.0.2.80:443", "", ""),
            ("203.0.113.15:443", range_route, range_label.as_str()),
            // A longer main-link prefix inside the secondary network wins.
            ("198.51.100.200:443", "", ""),
            // An exact main-link address inside it stays main.
            ("198.51.100.9:443", "", ""),
            ("198.51.100.7:443", subnet_route, subnet_label.as_str()),
        ]
    );
}

#[test]
fn cache_clear_app_only_does_not_flush_os_cache() {
    let (_dir, cache) = temp_cache();
    let flush = Arc::new(nrr_platform_api::dns::MockDnsCacheControl::new());
    let handler = CacheClearHandler::new(cache).with_dns_cache_control(
        flush.clone() as Arc<dyn nrr_platform_api::dns::DnsCacheControlPort>
    );
    // Default request = app cache only (clear_app_cache defaults true).
    let resp = cache_clear(&handler, serde_json::json!({}));
    assert_eq!(resp.os_cache_flushed, None, "OS flush not requested");
    assert_eq!(flush.flush_count(), 0);
}

#[test]
fn cache_clear_os_only_flushes_and_does_not_error() {
    let (_dir, cache) = temp_cache();
    let flush = Arc::new(nrr_platform_api::dns::MockDnsCacheControl::new());
    let handler = CacheClearHandler::new(cache).with_dns_cache_control(
        flush.clone() as Arc<dyn nrr_platform_api::dns::DnsCacheControlPort>
    );
    let resp = cache_clear(
        &handler,
        serde_json::json!({ "clear-app-cache": false, "flush-os-cache": true }),
    );
    assert_eq!(resp.resolutions_removed, 0, "app cache untouched");
    assert_eq!(resp.os_cache_flushed, Some(true));
    assert_eq!(flush.flush_count(), 1);
}

#[test]
fn cache_clear_os_flush_without_port_reports_false() {
    let (_dir, cache) = temp_cache();
    let handler = CacheClearHandler::new(cache); // no port wired
    let resp = cache_clear(
        &handler,
        serde_json::json!({ "clear-app-cache": false, "flush-os-cache": true }),
    );
    assert_eq!(
        resp.os_cache_flushed,
        Some(false),
        "flush requested with no port must report Some(false), not error"
    );
}

#[test]
fn sanitize_for_filename_keeps_safe_chars_and_replaces_the_rest() {
    assert_eq!(sanitize_for_filename("0.1.0-preview"), "0.1.0-preview");
    assert_eq!(sanitize_for_filename("1.0 build/x64"), "1.0-build-x64");
    assert_eq!(sanitize_for_filename(""), "unknown");
}

#[test]
fn unique_archive_path_avoids_collision() {
    let dir = tempfile::tempdir().expect("temp");
    let now_ms = 1_745_000_000_123;
    let first = unique_archive_path(dir.path(), "0.1.0", now_ms);
    assert!(first
        .file_name()
        .unwrap()
        .to_string_lossy()
        .starts_with("nrr-diagnostics-v0.1.0-"));
    // Create the first file so the SAME timestamp must pick a new name.
    std::fs::write(&first, b"x").expect("write");
    let second = unique_archive_path(dir.path(), "0.1.0", now_ms);
    assert_ne!(first, second, "a taken name must be bumped");
    assert!(second
        .file_name()
        .unwrap()
        .to_string_lossy()
        .contains("-1.zip"));
}

#[test]
fn prune_keeps_newest_archives_and_ignores_foreign_files() {
    // Retention keeps the newest `keep`
    // of OUR archives (by mtime) and never touches other files.
    let dir = tempfile::tempdir().expect("tempdir");
    let base = std::time::SystemTime::now() - std::time::Duration::from_secs(1_000);
    for i in 0..7u64 {
        let p = dir.path().join(format!("nrr-diagnostics-v0-t-{i}.zip"));
        std::fs::write(&p, b"z").expect("write");
        let f = std::fs::OpenOptions::new()
            .write(true)
            .open(&p)
            .expect("open");
        f.set_modified(base + std::time::Duration::from_secs(i * 10))
            .expect("set mtime");
    }
    let foreign = dir.path().join("keep-me.txt");
    std::fs::write(&foreign, b"f").expect("write foreign");

    prune_old_archives(dir.path(), 5);

    let mut left: Vec<String> = std::fs::read_dir(dir.path())
        .expect("read dir")
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    left.sort();
    assert!(
        left.contains(&"keep-me.txt".to_string()),
        "foreign untouched"
    );
    let zips: Vec<&String> = left.iter().filter(|n| n.ends_with(".zip")).collect();
    assert_eq!(zips.len(), 5, "exactly the newest 5 archives remain");
    assert!(
        !left.contains(&"nrr-diagnostics-v0-t-0.zip".to_string())
            && !left.contains(&"nrr-diagnostics-v0-t-1.zip".to_string()),
        "the two OLDEST archives are pruned"
    );
}

use crate::ipc::{IpcOperationClass, IpcRequestContext, IpcRequestEnvelope};

fn ctx() -> IpcRequestContext {
    IpcRequestContext {
        client_profile: IpcClientProfile::GuiInteractive,
        caller_is_elevated: true,
        caller_principal: crate::UserPrincipal::from_windows_sid("S-1-5-21-test").ok(),
        caller_pid: None,
    }
}

fn envelope(payload: serde_json::Value) -> IpcRequestEnvelope {
    IpcRequestEnvelope {
        protocol_version: 1,
        request_id: "req-1".into(),
        correlation_id: None,
        operation: IpcOperationName::ExplainGet,
        operation_class: IpcOperationClass::ReadSnapshot,
        confirmation_token: None,
        payload,
    }
}

fn facade() -> Arc<dyn DiagnosticsFacade> {
    let temp = tempfile::tempdir().unwrap();
    let alerts: Arc<dyn nrr_diagnostics::audit::alert::SecurityAlertsRepository> =
        Arc::new(InMemorySecurityAlertsRepository::new());
    Arc::new(
        crate::production_diagnostics::ProductionDiagnosticsFacade::new(
            temp.path().to_path_buf(),
            temp.path().to_path_buf(),
            None,
            alerts,
            None,
        ),
    )
    // tempdir dropped here; the facade only stores the path. Tests
    // that need on-disk artifacts construct their own facade.
}

#[test]
fn explain_rejects_both_fields_set() {
    let h = ExplainGetHandler::new(facade());
    let payload = serde_json::json!({
        "decision-id": "d-1",
        "input-sample": { "hostname": "short.example" }
    });
    let r = h.handle(&envelope(payload), &ctx());
    assert!(r.is_err());
    let err = r.unwrap_err();
    assert_eq!(err.code, IpcErrorCode::MalformedRequest);
}

#[test]
fn explain_rejects_neither_field_set() {
    let h = ExplainGetHandler::new(facade());
    let r = h.handle(&envelope(serde_json::json!({})), &ctx());
    assert!(r.is_err());
    assert_eq!(r.unwrap_err().code, IpcErrorCode::MalformedRequest);
}

#[test]
fn explain_rejects_empty_decision_id() {
    let h = ExplainGetHandler::new(facade());
    let payload = serde_json::json!({ "decision-id": "" });
    let r = h.handle(&envelope(payload), &ctx());
    assert!(r.is_err());
    assert_eq!(r.unwrap_err().code, IpcErrorCode::MalformedRequest);
}

#[test]
fn explain_historical_returns_compact_view() {
    let h = ExplainGetHandler::new(facade());
    let payload = serde_json::json!({ "decision-id": "d-unknown" });
    let v = h.handle(&envelope(payload), &ctx()).expect("ok");
    // Facade returns Unavailable::DecisionNotFound → response
    // still has summary + correlation; compact view falls back
    // to summary_key as reason_key, "-" as input, "none" as
    // route (no final_action_section on unavailable).
    let compact = &v["compact"];
    assert!(compact.is_object());
    assert_eq!(compact["input"], "-");
    assert_eq!(compact["route"], "none");
}

#[test]
fn explain_synthetic_passes_input_sample() {
    let h = ExplainGetHandler::new(facade());
    let payload = serde_json::json!({
        "input-sample": {
            "hostname": "example.com",
            "process-name": "chrome.exe"
        }
    });
    let v = h.handle(&envelope(payload), &ctx()).expect("ok");
    let full = &v["full"];
    // ExplainResponse.is_simulation = true.
    assert_eq!(full["query_kind"], "synthetic");
}

// The kill-switch verdict rides the compact view: an
// enabled kill-switch with block-all-unknown coverage marks an uncached
// hostname as blocked-while-armed even though the rule verdict alone
// would read "primary"/"none".
#[test]
fn explain_synthetic_stamps_killswitch_enforcement_verdict() {
    use crate::fqdn_cache_lookup::MockFqdnCacheLookup;

    struct FixedPolicy(nrr_shared::ipc_payloads::RoutePolicyDto);
    impl crate::ipc_handlers::providers::RoutePolicyProvider for FixedPolicy {
        fn get_for_sid(&self, _sid: &str) -> Option<nrr_shared::ipc_payloads::RoutePolicyDto> {
            Some(self.0.clone())
        }
    }

    let dto: nrr_shared::ipc_payloads::RoutePolicyDto = serde_json::from_value(serde_json::json!({
        "mode": "prefer-primary",
        "block-secondary-when-unavailable": true,
        "kill-switch-enabled": true,
        "mode-a-coverage-strategy": "fail-closed-unknown",
        "binding-source": "user-assigned"
    }))
    .expect("policy dto");
    let h = ExplainGetHandler::new(facade()).with_enforcement_verdict(
        Arc::new(FixedPolicy(dto)),
        Arc::new(MockFqdnCacheLookup::default()),
        Arc::new(|| Some("S-1-5-21-TEST".to_string())),
    );
    // Hostname absent from the (empty) FQDN cache → no permit compiles
    // while armed → the verdict slug rides along.
    let payload = serde_json::json!({ "input-sample": { "hostname": "search.example" } });
    let v = h.handle(&envelope(payload), &ctx()).expect("ok");
    assert_eq!(
        v["compact"]["enforcement"],
        "blocked-unknown-under-block-all"
    );

    // Same probe WITHOUT the deps → field absent (skip_serializing_if).
    let bare = ExplainGetHandler::new(facade());
    let payload = serde_json::json!({ "input-sample": { "hostname": "search.example" } });
    let v = bare.handle(&envelope(payload), &ctx()).expect("ok");
    assert!(v["compact"].get("enforcement").is_none());
}

// ── CacheEntriesList ──────────────────────────────────────────────────────

fn seeded_cache() -> Arc<Mutex<dyn CacheRepository + Send>> {
    use nrr_domain::decision_lookup::FreshnessThresholds;
    use nrr_storage::dto::ResolutionEntry;
    use nrr_storage::migration::SqliteMigrationRunner;
    use nrr_storage::repository::MigrationRunner;
    use nrr_storage::resolution_source::StorageResolutionSource;
    use nrr_storage::store::SqliteCacheStore;
    use std::net::Ipv4Addr;

    let conn = rusqlite::Connection::open_in_memory().expect("in-memory");
    let runner = SqliteMigrationRunner::for_cache_db(conn);
    runner.run_pending_migrations().expect("migrate");
    let store = SqliteCacheStore::new(
        runner.into_connection(),
        FreshnessThresholds::default_production(),
    );
    store
        .upsert_resolution(ResolutionEntry {
            canonical_hostname: "sub.example.com".into(),
            raw_hostname_sample: None,
            resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5))],
            ttl_seconds: Some(300),
            source: StorageResolutionSource::Dns,
            resolved_at: SystemTime::now(),
            active_revision_id: Some("rev-1".into()),
        })
        .expect("seed");
    store
        .upsert_resolution(ResolutionEntry {
            canonical_hostname: "api.other.example.net".into(),
            raw_hostname_sample: None,
            resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9))],
            ttl_seconds: Some(300),
            source: StorageResolutionSource::ObservedFromTraffic,
            resolved_at: SystemTime::now(),
            active_revision_id: Some("rev-1".into()),
        })
        .expect("seed");
    Arc::new(Mutex::new(store))
}

#[test]
fn cache_entries_local_viewer_shows_real_hostname_and_ip() {
    // The local cache viewer surfaces the real resolved hostnames
    // and IPs (so the user can inspect + search by IP) regardless of the
    // diagnostic-mode toggle. total_count reflects the real cache size.
    let h = CacheEntriesListHandler::new(seeded_cache());
    let v = h
        .handle(&envelope(serde_json::json!({})), &ctx())
        .expect("ok");
    assert_eq!(v["redacted"], false, "local viewer is not redacted");
    assert_eq!(v["page"]["total_count"], 2, "live cache total");
    let items = v["page"]["items"].as_array().expect("items array");
    assert_eq!(items.len(), 2);
    // Ordered by canonical_host: api.other.example.net before sub.example.com.
    assert_eq!(
        items[0]["hostname"], "api.other.example.net",
        "full hostname"
    );
    assert_eq!(items[0]["source"], "observed_from_traffic");
    assert_eq!(items[0]["ip"], "198.51.100.9", "real IP");
    assert_eq!(items[1]["hostname"], "sub.example.com", "full hostname");
    assert_eq!(items[1]["ip"], "203.0.113.5", "real IP");
    assert_eq!(items[1]["freshness"], "fresh");
}

#[test]
fn cache_entries_pagination_reports_next_cursor() {
    let h = CacheEntriesListHandler::new(seeded_cache());
    let payload = serde_json::json!({ "pagination": { "page_size": 1 } });
    let v = h.handle(&envelope(payload), &ctx()).expect("ok");
    let items = v["page"]["items"].as_array().expect("items");
    assert_eq!(items.len(), 1, "page_size clamps to one item");
    let cursor = v["page"]["next_cursor"]
        .as_str()
        .expect("next cursor present");
    // Second page via the returned cursor yields the remaining row and
    // no further cursor.
    let payload2 = serde_json::json!({ "pagination": { "page_size": 1, "cursor": cursor } });
    let v2 = h.handle(&envelope(payload2), &ctx()).expect("ok");
    assert_eq!(v2["page"]["items"].as_array().expect("items2").len(), 1);
    assert!(
        v2["page"]["next_cursor"].is_null(),
        "last page has no cursor"
    );
}

#[test]
fn cache_entries_carry_expected_route_when_expectation_wired() {
    // The cache viewer's "Route" column: secondary name-match
    // wins, primary name-match second, no match → empty.
    use crate::fqdn_cache_lookup::MockFqdnCacheLookup;
    use crate::per_sid_orchestrator::ActiveRulesSnapshot;
    use nrr_domain::canonical::{
        CanonicalAddressMatch, CanonicalRule, CanonicalRuleBook, CanonicalRuleSet,
    };
    use nrr_domain::RuleId;

    struct ScriptedRules;
    impl RulesProvider for ScriptedRules {
        fn active_rules(&self) -> Option<ActiveRulesSnapshot> {
            let rule = |id: &str, m: CanonicalAddressMatch| CanonicalRule {
                id: RuleId(id.into()),
                enabled: true,
                address_match: Some(m),
                app_match: None,
                comment: String::new(),
                action: nrr_domain::RuleAction::Route,
                origin: None,
            };
            Some(ActiveRulesSnapshot {
                rule_book: CanonicalRuleBook {
                    primary: CanonicalRuleSet::from_rules(vec![rule(
                        "p1",
                        CanonicalAddressMatch::SuffixDomain("other.example.net".into()),
                    )]),
                    secondary: CanonicalRuleSet::from_rules(vec![rule(
                        "s1",
                        CanonicalAddressMatch::SuffixDomain("example.com".into()),
                    )]),
                },
                behavior_mode: nrr_domain::RouteBehaviorMode::PreferPrimary,
            })
        }
    }

    let h = CacheEntriesListHandler::new(seeded_cache()).with_route_expectation(
        Arc::new(ScriptedRules),
        Arc::new(MockFqdnCacheLookup::new()),
        Arc::new(|| Some("S-1-5-21-T".to_string())),
    );
    let v = h
        .handle(&envelope(serde_json::json!({})), &ctx())
        .expect("ok");
    let items = v["page"]["items"].as_array().expect("items");
    assert_eq!(items[0]["hostname"], "api.other.example.net");
    assert_eq!(items[0]["expected_route"], "primary");
    assert_eq!(items[1]["hostname"], "sub.example.com");
    assert_eq!(items[1]["expected_route"], "secondary");
}

#[test]
fn cache_entries_expected_route_empty_without_expectation() {
    let h = CacheEntriesListHandler::new(seeded_cache());
    let v = h
        .handle(&envelope(serde_json::json!({})), &ctx())
        .expect("ok");
    let items = v["page"]["items"].as_array().expect("items");
    assert_eq!(items[0]["expected_route"], "");
    assert_eq!(items[1]["expected_route"], "");
}

#[test]
fn timestamp_filename_is_well_formed() {
    // Format-pattern assertion only — exact date arithmetic is
    // verified by round-tripping a few known epochs below.
    let s = format_timestamp_for_filename(1_778_502_645_000);
    assert_eq!(s.len(), 15, "format must be YYYYMMDD-HHMMSS, got {s}");
    assert_eq!(s.chars().filter(|c| *c == '-').count(), 1);
    let (date, time) = s.split_once('-').unwrap();
    assert_eq!(date.len(), 8, "date segment must be 8 chars");
    assert_eq!(time.len(), 6, "time segment must be 6 chars");
    assert!(date.chars().all(|c| c.is_ascii_digit()));
    assert!(time.chars().all(|c| c.is_ascii_digit()));
}

#[test]
fn timestamp_filename_unix_epoch_is_19700101() {
    // Epoch zero — sanity check that the civil-calendar conversion
    // anchors on 1970-01-01 (UTC).
    let s = format_timestamp_for_filename(0);
    assert_eq!(s, "19700101-000000");
}

#[test]
fn timestamp_filename_is_monotonic_within_a_year() {
    // Two timestamps a day apart should produce sortable filenames.
    let a = format_timestamp_for_filename(1_700_000_000_000);
    let b = format_timestamp_for_filename(1_700_086_400_000);
    assert!(
        a < b,
        "filenames must be lexicographically sortable: {a} < {b}"
    );
}

#[test]
fn archive_handler_builds_a_zip_and_returns_path() {
    let temp = tempfile::tempdir().unwrap();
    let alerts: Arc<dyn nrr_diagnostics::audit::alert::SecurityAlertsRepository> =
        Arc::new(InMemorySecurityAlertsRepository::new());
    let logs_dir = temp.path().join("logs");
    let audit_dir = temp.path().join("audit");
    let archives_dir = temp.path().join("archives");
    std::fs::create_dir_all(&logs_dir).unwrap();
    std::fs::create_dir_all(&audit_dir).unwrap();
    let facade: Arc<dyn DiagnosticsFacade> = Arc::new(
        crate::production_diagnostics::ProductionDiagnosticsFacade::new(
            logs_dir.clone(),
            audit_dir.clone(),
            None,
            alerts,
            None,
        ),
    );
    let handler = DiagnosticsExportArchiveHandler::new(
        facade,
        archives_dir.clone(),
        "test-1.0.0".into(),
        None,
        fake_adapters(),
        fake_route_policy(),
        Some(29),
        Arc::new(nrr_platform_api::file_handoff::NoopFileHandoff),
    );
    let env = IpcRequestEnvelope {
        protocol_version: 1,
        request_id: "req-arc".into(),
        correlation_id: None,
        operation: IpcOperationName::DiagnosticsExportArchive,
        operation_class: IpcOperationClass::ReadSnapshot,
        confirmation_token: None,
        payload: serde_json::json!({}),
    };
    let v = handler.handle(&env, &ctx()).expect("archive build");
    let path_str = v["archive-path"].as_str().expect("archive-path string");
    assert!(path_str.contains("nrr-diagnostics-"));
    assert!(path_str.ends_with(".zip"));
    let size = v["size-bytes"].as_u64().expect("size-bytes");
    assert!(size > 0, "archive must have non-zero size");
    // File actually exists on disk.
    assert!(std::path::Path::new(path_str).exists());
    // Generated_at_ms is a real timestamp (within last 10s).
    let ts = v["generated-at-ms"].as_i64().expect("generated-at-ms");
    let now = millis_since_epoch();
    assert!(
        (now - ts).abs() < 10_000,
        "generated-at-ms must be near now"
    );
}

/// The archive is written into the service's own tree, which ordinary
/// accounts cannot read — so the export is only finished when the file has
/// been handed to the caller. Without this the GUI reports a path its user
/// cannot open, and the failure is silent on both sides.
#[test]
fn a_finished_archive_is_handed_to_the_caller_that_asked_for_it() {
    let temp = tempfile::tempdir().unwrap();
    let alerts: Arc<dyn nrr_diagnostics::audit::alert::SecurityAlertsRepository> =
        Arc::new(InMemorySecurityAlertsRepository::new());
    let logs_dir = temp.path().join("logs");
    let audit_dir = temp.path().join("audit");
    let archives_dir = temp.path().join("archives");
    std::fs::create_dir_all(&logs_dir).unwrap();
    std::fs::create_dir_all(&audit_dir).unwrap();
    let facade: Arc<dyn DiagnosticsFacade> = Arc::new(
        crate::production_diagnostics::ProductionDiagnosticsFacade::new(
            logs_dir.clone(),
            audit_dir.clone(),
            None,
            alerts,
            None,
        ),
    );
    let handoff = Arc::new(nrr_platform_api::file_handoff::MockFileHandoff::default());
    let handler = DiagnosticsExportArchiveHandler::new(
        facade,
        archives_dir.clone(),
        "test-1.0.0".into(),
        None,
        fake_adapters(),
        fake_route_policy(),
        None,
        Arc::clone(&handoff) as Arc<dyn nrr_platform_api::file_handoff::FileHandoffPort>,
    );
    let env = IpcRequestEnvelope {
        protocol_version: 1,
        request_id: "req-handoff".into(),
        correlation_id: None,
        operation: IpcOperationName::DiagnosticsExportArchive,
        operation_class: IpcOperationClass::DiagnosticAction,
        confirmation_token: None,
        payload: serde_json::json!({}),
    };
    let v = handler.handle(&env, &ctx()).expect("archive build");
    let path = v["archive-path"]
        .as_str()
        .expect("archive-path")
        .to_string();

    let grants = handoff.grants.lock().expect("grants");
    assert_eq!(grants.len(), 1, "exactly one file is handed over");
    assert_eq!(grants[0].0, std::path::PathBuf::from(&path));
    assert_eq!(
        grants[0].1, "S-1-5-21-test",
        "the grant names the caller, not the service"
    );
}

#[test]
fn archive_handler_with_no_logs_flag_still_succeeds() {
    let temp = tempfile::tempdir().unwrap();
    let alerts: Arc<dyn nrr_diagnostics::audit::alert::SecurityAlertsRepository> =
        Arc::new(InMemorySecurityAlertsRepository::new());
    let archives_dir = temp.path().join("archives");
    let facade: Arc<dyn DiagnosticsFacade> = Arc::new(
        crate::production_diagnostics::ProductionDiagnosticsFacade::new(
            temp.path().to_path_buf(),
            temp.path().to_path_buf(),
            None,
            alerts,
            None,
        ),
    );
    let handler = DiagnosticsExportArchiveHandler::new(
        facade,
        archives_dir.clone(),
        "t".into(),
        None,
        fake_adapters(),
        fake_route_policy(),
        None,
        Arc::new(nrr_platform_api::file_handoff::NoopFileHandoff),
    );
    let env = IpcRequestEnvelope {
        protocol_version: 1,
        request_id: "req-arc-2".into(),
        correlation_id: None,
        operation: IpcOperationName::DiagnosticsExportArchive,
        operation_class: IpcOperationClass::ReadSnapshot,
        confirmation_token: None,
        payload: serde_json::json!({
            "include-logs": false,
            "include-audit-summary": false,
            "include-troubleshooting-playbooks": false,
        }),
    };
    let v = handler.handle(&env, &ctx()).expect("archive build");
    assert!(v["archive-path"].as_str().is_some());
}

#[test]
fn diagnostics_redaction_level_ships_the_extra_sections() {
    // With `redaction-level: "diagnostics"` the archive gains
    // cache_health.json / storage_health.json / explain_samples.json;
    // "standard" (and absent) stays at the lean default set.
    use std::io::Read;
    let temp = tempfile::tempdir().unwrap();
    let alerts: Arc<dyn nrr_diagnostics::audit::alert::SecurityAlertsRepository> =
        Arc::new(InMemorySecurityAlertsRepository::new());
    let archives_dir = temp.path().join("archives");
    let facade: Arc<dyn DiagnosticsFacade> = Arc::new(
        crate::production_diagnostics::ProductionDiagnosticsFacade::new(
            temp.path().to_path_buf(),
            temp.path().to_path_buf(),
            None,
            alerts,
            None,
        ),
    );
    let handler = DiagnosticsExportArchiveHandler::new(
        facade,
        archives_dir,
        "t".into(),
        None,
        fake_adapters(),
        fake_route_policy(),
        Some(29),
        Arc::new(nrr_platform_api::file_handoff::NoopFileHandoff),
    );
    let names_for = |level: serde_json::Value| -> Vec<String> {
        let env = IpcRequestEnvelope {
            protocol_version: 1,
            request_id: "req-arc-lvl".into(),
            correlation_id: None,
            operation: IpcOperationName::DiagnosticsExportArchive,
            operation_class: IpcOperationClass::ReadSnapshot,
            confirmation_token: None,
            payload: level,
        };
        let v = handler.handle(&env, &ctx()).expect("archive build");
        let path = v["archive-path"].as_str().expect("path").to_string();
        let file = std::fs::File::open(&path).expect("open zip");
        let mut zip = zip::ZipArchive::new(file).expect("zip");
        let mut names = Vec::new();
        for i in 0..zip.len() {
            let mut e = zip.by_index(i).expect("entry");
            let n = e.name().to_string();
            if n == "manifest.json" {
                // Provenance is embedded — non-empty profile at minimum.
                let mut body = String::new();
                e.read_to_string(&mut body).expect("read manifest");
                let mv: serde_json::Value = serde_json::from_str(&body).expect("json");
                assert!(
                    !mv["build-profile"].as_str().unwrap_or("").is_empty()
                        || !mv["build_profile"].as_str().unwrap_or("").is_empty(),
                    "manifest carries build provenance"
                );
            }
            names.push(n);
        }
        names
    };

    let standard = names_for(serde_json::json!({ "redaction-level": "standard" }));
    assert!(!standard.contains(&"cache_health.json".to_string()));
    assert!(!standard.contains(&"explain_samples.json".to_string()));

    let diagnostics = names_for(serde_json::json!({ "redaction-level": "diagnostics" }));
    assert!(diagnostics.contains(&"cache_health.json".to_string()));
    assert!(diagnostics.contains(&"storage_health.json".to_string()));
    // `explain_samples.json` belongs to this tier's section set, but this
    // service has no decisions to explain, and a section with nothing in it
    // is now absent rather than shipped as an empty `[]` — what is missing
    // is stated in the redaction report instead.
    assert!(!diagnostics.contains(&"explain_samples.json".to_string()));
}

#[test]
fn health_json_carries_enrichment_from_providers() {
    // Behavior mode, state
    // schema version, and the adapters snapshot must reach `health.json`
    // via the real `RoutePolicyProvider` / `AdaptersSnapshotProvider`
    // deps, keyed by the caller's SID from `IpcRequestContext`.
    use nrr_shared::ipc_payloads::{
        AdapterEntry, BehaviorModeDto, BindingSourceDto, RoutePolicyDto,
    };
    use std::io::Read;

    let temp = tempfile::tempdir().unwrap();
    let alerts: Arc<dyn nrr_diagnostics::audit::alert::SecurityAlertsRepository> =
        Arc::new(InMemorySecurityAlertsRepository::new());
    let archives_dir = temp.path().join("archives");
    let facade: Arc<dyn DiagnosticsFacade> = Arc::new(
        crate::production_diagnostics::ProductionDiagnosticsFacade::new(
            temp.path().to_path_buf(),
            temp.path().to_path_buf(),
            None,
            alerts,
            None,
        ),
    );

    let adapters: Arc<dyn AdaptersSnapshotProvider> =
        Arc::new(FakeAdapters::with_one(AdapterEntry {
            persistent_id: "adp-1".into(),
            adapter_name: "eth0".into(),
            ipv6_if_index: 1,
            physical_address: None,
            name: "Ethernet".into(),
            interface_description: "Test NIC".into(),
            interface_type: "ethernet".into(),
            oper_status: "up".into(),
        }));
    let route_policy = Arc::new(FakeRoutePolicy::default());
    *route_policy.stored.lock().unwrap() = Some(RoutePolicyDto {
        primary: None,
        secondary: None,
        mode: BehaviorModeDto::PreferSecondaryWhenAvailable,
        block_secondary_when_unavailable: false,
        kill_switch_fail_closed: true,
        kill_switch_protocols: 127,
        kill_switch_block_all: false,
        kill_switch_enabled: false,
        allow_dns_over_primary: false,
        include_subdomains: false,
        shared_ip_policy: "majority-of-ip".into(),
        mode_a_coverage_strategy: "fail-closed-unknown".into(),
        resolve_hosts_bypass: true,
        secondary_link_provider_apps: Vec::new(),
        doh_lockdown_enabled: false,
        doh_lockdown_scope: "leak-protection-only".into(),
        browser_history_auto_seed: false,
        kill_switch_strict_shared_ips: false,
        auto_rules_mode: "suggest".to_string(),
        auto_rules_eager_delivery_names: false,
        primary_probe_auto: false,
        primary_probe_timeout_ms: 1500,
        primary_probe_max_targets: 8,
        primary_probe_repeat_secs: 300,
        local_networks_auto_accept: false,
        zone_priority_over_ip: false,
        short_name_completion: false,
        short_name_suffix: String::new(),
        binding_source: BindingSourceDto::UserAssigned,
    });

    let handler = DiagnosticsExportArchiveHandler::new(
        facade,
        archives_dir,
        "t".into(),
        None,
        adapters,
        route_policy as Arc<dyn RoutePolicyProvider>,
        Some(29),
        Arc::new(nrr_platform_api::file_handoff::NoopFileHandoff),
    );
    let env = IpcRequestEnvelope {
        protocol_version: 1,
        request_id: "req-arc-health".into(),
        correlation_id: None,
        operation: IpcOperationName::DiagnosticsExportArchive,
        operation_class: IpcOperationClass::ReadSnapshot,
        confirmation_token: None,
        payload: serde_json::json!({}),
    };
    let v = handler.handle(&env, &ctx()).expect("archive build");
    let path = v["archive-path"].as_str().expect("path").to_string();
    let file = std::fs::File::open(&path).expect("open zip");
    let mut zip = zip::ZipArchive::new(file).expect("zip");
    let mut body = String::new();
    zip.by_name("health.json")
        .expect("health.json present")
        .read_to_string(&mut body)
        .expect("read");
    let health: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(health["behavior_mode"], "prefer-secondary-when-available");
    assert_eq!(health["state_schema_version"], 29);
    assert_eq!(
        health["adapters_snapshot"]["adapters"][0]["adapter-name"],
        "eth0"
    );
}

#[test]
fn explain_samples_are_wired_from_recent_decision_ids_not_hardcoded_empty() {
    // A log entry carrying a `decision:<id>` correlation token must
    // produce a REAL `get_explain(HistoricalDecision)` call, not an
    // empty vec. The production facade currently answers
    // `DecisionNotFound` for every historical id (no snapshot-replay
    // store yet); the assertion here is on the WIRING: the sample is
    // present and reflects that real facade response.
    use std::io::Read;

    let temp = tempfile::tempdir().unwrap();
    let logs_dir = temp.path().join("logs");
    let audit_dir = temp.path().join("audit");
    let archives_dir = temp.path().join("archives");
    std::fs::create_dir_all(&logs_dir).unwrap();
    std::fs::create_dir_all(&audit_dir).unwrap();

    // Write one operational log line carrying a decision correlation —
    // the mechanism `recent_decision_ids` mines.
    {
        let date = nrr_diagnostics::audit::writer::local_date_string(std::time::SystemTime::now());
        let path = logs_dir.join(format!("nrr_service_{date}-1.ndjson"));
        let event = nrr_diagnostics::event::LogEvent::new(
            "evt-decision-001",
            1_745_000_000_000,
            nrr_diagnostics::taxonomy::EventLevel::Info,
            nrr_diagnostics::reason::service::STARTED,
        )
        .with_correlation(
            nrr_diagnostics::taxonomy::EventCorrelation::default().with_decision("d-sample-1"),
        );
        std::fs::write(
            &path,
            format!("{}\n", event.to_ndjson().expect("serialize")),
        )
        .unwrap();
    }

    let alerts: Arc<dyn nrr_diagnostics::audit::alert::SecurityAlertsRepository> =
        Arc::new(InMemorySecurityAlertsRepository::new());
    let facade: Arc<dyn DiagnosticsFacade> = Arc::new(
        crate::production_diagnostics::ProductionDiagnosticsFacade::new(
            logs_dir, audit_dir, None, alerts, None,
        ),
    );
    let handler = DiagnosticsExportArchiveHandler::new(
        facade,
        archives_dir,
        "t".into(),
        None,
        fake_adapters(),
        fake_route_policy(),
        None,
        Arc::new(nrr_platform_api::file_handoff::NoopFileHandoff),
    );
    let env = IpcRequestEnvelope {
        protocol_version: 1,
        request_id: "req-arc-explain".into(),
        correlation_id: None,
        operation: IpcOperationName::DiagnosticsExportArchive,
        operation_class: IpcOperationClass::ReadSnapshot,
        confirmation_token: None,
        payload: serde_json::json!({ "redaction-level": "diagnostics" }),
    };
    let v = handler.handle(&env, &ctx()).expect("archive build");
    let path = v["archive-path"].as_str().expect("path").to_string();
    let file = std::fs::File::open(&path).expect("open zip");
    let mut zip = zip::ZipArchive::new(file).expect("zip");
    let mut body = String::new();
    zip.by_name("explain_samples.json")
        .expect("explain_samples.json present")
        .read_to_string(&mut body)
        .expect("read");
    let samples: serde_json::Value = serde_json::from_str(&body).expect("json");
    let samples = samples.as_array().expect("array");
    assert_eq!(samples.len(), 1, "the one decision id must be sampled");
    assert_eq!(samples[0]["query_kind"], "historical");
}

// ── Audience scoping and the outage list ─────────────────────────

fn ctx_for(
    principal: Option<nrr_domain::user_principal::UserPrincipal>,
    elevated: bool,
) -> IpcRequestContext {
    IpcRequestContext {
        client_profile: IpcClientProfile::GuiInteractive,
        caller_is_elevated: elevated,
        caller_principal: principal,
        caller_pid: None,
    }
}

fn call_as<H: IpcHandler>(
    handler: &H,
    operation: IpcOperationName,
    ctx: &IpcRequestContext,
) -> serde_json::Value {
    let env = IpcRequestEnvelope {
        protocol_version: crate::ipc::IPC_PROTOCOL_VERSION,
        request_id: "r".into(),
        correlation_id: None,
        operation,
        operation_class: crate::ipc::IpcOperationClass::DiagnosticQuery,
        confirmation_token: None,
        payload: serde_json::Value::Null,
    };
    handler.handle(&env, ctx).expect("handler answers")
}

/// Another user's rows name their programs and destinations; an ordinary
/// caller gets their own plus the machine's (no owner, or the service's own
/// relay connections), an elevated one everything.
#[test]
fn conn_trace_shows_an_ordinary_caller_only_their_own_and_the_machines_rows() {
    use nrr_domain::user_principal::UserPrincipal;
    let me = UserPrincipal::from_linux_uid(1000);
    let other = UserPrincipal::from_linux_uid(1001);
    let service = nrr_shared::product_identity::BinaryRole::Service.windows_file_name();
    let ring = Arc::new(crate::conn_observation_consumer::ConnectionTraceRing::new(
        16,
    ));
    let row = |owner: Option<&str>, process: String| {
        let mut r = trace_row();
        r.user_sid = owner.map(str::to_string);
        r.process_path = Some(process);
        r
    };
    ring.push(row(Some(me.as_stored()), r"\device\hd\mine.exe".into()));
    ring.push(row(
        Some(other.as_stored()),
        r"\device\hd\theirs.exe".into(),
    ));
    ring.push(row(None, r"\device\hd\nobody.exe".into()));
    ring.push(row(Some("S-1-5-18"), format!(r"\device\hd\{service}")));
    let handler = ConnTraceEntriesListHandler::new(Arc::clone(&ring));
    let processes = |ctx: IpcRequestContext| -> Vec<String> {
        let resp: ConnTraceEntriesListResponse = serde_json::from_value(call_as(
            &handler,
            IpcOperationName::ConnTraceEntriesList,
            &ctx,
        ))
        .expect("decode ConnTraceEntriesListResponse");
        resp.page.items.into_iter().map(|i| i.process).collect()
    };

    assert_eq!(
        processes(ctx_for(Some(me.clone()), false)),
        vec![service, "nobody.exe", "mine.exe"]
    );
    assert_eq!(
        processes(ctx_for(Some(me), true)),
        vec![service, "nobody.exe", "theirs.exe", "mine.exe"],
        "positive control: an elevated caller sees the machine"
    );
    assert_eq!(
        processes(ctx_for(None, false)),
        vec![service, "nobody.exe"],
        "an unattributed caller owns nothing"
    );
}

fn outage_list(
    handler: &ConnTraceOutageBlocksListHandler,
    ctx: &IpcRequestContext,
) -> nrr_shared::ipc_payloads::ConnTraceOutageBlocksResponse {
    serde_json::from_value(call_as(
        handler,
        IpcOperationName::ConnTraceOutageBlocksList,
        ctx,
    ))
    .expect("decode ConnTraceOutageBlocksResponse")
}

fn note_outage_drop(
    ring: &crate::conn_observation_consumer::ConnectionTraceRing,
    sid: &str,
    app: &str,
    remote: &str,
    at_ms: u64,
) {
    let path = format!(r"\device\hd\{app}");
    ring.outage_blocks()
        .record(crate::outage_blocks::OutageDrop {
            sid,
            app,
            process_path: Some(&path),
            remote: remote.parse().expect("remote"),
            host: Some("site.example"),
            at_ms,
        });
}

/// The request names nobody, so the answer is always the caller's own — also
/// for an elevated caller, whose list is the counterpart of their own notice.
#[test]
fn the_outage_list_is_only_ever_the_callers_own() {
    use nrr_domain::user_principal::UserPrincipal;
    use nrr_shared::ipc_payloads::OutageEpisodeDto;
    let me = UserPrincipal::from_linux_uid(1000);
    let other = UserPrincipal::from_linux_uid(1001);
    let ring = Arc::new(crate::conn_observation_consumer::ConnectionTraceRing::new(
        4,
    ));
    ring.mark_observer_active();
    ring.outage_blocks().mark_fed();
    ring.outage_blocks().outage_began(me.as_stored(), 1_000);
    note_outage_drop(&ring, me.as_stored(), "mine.exe", "198.51.100.1:443", 2_000);
    note_outage_drop(
        &ring,
        other.as_stored(),
        "theirs.exe",
        "198.51.100.2:443",
        2_500,
    );
    ring.outage_blocks().outage_ended(me.as_stored(), 3_000);
    let handler = ConnTraceOutageBlocksListHandler::new(Arc::clone(&ring));

    let mine = outage_list(&handler, &ctx_for(Some(me.clone()), false));
    assert_eq!(
        mine.episode,
        Some(OutageEpisodeDto {
            since_unix_ms: 1_000,
            until_unix_ms: Some(3_000),
        })
    );
    assert_eq!(mine.entries.len(), 1);
    let entry = &mine.entries[0];
    assert_eq!(entry.process, "mine.exe");
    assert_eq!(entry.remote_ip, "198.51.100.1");
    assert_eq!(entry.remote_port, 443);
    assert_eq!(entry.host, "site.example");
    assert_eq!((entry.first_seen_ms, entry.last_seen_ms), (2_000, 2_000));
    assert_eq!(entry.attempts, 1);
    assert_eq!(mine.omitted, 0);
    assert!(mine.observer_active && mine.gui_stream_enabled);

    let elevated = outage_list(&handler, &ctx_for(Some(me), true));
    assert_eq!(
        elevated.entries, mine.entries,
        "elevation widens nothing here"
    );

    let theirs = outage_list(&handler, &ctx_for(Some(other), false));
    assert_eq!(theirs.entries.len(), 1);
    assert_eq!(theirs.entries[0].process, "theirs.exe");
    assert_eq!(
        theirs.episode.map(|e| (e.since_unix_ms, e.until_unix_ms)),
        Some((2_500, None)),
        "the drop itself opened their outage"
    );

    let anonymous = outage_list(&handler, &ctx_for(None, true));
    assert!(anonymous.entries.is_empty());
    assert_eq!(anonymous.episode, None);
}

/// The trace switch silences this view too, and a store nothing attributes
/// drops into reads as "not watching", never as "nothing was blocked".
#[test]
fn the_outage_list_follows_the_trace_switch_and_says_when_nothing_watches() {
    use nrr_domain::user_principal::UserPrincipal;
    let me = UserPrincipal::from_linux_uid(1000);
    let ring = Arc::new(crate::conn_observation_consumer::ConnectionTraceRing::new(
        4,
    ));
    ring.mark_observer_active();
    note_outage_drop(&ring, me.as_stored(), "mine.exe", "198.51.100.1:443", 2_000);

    let unfed = ConnTraceOutageBlocksListHandler::new(Arc::clone(&ring));
    assert!(
        !outage_list(&unfed, &ctx_for(Some(me.clone()), false)).observer_active,
        "a ring fed without drop attribution cannot see an outage"
    );

    ring.outage_blocks().mark_fed();
    let hidden = ConnTraceOutageBlocksListHandler::new(Arc::clone(&ring)).with_gui_stream_gate(
        crate::ipc_handlers::test_fakes::FakeConnTraceGui::showing(false),
    );
    let resp = outage_list(&hidden, &ctx_for(Some(me.clone()), false));
    assert!(resp.entries.is_empty() && resp.episode.is_none());
    assert!(!resp.gui_stream_enabled);
    assert!(resp.observer_active);

    let shown = ConnTraceOutageBlocksListHandler::new(Arc::clone(&ring)).with_gui_stream_gate(
        crate::ipc_handlers::test_fakes::FakeConnTraceGui::showing(true),
    );
    assert_eq!(
        outage_list(&shown, &ctx_for(Some(me), false)).entries.len(),
        1,
        "positive control: switched on, the same entry is served"
    );
}
