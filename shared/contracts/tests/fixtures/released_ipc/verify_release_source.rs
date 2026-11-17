//! Copy into the release checkout's tests directory, with the fixture folder.
//! This verifies reconstruction against release types, not the current schema.

use nrr_shared::ipc_payloads::*;
use serde::Serialize;

fn matches_release(name: &str, value: impl Serialize) {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/released_ipc/v0.1.0-alpha.1")
        .join(name);
    let expected: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path).expect("frozen fixture")).expect("JSON");
    assert_eq!(serde_json::to_value(value).expect("release serializer"), expected);
}

#[test]
fn reconstructed_examples_are_emitted_by_the_release_types() {
    matches_release("negotiate.json", ContractNegotiateResponse {
        server_version: 1,
        negotiated_protocol: 1,
        session_id: "fixture-session".into(),
        contract_revision: 3,
        service_version: "0.1.0-alpha.1".into(),
    });
    matches_release("health.json", ServiceHealthResponse {
        service_state: "running".into(),
        worst_severity: "degraded".into(),
        active_revision_id: None,
        components: vec![],
        fake_ip_datapath: Some(FakeIpDatapathDto { desired: true, running: false, zombies: 0 }),
    });
    matches_release("site-check.json", SiteCheckStatus {
        state: "done".into(),
        host: "fixture.example".into(),
        report: Some(SiteCheckReport {
            site: "fixture.example".into(),
            verdict: "unclear".into(),
            site_route: "primary".into(),
            names: vec![SiteCheckNameDto {
                name: "fixture.example".into(),
                role: "site".into(),
                address: "192.0.2.10".into(),
                route: "primary".into(),
                answer: "silent".into(),
                status: None,
                redirects: vec![],
            }],
            move_names: vec![],
            reads_answer: false,
        }),
    });
    matches_release("route-policy.json", RoutePolicyDto {
        primary: Some(RouteBindingDto {
            stable_id: "fixture-primary".into(),
            display_name: "Main".into(),
            user_confirmed: false,
            known_stable_ids: vec![],
        }),
        secondary: None,
        mode: BehaviorModeDto::PreferPrimary,
        leak_protection: LeakProtectionDto::Everything,
        kill_switch_protocols: 127,
        allow_dns_over_primary: false,
        include_subdomains: false,
        shared_ip_policy: "majority-of-ip".into(),
        resolve_hosts_bypass: false,
        secondary_link_provider_apps: vec![],
        doh_lockdown_enabled: false,
        doh_lockdown_scope: "leak-protection-only".into(),
        doh_lockdown_auto: false,
        doh_lockdown_effective: false,
        browser_history_auto_seed: false,
        kill_switch_strict_shared_ips: false,
        auto_rules_mode: "suggest".into(),
        auto_rules_eager_delivery_names: false,
        binding_source: BindingSourceDto::UserAssigned,
        primary_probe_auto: false,
        primary_probe_timeout_ms: 1000,
        primary_probe_max_targets: 8,
        primary_probe_repeat_secs: 60,
        local_networks_auto_accept: false,
        zone_priority_over_ip: false,
        short_name_completion: false,
        short_name_suffix: String::new(),
        app_rules_take_all_addresses: false,
        forwarded_outage: String::new(),
        external_address_auto_check: false,
    });
}
