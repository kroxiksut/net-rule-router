//! Source-reconstructed release payloads; see fixtures/released_ipc/README.md.
//! Expectations are user meanings, not a round trip through today's serializer.

use nrr_shared::ipc_payloads::*;
use serde_json::{json, Value};

const POLICY: &str = include_str!("fixtures/released_ipc/v0.1.0-alpha.1/route-policy.json");
const HEALTH: &str = include_str!("fixtures/released_ipc/v0.1.0-alpha.1/health.json");
const SITE: &str = include_str!("fixtures/released_ipc/v0.1.0-alpha.1/site-check.json");

#[test]
fn release_policy_keeps_explicit_opt_outs_instead_of_enabling_defaults() {
    let p: RoutePolicyDto = serde_json::from_str(POLICY).expect("release policy");
    assert_eq!(p.mode, BehaviorModeDto::PreferPrimary);
    assert_eq!(p.leak_protection, LeakProtectionDto::Everything);
    assert_eq!(p.kill_switch_protocols, 127);
    assert!(!p.allow_dns_over_primary);
    assert!(!p.include_subdomains);
    assert!(!p.resolve_hosts_bypass);
    assert!(!p.doh_lockdown_auto);
    assert!(!p.kill_switch_strict_shared_ips);
    assert!(!p.external_address_auto_check);
    assert!(!p.auto_rules_eager_delivery_names);
    assert!(!p.primary_probe_auto);
    assert!(!p.local_networks_auto_accept);
    assert!(!p.app_rules_take_all_addresses);
    assert_eq!(p.auto_rules_mode, "suggest");
    assert!(p.secondary_link_provider_apps.is_empty());
    assert!(p.secondary.is_none());
    assert!(p.short_name_suffix.is_empty());
    assert!(p.forwarded_outage.is_empty());
    assert!(!p.primary.expect("bound primary").user_confirmed);
}

#[test]
fn release_datapath_outage_is_not_running_or_a_known_failure_reason() {
    let h: ServiceHealthResponse = serde_json::from_str(HEALTH).expect("release health");
    assert_eq!(h.service_state, "running");
    let stack = h.fake_ip_datapath.expect("datapath reported");
    assert!(stack.desired);
    assert!(
        !stack.running,
        "running service does not imply running datapath"
    );
    assert_eq!(stack.zombies, 0);
    assert!(
        stack.last_failure.is_none(),
        "old sender did not report a cause"
    );
}

#[test]
fn release_finished_site_check_does_not_claim_https_success_or_fresh_dns() {
    let status: SiteCheckStatus = serde_json::from_str(SITE).expect("release check");
    assert_eq!(status.state, "done");
    let report = status.report.expect("finished report");
    assert_eq!(report.verdict, "unclear");
    assert!(!report.reads_answer);
    assert!(report.move_names.is_empty());
    let name = &report.names[0];
    assert_eq!(name.answer, "silent");
    assert_eq!(name.route, "primary");
    assert_eq!(name.address, "192.0.2.10");
    assert!(name.status.is_none());
    assert!(name.not_run_reason.is_none());
    assert!(name.rule_id.is_none());
    assert!(name.revision.is_none());
    assert!(name.real_addresses.is_empty());
    assert!(name.fake_address.is_none());
    assert!(
        name.dns.is_empty(),
        "absence is not a fresh DNS observation"
    );
}

#[test]
fn synthetic_incompatible_policy_is_rejected_instead_of_showing_protection_off() {
    // These mutations are negative cases, NOT historical messages.
    for replacement in [None, Some(Value::Null), Some(json!("future-protection"))] {
        let mut policy: Value = serde_json::from_str(POLICY).expect("fixture JSON");
        match replacement {
            None => {
                policy
                    .as_object_mut()
                    .expect("object")
                    .remove("leak-protection");
            }
            Some(value) => policy["leak-protection"] = value,
        }
        assert!(serde_json::from_value::<RoutePolicyDto>(policy).is_err());
    }
    let mut policy: Value = serde_json::from_str(POLICY).expect("fixture JSON");
    policy["allow-dns-over-primary"] = Value::Null;
    assert!(serde_json::from_value::<RoutePolicyDto>(policy).is_err());
}

#[test]
fn synthetic_additive_metadata_and_null_optional_cause_do_not_invent_state() {
    let mut health: Value = serde_json::from_str(HEALTH).expect("fixture JSON");
    health["future-display-metadata"] = json!({"label": "unused"});
    health["fake-ip-datapath"]["last-failure"] = Value::Null;
    let h: ServiceHealthResponse = serde_json::from_value(health).expect("additive read");
    let stack = h.fake_ip_datapath.expect("datapath");
    assert!(!stack.running);
    assert_eq!(stack.zombies, 0);
    assert!(stack.last_failure.is_none());
}
