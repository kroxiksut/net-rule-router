use super::*;
use crate::ipc_handlers::payloads::AdapterEntry;
use crate::ipc_handlers::providers::FailClosedStateProbe;
use nrr_storage::migration::{open_connection, SqliteMigrationRunner};
use nrr_storage::repository::MigrationRunner;
use nrr_storage::route_bindings::{
    BehaviorMode, BindingSource, RouteBindingRecord, RoutePolicyRecord,
};

const TEST_SID: &str = "S-1-5-21-test";
const SECONDARY_ID: &str = "vpn-adapter-stable-id";

fn open_state_db() -> (tempfile::TempDir, Arc<Mutex<Connection>>) {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("state.db");
    let conn = open_connection(&path).expect("open");
    let runner = SqliteMigrationRunner::for_state_db(conn);
    runner.run_pending_migrations().expect("migrate");
    let conn = runner.into_connection();
    (dir, Arc::new(Mutex::new(conn)))
}

fn seed_policy(conn: &Arc<Mutex<Connection>>, mode: BehaviorMode, block_when_unavailable: bool) {
    // Default posture is fail-closed (block) — the common case.
    seed_policy_posture(conn, mode, block_when_unavailable, true);
}

fn seed_policy_posture(
    conn: &Arc<Mutex<Connection>>,
    mode: BehaviorMode,
    block_when_unavailable: bool,
    kill_switch_fail_closed: bool,
) {
    let guard = conn.lock().unwrap();
    let repo = RouteBindingsRepository::new(&guard);
    repo.update_for_sid(
        TEST_SID,
        &RoutePolicyRecord {
            primary: Some(RouteBindingRecord {
                stable_id: "primary-id".into(),
                display_name: "Primary".into(),
                user_confirmed: true,
                known_stable_ids: vec![],
            }),
            secondary: Some(RouteBindingRecord {
                stable_id: SECONDARY_ID.into(),
                display_name: "Secondary VPN".into(),
                user_confirmed: true,
                known_stable_ids: vec![],
            }),
            mode,
            block_secondary_when_unavailable: block_when_unavailable,
            kill_switch_fail_closed,
            kill_switch_protocols: 0x7F,
            kill_switch_block_all: false,
            // This fixture drives fail-closed behaviour tests; keep
            // the master toggle ON so the armed path is exercised.
            kill_switch_enabled: true,
            allow_dns_over_primary: false,
            include_subdomains: false,
            shared_ip_policy: nrr_domain::shared_ip::SharedIpPolicy::default(),
            mode_a_coverage_strategy: nrr_domain::mode_a_coverage::ModeACoverageStrategy::default(),
            resolve_hosts_bypass: true,
            doh_lockdown_enabled: false,
            doh_lockdown_scope: nrr_storage::doh_lockdown::DohLockdownScope::default(),
            browser_history_auto_seed: false,
            kill_switch_strict_shared_ips: false,
            auto_rules_mode: nrr_storage::auto_rules::AutoRulesMode::default(),
            auto_rules_eager_delivery_names: false,
            primary_probe_auto: false,
            primary_probe_timeout_ms: 1500,
            primary_probe_max_targets: 8,
            primary_probe_repeat_secs: 300,
            local_networks_auto_accept: false,
            zone_priority_over_ip: false,
            binding_source: BindingSource::UserAssigned,
        },
        100,
    )
    .expect("update_for_sid");
}

fn adapter(id: &str, oper_status: &str) -> AdapterEntry {
    AdapterEntry {
        persistent_id: id.into(),
        adapter_name: id.into(),
        ipv6_if_index: 0,
        physical_address: None,
        windows_name: id.into(),
        interface_description: String::new(),
        interface_type: "Ethernet".into(),
        oper_status: oper_status.into(),
    }
}

#[test]
fn empty_sid_returns_none() {
    let (_d, conn) = open_state_db();
    let probe = ProductionFailClosedProbe::new(conn);
    assert!(probe.probe("", &[]).is_none());
}

#[test]
fn no_secondary_bound_returns_inactive_state() {
    let (_d, conn) = open_state_db();
    // Caller has never sent a RoutePolicyUpdate — load_for_sid
    // returns the empty record (no secondary, PreferPrimary mode).
    let probe = ProductionFailClosedProbe::new(conn);
    let state = probe.probe(TEST_SID, &[]).expect("Some");
    assert!(!state.fail_closed_active);
}

#[test]
fn secondary_offline_with_block_policy_on_yields_active() {
    let (_d, conn) = open_state_db();
    seed_policy(&conn, BehaviorMode::PreferPrimary, true);
    let probe = ProductionFailClosedProbe::new(conn);
    // Secondary adapter listed as Down → offline + block ON.
    let adapters = vec![adapter("primary-id", "Up"), adapter(SECONDARY_ID, "Down")];
    let state = probe.probe(TEST_SID, &adapters).expect("Some");
    assert!(state.fail_closed_active);
}

#[test]
fn secondary_up_with_block_policy_on_yields_inactive() {
    let (_d, conn) = open_state_db();
    seed_policy(&conn, BehaviorMode::PreferPrimary, true);
    let probe = ProductionFailClosedProbe::new(conn);
    let adapters = vec![adapter(SECONDARY_ID, "Up")];
    let state = probe.probe(TEST_SID, &adapters).expect("Some");
    assert!(!state.fail_closed_active);
}

#[test]
fn secondary_offline_with_block_toggle_off_still_yields_active() {
    // A bound secondary arms the leak-guard on
    // its own, so the opt-in `block_secondary_when_unavailable` toggle no
    // longer disables protection. An offline secondary with the default
    // fail-closed posture is therefore ACTIVE even with the toggle off.
    // The user's opt-out is the fail-OPEN posture, below.
    let (_d, conn) = open_state_db();
    seed_policy(&conn, BehaviorMode::PreferPrimary, false);
    let probe = ProductionFailClosedProbe::new(conn);
    let adapters = vec![adapter(SECONDARY_ID, "Down")];
    let state = probe.probe(TEST_SID, &adapters).expect("Some");
    assert!(state.fail_closed_active);
}

#[test]
fn secondary_offline_with_fail_open_posture_yields_inactive() {
    // The way to let traffic ride the primary
    // when the secondary drops is the fail-OPEN posture
    // (kill_switch_fail_closed = false), NOT unticking the block toggle.
    let (_d, conn) = open_state_db();
    seed_policy_posture(&conn, BehaviorMode::PreferPrimary, false, false);
    let probe = ProductionFailClosedProbe::new(conn);
    let adapters = vec![adapter(SECONDARY_ID, "Down")];
    let state = probe.probe(TEST_SID, &adapters).expect("Some");
    assert!(!state.fail_closed_active);
}

#[test]
fn strict_secondary_fail_closed_mode_triggers_without_explicit_block_flag() {
    let (_d, conn) = open_state_db();
    // StrictSecondaryFailClosed mode counts as block-when-unavailable
    // regardless of the explicit flag.
    seed_policy(&conn, BehaviorMode::StrictSecondaryFailClosed, false);
    let probe = ProductionFailClosedProbe::new(conn);
    let adapters = vec![adapter(SECONDARY_ID, "Down")];
    let state = probe.probe(TEST_SID, &adapters).expect("Some");
    assert!(state.fail_closed_active);
}

#[test]
fn missing_secondary_adapter_in_snapshot_counts_as_offline() {
    let (_d, conn) = open_state_db();
    seed_policy(&conn, BehaviorMode::PreferPrimary, true);
    let probe = ProductionFailClosedProbe::new(conn);
    // Secondary stable_id NOT in the adapter list at all (e.g.
    // device unplugged) — must be treated as offline.
    let adapters = vec![adapter("primary-id", "Up")];
    let state = probe.probe(TEST_SID, &adapters).expect("Some");
    assert!(state.fail_closed_active);
}

// ── Regression: persistent-id scheme mismatch (GUID/MAC bindings) ──────

const GUID_SECONDARY: &str = "{12AB34CD-0000-0000-0000-000000000001}";
const MAC_SECONDARY: [u8; 6] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

fn seed_policy_with_secondary_stable_id(conn: &Arc<Mutex<Connection>>, secondary_stable_id: &str) {
    let guard = conn.lock().unwrap();
    let repo = RouteBindingsRepository::new(&guard);
    repo.update_for_sid(
        TEST_SID,
        &RoutePolicyRecord {
            primary: Some(RouteBindingRecord {
                stable_id: "primary-id".into(),
                display_name: "Primary".into(),
                user_confirmed: true,
                known_stable_ids: vec![],
            }),
            secondary: Some(RouteBindingRecord {
                stable_id: secondary_stable_id.into(),
                display_name: "Secondary VPN".into(),
                user_confirmed: true,
                known_stable_ids: vec![],
            }),
            mode: BehaviorMode::PreferPrimary,
            block_secondary_when_unavailable: true,
            kill_switch_fail_closed: true,
            kill_switch_protocols: 0x7F,
            kill_switch_block_all: false,
            kill_switch_enabled: true,
            allow_dns_over_primary: false,
            include_subdomains: false,
            shared_ip_policy: nrr_domain::shared_ip::SharedIpPolicy::default(),
            mode_a_coverage_strategy: nrr_domain::mode_a_coverage::ModeACoverageStrategy::default(),
            resolve_hosts_bypass: true,
            doh_lockdown_enabled: false,
            doh_lockdown_scope: nrr_storage::doh_lockdown::DohLockdownScope::default(),
            browser_history_auto_seed: false,
            kill_switch_strict_shared_ips: false,
            auto_rules_mode: nrr_storage::auto_rules::AutoRulesMode::default(),
            auto_rules_eager_delivery_names: false,
            primary_probe_auto: false,
            primary_probe_timeout_ms: 1500,
            primary_probe_max_targets: 8,
            primary_probe_repeat_secs: 300,
            local_networks_auto_accept: false,
            zone_priority_over_ip: false,
            binding_source: BindingSource::UserAssigned,
        },
        100,
    )
    .expect("update_for_sid");
}

/// Wire `AdapterEntry` as `adapter_to_entry` would produce it for a live
/// adapter identified only by its GUID (no MAC).
fn guid_adapter_entry(oper_status: &str) -> AdapterEntry {
    AdapterEntry {
        persistent_id: GUID_SECONDARY.into(),
        adapter_name: GUID_SECONDARY.into(),
        ipv6_if_index: 7,
        physical_address: None,
        windows_name: "VPN".into(),
        interface_description: String::new(),
        interface_type: "Ppp".into(),
        oper_status: oper_status.into(),
    }
}

fn mac_hex_colon(mac: [u8; 6]) -> String {
    mac.iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

#[test]
fn win_adapter_scheme_binding_matches_live_guid_adapter_up() {
    // Regression for the persistent-id scheme mismatch: the binding
    // stores `win-adapter:{lowercased-guid}` (the GUI persistent-id
    // scheme), while the wire `AdapterEntry` this probe receives carries
    // `AdapterInfo::stable_id()` (bare GUID here, no MAC). A raw `==`
    // compare between the two schemes never matched, so a live,
    // working secondary was permanently reported offline.
    let (_d, conn) = open_state_db();
    let bound_id = format!("win-adapter:{}", GUID_SECONDARY.to_ascii_lowercase());
    seed_policy_with_secondary_stable_id(&conn, &bound_id);
    let probe = ProductionFailClosedProbe::new(conn);

    let adapters = vec![adapter("primary-id", "Up"), guid_adapter_entry("Up")];
    let state = probe.probe(TEST_SID, &adapters).expect("Some");
    assert!(
        !state.fail_closed_active,
        "a live win-adapter:-scheme secondary must not trip the Fail-Closed banner"
    );
}

#[test]
fn win_adapter_scheme_binding_down_adapter_yields_active() {
    let (_d, conn) = open_state_db();
    let bound_id = format!("win-adapter:{}", GUID_SECONDARY.to_ascii_lowercase());
    seed_policy_with_secondary_stable_id(&conn, &bound_id);
    let probe = ProductionFailClosedProbe::new(conn);

    let adapters = vec![adapter("primary-id", "Up"), guid_adapter_entry("Down")];
    let state = probe.probe(TEST_SID, &adapters).expect("Some");
    assert!(
        state.fail_closed_active,
        "a resolved but Down secondary must still trip the banner"
    );
}

#[test]
fn win_adapter_scheme_binding_absent_adapter_yields_active() {
    let (_d, conn) = open_state_db();
    let bound_id = format!("win-adapter:{}", GUID_SECONDARY.to_ascii_lowercase());
    seed_policy_with_secondary_stable_id(&conn, &bound_id);
    let probe = ProductionFailClosedProbe::new(conn);

    let adapters = vec![adapter("primary-id", "Up")];
    let state = probe.probe(TEST_SID, &adapters).expect("Some");
    assert!(
        state.fail_closed_active,
        "a genuinely absent secondary must trip the banner"
    );
}

#[test]
fn win_ifindex_mac_scheme_binding_matches_live_mac_adapter() {
    // Same mismatch, MAC-fallback branch: the binding stores
    // `win-ifindex-mac:{index}:{dash-separated-MAC}` while the wire
    // `AdapterEntry::physical_address` is colon-separated hex.
    let (_d, conn) = open_state_db();
    let mac_dash = mac_hex_colon(MAC_SECONDARY).replace(':', "-");
    let bound_id = format!("win-ifindex-mac:9:{mac_dash}");
    seed_policy_with_secondary_stable_id(&conn, &bound_id);
    let probe = ProductionFailClosedProbe::new(conn);

    let mac_adapter = AdapterEntry {
        persistent_id: "irrelevant-low-level-id".into(),
        adapter_name: String::new(),
        ipv6_if_index: 9,
        physical_address: Some(mac_hex_colon(MAC_SECONDARY)),
        windows_name: "VPN".into(),
        interface_description: String::new(),
        interface_type: "Ppp".into(),
        oper_status: "Up".into(),
    };
    let adapters = vec![adapter("primary-id", "Up"), mac_adapter];
    let state = probe.probe(TEST_SID, &adapters).expect("Some");
    assert!(
        !state.fail_closed_active,
        "a live win-ifindex-mac:-scheme secondary must not trip the Fail-Closed banner"
    );
}
