#![allow(clippy::expect_used)]

use nrr_client_logic::rules_table::{RuleRow, RuleType, TargetRoute};
use nrr_ipc_client::ConnectionStatus;
use nrr_platform_api::{AppDiscoverySource, HypervisorInventory, VirtualMachine};
use nrr_shared::ipc::IpcOperationName;
use serde_json::json;

use super::*;
use crate::link::Link;
use crate::screens::screen;
use crate::screens::suggestions::tests::{drain, missing_in_locales};
use crate::testing::{app_at, texts_en, FakeService, Fixture};

#[test]
fn every_key_is_in_both_locale_files() {
    let missing = missing_in_locales(&keys::all());
    assert!(missing.is_empty(), "{missing:?}");
}

fn found(kind: AppGroupKind, name: &str, path: Option<&str>) -> DiscoveredApp {
    DiscoveredApp {
        kind,
        display_name: name.to_owned(),
        exe_path: path.map(str::to_owned),
        running: true,
        source: AppDiscoverySource::RunningProcess,
    }
}

fn virtualbox() -> HypervisorInventory {
    HypervisorInventory {
        hypervisor: Hypervisor::VirtualBox,
        host_network_seen: true,
        traffic_processes: vec!["VBoxHeadless.exe".into(), "VBoxSVC.exe".into()],
        machines: vec![VirtualMachine {
            id: "m1".into(),
            name: "Lab".into(),
            adapters: Vec::new(),
        }],
    }
}

fn on_screen() -> (AppState, FakeService) {
    let fake = FakeService::new(ConnectionStatus::Connected);
    fake.answer(
        IpcOperationName::RulesList,
        json!({
            "rows": [{
                "id": "1", "rule-type": "domain", "match-value": "example.com",
                "target-route": "primary", "enabled": true, "validation-status": "ok"
            }],
            "supported-rule-types": ["zone", "domain", "exact-ip", "application"]
        }),
    );
    let mut app = app_at(Link::Connected, Some(&Fixture::healthy()));
    app.open(ScreenId::Rules);
    drain(&mut app, &fake);
    // The scan the screen starts is not run: its answer is put in by hand.
    app.open(ScreenId::AppGroups);
    app.outbox.take();
    let generation = app.app_groups.generation;
    let apps = [
        found(
            AppGroupKind::BitTorrent,
            "qBittorrent",
            Some("C:\\Program Files\\qBittorrent\\qbittorrent.exe"),
        ),
        found(AppGroupKind::KernelVirtualNet, "WSL", None),
    ];
    scanned(&mut app, generation, &apps, &[virtualbox()]);
    // The rule comments come from the loaded texts.
    on_texts(&mut app, &texts_en());
    (app, fake)
}

fn text(app: &AppState) -> String {
    let view = screen(ScreenId::AppGroups).view(app, &texts_en());
    let mut out = String::new();
    for panel in &view.panels {
        out.push_str(&panel.title);
        out.push('\n');
        for line in &panel.lines {
            out.push_str(&line.plain_text());
            out.push('\n');
        }
    }
    out
}

fn app_rules(app: &AppState) -> Vec<(String, String, bool)> {
    app.rules
        .table
        .rules()
        .filter(|r| r.rule_type == RuleType::Application)
        .map(|r| {
            (
                r.match_value.clone(),
                r.target_route.as_str().to_owned(),
                r.enabled,
            )
        })
        .collect()
}

#[test]
fn machines_lead_and_every_group_shows_its_route() {
    let (app, _) = on_screen();
    let shown = text(&app);
    let vbox = shown.find("VirtualBox").expect("hypervisor");
    let torrent = shown.find("qBittorrent").expect("torrent client");
    assert!(vbox < torrent, "{shown}");
    assert!(shown.contains("1. VirtualBox \u{2014} Primary"), "{shown}");
    assert!(shown.contains("Machines: Lab"), "{shown}");
    assert!(
        shown.contains("2. WSL \u{2014} Main"),
        "display only: {shown}"
    );
    assert!(shown.contains("for information only"), "{shown}");
}

#[test]
fn a_route_is_an_edit_of_the_rules_list_not_an_apply() {
    let (mut app, fake) = on_screen();
    assert!(screen(ScreenId::AppGroups).on_line(&mut app, "s 1"));
    assert_eq!(
        app_rules(&app),
        vec![
            ("VBoxHeadless.exe".into(), "secondary".into(), true),
            ("VBoxSVC.exe".into(), "secondary".into(), true),
        ]
    );
    let added = app.rules.table.rules().last().expect("rule");
    assert_eq!(added.comment, "Hypervisors");
    assert!(app.rules.table.is_dirty());
    assert!(fake.sent(IpcOperationName::MutationSubmit).is_empty());
    let shown = text(&app);
    assert!(shown.contains("Routes updated for 2 programs."), "{shown}");
    assert!(
        shown.contains("1. VirtualBox \u{2014} Additional"),
        "{shown}"
    );
}

#[test]
fn sending_a_group_back_to_the_main_route_removes_its_rules() {
    let (mut app, _) = on_screen();
    screen(ScreenId::AppGroups).on_line(&mut app, "s 3");
    assert_eq!(app_rules(&app).len(), 1);
    screen(ScreenId::AppGroups).on_line(&mut app, "p 3");
    assert!(app_rules(&app).is_empty());
    screen(ScreenId::AppGroups).on_line(&mut app, "p 3");
    assert!(text(&app).contains("Nothing changed"), "already there");
}

#[test]
fn a_disabled_rule_is_switched_on_rather_than_duplicated() {
    let (mut app, _) = on_screen();
    app.rules.table.import(
        vec![RuleRow {
            id: String::new(),
            enabled: false,
            rule_type: RuleType::Application,
            match_value: "qbittorrent.exe".into(),
            target_route: TargetRoute::Secondary,
            verify: false,
            comment: String::new(),
            origin: None,
        }],
        false,
    );
    screen(ScreenId::AppGroups).on_line(&mut app, "s 3");
    assert_eq!(
        app_rules(&app),
        vec![("qbittorrent.exe".into(), "secondary".into(), true)]
    );
}

#[test]
fn a_kernel_network_cannot_be_given_a_route() {
    let (mut app, _) = on_screen();
    screen(ScreenId::AppGroups).on_line(&mut app, "s 2");
    assert!(app_rules(&app).is_empty());
    assert!(text(&app).contains("Item 2 cannot be given a route"));
}

#[test]
fn the_free_rules_limit_stops_the_additions() {
    let (mut app, _) = on_screen();
    let rows: Vec<RuleRow> = (0..FREE_MAX_RULES)
        .map(|i| RuleRow {
            id: String::new(),
            enabled: true,
            rule_type: RuleType::Domain,
            match_value: format!("site{i}.example"),
            target_route: TargetRoute::Primary,
            verify: false,
            comment: String::new(),
            origin: None,
        })
        .collect();
    app.rules.table.import(rows, true);
    screen(ScreenId::AppGroups).on_line(&mut app, "s 3");
    assert!(app_rules(&app).is_empty());
    assert!(text(&app).contains("Up to"), "{}", text(&app));
}

#[test]
fn names_that_cannot_stand_in_a_rule_are_not_listed() {
    let apps = [
        found(AppGroupKind::BitTorrent, "bad\nname", None),
        found(AppGroupKind::BitTorrent, &"x".repeat(400), None),
        found(AppGroupKind::BitTorrent, "good", None),
    ];
    let entries = entries_of(&apps, &[]);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].programs, vec!["good".to_owned()]);
}

#[test]
fn an_older_scan_does_not_replace_a_newer_one() {
    let (mut app, _) = on_screen();
    let stale = app.app_groups.generation - 1;
    scanned(&mut app, stale, &[], &[]);
    assert!(!app.app_groups.entries.is_empty());
}

fn lab_with_adapters(bound: Option<std::net::Ipv4Addr>) -> HypervisorInventory {
    use nrr_platform_api::{NatAdapter, VmAdapter, VmAttachment};
    let nat = NatAdapter::new("10.0.2.0/24".into(), "10.0.2.2".parse().expect("ip"), true)
        .with_bound_address(bound);
    let mut inventory = virtualbox();
    inventory.machines[0].adapters = vec![
        VmAdapter {
            slot: 0,
            attachment: VmAttachment::Nat(nat),
        },
        VmAdapter {
            slot: 1,
            attachment: VmAttachment::Bridged,
        },
    ];
    inventory
}

/// The additional adapter's address in the snapshot, or none at all.
fn additional_ip(app: &mut AppState, ip: &str) {
    let snapshot = app.snapshot.as_mut().expect("snapshot");
    snapshot.adapters.rows[1].local_ip = ip.into();
}

fn with_machines(bound: Option<std::net::Ipv4Addr>) -> AppState {
    let (mut app, _) = on_screen();
    additional_ip(&mut app, "198.51.100.7");
    let generation = app.app_groups.generation;
    scanned(&mut app, generation, &[], &[lab_with_adapters(bound)]);
    assert!(screen(ScreenId::AppGroups).on_line(&mut app, "m 1"));
    app
}

#[test]
fn a_hypervisors_machines_show_each_adapter_and_its_advice() {
    let app = with_machines(None);
    let shown = text(&app);
    assert!(shown.contains("Machines of VirtualBox"), "{shown}");
    assert!(shown.contains("Machine: Lab"), "{shown}");
    assert!(shown.contains("1. Adapter 1: NAT"), "{shown}");
    assert!(shown.contains("set its DNS server to 10.0.2.2"), "{shown}");
    assert!(shown.contains("This machine follows your rules"), "{shown}");
    assert!(shown.contains("Adapter 2: Bridged"), "{shown}");
    assert!(
        !shown.contains("2. Adapter 2"),
        "a bridged adapter takes no pin: {shown}"
    );
    assert!(shown.contains("bypasses your rules"), "{shown}");
}

#[test]
fn a_pin_changes_the_hypervisor_and_reads_the_machines_again() {
    let mut app = with_machines(None);
    app.outbox.take();
    assert!(screen(ScreenId::AppGroups).on_line(&mut app, "a 1"));
    assert_eq!(app.outbox.len(), 1, "one call to the hypervisor");
    assert!(text(&app).contains("Changing the machine in VirtualBox"));
    assert!(
        screen(ScreenId::AppGroups).on_line(&mut app, "f 1"),
        "a second change waits for the first"
    );
    assert!(text(&app).contains("still being made"));
    let key = app.app_groups.pinning.clone().expect("in flight");
    app.outbox.take();
    machines::pinned(&mut app, key, Ok(()));
    assert!(app.app_groups.pinning.is_none());
    assert!(app.app_groups.scanning, "read back after the change");
    assert_eq!(app.outbox.len(), 1);
}

#[test]
fn a_refused_pin_names_the_cure() {
    let mut app = with_machines(None);
    screen(ScreenId::AppGroups).on_line(&mut app, "a 1");
    let key = app.app_groups.pinning.clone().expect("in flight");
    machines::pinned(
        &mut app,
        key,
        Err(nrr_platform_api::VmControlError::MachineNotMutable),
    );
    let generation = app.app_groups.generation;
    scanned(&mut app, generation, &[], &[lab_with_adapters(None)]);
    assert!(
        text(&app).contains("Shut it down completely"),
        "{}",
        text(&app)
    );
}

#[test]
fn a_pin_needs_the_additional_adapters_address_first() {
    let mut app = with_machines(None);
    additional_ip(&mut app, "");
    app.outbox.take();
    screen(ScreenId::AppGroups).on_line(&mut app, "a 1");
    assert_eq!(app.outbox.len(), 0, "the hypervisor is not asked");
    assert!(
        text(&app).contains("has no IPv4 address right now"),
        "{}",
        text(&app)
    );
}

#[test]
fn a_machine_tied_to_the_additional_address_reads_as_that_route() {
    let mut app = with_machines(Some("198.51.100.7".parse().expect("ip")));
    let shown = text(&app);
    assert!(
        shown.contains("All of this machine's traffic goes over Additional"),
        "{shown}"
    );
    screen(ScreenId::AppGroups).on_line(&mut app, "a 1");
    assert!(text(&app).contains("already set that way"));

    let mut gone = with_machines(Some("203.0.113.9".parse().expect("ip")));
    assert!(text(&gone).contains("which your computer no longer has"));
    assert!(screen(ScreenId::AppGroups).on_line(&mut gone, "m"));
    assert!(
        text(&gone).contains("Groups and machines"),
        "back on the list"
    );
}

#[test]
fn only_a_hypervisor_has_machines_to_show() {
    let (mut app, _) = on_screen();
    assert!(screen(ScreenId::AppGroups).on_line(&mut app, "m 3"));
    assert!(text(&app).contains("Item 3 is not a hypervisor"));
    assert!(app.app_groups.machines.is_none());
}

#[test]
fn app_groups_snapshot() {
    let (mut app, _) = on_screen();
    app.focus = Focus::Feed;
    crate::testing::assert_snapshot(
        "app-groups-100x30",
        &crate::screens::suggestions::tests::render(&app, 100, 30),
    );
    let app = with_machines(None);
    crate::testing::assert_snapshot(
        "app-groups-machines-100x40",
        &crate::screens::suggestions::tests::render(&app, 100, 40),
    );
}
