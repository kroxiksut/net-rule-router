//! The blanket block, end to end against a live kernel: planner → lowering →
//! nftables.
//!
//! The pure tests prove which rules the plan contains and which order they sort
//! into. What only the kernel can show is the finished chain — and the property
//! that matters there is ORDER, because the first matching rule wins: a block
//! that sits above the tunnel's own server address is a block nothing on the
//! machine can lift, which is how a kill-switch turns an outage into a permanent
//! one.
//!
//! Ignored by default: it needs root, `nft` and a real uplink. Run it with
//! `--ignored`; it then fails, rather than passes, on a host that lacks them.
//! It installs into a table of its own and refuses to run beside a live daemon.

#![cfg(target_os = "linux")]
#![allow(clippy::expect_used)]

use std::net::Ipv4Addr;
use std::process::Command;
use std::sync::Arc;

use nrr_platform_api::adapters::{AdapterEventSource, IfOperStatus, InterfaceType};
use nrr_platform_api::enforcement::{
    EgressBinding, EgressBindingSource, EnforcementPlan, PolicyEnforcer, UserPrincipal,
};
use nrr_platform_linux::adapters::LinuxAdapterSource;
use nrr_platform_linux::lower_linux::NRR_TABLE;
use nrr_platform_linux::nft_apply::{NftApplyError, NftCliEnforcement};
use nrr_platform_linux::nft_policy_enforcer::NftPolicyEnforcer;
use nrr_service_runtime::enforcement_planner::plan_catch_all_kill_switch;
use nrr_service_runtime::killswitch_codegen::KillSwitchProtocols;

const SERVER: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 7);
const LAN: (Ipv4Addr, u8) = (Ipv4Addr::new(192, 168, 1, 0), 24);
const IFACE_ENV: &str = "NRR_LIVE_TEST_IFACE";
/// Above every range a distro's `useradd` assigns by default (`UID_MIN`/`UID_MAX`,
/// usually 1000..60000) and outside systemd's `DynamicUser` band (61184..65519):
/// no real login account or service can hold it, unlike `nobody` (65534), which
/// some daemons run under. `skuid` matches the raw number — the account need not
/// exist.
const TEST_UID: u32 = 999_999;

fn is_root() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find(|l| l.starts_with("Uid:"))
                .and_then(|l| l.split_whitespace().nth(1).map(str::to_owned))
        })
        .is_some_and(|uid| uid == "0")
}

fn list_tables() -> String {
    let output = Command::new("nft")
        .args(["list", "tables"])
        .output()
        .expect("nft must be runnable");
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Panics with the reason when the host cannot run this: an explicit
/// `--ignored` run that passes without touching the kernel is false coverage.
fn require_environment() {
    assert!(
        is_root(),
        "needs root: nf_tables refuses an unprivileged caller"
    );
    match NftCliEnforcement::new().probe() {
        Ok(()) => {}
        Err(NftApplyError::NftUnavailable { detail }) => {
            panic!("nft is unavailable ({detail})")
        }
        Err(other) => panic!("nft answered an error: {other}"),
    }
    let product = format!("table inet {NRR_TABLE}");
    assert!(
        !list_tables().lines().any(|l| l.trim() == product),
        "`{product}` exists: a live daemon is enforcing on this host. Stop it first — \
         this test must not share the kernel with the user's kill-switch",
    );
}

/// A real uplink: `NRR_LIVE_TEST_IFACE` when set, else the first link that is
/// up, is not loopback and carries a default route.
fn uplink(adapters: &LinuxAdapterSource) -> String {
    let all = adapters.enumerate_all().expect("adapters must enumerate");
    if let Ok(wanted) = std::env::var(IFACE_ENV) {
        let found = all
            .iter()
            .find(|a| a.friendly_name == wanted || a.adapter_name == wanted)
            .unwrap_or_else(|| panic!("{IFACE_ENV}=`{wanted}` names no interface on this host"));
        assert!(
            found.oper_status == IfOperStatus::Up,
            "{IFACE_ENV}=`{wanted}` is not up",
        );
        return wanted;
    }
    all.into_iter()
        .find(|a| {
            a.oper_status == IfOperStatus::Up
                && a.interface_type != InterfaceType::Loopback
                && a.has_gateway()
        })
        .map(|a| a.friendly_name)
        .unwrap_or_else(|| {
            panic!("no up, non-loopback link with a default route; name one in {IFACE_ENV}")
        })
}

/// Deletes the test table on every exit, a failed assert included.
struct TableGuard(String);

impl Drop for TableGuard {
    fn drop(&mut self) {
        let _ = NftCliEnforcement::new().teardown(&self.0);
    }
}

/// Bound to a link the machine really has, so the blanket permit resolves the
/// way it would with a live tunnel.
struct BoundToLink(String);

impl EgressBindingSource for BoundToLink {
    fn bindings_for(&self, _principal: &UserPrincipal) -> EgressBinding {
        EgressBinding {
            primary: Some(self.0.clone()),
            secondary: Some(self.0.clone()),
        }
    }
}

fn installed_ruleset(table: &str) -> String {
    let output = Command::new("nft")
        .args(["list", "table", "inet", table])
        .output()
        .expect("nft must be runnable");
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Byte offset of the first line matching `predicate`, so two rules' positions
/// in the chain can be compared.
fn line_offset(text: &str, predicate: impl Fn(&str) -> bool) -> Option<usize> {
    let mut offset = 0;
    for line in text.lines() {
        if predicate(line) {
            return Some(offset);
        }
        offset += line.len() + 1;
    }
    None
}

#[test]
#[ignore = "needs root, nft and a real uplink, and no live daemon; run with --ignored"]
fn the_blanket_block_lands_below_the_escapes_it_must_not_cut() {
    require_environment();

    let adapters = Arc::new(LinuxAdapterSource);
    let link = uplink(&adapters);
    eprintln!("blanket_block_live: binding to `{link}`");

    let flows = plan_catch_all_kill_switch(
        &format!("unix:uid:{TEST_UID}"),
        &[SERVER],
        &[LAN],
        // No IPv6 on this fixture: the subject is the v4 blanket block.
        nrr_service_runtime::enforcement_planner::Ipv6Exemptions::default(),
        KillSwitchProtocols::from_bits(0x7F),
    );
    assert!(!flows.is_empty(), "the planner refused to plan the block");

    let table = format!("nrr_test_{}", std::process::id());
    let _guard = TableGuard(table.clone());
    let enforcer =
        NftPolicyEnforcer::new(Arc::new(BoundToLink(link)), adapters).with_table(table.clone());
    enforcer
        .enforce(&[EnforcementPlan {
            principal: UserPrincipal::from_linux_uid(TEST_UID),
            flows,
            routes: Vec::new(),
            policy_rules: Vec::new(),
        }])
        .expect("the kernel must accept the blanket block");

    let installed = installed_ruleset(&table);
    let server_at = line_offset(&installed, |l| l.contains("203.0.113.7"))
        .unwrap_or_else(|| panic!("the tunnel server is not exempt:\n{installed}"));
    let lan_at = line_offset(&installed, |l| l.contains("192.168.1.0/24"))
        .unwrap_or_else(|| panic!("the LAN is not exempt:\n{installed}"));
    // The blanket drop is the one that names no destination at all.
    let block_at = line_offset(&installed, |l| l.contains("drop") && !l.contains("daddr"))
        .unwrap_or_else(|| panic!("nothing blocks the off-tunnel traffic:\n{installed}"));

    assert!(
        server_at < block_at,
        "the block sits above the tunnel's server — it could never reconnect:\n{installed}",
    );
    assert!(
        lan_at < block_at,
        "the block sits above the LAN — the local network would be cut:\n{installed}",
    );
    assert!(
        installed.contains(&format!("meta skuid {TEST_UID}")),
        "the block is not scoped to the user it belongs to:\n{installed}",
    );

    enforcer.teardown().expect("teardown must succeed");
}
