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
//! Skips itself, loudly, without root or `nft`. Uses the product's own table, so
//! it must not run beside a live daemon on the same host.

#![cfg(target_os = "linux")]
#![allow(clippy::expect_used)]

use std::net::Ipv4Addr;
use std::process::Command;
use std::sync::Arc;

use nrr_platform_api::adapters::{AdapterEventSource, IfOperStatus};
use nrr_platform_api::enforcement::{
    EgressBinding, EgressBindingSource, EnforcementPlan, PolicyEnforcer, UserPrincipal,
};
use nrr_platform_linux::adapters::LinuxAdapterSource;
use nrr_platform_linux::nft_apply::{NftApplyError, NftCliEnforcement};
use nrr_platform_linux::nft_policy_enforcer::NftPolicyEnforcer;
use nrr_service_runtime::enforcement_planner::plan_catch_all_kill_switch;
use nrr_service_runtime::killswitch_codegen::KillSwitchProtocols;

const SERVER: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 7);
const LAN: (Ipv4Addr, u8) = (Ipv4Addr::new(192, 168, 1, 0), 24);

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

fn probe_environment() -> Result<(), String> {
    if !is_root() {
        return Err("needs root: nf_tables refuses an unprivileged caller".to_owned());
    }
    match NftCliEnforcement::new().probe() {
        Ok(()) => Ok(()),
        Err(NftApplyError::NftUnavailable { detail }) => {
            Err(format!("nft is unavailable ({detail})"))
        }
        Err(other) => Err(format!("nft answered an error: {other}")),
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

fn installed_ruleset() -> String {
    let output = Command::new("nft")
        .args(["list", "table", "inet", "nrr"])
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
fn the_blanket_block_lands_below_the_escapes_it_must_not_cut() {
    if let Err(reason) = probe_environment() {
        eprintln!("SKIPPED blanket_block_live: {reason}");
        return;
    }

    let adapters = Arc::new(LinuxAdapterSource);
    let link = adapters
        .enumerate_all()
        .expect("adapters must enumerate")
        .into_iter()
        .find(|a| a.oper_status == IfOperStatus::Up)
        .map(|a| a.friendly_name)
        .expect("a machine has at least one link that is up");

    let flows = plan_catch_all_kill_switch(
        "unix:uid:1000",
        &[SERVER],
        &[LAN],
        KillSwitchProtocols::from_bits(0x7F),
    );
    assert!(!flows.is_empty(), "the planner refused to plan the block");

    let enforcer = NftPolicyEnforcer::new(Arc::new(BoundToLink(link)), adapters);
    enforcer
        .enforce(&[EnforcementPlan {
            principal: UserPrincipal::from_linux_uid(1000),
            flows,
            routes: Vec::new(),
            policy_rules: Vec::new(),
        }])
        .expect("the kernel must accept the blanket block");

    let installed = installed_ruleset();
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
        installed.contains("meta skuid 1000"),
        "the block is not scoped to the user it belongs to:\n{installed}",
    );

    enforcer.teardown().expect("teardown must succeed");
}
