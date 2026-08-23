//! The whole enforcement path against a live kernel: neutral plans in, kernel
//! state out.
//!
//! `nft_live` proves the kernel accepts the ruleset we render. This proves the
//! step above it — that two principals' plans, resolved and lowered together,
//! both survive one apply. That is the property no pure test can establish,
//! because the thing that would break it is the kernel replacing a table.
//!
//! Skips itself, loudly, when the host cannot run it. A silent pass on an
//! unequipped machine reads as coverage it does not have.
//!
//! Uses the product's own table name — the enforcer owns it — so this test must
//! not run beside a live daemon on the same host.

#![cfg(target_os = "linux")]
#![allow(clippy::expect_used)]

use std::process::Command;
use std::sync::Arc;

use nrr_platform_api::adapters::AdapterEventSource;
use nrr_platform_api::enforcement::{
    AppScope, Coverage, DstMatch, EgressBinding, EgressBindingSource, EgressConstraint, EgressRef,
    EnforcementPlan, FlowMatch, FlowRule, PolicyEnforcer, Precedence, PrecedenceClass,
    PrincipalScope, UserPrincipal, Verdict,
};
use nrr_platform_linux::adapters::LinuxAdapterSource;
use nrr_platform_linux::nft_apply::{NftApplyError, NftCliEnforcement};
use nrr_platform_linux::nft_policy_enforcer::NftPolicyEnforcer;
use nrr_shared::RouteRole;

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

/// Everyone is bound to the same live link, named as the machine names it.
struct BoundToLink(String);

impl EgressBindingSource for BoundToLink {
    fn bindings_for(&self, _principal: &UserPrincipal) -> EgressBinding {
        EgressBinding {
            primary: Some(self.0.clone()),
            secondary: Some(self.0.clone()),
        }
    }
}

fn plan_for(uid: u32, last_octet: u8) -> EnforcementPlan {
    let principal = UserPrincipal::from_linux_uid(uid);
    EnforcementPlan {
        principal: principal.clone(),
        flows: vec![FlowRule {
            verdict: Verdict::Permit,
            precedence: Precedence {
                class: PrecedenceClass::RouteRule(RouteRole::Secondary),
                ordinal: 0,
            },
            flow: FlowMatch {
                dst: DstMatch::HostV4(std::net::Ipv4Addr::new(198, 51, 100, last_octet)),
                dst_port: None,
                protocol: None,
            },
            principal: PrincipalScope(Some(principal)),
            app: AppScope::Any,
            egress: EgressConstraint::OnlyVia(EgressRef::Secondary),
            coverage: Coverage::ConnectOnly,
        }],
        routes: Vec::new(),
        policy_rules: Vec::new(),
    }
}

fn list_our_table() -> String {
    let output = Command::new("nft")
        .args(["list", "table", "inet", "nrr"])
        .output()
        .expect("nft must be runnable");
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// The leak-guard as it reaches the kernel: with the tunnel gone, the address it
/// carried must be DROPPED, not left to leave over the primary.
fn guarded_plan(uid: u32, guarded: std::net::Ipv4Addr) -> EnforcementPlan {
    let principal = UserPrincipal::from_linux_uid(uid);
    EnforcementPlan {
        principal: principal.clone(),
        flows: vec![FlowRule {
            verdict: Verdict::Block,
            precedence: Precedence {
                class: PrecedenceClass::KillSwitchBlock,
                ordinal: 0,
            },
            flow: FlowMatch {
                dst: DstMatch::HostV4(guarded),
                dst_port: None,
                protocol: None,
            },
            principal: PrincipalScope(Some(principal)),
            app: AppScope::Any,
            egress: EgressConstraint::Any,
            coverage: Coverage::AllPackets,
        }],
        routes: Vec::new(),
        policy_rules: Vec::new(),
    }
}

#[test]
fn the_leak_guard_reaches_the_kernel_as_a_drop() {
    if let Err(reason) = probe_environment() {
        eprintln!("SKIPPED enforce_live: {reason}");
        return;
    }

    // The binding names a link that does NOT exist — the shape of a tunnel that
    // went away, which is exactly when the guard has to hold.
    let enforcer = NftPolicyEnforcer::new(
        Arc::new(BoundToLink("nrr-absent-link".to_owned())),
        Arc::new(LinuxAdapterSource),
    );

    let guarded = std::net::Ipv4Addr::new(198, 51, 100, 66);
    enforcer
        .enforce(&[guarded_plan(1000, guarded)])
        .expect("the kernel must accept the guard");

    let installed = list_our_table();
    assert!(
        installed.contains("198.51.100.66") && installed.contains("drop"),
        "the guarded address must be dropped:\n{installed}",
    );

    // And the platform must report the missing link as unavailable rather than
    // claim a channel that is gone.
    let availability = enforcer.channel_availability(&UserPrincipal::from_linux_uid(1000));
    assert!(!availability.secondary && !availability.primary);

    enforcer.teardown().expect("teardown must succeed");
}

#[test]
fn two_principals_survive_one_apply_on_a_live_kernel() {
    if let Err(reason) = probe_environment() {
        eprintln!("SKIPPED enforce_live: {reason}");
        return;
    }

    // A link the machine really has, so the pin resolves the way it would in
    // production instead of being reported unsupported.
    let adapters = Arc::new(LinuxAdapterSource);
    let link = adapters
        .enumerate_all()
        .expect("adapters must enumerate")
        .into_iter()
        .find(|a| a.oper_status == nrr_platform_api::adapters::IfOperStatus::Up)
        .map(|a| {
            if a.friendly_name.is_empty() {
                a.adapter_name
            } else {
                a.friendly_name
            }
        })
        .expect("at least one link must be up");
    eprintln!("enforce_live: binding both principals to `{link}`");

    let enforcer = NftPolicyEnforcer::new(Arc::new(BoundToLink(link)), adapters);
    let report = enforcer
        .enforce(&[plan_for(1000, 7), plan_for(1001, 8)])
        .expect("the kernel must accept the plans");

    assert_eq!(report.skipped, 0, "notes: {:?}", report.notes);
    assert!(report.applied >= 4, "each pin lowers to a pair: {report:?}");

    let installed = list_our_table();
    assert!(
        installed.contains("skuid 1000") && installed.contains("skuid 1001"),
        "both users must be enforced after ONE apply; got:\n{installed}",
    );
    assert!(
        installed.contains("198.51.100.7") && installed.contains("198.51.100.8"),
        "each user's own destination must be present:\n{installed}",
    );

    // Re-applying the same set must not accumulate rules — the reconcile is
    // idempotent by construction, and this is where that claim is tested.
    let before = installed.matches("skuid").count();
    enforcer
        .enforce(&[plan_for(1000, 7), plan_for(1001, 8)])
        .expect("re-apply must succeed");
    let after = list_our_table().matches("skuid").count();
    assert_eq!(before, after, "re-apply duplicated rules");

    enforcer.teardown().expect("teardown must succeed");
    let remaining = Command::new("nft")
        .args(["list", "tables"])
        .output()
        .expect("nft must be runnable");
    assert!(
        !String::from_utf8_lossy(&remaining.stdout).contains("table inet nrr"),
        "teardown must remove our table",
    );
}
