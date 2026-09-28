//! The whole enforcement path against a live kernel: neutral plans in, kernel
//! state out.
//!
//! `nft_live` proves the kernel accepts the ruleset we render. This proves the
//! step above it — that two principals' plans, resolved and lowered together,
//! both survive one apply. That is the property no pure test can establish,
//! because the thing that would break it is the kernel replacing a table.
//!
//! Ignored by default: it needs root, `nft` and a real uplink. Run it with
//! `--ignored`; it then fails, rather than passes, on a host that lacks them —
//! a silent pass reads as coverage it does not have. Each test installs into a
//! table of its own and refuses to run beside a live daemon.

#![cfg(target_os = "linux")]
#![allow(clippy::expect_used)]

use std::process::Command;
use std::sync::Arc;

use nrr_platform_api::adapters::{AdapterEventSource, IfOperStatus, InterfaceType};
use nrr_platform_api::enforcement::{
    AppScope, Coverage, DstMatch, EgressBinding, EgressBindingSource, EgressConstraint, EgressRef,
    EnforcementPlan, FlowMatch, FlowRule, PolicyEnforcer, Precedence, PrecedenceClass,
    PrincipalScope, UserPrincipal, Verdict,
};
use nrr_platform_linux::adapters::LinuxAdapterSource;
use nrr_platform_linux::lower_linux::NRR_TABLE;
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

const IFACE_ENV: &str = "NRR_LIVE_TEST_IFACE";

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

/// Per test, not per process: the tests in this file run in parallel threads.
fn test_table(test: &str) -> String {
    format!("nrr_test_{}_{test}", std::process::id())
}

/// Deletes the test table on every exit, a failed assert included.
struct TableGuard(String);

impl Drop for TableGuard {
    fn drop(&mut self) {
        let _ = NftCliEnforcement::new().teardown(&self.0);
    }
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
        .map(|a| {
            if a.friendly_name.is_empty() {
                a.adapter_name
            } else {
                a.friendly_name
            }
        })
        .unwrap_or_else(|| {
            panic!("no up, non-loopback link with a default route; name one in {IFACE_ENV}")
        })
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

fn list_our_table(table: &str) -> String {
    let output = Command::new("nft")
        .args(["list", "table", "inet", table])
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
#[ignore = "needs root and nft, and no live daemon; run with --ignored"]
fn the_leak_guard_reaches_the_kernel_as_a_drop() {
    require_environment();

    let table = test_table("leak_guard");
    let _guard = TableGuard(table.clone());
    // The binding names a link that does NOT exist — the shape of a tunnel that
    // went away, which is exactly when the guard has to hold.
    let enforcer = NftPolicyEnforcer::new(
        Arc::new(BoundToLink("nrr-absent-link".to_owned())),
        Arc::new(LinuxAdapterSource),
    )
    .with_table(table.clone());

    let guarded = std::net::Ipv4Addr::new(198, 51, 100, 66);
    enforcer
        .enforce(&[guarded_plan(1000, guarded)])
        .expect("the kernel must accept the guard");

    let installed = list_our_table(&table);
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
#[ignore = "needs root, nft and a real uplink, and no live daemon; run with --ignored"]
fn two_principals_survive_one_apply_on_a_live_kernel() {
    require_environment();

    // A link the machine really has, so the pin resolves the way it would in
    // production instead of being reported unsupported.
    let adapters = Arc::new(LinuxAdapterSource);
    let link = uplink(&adapters);
    eprintln!("enforce_live: binding both principals to `{link}`");

    let table = test_table("two_principals");
    let _guard = TableGuard(table.clone());
    let enforcer =
        NftPolicyEnforcer::new(Arc::new(BoundToLink(link)), adapters).with_table(table.clone());
    let report = enforcer
        .enforce(&[plan_for(1000, 7), plan_for(1001, 8)])
        .expect("the kernel must accept the plans");

    assert_eq!(report.skipped, 0, "notes: {:?}", report.notes);
    assert!(report.applied >= 4, "each pin lowers to a pair: {report:?}");

    let installed = list_our_table(&table);
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
    let after = list_our_table(&table).matches("skuid").count();
    assert_eq!(before, after, "re-apply duplicated rules");

    enforcer.teardown().expect("teardown must succeed");
    let ours = format!("table inet {table}");
    assert!(
        !list_tables().lines().any(|l| l.trim() == ours),
        "teardown must remove our table",
    );
}
