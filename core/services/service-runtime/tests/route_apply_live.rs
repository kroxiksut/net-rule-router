//! The route half of enforcement, against the LIVE kernel route table.
//!
//! The pure tests prove which entries a plan lowers to. Only the kernel proves
//! that the entry we build is one it will accept and that we can find it again
//! afterwards — and that is the step whose absence made a route-to-secondary
//! rule behave as a block.
//!
//! Skips itself, loudly, without root: adding a route is privileged.

#![cfg(target_os = "linux")]
#![allow(clippy::expect_used)]

use std::net::Ipv4Addr;
use std::sync::Arc;

use nrr_platform_api::adapters::{AdapterEventSource, IfOperStatus};
use nrr_platform_api::enforcement::{
    DstMatch, EgressBinding, EgressBindingSource, EgressRef, EnforcementPlan, RouteIntent,
    RouteTableRef, UserPrincipal,
};
use nrr_platform_api::route_table::RouteTablePort;
use nrr_service_runtime::route_apply::PlannedRouteApplier;

/// A test destination inside TEST-NET-3, which no real network routes.
const TEST_DST: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 77);

struct BoundToLink(String);

impl EgressBindingSource for BoundToLink {
    fn bindings_for(&self, _principal: &UserPrincipal) -> EgressBinding {
        EgressBinding {
            primary: None,
            secondary: Some(self.0.clone()),
        }
    }
}

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

fn plan_routing(dst: Ipv4Addr) -> EnforcementPlan {
    EnforcementPlan {
        principal: UserPrincipal::from_linux_uid(1000),
        flows: Vec::new(),
        routes: vec![RouteIntent {
            dst: DstMatch::HostV4(dst),
            egress: EgressRef::Secondary,
            metric: 50,
            table: RouteTableRef::Main,
        }],
        policy_rules: Vec::new(),
    }
}

#[test]
fn a_planned_route_reaches_the_kernel_table() {
    if !is_root() {
        eprintln!("SKIPPED route_apply_live: needs root to modify the route table");
        return;
    }

    let adapters: Arc<dyn AdapterEventSource> =
        Arc::new(nrr_platform_linux::adapters::LinuxAdapterSource);
    // A link that is really up, so the entry names an interface the kernel has.
    let link = adapters
        .enumerate_all()
        .expect("adapters must enumerate")
        .into_iter()
        .find(|a| a.oper_status == IfOperStatus::Up && a.index != 0)
        .map(|a| {
            if a.friendly_name.is_empty() {
                a.adapter_name
            } else {
                a.friendly_name
            }
        })
        .expect("at least one link must be up");
    eprintln!("route_apply_live: steering through `{link}`");

    let api: Arc<dyn RouteTablePort> = Arc::new(nrr_platform_linux::LinuxApi);
    let applier = PlannedRouteApplier::new(Arc::clone(&api), adapters, Arc::new(BoundToLink(link)));

    let report = applier
        .apply(&[plan_routing(TEST_DST)])
        .expect("the kernel must accept the route");
    assert_eq!(report.added, 1, "report: {report:?}");
    assert!(report.unresolved.is_empty(), "report: {report:?}");

    let table = api
        .get_ip_forward_table()
        .expect("the table must be readable");
    assert!(
        table
            .iter()
            .any(|r| r.destination == TEST_DST && r.prefix_length == 32),
        "the planned route must be in the kernel table",
    );

    // Re-applying the same plan must add nothing: the pass runs every tick, and
    // a reconcile that re-adds on every pass would churn the table forever.
    let again = applier
        .apply(&[plan_routing(TEST_DST)])
        .expect("re-apply must succeed");
    assert_eq!(again.added, 0, "re-apply churned the table: {again:?}");

    // An empty plan set withdraws what we own — this is what a user logging out
    // must leave behind.
    let cleared = applier.apply(&[]).expect("withdrawal must succeed");
    assert_eq!(cleared.removed, 1, "report: {cleared:?}");

    let after = api
        .get_ip_forward_table()
        .expect("the table must be readable");
    assert!(
        !after
            .iter()
            .any(|r| r.destination == TEST_DST && r.prefix_length == 32),
        "our route must be gone once no plan asks for it",
    );
}
