//! The route-policy wire shape is pinned to `IPC_CONTRACT_REVISION`: a field
//! added, removed or renamed without a bump would let a mismatched window and
//! service talk past each other with no banner.

use std::collections::BTreeSet;

use nrr_shared::ipc::IPC_CONTRACT_REVISION;
use nrr_shared::ipc_payloads::{
    RoutePolicyDto, RoutePolicyUpdateRequest, ROUTE_POLICY_SNAPSHOT_ONLY_KEYS,
};
use nrr_shared::wire_fields::struct_wire_fields;

const REVISION: u32 = 2;

const REQUEST_FIELDS: [&str; 29] = [
    "allow-dns-over-primary",
    "app-rules-take-all-addresses",
    "apply-only",
    "auto-rules-eager-delivery-names",
    "auto-rules-mode",
    "binding-source",
    "browser-history-auto-seed",
    "doh-lockdown-auto",
    "doh-lockdown-enabled",
    "doh-lockdown-scope",
    "external-address-auto-check",
    "forwarded-outage",
    "include-subdomains",
    "kill-switch-protocols",
    "kill-switch-strict-shared-ips",
    "leak-protection",
    "local-networks-auto-accept",
    "mode",
    "primary",
    "primary-probe-auto",
    "primary-probe-max-targets",
    "primary-probe-repeat-secs",
    "primary-probe-timeout-ms",
    "resolve-hosts-bypass",
    "secondary",
    "shared-ip-policy",
    "short-name-completion",
    "short-name-suffix",
    "zone-priority-over-ip",
];

const SNAPSHOT_FIELDS: [&str; 30] = [
    "allow-dns-over-primary",
    "app-rules-take-all-addresses",
    "auto-rules-eager-delivery-names",
    "auto-rules-mode",
    "binding-source",
    "browser-history-auto-seed",
    "doh-lockdown-auto",
    "doh-lockdown-effective",
    "doh-lockdown-enabled",
    "doh-lockdown-scope",
    "external-address-auto-check",
    "forwarded-outage",
    "include-subdomains",
    "kill-switch-protocols",
    "kill-switch-strict-shared-ips",
    "leak-protection",
    "local-networks-auto-accept",
    "mode",
    "primary",
    "primary-probe-auto",
    "primary-probe-max-targets",
    "primary-probe-repeat-secs",
    "primary-probe-timeout-ms",
    "resolve-hosts-bypass",
    "secondary",
    "secondary-link-provider-apps",
    "shared-ip-policy",
    "short-name-completion",
    "short-name-suffix",
    "zone-priority-over-ip",
];

fn fields<T: serde::de::DeserializeOwned>() -> BTreeSet<&'static str> {
    struct_wire_fields::<T>().iter().copied().collect()
}

#[test]
fn the_route_policy_fields_match_the_contract_revision() {
    assert_eq!(
        IPC_CONTRACT_REVISION, REVISION,
        "the revision moved: record its route-policy fields here"
    );
    assert_eq!(
        fields::<RoutePolicyUpdateRequest>(),
        REQUEST_FIELDS.into_iter().collect(),
        "the request fields changed: bump IPC_CONTRACT_REVISION and record the new set"
    );
    assert_eq!(
        fields::<RoutePolicyDto>(),
        SNAPSHOT_FIELDS.into_iter().collect(),
        "the snapshot fields changed: bump IPC_CONTRACT_REVISION and record the new set"
    );
}

#[test]
fn only_the_declared_keys_are_snapshot_only() {
    let request = fields::<RoutePolicyUpdateRequest>();
    let snapshot_only: BTreeSet<&str> = fields::<RoutePolicyDto>()
        .difference(&request)
        .copied()
        .collect();
    assert_eq!(
        snapshot_only,
        ROUTE_POLICY_SNAPSHOT_ONLY_KEYS.into_iter().collect()
    );
}

#[test]
fn the_window_speaks_the_same_revision() {
    let pure = include_str!("../../../apps/desktop/qml/lib/pure.js");
    let declared = format!("var WIRE_CONTRACT_REVISION = {IPC_CONTRACT_REVISION}");
    assert!(
        pure.contains(&declared),
        "pure.js must declare `{declared}`"
    );
}
