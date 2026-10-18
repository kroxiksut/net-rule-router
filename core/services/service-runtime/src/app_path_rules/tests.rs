use std::path::PathBuf;

use nrr_domain::protected_places::{ProtectedPlaces, ProtectionReason, RuleEffect};
use nrr_domain::rules_file::HostPlatform;
use nrr_platform_api::app_folders::{AppPath, PathOutcome, PathPrograms, PathStyle};
use nrr_platform_api::MockAppPathResolver;

use super::path_rule_targets;
use crate::address_ownership::{AddressOwnership, AppDestinationGate};
use crate::app_observation_lookup::{AppObservationLookup, AppObservationStore};

fn found(place: &AppPath, programs: &[&str]) -> PathPrograms {
    PathPrograms {
        outcome: PathOutcome::Found,
        place: Some(place.clone()),
        programs: programs.iter().map(PathBuf::from).collect(),
        over_cap: false,
    }
}

fn targets(
    rule: &AppPath,
    owner: &str,
    effect: RuleEffect,
    resolver: &MockAppPathResolver,
    store: &AppObservationStore,
    places: &ProtectedPlaces,
) -> super::PathRuleTargets {
    let ownership = AddressOwnership::default();
    let gate = AppDestinationGate::for_rule_set(&ownership, store, &Default::default());
    path_rule_targets(rule, owner, effect, resolver, &gate, places)
}

/// The rules file names a harmless folder; the disk says it is a link into a
/// system one. The real place decides, so the deny is not applied.
#[test]
fn a_link_into_a_system_folder_is_refused_by_where_it_really_leads() {
    let rule = AppPath::parse("/opt/tools/*", PathStyle::Linux).expect("rule");
    let real = rule.on_disk("/usr/bin", true).expect("real");
    let resolver = MockAppPathResolver::new().with_path_programs(
        rule.as_str(),
        "*",
        found(&real, &["/usr/bin/curl"]),
    );
    let store = AppObservationStore::new().with_path_style(PathStyle::Linux);
    let places = ProtectedPlaces::defaults(HostPlatform::Linux);
    let denied = targets(
        &rule,
        "uid:1000",
        RuleEffect::Deny,
        &resolver,
        &store,
        &places,
    );
    assert_eq!(denied.refused, Some(ProtectionReason::SystemFolder));
    assert!(denied.programs.is_empty());
    // The main route is the way every program goes anyway: nothing to refuse.
    let main = targets(
        &rule,
        "uid:1000",
        RuleEffect::PrimaryRoute,
        &resolver,
        &store,
        &places,
    );
    assert_eq!(main.refused, None);
    assert_eq!(main.programs, vec![PathBuf::from("/usr/bin/curl")]);
}

#[test]
fn a_windows_junction_into_the_system_folder_is_refused_too() {
    let rule = AppPath::parse(r"C:\Tools\*", PathStyle::Windows).expect("rule");
    let real = rule.on_disk(r"C:\Windows\System32", true).expect("real");
    let resolver = MockAppPathResolver::new().with_path_programs(
        rule.as_str(),
        "*",
        found(&real, &[r"C:\Windows\System32\curl.exe"]),
    );
    let store = AppObservationStore::new().with_path_style(PathStyle::Windows);
    let places = ProtectedPlaces::defaults(HostPlatform::Windows);
    let routed = targets(
        &rule,
        "S-1-5-21-1",
        RuleEffect::SecondaryRoute,
        &resolver,
        &store,
        &places,
    );
    assert!(routed.refused.is_some(), "{routed:?}");
    assert!(routed.programs.is_empty());
}

/// One user's rule covers that user's programs only: another owner of the
/// same rule text gets what the platform answers for them — here, nothing.
#[test]
fn the_answer_is_the_owners_own() {
    let rule = AppPath::parse("/home/a/apps/*", PathStyle::Linux).expect("rule");
    let resolver = MockAppPathResolver::new().with_path_programs(
        rule.as_str(),
        "uid:1000",
        found(&rule, &["/home/a/apps/tool"]),
    );
    let store = AppObservationStore::new().with_path_style(PathStyle::Linux);
    let places = ProtectedPlaces::defaults(HostPlatform::Linux);
    let own = targets(
        &rule,
        "uid:1000",
        RuleEffect::SecondaryRoute,
        &resolver,
        &store,
        &places,
    );
    assert_eq!(own.programs, vec![PathBuf::from("/home/a/apps/tool")]);
    let other = targets(
        &rule,
        "uid:1001",
        RuleEffect::SecondaryRoute,
        &resolver,
        &store,
        &places,
    );
    assert_eq!(other.outcome, PathOutcome::Missing);
    assert!(other.programs.is_empty());
}

/// The real place reaches the observations: a program the kernel reports at
/// the link's target is counted for the rule spelled with the link.
#[test]
fn the_real_place_teaches_the_observations() {
    let rule = AppPath::parse("/opt/link/*", PathStyle::Linux).expect("rule");
    let real = rule.on_disk("/data/app", true).expect("real");
    let resolver = MockAppPathResolver::new().with_path_programs(
        rule.as_str(),
        "*",
        found(&real, &["/data/app/bin/tool"]),
    );
    let store = AppObservationStore::new().with_path_style(PathStyle::Linux);
    let places = ProtectedPlaces::defaults(HostPlatform::Linux);
    // A plan asks first, then a connection from the real place arrives.
    assert!(store.ips_for_app(rule.as_str()).is_empty());
    let answer = targets(
        &rule,
        "uid:1000",
        RuleEffect::SecondaryRoute,
        &resolver,
        &store,
        &places,
    );
    assert_eq!(answer.key, rule.as_str());
    let ip = std::net::Ipv4Addr::new(203, 0, 113, 40);
    store.record("/data/app/bin/tool", ip);
    assert_eq!(store.ips_for_app(rule.as_str()), vec![ip]);
}
