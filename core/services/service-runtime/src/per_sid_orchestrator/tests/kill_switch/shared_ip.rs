use super::*;

fn shared_addresses() -> [IpAddr; 2] {
    [
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 51)),
        "2001:db8:2::51".parse().expect("test address"),
    ]
}

fn withdrawn_observations() -> Arc<crate::app_observation_lookup::AppObservationStore> {
    let observations = Arc::new(crate::app_observation_lookup::AppObservationStore::new());
    for address in shared_addresses() {
        assert!(observations.record(PINNED_APP, address));
        assert!(observations.retract("tg.exe", address));
    }
    observations
}

fn secondary_app_book() -> CanonicalRuleBook {
    let mut book = rules_with_one_app("tg.exe").rule_book;
    std::mem::swap(&mut book.primary, &mut book.secondary);
    book
}

// Evaluate the generated ALE filters for a new TCP/UDP flow, including explicit exceptions.
fn may_send(
    filters: &[WfpFilterSpec],
    program: &str,
    address: IpAddr,
    protocol: u8,
    egress: u64,
) -> bool {
    let layer = if address.is_ipv4() {
        WfpLayerKey::AleAuthConnectV4
    } else {
        WfpLayerKey::AleAuthConnectV6
    };
    filters
        .iter()
        .filter(|f| f.layer == layer)
        .filter(|f| f.user_sid.as_deref().is_none_or(|sid| sid == "S-1-5-21-A"))
        .filter(|f| f.app_pattern.as_deref().is_none_or(|app| app == program))
        .filter(|f| f.local_interface_luid.is_none_or(|luid| luid == egress))
        .filter(|f| f.ip_protocol.is_none_or(|value| value == protocol))
        .filter(|f| f.remote_port.is_none_or(|port| port == 3478))
        .filter(|f| {
            if !f.names_a_destination() {
                return true;
            }
            match address {
                IpAddr::V4(ip) => {
                    f.covers_v4(ip) || f.remote_subnet.is_some_and(|subnet| in_subnet(ip, subnet))
                }
                IpAddr::V6(ip) => {
                    f.covers_v6(ip)
                        || f.remote_subnet_v6.is_some_and(|(net, prefix)| {
                            nrr_shared::ip_block::IpBlock::new(IpAddr::V6(net), prefix)
                                .is_some_and(|block| block.contains(address))
                        })
                }
            }
        })
        .max_by_key(|f| (f.weight, f.action == WfpAction::Block))
        .is_none_or(|f| f.action == WfpAction::Permit)
}

#[test]
fn strict_withdrawn_shared_ip_cannot_escape_to_primary() {
    use crate::enforcement_planner::Ipv6Guard;

    let mut escaped = Vec::new();
    for ipv6 in [Ipv6Guard::Off, Ipv6Guard::FiltersAndRoutes] {
        for takeover in [false, true] {
            let policy = PerSidPolicySnapshot {
                kill_switch_strict_shared_ips: true,
                app_rules_take_all_addresses: takeover,
                ..snap_block("Wi-Fi", "TAP")
            };
            let filters = filters_observing_ipv6(
                policy,
                full_ks_resolution(),
                secondary_app_book(),
                withdrawn_observations(),
                ipv6,
            );
            for address in shared_addresses() {
                for protocol in [17, 6] {
                    if may_send(&filters, PINNED_APP, address, protocol, PRIMARY_LUID) {
                        escaped.push((address, protocol, takeover, ipv6));
                    }
                    assert!(
                        may_send(&filters, PINNED_APP, address, protocol, KS_LUID),
                        "the selected route must remain permitted: {address}, protocol {protocol}"
                    );
                    assert!(
                    may_send(
                        &filters,
                        r"C:\Apps\other.exe",
                        address,
                        protocol,
                        PRIMARY_LUID
                    ),
                    "holding the routed app must not block another program on the shared address"
                );
                }
            }
        }
    }
    assert!(
        escaped.is_empty(),
        "strict protection allowed a withdrawn shared address on Primary: {escaped:?}"
    );
}

#[test]
fn explicit_primary_rule_survives_strict_app_withdrawal() {
    let mut book = secondary_app_book();
    book.primary = CanonicalRuleSet::from_rules(
        shared_addresses()
            .into_iter()
            .enumerate()
            .map(|(index, address)| CanonicalRule {
                id: RuleId(format!("explicit-main-{index}")),
                enabled: true,
                address_match: Some(CanonicalAddressMatch::ExactIp(address)),
                app_match: None,
                comment: String::new(),
                action: nrr_domain::RuleAction::Route,
                origin: None,
            })
            .collect(),
    );
    let filters = filters_observing_ipv6(
        snap_block("Wi-Fi", "TAP"),
        full_ks_resolution(),
        book,
        withdrawn_observations(),
        crate::enforcement_planner::Ipv6Guard::FiltersAndRoutes,
    );
    for address in shared_addresses() {
        for protocol in [17, 6] {
            assert!(
                may_send(&filters, PINNED_APP, address, protocol, PRIMARY_LUID),
                "explicit Primary must beat an application rule: {address}, protocol {protocol}"
            );
        }
    }
}
