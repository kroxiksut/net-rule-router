use super::*;

const SID: &str = "S-1-5-21-1-2-3-1001";

fn server() -> [Ipv4Addr; 1] {
    [Ipv4Addr::new(203, 0, 113, 7)]
}

fn gateway() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20))
}

fn rule_host() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(192, 0, 2, 80))
}

/// What "everything" arms with the tunnel up, and with it gone.
fn blanket_postures() -> Vec<(&'static str, Vec<FlowRule>)> {
    let all = KillSwitchProtocols::ALL;
    vec![
        (
            "catch-all",
            plan_catch_all_kill_switch(SID, &server(), &[], Ipv6Exemptions::default(), all),
        ),
        (
            "block-all",
            plan_fail_closed_block_all(
                SID,
                &server(),
                &[],
                &[],
                &[],
                &[],
                Ipv6Exemptions::default(),
                false,
                &[],
                all,
            ),
        ),
    ]
}

/// What "sites" arms: the rule host pinned, or blocked with the tunnel gone.
fn site_postures() -> Vec<(&'static str, Vec<FlowRule>)> {
    let all = KillSwitchProtocols::ALL;
    vec![
        (
            "pins",
            plan_kill_switch_destinations(SID, &[rule_host()], all),
        ),
        (
            "fail-closed",
            plan_fail_closed_destinations(SID, &[rule_host()], all),
        ),
    ]
}

fn is_esp_anywhere(f: &FlowRule) -> bool {
    f.flow.protocol == Some(L4Proto::Esp)
        && f.flow.dst == DstMatch::Any
        && f.flow.dst_port.is_none()
}

#[test]
fn every_blanket_lets_esp_through_for_the_user() {
    for (name, flows) in blanket_postures() {
        let permits = plan_vpn_handshake_permits(SID, &flows, &[]);
        assert_eq!(permits.len(), 1, "{name}: {permits:?}");
        let esp = &permits[0];
        assert!(is_esp_anywhere(esp), "{name}");
        assert_eq!(esp.verdict, Verdict::Permit);
        assert_eq!(esp.principal, principal_scope(SID));
        assert_eq!(esp.app, AppScope::Any);
        assert_eq!(esp.egress, EgressConstraint::Any);
        // Above every class the posture blocks with, below the user's own
        // Blocks.
        assert!(flows
            .iter()
            .filter(|f| f.verdict == Verdict::Block)
            .all(|f| f.precedence.class.rank() < esp.precedence.class.rank()));
        assert!(esp.precedence.class.rank() < PrecedenceClass::HardBlock.rank());
    }
}

/// "Sites" cuts only rule hosts: a VPN's gateway is not one, and ESP to a
/// rule host stays held to the tunnel.
#[test]
fn the_per_destination_guard_spares_nothing() {
    for (name, flows) in site_postures() {
        assert!(
            plan_vpn_handshake_permits(SID, &flows, &[gateway()]).is_empty(),
            "{name}"
        );
    }
}

#[test]
fn nothing_is_spared_where_nothing_is_blocked() {
    assert!(plan_vpn_handshake_permits(SID, &[], &[gateway()]).is_empty());
    // Route rules alone are posture "off".
    let routed = vec![FlowRule {
        verdict: Verdict::Permit,
        precedence: Precedence {
            class: PrecedenceClass::RouteRule(RouteRole::Secondary),
            ordinal: 0,
        },
        flow: FlowMatch {
            dst: DstMatch::HostV4(Ipv4Addr::new(192, 0, 2, 80)),
            dst_port: None,
            protocol: None,
        },
        principal: principal_scope(SID),
        app: AppScope::Any,
        egress: EgressConstraint::Any,
        coverage: Coverage::ConnectOnly,
        observed_by_program: false,
    }];
    assert!(plan_vpn_handshake_permits(SID, &routed, &[gateway()]).is_empty());
    // The DoH lockdown blocks resolvers, never the main link.
    let doh = plan_doh_dot_block(SID, &[IpAddr::V4(Ipv4Addr::new(198, 51, 100, 53))], true);
    assert!(plan_vpn_handshake_permits(SID, &doh, &[gateway()]).is_empty());
    assert!(plan_ike_service_permits(&doh, IkeServiceMatch::AnyServiceProgram).is_empty());
    // Another user's blocks spare nothing of this one's.
    let other = plan_catch_all_kill_switch(
        "S-1-5-21-1-2-3-1002",
        &server(),
        &[],
        Ipv6Exemptions::default(),
        KillSwitchProtocols::ALL,
    );
    assert!(plan_vpn_handshake_permits(SID, &other, &[]).is_empty());
}

/// No TCP at all, and UDP only on the handshake ports to the confirmed
/// gateway: a rule host's HTTPS stays as cut as it was.
#[test]
fn nothing_opens_tcp_or_a_rule_hosts_other_ports() {
    for (name, flows) in blanket_postures() {
        let permits = plan_vpn_handshake_permits(SID, &flows, &[gateway()]);
        for f in &permits {
            assert_ne!(f.flow.protocol, Some(L4Proto::Tcp), "{name}: {f:?}");
            assert_ne!(f.flow.protocol, None, "{name}: a permit without a protocol");
            assert_ne!(f.flow.dst_port, Some(443), "{name}: {f:?}");
            if f.flow.protocol == Some(L4Proto::Udp) {
                assert_eq!(
                    f.flow.dst,
                    DstMatch::HostV4(Ipv4Addr::new(198, 51, 100, 20))
                );
                assert!(f
                    .flow
                    .dst_port
                    .is_some_and(|p| VPN_HANDSHAKE_UDP_PORTS.contains(&p)));
            } else {
                assert!(is_esp_anywhere(f), "{name}: {f:?}");
            }
            assert_ne!(f.flow.dst, host_match(rule_host()), "{name}: {f:?}");
        }
    }
}

/// A confirmed gateway is reachable on the handshake ports for its user;
/// taken back, it is not.
#[test]
fn a_confirmed_gateway_is_named_on_the_handshake_ports_and_only_while_confirmed() {
    let flows = &blanket_postures()[0].1;
    let confirmed = plan_vpn_handshake_permits(SID, flows, &[gateway(), gateway()]);
    let ports: Vec<u16> = confirmed
        .iter()
        .filter(|f| f.flow.dst == host_match(gateway()))
        .filter_map(|f| f.flow.dst_port)
        .collect();
    assert_eq!(
        ports,
        VPN_HANDSHAKE_UDP_PORTS.to_vec(),
        "once per port, deduplicated"
    );
    assert!(confirmed
        .iter()
        .all(|f| f.principal == principal_scope(SID)));
    let revoked = plan_vpn_handshake_permits(SID, flows, &[]);
    assert!(revoked.iter().all(|f| f.flow.dst != host_match(gateway())));
    // The machine's own upkeep is never a gateway.
    let local = plan_vpn_handshake_permits(SID, flows, &[IpAddr::V4(Ipv4Addr::LOCALHOST)]);
    assert_eq!(local.len(), 1);
}

#[test]
fn ike_passes_only_from_the_service_accounts() {
    let owner = &blanket_postures()[0].1;
    // The owner's own blanket says nothing about the service accounts.
    assert!(plan_ike_service_permits(owner, IkeServiceMatch::AnyServiceProgram).is_empty());

    let holds = NetworkHolds::default();
    let guard = service_account_guard(&ServiceAccountInput {
        is_route_table_owner: true,
        posture: Some(ServiceAccountPosture::Block),
        destinations: &[rule_host()],
        holds: &holds,
        tunnel_servers: &[],
        local_subnets: &[],
        primary_dns: &[],
    })
    .expect("owner with a guard");
    let service = plan_service_account_flows(SID, &guard, KillSwitchProtocols::ALL, &[]);

    let svchost = [r"C:\Windows\System32\svchost.exe".to_string()];
    for (ike, app) in [
        (
            IkeServiceMatch::Images(&svchost),
            AppScope::Program {
                key: IKE_SERVICE_KEY.to_owned(),
                exe_paths: vec![PathBuf::from(&svchost[0])],
            },
        ),
        (IkeServiceMatch::AnyServiceProgram, AppScope::Any),
    ] {
        let permits = plan_ike_service_permits(&service, ike);
        let mut ports: Vec<u16> = permits.iter().filter_map(|f| f.flow.dst_port).collect();
        ports.sort_unstable();
        assert_eq!(ports, vec![500, 500, 4500, 4500], "both families");
        for f in &permits {
            assert_eq!(f.principal, PrincipalScope::ServiceAccounts);
            assert_eq!(f.flow.protocol, Some(L4Proto::Udp));
            assert_eq!(f.app, app);
            assert_eq!(f.verdict, Verdict::Permit);
        }
    }
    assert!(
        plan_ike_service_permits(&service, IkeServiceMatch::Images(&[])).is_empty(),
        "an IKE service the OS could not name gets nothing"
    );
}

/// On Linux the user's share lowers to plain accepts ahead of the blanket
/// drop: ESP by protocol number, the gateway by address and port.
#[cfg(not(windows))]
#[test]
fn the_handshake_permits_lower_to_nftables_ahead_of_the_blanket() {
    use nrr_platform_api::enforcement::EnforcementPlan;
    use nrr_platform_linux::lower_linux::{lower_plan, EgressNames};

    let principal = nrr_platform_api::enforcement::UserPrincipal::from_linux_uid(1000);
    let sid = principal.as_stored().to_string();
    let mut flows = plan_catch_all_kill_switch(
        &sid,
        &server(),
        &[],
        Ipv6Exemptions::default(),
        KillSwitchProtocols::ALL,
    );
    let permits = plan_vpn_handshake_permits(&sid, &flows, &[gateway()]);
    assert!(!permits.is_empty());
    flows.extend(permits);
    let plan = EnforcementPlan {
        principal,
        flows,
        routes: Vec::new(),
        policy_rules: Vec::new(),
    };
    let lowered = lower_plan(
        &plan,
        &EgressNames {
            primary: Some("eth0".into()),
            secondary: Some("nrrtun0".into()),
        },
    );
    assert!(lowered.unsupported.is_empty(), "{:?}", lowered.unsupported);
    let script = lowered.ruleset.to_nft_script();
    let esp = script
        .find("meta skuid 1000 meta l4proto 50 accept")
        .unwrap_or_else(|| panic!("no ESP accept in\n{script}"));
    let ike = script
        .find("meta skuid 1000 ip daddr 198.51.100.20 meta l4proto 17 th dport 4500 accept")
        .unwrap_or_else(|| panic!("no gateway accept in\n{script}"));
    let blanket = script
        .find("comment \"catch-all-block#")
        .unwrap_or_else(|| panic!("no blanket drop in\n{script}"));
    assert!(esp < blanket && ike < blanket, "{script}");
    assert!(
        !script.contains("th dport 443 accept"),
        "nothing opens HTTPS: {script}"
    );
}
