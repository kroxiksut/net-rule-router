use super::*;

fn net(text: &str) -> IpBlock {
    IpBlock::parse(text).expect("block")
}

fn addr(text: &str) -> IpAddr {
    text.parse().expect("address")
}

fn holds(
    additional: &[&str],
    main: &[&str],
    main_addresses: &[&str],
    pinned: &[&str],
    never_block: &[&str],
) -> NetworkHolds {
    let additional: Vec<IpBlock> = additional.iter().map(|t| net(t)).collect();
    let main: Vec<IpBlock> = main.iter().map(|t| net(t)).collect();
    let main_addresses: Vec<IpAddr> = main_addresses.iter().map(|t| addr(t)).collect();
    let pinned: Vec<IpAddr> = pinned.iter().map(|t| addr(t)).collect();
    let never_block: Vec<IpBlock> = never_block.iter().map(|t| net(t)).collect();
    NetworkHolds::compute(&NetworkHoldInput {
        additional_networks: &additional,
        main_networks: &main,
        main_addresses: &main_addresses,
        pinned: &pinned,
        never_block: &never_block,
    })
}

fn blocks(list: &[&str]) -> Vec<IpBlock> {
    list.iter().map(|t| net(t)).collect()
}

/// Whether `ip` ends up blocked: inside a hold and inside no cut-out.
fn blocked(h: &NetworkHolds, ip: &str) -> bool {
    let ip = addr(ip);
    h.held.iter().any(|b| b.contains(ip)) && !h.cut_outs.iter().any(|b| b.contains(ip))
}

#[test]
fn each_family_holds_up_to_its_own_boundary() {
    let h = holds(&["10.20.0.0/16", "10.30.0.0/15"], &[], &[], &[], &[]);
    assert_eq!(h.held, blocks(&["10.20.0.0/16"]));
    assert_eq!(h.too_wide, blocks(&["10.30.0.0/15"]));
    let v6 = holds(&["2001:db8:1::/48", "2001:db8:2::/47"], &[], &[], &[], &[]);
    assert_eq!(v6.held, blocks(&["2001:db8:1::/48"]));
    assert_eq!(v6.too_wide, blocks(&["2001:db8:2::/47"]));
}

#[test]
fn a_range_is_judged_block_by_block() {
    // 10.0.0.0-10.2.255.255 decomposes into a /15 and a /16.
    let range = nrr_shared::ip_block::IpRange::parse("10.0.0.0-10.2.255.255").expect("range");
    let networks = range.blocks().to_vec();
    let h = NetworkHolds::compute(&NetworkHoldInput {
        additional_networks: &networks,
        ..NetworkHoldInput::default()
    });
    assert_eq!(h.held, blocks(&["10.2.0.0/16"]));
    assert_eq!(h.too_wide, blocks(&["10.0.0.0/15"]));
}

#[test]
fn main_link_rules_inside_a_held_network_stay_open() {
    let h = holds(
        &["10.20.0.0/16"],
        &["10.20.5.0/24"],
        &["10.20.9.9"],
        &[],
        &[],
    );
    assert_eq!(h.held, blocks(&["10.20.0.0/16"]));
    assert_eq!(h.cut_outs, blocks(&["10.20.5.0/24", "10.20.9.9/32"]));
    assert!(blocked(&h, "10.20.1.1"));
    assert!(!blocked(&h, "10.20.5.77"));
    assert!(!blocked(&h, "10.20.9.9"));
}

#[test]
fn a_narrower_additional_rule_inside_a_main_cut_out_is_still_held() {
    // 10.20.0.0/16 additional > 10.20.5.0/24 main > 10.20.5.0/28 additional,
    // 10.20.5.200 additional (pinned) > 10.20.5.3 main.
    let h = holds(
        &["10.20.0.0/16", "10.20.5.0/28"],
        &["10.20.5.0/24"],
        &["10.20.5.3"],
        &["10.20.5.200"],
        &[],
    );
    assert_eq!(
        h.held,
        blocks(&["10.20.0.0/16"]),
        "the nested hold is redundant"
    );
    assert!(blocked(&h, "10.20.5.1"), "the /28 inside the main /24");
    assert!(blocked(&h, "10.20.5.200"), "the pinned address inside it");
    assert!(!blocked(&h, "10.20.5.3"), "the main address inside the /28");
    assert!(!blocked(&h, "10.20.5.100"));
    assert!(!blocked(&h, "10.20.5.201"));
    // Split around two holes: never one block per address.
    assert!(h.cut_outs.len() <= 2 * 8 + 1, "{:?}", h.cut_outs);
}

#[test]
fn a_main_network_wider_than_the_hold_is_not_a_cut_out() {
    let h = holds(&["10.20.0.0/16"], &["10.0.0.0/8"], &[], &[], &[]);
    assert_eq!(h.held, blocks(&["10.20.0.0/16"]));
    assert!(h.cut_outs.is_empty());
}

#[test]
fn the_same_network_on_both_links_goes_to_the_main_one() {
    let h = holds(&["10.20.0.0/16"], &["10.20.0.0/16"], &[], &[], &[]);
    assert!(h.held.is_empty());
    assert_eq!(h.spared, blocks(&["10.20.0.0/16"]));
}

#[test]
fn the_tunnel_server_and_a_lan_are_never_held() {
    let h = holds(
        &["198.51.0.0/16", "192.168.1.0/28"],
        &[],
        &[],
        &[],
        &["198.51.100.9/32", "198.51.7.0/24", "192.168.1.0/24"],
    );
    assert_eq!(h.held, blocks(&["198.51.0.0/16"]));
    assert_eq!(
        h.spared,
        blocks(&["192.168.1.0/28"]),
        "inside an attached LAN"
    );
    assert!(!blocked(&h, "198.51.100.9"));
    assert!(!blocked(&h, "198.51.7.40"));
    assert!(blocked(&h, "198.51.100.10"));
}

#[test]
fn an_exemption_is_not_split_around_an_additional_destination() {
    let h = holds(
        &["198.51.0.0/16"],
        &[],
        &[],
        &["198.51.7.5"],
        &["198.51.7.0/24"],
    );
    assert!(!blocked(&h, "198.51.7.5"), "the LAN wins over a pin");
}

#[test]
fn reserved_and_link_local_networks_are_never_held() {
    let h = holds(&["169.254.0.0/16", "fe80::/64"], &[], &[], &[], &[]);
    assert!(h.held.is_empty());
    assert_eq!(h.spared.len(), 2);
}

#[test]
fn ipv6_holds_and_cut_outs_follow_the_same_rules() {
    let h = holds(
        &["2001:db8::/48"],
        &["2001:db8:0:5::/64"],
        &["2001:db8:0:9::1"],
        &[],
        &[],
    );
    assert_eq!(h.held, blocks(&["2001:db8::/48"]));
    assert!(blocked(&h, "2001:db8:0:1::1"));
    assert!(!blocked(&h, "2001:db8:0:5::1"));
    assert!(!blocked(&h, "2001:db8:0:9::1"));
}

#[test]
fn addresses_outside_every_hold_are_not_cut_outs() {
    let h = holds(
        &["10.20.0.0/16"],
        &["192.0.2.0/24"],
        &["203.0.113.5"],
        &[],
        &[],
    );
    assert!(h.cut_outs.is_empty());
}

#[test]
fn a_hold_whose_cut_outs_pass_the_cap_is_not_armed() {
    let main: Vec<IpAddr> = (0..=u16::MAX)
        .map(|n| IpAddr::V4(std::net::Ipv4Addr::new(10, 20, (n >> 8) as u8, n as u8)))
        .chain(std::iter::once(addr("10.21.0.1")))
        .collect();
    let additional = blocks(&["10.20.0.0/16", "10.21.0.0/16"]);
    let h = NetworkHolds::compute(&NetworkHoldInput {
        additional_networks: &additional,
        main_addresses: &main,
        ..NetworkHoldInput::default()
    });
    // The first hold fills the cap exactly; the second would pass it.
    assert_eq!(h.held, blocks(&["10.20.0.0/16"]));
    assert_eq!(h.cut_outs.len(), NETWORK_CUT_OUT_MAX);
    assert_eq!(h.over_cap, blocks(&["10.21.0.0/16"]));
}

#[test]
fn the_result_does_not_depend_on_input_order() {
    let a = holds(
        &["10.20.0.0/16", "2001:db8::/48", "10.30.0.0/16"],
        &["10.30.4.0/24", "10.20.5.0/24"],
        &["10.20.9.9", "10.30.1.1"],
        &[],
        &[],
    );
    let b = holds(
        &["10.30.0.0/16", "2001:db8::/48", "10.20.0.0/16"],
        &["10.20.5.0/24", "10.30.4.0/24"],
        &["10.30.1.1", "10.20.9.9"],
        &[],
        &[],
    );
    assert_eq!(a, b);
    assert!(a.held[0].is_ipv4() && !a.held[2].is_ipv4(), "IPv4 first");
}
