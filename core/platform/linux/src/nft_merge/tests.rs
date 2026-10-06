use super::*;
use std::net::{Ipv4Addr, Ipv6Addr};

fn host(last: u8) -> NftMatch {
    NftMatch::DstV4 {
        net: Ipv4Addr::new(10, 0, 0, last),
        prefix: 32,
    }
}

fn net(last: u8, prefix: u8) -> NftMatch {
    NftMatch::DstV4 {
        net: Ipv4Addr::new(10, 0, 0, last),
        prefix,
    }
}

fn rule(matches: Vec<NftMatch>, verdict: NftVerdict, comment: &str) -> NftRule {
    NftRule {
        matches,
        verdict,
        comment: comment.into(),
    }
}

fn block(text: &str) -> IpBlock {
    IpBlock::parse(text).expect("block")
}

#[test]
fn rules_that_differ_only_in_the_address_become_one_set() {
    let rules = (1..=5)
        .map(|i| {
            rule(
                vec![NftMatch::SkUid(1000), host(i)],
                NftVerdict::Accept,
                "route-secondary#0",
            )
        })
        .collect();
    let folded = fold_into_sets(rules);
    assert_eq!(folded.len(), 1);
    assert_eq!(
        folded[0].matches,
        vec![
            NftMatch::SkUid(1000),
            NftMatch::DstSetV4((1..=5).map(|i| block(&format!("10.0.0.{i}/32"))).collect()),
        ]
    );
    assert_eq!(folded[0].comment, "route-secondary#0 +4");
}

#[test]
fn interleaved_pins_fold_into_one_permit_set_above_one_guard_set() {
    let mut rules = Vec::new();
    for i in 1..=3 {
        rules.push(rule(
            vec![host(i), NftMatch::OutInterface("wg0".into())],
            NftVerdict::Accept,
            "via",
        ));
        rules.push(rule(vec![host(i)], NftVerdict::Drop, "leak-guard"));
    }
    let folded = fold_into_sets(rules);
    assert_eq!(folded.len(), 2);
    assert_eq!(folded[0].verdict, NftVerdict::Accept);
    assert_eq!(folded[1].verdict, NftVerdict::Drop);
}

#[test]
fn a_rule_never_overtakes_one_that_decides_its_address_the_other_way() {
    let rules = vec![
        rule(vec![host(1)], NftVerdict::Accept, "a"),
        rule(vec![net(0, 24)], NftVerdict::Drop, "b"),
        rule(vec![host(2)], NftVerdict::Accept, "c"),
    ];
    let folded = fold_into_sets(rules.clone());
    assert_eq!(folded, rules, "10.0.0.2 is dropped and must stay dropped");
}

#[test]
fn a_block_another_in_the_set_covers_is_left_out() {
    let folded = fold_into_sets(vec![
        rule(vec![net(0, 24)], NftVerdict::Accept, "x#0"),
        rule(vec![host(5)], NftVerdict::Accept, "x#0"),
    ]);
    assert_eq!(folded.len(), 1);
    assert_eq!(folded[0].matches, vec![net(0, 24)]);
}

#[test]
fn a_rule_without_a_destination_holds_its_place() {
    let rules = vec![
        rule(vec![host(1)], NftVerdict::Drop, "a"),
        rule(vec![NftMatch::SkUid(1000)], NftVerdict::Accept, "b"),
        rule(vec![host(2)], NftVerdict::Drop, "c"),
    ];
    assert_eq!(fold_into_sets(rules.clone()), rules);
}

#[test]
fn bands_never_share_a_set() {
    let folded = fold_into_sets(vec![
        rule(vec![host(1)], NftVerdict::Accept, "route-primary#0"),
        rule(vec![host(2)], NftVerdict::Accept, "route-secondary#0"),
        rule(vec![host(3)], NftVerdict::Accept, "route-secondary#1"),
    ]);
    let comments: Vec<&str> = folded.iter().map(|r| r.comment.as_str()).collect();
    assert_eq!(comments, vec!["route-primary#0", "route-secondary#0 +1"]);
}

#[test]
fn the_families_never_share_a_set() {
    let v6 = NftMatch::DstV6 {
        net: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
        prefix: 128,
    };
    let folded = fold_into_sets(vec![
        rule(vec![host(1)], NftVerdict::Drop, "x#0"),
        rule(vec![v6], NftVerdict::Drop, "x#0"),
        rule(vec![host(2)], NftVerdict::Drop, "x#0"),
    ]);
    assert_eq!(folded.len(), 2);
}

// ── Folding never changes a verdict ─────────────────────────────────────────

struct Packet {
    uid: u32,
    dst: IpAddr,
    proto: u8,
    port: u16,
    oif: &'static str,
}

fn matches(m: &NftMatch, p: &Packet) -> bool {
    match m {
        NftMatch::DstV4 { net, prefix } => {
            IpBlock::new(IpAddr::V4(*net), *prefix).is_some_and(|b| b.contains(p.dst))
        }
        NftMatch::DstV6 { net, prefix } => {
            IpBlock::new(IpAddr::V6(*net), *prefix).is_some_and(|b| b.contains(p.dst))
        }
        NftMatch::DstSetV4(blocks) | NftMatch::DstSetV6(blocks) => {
            blocks.iter().any(|b| b.contains(p.dst))
        }
        NftMatch::Protocol(proto) => *proto == p.proto,
        NftMatch::DstPort(port) => *port == p.port,
        NftMatch::OutInterface(dev) => dev == p.oif,
        NftMatch::SkUid(uid) => *uid == p.uid,
    }
}

fn decide(rules: &[NftRule], p: &Packet) -> Option<NftVerdict> {
    rules
        .iter()
        .find(|r| r.matches.iter().all(|m| matches(m, p)))
        .map(|r| r.verdict)
}

/// A small deterministic generator: the property needs many chains, not a
/// dependency.
struct Lcg(u64);
impl Lcg {
    fn next(&mut self, below: u64) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (self.0 >> 33) % below
    }
}

fn random_rule(g: &mut Lcg) -> NftRule {
    let mut matches = Vec::new();
    if g.next(3) > 0 {
        matches.push(NftMatch::SkUid(1000 + g.next(2) as u32));
    }
    match g.next(10) {
        0 => {}
        1 => matches.push(NftMatch::DstV6 {
            net: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1 + g.next(3) as u16),
            prefix: 128,
        }),
        2 => matches.push(net(0, 29)),
        3 => matches.push(net(4, 30)),
        4 => matches.push(net(0, 24)),
        _ => matches.push(host(1 + g.next(8) as u8)),
    }
    if g.next(4) == 0 {
        matches.push(NftMatch::Protocol(if g.next(2) == 0 { 6 } else { 17 }));
        matches.push(NftMatch::DstPort(443));
    }
    if g.next(3) == 0 {
        matches.push(NftMatch::OutInterface("wg0".into()));
    }
    let verdict = if g.next(2) == 0 {
        NftVerdict::Accept
    } else {
        NftVerdict::Drop
    };
    // Two bands, so the property also covers rules a band keeps apart.
    rule(matches, verdict, if g.next(2) == 0 { "a#1" } else { "b#1" })
}

#[test]
fn folding_never_changes_the_verdict_of_any_packet() {
    let mut g = Lcg(0x5eed);
    let dsts: Vec<IpAddr> = (0..=9)
        .map(|i| IpAddr::V4(Ipv4Addr::new(10, 0, 0, i)))
        .chain((1..=3).map(|i| IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, i))))
        .collect();
    for _ in 0..600 {
        let len = 1 + g.next(30) as usize;
        let rules: Vec<NftRule> = (0..len).map(|_| random_rule(&mut g)).collect();
        let folded = fold_into_sets(rules.clone());
        assert!(folded.len() <= rules.len());
        for &dst in &dsts {
            for uid in [1000, 1001] {
                for proto in [6, 17] {
                    for port in [443, 80] {
                        for oif in ["wg0", "wlp"] {
                            let p = Packet {
                                uid,
                                dst,
                                proto,
                                port,
                                oif,
                            };
                            assert_eq!(
                                decide(&rules, &p),
                                decide(&folded, &p),
                                "{dst} uid {uid} proto {proto} port {port} oif {oif}\n\
                                 before: {rules:#?}\nafter: {folded:#?}"
                            );
                        }
                    }
                }
            }
        }
    }
}
