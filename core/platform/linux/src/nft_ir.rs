//! The nftables intermediate representation the Linux lowering produces.
//!
//! This is deliberately OUR type, not the `nftables` crate's JSON schema. Two
//! mechanisms will render it: today `nft --json` through that crate, later a
//! direct-netlink crate of our own. Both are renderers of the same IR, so
//! swapping them cannot change what gets enforced — only how it is delivered.
//!
//! The IR is also the whole reason the interesting half of this port is
//! testable on a Windows dev host: building it needs no kernel, no root and no
//! `nft` binary.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use nrr_shared::ip_block::IpBlock;

/// Address family of a table. `Inet` sees both IPv4 and IPv6 in one table,
/// which is what the neutral plan wants: rules are written per destination
/// family, not per table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NftFamily {
    Inet,
}

impl fmt::Display for NftFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inet => write!(f, "inet"),
        }
    }
}

/// What a matched packet is done with. `Accept` and `Drop` are terminal —
/// evaluation of the chain stops — which is exactly how the first-match
/// ordering realises the arbitration WFP expresses with weights.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NftVerdict {
    Accept,
    Drop,
}

impl fmt::Display for NftVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Accept => write!(f, "accept"),
            Self::Drop => write!(f, "drop"),
        }
    }
}

/// One match condition. A rule's conditions are ANDed, mirroring how a WFP
/// filter ANDs its conditions.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum NftMatch {
    /// `ip daddr <addr>/<prefix>` — a v4 destination host or subnet.
    DstV4 { net: Ipv4Addr, prefix: u8 },
    /// `ip6 daddr <addr>/<prefix>` — a v6 destination host or subnet.
    DstV6 { net: Ipv6Addr, prefix: u8 },
    /// `ip daddr { a, b/p, … }` — several v4 destinations answered by one set
    /// lookup instead of one rule each. Disjoint, sorted blocks.
    DstSetV4(Vec<IpBlock>),
    /// `ip6 daddr { … }`, the v6 twin.
    DstSetV6(Vec<IpBlock>),
    /// `meta l4proto <proto>` — by IANA protocol number, so protocols without a
    /// keyword still express.
    Protocol(u8),
    /// `th dport <port>` — transport destination port.
    DstPort(u16),
    /// `oifname "<dev>"` — the egress interface, by name.
    OutInterface(String),
    /// `meta skuid <uid>` — the owning user. This is the per-user match Windows
    /// cannot do at the filter layer; on Linux it is one condition.
    SkUid(u32),
}

/// A single rule in the output chain, in evaluation order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NftRule {
    /// ANDed conditions; empty means "every packet".
    pub matches: Vec<NftMatch>,
    pub verdict: NftVerdict,
    /// Human-readable provenance, rendered as a rule comment. Carries the
    /// precedence band it came from so a live ruleset can be read back against
    /// the plan that produced it.
    pub comment: String,
}

/// Priority of our output chain: `filter - 10`, ahead of ufw and Docker
/// (iptables, `filter`) and firewalld (`filter + 10`); at an equal priority the
/// order is undefined. Still after `dstnat` (-100), so the destination matched
/// is the one NAT already rewrote.
pub const NRR_CHAIN_PRIORITY: i32 = -10;

/// The full ruleset for one principal: one table, one chain, rules in order.
///
/// The chain's `policy` is deliberately `accept`: this product routes traffic,
/// it is not a firewall, so anything the plan does not speak about must be left
/// alone. Blocking is always an explicit rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NftRuleset {
    pub family: NftFamily,
    pub table: String,
    pub chain: String,
    pub rules: Vec<NftRule>,
}

impl NftRuleset {
    /// Render as `nft` script lines — the form a human reads in a bug report,
    /// and what the tests assert against. Not the apply path: applying goes
    /// through the JSON API so errors come back structured.
    pub fn to_nft_script(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "table {} {} {{\n  chain {} {{\n    type filter hook output priority {}; policy accept;\n",
            self.family, self.table, self.chain, NRR_CHAIN_PRIORITY
        ));
        for rule in &self.rules {
            out.push_str("    ");
            for m in &rule.matches {
                out.push_str(&render_match(m));
                out.push(' ');
            }
            out.push_str(&rule.verdict.to_string());
            if !rule.comment.is_empty() {
                out.push_str(&format!(" comment \"{}\"", rule.comment.replace('"', "'")));
            }
            out.push('\n');
        }
        out.push_str("  }\n}\n");
        out
    }
}

fn render_match(m: &NftMatch) -> String {
    match m {
        NftMatch::DstV4 { net, prefix } => {
            if *prefix == 32 {
                format!("ip daddr {net}")
            } else {
                format!("ip daddr {net}/{prefix}")
            }
        }
        NftMatch::DstV6 { net, prefix } => {
            if *prefix == 128 {
                format!("ip6 daddr {net}")
            } else {
                format!("ip6 daddr {net}/{prefix}")
            }
        }
        NftMatch::DstSetV4(blocks) => format!("ip daddr {{ {} }}", set_items(blocks)),
        NftMatch::DstSetV6(blocks) => format!("ip6 daddr {{ {} }}", set_items(blocks)),
        NftMatch::Protocol(proto) => format!("meta l4proto {proto}"),
        NftMatch::DstPort(port) => format!("th dport {port}"),
        NftMatch::OutInterface(dev) => format!("oifname \"{dev}\""),
        NftMatch::SkUid(uid) => format!("meta skuid {uid}"),
    }
}

fn set_items(blocks: &[IpBlock]) -> String {
    blocks
        .iter()
        .map(|b| {
            if b.is_single_address() {
                b.network().to_string()
            } else {
                b.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_set_renders_hosts_bare_and_networks_with_their_prefix() {
        let blocks = vec![
            IpBlock::parse("10.0.0.0/8").expect("net"),
            IpBlock::parse("192.0.2.4/32").expect("host"),
        ];
        assert_eq!(
            render_match(&NftMatch::DstSetV4(blocks)),
            "ip daddr { 10.0.0.0/8, 192.0.2.4 }"
        );
    }

    #[test]
    fn a_host_match_renders_without_a_redundant_prefix() {
        let m = NftMatch::DstV4 {
            net: Ipv4Addr::new(203, 0, 113, 138),
            prefix: 32,
        };
        assert_eq!(render_match(&m), "ip daddr 203.0.113.138");
    }

    #[test]
    fn a_subnet_match_keeps_its_prefix() {
        let m = NftMatch::DstV4 {
            net: Ipv4Addr::new(10, 0, 0, 0),
            prefix: 8,
        };
        assert_eq!(render_match(&m), "ip daddr 10.0.0.0/8");
    }

    #[test]
    fn the_chain_never_defaults_to_dropping() {
        // The product routes traffic; it does not firewall the machine. A
        // `policy drop` here would cut every flow the plan says nothing about.
        let ruleset = NftRuleset {
            family: NftFamily::Inet,
            table: "nrr".into(),
            chain: "output".into(),
            rules: Vec::new(),
        };
        let script = ruleset.to_nft_script();
        assert!(script.contains("policy accept;"), "{script}");
        assert!(!script.contains("policy drop"), "{script}");
    }

    #[test]
    fn a_rule_renders_its_conditions_then_its_verdict() {
        let ruleset = NftRuleset {
            family: NftFamily::Inet,
            table: "nrr".into(),
            chain: "output".into(),
            rules: vec![NftRule {
                matches: vec![
                    NftMatch::SkUid(1000),
                    NftMatch::DstV4 {
                        net: Ipv4Addr::new(192, 0, 2, 4),
                        prefix: 32,
                    },
                    NftMatch::OutInterface("tun0".into()),
                ],
                verdict: NftVerdict::Accept,
                comment: "route-rule/secondary#0".into(),
            }],
        };
        let script = ruleset.to_nft_script();
        assert!(
            script.contains(
                "meta skuid 1000 ip daddr 192.0.2.4 oifname \"tun0\" accept comment \"route-rule/secondary#0\""
            ),
            "{script}"
        );
    }
}
