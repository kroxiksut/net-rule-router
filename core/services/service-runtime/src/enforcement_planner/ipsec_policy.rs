//! What a blanket block leaves to a policy-based IPsec VPN.
//!
//! strongSwan and libreswan without a tunnel interface send the inner traffic
//! out the main link and encrypt it after the filter has judged it, so the
//! catch-all would cut the corporate networks of a VPN that connected fine.
//! The permit matches only what the kernel will encrypt under a policy, and
//! only to private destinations: a policy that takes the whole internet keeps
//! the company's own networks, and the rest waits for our tunnel, as a foreign
//! tunnel interface does. The user's own hard blocks stay above it.

use super::*;

/// First ordinal of these permits in the exemption band, past the handshake
/// permits so the two never share a slot.
pub const IPSEC_POLICY_ORDINAL_BASE: u32 = 0x0019_0000;

/// The permits for `sid`, one per private network. Empty unless `flows` hold
/// the user's blanket block: under the per-destination guard nothing outside
/// the rule hosts is cut, and with protection off nothing is.
#[must_use]
pub fn plan_ipsec_policy_permits(sid: &str, flows: &[FlowRule]) -> Vec<FlowRule> {
    let principal = principal_scope(sid);
    let blanket = flows.iter().any(|f| {
        f.principal == principal
            && f.verdict == Verdict::Block
            && f.precedence.class == PrecedenceClass::CatchAllBlock
    });
    if !blanket {
        return Vec::new();
    }
    nrr_domain::ip_network_policy::private_networks()
        .enumerate()
        .map(|(n, net)| {
            let dst = match net.network() {
                IpAddr::V4(addr) => DstMatch::SubnetV4 {
                    net: addr,
                    prefix: net.prefix_len(),
                },
                IpAddr::V6(addr) => DstMatch::SubnetV6 {
                    net: addr,
                    prefix: net.prefix_len(),
                },
            };
            catch_all_flow(
                &principal,
                Verdict::Permit,
                PrecedenceClass::CatchAllExempt,
                dst,
                EgressConstraint::UnderIpsecPolicy,
                None,
                Coverage::AllPackets,
                IPSEC_POLICY_ORDINAL_BASE + n as u32,
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SID: &str = "1000";

    fn block(class: PrecedenceClass) -> FlowRule {
        catch_all_flow(
            &principal_scope(SID),
            Verdict::Block,
            class,
            DstMatch::Any,
            EgressConstraint::Any,
            None,
            Coverage::AllPackets,
            0,
        )
    }

    #[test]
    fn a_blanket_block_spares_ipsec_traffic_to_private_networks_only() {
        let permits = plan_ipsec_policy_permits(SID, &[block(PrecedenceClass::CatchAllBlock)]);
        assert!(!permits.is_empty());
        for p in &permits {
            assert_eq!(p.verdict, Verdict::Permit);
            assert_eq!(p.precedence.class, PrecedenceClass::CatchAllExempt);
            assert_eq!(p.egress, EgressConstraint::UnderIpsecPolicy);
            assert_eq!(p.principal, principal_scope(SID));
            let net = match p.flow.dst {
                DstMatch::SubnetV4 { net, prefix } => {
                    nrr_shared::ip_block::IpBlock::new(IpAddr::V4(net), prefix)
                }
                DstMatch::SubnetV6 { net, prefix } => {
                    nrr_shared::ip_block::IpBlock::new(IpAddr::V6(net), prefix)
                }
                other => panic!("not a network: {other:?}"),
            }
            .expect("a valid block");
            assert!(nrr_domain::ip_network_policy::is_private(net), "{net}");
        }
        assert!(permits.iter().any(|p| p.flow.dst
            == DstMatch::SubnetV4 {
                net: Ipv4Addr::new(10, 0, 0, 0),
                prefix: 8
            }));
    }

    /// The DoH/DoT lockdown is the user's own: a resolver inside the IPsec
    /// networks is not exempt from it.
    #[test]
    fn the_lockdown_is_restated_for_the_ipsec_traffic_it_spares() {
        let mut flows = vec![block(PrecedenceClass::CatchAllBlock)];
        flows.extend(plan_ipsec_policy_permits(SID, &flows));
        let doh = plan_doh_dot_block(SID, &[IpAddr::V4(Ipv4Addr::new(10, 1, 1, 1))], true);
        let vetoes = plan_doh_foreign_vetoes(SID, &doh, &flows);
        let lockdown = doh
            .iter()
            .filter(|f| {
                f.verdict == Verdict::Block && f.precedence.class == PrecedenceClass::DohBlock
            })
            .count();
        assert!(lockdown > 0, "fixture: the lockdown blocks");
        assert_eq!(vetoes.len(), lockdown);
        for veto in &vetoes {
            assert_eq!(veto.verdict, Verdict::Block);
            assert_eq!(veto.precedence.class, PrecedenceClass::HardBlock);
            assert_eq!(veto.egress, EgressConstraint::UnderIpsecPolicy);
        }
        assert!(
            plan_doh_foreign_vetoes(SID, &doh, &[block(PrecedenceClass::CatchAllBlock)]).is_empty(),
            "nothing spared, nothing to restate"
        );
    }

    #[test]
    fn without_a_blanket_block_nothing_is_spared() {
        assert!(plan_ipsec_policy_permits(SID, &[]).is_empty());
        assert!(
            plan_ipsec_policy_permits(SID, &[block(PrecedenceClass::KillSwitchBlock)]).is_empty(),
            "the per-destination guard cuts only rule hosts"
        );
        assert!(
            plan_ipsec_policy_permits("1001", &[block(PrecedenceClass::CatchAllBlock)]).is_empty(),
            "another user's block is not this user's"
        );
    }
}
