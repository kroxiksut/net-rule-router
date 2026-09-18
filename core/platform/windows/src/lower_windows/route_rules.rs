// Address-match route rules lowered to WFP filters.

use super::*;

/// Lower the address-match route rules of `plan` to WFP filters.
///
/// Handles [`PrecedenceClass::RouteRule`] permits and
/// [`PrecedenceClass::HardBlock`] blocks matching a
/// [`DstMatch::HostV4`]; other flows are handled by other lowering functions
/// and are skipped here.
/// The weight is `base + ordinal` (the planner folds `pos * SLOTS_PER_RULE +
/// fanout_idx` into `ordinal`), preserving the current arbitration order. A
/// `Block` with [`Coverage::AllPackets`] additionally emits the packet-layer
/// mirror (`user_sid = None`) so ICMP/etc. to that IP is dropped too — matching
/// `wfp_codegen::push_packet_block_mirror`. Ids are deterministic (re-apply = no
/// churn) but need NOT match the old FNV scheme — the oracle ignores ids.
pub fn lower_route_rules(plan: &EnforcementPlan) -> Vec<WfpFilterSpec> {
    // Host flows are COLLECTED per rule and packed; everything else (app
    // filters, the default catch-all) lowers one flow at a time.
    //
    // The neutral plan stays per-address — which addresses a rule covers is
    // policy. Folding them into chunk filters is Windows mechanism (WFP ORs
    // conditions on one field), shared with `wfp_codegen` through
    // `wfp_slotting` so both pipelines produce identical chunk keys and the
    // behavioural oracle still compares like with like.
    let mut out = Vec::new();
    let mut rules: Vec<(RuleChunkKey, Vec<IpAddr>)> = Vec::new();
    for flow in &plan.flows {
        match rule_chunk_key(flow) {
            Some((key, ip)) => match rules.iter_mut().find(|(k, _)| *k == key) {
                Some((_, ips)) => ips.push(ip),
                None => rules.push((key, vec![ip])),
            },
            None => out.extend(lower_flow(flow)),
        }
    }
    for (key, ips) in rules {
        for (idx, chunk) in pack_both(ips).into_iter().enumerate() {
            let weight = key.base
                + key.rule_position * nrr_platform_api::enforcement::SLOTS_PER_RULE
                + key.slot_base
                + idx as u64;
            let (ale, packet) = match chunk {
                FamilyChunk::V4(_) => (
                    WfpLayerKey::AleAuthConnectV4,
                    WfpLayerKey::OutboundIpPacketV4,
                ),
                FamilyChunk::V6(_) => (
                    WfpLayerKey::AleAuthConnectV6,
                    WfpLayerKey::OutboundIpPacketV6,
                ),
            };
            out.push(make_chunk_filter(
                ale,
                key.action,
                &chunk,
                weight,
                key.user_sid.clone(),
            ));
            // A Block with packet coverage drops the destination at the packet
            // layer too; that layer exposes no ALE user id.
            if key.action == WfpAction::Block && key.all_packets {
                out.push(make_chunk_filter(
                    packet,
                    WfpAction::Block,
                    &chunk,
                    weight,
                    None,
                ));
            }
        }
    }
    out
}

/// What makes two host flows part of the SAME packed rule.
///
/// The ordinal the planner assigns is `rule_position * SLOTS_PER_RULE +
/// fanout_index`, so dividing it recovers the rule and every address of one
/// rule lands in one group. Everything else in the key is what a filter would
/// carry anyway — mixing two of them into one chunk would change what the
/// filter means.
#[derive(Clone, PartialEq, Eq)]
pub(super) struct RuleChunkKey {
    base: u64,
    rule_position: u64,
    /// First slot of the range this group occupies. A rule's own addresses
    /// start at 0; the addresses its application was OBSERVED using start after
    /// the per-executable app-id filters. Packing the two together would put a
    /// filter in a slot the codegen reserved for the other kind.
    slot_base: u64,
    action: WfpAction,
    all_packets: bool,
    user_sid: Option<String>,
}

/// `Some((key, ip))` for a plain per-address rule flow; `None` for anything
/// that is not one (an app filter, the default catch-all, a non-rule class).
pub(super) fn rule_chunk_key(flow: &FlowRule) -> Option<(RuleChunkKey, IpAddr)> {
    let base = base_for_class(flow.precedence.class)?;
    if matches!(flow.app, AppScope::Program { .. }) {
        return None;
    }
    let ip = match flow.flow.dst {
        DstMatch::HostV4(ip) => IpAddr::V4(ip),
        DstMatch::HostV6(ip) => IpAddr::V6(ip),
        _ => return None,
    };
    let action = match flow.verdict {
        Verdict::Permit => WfpAction::Permit,
        Verdict::Block => WfpAction::Block,
    };
    let ordinal = u64::from(flow.precedence.ordinal);
    let slot = ordinal % nrr_platform_api::enforcement::SLOTS_PER_RULE;
    let observed_app_range = nrr_platform_api::enforcement::APP_PATH_FANOUT_CAP + 1;
    Some((
        RuleChunkKey {
            base,
            rule_position: ordinal / nrr_platform_api::enforcement::SLOTS_PER_RULE,
            slot_base: if slot >= observed_app_range {
                observed_app_range
            } else {
                0
            },
            action,
            all_packets: flow.coverage == Coverage::AllPackets,
            user_sid: flow.principal.0.as_ref().map(|p| p.as_stored().to_string()),
        },
        ip,
    ))
}
