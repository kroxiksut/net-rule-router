//! Behavioral equivalence over [`WfpFilterSpec`].
//!
//! Relocating the WFP codegen into `lower_windows` explicitly DROPS the
//! byte-identical golden test: the ~13 weight bands and the FNV-1a id scheme
//! stay Windows-side and need NOT be reproduced literally. What MUST be preserved
//! is *behaviour* — the same set of match+action filters, and the same relative
//! arbitration among them. This module defines exactly that, so the eventual
//! `lower_windows` output can be checked against today's codegen without pinning
//! literal weights or ids.
//!
//! Two notions, weakest first:
//!
//! - [`behaviorally_equivalent`] — same MULTISET of [`BehavioralKey`]s (every
//!   match condition + the action), ignoring `weight` and `id`. "The same
//!   filters are installed."
//! - [`arbitration_order_preserved`] — additionally, sorting both sets by weight
//!   yields the same key sequence. "The same filters, evaluated in the same
//!   relative priority order." This is the STRONG check the re-baseline uses.
//!
//! `arbitration_order_preserved` is a *sufficient* condition (it also flags a
//! reordering of two filters that could never both match the same flow, which is
//! behaviourally harmless). The fully-faithful check only compares the weight
//! order of *conflicting* filters (same layer + overlapping match sets); that
//! conflict-pairwise refinement is a Phase-B upgrade documented in
//! [`arbitration_order_preserved`] and only needed once `lower_windows` assigns
//! its own weights. For the Phase-A characterisation (current codegen vs itself)
//! the strong check is exact.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::types::{WfpAction, WfpFilterSpec, WfpLayerKey};

/// The behaviour-carrying identity of a [`WfpFilterSpec`]: every field that
/// affects WHICH flows match and WHAT happens to them, with `weight` and `id`
/// (the arbitration/identity MECHANISM) deliberately excluded. Two filters with
/// the same key enforce the same thing; a different weight or id is not a
/// behavioural difference.
///
/// The `layer` and `action` enums are projected to stable small integers via
/// [`layer_ord`] / [`action_ord`] so the key is `Ord` + `Hash` without relying
/// on derive order of the source enums.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BehavioralKey {
    pub layer: u8,
    pub action: u8,
    pub remote_ip: Option<Ipv4Addr>,
    pub remote_port: Option<u16>,
    pub user_sid: Option<String>,
    pub app_pattern: Option<String>,
    pub local_interface_luid: Option<u64>,
    pub remote_subnet: Option<(Ipv4Addr, u8)>,
    pub remote_subnet_v6: Option<(Ipv6Addr, u8)>,
    pub ip_protocol: Option<u8>,
}

/// Stable ordinal for a WFP layer (projection for [`BehavioralKey`]).
pub fn layer_ord(layer: WfpLayerKey) -> u8 {
    match layer {
        WfpLayerKey::AleAuthConnectV4 => 0,
        WfpLayerKey::OutboundIpPacketV4 => 1,
        WfpLayerKey::AleAuthConnectV6 => 2,
        WfpLayerKey::OutboundIpPacketV6 => 3,
        WfpLayerKey::OutboundTransportV4 => 4,
    }
}

/// Stable ordinal for a WFP action (projection for [`BehavioralKey`]).
pub fn action_ord(action: WfpAction) -> u8 {
    match action {
        WfpAction::Block => 0,
        WfpAction::Permit => 1,
    }
}

/// Project a filter to its [`BehavioralKey`] (drops `weight` + `id`).
pub fn behavioral_key(f: &WfpFilterSpec) -> BehavioralKey {
    BehavioralKey {
        layer: layer_ord(f.layer),
        action: action_ord(f.action),
        remote_ip: f.remote_ip,
        remote_port: f.remote_port,
        user_sid: f.user_sid.clone(),
        app_pattern: f.app_pattern.clone(),
        local_interface_luid: f.local_interface_luid,
        remote_subnet: f.remote_subnet,
        remote_subnet_v6: f.remote_subnet_v6,
        ip_protocol: f.ip_protocol,
    }
}

/// The multiset of behavioural keys in a filter set (key → count). Two sets
/// enforce the same policy iff their multisets are equal.
pub fn behavioral_multiset(filters: &[WfpFilterSpec]) -> BTreeMap<BehavioralKey, usize> {
    let mut m = BTreeMap::new();
    for f in filters {
        *m.entry(behavioral_key(f)).or_insert(0) += 1;
    }
    m
}

/// `true` when `a` and `b` install the same set of match+action filters,
/// ignoring weights and ids. Order-independent.
pub fn behaviorally_equivalent(a: &[WfpFilterSpec], b: &[WfpFilterSpec]) -> bool {
    behavioral_multiset(a) == behavioral_multiset(b)
}

/// The behavioural keys of a filter set in weight order (weight ascending; the
/// key itself breaks ties so the sequence is deterministic). This is the
/// relative arbitration order — WFP evaluates higher weights first, so a stable
/// weight-sort maps to a stable priority sequence independent of literal values.
pub fn arbitration_sequence(filters: &[WfpFilterSpec]) -> Vec<BehavioralKey> {
    let mut v: Vec<(u64, BehavioralKey)> = filters
        .iter()
        .map(|f| (f.weight, behavioral_key(f)))
        .collect();
    v.sort();
    v.into_iter().map(|(_, k)| k).collect()
}

/// `true` when `a` and `b` install the same filters AND in the same relative
/// weight order (a strictly stronger check than [`behaviorally_equivalent`]).
///
/// This is the check the Step-3 re-baseline uses: `lower_windows` may assign
/// different literal weight values than today's codegen, but the *order* those
/// weights impose on the filter set must be identical, or arbitration changes.
///
/// Phase-B refinement (only needed once `lower_windows` assigns its own
/// weights): this full-sequence comparison also rejects a reordering of two
/// filters that could never both match one flow — behaviourally harmless. The
/// faithful check compares the weight order only for *conflicting* pairs (same
/// layer + overlapping match sets). Until `lower_windows` exists, current-vs-
/// current is identical, so the strong check is exact.
pub fn arbitration_order_preserved(a: &[WfpFilterSpec], b: &[WfpFilterSpec]) -> bool {
    arbitration_sequence(a) == arbitration_sequence(b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::WfpFilterId;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr::new(a, b, c, d)
    }

    /// A permit filter for `remote_ip` at `weight`, id from `id_raw` so two
    /// filters can share a behavioural key while differing in weight/id.
    fn permit(remote: Ipv4Addr, weight: u64, id_raw: u64) -> WfpFilterSpec {
        WfpFilterSpec {
            layer: WfpLayerKey::AleAuthConnectV4,
            action: WfpAction::Permit,
            remote_ip: Some(remote),
            remote_port: None,
            weight,
            id: WfpFilterId::from_raw(id_raw),
            user_sid: Some("S-1-5-21-A".to_string()),
            app_pattern: None,
            local_interface_luid: None,
            remote_subnet: None,
            remote_subnet_v6: None,
            ip_protocol: None,
        }
    }

    #[test]
    fn weight_and_id_do_not_affect_behavioural_key() {
        let a = permit(ip(203, 0, 113, 5), 0x0010_0000, 1);
        let mut b = a.clone();
        b.weight = 0x0099_0000; // different band
        b.id = WfpFilterId::from_raw(0x9999);
        assert_eq!(behavioral_key(&a), behavioral_key(&b));
        assert!(behaviorally_equivalent(&[a], &[b]));
    }

    #[test]
    fn different_action_or_target_is_not_equivalent() {
        let permit_a = permit(ip(203, 0, 113, 5), 1, 1);
        let mut block_a = permit_a.clone();
        block_a.action = WfpAction::Block;
        assert!(!behaviorally_equivalent(
            std::slice::from_ref(&permit_a),
            &[block_a]
        ));

        let permit_other = permit(ip(198, 51, 100, 9), 1, 1);
        assert!(!behaviorally_equivalent(&[permit_a], &[permit_other]));
    }

    #[test]
    fn multiset_is_order_independent_but_count_sensitive() {
        let f1 = permit(ip(1, 1, 1, 1), 10, 1);
        let f2 = permit(ip(2, 2, 2, 2), 20, 2);
        // Same two filters, emitted in the opposite order → still equivalent.
        assert!(behaviorally_equivalent(
            &[f1.clone(), f2.clone()],
            &[f2.clone(), f1.clone()]
        ));
        // A duplicate is a real difference (count-sensitive multiset).
        assert!(!behaviorally_equivalent(
            std::slice::from_ref(&f1),
            &[f1.clone(), f1.clone()]
        ));
    }

    #[test]
    fn arbitration_ignores_absolute_weights_but_catches_reorder() {
        let lo = permit(ip(1, 1, 1, 1), 10, 1);
        let hi = permit(ip(2, 2, 2, 2), 20, 2);
        // Same relative order, different absolute weights → preserved.
        let mut lo2 = lo.clone();
        lo2.weight = 0x0010_0000;
        let mut hi2 = hi.clone();
        hi2.weight = 0x0050_0000;
        assert!(arbitration_order_preserved(
            &[lo.clone(), hi.clone()],
            &[lo2.clone(), hi2.clone()]
        ));
        // Swap the relative order (lo now outranks hi) → NOT preserved, even
        // though the filter SET is still behaviourally equivalent.
        let mut lo_hi = lo.clone();
        lo_hi.weight = 30;
        assert!(behaviorally_equivalent(
            &[lo.clone(), hi.clone()],
            &[lo_hi.clone(), hi.clone()]
        ));
        assert!(!arbitration_order_preserved(
            &[lo, hi.clone()],
            &[lo_hi, hi]
        ));
    }

    #[test]
    fn wildcard_conditions_are_distinct_from_specific_ones() {
        let specific = permit(ip(203, 0, 113, 5), 1, 1);
        let mut any_user = specific.clone();
        any_user.user_sid = None; // system-wide vs per-user is a real difference
        assert!(!behaviorally_equivalent(&[specific], &[any_user]));
    }
}
