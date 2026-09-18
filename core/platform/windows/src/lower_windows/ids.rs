// Deriving stable filter identities and building the filter specs.

use super::*;

pub(super) fn make_host_filter(
    layer: WfpLayerKey,
    action: WfpAction,
    ip: Ipv4Addr,
    weight: u64,
    user_sid: Option<String>,
) -> WfpFilterSpec {
    let id = derive_filter_id(user_sid.as_deref(), layer, action, ip, weight);
    WfpFilterSpec {
        layer,
        action,
        remote_ip: Some(ip),
        remote_ip_set: Vec::new(),
        remote_ip_set_v6: Vec::new(),
        remote_port: None,
        weight,
        id,
        user_sid,
        app_pattern: None,
        local_interface_luid: None,
        remote_subnet: None,
        remote_subnet_v6: None,
        ip_protocol: None,
    }
}

/// One packed chunk as a filter. The per-address twin of this is
/// [`make_host_filter`]; identity comes from the chunk digest, so the same
/// address set always yields the same id.
pub(super) fn make_chunk_filter(
    layer: WfpLayerKey,
    action: WfpAction,
    chunk: &FamilyChunk,
    weight: u64,
    user_sid: Option<String>,
) -> WfpFilterSpec {
    let id = derive_catch_all_id(user_sid.as_deref(), layer, action, weight, &chunk.id_seg());
    let (members_v4, members_v6) = match chunk {
        FamilyChunk::V4(c) => (c.members.clone(), Vec::new()),
        FamilyChunk::V6(c) => (Vec::new(), c.members.clone()),
    };
    WfpFilterSpec {
        layer,
        action,
        remote_ip: None,
        remote_ip_set: members_v4,
        remote_ip_set_v6: members_v6,
        remote_port: None,
        weight,
        id,
        user_sid,
        app_pattern: None,
        local_interface_luid: None,
        remote_subnet: None,
        remote_subnet_v6: None,
        ip_protocol: None,
    }
}

/// Deterministic id for an app-id filter (keyed on user/action/exe-path/weight —
/// no remote IP). Oracle ignores ids; this only needs to be stable + unique.
pub(super) fn derive_app_id(
    sid: Option<&str>,
    action: WfpAction,
    path: &str,
    weight: u64,
) -> WfpFilterId {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
    let seed = format!(
        "app|{}|{}|{path}|{weight}",
        sid.unwrap_or(""),
        nrr_platform_api::wfp_behavioral::action_ord(action),
    );
    let mut h = FNV_OFFSET;
    for b in seed.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(FNV_PRIME);
    }
    WfpFilterId::from_raw(h)
}

/// Deterministic id for a packed-set filter. The chunk's id segment digests
/// the membership, so a membership change mints a new id and the reconcile
/// swaps the filter make-before-break; `weight` keeps the two halves of a
/// pair (and different bands over one chunk) apart.
pub(super) fn derive_set_id(
    sid: Option<&str>,
    layer: WfpLayerKey,
    action: WfpAction,
    seg: &str,
    weight: u64,
) -> WfpFilterId {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
    let seed = format!(
        "set|{}|{}|{}|{seg}|{weight}",
        sid.unwrap_or(""),
        nrr_platform_api::wfp_behavioral::layer_ord(layer),
        nrr_platform_api::wfp_behavioral::action_ord(action),
    );
    let mut h = FNV_OFFSET;
    for b in seed.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(FNV_PRIME);
    }
    WfpFilterId::from_raw(h)
}

/// Deterministic filter id (FNV-1a of the fields that make a filter unique in a
/// plan: user, layer, action, target, weight). Same plan → same id → a WFP
/// re-apply is a no-op. Including `layer` + `weight` keeps the id distinct for
/// the ALE/packet-mirror pair and for two fan-out targets that resolve to the
/// same IP. Its literal value is NOT part of the cross-OS contract (the oracle
/// ignores ids); it only has to be stable + unique within a build.
pub(super) fn derive_filter_id(
    sid: Option<&str>,
    layer: WfpLayerKey,
    action: WfpAction,
    ip: Ipv4Addr,
    weight: u64,
) -> WfpFilterId {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
    let seed = format!(
        "{}|{}|{}|{}|{weight}",
        sid.unwrap_or(""),
        nrr_platform_api::wfp_behavioral::layer_ord(layer),
        nrr_platform_api::wfp_behavioral::action_ord(action),
        ip,
    );
    let mut h = FNV_OFFSET;
    for b in seed.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(FNV_PRIME);
    }
    WfpFilterId::from_raw(h)
}

/// Everything the Windows lowering needs that a neutral plan cannot carry:
/// identities the kernel hands out at runtime, and which change when a link
/// reconnects.
///
/// Supplied per call, never cached — the same rule the Linux side follows with
/// interface names. A stale LUID does not fail loudly; it pins traffic to an
/// interface that no longer exists while the rule still reads as applied.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EgressLuids {
    /// LUID of the additional link. `0` means "not resolvable right now" and
    /// the kill-switch lowering declines rather than guessing.
    pub secondary: u64,
}

/// Identity for a subnet-scoped filter. The address itself is not part of the
/// seed because a band's subnet is fixed by configuration, while the weight
/// already separates the members of the band.
pub(super) fn derive_subnet_filter_id(
    sid: Option<&str>,
    layer: WfpLayerKey,
    action: WfpAction,
    weight: u64,
) -> WfpFilterId {
    derive_filter_id(sid, layer, action, Ipv4Addr::UNSPECIFIED, weight)
}
