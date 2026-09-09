//! Every WFP weight band in one place, ordered once.
//!
//! All of this crate's filters live in ONE sub-layer, where the highest weight
//! wins outright. So the only thing that decides whether a user's explicit
//! Block beats the kill switch's app exemption — or loses to it — is the
//! numeric distance between two constants. Ties and inversions are silent: the
//! filters install, the service reports success, and arbitration happens by
//! accident.
//!
//! # Why one module rather than a constant beside each emitter
//!
//! The bands used to be declared in `wfp_codegen` and `killswitch_codegen`,
//! each asserting about the other's constants across a module boundary. Two
//! half-views, and neither could see the whole order: a band added to either
//! file was checked only against the handful of neighbours its author happened
//! to name. This module holds the complete ordered list and asserts THAT, so a
//! new band collides at compile time no matter which emitter introduces it.
//!
//! # Two orders, not one
//!
//! The ALE connect layer and the packet layer arbitrate SEPARATELY, so their
//! numeric spaces are independent and are listed separately. Mixing them would
//! invent constraints the hardware does not impose — and hide the one it does,
//! that each layer is internally ordered.
//!
//! # Adding a band
//!
//! Declare it here, put it in the matching table in ascending order, and give
//! it a gap wide enough for whatever index or slot arithmetic its emitter does.
//! If the table stops ascending the crate stops compiling.

// ── ALE connect layer ───────────────────────────────────────────────────────

/// The fail-closed catch-all. Below every per-rule weight so a rule-driven
/// `Permit` always wins.
pub(crate) const DEFAULT_BLOCK_WEIGHT: u64 = 0x0000_FFFF;

/// `secondary`-route rules.
pub(crate) const BASE_SECONDARY: u64 = 0x0010_0000;

/// The catch-all block-all. Deliberately BETWEEN the secondary and primary rule
/// bands: a primary rule keeps working under block-all, a secondary permit does
/// not.
pub(crate) const CATCHALL_BLOCK_WEIGHT: u64 = 0x0018_0000;

/// Per-app kill-switch / fail-closed Block filters. Same reasoning as
/// [`CATCHALL_BLOCK_WEIGHT`]: above every secondary-band permit (including the
/// app's own), below the primary band, so an address the main link names keeps
/// working for a pinned app in every posture.
pub(crate) const APP_KILLSWITCH_BLOCK_BASE: u64 = 0x001C_0000;

/// `primary`-route rules. Above the secondary band so an explicit primary rule
/// outranks a more general secondary one.
pub(crate) const BASE_PRIMARY: u64 = 0x0020_0000;

/// DNS-over-HTTPS / DNS-over-TLS blocks.
pub(crate) const DOH_BLOCK_BASE: u64 = 0x0028_0000;

/// The kill switch's Block half. Above the rule bands but below its own permit,
/// so the permit wins while the secondary adapter is up and the block wins the
/// instant it is not.
pub(crate) const KILLSWITCH_BLOCK_BASE: u64 = 0x0030_0000;

/// The kill switch's per-destination egress-conditional permit. Above
/// [`BASE_PRIMARY`] so it outranks the plain rule permit for the same address.
pub(crate) const KILLSWITCH_PERMIT_BASE: u64 = 0x0040_0000;

/// The fake-IP pool permit. Inside the kill-switch permit band, near its top and
/// far above the per-destination permits, so an application can always reach the
/// pool (and the TUN) even under block-all.
pub(crate) const FAKEIP_POOL_PERMIT_BASE: u64 = KILLSWITCH_PERMIT_BASE + 0x000E_0000;

/// Catch-all exemptions: loopback, link-local, the link's own upkeep.
pub(crate) const CATCHALL_EXEMPT_BASE: u64 = 0x0050_0000;

/// Per-app exemptions (the VPN client's own process, and anything the user
/// exempted by name).
pub(crate) const APP_EXEMPT_BASE: u64 = 0x0060_0000;

/// Per-rule **Block**-action filters. The top of the ALE order: an explicit user
/// Block beats even the kill switch's egress-conditional permit. The hard veto
/// itself comes from `FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT`, which defends a
/// Block against OTHER sub-layers — not against our own higher-weighted permit,
/// which is why the ordering here has to carry it.
pub(crate) const BASE_BLOCK: u64 = 0x0070_0000;

/// The ALE order, low to high. The list IS the invariant.
const ALE_BANDS: &[(&str, u64)] = &[
    ("DEFAULT_BLOCK_WEIGHT", DEFAULT_BLOCK_WEIGHT),
    ("BASE_SECONDARY", BASE_SECONDARY),
    ("CATCHALL_BLOCK_WEIGHT", CATCHALL_BLOCK_WEIGHT),
    ("APP_KILLSWITCH_BLOCK_BASE", APP_KILLSWITCH_BLOCK_BASE),
    ("BASE_PRIMARY", BASE_PRIMARY),
    ("DOH_BLOCK_BASE", DOH_BLOCK_BASE),
    ("KILLSWITCH_BLOCK_BASE", KILLSWITCH_BLOCK_BASE),
    ("KILLSWITCH_PERMIT_BASE", KILLSWITCH_PERMIT_BASE),
    ("FAKEIP_POOL_PERMIT_BASE", FAKEIP_POOL_PERMIT_BASE),
    ("CATCHALL_EXEMPT_BASE", CATCHALL_EXEMPT_BASE),
    ("APP_EXEMPT_BASE", APP_EXEMPT_BASE),
    ("BASE_BLOCK", BASE_BLOCK),
];

// ── Packet layer ────────────────────────────────────────────────────────────
//
// `FWPM_LAYER_OUTBOUND_IPPACKET_V4` arbitrates separately from ALE, so these
// numbers are free to reuse the ALE space. Within the layer the order is
// blocks, then permit-unselected, then exemptions — so loopback, the LAN, the
// tunnel server and any UN-selected protocol always escape the block.

/// Packet-layer blocks.
pub(crate) const PACKET_BLOCK_BASE: u64 = 0x0030_0000;
/// Packet-layer permits for protocols the kill switch did not select.
pub(crate) const PACKET_PERMIT_BASE: u64 = 0x0140_0000;
/// Packet-layer exemptions.
pub(crate) const PACKET_EXEMPT_BASE: u64 = 0x0250_0000;

/// The packet-layer order, low to high.
const PACKET_BANDS: &[(&str, u64)] = &[
    ("PACKET_BLOCK_BASE", PACKET_BLOCK_BASE),
    ("PACKET_PERMIT_BASE", PACKET_PERMIT_BASE),
    ("PACKET_EXEMPT_BASE", PACKET_EXEMPT_BASE),
];

// ── Widths and caps ─────────────────────────────────────────────────────────

/// Width of one rule weight band. Every rule base is a multiple of it.
pub(crate) const BAND_WIDTH: u64 = 0x0010_0000;

/// Fan-out slots one rule may use before colliding with the next rule's range.
///
/// Declared in `nrr-platform-api` because the Windows lowering needs the same
/// number to recover a rule from a plan ordinal, and it cannot depend on this
/// crate. Re-exported here so the band story still reads in one place.
pub use nrr_platform_api::enforcement::SLOTS_PER_RULE;

/// Protected destination ADDRESSES one kill-switch plan accepts. Applied before
/// packing, so a chunk index can never exceed the address count and every
/// `BASE + idx` weight stays inside its band.
pub const KILLSWITCH_MAX_DESTINATIONS: usize = 0x000D_FFFF;

/// Per-app kill-switch / fail-closed entries, so `+ idx` cannot climb out of the
/// app-block window into the primary rule band.
pub(crate) const APP_KILLSWITCH_MAX_APPS: usize = 0x0003_FFFF;

/// Slots one packet-layer per-destination filter takes (`idx * 16 + k`).
const PACKET_SLOTS_PER_DESTINATION: u64 = 16;

// ── Reading a weight back ───────────────────────────────────────────────────

/// Which band a weight belongs to, by name.
///
/// The tables above are the only thing that knows where a band starts, so the
/// answer is derived from them rather than from a second list that would drift.
/// A weight below the lowest band is `"below-bands"` — an emitter that produced
/// one is a defect worth seeing rather than silently filing under a neighbour.
fn band_of(bands: &[(&'static str, u64)], weight: u64) -> &'static str {
    let mut found = "below-bands";
    for (name, base) in bands {
        if weight >= *base {
            found = name;
        }
    }
    found
}

/// Which band this filter's weight sits in. ALE and the packet layer arbitrate
/// separately and reuse the same numeric space, so the layer picks the table.
pub(crate) fn band_of_filter(spec: &nrr_platform_api::types::WfpFilterSpec) -> &'static str {
    use nrr_platform_api::types::WfpLayerKey;
    match spec.layer {
        WfpLayerKey::OutboundIpPacketV4 | WfpLayerKey::OutboundIpPacketV6 => {
            band_of(PACKET_BANDS, spec.weight)
        }
        _ => band_of(ALE_BANDS, spec.weight),
    }
}

/// How the standing filter set breaks down by band, biggest first.
///
/// The volume watchdog names a total; a total says a number is high and nothing
/// about which emitter produced it. The first packed run measured 2260 filters
/// with the kill switch at 176 and DoH at 34 — the remaining ~2000 were the
/// rule band, and it took a separate hand count to learn that.
pub(crate) fn standing_volume_by_band(
    specs: &[nrr_platform_api::types::WfpFilterSpec],
) -> Vec<(&'static str, usize)> {
    let mut counts: std::collections::HashMap<&'static str, usize> =
        std::collections::HashMap::new();
    for spec in specs {
        *counts.entry(band_of_filter(spec)).or_insert(0) += 1;
    }
    let mut out: Vec<(&'static str, usize)> = counts.into_iter().collect();
    // Biggest first, then by name: the reader wants the culprit on the left,
    // and a stable order makes two lines comparable.
    out.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
    out
}

/// The breakdown as one log field: `BASE_SECONDARY=1980 KILLSWITCH_BLOCK_BASE=176`.
pub(crate) fn render_standing_volume(specs: &[nrr_platform_api::types::WfpFilterSpec]) -> String {
    standing_volume_by_band(specs)
        .into_iter()
        .map(|(band, count)| format!("{band}={count}"))
        .collect::<Vec<_>>()
        .join(" ")
}

// ── The invariant ───────────────────────────────────────────────────────────

/// Each table must ascend strictly. Two bands at the same weight, or out of
/// order, means two filters arbitrate by accident.
const fn ascends(bands: &[(&str, u64)]) -> bool {
    let mut i = 1;
    while i < bands.len() {
        if bands[i - 1].1 >= bands[i].1 {
            return false;
        }
        i += 1;
    }
    true
}

const _: () = {
    assert!(
        ascends(ALE_BANDS),
        "ALE weight bands are not strictly ascending — two filters would \
         arbitrate by accident"
    );
    assert!(
        ascends(PACKET_BANDS),
        "packet-layer weight bands are not strictly ascending"
    );

    // A rule band must fit its own rules without reaching the next band.
    assert!(BASE_SECONDARY + BAND_WIDTH <= BASE_PRIMARY);
    assert!(BASE_PRIMARY + BAND_WIDTH <= KILLSWITCH_PERMIT_BASE);
    assert!(
        BASE_BLOCK - APP_EXEMPT_BASE >= BAND_WIDTH,
        "an explicit user Block must sit a full band above the app exemptions"
    );

    // Index arithmetic must stay inside the band it starts in.
    assert!(
        (KILLSWITCH_MAX_DESTINATIONS as u64) < FAKEIP_POOL_PERMIT_BASE - KILLSWITCH_PERMIT_BASE
    );
    assert!((KILLSWITCH_MAX_DESTINATIONS as u64) < CATCHALL_EXEMPT_BASE - KILLSWITCH_PERMIT_BASE);
    assert!((KILLSWITCH_MAX_DESTINATIONS as u64) < KILLSWITCH_PERMIT_BASE - KILLSWITCH_BLOCK_BASE);
    assert!(APP_KILLSWITCH_BLOCK_BASE + (APP_KILLSWITCH_MAX_APPS as u64) < BASE_PRIMARY);

    // The packet layer's per-destination window must fit each of its gaps.
    let window = (KILLSWITCH_MAX_DESTINATIONS as u64) * PACKET_SLOTS_PER_DESTINATION;
    assert!(
        window <= PACKET_PERMIT_BASE - PACKET_BLOCK_BASE
            && window <= PACKET_EXEMPT_BASE - PACKET_PERMIT_BASE,
        "packet-layer per-destination weight window overflows a band gap — widen \
         the packet bands or cap the packet destination count"
    );
};

#[cfg(test)]
mod tests {
    use super::*;

    /// Positive control for the compile-time guard: the checker has to reject
    /// an order it should reject, or the `const` assert above is decoration.
    #[test]
    fn the_order_checker_rejects_a_tie_and_an_inversion() {
        assert!(ascends(&[("a", 1), ("b", 2), ("c", 3)]));
        assert!(!ascends(&[("a", 1), ("b", 1)]), "a tie must be rejected");
        assert!(
            !ascends(&[("a", 2), ("b", 1)]),
            "an inversion must be rejected"
        );
    }

    /// The tables must name every band, or a band could drift without the guard
    /// noticing. Counted rather than matched by name: a new constant added
    /// without a table entry changes this number.
    #[test]
    fn every_band_is_in_a_table() {
        assert_eq!(ALE_BANDS.len(), 12);
        assert_eq!(PACKET_BANDS.len(), 3);
    }

    fn spec_at(
        layer: nrr_platform_api::types::WfpLayerKey,
        weight: u64,
    ) -> nrr_platform_api::types::WfpFilterSpec {
        use nrr_platform_api::types::{WfpAction, WfpFilterId, WfpFilterSpec};
        WfpFilterSpec {
            layer,
            action: WfpAction::Block,
            remote_ip: None,
            remote_ip_set: Vec::new(),
            remote_port: None,
            weight,
            id: WfpFilterId { raw: weight },
            user_sid: None,
            app_pattern: None,
            local_interface_luid: None,
            remote_subnet: None,
            remote_subnet_v6: None,
            ip_protocol: None,
        }
    }

    #[test]
    fn a_weight_is_filed_under_the_band_it_sits_in() {
        use nrr_platform_api::types::WfpLayerKey;
        assert_eq!(
            band_of_filter(&spec_at(WfpLayerKey::AleAuthConnectV4, BASE_SECONDARY + 7)),
            "BASE_SECONDARY"
        );
        // The top band has no upper neighbour, so anything above it is still
        // its own.
        assert_eq!(
            band_of_filter(&spec_at(WfpLayerKey::AleAuthConnectV4, BASE_BLOCK + 1_000)),
            "BASE_BLOCK"
        );
    }

    #[test]
    fn the_layer_decides_which_table_answers() {
        // The two layers arbitrate separately and REUSE the numeric space:
        // 0x0030_0000 is the kill-switch block on ALE and the packet block on
        // the packet layer. Filing both under one table would invent a
        // constraint the hardware does not impose.
        use nrr_platform_api::types::WfpLayerKey;
        assert_eq!(
            band_of_filter(&spec_at(
                WfpLayerKey::AleAuthConnectV4,
                KILLSWITCH_BLOCK_BASE
            )),
            "KILLSWITCH_BLOCK_BASE"
        );
        assert_eq!(
            band_of_filter(&spec_at(WfpLayerKey::OutboundIpPacketV4, PACKET_BLOCK_BASE)),
            "PACKET_BLOCK_BASE"
        );
    }

    #[test]
    fn a_weight_under_every_band_is_named_rather_than_filed_away() {
        // An emitter that produced one is a defect; filing it under a
        // neighbour would hide that.
        use nrr_platform_api::types::WfpLayerKey;
        assert_eq!(
            band_of_filter(&spec_at(WfpLayerKey::AleAuthConnectV4, 1)),
            "below-bands"
        );
    }

    #[test]
    fn the_breakdown_names_the_biggest_producer_first() {
        use nrr_platform_api::types::WfpLayerKey;
        let mut specs = Vec::new();
        for i in 0..5 {
            specs.push(spec_at(WfpLayerKey::AleAuthConnectV4, BASE_SECONDARY + i));
        }
        specs.push(spec_at(WfpLayerKey::AleAuthConnectV4, DOH_BLOCK_BASE));
        specs.push(spec_at(WfpLayerKey::AleAuthConnectV4, DOH_BLOCK_BASE + 1));

        let summary = standing_volume_by_band(&specs);
        assert_eq!(summary[0], ("BASE_SECONDARY", 5), "the culprit reads first");
        assert_eq!(summary[1], ("DOH_BLOCK_BASE", 2));
        assert_eq!(
            render_standing_volume(&specs),
            "BASE_SECONDARY=5 DOH_BLOCK_BASE=2"
        );
    }
}
