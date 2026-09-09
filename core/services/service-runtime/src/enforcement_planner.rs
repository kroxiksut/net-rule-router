//! The neutral enforcement PLANNER.
//!
//! Converts the current codegen inputs (canonical rules + resolution/observation
//! views) into a neutral [`EnforcementPlan`] (`nrr_platform_api::enforcement`).
//! This is OS-neutral policy: it names no WFP layer, weight, or id — it only
//! decides WHAT to enforce. Each OS's `lower_*` step turns the plan back into
//! that platform's mechanism (`nrr_platform_windows::lower_windows` for WFP;
//! `lower_linux` for nftables later).
//!
//! ## Incremental build
//!
//! The planner is grown one rule-slice at a time, each proven behaviourally
//! equivalent to today's `wfp_codegen` via the `nrr_platform_api::wfp_behavioral`
//! oracle, WITHOUT deleting the current path.
//!
//! - **Slices 1–3: the full rule-driven surface of
//!   `wfp_codegen::generate_filters`.** Address-match route rules — `ExactIp`
//!   (Slice 1) and `ExactFqdn`/`SuffixDomain`/`Zone` fan-out (Slice 2) — plus
//!   `RuleAction::Block` (Slice 2, with the packet-layer mirror) and
//!   `Application` rules (Slice 3: per-exe `ALE_APP_ID` filters + observed-dest
//!   `/32`s). Proven by `tests::slices123_neutral_pipeline_matches_current_codegen`.
//! - **Sub-slices 4a + 4b: the per-destination kill-switch.**
//!   `plan_kill_switch_destinations` reproduces
//!   `killswitch_codegen::kill_switch_filters` — the ALE `OnlyVia(Secondary)`
//!   pair (4a) plus the packet-layer multi-protocol egress pairs and the "Other"
//!   block-all with per-protocol permit exceptions (4b).
//! - **Sub-slice 4c: the catch-all (Mode-B) kill-switch.**
//!   `plan_catch_all_kill_switch` reproduces
//!   `killswitch_codegen::catch_all_kill_switch_filters` (blanket egress permit +
//!   subnet/host exemptions + ALE/packet blocks + the IPv6 cut).
//! - **Sub-slice 4d: fail-closed + per-app kill-switch + app exemption.**
//!   `plan_app_kill_switch` / `plan_primary_app_exempt` /
//!   `plan_fail_closed_destinations` / `plan_fail_closed_apps` /
//!   `plan_fail_closed_block_all` reproduce the rest of `killswitch_codegen` —
//!   completing the whole module.
//! - **Slice 5: the system route table + the fail-closed default block.**
//!   `plan_routes` reproduces `route_codegen::generate_routes` (the `/32` host
//!   fan-out + `/1`/`/2` overlays as neutral [`RouteIntent`]s), and
//!   `plan_route_rules` emits the `StrictSecondaryFailClosed`
//!   [`PrecedenceClass::DefaultCatchAll`] block. Each slice is proven behaviourally
//!   equivalent to the current codegen by a `#[cfg(windows)] tests::slice*` test.

use std::collections::{BTreeSet, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

use nrr_domain::canonical::{
    CanonicalAddressMatch, CanonicalAppPattern, CanonicalRule, CanonicalRuleBook, CanonicalRuleSet,
};
use nrr_domain::user_principal::UserPrincipal;
use nrr_domain::{RouteBehaviorMode, RuleAction};
use nrr_platform_api::enforcement::{
    AppScope, Coverage, DstMatch, EgressConstraint, EgressRef, FlowMatch, FlowRule, L4Proto,
    Precedence, PrecedenceClass, PrincipalScope, RouteIntent, RouteTableRef, Verdict,
};
use nrr_platform_api::AppPathResolver;
use nrr_shared::RouteRole;

use crate::app_observation_lookup::AppObservationLookup;
use crate::fqdn_cache_lookup::FqdnCacheLookup;
// The caps live with the bands they protect.
use crate::killswitch_codegen::KillSwitchProtocols;
use crate::net_filter::is_non_routable_v4;
use crate::route_codegen::{
    COUNTER_OVERLAY, MAX_ROUTES_PER_RULE, OVERLAY_HIGH, OVERLAY_LOW, SECONDARY_ROUTE_METRIC,
};
use crate::secondary_ip_policy::DenylistFilteredCache;
use crate::wfp_bands::{APP_KILLSWITCH_MAX_APPS, KILLSWITCH_MAX_DESTINATIONS};
use crate::wfp_codegen::{
    APP_PATH_FANOUT_CAP, PER_HOSTNAME_IP_CAP, SLOTS_PER_RULE as WFP_SLOTS_PER_RULE,
    SUFFIX_FANOUT_BACKSTOP,
};

/// Borrowed resolution/observation views the planner needs, bundled so the
/// signature stays stable as slices are added (mirrors `wfp_codegen::CodegenInput`).
pub struct PlannerInput<'a> {
    pub fqdn_cache: &'a dyn FqdnCacheLookup,
    pub app_resolver: &'a dyn AppPathResolver,
    pub app_observations: &'a dyn AppObservationLookup,
    /// Evaluate a zone rule ahead of an exact-address rule, from the
    /// principal's stored `zone_priority_over_ip`. Reaches the
    /// address-ownership arbiter, which is the one place the two can contest
    /// the same address.
    pub zone_priority_over_ip: bool,
    /// Addresses the shared-IP policy declined for the ADDITIONAL route — the
    /// same set the Windows codegen hides behind
    /// [`crate::secondary_ip_policy::DenylistFilteredCache`].
    ///
    /// Applied to secondary rules only: a shared address declined for the
    /// tunnel must still be reachable over the main link, so the primary side
    /// reads the raw cache. Empty means "no policy declined anything", which is
    /// what a caller with no shared-IP census passes.
    pub secondary_ip_denylist: &'a HashSet<Ipv4Addr>,
}

/// Within-band ordinal slots reserved per rule, mirroring
/// `wfp_codegen::SLOTS_PER_RULE` so the neutral `ordinal` reconstructs the exact
/// Windows weight (`base + pos * SLOTS_PER_RULE + fanout_idx`). Kept in sync as
/// the SSOT of the per-rule slot width across the planner + `lower_windows`.
pub const SLOTS_PER_RULE: u32 = WFP_SLOTS_PER_RULE as u32;

/// The neutral principal scope for a stored partition key.
///
/// Reads the key for what it is on THIS OS — a Windows SID, `unix:uid:<n>`, or
/// the baseline sentinel — rather than assuming one spelling. Parsing it as a
/// Windows SID left every Linux rule unscoped, and an unscoped rule applies to
/// the whole machine: one user's policy would have governed everyone the first
/// time two people logged in.
///
/// The baseline maps to `None` deliberately: it belongs to no user, and a rule
/// planned from it is meant to hold for all of them.
fn principal_scope(sid: &str) -> PrincipalScope {
    PrincipalScope(
        UserPrincipal::from_stored(sid)
            .ok()
            .filter(|p| !p.is_baseline()),
    )
}

/// Per-destination packet-layer slot window (Sub-slice 4b), mirroring the
/// `idx * 16` weight window in `killswitch_codegen::packet_egress_pairs`. Each
/// protected destination reserves 16 within-band ordinal slots at the packet
/// layer (one per selectable protocol) so `lower_windows` reconstructs the exact
/// packet weights as `band + (idx * PACKET_SLOTS_PER_DEST + slot)`. Kept in sync
/// as the SSOT of the packet slot window across the planner + `lower_windows`.
const PACKET_SLOTS_PER_DEST: u32 = 16;

/// Plan the **rule-driven** filters (Slices 1–3) for `sid` into neutral
/// [`FlowRule`]s — the neutral equivalent of `wfp_codegen::generate_filters`.
///
/// Covers address-match rules (`ExactIp` + `ExactFqdn`/`SuffixDomain`/`Zone`
/// fan-out, resolved through `input.fqdn_cache`) and `Application` rules
/// (`app_match`: per-exe-path `ALE_APP_ID` filters resolved through
/// `input.app_resolver`, plus observed-destination `/32`s from
/// `input.app_observations`), for both [`RuleAction::Route`] (a `Permit`) and
/// [`RuleAction::Block`].
///
/// Ordering + `ordinal` are faithful to `wfp_codegen`: primary rules first, then
/// secondary; `ordinal = rule_position * SLOTS_PER_RULE + fanout_index`. A
/// `Block` maps to [`PrecedenceClass::HardBlock`] (the role-independent
/// `BASE_BLOCK` band) with [`Coverage::AllPackets`]; the packet-layer mirror is
/// only emitted for a host destination, so an app-id block (no remote IP) is not
/// mirrored — matching today's codegen. Resolution failures emit no flow
/// (the current codegen's diagnostics are not part of the neutral plan).
///
/// Slice 5 — when `behavior_mode` is
/// [`RouteBehaviorMode::StrictSecondaryFailClosed`], a trailing user-scoped
/// [`PrecedenceClass::DefaultCatchAll`] `Block` (`dst = Any`, ALE only) is emitted
/// — the fail-closed default that `wfp_codegen::default_block_spec` appends.
pub fn plan_route_rules(
    rule_book: &CanonicalRuleBook,
    sid: &str,
    behavior_mode: RouteBehaviorMode,
    input: &PlannerInput,
) -> (Vec<FlowRule>, PlanReport) {
    let principal = principal_scope(sid);
    let mut flows = Vec::new();
    let mut report = PlanReport::default();
    // The same arbiter the Windows codegens read. Without it this path pins an
    // app rule's observed destinations over an address rule the user wrote for
    // that very host, and the kill-switch then blocks the address for every
    // process — the incident the arbiter exists for, reproduced on the Linux
    // enforcement path.
    let ownership = crate::address_ownership::AddressOwnership::resolve_with_order(
        rule_book,
        input.fqdn_cache,
        crate::address_ownership::ZoneVsIpOrder::from_zone_priority_over_ip(
            input.zone_priority_over_ip,
        ),
    );
    // Secondary rules read the denylist-filtered view, primary rules the raw
    // cache — the same split `wfp_codegen::generate_filters` makes. Without it
    // this path plans the tunnel over addresses the shared-IP policy already
    // declined, which is both a different plan and a different set of ordinals
    // for everything after it.
    let secondary_cache = crate::secondary_ip_policy::DenylistFilteredCache::new(
        input.fqdn_cache,
        input.secondary_ip_denylist,
    );
    for (role, set) in [
        (RouteRole::Primary, &rule_book.primary),
        (RouteRole::Secondary, &rule_book.secondary),
    ] {
        let cache_for_role: &dyn FqdnCacheLookup = match role {
            RouteRole::Primary => input.fqdn_cache,
            RouteRole::Secondary => &secondary_cache,
        };
        let gate = crate::address_ownership::AppDestinationGate::for_rule_set(
            &ownership,
            input.app_observations,
            set,
        );
        let link = match role {
            RouteRole::Primary => crate::address_ownership::Link::Main,
            RouteRole::Secondary => crate::address_ownership::Link::Additional,
        };
        for (pos, rule) in set.rules().iter().enumerate() {
            if !rule.enabled {
                continue;
            }
            let (verdict, class, coverage) = match rule.action {
                RuleAction::Route => (
                    Verdict::Permit,
                    PrecedenceClass::RouteRule(role),
                    Coverage::ConnectOnly,
                ),
                RuleAction::Block => (
                    Verdict::Block,
                    PrecedenceClass::HardBlock,
                    Coverage::AllPackets,
                ),
            };
            let base_ordinal = (pos as u32) * SLOTS_PER_RULE;
            let host_flow = |fanout_idx: u32, ip: Ipv4Addr| FlowRule {
                verdict,
                precedence: Precedence {
                    class,
                    ordinal: base_ordinal + fanout_idx,
                },
                flow: FlowMatch {
                    dst: DstMatch::HostV4(ip),
                    dst_port: None,
                    protocol: None,
                },
                principal: principal.clone(),
                app: AppScope::Any,
                egress: EgressConstraint::Any,
                coverage,
            };

            if let Some(addr_match) = rule.address_match.as_ref() {
                let targets = resolve_targets(addr_match, cache_for_role);
                note_address_resolution(&mut report, rule, addr_match, &targets, cache_for_role);
                for (fanout_idx, ip) in targets {
                    // A Block rule steers nothing, so the arbiter has no say
                    // over it. Otherwise: an address the main link's own rules
                    // name is not this link's to take, however specific this
                    // rule is about the HOST — the flow acts on the ADDRESS,
                    // and it carries the main link's hosts too.
                    if !matches!(rule.action, RuleAction::Block)
                        && !ownership.address_rule_may_steer(ip, link)
                    {
                        continue;
                    }
                    flows.push(host_flow(fanout_idx, ip));
                }
            } else if let Some(app) = rule.app_match.as_ref() {
                let pattern = match &app.pattern {
                    CanonicalAppPattern::Exact(s) | CanonicalAppPattern::Glob(s) => s.as_str(),
                };
                // Per-exe-path ALE_APP_ID filters (slots 0..APP_PATH_FANOUT_CAP).
                // No remote IP → DstMatch::Any; no packet mirror (the packet
                // layer has no app context), so ConnectOnly.
                let resolved = input.app_resolver.resolve(pattern);
                if resolved.is_empty() {
                    report.unresolved_apps.push(pattern.to_string());
                } else if resolved.len() > APP_PATH_FANOUT_CAP as usize {
                    report.over_capped_apps.push((
                        pattern.to_string(),
                        APP_PATH_FANOUT_CAP as usize,
                        resolved.len(),
                    ));
                }
                for (k, path) in resolved
                    .into_iter()
                    .take(APP_PATH_FANOUT_CAP as usize)
                    .enumerate()
                {
                    flows.push(FlowRule {
                        verdict,
                        precedence: Precedence {
                            class,
                            ordinal: base_ordinal + k as u32,
                        },
                        flow: FlowMatch {
                            dst: DstMatch::Any,
                            dst_port: None,
                            protocol: None,
                        },
                        principal: principal.clone(),
                        app: AppScope::Program {
                            key: pattern.to_string(),
                            exe_paths: vec![path],
                        },
                        egress: EgressConstraint::Any,
                        coverage: Coverage::ConnectOnly,
                    });
                }
                // Observed-destination /32s (slots APP_PATH_FANOUT_CAP+1+i) —
                // ordinary host flows, so `coverage` (mirror for Block) applies.
                let destinations = gate.admit(pattern, link);
                for (ip, refusal) in &destinations.refused {
                    // Only the address-rule claim is the user's own two rules
                    // pointing one address both ways — the one they can act on.
                    if *refusal
                        == crate::address_ownership::AppDestinationRefusal::ClaimedByAddressRule
                    {
                        report.claimed_by_main.push((pattern.to_string(), *ip));
                    }
                }
                for (i, ip) in destinations
                    .admitted
                    .into_iter()
                    .take(PER_HOSTNAME_IP_CAP)
                    .enumerate()
                {
                    flows.push(host_flow(APP_PATH_FANOUT_CAP as u32 + 1 + i as u32, ip));
                }
            }
        }
    }
    // Slice 5 — the StrictSecondaryFailClosed default catch-all block (ALE only,
    // lowest band). Any rule-driven `Permit` above still wins.
    // (report is returned with the flows at the end)
    if matches!(behavior_mode, RouteBehaviorMode::StrictSecondaryFailClosed) {
        flows.push(FlowRule {
            verdict: Verdict::Block,
            precedence: Precedence {
                class: PrecedenceClass::DefaultCatchAll,
                ordinal: 0,
            },
            flow: FlowMatch {
                dst: DstMatch::Any,
                dst_port: None,
                protocol: None,
            },
            principal,
            app: AppScope::Any,
            egress: EgressConstraint::Any,
            coverage: Coverage::ConnectOnly,
        });
    }
    (flows, report)
}

/// Resolve an address match to its `(fanout_index, IPv4)` targets, replicating
/// `wfp_codegen`'s fan-out order + bounds exactly: `ExactIp` is a single target;
/// `ExactFqdn` fans out over the cached IPs (≤ `PER_HOSTNAME_IP_CAP`);
/// `SuffixDomain` / `Zone` fan out over cached subdomains — plus the apex for
/// `SuffixDomain` — (≤ `SUFFIX_FANOUT_BACKSTOP`) then each host's IPs (≤
/// `PER_HOSTNAME_IP_CAP`). The running fan-out index CLAMPS at
/// `SLOTS_PER_RULE - 1` instead of stopping (mirrors `emit_suffix_fanout`):
/// targets beyond the band share its top ordinal slot, so no host is dropped
/// while adjacent rules' bands stay disjoint.
fn resolve_targets(
    addr_match: &CanonicalAddressMatch,
    cache: &dyn FqdnCacheLookup,
) -> Vec<(u32, Ipv4Addr)> {
    let mut out = Vec::new();
    match addr_match {
        CanonicalAddressMatch::ExactIp(ip) => out.push((0, *ip)),
        CanonicalAddressMatch::ExactFqdn(host) => {
            for (i, ip) in cache
                .ips_for_hostname(host)
                .into_iter()
                .take(PER_HOSTNAME_IP_CAP)
                .enumerate()
            {
                out.push((i as u32, ip));
            }
        }
        // `SuffixDomain` covers its apex, `Zone` does not — the same split
        // `wfp_codegen::emit_suffix_fanout` makes, so the two views agree.
        CanonicalAddressMatch::SuffixDomain(suffix) => push_suffix_targets(
            &cache.hostnames_for_suffix_domain(suffix, SUFFIX_FANOUT_BACKSTOP),
            cache,
            &mut out,
        ),
        CanonicalAddressMatch::Zone(zone) => push_suffix_targets(
            &cache.hostnames_under_suffix(zone, SUFFIX_FANOUT_BACKSTOP),
            cache,
            &mut out,
        ),
    }
    out
}

/// Fan a resolved host list out to `(clamped fanout ordinal, IPv4)` targets.
fn push_suffix_targets(
    hosts: &[String],
    cache: &dyn FqdnCacheLookup,
    out: &mut Vec<(u32, Ipv4Addr)>,
) {
    let mut fanout_idx: u32 = 0;
    for host in hosts {
        for ip in cache
            .ips_for_hostname(host)
            .into_iter()
            .take(PER_HOSTNAME_IP_CAP)
        {
            out.push((fanout_idx.min(SLOTS_PER_RULE - 1), ip));
            fanout_idx += 1;
        }
    }
}

/// Plan the **per-destination kill-switch** (Sub-slices 4a + 4b) for `sid` — the
/// leak-proof `OnlyVia(Secondary)` pins over each protected IP, across every
/// selected protocol.
///
/// Neutral equivalent of `killswitch_codegen::kill_switch_filters` (the ALE pair
/// plus `packet_egress_pairs`). For each non-exempt, capped protected IP at
/// post-filter index `idx` it emits:
///
/// - **ALE-connect pair (4a)** — iff any ALE protocol (TCP/UDP) is selected: one
///   proto-agnostic [`FlowRule`], [`Coverage::ConnectOnly`], `ordinal = idx`,
///   egress [`EgressConstraint::OnlyVia`]`(Secondary)`.
/// - **Packet-layer flows (4b)** — one 16-slot window per destination
///   (`ordinal = idx * `[`PACKET_SLOTS_PER_DEST`]` + slot`), reproducing
///   `packet_egress_pairs`. When "Other" is selected: a proto-agnostic egress
///   pair (`OnlyVia`, [`Coverage::AllPackets`], slot 0) that cuts every protocol,
///   plus one `EgressConstraint::Any` permit per UN-selected protocol (in
///   `killswitch_codegen::unselected_named` order) so it keeps flowing. Otherwise:
///   one `OnlyVia` egress pair per selected named protocol (ICMP/IGMP/GRE/ESP, in
///   `killswitch_codegen::packet_named` order).
///
/// `lower_windows::lower_kill_switch` expands each flow into its WFP filter(s)
/// keyed on `(egress, coverage)`. Exempt IPs
/// (`nrr_platform_api::is_exempt_from_blocking`) are filtered and the set is
/// capped exactly as the current codegen does, so every `ordinal` reproduces the
/// kill-switch weights. All protocol vocabulary is the neutral [`L4Proto`]; the
/// WFP `ip_protocol` number is a lowering-time detail.
pub fn plan_kill_switch_destinations(
    sid: &str,
    protected_ips: &[Ipv4Addr],
    protocols: KillSwitchProtocols,
) -> Vec<FlowRule> {
    let principal = principal_scope(sid);
    let mut flows = Vec::new();
    for (idx, ip) in protected_ips
        .iter()
        .copied()
        .filter(|ip| !nrr_platform_api::is_exempt_from_blocking(*ip))
        .take(KILLSWITCH_MAX_DESTINATIONS)
        .enumerate()
    {
        let idx = idx as u32;
        // ALE-connect pair (4a): a proto-agnostic egress-conditional pin at
        // ordinal = idx. Present iff any ALE protocol (TCP or UDP) is selected —
        // the ALE pair is protocol-agnostic, so either one selected covers both.
        if protocols.tcp || protocols.udp {
            flows.push(kill_switch_flow(
                &principal,
                ip,
                None,
                EgressConstraint::OnlyVia(EgressRef::Secondary),
                Coverage::ConnectOnly,
                idx,
            ));
        }
        // Packet-layer flows (4b): one 16-slot window per destination — one
        // egress pair per selected NAMED packet protocol. By design the
        // proto-agnostic "Other" pair is GONE (see
        // `killswitch_codegen::KillSwitchProtocols::wants_packet_layer`).
        let base = idx * PACKET_SLOTS_PER_DEST;
        for (slot, proto) in selected_packet_protocols(protocols).into_iter().enumerate() {
            flows.push(kill_switch_flow(
                &principal,
                ip,
                Some(proto),
                EgressConstraint::OnlyVia(EgressRef::Secondary),
                Coverage::AllPackets,
                base + slot as u32,
            ));
        }
    }
    flows
}

/// Build one [`PrecedenceClass::KillSwitchPermit`] `Permit` flow over `ip`.
fn kill_switch_flow(
    principal: &PrincipalScope,
    ip: Ipv4Addr,
    protocol: Option<L4Proto>,
    egress: EgressConstraint,
    coverage: Coverage,
    ordinal: u32,
) -> FlowRule {
    FlowRule {
        verdict: Verdict::Permit,
        precedence: Precedence {
            class: PrecedenceClass::KillSwitchPermit,
            ordinal,
        },
        flow: FlowMatch {
            dst: DstMatch::HostV4(ip),
            dst_port: None,
            protocol,
        },
        principal: principal.clone(),
        app: AppScope::Any,
        egress,
        coverage,
    }
}

/// The named packet protocols (ICMP/IGMP/GRE/ESP) that ARE selected, in
/// `killswitch_codegen::packet_named` order — each gets its own egress pair.
fn selected_packet_protocols(p: KillSwitchProtocols) -> Vec<L4Proto> {
    let mut v = Vec::new();
    if p.icmp {
        v.push(L4Proto::Icmp);
    }
    if p.igmp {
        v.push(L4Proto::Igmp);
    }
    if p.gre {
        v.push(L4Proto::Gre);
    }
    if p.esp {
        v.push(L4Proto::Esp);
    }
    v
}

/// Plan the **catch-all (Mode-B) kill-switch** (Sub-slice 4c) for `sid` — the
/// blanket "block everything not exempted" for everything-via-secondary.
///
/// Neutral equivalent of `killswitch_codegen::catch_all_kill_switch_filters`. For
/// the selected `protocols` (with `server_ips` the tunnel-server host exemptions
/// and `local_subnets` the primary's connected subnets, both resolved by the
/// caller — the secondary LUID is a lowering-time concern) it emits, in the exact
/// codegen order so each `ordinal` reproduces the weight:
///
/// - **V4 exemptions** ([`PrecedenceClass::CatchAllExempt`], `ordinal = e`) — the
///   egress-via-secondary blanket permit, loopback `127/8`, link-local
///   `169.254/16`, limited broadcast, each server, each local subnet. Each is an
///   ALE flow ([`Coverage::ConnectOnly`]) plus, iff any packet protocol is
///   selected, a packet mirror ([`Coverage::AllPackets`]).
/// - **V4 ALE catch-all block** ([`PrecedenceClass::CatchAllBlock`],
///   [`Coverage::ConnectOnly`]) — proto-agnostic, always.
/// - **V4 packet blocks** (iff a packet protocol is selected) — reproducing
///   `packet_protocol_blocks`: with "Other", a proto-agnostic block-all plus a
///   lone permit per UN-selected protocol; otherwise one block per selected named
///   protocol.
/// - **IPv6 cut** (always) — loopback `::1/128` + link-local `fe80::/10`
///   exemptions over an `::/0` block-all, at BOTH V6 layers (Free's only IPv6
///   handling; independent of the V4 protocol mask).
///
/// Returns empty when there is no server exemption (arming the blanket block
/// without one would trap the tunnel's own reconnect) or no protocol is selected
/// — the planner-side safety valves. The zero-LUID fail-open is a lowering
/// concern (`lower_windows::lower_catch_all_kill_switch`).
pub fn plan_catch_all_kill_switch(
    sid: &str,
    server_ips: &[Ipv4Addr],
    local_subnets: &[(Ipv4Addr, u8)],
    protocols: KillSwitchProtocols,
) -> Vec<FlowRule> {
    let any_selected = protocols.tcp
        || protocols.udp
        || protocols.icmp
        || protocols.igmp
        || protocols.gre
        || protocols.esp
        || protocols.other;
    if server_ips.is_empty() || !any_selected {
        return Vec::new();
    }
    // `other` does not activate the packet layer
    // (mirrors `KillSwitchProtocols::wants_packet_layer`).
    let wants_packet = protocols.icmp || protocols.igmp || protocols.gre || protocols.esp;
    let principal = principal_scope(sid);
    let mut flows = Vec::new();

    // ── V4 exemptions, in codegen order (egress, loopback, link-local, broadcast,
    //    servers, local subnets). Each: an ALE flow + a packet mirror iff the
    //    packet layer is active. ──
    let mut exemptions: Vec<(DstMatch, EgressConstraint)> = vec![
        (
            DstMatch::Any,
            EgressConstraint::OnlyVia(EgressRef::Secondary),
        ),
        (
            DstMatch::SubnetV4 {
                net: Ipv4Addr::new(127, 0, 0, 0),
                prefix: 8,
            },
            EgressConstraint::Any,
        ),
        (
            DstMatch::SubnetV4 {
                net: Ipv4Addr::new(169, 254, 0, 0),
                prefix: 16,
            },
            EgressConstraint::Any,
        ),
        (DstMatch::HostV4(Ipv4Addr::BROADCAST), EgressConstraint::Any),
        // Local network control block: mDNS/LLMNR/IGMP never leave the link.
        (
            DstMatch::SubnetV4 {
                net: Ipv4Addr::new(224, 0, 0, 0),
                prefix: 24,
            },
            EgressConstraint::Any,
        ),
    ];
    for ip in server_ips {
        exemptions.push((DstMatch::HostV4(*ip), EgressConstraint::Any));
    }
    for (net, prefix) in local_subnets {
        exemptions.push((
            DstMatch::SubnetV4 {
                net: *net,
                prefix: *prefix,
            },
            EgressConstraint::Any,
        ));
    }
    for (e, (dst, egress)) in exemptions.into_iter().enumerate() {
        flows.push(catch_all_flow(
            &principal,
            Verdict::Permit,
            PrecedenceClass::CatchAllExempt,
            dst,
            egress.clone(),
            None,
            Coverage::ConnectOnly,
            e as u32,
        ));
        if wants_packet {
            flows.push(catch_all_flow(
                &principal,
                Verdict::Permit,
                PrecedenceClass::CatchAllExempt,
                dst,
                egress,
                None,
                Coverage::AllPackets,
                e as u32,
            ));
        }
    }

    // ── V4 ALE catch-all block (proto-agnostic, always). ──
    flows.push(catch_all_flow(
        &principal,
        Verdict::Block,
        PrecedenceClass::CatchAllBlock,
        DstMatch::Any,
        EgressConstraint::Any,
        None,
        Coverage::ConnectOnly,
        0,
    ));

    // ── V4 packet blocks (iff the packet layer is active) — one block per
    //    selected NAMED protocol; the "Other" block-all is GONE. ──
    if wants_packet {
        for (k, proto) in selected_packet_protocols(protocols).into_iter().enumerate() {
            flows.push(catch_all_flow(
                &principal,
                Verdict::Block,
                PrecedenceClass::CatchAllBlock,
                DstMatch::Any,
                EgressConstraint::Any,
                Some(proto),
                Coverage::AllPackets,
                k as u32,
            ));
        }
    }

    // ── IPv6 cut (always): loopback + link-local + link-local-multicast
    //    exemptions over an ::/0 block-all, at BOTH V6 layers (ALE + packet). ──
    push_ipv6_cut(&principal, &mut flows);

    flows
}

/// Append the IPv6 cut (Free's blanket IPv6 handling) — loopback `::1/128`,
/// link-local `fe80::/10` and link-local-multicast `ff02::/16` exemptions over
/// an `::/0` block-all, at BOTH V6 layers. Shared by the catch-all and
/// fail-closed block-all planners (`killswitch_codegen::catch_all_v6_filters`).
fn push_ipv6_cut(principal: &PrincipalScope, flows: &mut Vec<FlowRule>) {
    let v6_exempts = [
        DstMatch::SubnetV6 {
            net: Ipv6Addr::LOCALHOST,
            prefix: 128,
        },
        DstMatch::SubnetV6 {
            net: Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0),
            prefix: 10,
        },
        // Neighbour discovery, MLD, mDNS and DHCPv6 address the group, not
        // `fe80::` — cutting this scope breaks the link, leaks nothing.
        DstMatch::SubnetV6 {
            net: Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0),
            prefix: 16,
        },
    ];
    for (e, dst) in v6_exempts.into_iter().enumerate() {
        flows.push(catch_all_flow(
            principal,
            Verdict::Permit,
            PrecedenceClass::CatchAllExempt,
            dst,
            EgressConstraint::Any,
            None,
            Coverage::ConnectOnly,
            e as u32,
        ));
        flows.push(catch_all_flow(
            principal,
            Verdict::Permit,
            PrecedenceClass::CatchAllExempt,
            dst,
            EgressConstraint::Any,
            None,
            Coverage::AllPackets,
            e as u32,
        ));
    }
    let v6_all = DstMatch::SubnetV6 {
        net: Ipv6Addr::UNSPECIFIED,
        prefix: 0,
    };
    flows.push(catch_all_flow(
        principal,
        Verdict::Block,
        PrecedenceClass::CatchAllBlock,
        v6_all,
        EgressConstraint::Any,
        None,
        Coverage::ConnectOnly,
        0,
    ));
    flows.push(catch_all_flow(
        principal,
        Verdict::Block,
        PrecedenceClass::CatchAllBlock,
        v6_all,
        EgressConstraint::Any,
        None,
        Coverage::AllPackets,
        0,
    ));
}

/// Build one catch-all [`FlowRule`] (Sub-slices 4c/4d), `app = Any`.
#[allow(clippy::too_many_arguments)]
fn catch_all_flow(
    principal: &PrincipalScope,
    verdict: Verdict,
    class: PrecedenceClass,
    dst: DstMatch,
    egress: EgressConstraint,
    protocol: Option<L4Proto>,
    coverage: Coverage,
    ordinal: u32,
) -> FlowRule {
    FlowRule {
        verdict,
        precedence: Precedence { class, ordinal },
        flow: FlowMatch {
            dst,
            dst_port: None,
            protocol,
        },
        principal: principal.clone(),
        app: AppScope::Any,
        egress,
        coverage,
    }
}

// ── Sub-slice 4d — fail-closed + per-app kill-switch + primary-app exemption ────

/// A named-app scope carrying `pattern` as its `ALE_APP_ID` — the kill-switch app
/// filters put the pattern straight into `app_pattern` (no exe-path resolution),
/// so `exe_paths` holds the single pattern the Windows lowering reads.
fn app_scope(pattern: &str) -> AppScope {
    AppScope::Program {
        key: pattern.to_string(),
        exe_paths: vec![PathBuf::from(pattern)],
    }
}

/// The single ALE `ip_protocol` narrowing for a mask (neutral), mirroring
/// `KillSwitchProtocols::ale_protocol`: `None` when both or neither TCP/UDP are
/// selected (one proto-agnostic block covers both), else the one selected.
fn ale_protocol(p: KillSwitchProtocols) -> Option<L4Proto> {
    match (p.tcp, p.udp) {
        (true, true) | (false, false) => None,
        (true, false) => Some(L4Proto::Tcp),
        (false, true) => Some(L4Proto::Udp),
    }
}

/// Build one kill-switch / fail-closed [`FlowRule`] (Sub-slice 4d).
#[allow(clippy::too_many_arguments)]
fn ks_flow(
    principal: &PrincipalScope,
    verdict: Verdict,
    class: PrecedenceClass,
    dst: DstMatch,
    app: AppScope,
    egress: EgressConstraint,
    protocol: Option<L4Proto>,
    coverage: Coverage,
    ordinal: u32,
) -> FlowRule {
    FlowRule {
        verdict,
        precedence: Precedence { class, ordinal },
        flow: FlowMatch {
            dst,
            dst_port: None,
            protocol,
        },
        principal: principal.clone(),
        app,
        egress,
        coverage,
    }
}

/// Plan the **per-app kill-switch** (Sub-slice 4d) — the leak-proof
/// `OnlyVia(Secondary)` pin over each protected app, keyed on `ALE_APP_ID` instead
/// of a remote IP. Neutral equivalent of `killswitch_codegen::app_kill_switch_filters`.
///
/// ALE-connect only (the packet layer has no app context) and protocol-agnostic,
/// so it emits nothing unless a TCP/UDP protocol is selected — like the codegen.
/// One [`PrecedenceClass::KillSwitchPermit`] flow per app; `lower_kill_switch`
/// expands each into the ALE permit(luid)+block pair. Zero-LUID fail-open is a
/// lowering concern.
///
/// Main-named addresses need no rescue flows: the lowered per-app block sits
/// below the primary rule band, so the primary rules' own permits carry every
/// address the main link names — uncapped, unlike the per-(app, address) rescue
/// permits that ordering replaced.
pub fn plan_app_kill_switch(
    sid: &str,
    app_patterns: &[String],
    protocols: KillSwitchProtocols,
) -> Vec<FlowRule> {
    if !(protocols.tcp || protocols.udp) {
        return Vec::new();
    }
    let principal = principal_scope(sid);
    let mut flows = Vec::new();
    for (idx, pattern) in app_patterns
        .iter()
        .take(APP_KILLSWITCH_MAX_APPS)
        .enumerate()
    {
        flows.push(ks_flow(
            &principal,
            Verdict::Permit,
            PrecedenceClass::KillSwitchPermit,
            DstMatch::Any,
            app_scope(pattern),
            EgressConstraint::OnlyVia(EgressRef::Secondary),
            None,
            Coverage::ConnectOnly,
            idx as u32,
        ));
    }
    flows
}

/// Plan the **primary-app kill-switch exemption** (Sub-slice 4d) — one
/// unconditional ALE `Permit` per app pattern in the top exempt band, so a user's
/// deliberately primary-routed app (e.g. a VPN client bootstrapping over the
/// primary link) is never cut. Neutral equivalent of
/// `killswitch_codegen::primary_app_exempt_filters`.
///
/// A [`PrecedenceClass::CatchAllExempt`] flow with an [`AppScope::Program`] and no
/// egress condition; `lower_catch_all_kill_switch` maps it to the `APP_EXEMPT_BASE`
/// band. There is no block half — this is a pure exemption.
pub fn plan_primary_app_exempt(sid: &str, app_patterns: &[String]) -> Vec<FlowRule> {
    let principal = principal_scope(sid);
    app_patterns
        .iter()
        .take(KILLSWITCH_MAX_DESTINATIONS)
        .enumerate()
        .map(|(idx, pattern)| {
            ks_flow(
                &principal,
                Verdict::Permit,
                PrecedenceClass::CatchAllExempt,
                DstMatch::Any,
                app_scope(pattern),
                EgressConstraint::Any,
                None,
                Coverage::ConnectOnly,
                idx as u32,
            )
        })
        .collect()
}

/// Plan the **fail-closed per-destination block** (Sub-slice 4d) — the secondary
/// is unresolvable, so block each protected IP outright (no egress permit). Neutral
/// equivalent of `killswitch_codegen::fail_closed_block_destinations`.
///
/// Per non-exempt, capped IP at index `idx`: an ALE block narrowed to the ALE
/// protocol ([`PrecedenceClass::KillSwitchBlock`], if TCP/UDP selected) plus the
/// packet-layer blocks (reproducing `packet_protocol_blocks`): with "Other", a
/// proto-agnostic block-all plus a lone permit per UN-selected protocol; else one
/// block per selected named protocol. Empty when no protocol is selected.
pub fn plan_fail_closed_destinations(
    sid: &str,
    protected_ips: &[Ipv4Addr],
    protocols: KillSwitchProtocols,
) -> Vec<FlowRule> {
    let any_selected = protocols.tcp
        || protocols.udp
        || protocols.icmp
        || protocols.igmp
        || protocols.gre
        || protocols.esp
        || protocols.other;
    if !any_selected {
        return Vec::new();
    }
    let principal = principal_scope(sid);
    let ale_proto = ale_protocol(protocols);
    let mut flows = Vec::new();
    for (idx, ip) in protected_ips
        .iter()
        .copied()
        .filter(|ip| !nrr_platform_api::is_exempt_from_blocking(*ip))
        .take(KILLSWITCH_MAX_DESTINATIONS)
        .enumerate()
    {
        let idx = idx as u32;
        // ALE block (narrowed to the ALE protocol), if TCP/UDP selected.
        if protocols.tcp || protocols.udp {
            flows.push(ks_flow(
                &principal,
                Verdict::Block,
                PrecedenceClass::KillSwitchBlock,
                DstMatch::HostV4(ip),
                AppScope::Any,
                EgressConstraint::Any,
                ale_proto,
                Coverage::ConnectOnly,
                idx,
            ));
        }
        // Packet-layer blocks (the `idx * 16` window) — one block per selected
        // NAMED protocol; the "Other" block-all is GONE.
        let base = idx * PACKET_SLOTS_PER_DEST;
        for (k, proto) in selected_packet_protocols(protocols).into_iter().enumerate() {
            flows.push(ks_flow(
                &principal,
                Verdict::Block,
                PrecedenceClass::KillSwitchBlock,
                DstMatch::HostV4(ip),
                AppScope::Any,
                EgressConstraint::Any,
                Some(proto),
                Coverage::AllPackets,
                base + k as u32,
            ));
        }
    }
    flows
}

/// Plan the **fail-closed per-app block** (Sub-slice 4d) — block each protected
/// app at the ALE layer (proto-agnostic, no egress permit). Neutral equivalent of
/// `killswitch_codegen::fail_closed_block_apps`. Emits nothing unless TCP/UDP is
/// selected (ALE only).
pub fn plan_fail_closed_apps(
    sid: &str,
    app_patterns: &[String],
    protocols: KillSwitchProtocols,
) -> Vec<FlowRule> {
    if !(protocols.tcp || protocols.udp) {
        return Vec::new();
    }
    let principal = principal_scope(sid);
    app_patterns
        .iter()
        .take(APP_KILLSWITCH_MAX_APPS)
        .enumerate()
        .map(|(idx, pattern)| {
            ks_flow(
                &principal,
                Verdict::Block,
                PrecedenceClass::KillSwitchBlock,
                DstMatch::Any,
                app_scope(pattern),
                EgressConstraint::Any,
                None,
                Coverage::ConnectOnly,
                idx as u32,
            )
        })
        .collect()
}

/// Plan the DoH/DoT lockdown blocks as neutral
/// [`FlowRule`]s — the neutral equivalent of
/// [`crate::killswitch_codegen::doh_dot_block_filters`]. Per resolver IP: a
/// [`PrecedenceClass::DohBlock`] `Block` on `443` for TCP then UDP; then, when
/// `block_dot`, a global `Block` on `853` for TCP then UDP. Emission order fixes
/// the ascending `ordinal` so `lower_windows::lower_doh_dot_block` reproduces the
/// exact same arbitration order as the codegen.
pub fn plan_doh_dot_block(sid: &str, resolver_ips: &[Ipv4Addr], block_dot: bool) -> Vec<FlowRule> {
    let principal = principal_scope(sid);
    let mut flows = Vec::new();
    let mut ordinal = 0u32;
    let flow_for = |dst: DstMatch, port: u16, ordinal: u32| FlowRule {
        verdict: Verdict::Block,
        precedence: Precedence {
            class: PrecedenceClass::DohBlock,
            ordinal,
        },
        flow: FlowMatch {
            dst,
            dst_port: Some(port),
            protocol: None, // set per proto below
        },
        principal: principal.clone(),
        app: AppScope::Any,
        egress: EgressConstraint::Any,
        coverage: Coverage::ConnectOnly,
    };
    for ip in resolver_ips
        .iter()
        .copied()
        .filter(|ip| !nrr_platform_api::is_exempt_from_blocking(*ip))
        .take(crate::killswitch_codegen::DOH_MAX_RESOLVER_IPS)
    {
        for proto in [L4Proto::Tcp, L4Proto::Udp] {
            let mut f = flow_for(DstMatch::HostV4(ip), 443, ordinal);
            f.flow.protocol = Some(proto);
            flows.push(f);
            ordinal += 1;
        }
    }
    if block_dot {
        for proto in [L4Proto::Tcp, L4Proto::Udp] {
            let mut f = flow_for(DstMatch::Any, 853, ordinal);
            f.flow.protocol = Some(proto);
            flows.push(f);
            ordinal += 1;
        }
    }
    flows
}

/// Plan the **fail-closed Mode-B block-all** (Sub-slice 4d) — the secondary is
/// gone, so block ALL egress for this user except the safe exemptions. Neutral
/// equivalent of `killswitch_codegen::fail_closed_block_all_filters`.
///
/// Unlike [`plan_catch_all_kill_switch`] it arms WITHOUT a resolvable secondary
/// (there is none — so no egress-via-secondary permit) and WITHOUT requiring
/// server IPs. The exemptions are loopback / link-local / broadcast / servers /
/// liveness-probe targets / local subnets (ALE + packet mirror), plus opt-in
/// DNS-over-primary (port-53
/// UDP/TCP, ALE only). The ALE catch-all block is narrowed to the ALE protocol and
/// emitted only when TCP/UDP is selected; the packet blocks reproduce
/// `packet_protocol_blocks`; the IPv6 cut always applies. Empty when no protocol is
/// selected.
// Mirrors `FailClosedExemptions` field-by-field as plain slices — the
// equivalence tests drive both sides from the same locals, and a struct here
// would just duplicate the codegen's.
#[allow(clippy::too_many_arguments)]
pub fn plan_fail_closed_block_all(
    sid: &str,
    server_ips: &[Ipv4Addr],
    probe_target_ips: &[Ipv4Addr],
    local_subnets: &[(Ipv4Addr, u8)],
    primary_dest_ips: &[Ipv4Addr],
    known_direct_ips: &[Ipv4Addr],
    allow_dns_over_primary: bool,
    protocols: KillSwitchProtocols,
) -> Vec<FlowRule> {
    let any_selected = protocols.tcp
        || protocols.udp
        || protocols.icmp
        || protocols.igmp
        || protocols.gre
        || protocols.esp
        || protocols.other;
    if !any_selected {
        return Vec::new();
    }
    // `other` does not activate the packet layer
    // (mirrors `KillSwitchProtocols::wants_packet_layer`).
    let wants_packet = protocols.icmp || protocols.igmp || protocols.gre || protocols.esp;
    let principal = principal_scope(sid);
    let mut flows = Vec::new();

    // ── ALE exemptions (+ packet mirror iff the packet layer is active), in
    //    codegen order — NO egress permit (the secondary is gone). ──
    let mut exemptions: Vec<(DstMatch, EgressConstraint)> = vec![
        (
            DstMatch::SubnetV4 {
                net: Ipv4Addr::new(127, 0, 0, 0),
                prefix: 8,
            },
            EgressConstraint::Any,
        ),
        (
            DstMatch::SubnetV4 {
                net: Ipv4Addr::new(169, 254, 0, 0),
                prefix: 16,
            },
            EgressConstraint::Any,
        ),
        (DstMatch::HostV4(Ipv4Addr::BROADCAST), EgressConstraint::Any),
        // Local network control block: mDNS/LLMNR/IGMP never leave the link.
        (
            DstMatch::SubnetV4 {
                net: Ipv4Addr::new(224, 0, 0, 0),
                prefix: 24,
            },
            EgressConstraint::Any,
        ),
    ];
    for ip in server_ips {
        exemptions.push((DstMatch::HostV4(*ip), EgressConstraint::Any));
    }
    // Liveness-probe targets — mirrors the codegen's placement between the
    // bootstrap servers and the local subnets.
    for ip in probe_target_ips {
        exemptions.push((DstMatch::HostV4(*ip), EgressConstraint::Any));
    }
    for (net, prefix) in local_subnets {
        exemptions.push((
            DstMatch::SubnetV4 {
                net: *net,
                prefix: *prefix,
            },
            EgressConstraint::Any,
        ));
    }
    let mut e = 0u32;
    for (dst, egress) in exemptions {
        flows.push(catch_all_flow(
            &principal,
            Verdict::Permit,
            PrecedenceClass::CatchAllExempt,
            dst,
            egress.clone(),
            None,
            Coverage::ConnectOnly,
            e,
        ));
        if wants_packet {
            flows.push(catch_all_flow(
                &principal,
                Verdict::Permit,
                PrecedenceClass::CatchAllExempt,
                dst,
                egress,
                None,
                Coverage::AllPackets,
                e,
            ));
        }
        e += 1;
    }
    // Known-DIRECT destinations: an ALE exempt now (matching
    // the codegen's within-layer order: …, subnets, direct, dns-53, block); the
    // packet twin is emitted after the known-primary permits below. Unlike
    // known-primary these have NO rule permit at all, so the ALE half is what
    // keeps a plain primary-path site reachable under the block-all.
    // Mirrors `killswitch_codegen::exempt_direct_host`.
    for ip in known_direct_ips
        .iter()
        .copied()
        .filter(|ip| !nrr_platform_api::is_exempt_from_blocking(*ip))
        .take(KILLSWITCH_MAX_DESTINATIONS)
    {
        flows.push(catch_all_flow(
            &principal,
            Verdict::Permit,
            PrecedenceClass::CatchAllExempt,
            DstMatch::HostV4(ip),
            EgressConstraint::Any,
            None,
            Coverage::ConnectOnly,
            e,
        ));
        e += 1;
    }
    // Known-primary destinations get a
    // packet-ONLY proto-agnostic permit (no ALE mirror — TCP/UDP already escape
    // via the primary rule permit), so ping/ICMP to a whitelisted host survives
    // the packet block-all. Skip loopback/link-local, cap like every other
    // destination list. Mirrors `killswitch_codegen::packet_permit_primary_host`.
    if wants_packet {
        for ip in primary_dest_ips
            .iter()
            .copied()
            .filter(|ip| !nrr_platform_api::is_exempt_from_blocking(*ip))
            .take(KILLSWITCH_MAX_DESTINATIONS)
        {
            flows.push(catch_all_flow(
                &principal,
                Verdict::Permit,
                PrecedenceClass::CatchAllExempt,
                DstMatch::HostV4(ip),
                EgressConstraint::Any,
                None,
                Coverage::AllPackets,
                e,
            ));
            e += 1;
        }
        // Packet twin of the known-direct ALE exempt above, after the
        // known-primary permits (the codegen's packet-layer emission order).
        // Mirrors `killswitch_codegen::packet_permit_direct_host`.
        for ip in known_direct_ips
            .iter()
            .copied()
            .filter(|ip| !nrr_platform_api::is_exempt_from_blocking(*ip))
            .take(KILLSWITCH_MAX_DESTINATIONS)
        {
            flows.push(catch_all_flow(
                &principal,
                Verdict::Permit,
                PrecedenceClass::CatchAllExempt,
                DstMatch::HostV4(ip),
                EgressConstraint::Any,
                None,
                Coverage::AllPackets,
                e,
            ));
            e += 1;
        }
    }
    // Opt-in DNS-over-primary: port-53 UDP then TCP, ALE only (no packet mirror).
    if allow_dns_over_primary {
        for proto in [L4Proto::Udp, L4Proto::Tcp] {
            flows.push(FlowRule {
                verdict: Verdict::Permit,
                precedence: Precedence {
                    class: PrecedenceClass::CatchAllExempt,
                    ordinal: e,
                },
                flow: FlowMatch {
                    dst: DstMatch::Any,
                    dst_port: Some(53),
                    protocol: Some(proto),
                },
                principal: principal.clone(),
                app: AppScope::Any,
                egress: EgressConstraint::Any,
                coverage: Coverage::ConnectOnly,
            });
            e += 1;
        }
    }

    // ── ALE catch-all block (narrowed to the ALE protocol), if TCP/UDP selected. ──
    if protocols.tcp || protocols.udp {
        flows.push(catch_all_flow(
            &principal,
            Verdict::Block,
            PrecedenceClass::CatchAllBlock,
            DstMatch::Any,
            EgressConstraint::Any,
            ale_protocol(protocols),
            Coverage::ConnectOnly,
            0,
        ));
    }

    // ── V4 packet blocks (iff the packet layer is active) — one block per
    //    selected NAMED protocol; the "Other" block-all is GONE. ──
    if wants_packet {
        for (k, proto) in selected_packet_protocols(protocols).into_iter().enumerate() {
            flows.push(catch_all_flow(
                &principal,
                Verdict::Block,
                PrecedenceClass::CatchAllBlock,
                DstMatch::Any,
                EgressConstraint::Any,
                Some(proto),
                Coverage::AllPackets,
                k as u32,
            ));
        }
    }

    // ── IPv6 cut (always). ──
    push_ipv6_cut(&principal, &mut flows);

    flows
}

// ── Slice 5 — system route table (route_codegen) ───────────────────────────────

/// Plan the **system route table** (Slice 5) for `mode` into neutral
/// [`RouteIntent`]s — the neutral equivalent of `route_codegen::generate_routes`
/// (the routing mechanism; the WFP planners above are the blocking one).
///
/// - **`PreferPrimary`** (mode A): secondary-bound rules → `/32` via
///   [`EgressRef::Secondary`], through the denylist-filtered cache view; with a
///   primary target (`has_primary`), the four `/2` [`COUNTER_OVERLAY`] blocks via
///   [`EgressRef::Primary`] so non-rule traffic rides the primary.
/// - **`PreferSecondaryWhenAvailable` / `StrictSecondaryFailClosed`** (mode B): the
///   `/1` split-default overlay ([`OVERLAY_LOW`] + [`OVERLAY_HIGH`]) via the
///   secondary, plus (with a primary target) the primary-bound rules pulled back
///   as `/32` exceptions via the primary.
///
/// `has_primary` gates the primary-egress routes (no primary bound → the codegen's
/// `PrimaryExceptionsUnavailable` path, which emits none). `denied` is the
/// shared-IP policy denylist applied to the mode-A secondary fan-out only.
/// `lower_windows::lower_routes` resolves each [`EgressRef`] to its concrete
/// gateway + interface index. Pure: no I/O beyond the injected cache reader.
pub fn plan_routes(
    mode: RouteBehaviorMode,
    rule_book: &CanonicalRuleBook,
    has_primary: bool,
    cache: &dyn FqdnCacheLookup,
    app_observations: &dyn AppObservationLookup,
    denied: &HashSet<Ipv4Addr>,
    // Where an exact-address rule sits against a zone rule, from the
    // principal's `zone_priority_over_ip`. The two can only contest the same
    // address in the ownership arbiter, so this is the whole of its reach here.
    order: crate::address_ownership::ZoneVsIpOrder,
) -> Vec<RouteIntent> {
    let mut routes = Vec::new();
    // Ownership from the UNFILTERED cache: the denylist view exists to trim
    // what goes to the tunnel, and reading it here would understate what the
    // main link claims.
    let ownership =
        crate::address_ownership::AddressOwnership::resolve_with_order(rule_book, cache, order);
    match mode {
        RouteBehaviorMode::PreferPrimary => {
            // Secondary rules → /32 via the secondary, minus any declined shared IP.
            let secondary_cache = DenylistFilteredCache::new(cache, denied);
            let mut seen = BTreeSet::new();
            plan_host_routes(
                &rule_book.secondary,
                EgressRef::Secondary,
                &secondary_cache,
                &crate::address_ownership::AppDestinationGate::for_rule_set(
                    &ownership,
                    app_observations,
                    &rule_book.secondary,
                ),
                &ownership,
                &mut seen,
                &mut routes,
            );
            // Mode-A counter-overlay: four /2 via the primary (needs a primary).
            if has_primary {
                for (net, prefix) in COUNTER_OVERLAY {
                    routes.push(overlay_intent(net, prefix, EgressRef::Primary));
                }
            }
        }
        RouteBehaviorMode::PreferSecondaryWhenAvailable
        | RouteBehaviorMode::StrictSecondaryFailClosed => {
            // Own the split-default overlay → all traffic to the tunnel.
            routes.push(overlay_intent(
                OVERLAY_LOW.0,
                OVERLAY_LOW.1,
                EgressRef::Secondary,
            ));
            routes.push(overlay_intent(
                OVERLAY_HIGH.0,
                OVERLAY_HIGH.1,
                EgressRef::Secondary,
            ));
            // Carve primary-bound rules back onto the primary as /32 exceptions.
            if has_primary {
                let mut seen = BTreeSet::new();
                plan_host_routes(
                    &rule_book.primary,
                    EgressRef::Primary,
                    cache,
                    &crate::address_ownership::AppDestinationGate::for_rule_set(
                        &ownership,
                        app_observations,
                        &rule_book.primary,
                    ),
                    &ownership,
                    &mut seen,
                    &mut routes,
                );
            }
        }
    }
    routes
}

/// Plan the `/32` host routes for one ruleset (neutral equivalent of
/// `route_codegen::generate_secondary_routes`), deduped by destination across
/// rules via `seen`. Skips disabled / `Block` rules and non-routable
/// destinations, capped per rule at [`MAX_ROUTES_PER_RULE`].
///
/// An APPLICATION-only rule routes the destinations the app has been observed
/// using, exactly as the Windows codegen does: the app's permit is conditional
/// on the traffic leaving that link, so without the route the packet leaves the
/// other one, misses its own permit and is dropped.
#[allow(clippy::too_many_arguments)]
fn plan_host_routes(
    rules: &CanonicalRuleSet,
    egress: EgressRef,
    cache: &dyn FqdnCacheLookup,
    gate: &crate::address_ownership::AppDestinationGate<'_>,
    ownership: &crate::address_ownership::AddressOwnership,
    seen: &mut BTreeSet<Ipv4Addr>,
    out: &mut Vec<RouteIntent>,
) {
    let link = match egress {
        EgressRef::Primary => crate::address_ownership::Link::Main,
        _ => crate::address_ownership::Link::Additional,
    };
    for rule in rules.rules() {
        if !rule.enabled || matches!(rule.action, RuleAction::Block) {
            continue;
        }
        // A rule carrying BOTH conditions matches as AND, and no route table
        // scopes a route to a process — routing its address would ignore the
        // application half and move every other process too.
        if rule.app_match.is_some() && rule.address_match.is_some() {
            continue;
        }
        let mut per_rule = 0usize;
        if let Some(app) = rule.app_match.as_ref() {
            let pattern = match &app.pattern {
                CanonicalAppPattern::Exact(s) | CanonicalAppPattern::Glob(s) => s.as_str(),
            };
            for ip in gate.admit(pattern, link).admitted {
                if !push_host_route(ip, &egress, seen, out, &mut per_rule) {
                    break;
                }
            }
            continue;
        }
        // The same gate the Windows route codegen applies: an address the main
        // link's rules also name stays on the main link.
        let steerable = |ip: Ipv4Addr| ownership.address_rule_may_steer(ip, link);
        match &rule.address_match {
            Some(CanonicalAddressMatch::ExactIp(ip)) => {
                if steerable(*ip) {
                    push_host_route(*ip, &egress, seen, out, &mut per_rule);
                }
            }
            Some(CanonicalAddressMatch::ExactFqdn(host)) => {
                for ip in cache
                    .ips_for_hostname(host)
                    .into_iter()
                    .take(PER_HOSTNAME_IP_CAP)
                {
                    if !steerable(ip) {
                        continue;
                    }
                    if !push_host_route(ip, &egress, seen, out, &mut per_rule) {
                        break;
                    }
                }
            }
            Some(CanonicalAddressMatch::SuffixDomain(_)) | Some(CanonicalAddressMatch::Zone(_)) => {
                // `*.suffix` covers its apex, a zone does not — the same split
                // `route_codegen::fanout_suffix` makes, so the neutral plan and
                // the Windows route codegen produce the same destinations.
                let hosts = match &rule.address_match {
                    Some(CanonicalAddressMatch::SuffixDomain(suffix)) => {
                        cache.hostnames_for_suffix_domain(suffix, SUFFIX_FANOUT_BACKSTOP)
                    }
                    Some(CanonicalAddressMatch::Zone(zone)) => {
                        cache.hostnames_under_suffix(zone, SUFFIX_FANOUT_BACKSTOP)
                    }
                    _ => Vec::new(),
                };
                'outer: for sub in hosts {
                    for ip in cache
                        .ips_for_hostname(&sub)
                        .into_iter()
                        .take(PER_HOSTNAME_IP_CAP)
                    {
                        if !steerable(ip) {
                            continue;
                        }
                        if !push_host_route(ip, &egress, seen, out, &mut per_rule) {
                            break 'outer;
                        }
                    }
                }
            }
            None => {}
        }
    }
}

/// Append a `/32` route intent for `ip` (deduped, per-rule capped), mirroring
/// `route_codegen::push_route`. Returns `false` only on a per-rule cap hit so the
/// caller stops fanning out; a non-routable or already-seen IP returns `true`
/// (skip, keep scanning).
fn push_host_route(
    ip: Ipv4Addr,
    egress: &EgressRef,
    seen: &mut BTreeSet<Ipv4Addr>,
    out: &mut Vec<RouteIntent>,
    per_rule: &mut usize,
) -> bool {
    if *per_rule >= MAX_ROUTES_PER_RULE {
        return false;
    }
    // Never route a non-routable destination (an ad-block hosts file pins a domain
    // to loopback/unspecified); loopback never leaves the box.
    if is_non_routable_v4(&ip) {
        return true;
    }
    if !seen.insert(ip) {
        return true;
    }
    out.push(RouteIntent {
        dst: DstMatch::HostV4(ip),
        egress: egress.clone(),
        metric: SECONDARY_ROUTE_METRIC,
        table: RouteTableRef::Main,
    });
    *per_rule += 1;
    true
}

/// One overlay route intent (a `/1` split-default half or a `/2` counter-overlay
/// block) via `egress`.
fn overlay_intent(net: Ipv4Addr, prefix: u8, egress: EgressRef) -> RouteIntent {
    RouteIntent {
        dst: DstMatch::SubnetV4 { net, prefix },
        egress,
        metric: SECONDARY_ROUTE_METRIC,
        table: RouteTableRef::Main,
    }
}

/// An empty denylist for callers with no shared-IP policy in play.
/// The floor a blanket block may never cut, as neutral flows.
///
/// The strict mode's default catch-all blocks everything no rule permitted —
/// including loopback, DHCP, the link's own control traffic and the tunnel's
/// handshake. Those are not traffic anyone routes; cutting them takes the
/// machine off its own network. On Windows this floor was carried by a branch
/// in the orchestrator, so the neutral plan — the one Linux enforces — had a
/// block with nothing underneath it.
///
/// Order mirrors the shipped `killswitch_codegen::default_block_exemptions`:
/// loopback, link-local, broadcast, the local network control block, then the
/// tunnel servers and the attached subnets. `server_ips` / `local_subnets` may
/// be empty (a machine whose route table has not been read yet); the
/// machine-independent part of the floor is planned regardless.
pub fn plan_default_block_exemptions(
    sid: &str,
    server_ips: &[Ipv4Addr],
    local_subnets: &[(Ipv4Addr, u8)],
) -> Vec<FlowRule> {
    let principal = principal_scope(sid);
    let mut dsts: Vec<DstMatch> = vec![
        DstMatch::SubnetV4 {
            net: Ipv4Addr::new(127, 0, 0, 0),
            prefix: 8,
        },
        DstMatch::SubnetV4 {
            net: Ipv4Addr::new(169, 254, 0, 0),
            prefix: 16,
        },
        DstMatch::HostV4(Ipv4Addr::BROADCAST),
        DstMatch::SubnetV4 {
            net: Ipv4Addr::new(224, 0, 0, 0),
            prefix: 24,
        },
    ];
    dsts.extend(server_ips.iter().map(|ip| DstMatch::HostV4(*ip)));
    dsts.extend(
        local_subnets
            .iter()
            .map(|(net, prefix)| DstMatch::SubnetV4 {
                net: *net,
                prefix: *prefix,
            }),
    );

    dsts.into_iter()
        .enumerate()
        .map(|(ordinal, dst)| FlowRule {
            verdict: Verdict::Permit,
            precedence: Precedence {
                class: PrecedenceClass::CatchAllExempt,
                ordinal: ordinal as u32,
            },
            flow: FlowMatch {
                dst,
                dst_port: None,
                protocol: None,
            },
            principal: principal.clone(),
            app: AppScope::Any,
            egress: EgressConstraint::Any,
            coverage: Coverage::ConnectOnly,
        })
        .collect()
}

/// The fake-IP relay's pool, as neutral flows.
///
/// Two things have to be true at once for a fake-routed host to work: an
/// application must be able to open a connection to the virtual address under
/// ANY posture (including a blanket block), and — while the UDP path is off —
/// QUIC must die at connect time rather than handshake against a stack that
/// will drop its datagrams. Hence a permit for the pool and, conditionally, a
/// UDP veto above it. Both sit in [`PrecedenceClass::FakeIpPool`]: the pool is
/// machinery a rule is served THROUGH, not a destination anyone named.
///
/// `ordinal` order is the emission order of the shipped codegen (v4 permit, v6
/// permit, v4 UDP veto, v6 UDP veto), so the veto outranks the permit it
/// qualifies.
pub fn plan_fake_ip_pool(
    sid: &str,
    pool: &nrr_platform_api::fake_ip::FakeIpPoolConfig,
    udp_relay_enabled: bool,
) -> Vec<FlowRule> {
    let principal = principal_scope(sid);
    let mut flows = Vec::new();
    let mut push = |ordinal: u32, verdict: Verdict, dst: DstMatch, protocol: Option<L4Proto>| {
        flows.push(FlowRule {
            verdict,
            precedence: Precedence {
                class: PrecedenceClass::FakeIpPool,
                ordinal,
            },
            flow: FlowMatch {
                dst,
                dst_port: None,
                protocol,
            },
            principal: principal.clone(),
            app: AppScope::Any,
            egress: EgressConstraint::Any,
            coverage: Coverage::ConnectOnly,
        })
    };

    push(
        0,
        Verdict::Permit,
        DstMatch::SubnetV4 {
            net: pool.v4_base,
            prefix: pool.v4_prefix_len,
        },
        None,
    );
    if let Some(v6) = pool.v6_base {
        push(
            1,
            Verdict::Permit,
            DstMatch::SubnetV6 {
                net: v6,
                prefix: pool.v6_prefix_len,
            },
            None,
        );
    }
    if !udp_relay_enabled {
        push(
            2,
            Verdict::Block,
            DstMatch::SubnetV4 {
                net: pool.v4_base,
                prefix: pool.v4_prefix_len,
            },
            Some(L4Proto::Udp),
        );
        if let Some(v6) = pool.v6_base {
            push(
                3,
                Verdict::Block,
                DstMatch::SubnetV6 {
                    net: v6,
                    prefix: pool.v6_prefix_len,
                },
                Some(L4Proto::Udp),
            );
        }
    }
    flows
}

/// Name what an address rule failed to resolve to, so the caller can say which
/// rule is waiting on DNS rather than reporting silence.
///
/// An `ExactIp` always resolves; the rest depend on the cache being warm. The
/// backstop is reported separately: a fan-out that STOPPED is a different fact
/// from one that found nothing.
fn note_address_resolution(
    report: &mut PlanReport,
    rule: &CanonicalRule,
    addr_match: &CanonicalAddressMatch,
    targets: &[(u32, Ipv4Addr)],
    cache: &dyn FqdnCacheLookup,
) {
    let name = match addr_match {
        CanonicalAddressMatch::ExactIp(_) => return,
        CanonicalAddressMatch::ExactFqdn(host) => host,
        CanonicalAddressMatch::SuffixDomain(suffix) => suffix,
        CanonicalAddressMatch::Zone(zone) => zone,
    };
    if targets.is_empty() {
        report.unresolved_hosts.push(name.clone());
        return;
    }
    let subdomains = match addr_match {
        CanonicalAddressMatch::SuffixDomain(suffix) => {
            cache.hostnames_for_suffix_domain(suffix, SUFFIX_FANOUT_BACKSTOP)
        }
        CanonicalAddressMatch::Zone(zone) => {
            cache.hostnames_under_suffix(zone, SUFFIX_FANOUT_BACKSTOP)
        }
        _ => return,
    };
    if subdomains.len() >= SUFFIX_FANOUT_BACKSTOP {
        report.truncated_suffixes.push((
            rule.id.as_str().to_string(),
            name.clone(),
            SUFFIX_FANOUT_BACKSTOP,
        ));
    }
}

/// What planning could NOT do, in the words the GUI shows the user.
///
/// A rule that resolves to nothing emits no flow, and a plan cannot say why:
/// the absence looks identical to "the user has no such rule". The shipped
/// codegen answered this with a diagnostics stream; the neutral planner answers
/// it with this report, returned alongside the flows so a caller cannot take
/// the plan and quietly drop the reasons.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PlanReport {
    /// Application rules whose name/glob resolved to no executable on disk.
    pub unresolved_apps: Vec<String>,
    /// Hostnames, suffixes and zones with nothing cached under them.
    pub unresolved_hosts: Vec<String>,
    /// Application rules that resolved to more executables than the fan-out
    /// allows: `(app, cap, resolved)`.
    pub over_capped_apps: Vec<(String, usize, usize)>,
    /// Destinations an application rule observed but did not take over, because
    /// the main link's own rules name them: `(app, address)`.
    pub claimed_by_main: Vec<(String, Ipv4Addr)>,
    /// Suffix/zone fan-outs stopped at the backstop: `(rule_id, suffix, cap)`.
    pub truncated_suffixes: Vec<(String, String, usize)>,
}

// ── Derived sets ────────────────────────────────────────────────────────────
//
// What the kill-switch, its exemptions and the GUI need is not the plan itself
// but a handful of sets READ BACK off it. Deriving them here — from the planned
// flows — is deliberate: the planner already did the fan-out, the caps and the
// arbitration, and computing the same sets a second time from the rule book is
// how the guarded set drifts from the routed one.

/// The destinations a role's rules route, in planning order (deduplicated).
///
/// Only `Permit` flows contribute: a Block rule's destinations are being
/// dropped, not routed, and protecting them would be the kill switch cancelling
/// the user's own rule.
pub fn route_destinations(flows: &[FlowRule], role: RouteRole) -> Vec<Ipv4Addr> {
    let mut seen = std::collections::HashSet::new();
    flows
        .iter()
        .filter(|f| {
            f.verdict == Verdict::Permit && f.precedence.class == PrecedenceClass::RouteRule(role)
        })
        .filter_map(|f| match f.flow.dst {
            DstMatch::HostV4(ip) => Some(ip),
            _ => None,
        })
        .filter(|ip| seen.insert(*ip))
        .collect()
}

/// The VPN clients' own executables, resolved from the built-in globs to real
/// on-disk paths.
///
/// A blanket block that seals the tunnel client's own traffic turns an outage
/// into a permanent one, so these processes are spared. Resolution happens here
/// rather than at lowering time because the apply layer needs a real path: a
/// raw glob in an app-id filter is silently dropped. Deduplicated
/// case-insensitively and sorted, so the exemption set does not depend on the
/// resolver's ordering.
pub fn vpn_default_exempt_paths(resolver: &dyn AppPathResolver) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut paths: Vec<String> = crate::killswitch_codegen::DEFAULT_VPN_EXEMPT_PATTERNS
        .iter()
        .flat_map(|glob| resolver.resolve(glob))
        .map(|p| p.to_string_lossy().into_owned())
        .filter(|p| seen.insert(p.to_ascii_lowercase()))
        .collect();
    paths.sort_unstable();
    paths
}

/// The destinations that reached a role's plan through OBSERVATION of an
/// application, not through a rule naming the address.
///
/// The kill switch treats them differently on purpose: such an address is
/// already guarded by its application's own permit/block pair, and pinning it a
/// second time per-destination is what made a shared address unreachable for
/// every other process. The two are told apart by the ordinal window each rule
/// slot reserves — paths occupy `0..APP_PATH_FANOUT_CAP`, observed addresses
/// start one past it — which is the same arithmetic `lower_windows` uses to
/// rebuild the literal weight.
pub fn app_observed_destinations(flows: &[FlowRule], role: RouteRole) -> Vec<Ipv4Addr> {
    let mut seen = std::collections::HashSet::new();
    flows
        .iter()
        .filter(|f| {
            f.verdict == Verdict::Permit && f.precedence.class == PrecedenceClass::RouteRule(role)
        })
        .filter(|f| f.precedence.ordinal % SLOTS_PER_RULE > APP_PATH_FANOUT_CAP as u32)
        .filter_map(|f| match f.flow.dst {
            DstMatch::HostV4(ip) => Some(ip),
            _ => None,
        })
        .filter(|ip| seen.insert(*ip))
        .collect()
}

/// The executable paths a role's application rules route, in planning order
/// (deduplicated). These are what an app-scoped kill-switch pins and what the
/// fail-closed exemption band spares.
pub fn route_app_paths(flows: &[FlowRule], role: RouteRole) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for flow in flows.iter().filter(|f| {
        f.verdict == Verdict::Permit && f.precedence.class == PrecedenceClass::RouteRule(role)
    }) {
        if let AppScope::Program { exe_paths, .. } = &flow.app {
            for path in exe_paths {
                let path = path.to_string_lossy().into_owned();
                if seen.insert(path.clone()) {
                    out.push(path);
                }
            }
        }
    }
    out
}

#[cfg(test)]
static NO_DENYLIST: std::sync::OnceLock<HashSet<Ipv4Addr>> = std::sync::OnceLock::new();

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_domain::canonical::{CanonicalRule, CanonicalRuleSet};
    use nrr_domain::RuleId;
    use std::collections::HashMap;

    fn rule(id: &str, m: CanonicalAddressMatch, action: RuleAction) -> CanonicalRule {
        CanonicalRule {
            id: RuleId(id.into()),
            enabled: true,
            address_match: Some(m),
            app_match: None,
            comment: String::new(),
            action,
            origin: None,
        }
    }

    fn exact_ip_rule(id: &str, addr: Ipv4Addr) -> CanonicalRule {
        rule(id, CanonicalAddressMatch::ExactIp(addr), RuleAction::Route)
    }

    fn book(primary: Vec<CanonicalRule>, secondary: Vec<CanonicalRule>) -> CanonicalRuleBook {
        CanonicalRuleBook {
            primary: CanonicalRuleSet::from_rules(primary),
            secondary: CanonicalRuleSet::from_rules(secondary),
        }
    }

    /// In-memory cache mock (host→IPs, suffix→subdomains) for the fan-out tests.
    #[derive(Default)]
    struct MapCache {
        hosts: HashMap<String, Vec<Ipv4Addr>>,
        suffixes: HashMap<String, Vec<String>>,
    }
    impl FqdnCacheLookup for MapCache {
        fn ips_for_hostname(&self, h: &str) -> Vec<Ipv4Addr> {
            self.hosts.get(h).cloned().unwrap_or_default()
        }
        fn hostnames_under_suffix(&self, s: &str, _limit: usize) -> Vec<String> {
            self.suffixes.get(s).cloned().unwrap_or_default()
        }
    }

    #[derive(Default)]
    struct MapResolver(HashMap<String, Vec<std::path::PathBuf>>);
    impl AppPathResolver for MapResolver {
        fn resolve(&self, pat: &str) -> Vec<std::path::PathBuf> {
            self.0.get(pat).cloned().unwrap_or_default()
        }
    }

    #[derive(Default)]
    struct MapObs(HashMap<String, Vec<Ipv4Addr>>);
    impl AppObservationLookup for MapObs {
        fn ips_for_app(&self, app: &str) -> Vec<Ipv4Addr> {
            self.0.get(app).cloned().unwrap_or_default()
        }
    }

    /// A `PlannerInput` from a cache, resolver, and observations.
    fn planner_input<'a>(
        cache: &'a MapCache,
        resolver: &'a MapResolver,
        obs: &'a MapObs,
    ) -> PlannerInput<'a> {
        PlannerInput {
            secondary_ip_denylist: NO_DENYLIST.get_or_init(HashSet::new),
            fqdn_cache: cache,
            app_resolver: resolver,
            app_observations: obs,
            zone_priority_over_ip: false,
        }
    }

    /// The shared-IP policy decides what the tunnel may claim, and the plan has
    /// to be built behind that decision — the Windows codegen reads a
    /// denylist-filtered cache for secondary rules and the raw one for primary.
    /// Planning without it put declined addresses back on the tunnel, and
    /// shifted every ordinal after them, which is what made the live and
    /// neutral pipelines disagree on real data.
    #[test]
    fn a_declined_shared_address_is_kept_off_the_tunnel() {
        let shared = Ipv4Addr::new(203, 0, 113, 7);
        let own = Ipv4Addr::new(203, 0, 113, 8);
        let cache = MapCache {
            hosts: HashMap::from([("site.test".to_string(), vec![shared, own])]),
            suffixes: HashMap::new(),
        };
        let resolver = MapResolver::default();
        let obs = MapObs::default();
        let declined: HashSet<Ipv4Addr> = HashSet::from([shared]);
        // One rule, on the additional route: the policy is about what the
        // TUNNEL may claim. (A main-link rule naming the same host would settle
        // the address by ownership instead, which is a different mechanism.)
        let rule_book = book(
            Vec::new(),
            vec![rule(
                "r-2",
                CanonicalAddressMatch::ExactFqdn("site.test".into()),
                RuleAction::Route,
            )],
        );

        let planned = |denylist: &HashSet<Ipv4Addr>| -> Vec<(RouteRole, Ipv4Addr)> {
            let input = PlannerInput {
                fqdn_cache: &cache,
                app_resolver: &resolver,
                app_observations: &obs,
                zone_priority_over_ip: false,
                secondary_ip_denylist: denylist,
            };
            plan_route_rules(
                &rule_book,
                "S-1-5-21-DENY",
                RouteBehaviorMode::PreferPrimary,
                &input,
            )
            .0
            .into_iter()
            .filter_map(|f| match (f.precedence.class, f.flow.dst) {
                (PrecedenceClass::RouteRule(role), DstMatch::HostV4(ip)) => Some((role, ip)),
                _ => None,
            })
            .collect()
        };

        let with_policy = planned(&declined);
        assert!(
            !with_policy.contains(&(RouteRole::Secondary, shared)),
            "the tunnel must not claim an address the policy declined: {with_policy:?}",
        );
        assert!(with_policy.contains(&(RouteRole::Secondary, own)));

        // Positive control: without the denylist the tunnel claims it, which is
        // exactly the plan the live pipeline does NOT produce.
        let without_policy = planned(&HashSet::new());
        assert!(without_policy.contains(&(RouteRole::Secondary, shared)));
    }

    fn app_rule(id: &str, pattern: &str, action: RuleAction) -> CanonicalRule {
        CanonicalRule {
            id: RuleId(id.into()),
            enabled: true,
            address_match: None,
            app_match: Some(nrr_domain::canonical::CanonicalAppMatch {
                pattern: CanonicalAppPattern::Exact(pattern.into()),
                include_child_processes: false,
            }),
            comment: String::new(),
            action,
            origin: None,
        }
    }

    /// A Linux principal must survive planning. Parsing the partition key as a
    /// Windows SID silently produced an UNSCOPED rule, and unscoped means "every
    /// user on this machine" — one user's routing policy would have governed
    /// everyone else's traffic.
    #[test]
    fn a_unix_principal_scopes_the_flows_it_plans() {
        let rb = book(
            vec![exact_ip_rule("p-0", Ipv4Addr::new(203, 0, 113, 1))],
            vec![],
        );
        let (cache, resolver, obs) = (
            MapCache::default(),
            MapResolver::default(),
            MapObs::default(),
        );
        let flows = plan_route_rules(
            &rb,
            "unix:uid:1000",
            RouteBehaviorMode::PreferPrimary,
            &planner_input(&cache, &resolver, &obs),
        )
        .0;

        assert!(!flows.is_empty(), "the rule must plan at least one flow");
        for flow in &flows {
            let scoped = flow
                .principal
                .0
                .as_ref()
                .and_then(|p| p.as_unix_uid())
                .expect("every flow must carry the uid it was planned for");
            assert_eq!(scoped, 1000);
        }
    }

    /// The baseline belongs to no user, so it plans unscoped on purpose — the
    /// one case where a missing principal is the answer rather than a bug.
    #[test]
    fn the_baseline_plans_without_a_principal() {
        let rb = book(
            vec![exact_ip_rule("p-0", Ipv4Addr::new(203, 0, 113, 1))],
            vec![],
        );
        let (cache, resolver, obs) = (
            MapCache::default(),
            MapResolver::default(),
            MapObs::default(),
        );
        let flows = plan_route_rules(
            &rb,
            nrr_domain::user_principal::BASELINE_PRINCIPAL,
            RouteBehaviorMode::PreferPrimary,
            &planner_input(&cache, &resolver, &obs),
        )
        .0;

        assert!(!flows.is_empty());
        assert!(flows.iter().all(|f| f.principal.0.is_none()));
    }

    #[test]
    fn plans_exact_ip_permits_primary_then_secondary_with_slot_ordinals() {
        let rb = book(
            vec![
                exact_ip_rule("p-0", Ipv4Addr::new(203, 0, 113, 1)),
                exact_ip_rule("p-1", Ipv4Addr::new(203, 0, 113, 2)),
            ],
            vec![exact_ip_rule("s-0", Ipv4Addr::new(198, 51, 100, 9))],
        );
        let flows = plan_route_rules(
            &rb,
            "S-1-5-21-A",
            RouteBehaviorMode::PreferPrimary,
            &planner_input(
                &MapCache::default(),
                &MapResolver::default(),
                &MapObs::default(),
            ),
        )
        .0;
        assert_eq!(flows.len(), 3);
        assert_eq!(
            flows[0].precedence.class,
            PrecedenceClass::RouteRule(RouteRole::Primary)
        );
        assert_eq!(flows[0].precedence.ordinal, 0);
        assert_eq!(flows[1].precedence.ordinal, SLOTS_PER_RULE);
        assert_eq!(
            flows[2].precedence.class,
            PrecedenceClass::RouteRule(RouteRole::Secondary)
        );
        assert_eq!(flows[2].precedence.ordinal, 0);
        assert_eq!(
            flows[0].principal.0.as_ref().map(|p| p.as_stored()),
            Some("S-1-5-21-A")
        );
        assert!(flows.iter().all(|f| f.verdict == Verdict::Permit));
    }

    #[test]
    fn plans_fqdn_fanout_and_block() {
        let mut cache = MapCache::default();
        cache.hosts.insert(
            "api.example.com".into(),
            vec![Ipv4Addr::new(203, 0, 113, 1), Ipv4Addr::new(203, 0, 113, 2)],
        );
        let rb = book(
            vec![rule(
                "p-fqdn",
                CanonicalAddressMatch::ExactFqdn("api.example.com".into()),
                RuleAction::Route,
            )],
            vec![rule(
                "s-block",
                CanonicalAddressMatch::ExactIp(Ipv4Addr::new(10, 0, 0, 9)),
                RuleAction::Block,
            )],
        );
        let flows = plan_route_rules(
            &rb,
            "S-1-5-21-A",
            RouteBehaviorMode::PreferPrimary,
            &planner_input(&cache, &MapResolver::default(), &MapObs::default()),
        )
        .0;
        // Two fan-out permits (ordinals 0,1) + one block flow.
        assert_eq!(flows.len(), 3);
        assert_eq!(flows[0].precedence.ordinal, 0);
        assert_eq!(flows[1].precedence.ordinal, 1);
        assert!(flows[..2].iter().all(|f| f.verdict == Verdict::Permit));
        let blk = &flows[2];
        assert_eq!(blk.verdict, Verdict::Block);
        assert_eq!(blk.precedence.class, PrecedenceClass::HardBlock);
        assert_eq!(blk.coverage, Coverage::AllPackets);
    }

    #[test]
    fn skips_disabled_and_unresolved_rules() {
        let mut disabled = exact_ip_rule("d", Ipv4Addr::new(10, 0, 0, 1));
        disabled.enabled = false;
        // An app rule with no resolved exe/observed IP → no flow (like the
        // current codegen's diagnostic-only path).
        let app = app_rule("a", "notinstalled.exe", RuleAction::Route);
        // A cold-cache ExactFqdn resolves to nothing → no flow.
        let cold = rule(
            "f",
            CanonicalAddressMatch::ExactFqdn("uncached.example".into()),
            RuleAction::Route,
        );
        let rb = book(vec![disabled, app, cold], vec![]);
        assert!(plan_route_rules(
            &rb,
            "S-1-5-21-A",
            RouteBehaviorMode::PreferPrimary,
            &planner_input(
                &MapCache::default(),
                &MapResolver::default(),
                &MapObs::default()
            )
        )
        .0
        .is_empty());
    }

    // ── Slices 1–3 EQUIVALENCE — the Phase-B proof (Windows only) ───────────────
    // The neutral pipeline `plan_route_rules` → `lower_windows::lower_route_rules`
    // must produce the SAME enforcement as today's `wfp_codegen::generate_filters`
    // for the full rule-driven surface (ExactIp + ExactFqdn/Suffix fan-out + Block
    // + Application: per-exe ALE_APP_ID filters and observed-dest /32s), checked
    // by the behavioral oracle (weights/ids ignored, arbitration order preserved).
    // `lower_windows` lives in the Windows backend → this proof is `#[cfg(windows)]`.
    #[cfg(windows)]
    #[test]
    fn slices123_neutral_pipeline_matches_current_codegen() {
        use crate::wfp_codegen::{generate_filters, CodegenInput};
        use nrr_platform_api::enforcement::EnforcementPlan;
        use nrr_platform_api::wfp_behavioral::{
            arbitration_order_preserved, behaviorally_equivalent,
        };

        let mut cache = MapCache::default();
        cache.hosts.insert(
            "api.example.com".into(),
            vec![Ipv4Addr::new(203, 0, 113, 1), Ipv4Addr::new(203, 0, 113, 2)],
        );
        cache.suffixes.insert(
            "corp.example".into(),
            vec!["a.corp.example".into(), "b.corp.example".into()],
        );
        cache.hosts.insert(
            "a.corp.example".into(),
            vec![Ipv4Addr::new(198, 51, 100, 1)],
        );
        cache.hosts.insert(
            "b.corp.example".into(),
            vec![Ipv4Addr::new(198, 51, 100, 2)],
        );

        // App rule: resolves to two exe paths + one observed destination IP.
        let mut resolver = MapResolver::default();
        resolver.0.insert(
            "aiclient.exe".into(),
            vec![
                std::path::PathBuf::from(r"C:\Apps\aiclient.exe"),
                std::path::PathBuf::from(r"C:\Apps2\aiclient.exe"),
            ],
        );
        let mut obs = MapObs::default();
        obs.0
            .insert("aiclient.exe".into(), vec![Ipv4Addr::new(23, 10, 20, 159)]);

        let sid = "S-1-5-21-1-2-3-1001";
        let rb = book(
            vec![
                exact_ip_rule("p-ip", Ipv4Addr::new(192, 0, 2, 5)),
                rule(
                    "p-fqdn",
                    CanonicalAddressMatch::ExactFqdn("api.example.com".into()),
                    RuleAction::Route,
                ),
            ],
            vec![
                rule(
                    "s-suffix",
                    CanonicalAddressMatch::SuffixDomain("corp.example".into()),
                    RuleAction::Route,
                ),
                rule(
                    "s-block",
                    CanonicalAddressMatch::ExactIp(Ipv4Addr::new(10, 0, 0, 9)),
                    RuleAction::Block,
                ),
                app_rule("s-app", "aiclient.exe", RuleAction::Route),
            ],
        );

        let denylist = std::collections::HashSet::new();
        let current = generate_filters(CodegenInput {
            sid,
            rule_book: &rb,
            behavior_mode: nrr_domain::RouteBehaviorMode::PreferPrimary,
            fqdn_cache: &cache,
            app_observations: &obs,
            app_resolver: &resolver,
            secondary_ip_denylist: &denylist,
            zone_priority_over_ip: false,
        });

        let plan = EnforcementPlan {
            principal: nrr_platform_api::enforcement::UserPrincipal::from_windows_sid(sid)
                .expect("valid sid"),
            flows: plan_route_rules(
                &rb,
                sid,
                nrr_domain::RouteBehaviorMode::PreferPrimary,
                &planner_input(&cache, &resolver, &obs),
            )
            .0,
            routes: Vec::new(),
            policy_rules: Vec::new(),
        };
        let lowered = nrr_platform_windows::lower_windows::lower_route_rules(&plan);

        // 1 ExactIp + 2 fqdn + 2 suffix + (1 ALE block + 1 mirror) + (2 app-id +
        // 1 observed /32) = 10 filters.
        assert_eq!(current.filters.len(), 10, "sanity: ten filters");
        assert!(
            behaviorally_equivalent(&current.filters, &lowered),
            "neutral pipeline must install the SAME filters as the current codegen"
        );
        assert!(
            arbitration_order_preserved(&current.filters, &lowered),
            "neutral pipeline must preserve the arbitration order"
        );
    }

    // ── Sub-slice 4a EQUIVALENCE — per-destination kill-switch (Windows only) ───
    // `plan_kill_switch_destinations` → `lower_windows::lower_kill_switch` must
    // produce the SAME leak-proof pins as `killswitch_codegen::kill_switch_filters`
    // for the ALE (TCP/UDP) case: each protected IP → a permit(luid) + block pair.
    #[cfg(windows)]
    #[test]
    fn slice4a_kill_switch_matches_current_codegen() {
        use crate::killswitch_codegen::{kill_switch_filters, KillSwitchProtocols};
        use nrr_platform_api::enforcement::EnforcementPlan;
        use nrr_platform_api::wfp_behavioral::{
            arbitration_order_preserved, behaviorally_equivalent,
        };

        let sid = "S-1-5-21-1-2-3-1001";
        let luid = 0x1234_5678_u64;
        let ips = [
            Ipv4Addr::new(203, 0, 113, 5),
            Ipv4Addr::new(198, 51, 100, 9),
        ];
        // TCP/UDP only → ALE pairs, no packet-layer (multi-protocol) pairs.
        let protos = KillSwitchProtocols {
            tcp: true,
            udp: true,
            icmp: false,
            igmp: false,
            gre: false,
            esp: false,
            other: false,
        };
        let current = kill_switch_filters(sid, &ips, luid, protos);

        let plan = EnforcementPlan {
            principal: nrr_platform_api::enforcement::UserPrincipal::from_windows_sid(sid)
                .expect("valid sid"),
            flows: plan_kill_switch_destinations(sid, &ips, protos),
            routes: Vec::new(),
            policy_rules: Vec::new(),
        };
        let lowered = nrr_platform_windows::lower_windows::lower_kill_switch(&plan, luid);

        assert_eq!(current.len(), 4, "2 destinations × (permit + block)");
        assert!(
            behaviorally_equivalent(&current, &lowered),
            "kill-switch pins must be behaviourally equivalent"
        );
        assert!(
            arbitration_order_preserved(&current, &lowered),
            "kill-switch permit must still outrank its block"
        );
    }

    /// The pool is the machinery every fake-routed host is served through, so
    /// the neutral pipeline has to reproduce it exactly — including the UDP
    /// veto that must sit ABOVE the permit it qualifies. Both switch positions
    /// are exercised: with the relay on, the vetoes are absent, and a pipeline
    /// that emitted them unconditionally would still pass the off-case alone.
    #[cfg(windows)]
    #[test]
    fn slice6_fake_ip_pool_matches_current_codegen() {
        use crate::killswitch_codegen::fake_ip_pool_permit_filters;
        use nrr_platform_api::enforcement::EnforcementPlan;
        use nrr_platform_api::fake_ip::FakeIpPoolConfig;
        use nrr_platform_api::wfp_behavioral::{
            arbitration_order_preserved, behaviorally_equivalent,
        };

        let sid = "S-1-5-21-1-2-3-1001";
        let pool = FakeIpPoolConfig::default();

        for udp_relay_enabled in [false, true] {
            let current = fake_ip_pool_permit_filters(sid, &pool, udp_relay_enabled);
            let plan = EnforcementPlan {
                principal: nrr_platform_api::enforcement::UserPrincipal::from_windows_sid(sid)
                    .expect("valid sid"),
                flows: plan_fake_ip_pool(sid, &pool, udp_relay_enabled),
                routes: Vec::new(),
                policy_rules: Vec::new(),
            };
            let lowered = nrr_platform_windows::lower_windows::lower_fake_ip_pool(&plan);

            assert!(
                !current.is_empty(),
                "the pool always permits itself — otherwise this proves nothing"
            );
            assert!(
                behaviorally_equivalent(&current, &lowered),
                "pool filters must match (udp_relay_enabled={udp_relay_enabled}):
current={current:#?}
lowered={lowered:#?}"
            );
            assert!(
                arbitration_order_preserved(&current, &lowered),
                "the UDP veto must keep outranking the pool permit"
            );
        }
    }

    /// The floor under the strict default block. Lowered with NO tunnel LUID
    /// on purpose: the floor exists whether or not a tunnel is up, and the
    /// posture that needs a LUID (the blanket block and its egress permit) is
    /// exactly what must NOT appear in that case.
    #[cfg(windows)]
    #[test]
    fn slice7_default_block_exemptions_match_current_codegen() {
        use crate::killswitch_codegen::{default_block_exemptions, FailClosedExemptions};
        use nrr_platform_api::enforcement::EnforcementPlan;
        use nrr_platform_api::wfp_behavioral::{
            arbitration_order_preserved, behaviorally_equivalent,
        };

        let sid = "S-1-5-21-1-2-3-1001";
        let server_ips = vec![Ipv4Addr::new(203, 0, 113, 5)];
        let local_subnets = vec![(Ipv4Addr::new(192, 168, 1, 0), 24)];

        let current = default_block_exemptions(
            sid,
            &FailClosedExemptions {
                bootstrap_server_ips: server_ips.clone(),
                local_subnets: local_subnets.clone(),
                foreign_tunnel_luids: Vec::new(),
                ..Default::default()
            },
        );
        assert!(!current.is_empty(), "the floor is never empty");

        let plan = EnforcementPlan {
            principal: nrr_platform_api::enforcement::UserPrincipal::from_windows_sid(sid)
                .expect("valid sid"),
            flows: plan_default_block_exemptions(sid, &server_ips, &local_subnets),
            routes: Vec::new(),
            policy_rules: Vec::new(),
        };
        let lowered = nrr_platform_windows::lower_windows::lower_catch_all_kill_switch(&plan, 0);

        assert!(
            behaviorally_equivalent(&current, &lowered),
            "the floor must match:
current={current:#?}
lowered={lowered:#?}"
        );
        assert!(
            arbitration_order_preserved(&current, &lowered),
            "the floor's own order is what the codegen's running weight encodes"
        );
    }

    /// The kill switch and the GUI do not consume the plan — they consume sets
    /// READ BACK off it. Until those sets come from the plan, the live codegen
    /// cannot be switched off no matter how equal the filters are.
    #[test]
    fn slice8_derived_sets_match_current_codegen() {
        use crate::wfp_codegen::{generate_filters, CodegenInput};

        let mut cache = MapCache::default();
        cache.hosts.insert(
            "api.example.com".into(),
            vec![Ipv4Addr::new(203, 0, 113, 1), Ipv4Addr::new(203, 0, 113, 2)],
        );
        cache.suffixes.insert(
            "corp.example".into(),
            vec!["a.corp.example".into(), "b.corp.example".into()],
        );
        cache.hosts.insert(
            "a.corp.example".into(),
            vec![Ipv4Addr::new(198, 51, 100, 1)],
        );
        cache.hosts.insert(
            "b.corp.example".into(),
            vec![Ipv4Addr::new(198, 51, 100, 2)],
        );
        let mut resolver = MapResolver::default();
        resolver.0.insert(
            "aiclient.exe".into(),
            vec![
                std::path::PathBuf::from(r"C:\Apps\aiclient.exe"),
                std::path::PathBuf::from(r"C:\Apps2\aiclient.exe"),
            ],
        );
        // One of the built-in VPN globs resolves here, so the exemption set is
        // NOT empty — two empty lists would agree about nothing.
        resolver.0.insert(
            "*vpn*".into(),
            vec![std::path::PathBuf::from(
                r"C:\Program Files\Acme VPN\acmevpn.exe",
            )],
        );
        let mut obs = MapObs::default();
        obs.0
            .insert("aiclient.exe".into(), vec![Ipv4Addr::new(23, 10, 20, 159)]);

        let sid = "S-1-5-21-1-2-3-1001";
        let rb = book(
            vec![
                exact_ip_rule("p-ip", Ipv4Addr::new(192, 0, 2, 5)),
                rule(
                    "p-fqdn",
                    CanonicalAddressMatch::ExactFqdn("api.example.com".into()),
                    RuleAction::Route,
                ),
            ],
            vec![
                rule(
                    "s-suffix",
                    CanonicalAddressMatch::SuffixDomain("corp.example".into()),
                    RuleAction::Route,
                ),
                rule(
                    "s-block",
                    CanonicalAddressMatch::ExactIp(Ipv4Addr::new(10, 0, 0, 9)),
                    RuleAction::Block,
                ),
                app_rule("s-app", "aiclient.exe", RuleAction::Route),
            ],
        );
        let denylist = std::collections::HashSet::new();
        let current = generate_filters(CodegenInput {
            sid,
            rule_book: &rb,
            behavior_mode: nrr_domain::RouteBehaviorMode::PreferPrimary,
            fqdn_cache: &cache,
            app_observations: &obs,
            app_resolver: &resolver,
            secondary_ip_denylist: &denylist,
            zone_priority_over_ip: false,
        });
        let flows = plan_route_rules(
            &rb,
            sid,
            nrr_domain::RouteBehaviorMode::PreferPrimary,
            &planner_input(&cache, &resolver, &obs),
        )
        .0;

        // Compared as SETS. The shipped order is an artefact of WFP slot
        // packing — the codegen reads its addresses back out of packed chunks,
        // whose bucket order comes from an FNV hash — while the plan keeps them
        // in planning order. Neither order carries policy: these addresses each
        // get their own permit/block pair, and pairs for different destinations
        // never arbitrate against each other. What the switch-over WILL change
        // is the ordinals, hence the literal weights, hence a one-off churn on
        // the first apply after it.
        let sorted = |mut v: Vec<Ipv4Addr>| {
            v.sort_unstable();
            v
        };
        assert_eq!(
            sorted(route_destinations(&flows, RouteRole::Secondary)),
            sorted(current.secondary_dest_ips.clone()),
            "the kill switch protects what the tunnel routes"
        );
        assert_eq!(
            sorted(route_destinations(&flows, RouteRole::Primary)),
            sorted(current.primary_dest_ips.clone()),
            "the block-all spares what the main link routes"
        );
        assert_eq!(
            route_app_paths(&flows, RouteRole::Secondary),
            current.secondary_app_patterns,
            "an app the tunnel routes is pinned by its own pair"
        );
        assert_eq!(
            route_app_paths(&flows, RouteRole::Primary),
            current.primary_app_patterns,
            "an app the main link routes is never a leak to cut"
        );
        assert_eq!(
            sorted(app_observed_destinations(&flows, RouteRole::Secondary)),
            sorted(current.app_observed_secondary_ips.clone()),
            "an address learned from watching an app is guarded by that app's pair"
        );
        // Positive control for the ordinal window: the fixture's app rule DOES
        // contribute an observed address, so an empty answer would be a passing
        // test that proves nothing.
        assert_eq!(
            app_observed_destinations(&flows, RouteRole::Secondary),
            vec![Ipv4Addr::new(23, 10, 20, 159)],
        );
        assert_eq!(
            vpn_default_exempt_paths(&resolver),
            current.vpn_default_exempt_paths,
            "the tunnel client's own exemption set is resolved the same way"
        );
        assert!(
            !current.vpn_default_exempt_paths.is_empty(),
            "positive control: the fixture resolves one VPN client"
        );
    }

    /// The report is the half of the codegen's answer the plan cannot carry: a
    /// rule that resolved to nothing emits no flow, and silence reads as "no
    /// such rule". Every list here has a fixture behind it — an app that does
    /// not resolve, a host nobody cached, a zone with nothing under it and an
    /// address both links claim — so an empty report would fail the test.
    #[test]
    fn slice9_plan_report_matches_current_codegen_diagnostics() {
        use crate::wfp_codegen::{generate_filters, CodegenDiagnostic, CodegenInput};

        let mut cache = MapCache::default();
        cache
            .hosts
            .insert("known.example".into(), vec![Ipv4Addr::new(203, 0, 113, 9)]);
        let mut resolver = MapResolver::default();
        resolver.0.insert(
            "known.exe".into(),
            vec![std::path::PathBuf::from(r"C:\Apps\known.exe")],
        );
        let mut obs = MapObs::default();
        // The app watched an address the MAIN link's own rule names: the app
        // rule does not take it over, and the user is told which one it was.
        obs.0
            .insert("known.exe".into(), vec![Ipv4Addr::new(203, 0, 113, 9)]);

        let sid = "S-1-5-21-1-2-3-1001";
        let rb = book(
            vec![rule(
                "p-known",
                CanonicalAddressMatch::ExactFqdn("known.example".into()),
                RuleAction::Route,
            )],
            vec![
                rule(
                    "s-cold",
                    CanonicalAddressMatch::ExactFqdn("cold.example".into()),
                    RuleAction::Route,
                ),
                rule(
                    "s-zone",
                    CanonicalAddressMatch::Zone("empty.zone".into()),
                    RuleAction::Route,
                ),
                app_rule("s-missing-app", "ghost.exe", RuleAction::Route),
                app_rule("s-app", "known.exe", RuleAction::Route),
            ],
        );

        let denylist = std::collections::HashSet::new();
        let current = generate_filters(CodegenInput {
            sid,
            rule_book: &rb,
            behavior_mode: nrr_domain::RouteBehaviorMode::PreferPrimary,
            fqdn_cache: &cache,
            app_observations: &obs,
            app_resolver: &resolver,
            secondary_ip_denylist: &denylist,
            zone_priority_over_ip: false,
        });
        let (_, report) = plan_route_rules(
            &rb,
            sid,
            nrr_domain::RouteBehaviorMode::PreferPrimary,
            &planner_input(&cache, &resolver, &obs),
        );

        let mut codegen_apps: Vec<String> = Vec::new();
        let mut codegen_hosts: Vec<String> = Vec::new();
        let mut codegen_claimed: Vec<(String, Ipv4Addr)> = Vec::new();
        for diag in &current.diagnostics {
            match diag {
                CodegenDiagnostic::AppUnresolved { app, .. } => codegen_apps.push(app.clone()),
                CodegenDiagnostic::HostnameUnresolved { hostname, .. } => {
                    codegen_hosts.push(hostname.clone())
                }
                CodegenDiagnostic::SuffixEmpty { suffix, .. } => codegen_hosts.push(suffix.clone()),
                CodegenDiagnostic::ZoneEmpty { zone, .. } => codegen_hosts.push(zone.clone()),
                CodegenDiagnostic::AppDestinationClaimedByPrimary { app, ip, .. } => {
                    codegen_claimed.push((app.clone(), *ip))
                }
                _ => {}
            }
        }

        let sorted = |mut v: Vec<String>| {
            v.sort();
            v
        };
        assert_eq!(
            sorted(report.unresolved_apps.clone()),
            sorted(codegen_apps.clone()),
            "an app rule pointing at nothing installed"
        );
        assert_eq!(
            sorted(report.unresolved_hosts.clone()),
            sorted(codegen_hosts.clone()),
            "a rule waiting on DNS, and a zone with nothing under it"
        );
        assert_eq!(
            report.claimed_by_main.clone(),
            codegen_claimed.clone(),
            "an address the main link named is not the app rule's to take"
        );

        // Positive controls: each list is non-empty, so an all-empty report
        // could not pass this test by agreeing about nothing.
        assert_eq!(codegen_apps, vec!["ghost.exe".to_string()]);
        assert_eq!(sorted(codegen_hosts), vec!["cold.example", "empty.zone"]);
        assert_eq!(
            codegen_claimed,
            vec![("known.exe".to_string(), Ipv4Addr::new(203, 0, 113, 9))]
        );
    }

    /// The two caps in the report. Both are silent truncations in the plan —
    /// filters simply stop appearing — so the only place a user can learn that
    /// a rule was cut short is this report.
    #[test]
    fn slice9_plan_report_names_both_caps() {
        use crate::wfp_codegen::{generate_filters, CodegenDiagnostic, CodegenInput};

        let mut cache = MapCache::default();
        // A zone whose fan-out hits the backstop.
        let hosts: Vec<String> = (0..SUFFIX_FANOUT_BACKSTOP)
            .map(|i| format!("h{i}.wide.zone"))
            .collect();
        for (i, h) in hosts.iter().enumerate() {
            cache.hosts.insert(
                h.clone(),
                vec![Ipv4Addr::new(
                    10,
                    ((i >> 16) & 0xff) as u8,
                    ((i >> 8) & 0xff) as u8,
                    (i & 0xff) as u8,
                )],
            );
        }
        cache.suffixes.insert("wide.zone".into(), hosts);

        // An app resolving to more executables than the fan-out allows.
        let mut resolver = MapResolver::default();
        resolver.0.insert(
            "many.exe".into(),
            (0..(APP_PATH_FANOUT_CAP + 1))
                .map(|i| std::path::PathBuf::from(format!(r"C:\Apps\{i}\many.exe")))
                .collect(),
        );
        let obs = MapObs::default();

        let sid = "S-1-5-21-1-2-3-1001";
        let rb = book(
            Vec::new(),
            vec![
                rule(
                    "s-wide",
                    CanonicalAddressMatch::Zone("wide.zone".into()),
                    RuleAction::Route,
                ),
                app_rule("s-many", "many.exe", RuleAction::Route),
            ],
        );
        let denylist = std::collections::HashSet::new();
        let current = generate_filters(CodegenInput {
            sid,
            rule_book: &rb,
            behavior_mode: nrr_domain::RouteBehaviorMode::PreferPrimary,
            fqdn_cache: &cache,
            app_observations: &obs,
            app_resolver: &resolver,
            secondary_ip_denylist: &denylist,
            zone_priority_over_ip: false,
        });
        let (_, report) = plan_route_rules(
            &rb,
            sid,
            nrr_domain::RouteBehaviorMode::PreferPrimary,
            &planner_input(&cache, &resolver, &obs),
        );

        let codegen_truncated: Vec<(String, String, usize)> = current
            .diagnostics
            .iter()
            .filter_map(|d| match d {
                CodegenDiagnostic::SuffixTruncated {
                    rule_id,
                    suffix,
                    cap,
                } => Some((rule_id.clone(), suffix.clone(), *cap)),
                _ => None,
            })
            .collect();
        let codegen_over_capped: Vec<(String, usize, usize)> = current
            .diagnostics
            .iter()
            .filter_map(|d| match d {
                CodegenDiagnostic::AppOverCapped {
                    app, cap, resolved, ..
                } => Some((app.clone(), *cap as usize, *resolved)),
                _ => None,
            })
            .collect();

        assert_eq!(report.truncated_suffixes, codegen_truncated);
        assert_eq!(report.over_capped_apps, codegen_over_capped);
        // Positive controls: both caps really fired in this fixture.
        assert_eq!(
            codegen_truncated,
            vec![(
                "s-wide".to_string(),
                "wide.zone".to_string(),
                SUFFIX_FANOUT_BACKSTOP
            )]
        );
        assert_eq!(
            codegen_over_capped,
            vec![(
                "many.exe".to_string(),
                APP_PATH_FANOUT_CAP as usize,
                APP_PATH_FANOUT_CAP as usize + 1
            )]
        );
    }

    // ── DoH/DoT lockdown on LINUX ───────────────────────────────────────────────
    // Windows needs its own `lower_doh_dot_block` because WFP packs addresses
    // into OR-condition slots; nftables has no such shape, so the lockdown
    // lowers through the ordinary flow path. This test is what says so — the
    // generic path was believed to swallow `DohBlock`, and nothing measured it.
    #[cfg(not(windows))]
    #[test]
    fn the_doh_lockdown_lowers_to_nftables_through_the_ordinary_flow_path() {
        use nrr_platform_api::enforcement::EnforcementPlan;
        use nrr_platform_linux::lower_linux::{lower_plan, EgressNames};
        use nrr_platform_linux::nft_ir::{NftMatch, NftVerdict};

        let principal = nrr_platform_api::enforcement::UserPrincipal::from_linux_uid(1000);
        let sid = principal.as_stored().to_string();
        let resolvers = [Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(77, 88, 8, 8)];
        let plan = EnforcementPlan {
            principal,
            flows: plan_doh_dot_block(&sid, &resolvers, true),
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
        assert!(
            lowered.unsupported.is_empty(),
            "no DoH flow may be reported unsupported: {:?}",
            lowered.unsupported
        );

        // Every resolver is cut on 443 for both transports, and the global DoT
        // port is cut for both — the same twelve verdicts the Windows codegen
        // installs, expressed as ten nft rules (the two `Any:853` cuts carry no
        // address).
        let rules = &lowered.ruleset.rules;
        for ip in resolvers {
            for proto in [6u8, 17u8] {
                assert!(
                    rules.iter().any(|r| {
                        r.verdict == NftVerdict::Drop
                            && r.comment.starts_with("doh-block#")
                            && r.matches.contains(&NftMatch::DstV4 {
                                net: ip,
                                prefix: 32,
                            })
                            && r.matches.contains(&NftMatch::Protocol(proto))
                            && r.matches.contains(&NftMatch::DstPort(443))
                    }),
                    "no 443 drop for {ip} proto {proto} in {rules:#?}"
                );
            }
        }
        for proto in [6u8, 17u8] {
            assert!(
                rules.iter().any(|r| {
                    r.verdict == NftVerdict::Drop
                        && r.matches.contains(&NftMatch::Protocol(proto))
                        && r.matches.contains(&NftMatch::DstPort(853))
                        && !r
                            .matches
                            .iter()
                            .any(|m| matches!(m, NftMatch::DstV4 { .. }))
                }),
                "the DoT cut must be global, not per-resolver: {rules:#?}"
            );
        }
    }

    // ── DoH/DoT lockdown EQUIVALENCE (Windows only) ─────────────────────────────
    // `plan_doh_dot_block` → `lower_windows::lower_doh_dot_block` must produce the
    // SAME per-resolver 443 blocks + global 853 blocks as
    // `killswitch_codegen::doh_dot_block_filters`.
    #[cfg(windows)]
    #[test]
    fn slice_doh_dot_matches_current_codegen() {
        use crate::killswitch_codegen::doh_dot_block_filters;
        use nrr_platform_api::enforcement::EnforcementPlan;
        use nrr_platform_api::wfp_behavioral::{
            arbitration_order_preserved, behaviorally_equivalent,
        };

        let sid = "S-1-5-21-1-2-3-1001";
        let ips = [Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(77, 88, 8, 8)];

        let check = |block_dot: bool, expected_len: usize| {
            let current = doh_dot_block_filters(sid, &ips, block_dot);
            assert_eq!(
                current.len(),
                expected_len,
                "codegen DoH filter count (block_dot={block_dot})"
            );
            let plan = EnforcementPlan {
                principal: nrr_platform_api::enforcement::UserPrincipal::from_windows_sid(sid)
                    .expect("valid sid"),
                flows: plan_doh_dot_block(sid, &ips, block_dot),
                routes: Vec::new(),
                policy_rules: Vec::new(),
            };
            let lowered = nrr_platform_windows::lower_windows::lower_doh_dot_block(&plan);
            assert!(
                behaviorally_equivalent(&current, &lowered),
                "neutral pipeline must install the SAME DoH/DoT blocks as the codegen \
                 (block_dot={block_dot})"
            );
            assert!(
                arbitration_order_preserved(&current, &lowered),
                "DoH/DoT block arbitration order must be preserved (block_dot={block_dot})"
            );
        };

        // Per packed chunk: TCP+UDP on 443; + global DoT (TCP+UDP on 853).
        let chunks = nrr_platform_api::wfp_slotting::pack_v4(ips).len();
        check(true, chunks * 2 + 2);
        // Without DoT: only the packed 443 blocks.
        check(false, chunks * 2);
    }

    // A loopback / link-local resolver IP is never blocked (safety valve).
    #[test]
    fn doh_lockdown_skips_exempt_resolver_ips() {
        use crate::killswitch_codegen::doh_dot_block_filters;
        let sid = "S-1-5-21-1-2-3-1001";
        let ips = [
            Ipv4Addr::new(127, 0, 0, 1),   // loopback — skipped
            Ipv4Addr::new(169, 254, 1, 1), // link-local — skipped
            Ipv4Addr::new(9, 9, 9, 9),     // public — blocked
        ];
        let filters = doh_dot_block_filters(sid, &ips, false);
        assert_eq!(filters.len(), 2, "only the public IP yields TCP+UDP blocks");
        assert!(filters
            .iter()
            .all(|f| f.covers_v4(Ipv4Addr::new(9, 9, 9, 9))));
        assert!(!filters
            .iter()
            .any(|f| f.covers_v4(Ipv4Addr::new(127, 0, 0, 1))
                || f.covers_v4(Ipv4Addr::new(169, 254, 1, 1))));
    }

    // ── Sub-slice 4b EQUIVALENCE — multi-protocol kill-switch (Windows only) ────
    // `plan_kill_switch_destinations` → `lower_windows::lower_kill_switch` must
    // reproduce `killswitch_codegen::kill_switch_filters` for the FULL protocol
    // surface, not just TCP/UDP: the ALL default (proto-agnostic ALE + packet
    // pairs), an ICMP-only selection (`other == false`, one named packet pair, no
    // ALE), and an all-except-ICMP selection (`other == true`, block-all + an ICMP
    // permit exception). Two destinations exercise the per-destination `idx * 16`
    // packet slot window.
    #[cfg(windows)]
    #[test]
    fn slice4b_multiprotocol_kill_switch_matches_current_codegen() {
        use crate::killswitch_codegen::{kill_switch_filters, KillSwitchProtocols};
        use nrr_platform_api::enforcement::EnforcementPlan;
        use nrr_platform_api::wfp_behavioral::{
            arbitration_order_preserved, behaviorally_equivalent,
        };

        let sid = "S-1-5-21-1-2-3-1001";
        let luid = 0x1234_5678_u64;
        let ips = [
            Ipv4Addr::new(203, 0, 113, 5),
            Ipv4Addr::new(198, 51, 100, 9),
        ];

        // A helper: lower the neutral plan for `protos` and compare to the codegen.
        let check = |protos: KillSwitchProtocols, expected_len: usize| {
            let current = kill_switch_filters(sid, &ips, luid, protos);
            assert_eq!(
                current.len(),
                expected_len,
                "codegen filter count for {protos:?}"
            );
            let plan = EnforcementPlan {
                principal: nrr_platform_api::enforcement::UserPrincipal::from_windows_sid(sid)
                    .expect("valid sid"),
                flows: plan_kill_switch_destinations(sid, &ips, protos),
                routes: Vec::new(),
                policy_rules: Vec::new(),
            };
            let lowered = nrr_platform_windows::lower_windows::lower_kill_switch(&plan, luid);
            assert!(
                behaviorally_equivalent(&current, &lowered),
                "neutral pipeline must install the SAME kill-switch filters as the \
                 codegen for {protos:?}"
            );
            assert!(
                arbitration_order_preserved(&current, &lowered),
                "arbitration order must be preserved for {protos:?}"
            );
        };

        // ALL (the 127 default): per dest, ALE pair (proto-agnostic) + one packet
        // pair per NAMED protocol (ICMP/IGMP/GRE/ESP, no agnostic
        // pair) = 2 + 8 = 10; two dests = 20.
        check(KillSwitchProtocols::ALL, 20);

        // ICMP only: no ALE pair, one packet egress pair per dest = 2; two = 4.
        check(
            KillSwitchProtocols {
                tcp: false,
                udp: false,
                icmp: true,
                igmp: false,
                gre: false,
                esp: false,
                other: false,
            },
            4,
        );

        // All-except-ICMP: ALE pair (tcp/udp) + one packet pair per remaining
        // named protocol (IGMP/GRE/ESP — unchecked ICMP simply gets
        // no filter) = 2 + 6 = 8 per dest; two = 16.
        check(
            KillSwitchProtocols {
                icmp: false,
                ..KillSwitchProtocols::ALL
            },
            16,
        );
    }

    // ── Sub-slice 4c EQUIVALENCE — catch-all (Mode-B) kill-switch (Windows only) ─
    // `plan_catch_all_kill_switch` → `lower_windows::lower_catch_all_kill_switch`
    // must reproduce `killswitch_codegen::catch_all_kill_switch_filters` — the
    // blanket block-everything-not-exempted with its loopback/link-local/broadcast/
    // server/LAN exemptions, the ALE + packet catch-all blocks, and the IPv6 cut —
    // across the ALL default, a TCP/UDP-only mask (no V4 packet layer), and an
    // all-except-ICMP mask (block-all + an ICMP permit exception).
    #[cfg(windows)]
    #[test]
    fn slice4c_catch_all_kill_switch_matches_current_codegen() {
        use crate::killswitch_codegen::{
            catch_all_kill_switch_filters, KillSwitchProtocols, KillSwitchResolution,
        };
        use nrr_platform_api::enforcement::EnforcementPlan;
        use nrr_platform_api::wfp_behavioral::{
            arbitration_order_preserved, behaviorally_equivalent,
        };

        let sid = "S-1-5-21-1-2-3-1001";
        let luid = 0x0001_0000_0000_0007_u64;
        let servers = [Ipv4Addr::new(203, 0, 113, 7)];
        let local_subnets = [(Ipv4Addr::new(192, 168, 1, 0), 24)];
        let resolution = KillSwitchResolution {
            secondary_luid: luid,
            bootstrap_server_ips: servers.to_vec(),
            local_subnets: local_subnets.to_vec(),
            foreign_tunnel_luids: Vec::new(),
        };

        let check = |protos: KillSwitchProtocols, expected_len: usize| {
            let current = catch_all_kill_switch_filters(
                sid,
                &resolution,
                &crate::killswitch_codegen::FailClosedExemptions::default(),
                protos,
            );
            assert_eq!(
                current.len(),
                expected_len,
                "codegen catch-all filter count for {protos:?}"
            );
            let plan = EnforcementPlan {
                principal: nrr_platform_api::enforcement::UserPrincipal::from_windows_sid(sid)
                    .expect("valid sid"),
                flows: plan_catch_all_kill_switch(sid, &servers, &local_subnets, protos),
                routes: Vec::new(),
                policy_rules: Vec::new(),
            };
            let lowered =
                nrr_platform_windows::lower_windows::lower_catch_all_kill_switch(&plan, luid);
            assert!(
                behaviorally_equivalent(&current, &lowered),
                "neutral pipeline must install the SAME catch-all filters as the \
                 codegen for {protos:?}"
            );
            assert!(
                arbitration_order_preserved(&current, &lowered),
                "catch-all arbitration order must be preserved for {protos:?}"
            );
        };

        // ALL: ALE 8 (egress+loopback+link-local+broadcast+local-network-
        // control+server+subnet+block) + packet 11 (7 mirror exempts + 4 named
        // blocks — no agnostic block-all) + IPv6 8 (4 ALE + 4 packet) = 27.
        check(KillSwitchProtocols::ALL, 27);

        // TCP/UDP only: no V4 packet layer at all → ALE 8 + IPv6 8 = 16.
        check(KillSwitchProtocols::from_bits(0x03), 16);

        // All-except-ICMP: ALE 8 + packet 10 (7 mirror exempts + IGMP/GRE/ESP
        // named blocks; unchecked ICMP simply gets no filter) + IPv6 8 = 26.
        check(
            KillSwitchProtocols {
                icmp: false,
                ..KillSwitchProtocols::ALL
            },
            26,
        );
    }

    // ── Sub-slice 4d EQUIVALENCE — fail-closed + app kill-switch + app exempt ────
    // The neutral pipeline must reproduce `killswitch_codegen`'s
    // `app_kill_switch_filters` / `primary_app_exempt_filters` /
    // `fail_closed_block_destinations` / `fail_closed_block_apps` /
    // `fail_closed_block_all_filters` across the ALL / TCP-UDP-only / all-except-ICMP
    // masks (and DNS-over-primary on/off for the block-all).
    #[cfg(windows)]
    #[test]
    fn slice4d_fail_closed_and_app_kill_switch_match_current_codegen() {
        use crate::killswitch_codegen::{
            app_kill_switch_filters, fail_closed_block_all_filters, fail_closed_block_apps,
            fail_closed_block_destinations, primary_app_exempt_filters, FailClosedExemptions,
            KillSwitchProtocols,
        };
        use nrr_platform_api::enforcement::EnforcementPlan;
        use nrr_platform_api::types::WfpFilterSpec;
        use nrr_platform_api::wfp_behavioral::{
            arbitration_order_preserved, behaviorally_equivalent,
        };
        use nrr_platform_windows::lower_windows::{lower_catch_all_kill_switch, lower_kill_switch};

        let sid = "S-1-5-21-1-2-3-1001";
        let luid = 0x0001_0000_0000_0007_u64;
        let apps = vec![r"C:\Games\game.exe".to_string(), "*vpn*".to_string()];
        let ips = [Ipv4Addr::new(203, 0, 113, 5), Ipv4Addr::new(8, 8, 8, 8)];
        let servers = [Ipv4Addr::new(203, 0, 113, 7)];
        let subnets = [(Ipv4Addr::new(192, 168, 1, 0), 24)];

        let plan = |flows: Vec<FlowRule>| EnforcementPlan {
            principal: nrr_platform_api::enforcement::UserPrincipal::from_windows_sid(sid)
                .expect("valid sid"),
            flows,
            routes: Vec::new(),
            policy_rules: Vec::new(),
        };
        let assert_equiv = |current: &[WfpFilterSpec], lowered: &[WfpFilterSpec], label: &str| {
            assert!(
                !current.is_empty(),
                "{label}: codegen produced no filters (test would be vacuous)"
            );
            assert!(
                behaviorally_equivalent(current, lowered),
                "{label}: neutral pipeline must install the SAME filters as the codegen"
            );
            assert!(
                arbitration_order_preserved(current, lowered),
                "{label}: arbitration order must be preserved"
            );
        };

        // (A) per-app kill-switch — ALE pair per app. Main-named addresses no
        // longer earn rescue permits: the block sits below the primary rule
        // band, so the primary rules' own permits carry them.
        let cur = app_kill_switch_filters(sid, &apps, luid, KillSwitchProtocols::ALL);
        assert_eq!(cur.len(), 4, "2 apps × (permit + block)");
        let low = lower_kill_switch(
            &plan(plan_app_kill_switch(sid, &apps, KillSwitchProtocols::ALL)),
            luid,
        );
        assert_equiv(&cur, &low, "app-kill-switch");

        // (B) primary-app exemption — one unconditional ALE permit per app.
        let cur = primary_app_exempt_filters(sid, &apps);
        assert_eq!(cur.len(), 2, "one exempt permit per app, no block");
        let low = lower_catch_all_kill_switch(&plan(plan_primary_app_exempt(sid, &apps)), luid);
        assert_equiv(&cur, &low, "primary-app-exempt");

        // (D) fail-closed per-app blocks.
        let cur = fail_closed_block_apps(sid, &apps, KillSwitchProtocols::ALL);
        assert_eq!(cur.len(), 2, "one block per app");
        let low = lower_kill_switch(
            &plan(plan_fail_closed_apps(sid, &apps, KillSwitchProtocols::ALL)),
            luid,
        );
        assert_equiv(&cur, &low, "fail-closed-apps");

        // (C) fail-closed per-destination blocks + (E) fail-closed block-all,
        // across several protocol masks and DNS-over-primary.
        let masks = [
            KillSwitchProtocols::ALL,
            KillSwitchProtocols::from_bits(0x03),
            KillSwitchProtocols {
                icmp: false,
                ..KillSwitchProtocols::ALL
            },
        ];
        for protos in masks {
            let cur = fail_closed_block_destinations(sid, &ips, protos);
            let low = lower_kill_switch(
                &plan(plan_fail_closed_destinations(sid, &ips, protos)),
                luid,
            );
            assert_equiv(&cur, &low, "fail-closed-destinations");

            let primaries = [
                Ipv4Addr::new(203, 0, 113, 50),
                Ipv4Addr::new(203, 0, 113, 51),
            ];
            // Known-direct exemptions ride the same parity check.
            let directs = [Ipv4Addr::new(203, 0, 113, 68)];
            // The liveness-probe target (tunnel next-hop) rides the
            // same parity check as every other exemption.
            let probes = [Ipv4Addr::new(10, 91, 192, 1)];
            for allow_dns in [false, true] {
                let ex = FailClosedExemptions {
                    bootstrap_server_ips: servers.to_vec(),
                    local_subnets: subnets.to_vec(),
                    foreign_tunnel_luids: Vec::new(),
                    primary_dest_ips: primaries.to_vec(),
                    allow_dns_over_primary: allow_dns,
                    known_direct_ips: directs.to_vec(),
                    probe_target_ips: probes.to_vec(),
                    secondary_luid: 0,
                };
                let cur = fail_closed_block_all_filters(sid, &ex, protos);
                let low = lower_catch_all_kill_switch(
                    &plan(plan_fail_closed_block_all(
                        sid, &servers, &probes, &subnets, &primaries, &directs, allow_dns, protos,
                    )),
                    luid,
                );
                assert_equiv(&cur, &low, "fail-closed-block-all");
            }
        }
    }

    // ── Slice 5 EQUIVALENCE — fail-closed default block (Windows only) ──────────
    // With `StrictSecondaryFailClosed`, `plan_route_rules` → `lower_route_rules`
    // must reproduce the whole `generate_filters` output INCLUDING the trailing
    // `default_block_spec` catch-all block (`wfp_codegen`).
    #[cfg(windows)]
    #[test]
    fn slice5_fail_closed_default_block_matches_current_codegen() {
        use crate::wfp_codegen::{generate_filters, CodegenInput};
        use nrr_platform_api::enforcement::EnforcementPlan;
        use nrr_platform_api::types::WfpAction;
        use nrr_platform_api::wfp_behavioral::{
            arbitration_order_preserved, behaviorally_equivalent,
        };

        let sid = "S-1-5-21-1-2-3-1001";
        let rb = book(
            vec![exact_ip_rule("p-ip", Ipv4Addr::new(192, 0, 2, 5))],
            vec![rule(
                "s-block",
                CanonicalAddressMatch::ExactIp(Ipv4Addr::new(10, 0, 0, 9)),
                RuleAction::Block,
            )],
        );
        let cache = MapCache::default();
        let resolver = MapResolver::default();
        let obs = MapObs::default();
        let denylist = std::collections::HashSet::new();
        let current = generate_filters(CodegenInput {
            sid,
            rule_book: &rb,
            behavior_mode: RouteBehaviorMode::StrictSecondaryFailClosed,
            fqdn_cache: &cache,
            app_observations: &obs,
            app_resolver: &resolver,
            secondary_ip_denylist: &denylist,
            zone_priority_over_ip: false,
        });

        let plan = EnforcementPlan {
            principal: nrr_platform_api::enforcement::UserPrincipal::from_windows_sid(sid)
                .expect("valid sid"),
            flows: plan_route_rules(
                &rb,
                sid,
                RouteBehaviorMode::StrictSecondaryFailClosed,
                &planner_input(&cache, &resolver, &obs),
            )
            .0,
            routes: Vec::new(),
            policy_rules: Vec::new(),
        };
        let lowered = nrr_platform_windows::lower_windows::lower_route_rules(&plan);

        // 1 ExactIp permit + Block (ALE + packet mirror) + default block = 4.
        assert_eq!(current.filters.len(), 4, "sanity: incl the default block");
        assert_eq!(
            current
                .filters
                .iter()
                // Unconditional means NO destination at all — a packed
                // filter carries its addresses in `remote_ip_set`, so checking
                // the single field alone would count one as unconditional.
                .filter(|f| f.action == WfpAction::Block
                    && f.remote_ip.is_none()
                    && f.remote_ip_set.is_empty()
                    && f.remote_subnet.is_none())
                .count(),
            1,
            "exactly one unconditional default block in the codegen output"
        );
        assert!(
            behaviorally_equivalent(&current.filters, &lowered),
            "neutral pipeline must install the default block too"
        );
        assert!(arbitration_order_preserved(&current.filters, &lowered));
    }

    // ── Slice 5 EQUIVALENCE — system route table (Windows only) ─────────────────
    // `plan_routes` → `lower_windows::lower_routes` must produce the SAME route SET
    // as `route_codegen::generate_routes` across both behavior modes, with/without a
    // primary target, and through the shared-IP denylist — covering the /32 host
    // fan-out (ExactIp / ExactFqdn / Suffix), dedup, non-routable skip, the /1 and
    // /2 overlays, and the primary exceptions.
    #[cfg(windows)]
    #[test]
    fn slice5_routes_match_current_codegen() {
        use crate::route_codegen::{generate_routes, SecondaryRouteTarget};
        use nrr_platform_api::enforcement::EnforcementPlan;
        use nrr_platform_api::RouteEntry;
        use nrr_platform_windows::lower_windows::{lower_routes, RouteTarget};

        fn route_sets_equal(a: &[RouteEntry], b: &[RouteEntry]) -> bool {
            a.len() == b.len() && a.iter().all(|r| b.contains(r)) && b.iter().all(|r| a.contains(r))
        }

        let mut cache = MapCache::default();
        cache.hosts.insert(
            "api.example.com".into(),
            vec![Ipv4Addr::new(203, 0, 113, 1), Ipv4Addr::new(203, 0, 113, 2)],
        );
        cache.suffixes.insert(
            "corp.example".into(),
            vec!["a.corp.example".into(), "b.corp.example".into()],
        );
        cache.hosts.insert(
            "a.corp.example".into(),
            vec![Ipv4Addr::new(198, 51, 100, 1)],
        );
        cache.hosts.insert(
            "b.corp.example".into(),
            vec![Ipv4Addr::new(198, 51, 100, 2)],
        );

        // Secondary: an ExactIp, a duplicate of it (dedup), a Suffix fan-out, a
        // loopback (non-routable skip). Primary: an ExactIp + an ExactFqdn fan-out.
        let rb = book(
            vec![
                exact_ip_rule("p-ip", Ipv4Addr::new(8, 8, 8, 8)),
                rule(
                    "p-fqdn",
                    CanonicalAddressMatch::ExactFqdn("api.example.com".into()),
                    RuleAction::Route,
                ),
            ],
            vec![
                exact_ip_rule("s-ip", Ipv4Addr::new(1, 1, 1, 1)),
                exact_ip_rule("s-ip-dup", Ipv4Addr::new(1, 1, 1, 1)),
                rule(
                    "s-suffix",
                    CanonicalAddressMatch::SuffixDomain("corp.example".into()),
                    RuleAction::Route,
                ),
                exact_ip_rule("s-loop", Ipv4Addr::new(127, 0, 0, 1)),
                // An app-only rule: routed from observations on both sides, so
                // the equivalence covers the destinations the Windows codegen
                // learns rather than resolves.
                CanonicalRule {
                    id: nrr_domain::RuleId("s-app".into()),
                    enabled: true,
                    address_match: None,
                    app_match: Some(nrr_domain::canonical::CanonicalAppMatch {
                        pattern: CanonicalAppPattern::Exact("messenger.exe".into()),
                        include_child_processes: false,
                    }),
                    comment: String::new(),
                    action: RuleAction::Route,
                    origin: None,
                },
            ],
        );

        let sec = SecondaryRouteTarget {
            gateway: Ipv4Addr::new(10, 0, 0, 1),
            interface_index: 7,
        };
        let pri = SecondaryRouteTarget {
            gateway: Ipv4Addr::new(192, 168, 1, 1),
            interface_index: 12,
        };
        let sec_target = RouteTarget {
            gateway: sec.gateway,
            interface_index: sec.interface_index,
        };
        let pri_target = RouteTarget {
            gateway: pri.gateway,
            interface_index: pri.interface_index,
        };

        // A shared-IP denylist that drops one secondary destination (mode A only).
        let denied: std::collections::HashSet<Ipv4Addr> =
            [Ipv4Addr::new(198, 51, 100, 2)].into_iter().collect();

        for denylist in [std::collections::HashSet::new(), denied] {
            for mode in [
                RouteBehaviorMode::PreferPrimary,
                RouteBehaviorMode::PreferSecondaryWhenAvailable,
                RouteBehaviorMode::StrictSecondaryFailClosed,
            ] {
                for has_primary in [false, true] {
                    let primary_opt = has_primary.then_some(&pri);
                    let apps = crate::app_observation_lookup::MockAppObservationLookup::new();
                    apps.set_ips("messenger.exe", vec![Ipv4Addr::new(203, 0, 113, 7)]);
                    let current = generate_routes(
                        mode,
                        &rb,
                        primary_opt,
                        &sec,
                        &cache,
                        &apps,
                        &denylist,
                        crate::address_ownership::ZoneVsIpOrder::default(),
                        &[],
                    );
                    let plan = EnforcementPlan {
                        principal: nrr_platform_api::enforcement::UserPrincipal::from_windows_sid(
                            "S-1-5-21-A",
                        )
                        .expect("valid sid"),
                        flows: Vec::new(),
                        routes: plan_routes(
                            mode,
                            &rb,
                            has_primary,
                            &cache,
                            &apps,
                            &denylist,
                            crate::address_ownership::ZoneVsIpOrder::default(),
                        ),
                        policy_rules: Vec::new(),
                    };
                    let lowered =
                        lower_routes(&plan, sec_target, has_primary.then_some(pri_target));
                    assert!(
                        route_sets_equal(&current.routes, &lowered),
                        "route set mismatch for mode {mode:?}, has_primary {has_primary}\n\
                         codegen: {:#?}\nlowered: {:#?}",
                        current.routes,
                        lowered
                    );
                }
            }
        }
    }
}
