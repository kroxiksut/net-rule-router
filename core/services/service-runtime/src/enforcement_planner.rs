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
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
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
    /// What policy may do about IPv6 this pass. The CALLER decides, because
    /// this planner is pure and never sees an adapter — [`Ipv6Guard::from_links`]
    /// is where the machine's answer comes from.
    pub ipv6: Ipv6Guard,
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
    let families = input.ipv6.families();
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
            let host_flow = |fanout_idx: u32, ip: IpAddr| FlowRule {
                verdict,
                precedence: Precedence {
                    class,
                    ordinal: base_ordinal + fanout_idx,
                },
                flow: FlowMatch {
                    dst: host_match(ip),
                    dst_port: None,
                    protocol: None,
                },
                principal: principal.clone(),
                app: AppScope::Any,
                egress: EgressConstraint::Any,
                coverage,
            };

            if let Some(addr_match) = rule.address_match.as_ref() {
                let targets = resolve_targets(addr_match, cache_for_role, families);
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
                    flows.push(host_flow(
                        APP_PATH_FANOUT_CAP as u32 + 1 + i as u32,
                        IpAddr::V4(ip),
                    ));
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
    families: FamilyScope,
) -> Vec<(u32, IpAddr)> {
    let mut out = Vec::new();
    match addr_match {
        // A rule can only name an IPv4 literal today; the v6 form arrives with
        // address rules over that family.
        CanonicalAddressMatch::ExactIp(ip) if families.admits(*ip) => out.push((0, *ip)),
        CanonicalAddressMatch::ExactIp(_) => {}
        CanonicalAddressMatch::ExactFqdn(host) => {
            for (i, ip) in capped_for_host(cache, host, families).enumerate() {
                out.push((i as u32, ip));
            }
        }
        // `SuffixDomain` covers its apex, `Zone` does not — the same split
        // `wfp_codegen::emit_suffix_fanout` makes, so the two views agree.
        CanonicalAddressMatch::SuffixDomain(suffix) => push_suffix_targets(
            &cache.hostnames_for_suffix_domain(suffix, SUFFIX_FANOUT_BACKSTOP),
            cache,
            families,
            &mut out,
        ),
        CanonicalAddressMatch::Zone(zone) => push_suffix_targets(
            &cache.hostnames_under_suffix(zone, SUFFIX_FANOUT_BACKSTOP),
            cache,
            families,
            &mut out,
        ),
    }
    out
}

/// A single-host destination match for `ip` — `/32` or `/128` by family.
fn host_match(ip: IpAddr) -> DstMatch {
    match ip {
        IpAddr::V4(v4) => DstMatch::HostV4(v4),
        IpAddr::V6(v6) => DstMatch::HostV6(v6),
    }
}

/// Can this link carry an IPv6 packet off the wire?
///
/// A `fe80::` link-local does not qualify: every interface has one whether or
/// not the network offers IPv6 at all, so treating it as capability would arm
/// the family everywhere and steer traffic into a hole. Unique-local
/// (`fc00::/7`) DOES qualify — on a corporate network it is a real destination,
/// the same way RFC 1918 space is on IPv4.
#[must_use]
fn link_carries_ipv6(link: &nrr_platform_api::adapters::AdapterInfo) -> bool {
    use nrr_domain::address_class::{classify, AddressClass};
    link.ipv6_addresses
        .iter()
        .any(|ip| matches!(classify(IpAddr::V6(*ip)), AddressClass::Routable))
}

/// May policy name IPv6 destinations, given what this machine's links carry?
#[must_use]
pub fn ipv6_policy_possible(adapters: &[nrr_platform_api::adapters::AdapterInfo]) -> bool {
    adapters.iter().any(link_carries_ipv6)
}

/// What policy may do about IPv6 this pass.
///
/// The two questions are separate and the split is the whole point: a filter
/// pins a destination to a link, a ROUTE hands traffic to one. Pinning a
/// destination to a tunnel that cannot carry the family blocks it — the honest
/// outcome. Routing it there black-holes it instead, and the user reads a hang
/// as a broken site rather than as protection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ipv6Guard {
    /// No link carries routable IPv6. Nothing can travel the family, so naming
    /// it would only add filters nothing ever matches.
    Off,
    /// Some link carries IPv6, but not the additional one. A rule that sends a
    /// host down the tunnel cannot be honoured over v6, so the host's v6
    /// addresses are pinned to the tunnel and therefore blocked — every OTHER
    /// destination keeps the family, which the blanket family cut never
    /// allowed.
    FiltersOnly,
    /// The additional link carries IPv6: a rule host's v6 addresses ride it,
    /// pinned and routed exactly as its v4 ones are.
    FiltersAndRoutes,
}

impl Ipv6Guard {
    /// Derive the disposition from this pass's links. `secondary` is the
    /// additional link as the machine reports it now — `None` when it is
    /// unbound or currently absent.
    #[must_use]
    pub fn from_links(
        adapters: &[nrr_platform_api::adapters::AdapterInfo],
        secondary: Option<&nrr_platform_api::adapters::AdapterInfo>,
    ) -> Self {
        if secondary.is_some_and(link_carries_ipv6) {
            Self::FiltersAndRoutes
        } else if ipv6_policy_possible(adapters) {
            // Some OTHER link can carry the family — including one the user
            // never bound. That is the leak the family cut existed for, and a
            // pin whose permit cannot match closes it per address.
            Self::FiltersOnly
        } else {
            Self::Off
        }
    }

    /// Which families policy may name.
    #[must_use]
    pub fn families(self) -> FamilyScope {
        match self {
            Self::Off => FamilyScope::V4Only,
            Self::FiltersOnly | Self::FiltersAndRoutes => FamilyScope::Both,
        }
    }

    /// Which families the SYSTEM ROUTE TABLE may be told about.
    #[must_use]
    pub fn route_families(self) -> FamilyScope {
        match self {
            Self::FiltersAndRoutes => FamilyScope::Both,
            Self::Off | Self::FiltersOnly => FamilyScope::V4Only,
        }
    }
}

/// Which address families policy may name right now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FamilyScope {
    /// IPv4 only — the shape whenever no egress can carry IPv6.
    V4Only,
    /// Both families.
    Both,
}

impl FamilyScope {
    pub(crate) fn admits(self, ip: IpAddr) -> bool {
        matches!((self, ip), (Self::Both, _) | (Self::V4Only, IpAddr::V4(_)))
    }
}

/// One host's cached addresses, capped PER FAMILY and IPv4 first.
///
/// Per family rather than per host: a shared cap would let a dual-stacked CDN's
/// IPv6 records push out IPv4 pins that are carrying traffic today, which is a
/// regression dressed as a new feature. IPv4 first keeps the fan-out ordinals
/// of a v4-only host exactly as they were, so nothing about today's machine
/// moves.
pub(crate) fn capped_for_host<'a>(
    cache: &'a dyn FqdnCacheLookup,
    host: &str,
    families: FamilyScope,
) -> impl Iterator<Item = IpAddr> + 'a {
    let all = cache.ips_for_hostname(host);
    let v4 = all
        .iter()
        .copied()
        .filter(|ip| ip.is_ipv4())
        .take(PER_HOSTNAME_IP_CAP);
    let v6 = all
        .iter()
        .copied()
        .filter(move |ip| !ip.is_ipv4() && families.admits(*ip))
        .take(PER_HOSTNAME_IP_CAP);
    v4.chain(v6).collect::<Vec<_>>().into_iter()
}

/// Fan a resolved host list out to `(clamped fanout ordinal, address)` targets.
fn push_suffix_targets(
    hosts: &[String],
    cache: &dyn FqdnCacheLookup,
    families: FamilyScope,
    out: &mut Vec<(u32, IpAddr)>,
) {
    let mut fanout_idx: u32 = 0;
    for host in hosts {
        for ip in capped_for_host(cache, host, families) {
            out.push((fanout_idx.min(SLOTS_PER_RULE - 1), ip));
            fanout_idx += 1;
        }
    }
}

mod kill_switch;
pub use kill_switch::*;
mod fail_closed;
pub use fail_closed::*;
mod routes;
pub use routes::*;
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
pub fn route_destinations(flows: &[FlowRule], role: RouteRole) -> Vec<IpAddr> {
    let mut seen = std::collections::HashSet::new();
    flows
        .iter()
        .filter(|f| {
            f.verdict == Verdict::Permit && f.precedence.class == PrecedenceClass::RouteRule(role)
        })
        .filter_map(|f| match f.flow.dst {
            DstMatch::HostV4(ip) => Some(IpAddr::V4(ip)),
            DstMatch::HostV6(ip) => Some(IpAddr::V6(ip)),
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
mod tests;
