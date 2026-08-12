//! The neutral cross-OS enforcement data model.
//!
//! This module is the SINGLE cross-OS boundary for enforcement intent. It
//! describes WHAT to enforce (a per-principal [`EnforcementPlan`]) in terms that
//! are honestly shared by Windows WFP and Linux nftables, and NOTHING about HOW:
//! nothing here names a WFP layer, a `u64` weight, an `ALE_APP_ID` blob, a LUID,
//! or an nftables chain. Each OS provides a `lower_*` step behind
//! [`EnforcementBackend`] that turns a plan into that platform's mechanism.
//!
//! ## Why this shape (see `ENFORCEMENT_DATAMODEL_DESIGN.md`)
//!
//! The model is C-hybrid: a shared CONCRETE core for the dimensions that map 1:1
//! on both platforms (the 5-tuple [`FlowMatch`] and the [`RouteIntent`]), plus
//! neutral POLICY structure for the parts that diverge ([`PrecedenceClass`],
//! [`EgressConstraint`], [`Coverage`], [`PrincipalScope`], [`AppScope`]). We do
//! NOT generalise `WfpFilterSpec` into a neutral filter (its `weight` / layer /
//! exe-path app-id have no nftables round-trip), and we do NOT re-abstract the
//! flow-match / route entry that already agree.
//!
//! ## Two load-bearing invariants
//!
//! 1. **No byte-identical golden output.** Lowering must be behaviourally
//!    equivalent and self-consistently idempotent (re-apply is a no-op); the
//!    Windows weight bands / id schemes stay Windows-side and are NOT reproduced
//!    bit-for-bit.
//! 2. **No neutral plan-hash apply gate.** Each OS's reconcile is authoritative
//!    and always runs against kernel/environment truth (the secondary adapter and
//!    resolved IPs are read fresh at lowering time). [`plan_delta`] exists for
//!    audit / explain only — never to short-circuit an apply.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

// Re-exported: `UserPrincipal` appears in the public signatures of
// `PrincipalScope` / `RouteTableRef` / `RouteSelector` / `EnforcementPlan`, so
// consumers of this module need to name it. `nrr-platform-api` depends on the
// (OS-neutral) `nrr-domain` for exactly this type.
pub use nrr_domain::user_principal::UserPrincipal;
use nrr_shared::RouteRole;

// ── Shared CONCRETE core ─────────────────────────────────────────────────────
// These genuinely map 1:1 onto WFP conditions and nftables expressions, so they
// are modelled concretely rather than behind a policy abstraction.

/// A destination address match. Family-specific catch-alls are expressed as a
/// `/0` subnet (`SubnetV4 { 0.0.0.0, 0 }` = all IPv4; `SubnetV6 { ::, 0 }` = all
/// IPv6), distinct from the family-agnostic [`DstMatch::Any`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DstMatch {
    /// Any destination, any address family.
    Any,
    /// A single IPv4 host (`/32`).
    HostV4(Ipv4Addr),
    /// A single IPv6 host (`/128`).
    HostV6(Ipv6Addr),
    /// An IPv4 subnet `net/prefix`.
    SubnetV4 { net: Ipv4Addr, prefix: u8 },
    /// An IPv6 subnet `net/prefix`.
    SubnetV6 { net: Ipv6Addr, prefix: u8 },
}

/// An IP-layer transport protocol. `Other(n)` carries an IANA protocol number
/// for anything not individually named (e.g. IPv6 ICMP variants, SCTP).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum L4Proto {
    Tcp,
    Udp,
    Icmp,
    IcmpV6,
    Igmp,
    Gre,
    Esp,
    /// Any other IP protocol, by IANA number.
    Other(u8),
}

/// A 5-tuple-style flow match. `dst_port` / `protocol` of `None` mean
/// "unconstrained on that field".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlowMatch {
    pub dst: DstMatch,
    pub dst_port: Option<u16>,
    pub protocol: Option<L4Proto>,
}

/// The action a [`FlowRule`] takes on a matching flow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Permit,
    Block,
}

// ── Neutral POLICY structure (intent, not mechanism) ─────────────────────────

/// The precedence band a rule belongs to. This is a real cross-OS policy
/// concept: both platforms need "a block can veto", "exemptions outrank the
/// catch-all block", and "primary outranks secondary". Windows lowering maps a
/// `(class, ordinal)` pair onto a weight band; Linux maps `class` onto chain
/// position and `ordinal` onto the within-class order (first-match / terminal
/// drop realising the same arbitration WFP does with weights).
///
/// Ranking is defined by [`PrecedenceClass::rank`] (higher wins), faithful to
/// the shipped Windows weight bands (`killswitch_codegen`): exemption permits
/// (`0x0050_0000`/`0x0060_0000`) > kill-switch permits (`0x0040_0000`) >
/// kill-switch blocks (`0x0030_0000`) > route rules > the catch-all block
/// (`0x0018_0000`) > the default. A [`PrecedenceClass::HardBlock`] is the
/// terminal veto (the `CLEAR_ACTION_RIGHT` analog).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrecedenceClass {
    /// The base band: unmatched traffic follows the default route (allow).
    DefaultCatchAll,
    /// A per-rule route pin for the given role (primary/secondary).
    RouteRule(RouteRole),
    /// The DoH/DoT lockdown band: per-resolver-IP blocks
    /// on 443 and a global DoT block on 853. Outranks a route-rule permit for the
    /// same resolver IP (so a zone rule covering the resolver's hostname cannot
    /// let encrypted DNS through) but stays below the kill-switch permit /
    /// exemption bands, so it never breaks the tunnel or a primary-routed app.
    DohBlock,
    /// The Mode-B blanket "block everything not exempted" band.
    CatchAllBlock,
    /// Permits that survive the catch-all block (loopback / LAN / DNS /
    /// egress-via-secondary / primary-routed-app exemptions).
    CatchAllExempt,
    /// Per-destination / per-app fail-closed blocks (kill-switch armed).
    KillSwitchBlock,
    /// Per-protocol / reconnection permits that outrank the kill-switch block.
    KillSwitchPermit,
    /// The terminal veto — a hard block that outranks everything.
    HardBlock,
}

impl PrecedenceClass {
    /// Canonical priority rank; a HIGHER value is evaluated with higher priority
    /// (Windows: higher weight band; Linux: an earlier terminal rule). Faithful
    /// to the shipped weight-band ordering — but the neutral model commits only
    /// to the RELATIVE order, never to the literal band numbers (which stay in
    /// `lower_windows`). Within one class, a lower [`Precedence::ordinal`] breaks
    /// the tie (planner-owned canonical order).
    pub const fn rank(self) -> u16 {
        match self {
            Self::DefaultCatchAll => 0,
            Self::CatchAllBlock => 10,
            Self::RouteRule(RouteRole::Secondary) => 20,
            Self::RouteRule(RouteRole::Primary) => 30,
            // Above both route-rule bands (beats a rule permit for the resolver
            // IP), below the kill-switch permit / exemptions (never breaks the
            // tunnel or a primary-routed app).
            Self::DohBlock => 35,
            Self::KillSwitchBlock => 40,
            Self::KillSwitchPermit => 50,
            Self::CatchAllExempt => 60,
            Self::HardBlock => 70,
        }
    }
}

/// A rule's full precedence: its band plus a within-band ordinal the planner
/// assigns for deterministic, stable ordering (0 = highest within the band).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Precedence {
    pub class: PrecedenceClass,
    pub ordinal: u32,
}

impl Precedence {
    /// `true` when `self` is evaluated with strictly higher priority than
    /// `other`: a higher class rank wins; within the same class, a lower ordinal
    /// wins. This is the total order both lowerings realise (weight bands on
    /// Windows, rule position on Linux).
    pub fn is_higher_priority_than(self, other: Self) -> bool {
        match self.class.rank().cmp(&other.class.rank()) {
            std::cmp::Ordering::Greater => true,
            std::cmp::Ordering::Less => false,
            std::cmp::Ordering::Equal => self.ordinal < other.ordinal,
        }
    }
}

/// Which principal a rule applies to. `None` is system-wide (no per-user scope).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrincipalScope(pub Option<UserPrincipal>);

/// A neutral stable adapter identity. On Windows this resolves to a LUID, on
/// Linux to an interface name — at lowering time, never in the plan. It is the
/// persistent adapter identity (not an ephemeral ifindex).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdapterId(pub String);

/// Which application(s) a rule applies to. `exe_paths` is a Windows-only
/// consumer (`ALE_APP_ID`); Linux ignores it (no per-exe nft match) and enforces
/// app rules via observed destinations until the eBPF fwmark port ships.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AppScope {
    /// Any application.
    Any,
    /// A named program plus its resolved executable paths (Windows consumer).
    Program {
        key: String,
        exe_paths: Vec<PathBuf>,
    },
}

/// A reference to an egress interface, resolved to a LUID (Windows) or ifname
/// (Linux) at lowering time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EgressRef {
    Primary,
    Secondary,
    Adapter(AdapterId),
}

/// The egress pin, carried AS AN ATTRIBUTE of a rule (not a separate mechanism).
/// `OnlyVia` is the leak-proof pin: on Windows it lowers to the permit(luid) +
/// block pair; on Linux to `oifname <dev> accept` followed by a scoped drop.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EgressConstraint {
    Any,
    OnlyVia(EgressRef),
}

/// How much of a flow a rule covers. `AllPackets` signals that the rule must
/// hold at the packet layer (Windows adds an ALE + packet-layer mirror so
/// ICMP/IGMP/GRE/ESP are covered); Linux collapses this — its single output
/// hook already sees every protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Coverage {
    ConnectOnly,
    AllPackets,
}

/// One neutral enforcement rule. The ordered list of these (by [`Precedence`])
/// is the arbitration surface both lowerings realise.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlowRule {
    pub verdict: Verdict,
    pub precedence: Precedence,
    pub flow: FlowMatch,
    pub principal: PrincipalScope,
    pub app: AppScope,
    pub egress: EgressConstraint,
    pub coverage: Coverage,
}

// ── Policy routing objects ───────────────────────────────────────────────────
// The piece missing from today's `RouteEntry` (which has no table). Modelled
// here so per-principal / policy routing is expressible cross-OS: Windows treats
// `Main` as today and ignores the rest; Linux uses per-principal tables +
// `ip rule` selectors.

/// Which routing table a route/policy-rule targets. `Main` (the default) is the
/// system's single main table — what Windows uses today, and the only value the
/// Windows lowering acts on; `Principal` / `Tagged` are per-principal / marked
/// tables the Linux lowering populates.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum RouteTableRef {
    /// The system main routing table (the only one Windows uses).
    #[default]
    Main,
    /// A per-principal table (Linux per-user routing).
    Principal(UserPrincipal),
    /// A table selected by a numeric tag / firewall mark.
    Tagged(u32),
}

/// A single route intent: destination → egress, in a table, at a metric.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteIntent {
    pub dst: DstMatch,
    pub egress: EgressRef,
    pub metric: u32,
    pub table: RouteTableRef,
}

/// How a policy-routing rule selects traffic into a table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RouteSelector {
    /// By owning user — real per-user routing on Linux (`ip rule uidrange`);
    /// Windows has no driver for this (a declared capability inversion).
    Uid(UserPrincipal),
    /// By firewall mark — per-app routing once the eBPF fwmark port ships.
    Mark(u32),
}

/// A policy-routing rule: "traffic matching `selector` looks up `table`".
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyRoutingRule {
    pub selector: RouteSelector,
    pub table: RouteTableRef,
    pub priority: u32,
}

// ── The per-principal neutral plan ───────────────────────────────────────────

/// The complete enforcement intent for one principal. Built once in
/// `service-runtime` (unit-tested for EXPRESSIVENESS here), then handed to each
/// OS's [`EnforcementBackend::reconcile`]. Because [`UserPrincipal`] stores an
/// OS-shaped string, a plan is instantiated per-principal per-OS; nothing ever
/// compares plans (or hashes of them) across OSes — there is no cross-OS oracle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnforcementPlan {
    pub principal: UserPrincipal,
    pub flows: Vec<FlowRule>,
    pub routes: Vec<RouteIntent>,
    pub policy_rules: Vec<PolicyRoutingRule>,
}

/// An audit/explain-only diff of two plans' flow lists. NEVER an apply gate —
/// the OS reconcile is always authoritative (see the module-level invariants).
/// Indices are into `new.flows` (`added`) and `old.flows` (`removed`).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct PlanDelta {
    pub added: Vec<usize>,
    pub removed: Vec<usize>,
    pub reordered: bool,
}

/// Compute the flow-list delta between two plans, for audit/explain only.
/// `added`/`removed` are membership diffs; `reordered` is `true` when the flows
/// common to both appear in a different relative order. Scoped to `flows` (the
/// arbitration surface where ordering matters); a routes/policy delta is a
/// follow-up if a caller needs it.
pub fn plan_delta(old: &EnforcementPlan, new: &EnforcementPlan) -> PlanDelta {
    let added = new
        .flows
        .iter()
        .enumerate()
        .filter(|(_, f)| !old.flows.contains(f))
        .map(|(i, _)| i)
        .collect();
    let removed = old
        .flows
        .iter()
        .enumerate()
        .filter(|(_, f)| !new.flows.contains(f))
        .map(|(i, _)| i)
        .collect();
    // Among the flows present in BOTH plans, has their relative order changed?
    let common_old: Vec<&FlowRule> = old.flows.iter().filter(|f| new.flows.contains(f)).collect();
    let common_new: Vec<&FlowRule> = new.flows.iter().filter(|f| old.flows.contains(f)).collect();
    let reordered = common_old != common_new;
    PlanDelta {
        added,
        removed,
        reordered,
    }
}

// ── Mechanism seam ───────────────────────────────────────────────────────────

/// The outcome of a reconcile. Neutral counts + human-readable notes; the
/// per-OS backend fills it (e.g. Windows folds `execute_wfp_plan_resilient`'s
/// skip/abort diagnostics, Linux the `nft -f` result).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ApplyReport {
    pub applied: usize,
    pub skipped: usize,
    pub failed: usize,
    pub notes: Vec<String>,
}

/// How a platform matches per-application rules. Surfaced as a capability so the
/// GUI can tell the user when app rules are observation-based (not leak-proof).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppMatchMechanism {
    /// Windows `ALE_APP_ID` (exe NT-path) — leak-proof per-exe.
    WfpAppId,
    /// Linux eBPF cgroup/connect sets an fwmark — leak-proof per-exe once shipped.
    LinuxCgroupFwmark,
    /// Portable fallback: match only the destinations an app was observed using.
    ObservedDestOnly,
}

/// The honest per-platform capability set, declared (not inferred). Wired into
/// `PlatformCapabilities` → `platformProfile.supports.*` so the GUI degrades
/// without scattered `Qt.platform.os` branches. Captures the real inversions
/// (per-user routing is a Linux win; leak-proof per-app is a Windows win).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnforcementCapabilities {
    /// Route per user with no kernel driver (Linux `ip rule uidrange`; Windows
    /// Free: `false`).
    pub per_user_routing: bool,
    /// True per-exe routing (both need an extra mechanism: Windows callout /
    /// Linux eBPF fwmark).
    pub per_app_routing_true: bool,
    /// A per-app block cannot leak (Windows `ALE_APP_ID`: `true`; Linux needs
    /// eBPF connect-verdict, `false` until then).
    pub per_app_block_leakproof: bool,
    /// A per-user block can scope EVERY protocol including ICMP/ping (Linux
    /// `meta skuid`: `true`; Windows packet layer forces `user_sid=None` and
    /// widens system-wide: `false`).
    pub per_user_all_protocol_scoping: bool,
    /// How per-app matching is realised on this platform.
    pub app_match: AppMatchMechanism,
}

impl EnforcementCapabilities {
    /// Windows (WFP): leak-proof per-app block, but no driverless per-user
    /// routing and no all-protocol per-user scoping. This is the declared SSOT
    /// for the inversions; `nrr_shared::platform_profile::PlatformProfile::
    /// windows().supports.*` mirrors it (a drift-guard test asserts they agree).
    pub const fn windows() -> Self {
        Self {
            per_user_routing: false,
            per_app_routing_true: false,
            per_app_block_leakproof: true,
            per_user_all_protocol_scoping: false,
            app_match: AppMatchMechanism::WfpAppId,
        }
    }

    /// Linux MVP (nftables + observed-dest apps): per-user routing and
    /// all-protocol per-user scoping are Linux wins, but the per-app block is
    /// NOT leak-proof until the eBPF connect-verdict port ships.
    pub const fn linux_mvp() -> Self {
        Self {
            per_user_routing: true,
            per_app_routing_true: false,
            per_app_block_leakproof: false,
            per_user_all_protocol_scoping: true,
            app_match: AppMatchMechanism::ObservedDestOnly,
        }
    }
}

/// The per-OS mechanism boundary. `reconcile` is AUTHORITATIVE — it always runs
/// against kernel/environment truth and never consults a neutral plan hash. Each
/// OS's backend owns its own `lower_*` internally.
pub trait EnforcementBackend {
    /// Platform-specific error type surfaced by [`Self::reconcile`].
    type Error;
    /// Drive the platform to match `plan`, returning what changed. Idempotent by
    /// construction (re-apply is a no-op) — NOT gated on any neutral hash.
    fn reconcile(&self, plan: &EnforcementPlan) -> Result<ApplyReport, Self::Error>;
    /// The platform's honest capability set (see [`EnforcementCapabilities`]).
    fn capabilities(&self) -> EnforcementCapabilities;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr::new(a, b, c, d)
    }

    /// Build the hardest existing enforcement scenario PURELY from neutral
    /// types: a primary `ExactIp` permit, a secondary suffix/zone fan-out, and a
    /// FULL Mode-B catch-all (blanket egress-via-secondary permit + loopback /
    /// link-local / LAN / DNS-port(53) exemptions + a multi-protocol catch-all
    /// block covering ICMP/IGMP/GRE/ESP + an IPv6 cut + a hard block). If any
    /// element could not be built, this would not compile — that is the point.
    fn hardest_plan() -> EnforcementPlan {
        let user = UserPrincipal::from_linux_uid(1000);
        let scope = || PrincipalScope(Some(user.clone()));
        let mut flows = Vec::new();

        // 1. Primary ExactIp permit — a site pinned to the primary link.
        flows.push(FlowRule {
            verdict: Verdict::Permit,
            precedence: Precedence {
                class: PrecedenceClass::RouteRule(RouteRole::Primary),
                ordinal: 0,
            },
            flow: FlowMatch {
                dst: DstMatch::HostV4(v4(93, 184, 216, 34)),
                dst_port: None,
                protocol: None,
            },
            principal: scope(),
            app: AppScope::Any,
            egress: EgressConstraint::OnlyVia(EgressRef::Primary),
            coverage: Coverage::ConnectOnly,
        });

        // 2. Secondary suffix/zone fan-out — several resolved /32s pinned to the
        //    secondary (VPN) link, as a domain-suffix rule fans out.
        for (i, ip) in [v4(157, 240, 0, 35), v4(157, 240, 1, 35), v4(31, 13, 64, 35)]
            .into_iter()
            .enumerate()
        {
            flows.push(FlowRule {
                verdict: Verdict::Permit,
                precedence: Precedence {
                    class: PrecedenceClass::RouteRule(RouteRole::Secondary),
                    ordinal: i as u32,
                },
                flow: FlowMatch {
                    dst: DstMatch::HostV4(ip),
                    dst_port: None,
                    protocol: None,
                },
                principal: scope(),
                app: AppScope::Any,
                egress: EgressConstraint::OnlyVia(EgressRef::Secondary),
                coverage: Coverage::ConnectOnly,
            });
        }

        // 3a. Mode-B blanket pin: everything egresses the secondary link.
        flows.push(FlowRule {
            verdict: Verdict::Permit,
            precedence: Precedence {
                class: PrecedenceClass::CatchAllExempt,
                ordinal: 0,
            },
            flow: FlowMatch {
                dst: DstMatch::Any,
                dst_port: None,
                protocol: None,
            },
            principal: scope(),
            app: AppScope::Any,
            egress: EgressConstraint::OnlyVia(EgressRef::Secondary),
            coverage: Coverage::AllPackets,
        });

        // 3b. Exemption permits that survive the catch-all block: loopback,
        //     link-local, LAN, and DNS (UDP/53). These may egress anywhere.
        for (i, (net, prefix)) in [
            (v4(127, 0, 0, 0), 8u8),
            (v4(169, 254, 0, 0), 16),
            (v4(192, 168, 0, 0), 16),
        ]
        .into_iter()
        .enumerate()
        {
            flows.push(FlowRule {
                verdict: Verdict::Permit,
                precedence: Precedence {
                    class: PrecedenceClass::CatchAllExempt,
                    ordinal: (i + 1) as u32,
                },
                flow: FlowMatch {
                    dst: DstMatch::SubnetV4 { net, prefix },
                    dst_port: None,
                    protocol: None,
                },
                principal: scope(),
                app: AppScope::Any,
                egress: EgressConstraint::Any,
                coverage: Coverage::AllPackets,
            });
        }
        flows.push(FlowRule {
            verdict: Verdict::Permit,
            precedence: Precedence {
                class: PrecedenceClass::CatchAllExempt,
                ordinal: 4,
            },
            flow: FlowMatch {
                dst: DstMatch::Any,
                dst_port: Some(53),
                protocol: Some(L4Proto::Udp),
            },
            principal: scope(),
            app: AppScope::Any,
            egress: EgressConstraint::Any,
            coverage: Coverage::ConnectOnly,
        });

        // 3c. Multi-protocol packet-layer blocks (ICMP/IGMP/GRE/ESP) — the
        //     protocols the ALE layer cannot see; `AllPackets` marks them.
        for (i, proto) in [L4Proto::Icmp, L4Proto::Igmp, L4Proto::Gre, L4Proto::Esp]
            .into_iter()
            .enumerate()
        {
            flows.push(FlowRule {
                verdict: Verdict::Block,
                precedence: Precedence {
                    class: PrecedenceClass::CatchAllBlock,
                    ordinal: i as u32,
                },
                flow: FlowMatch {
                    dst: DstMatch::Any,
                    dst_port: None,
                    protocol: Some(proto),
                },
                principal: scope(),
                app: AppScope::Any,
                egress: EgressConstraint::Any,
                coverage: Coverage::AllPackets,
            });
        }

        // 3d. The IPv4 catch-all block (all-v4 = 0.0.0.0/0).
        flows.push(FlowRule {
            verdict: Verdict::Block,
            precedence: Precedence {
                class: PrecedenceClass::CatchAllBlock,
                ordinal: 10,
            },
            flow: FlowMatch {
                dst: DstMatch::SubnetV4 {
                    net: v4(0, 0, 0, 0),
                    prefix: 0,
                },
                dst_port: None,
                protocol: None,
            },
            principal: scope(),
            app: AppScope::Any,
            egress: EgressConstraint::Any,
            coverage: Coverage::AllPackets,
        });

        // 3e. The IPv6 cut (all-v6 = ::/0) — Mode-B is IPv4-routed, so v6 is
        //     blocked wholesale to prevent a v6 leak.
        flows.push(FlowRule {
            verdict: Verdict::Block,
            precedence: Precedence {
                class: PrecedenceClass::CatchAllBlock,
                ordinal: 11,
            },
            flow: FlowMatch {
                dst: DstMatch::SubnetV6 {
                    net: Ipv6Addr::UNSPECIFIED,
                    prefix: 0,
                },
                dst_port: None,
                protocol: None,
            },
            principal: scope(),
            app: AppScope::Any,
            egress: EgressConstraint::Any,
            coverage: Coverage::AllPackets,
        });

        // 4. A hard block (terminal veto) — a per-app block on a named program.
        flows.push(FlowRule {
            verdict: Verdict::Block,
            precedence: Precedence {
                class: PrecedenceClass::HardBlock,
                ordinal: 0,
            },
            flow: FlowMatch {
                dst: DstMatch::Any,
                dst_port: None,
                protocol: None,
            },
            principal: scope(),
            app: AppScope::Program {
                key: "leaky.exe".to_string(),
                exe_paths: vec![PathBuf::from(r"C:\Program Files\Leaky\leaky.exe")],
            },
            egress: EgressConstraint::Any,
            coverage: Coverage::AllPackets,
        });

        // Routes + policy routing: a /32 pinned to the secondary in a
        // per-principal table, plus per-user AND per-mark policy-routing rules.
        let routes = vec![RouteIntent {
            dst: DstMatch::HostV4(v4(157, 240, 0, 35)),
            egress: EgressRef::Secondary,
            metric: 1,
            table: RouteTableRef::Principal(user.clone()),
        }];
        let policy_rules = vec![
            PolicyRoutingRule {
                selector: RouteSelector::Uid(user.clone()),
                table: RouteTableRef::Principal(user.clone()),
                priority: 100,
            },
            PolicyRoutingRule {
                // A firewall mark the eBPF app-match port would set (per-app
                // routing); an arbitrary sentinel value here.
                selector: RouteSelector::Mark(0x4E52_5200),
                table: RouteTableRef::Tagged(42),
                priority: 200,
            },
        ];

        EnforcementPlan {
            principal: user,
            flows,
            routes,
            policy_rules,
        }
    }

    /// THE go/no-go gate. Everything the hardest shipped scenario needs must be
    /// expressible with neutral types — no WFP weight/layer/LUID/app-id-blob
    /// leaking into the plan (that is a structural property of these types: they
    /// have no such fields; this test proves the POSITIVE — that the required
    /// concepts ARE all representable).
    #[test]
    fn hardest_scenario_is_expressible() {
        let plan = hardest_plan();

        // Every named protocol the packet layer must carry is expressible.
        let protos: Vec<L4Proto> = plan.flows.iter().filter_map(|f| f.flow.protocol).collect();
        for needed in [
            L4Proto::Udp,
            L4Proto::Icmp,
            L4Proto::Igmp,
            L4Proto::Gre,
            L4Proto::Esp,
        ] {
            assert!(
                protos.contains(&needed),
                "protocol {needed:?} not expressible"
            );
        }

        // Both IP families are expressible (an IPv6 cut alongside IPv4 rules).
        let has_v4 = plan
            .flows
            .iter()
            .any(|f| matches!(f.flow.dst, DstMatch::HostV4(_) | DstMatch::SubnetV4 { .. }));
        let has_v6 = plan
            .flows
            .iter()
            .any(|f| matches!(f.flow.dst, DstMatch::HostV6(_) | DstMatch::SubnetV6 { .. }));
        assert!(has_v4 && has_v6, "both IP families must be expressible");

        // The leak-proof egress pin is an ATTRIBUTE of a rule, not a mechanism.
        assert!(
            plan.flows
                .iter()
                .any(|f| f.egress == EgressConstraint::OnlyVia(EgressRef::Secondary)),
            "the OnlyVia(Secondary) pin must be expressible"
        );
        // A primary pin too — proving both egress roles are representable.
        assert!(plan
            .flows
            .iter()
            .any(|f| f.egress == EgressConstraint::OnlyVia(EgressRef::Primary)));

        // Multi-packet vs connect-only coverage are both expressible.
        assert!(plan
            .flows
            .iter()
            .any(|f| f.coverage == Coverage::AllPackets));
        assert!(plan
            .flows
            .iter()
            .any(|f| f.coverage == Coverage::ConnectOnly));

        // Per-principal scoping is expressible.
        assert!(plan.flows.iter().all(|f| f.principal.0.is_some()));

        // A named per-app scope with exe paths (the Windows ALE_APP_ID consumer).
        assert!(plan.flows.iter().any(
            |f| matches!(&f.app, AppScope::Program { exe_paths, .. } if !exe_paths.is_empty())
        ));

        // Policy routing: real per-USER routing (the Linux inversion) AND a
        // per-mark rule (per-app once the eBPF port ships) into a per-principal
        // table are all expressible.
        assert!(plan
            .policy_rules
            .iter()
            .any(|r| matches!(r.selector, RouteSelector::Uid(_))));
        assert!(plan
            .policy_rules
            .iter()
            .any(|r| matches!(r.selector, RouteSelector::Mark(_))));
        assert!(plan
            .routes
            .iter()
            .any(|r| matches!(r.table, RouteTableRef::Principal(_))));
    }

    /// The neutral [`PrecedenceClass`] must encode a TOTAL order that realises
    /// the three cross-OS arbitration invariants — with NO weights.
    #[test]
    fn precedence_order_is_total_and_realises_the_invariants() {
        // Strictly increasing rank over the whole ladder (a total order).
        let ladder = [
            PrecedenceClass::DefaultCatchAll,
            PrecedenceClass::CatchAllBlock,
            PrecedenceClass::RouteRule(RouteRole::Secondary),
            PrecedenceClass::RouteRule(RouteRole::Primary),
            PrecedenceClass::KillSwitchBlock,
            PrecedenceClass::KillSwitchPermit,
            PrecedenceClass::CatchAllExempt,
            PrecedenceClass::HardBlock,
        ];
        for pair in ladder.windows(2) {
            assert!(
                pair[0].rank() < pair[1].rank(),
                "{:?} must rank below {:?}",
                pair[0],
                pair[1]
            );
        }

        // Invariant 1 — a block can veto the default.
        assert!(PrecedenceClass::HardBlock.rank() > PrecedenceClass::DefaultCatchAll.rank());
        // Invariant 2 — exemptions outrank the catch-all block (leak-proof
        // permit-over-block), and per-protocol permits outrank the fail-closed block.
        assert!(PrecedenceClass::CatchAllExempt.rank() > PrecedenceClass::CatchAllBlock.rank());
        assert!(PrecedenceClass::KillSwitchPermit.rank() > PrecedenceClass::KillSwitchBlock.rank());
        // Invariant 3 — primary outranks secondary.
        assert!(
            PrecedenceClass::RouteRule(RouteRole::Primary).rank()
                > PrecedenceClass::RouteRule(RouteRole::Secondary).rank()
        );

        // Within a class, a lower ordinal wins the tie.
        let a = Precedence {
            class: PrecedenceClass::CatchAllExempt,
            ordinal: 0,
        };
        let b = Precedence {
            class: PrecedenceClass::CatchAllExempt,
            ordinal: 1,
        };
        assert!(a.is_higher_priority_than(b));
        assert!(!b.is_higher_priority_than(a));
        // Across classes, the higher band wins regardless of ordinal.
        let low_band_first = Precedence {
            class: PrecedenceClass::DefaultCatchAll,
            ordinal: 0,
        };
        assert!(b.is_higher_priority_than(low_band_first));
    }

    /// [`plan_delta`] detects add / remove / reorder — for audit/explain only.
    #[test]
    fn plan_delta_detects_add_remove_reorder() {
        let base = hardest_plan();

        // Identical plan → no delta.
        let same = plan_delta(&base, &base);
        assert!(same.added.is_empty() && same.removed.is_empty() && !same.reordered);

        // Remove the last flow → one removed, nothing added, not reordered.
        let mut shorter = base.clone();
        let dropped = shorter.flows.pop().expect("plan has flows");
        let d = plan_delta(&base, &shorter);
        assert_eq!(d.removed.len(), 1);
        assert!(d.added.is_empty());
        assert!(!d.reordered);
        assert_eq!(base.flows[base.flows.len() - 1], dropped);

        // Add a brand-new flow → one added.
        let mut longer = base.clone();
        longer.flows.push(FlowRule {
            verdict: Verdict::Block,
            precedence: Precedence {
                class: PrecedenceClass::HardBlock,
                ordinal: 99,
            },
            flow: FlowMatch {
                dst: DstMatch::HostV4(v4(203, 0, 113, 7)),
                dst_port: None,
                protocol: None,
            },
            principal: PrincipalScope(None),
            app: AppScope::Any,
            egress: EgressConstraint::Any,
            coverage: Coverage::ConnectOnly,
        });
        let d = plan_delta(&base, &longer);
        assert_eq!(d.added.len(), 1);
        assert!(d.removed.is_empty());

        // Swap the first two flows → same set, reordered.
        let mut swapped = base.clone();
        swapped.flows.swap(0, 1);
        let d = plan_delta(&base, &swapped);
        assert!(d.added.is_empty() && d.removed.is_empty());
        assert!(d.reordered);
    }

    /// The capability inversions are representable (Linux wins per-user routing;
    /// Windows wins leak-proof per-app) — so `platformProfile.supports.*` can
    /// carry the honest per-OS truth.
    #[test]
    fn capability_inversions_are_representable() {
        let windows = EnforcementCapabilities::windows();
        let linux_mvp = EnforcementCapabilities::linux_mvp();
        // The inversions are real and opposite on the two axes.
        assert_ne!(windows.per_user_routing, linux_mvp.per_user_routing);
        assert_ne!(
            windows.per_app_block_leakproof,
            linux_mvp.per_app_block_leakproof
        );
        assert_ne!(
            windows.per_user_all_protocol_scoping,
            linux_mvp.per_user_all_protocol_scoping
        );
    }

    /// Drift guard: the GUI-facing `PlatformProfile.supports.*` (in `nrr-shared`,
    /// which sits BELOW this crate and cannot import `EnforcementCapabilities`,
    /// so the inversion values are duplicated there) MUST agree with this
    /// crate's declared SSOT. This test lives here because `nrr-platform-api`
    /// can see both sides.
    #[test]
    fn platform_profile_supports_mirror_enforcement_capabilities() {
        use nrr_shared::platform_profile::PlatformProfile;

        let win_caps = EnforcementCapabilities::windows();
        let win_sup = PlatformProfile::windows().supports;
        assert_eq!(win_sup.per_user_routing, win_caps.per_user_routing);
        assert_eq!(
            win_sup.per_app_block_leakproof,
            win_caps.per_app_block_leakproof
        );
        assert_eq!(
            win_sup.per_user_all_protocol_scoping,
            win_caps.per_user_all_protocol_scoping
        );

        let lin_caps = EnforcementCapabilities::linux_mvp();
        let lin_sup = PlatformProfile::linux().supports;
        assert_eq!(lin_sup.per_user_routing, lin_caps.per_user_routing);
        assert_eq!(
            lin_sup.per_app_block_leakproof,
            lin_caps.per_app_block_leakproof
        );
        assert_eq!(
            lin_sup.per_user_all_protocol_scoping,
            lin_caps.per_user_all_protocol_scoping
        );
    }
}
