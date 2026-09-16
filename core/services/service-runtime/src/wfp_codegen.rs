//! WFP filter codegen for the 6 canonical rule
//! kinds.
//!
//! Translates a [`CanonicalRuleBook`] + a [`RouteBehaviorMode`] + an
//! [`FqdnCacheLookup`] snapshot into a deterministic list of
//! [`WfpFilterSpec`] entries plus a list of
//! [`CodegenDiagnostic`]s explaining why any rule was skipped or
//! emitted fewer filters than expected.
//!
//! ## Rule-kind translations
//!
//! | Kind | Filters emitted | Notes |
//! |------|-----------------|-------|
//! | [`ExactIp(addr)`] | 1 | `remote_ip = Some(addr)`, action `Permit`. |
//! | [`ExactFqdn(name)`] | N | one per cached resolved IPv4. Cold cache → 0 + diagnostic. |
//! | [`SuffixDomain(suffix)`] | Σ | for the apex and each cached subdomain × its cached IPv4 set. Cold cache → 0 + diagnostic. |
//! | [`Zone(zone)`] | Σ | same fan-out as `SuffixDomain` minus the apex — the bare zone label is not a member of its zone. |
//! | App match (no address) | N | one per resolved exe path — the name/glob is resolved to concrete on-disk paths (`app_pattern` = absolute Win32 path). Unresolved name/glob → 0 + `AppUnresolved` diagnostic. |
//! | Default (`StrictSecondaryFailClosed`) | 1 | catch-all `Block` filter at the lowest weight. |
//! | Default (other modes) | 0 | the OS routing table is the catch-all. |
//!
//! [`ExactIp(addr)`]: nrr_domain::canonical::CanonicalAddressMatch::ExactIp
//! [`ExactFqdn(name)`]: nrr_domain::canonical::CanonicalAddressMatch::ExactFqdn
//! [`SuffixDomain(suffix)`]: nrr_domain::canonical::CanonicalAddressMatch::SuffixDomain
//! [`Zone(zone)`]: nrr_domain::canonical::CanonicalAddressMatch::Zone
//!
//! ## Weight assignment
//!
//! Per the WFP semantics, higher numeric weight = higher precedence.
//! We use three weight bands:
//!
//! | Band | Range | Used by |
//! |------|-------|---------|
//! | Block rules     | `0x0070_0000 + pos * SLOTS_PER_RULE + fanout_idx` | `RuleAction::Block` rules (hard drop, role-independent, above the kill-switch permit band) |
//! | Primary rules   | `0x0020_0000 + pos * SLOTS_PER_RULE + fanout_idx` | route rules in `rule_book.primary` |
//! | Secondary rules | `0x0010_0000 + pos * SLOTS_PER_RULE + fanout_idx` | route rules in `rule_book.secondary` |
//! | Default catch-all | `0x0000_FFFF` | fail-closed Block filter |
//!
//! A `RuleAction::Block` rule emits `FWP_ACTION_BLOCK` filters (hard veto via
//! `CLEAR_ACTION_RIGHT`) at both the ALE connect layer (TCP/UDP, SID-scoped)
//! and the packet layer (`OUTBOUND_IPPACKET_V4`, ICMP/other protocols,
//! system-wide per destination) and installs NO route.
//!
//! Primary rules outrank secondary rules so that an explicit
//! `ExactFqdn("api.example.com")` in `primary` wins over a more
//! general `SuffixDomain("example.com")` in `secondary`. `pos` is
//! the rule's canonical-order index inside its rule set
//! (`CanonicalRuleSet::rules()`); `SLOTS_PER_RULE = 256` keeps adjacent
//! rules' weight ranges from colliding. Fan-out targets beyond the band
//! are NOT dropped: they share the band's top slot — within
//! one rule every target carries the same action, so equal weights are
//! order-independent, and only cross-rule precedence needs distinct bands.
//!
//! ## Filter identity
//!
//! [`filter_id_for`] derives [`WfpFilterId`] via FNV-1a over the
//! 5-tuple `(sid, role, rule_id, rule_kind, target)`:
//!
//! - `target` for address kinds = the resolved IPv4 as
//!   `"a.b.c.d"`.
//! - `target` for app match = the resolved app path string.
//! - `target` for the default catch-all = `"block-all"`.
//!
//! Two re-applies of the same `(rule_book, behavior_mode, cache
//! snapshot)` produce **identical** filter ids — that's the
//! idempotent-reapply contract the apply layer relies on.

use std::net::{IpAddr, Ipv4Addr};

use nrr_domain::canonical::{
    CanonicalAddressMatch, CanonicalAppMatch, CanonicalAppPattern, CanonicalRule,
    CanonicalRuleBook, RuleAction,
};
use nrr_platform_api::types::{WfpAction, WfpFilterId, WfpFilterSpec, WfpLayerKey};
use nrr_shared::{RouteBehaviorMode, RouteRole};

use crate::address_ownership::AppDestinationRefusal;
use crate::app_observation_lookup::AppObservationLookup;
use crate::fqdn_cache_lookup::FqdnCacheLookup;

// ── Constants ───────────────────────────────────────────────────────────────

// Weight bands come from `wfp_bands`, which holds the complete order and
// asserts it. This file emits filters; it does not get to invent a band.
use crate::wfp_bands::{
    BAND_WIDTH, BASE_BLOCK, BASE_PRIMARY, BASE_SECONDARY, DEFAULT_BLOCK_WEIGHT,
};

/// Highest rule position a band can hold. `pos` comes from the rule book and
/// nothing upstream caps it, so without this the 8192nd primary rule would land
/// on the kill-switch permit band and the 4096th block rule inside the app
/// exemptions — a rule silently outranking a guard it must never outrank.
/// Positions past the cap SHARE the last slot: still deterministic, still
/// inside the band, and ordering among rules that far down is not what decides
/// anything.
const MAX_RULE_SLOT: u64 = BAND_WIDTH / SLOTS_PER_RULE - 1;

/// Weight of the `fanout_idx`-th filter of the rule at `pos` within `base`'s
/// band. The single place a rule weight is computed, so the cap cannot be
/// applied in two of three call sites.
fn rule_weight(base: u64, pos: u64, fanout_idx: u64) -> u64 {
    base + pos.min(MAX_RULE_SLOT) * SLOTS_PER_RULE + fanout_idx.min(SLOTS_PER_RULE - 1)
}

/// How many fan-out targets a single rule may emit before its weight
/// range collides with the next rule's range.
pub use crate::wfp_bands::SLOTS_PER_RULE;
/// Bounded fan-out cap for the number of resolved exe **paths** a single
/// `Application` rule may emit an `ALE_APP_ID` filter for. A name/glob can
/// resolve to several concrete binaries (32/64-bit installs, per-user +
/// per-machine copies, a glob matching a family); the cap keeps a pathological
/// glob from exhausting the per-rule weight band. Resolved-path filters occupy
/// slots `0..APP_PATH_FANOUT_CAP`; the observed-IP `/32` mirrors start AFTER
/// them (see [`emit_for_app_match`]). Invariant:
/// `APP_PATH_FANOUT_CAP + 1 + PER_HOSTNAME_IP_CAP (16 + 1 + 64 = 81) <
/// SLOTS_PER_RULE (256)`.
/// Declared in `nrr-platform-api` because the Windows lowering needs the same
/// split to recover a rule's own addresses from its app's observed ones.
pub use nrr_platform_api::enforcement::APP_PATH_FANOUT_CAP;
/// Runaway backstop (NOT a product limit) on the number of cached subdomains
/// [`SuffixDomain`](nrr_domain::canonical::CanonicalAddressMatch::SuffixDomain)
/// / [`Zone`](nrr_domain::canonical::CanonicalAddressMatch::Zone)
/// fan-outs will pull from the cache per rule.
///
///  — the old 256 cap (tied to [`SLOTS_PER_RULE`]) is gone: a busy
/// zone rule (`.ru`) overflowed it in normal use and every host beyond the
/// window lost its permit under block-all. Weight slots no longer bound the
/// fan-out — targets beyond the band simply share the band's top slot (see
/// `emit_suffix_fanout`) — so the only remaining bound is this defensive
/// ceiling against a pathological cache. The source query returns hosts in
/// `last_seen_at DESC` order, so even at the backstop the window holds the
/// most recently used hosts.
pub const SUFFIX_FANOUT_BACKSTOP: usize = 4096;
/// Default cap on the number of resolved IPs a single
/// [`ExactFqdn`](nrr_domain::canonical::CanonicalAddressMatch::ExactFqdn)
/// rule will emit filters for. Most A-records return ≤ 16 entries;
/// the cap is generous to keep edge-case CDN responses from being
/// silently truncated, but bounded to avoid runaway filter sets.
pub const PER_HOSTNAME_IP_CAP: usize = 64;

// ── Input / output ──────────────────────────────────────────────────────────

/// All inputs the codegen needs in a single bag. Borrowed — caller
/// owns the rule book / cache for the duration of the call.
pub struct CodegenInput<'a> {
    /// User SID the filters are scoped to. Stamped into every
    /// filter's `user_sid` field so `FWPM_CONDITION_ALE_USER_ID`
    /// matches only this user's connections.
    pub sid: &'a str,
    /// Canonical rules from the active revision.
    pub rule_book: &'a CanonicalRuleBook,
    /// Default routing behaviour when no rule matches. Determines
    /// whether the catch-all `Block` filter is emitted.
    pub behavior_mode: RouteBehaviorMode,
    /// FQDN/IP cache snapshot, queried for `ExactFqdn` /
    /// `SuffixDomain` / `Zone` fan-outs.
    pub fqdn_cache: &'a dyn FqdnCacheLookup,
    /// Observed app→IP map, queried for `Application` rule
    /// fan-out: an app rule routes the IPs the process has been observed
    /// connecting to, as /32s — the same mechanism `ExactFqdn` uses.
    pub app_observations: &'a dyn AppObservationLookup,
    /// resolves an `Application` rule's exe name/glob to the
    /// concrete on-disk exe paths present on this machine. The WFP
    /// `ALE_APP_ID` condition keys on a real file path
    /// (`FwpmGetAppIdFromFileName0`), NOT a name/glob, so the codegen emits one
    /// per-app filter per resolved path; an unresolved rule emits no app-id
    /// filter and records an [`CodegenDiagnostic::AppUnresolved`]. Defaults to a
    /// `NoopAppPathResolver` in unwired paths (app rules then resolve nothing).
    pub app_resolver: &'a dyn nrr_platform_api::AppPathResolver,
    /// secondary IPs the shared-IP policy declined to commit.
    /// The SECONDARY-role fan-out is fed a cache view that hides these, so no
    /// `/32` permit is emitted for them (kept consistent with the route codegen).
    /// Empty for the aggressive policy / no collateral — the common case.
    pub secondary_ip_denylist: &'a std::collections::HashSet<std::net::Ipv4Addr>,
    /// Evaluate a zone rule ahead of an exact-address rule, from the
    /// principal's stored `zone_priority_over_ip`. Reaches the
    /// address-ownership arbiter, which is the one place the two can contest
    /// the same address.
    pub zone_priority_over_ip: bool,
    /// Which address families this pass may emit filters for — the Windows
    /// twin of `PlannerInput::ipv6`. `V4Only` reproduces the shape from before
    /// IPv6 existed, filter for filter and weight for weight.
    pub families: crate::enforcement_planner::FamilyScope,
}

/// Result of one codegen invocation.
///
/// `filters` is in **emission order** — primary rules first (in
/// canonical-set order), then secondary rules, then the default
/// catch-all (if any). Tests that assert on filter content can
/// reason about ordering without resorting; production callers feed
/// the vector straight into `WfpSession::execute_wfp_plan`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CodegenOutput {
    pub filters: Vec<WfpFilterSpec>,
    pub diagnostics: Vec<CodegenDiagnostic>,
    /// the deduplicated destination
    /// IPv4 addresses the **secondary** (VPN) rules resolved to, in
    /// emission order. The per-destination kill-switch protects this set
    /// minus [`Self::app_observed_secondary_ips`] (the orchestrator does the
    /// subtraction): if the secondary adapter drops, these must be blocked
    /// rather than leak out the primary NIC. Primary-rule destinations
    /// are deliberately excluded — they are meant to use the primary
    /// adapter and must never be killed.
    pub secondary_dest_ips: Vec<IpAddr>,
    /// the deduplicated destination IPv4
    /// addresses the **primary** (main-link) rules resolved to, in emission
    /// order. Under an armed fail-closed BLOCK-ALL (Mode-A `FailClosedUnknown`
    /// or an explicit block-all, secondary down) TCP/UDP to these already
    /// escapes at the ALE layer (a primary rule permit at `BASE_PRIMARY`
    /// outranks the catch-all block), but the packet-layer named blocks
    /// (ICMP/IGMP/GRE/ESP) are unconditional, so **ping to a known-primary host
    /// like `ya.ru` was cut** (the 0716 complaint). This set feeds a
    /// packet-layer proto-agnostic permit per IP so a positively primary-routed
    /// host stays fully reachable while "unknown" traffic is blocked. The
    /// orchestrator subtracts [`Self::secondary_dest_ips`] before use: a
    /// shared IP that is ALSO secondary-destined must stay blocked while the
    /// secondary is down (fail-closed), never rescued via the primary permit.
    /// Only used in the block-all branch; in the per-IP path primary IPs are
    /// never blocked in the first place.
    ///
    /// Reports what THIS codegen emitted a permit for — not the answer to "is
    /// this address named by a main-link rule". That question has one owner,
    /// `address_ownership::AddressOwnership`, and the orchestrator's exemption
    /// sets ask it directly; this field's fan-out caps made it a second,
    /// quietly smaller answer to the same question.
    pub primary_dest_ips: Vec<IpAddr>,
    ///  — the deduplicated application id patterns the **secondary**
    /// (VPN) application route rules carry, in emission order. A secondary-
    /// routed app rule emits an unconditional per-process Permit (slot 0, no
    /// interface condition) that would keep egressing the primary NIC if the
    /// secondary adapter dropped; this set feeds the per-app kill-switch
    /// ([`crate::killswitch_codegen::app_kill_switch_filters`]) that pins each
    /// app to the secondary adapter egress. Primary-rule apps are excluded — they are meant
    /// to use the primary NIC and must never be killed.
    pub secondary_app_patterns: Vec<String>,
    /// the deduplicated application id patterns the **primary**
    /// (main-link) application ROUTE rules carry, in emission order. An app the
    /// user explicitly routes to the primary adapter must be EXEMPT from the
    /// kill-switch: fail-closed exists to stop leaks over the unprotected path,
    /// and an app deliberately sent to primary is not a leak. This set feeds the
    /// always-permit exemption ([`crate::killswitch_codegen::primary_app_exempt_filters`])
    /// so, e.g., a VPN client placed on primary can always reach its server to
    /// bring the tunnel up (no fail-closed deadlock). Block app rules are excluded
    /// (they are being dropped, not routed).
    pub primary_app_patterns: Vec<String>,
    /// the built-in
    /// [`DEFAULT_VPN_EXEMPT_PATTERNS`](crate::killswitch_codegen::DEFAULT_VPN_EXEMPT_PATTERNS)
    /// globs (`*vpn*`, `openvpn*`, …) RESOLVED through the injected
    /// [`app_resolver`](CodegenInput::app_resolver) to the concrete on-disk exe
    /// paths present on this machine, deduplicated and sorted for determinism.
    ///
    /// The raw globs must never reach enforcement: the WFP `ALE_APP_ID` condition
    /// keys on a real file path (`FwpmGetAppIdFromFileName0`), so a glob string
    /// stamped verbatim into `app_pattern` is silently skipped by the apply layer
    /// (the exact bug HW-0716 fixes). Resolving them here — the SAME path user app
    /// rules already take — means the orchestrator's fail-closed exemption
    /// (`primary_app_exempt_filters`) only ever stamps real paths. A glob that
    /// resolves to nothing (client not installed) simply contributes nothing; it
    /// never worked when stamped verbatim either.
    pub vpn_default_exempt_paths: Vec<String>,
    /// Deduplicated destination IPs admitted through a RESOLVED secondary
    /// **application** rule's observation fan-out (a subset of
    /// [`Self::secondary_dest_ips`]). These are evidence, not policy: the app's
    /// own leak-guard is its egress-conditional per-app pair, so the
    /// orchestrator excludes them from the per-destination kill-switch pin set
    /// — at ~12 standing filters per pinned address, hours of peer churn from
    /// one P2P app otherwise grow the filter set the platform holds for us into
    /// the thousands, well past what it is meant to carry. An address ALSO named by an address rule
    /// stays pinned (the arbiter's set wins); an app whose exe did not resolve
    /// contributes nothing here, so its destinations keep their pins — no
    /// per-app pair protects them.
    pub app_observed_secondary_ips: Vec<Ipv4Addr>,
}

impl CodegenOutput {
    pub fn is_empty(&self) -> bool {
        self.filters.is_empty()
    }
}

/// One reason a rule produced fewer filters than the caller might
/// expect. Diagnostics are non-fatal — they exist so the GUI can
/// surface "rule X has no effect right now because DNS hasn't
/// resolved Y" style messages.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CodegenDiagnostic {
    /// Rule is `enabled = false`. Emitted once per disabled rule
    /// so the GUI can render "n rules muted" badges.
    SkippedDisabled { rule_id: String },
    /// `ExactFqdn` rule's hostname is not in the FQDN cache (cold
    /// resolution). 0 filters emitted; once the DNS refresh task
    /// (block 16.12.A.1) lands the resolution, the next apply pass
    /// will pick it up.
    HostnameUnresolved { rule_id: String, hostname: String },
    /// `Application` rule's process has no observed connections yet (the
    /// connection observer is off, or the app hasn't connected since the
    /// service started). 0 `/32` filters emitted this pass; the per-process
    /// Permit is still in place, and the next apply after the app connects
    /// picks up the destinations.
    AppUnobserved { rule_id: String, app: String },
    /// An `Application` rule observed a destination the user's own MAIN-route
    /// rules already claim by name, so the address was NOT taken over.
    ///
    /// Two of the user's rules point one address in opposite directions. Pinning
    /// it to the additional link cannot win — the named rule sends it the other
    /// way — and the two orders cancel into a dead destination for EVERY process
    /// on the machine, not just the app. The named rule is the specific
    /// statement about that destination, so it holds.
    AppDestinationClaimedByPrimary {
        rule_id: String,
        app: String,
        ip: Ipv4Addr,
    },
    /// An ADDRESS rule on the additional link named an address the MAIN link's
    /// address rules also name, so no per-address filter was emitted for it.
    ///
    /// The sibling of [`Self::AppDestinationClaimedByPrimary`] for the case
    /// where BOTH claims are address rules. Rules name hosts and filters act on
    /// addresses; one address carries many hosts, so steering a shared one into
    /// the tunnel takes the main link's hosts with it. Aggregated per rule —
    /// `ip` is one example, `count` is how many that rule lost.
    AddressClaimedByPrimary {
        rule_id: String,
        ip: IpAddr,
        count: usize,
    },
    /// An `Application` rule observed a destination a process the rule set
    /// never named is ALSO using, so the address was not pinned.
    ///
    /// A `/32` filter is not process-scoped any more than a route is: pinning
    /// the address moves the other process's traffic too, and the kill-switch
    /// then blocks the address whenever the additional link is down — for that
    /// process as well. Nothing known about an address is not evidence of
    /// exclusivity, so an unobserved one still gets its filter.
    AppDestinationUsedByOtherProcess {
        rule_id: String,
        app: String,
        ip: Ipv4Addr,
    },
    /// an `Application` rule's exe name/glob resolved to NO concrete
    /// exe path on this machine (app not installed / not found). 0 `ALE_APP_ID`
    /// filters emitted this pass — the WFP condition needs a real file path
    /// (`FwpmGetAppIdFromFileName0`), which a bare name/glob cannot supply — so
    /// the rule installs no per-process enforcement until the exe appears. The
    /// observed-IP `/32` mirrors (if any) are still emitted. Surfaced so the GUI
    /// can render "rule X names an app that isn't installed" style hints.
    AppUnresolved { rule_id: String, app: String },
    /// an `Application` rule's name/glob
    /// resolved to MORE than [`APP_PATH_FANOUT_CAP`] concrete exe paths; only the
    /// first `cap` got an `ALE_APP_ID` filter, so enforcement is PARTIAL. Surfaced
    /// so a broad glob silently enforcing a subset is visible in logs/audit rather
    /// than reading as full coverage. `resolved` is the total resolved count.
    AppOverCapped {
        rule_id: String,
        app: String,
        resolved: usize,
        cap: u64,
    },
    /// `SuffixDomain` rule's suffix has no cached subdomains.
    SuffixEmpty { rule_id: String, suffix: String },
    /// `Zone` rule's zone has no cached subdomains.
    ZoneEmpty { rule_id: String, zone: String },
    /// A `SuffixDomain`/`Zone` rule's suffix matched `>= backstop` cached
    /// hostnames — [`FqdnCacheLookup::hostnames_under_suffix`] was called
    /// with [`SUFFIX_FANOUT_BACKSTOP`] and returned exactly that many entries,
    /// so the true cached set is (almost certainly) larger and was truncated:
    /// some rule hosts got NO permit this pass. With the backstop at 4096 this
    /// signals a pathological cache, not normal use. Mirrors
    /// [`CodegenDiagnostic::AppOverCapped`] for the app-path fan-out cap.
    /// `cap` is the fan-out limit that was hit; `suffix` is the rule's
    /// suffix/zone value (the fan-out is shared code for both rule kinds).
    SuffixTruncated {
        rule_id: String,
        suffix: String,
        cap: usize,
    },
    /// Rule has neither address-match nor app-match — should be
    /// impossible after `RulesJsonCodec::decode` (block 16.12.A.2)
    /// enforces the invariant, but kept as defence-in-depth.
    SkippedNoMatch { rule_id: String },
    /// Fail-closed catch-all `Block` filter was emitted. Exactly
    /// one of these appears per codegen output when
    /// `behavior_mode == StrictSecondaryFailClosed`. Useful for
    /// risk-scoring (16.12.A.5): a non-empty diagnostic of this
    /// kind signals "everything-else-blocked" mode is active.
    FailClosedDefaultEmitted,
}

// ── Public entry point ──────────────────────────────────────────────────────

/// Generate filters + diagnostics for the given SID.
///
/// The function is pure: no I/O, no allocation outside the returned
/// vectors. Same inputs → identical filter ids and identical
/// diagnostic vector.
pub fn generate_filters(input: CodegenInput<'_>) -> CodegenOutput {
    let mut out = CodegenOutput::default();

    // a cache view that hides policy-declined shared IPs.
    // Applied ONLY to the secondary role so primary permits are unaffected.
    let secondary_cache = crate::secondary_ip_policy::DenylistFilteredCache::new(
        input.fqdn_cache,
        input.secondary_ip_denylist,
    );

    // Index in `out.filters` where the secondary-role filters begin.
    // The role order below is fixed (Primary then Secondary), so every
    // filter from this offset on is secondary-driven — that slice gives
    // us the kill-switch's protected destination set.
    let mut secondary_filter_start = 0usize;
    // Who owns which address, decided once by the arbiter every mechanism reads.
    // Resolved from the UNFILTERED cache: the denylist view exists to trim what
    // goes to the tunnel, and reading it here would understate what the main
    // link claims.
    let ownership = crate::address_ownership::AddressOwnership::resolve_with_order(
        input.rule_book,
        input.fqdn_cache,
        crate::address_ownership::ZoneVsIpOrder::from_zone_priority_over_ip(
            input.zone_priority_over_ip,
        ),
    );
    for (role_idx, role) in [RouteRole::Primary, RouteRole::Secondary]
        .into_iter()
        .enumerate()
    {
        if role_idx == 1 {
            secondary_filter_start = out.filters.len();
        }
        let rule_set = match role {
            RouteRole::Primary => &input.rule_book.primary,
            RouteRole::Secondary => &input.rule_book.secondary,
        };
        let base = match role {
            RouteRole::Primary => BASE_PRIMARY,
            RouteRole::Secondary => BASE_SECONDARY,
        };
        // Secondary rules read the denylist-filtered view; primary rules the raw
        // cache (a shared IP declined for the secondary must still be reachable
        // via the primary, where it now egresses).
        let cache_for_role: &dyn FqdnCacheLookup = match role {
            RouteRole::Primary => input.fqdn_cache,
            RouteRole::Secondary => &secondary_cache,
        };
        let gate = crate::address_ownership::AppDestinationGate::for_rule_set(
            &ownership,
            input.app_observations,
            rule_set,
        );
        for (pos, rule) in rule_set.rules().iter().enumerate() {
            generate_for_rule(
                input.sid,
                role,
                base,
                pos as u64,
                rule,
                cache_for_role,
                &gate,
                &ownership,
                input.app_resolver,
                input.families,
                &mut out,
            );
        }
    }

    // Collect the secondary-rule destination IPs (deduped, in order) for
    // the kill-switch. App-match filters carry no `remote_ip` and are
    // skipped. Built from the secondary slice into a local first so the
    // immutable borrow of `out.filters` ends before we write the field.
    out.secondary_dest_ips = {
        let mut seen = std::collections::HashSet::new();
        out.filters[secondary_filter_start..]
            .iter()
            // A Block rule's destinations must NOT be fed to the kill-switch as
            // "protect via secondary adapter" targets — we are dropping them, not routing
            // them. Only Permit filters contribute protected destinations.
            .filter(|f| f.action == WfpAction::Permit)
            .flat_map(destination_ips)
            .filter(|ip| seen.insert(*ip))
            .collect()
    };

    //  — collect the secondary-rule application patterns (deduped, in
    // emission order) for the per-app kill-switch. Only Permit (route) app rules
    // contribute — a Block app rule is being dropped, not routed via the secondary adapter, so
    // it must not be "protected". Mirrors the secondary_dest_ips collection.
    out.secondary_app_patterns = {
        let mut seen = std::collections::HashSet::new();
        out.filters[secondary_filter_start..]
            .iter()
            .filter(|f| f.action == WfpAction::Permit)
            .filter_map(|f| f.app_pattern.clone())
            .filter(|p| seen.insert(p.clone()))
            .collect()
    };

    // collect the PRIMARY-rule destination
    // IPs (deduped, in emission order) over the primary slice
    // (`[..secondary_filter_start]`). Only Permit (route) filters with a
    // remote_ip contribute — a Block rule's dests are being dropped, and
    // app-match filters carry no IP. These earn a packet-layer permit under a
    // fail-closed block-all so ping/ICMP to a known-primary host is not cut
    // alongside truly-unknown traffic. Mirrors `secondary_dest_ips`.
    out.primary_dest_ips = {
        let mut seen = std::collections::HashSet::new();
        out.filters[..secondary_filter_start]
            .iter()
            .filter(|f| f.action == WfpAction::Permit)
            .flat_map(destination_ips)
            .filter(|ip| seen.insert(*ip))
            .collect()
    };

    // collect the PRIMARY-rule application patterns (deduped, in
    // emission order) for the kill-switch exemption. Mirrors secondary_app_patterns
    // but over the primary slice (`[..secondary_filter_start]`). Only Permit (route)
    // app rules contribute — a Block app rule is being dropped, not routed. These
    // feed `primary_app_exempt_filters`: an app the user routed to the primary
    // adapter must never be killed by fail-closed (it is not a leak).
    out.primary_app_patterns = {
        let mut seen = std::collections::HashSet::new();
        out.filters[..secondary_filter_start]
            .iter()
            .filter(|f| f.action == WfpAction::Permit)
            .filter_map(|f| f.app_pattern.clone())
            .filter(|p| seen.insert(p.clone()))
            .collect()
    };

    // resolve the built-in VPN-client exemption GLOBS
    // (`*vpn*`, `openvpn*`, …) to concrete on-disk exe paths through the SAME
    // resolver user app rules use. The orchestrator's fail-closed exemption stamps
    // these into `ALE_APP_ID` filters, which need a real file path — a raw glob is
    // silently dropped by the apply layer. Deduped case-insensitively and sorted so
    // the emitted exemption set is deterministic regardless of resolver ordering.
    out.vpn_default_exempt_paths = {
        let mut seen = std::collections::HashSet::new();
        let mut paths: Vec<String> = crate::killswitch_codegen::DEFAULT_VPN_EXEMPT_PATTERNS
            .iter()
            .flat_map(|glob| input.app_resolver.resolve(glob))
            .map(|p| p.to_string_lossy().into_owned())
            .filter(|p| seen.insert(p.to_ascii_lowercase()))
            .collect();
        paths.sort_unstable();
        paths
    };

    if matches!(
        input.behavior_mode,
        RouteBehaviorMode::StrictSecondaryFailClosed
    ) {
        out.filters.push(default_block_spec(input.sid));
        out.diagnostics
            .push(CodegenDiagnostic::FailClosedDefaultEmitted);
    }

    out
}

// ── Per-rule dispatch ───────────────────────────────────────────────────────

/// Per-rule emission context distinguishing a route (Permit) rule from a
/// hard-block rule. Threaded through every emit helper so both share the
/// identical address/app resolution fan-out — only the emitted spec's action,
/// weight band, filter-id kind prefix, and packet-layer mirror differ.
#[derive(Clone, Copy)]
struct EmitContext {
    /// WFP action for this rule's ALE filters: `Permit` (route) or `Block`.
    action: WfpAction,
    /// Weight base band: `BASE_PRIMARY`/`BASE_SECONDARY` for route rules,
    /// `BASE_BLOCK` for block rules (role-independent).
    base_weight: u64,
    /// Filter-id kind prefix (`""` route, `"block-"` block) so a block filter's
    /// id never collides with the route filter for the same rule/target.
    kind_prefix: &'static str,
    /// Which families this pass may name. Carried on the context rather than
    /// passed alongside it so every emitter reached from here answers the
    /// question the same way.
    families: crate::enforcement_planner::FamilyScope,
}

impl EmitContext {
    /// True when this rule drops traffic (hard block). Block rules additionally
    /// get a packet-layer (`OUTBOUND_IPPACKET_V4`) mirror per resolved IP so
    /// ICMP/other-protocol traffic is dropped, not just TCP/UDP.
    fn is_block(&self) -> bool {
        matches!(self.action, WfpAction::Block)
    }
}

#[allow(clippy::too_many_arguments)]
fn generate_for_rule(
    sid: &str,
    role: RouteRole,
    base_weight: u64,
    pos: u64,
    rule: &CanonicalRule,
    cache: &dyn FqdnCacheLookup,
    gate: &crate::address_ownership::AppDestinationGate<'_>,
    ownership: &crate::address_ownership::AddressOwnership,
    app_resolver: &dyn nrr_platform_api::AppPathResolver,
    families: crate::enforcement_planner::FamilyScope,
    out: &mut CodegenOutput,
) {
    if !rule.enabled {
        out.diagnostics.push(CodegenDiagnostic::SkippedDisabled {
            rule_id: rule.id.as_str().to_string(),
        });
        return;
    }

    // The "≥1 match" invariant is enforced by the rules-json codec
    // (block 16.12.A.2), but defensively handle the violation here
    // so a hand-crafted CanonicalRule from a future caller can't
    // silently emit zero filters with no explanation.
    if rule.address_match.is_none() && rule.app_match.is_none() {
        out.diagnostics.push(CodegenDiagnostic::SkippedNoMatch {
            rule_id: rule.id.as_str().to_string(),
        });
        return;
    }

    let role_slug = role_slug(role);
    // A Block rule overrides the route: it drops its destination regardless of
    // which set (primary/secondary) it lives in, using the BASE_BLOCK band.
    let ctx = match rule.action {
        RuleAction::Route => EmitContext {
            action: WfpAction::Permit,
            base_weight,
            kind_prefix: "",
            families,
        },
        RuleAction::Block => EmitContext {
            action: WfpAction::Block,
            base_weight: BASE_BLOCK,
            kind_prefix: "block-",
            families,
        },
    };

    let link = match role {
        RouteRole::Primary => crate::address_ownership::Link::Main,
        RouteRole::Secondary => crate::address_ownership::Link::Additional,
    };
    if let Some(addr_match) = rule.address_match.as_ref() {
        // A Block rule claims nothing and steers nothing — it drops its
        // destination, so the arbiter has no say over it (module rule 3).
        let steerable = |ip: IpAddr| {
            matches!(rule.action, RuleAction::Block) || ownership.address_rule_may_steer(ip, link)
        };
        emit_for_address_match(
            sid, role_slug, ctx, pos, rule, addr_match, cache, &steerable, out,
        );
    } else if let Some(app) = rule.app_match.as_ref() {
        emit_for_app_match(
            sid,
            role_slug,
            ctx,
            pos,
            rule,
            app,
            gate,
            app_resolver,
            link,
            out,
        );
    }
}

// Codegen helper threading the full WFP filter context (layer, action, sid,
// weight, …) — splitting it into a struct would obscure the call sites.
#[allow(clippy::too_many_arguments)]
fn emit_for_address_match(
    sid: &str,
    role_slug: &str,
    ctx: EmitContext,
    pos: u64,
    rule: &CanonicalRule,
    addr_match: &CanonicalAddressMatch,
    cache: &dyn FqdnCacheLookup,
    steerable: &dyn Fn(IpAddr) -> bool,
    out: &mut CodegenOutput,
) {
    let mut held: Option<(IpAddr, usize)> = None;
    match addr_match {
        // The pass names no IPv6 while no link carries the family.
        CanonicalAddressMatch::ExactIp(addr) if !ctx.families.admits(*addr) => {}
        CanonicalAddressMatch::ExactIp(addr) => {
            let addr = *addr;
            if steerable(addr) {
                emit_packed_ip_filters(
                    sid,
                    role_slug,
                    ctx,
                    pos,
                    0,
                    rule,
                    "exact-ip",
                    vec![addr],
                    out,
                );
            } else {
                note_held(&mut held, addr);
            }
        }
        CanonicalAddressMatch::ExactFqdn(hostname) => {
            let ips = cache.ips_for_hostname(hostname);
            if ips.is_empty() {
                out.diagnostics.push(CodegenDiagnostic::HostnameUnresolved {
                    rule_id: rule.id.as_str().to_string(),
                    hostname: hostname.clone(),
                });
                return;
            }
            let mut steerable_ips = Vec::new();
            for ip in crate::enforcement_planner::capped_for_host(cache, hostname, ctx.families) {
                if steerable(ip) {
                    steerable_ips.push(ip);
                } else {
                    note_held(&mut held, ip);
                }
            }
            emit_packed_ip_filters(
                sid,
                role_slug,
                ctx,
                pos,
                0,
                rule,
                "exact-fqdn",
                steerable_ips,
                out,
            );
        }
        CanonicalAddressMatch::SuffixDomain(suffix) => {
            emit_suffix_fanout(
                sid,
                role_slug,
                ctx,
                pos,
                rule,
                "suffix-domain",
                suffix,
                // `*.suffix` covers the apex too — expand it into the fan-out.
                SuffixFanoutKind::SuffixDomain,
                cache,
                steerable,
                &mut held,
                out,
                |id, s| CodegenDiagnostic::SuffixEmpty {
                    rule_id: id,
                    suffix: s,
                },
            );
        }
        CanonicalAddressMatch::Zone(zone) => {
            emit_suffix_fanout(
                sid,
                role_slug,
                ctx,
                pos,
                rule,
                "zone",
                zone,
                // A zone rule never covers the bare zone label.
                SuffixFanoutKind::Zone,
                cache,
                steerable,
                &mut held,
                out,
                |id, z| CodegenDiagnostic::ZoneEmpty {
                    rule_id: id,
                    zone: z,
                },
            );
        }
    }
    if let Some((ip, count)) = held {
        out.diagnostics
            .push(CodegenDiagnostic::AddressClaimedByPrimary {
                rule_id: rule.id.as_str().to_string(),
                ip,
                count,
            });
    }
}

/// Record one held-back address: the first is kept as the example, all of them
/// count.
fn note_held(held: &mut Option<(IpAddr, usize)>, ip: IpAddr) {
    match held {
        Some((_, count)) => *count += 1,
        None => *held = Some((ip, 1)),
    }
}

/// Which host set a suffix-shaped rule expands to.
///
/// The two forms share a fan-out body but not their coverage:
/// `SuffixDomain` includes the apex, `Zone` does not.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SuffixFanoutKind {
    SuffixDomain,
    Zone,
}

/// Shared body of `SuffixDomain` and `Zone` fan-out. They differ only
/// in the host set (apex included or not), the diagnostic constructor,
/// and the rule-kind slug stamped into the filter id derivation.
#[allow(clippy::too_many_arguments)]
fn emit_suffix_fanout<F>(
    sid: &str,
    role_slug: &str,
    ctx: EmitContext,
    pos: u64,
    rule: &CanonicalRule,
    rule_kind: &str,
    suffix_or_zone: &str,
    kind: SuffixFanoutKind,
    cache: &dyn FqdnCacheLookup,
    steerable: &dyn Fn(IpAddr) -> bool,
    held: &mut Option<(IpAddr, usize)>,
    out: &mut CodegenOutput,
    empty_diagnostic: F,
) where
    F: FnOnce(String, String) -> CodegenDiagnostic,
{
    let subdomains = match kind {
        SuffixFanoutKind::SuffixDomain => {
            cache.hostnames_for_suffix_domain(suffix_or_zone, SUFFIX_FANOUT_BACKSTOP)
        }
        SuffixFanoutKind::Zone => {
            cache.hostnames_under_suffix(suffix_or_zone, SUFFIX_FANOUT_BACKSTOP)
        }
    };
    if subdomains.is_empty() {
        out.diagnostics.push(empty_diagnostic(
            rule.id.as_str().to_string(),
            suffix_or_zone.to_string(),
        ));
        return;
    }
    if subdomains.len() >= SUFFIX_FANOUT_BACKSTOP {
        out.diagnostics.push(CodegenDiagnostic::SuffixTruncated {
            rule_id: rule.id.as_str().to_string(),
            suffix: suffix_or_zone.to_string(),
            cap: SUFFIX_FANOUT_BACKSTOP,
        });
    }
    // Collected, then packed: one filter per CHUNK of addresses rather than one
    // per (subdomain, address). A `.ru` zone rule over a warm cache is where the
    // rule band grew to thousands of standing filters.
    //
    // The subdomain stops appearing in the filter id, which is what made each
    // pair unique before. Identity now comes from the chunk's own digest — the
    // same address set always yields the same id — and the subdomain a filter
    // came from was never a fact the enforcement path read back.
    let mut fanout_ips = Vec::new();
    for sub in subdomains {
        let ips = cache.ips_for_hostname(&sub);
        if ips.is_empty() {
            // The hostname is in the cache (e.g. observed-only) but
            // has no IPs we can pin a filter to. Skip silently —
            // this is normal during DNS refresh windows and would
            // be noisy to surface per-subdomain.
            continue;
        }
        for ip in crate::enforcement_planner::capped_for_host(cache, &sub, ctx.families) {
            if steerable(ip) {
                fanout_ips.push(ip);
            } else {
                note_held(held, ip);
            }
        }
    }
    emit_packed_ip_filters(
        sid, role_slug, ctx, pos, 0, rule, rule_kind, fanout_ips, out,
    );
}

#[allow(clippy::too_many_arguments)]
fn emit_for_app_match(
    sid: &str,
    role_slug: &str,
    ctx: EmitContext,
    pos: u64,
    rule: &CanonicalRule,
    app: &CanonicalAppMatch,
    gate: &crate::address_ownership::AppDestinationGate<'_>,
    app_resolver: &dyn nrr_platform_api::AppPathResolver,
    link: crate::address_ownership::Link,
    out: &mut CodegenOutput,
) {
    let pattern_str = match &app.pattern {
        CanonicalAppPattern::Exact(s) | CanonicalAppPattern::Glob(s) => s.clone(),
    };
    // The per-process filter (app-id condition). For a route rule this is a
    // Permit (the app is explicitly allowed and the kill-switch's
    // block-when-unavailable posture still governs it). For a Block rule this
    // drops all connect-layer traffic from the process. (ICMP from a specific
    // process is not matchable at the packet layer, which has no app context —
    // the /32 mirrors below cover the app's observed destinations.)
    //
    // The WFP `ALE_APP_ID` condition keys on a real, on-disk file PATH
    // (`FwpmGetAppIdFromFileName0`), NOT the rule's name/glob — so we resolve
    // the name/glob to the concrete exe paths present on this machine and emit
    // one filter per resolved path (slots `0..APP_PATH_FANOUT_CAP`). An
    // unresolved app (not installed / not found) emits NO app-id filter and
    // records an `AppUnresolved` diagnostic; before this bridge the raw
    // name/glob was stamped into `app_pattern`, which the apply layer then
    // silently skipped (no per-app enforcement). The resolved paths flow into
    // `secondary_app_patterns` for the per-app kill-switch, so it too pins real
    // paths.
    let app_kind = format!("{}app", ctx.kind_prefix);
    let paths = app_resolver.resolve(&pattern_str);
    if paths.is_empty() {
        out.diagnostics.push(CodegenDiagnostic::AppUnresolved {
            rule_id: rule.id.as_str().to_string(),
            app: pattern_str.clone(),
        });
    } else {
        // a glob resolving to more paths than
        // the fan-out cap enforces only the first `cap`; record it so the partial
        // coverage is not silent (the apply layer / audit surfaces the diagnostic).
        if paths.len() > APP_PATH_FANOUT_CAP as usize {
            out.diagnostics.push(CodegenDiagnostic::AppOverCapped {
                rule_id: rule.id.as_str().to_string(),
                app: pattern_str.clone(),
                resolved: paths.len(),
                cap: APP_PATH_FANOUT_CAP,
            });
        }
        for (k, path) in paths.iter().take(APP_PATH_FANOUT_CAP as usize).enumerate() {
            let path_str = path.to_string_lossy();
            let id = filter_id_for(sid, role_slug, rule.id.as_str(), &app_kind, &path_str);
            out.filters.push(WfpFilterSpec {
                layer: WfpLayerKey::AleAuthConnectV4,
                action: ctx.action,
                remote_ip: None,
                remote_ip_set: Vec::new(),
                remote_ip_set_v6: Vec::new(),
                remote_port: None,
                weight: rule_weight(ctx.base_weight, pos, k as u64),
                id,
                user_sid: Some(sid.to_string()),
                app_pattern: Some(path_str.into_owned()),
                local_interface_luid: None,
                remote_subnet: None,
                remote_subnet_v6: None,
                ip_protocol: None,
            });
        }
    }

    // App-routing via observation: route the IPs this app has
    // been observed connecting to as `/32`s on this rule's route — the same
    // mechanism `ExactFqdn` uses, so a secondary app rule's destinations also
    // feed `secondary_dest_ips` and the kill-switch covers them. Both exact
    // (`chrome.exe`) and glob (`*vpn*.exe`) patterns resolve through
    // `ips_for_app` (the store unions matching processes for a glob). The
    // `/32` fan-out starts AFTER the resolved-path band (slots
    // `APP_PATH_FANOUT_CAP + 1 + i`) so it never collides with the per-path
    // app-id filters above.
    // Ownership and the outside-use census, asked through the gate the route
    // codegen reads — the two mechanisms must not disagree about who owns an
    // address, because a pin one way and a block the other leave the
    // destination dead for every process on the machine.
    let destinations = gate.admit(&pattern_str, link);
    let refused_count = destinations.refused.len();
    for (ip, reason) in destinations.refused {
        out.diagnostics.push(match reason {
            AppDestinationRefusal::ClaimedByAddressRule => {
                CodegenDiagnostic::AppDestinationClaimedByPrimary {
                    rule_id: rule.id.as_str().to_string(),
                    app: pattern_str.clone(),
                    ip,
                }
            }
            AppDestinationRefusal::UsedByOtherProcess => {
                CodegenDiagnostic::AppDestinationUsedByOtherProcess {
                    rule_id: rule.id.as_str().to_string(),
                    app: pattern_str.clone(),
                    ip,
                }
            }
        });
    }
    let ips = destinations.admitted;
    if ips.is_empty() {
        // "Never observed" and "everything it was seen using belongs to
        // somebody else" are different answers, and only the first one tells
        // the user to go run the application. The refusals above already say
        // which rule took each address; adding `AppUnobserved` on top sent the
        // user looking for a process that had, in fact, been seen.
        if refused_count == 0 {
            out.diagnostics.push(CodegenDiagnostic::AppUnobserved {
                rule_id: rule.id.as_str().to_string(),
                app: pattern_str,
            });
        }
    } else {
        // Only a RESOLVED route rule's destinations are marked app-observed:
        // the mark tells the orchestrator "the per-app pair covers this IP, no
        // per-destination pin needed", and an unresolved app has no pair.
        let app_pair_covers = ctx.action == WfpAction::Permit
            && link == crate::address_ownership::Link::Additional
            && !paths.is_empty();
        // App observations are IPv4: the destination memory records what the
        // conn observer saw, and it has no v6 half yet.
        let mut observed = Vec::new();
        for ip in ips.into_iter().take(PER_HOSTNAME_IP_CAP) {
            if app_pair_covers && !out.app_observed_secondary_ips.contains(&ip) {
                out.app_observed_secondary_ips.push(ip);
            }
            observed.push(IpAddr::V4(ip));
        }
        // Packed like every other address group, but in the slot range that
        // starts after the per-path app-id filters — the two must not share
        // slots, and the neutral lowering recovers the same split from the
        // ordinal.
        emit_packed_ip_filters(
            sid,
            role_slug,
            ctx,
            pos,
            APP_PATH_FANOUT_CAP + 1,
            rule,
            "application",
            observed,
            out,
        );
    }
}

// ── Filter constructors ─────────────────────────────────────────────────────

/// Every destination address a filter carries, whichever shape it is in.
///
/// A packed filter holds its addresses in `remote_ip_set`; a single-address one
/// in `remote_ip`. Every collector below reads through here, because reading
/// only the single field is how the packing change silently emptied
/// `secondary_dest_ips` — and that set is what the kill switch protects and
/// what the route table steers.
fn destination_ips(spec: &WfpFilterSpec) -> impl Iterator<Item = IpAddr> + '_ {
    spec.remote_ip
        .into_iter()
        .map(IpAddr::V4)
        .chain(spec.remote_ip_set.iter().copied().map(IpAddr::V4))
        .chain(spec.remote_ip_set_v6.iter().copied().map(IpAddr::V6))
}

/// Emit one rule's address set as PACKED chunks instead of one filter per
/// address.
///
/// WFP ORs several conditions on the same field, so a rule that resolves to
/// hundreds of addresses does not need hundreds of filters. That matters beyond
/// tidiness: four 0xEF bugchecks were traced to the BFE host degrading over
/// hours under thousands of standing filters, and the rule band was the largest
/// producer left after the kill switch was packed — about 2000 of 2260 on the
/// first measured run.
///
/// Safe here for the reason the fan-out comment already states: within one rule
/// every target carries the SAME verdict, so their relative order is
/// irrelevant. Ordering still matters BETWEEN rules, and that is untouched —
/// each chunk sits at `rule_weight(base, pos, chunk_index)`, inside the same
/// per-rule slot range a per-address filter used.
///
/// Filter identity becomes content-addressed (the chunk's digest), like the
/// kill switch's: the same address set always yields the same id, so a
/// recompute that changes nothing installs nothing.
#[allow(clippy::too_many_arguments)]
fn emit_packed_ip_filters(
    sid: &str,
    role_slug: &str,
    ctx: EmitContext,
    pos: u64,
    slot_base: u64,
    rule: &CanonicalRule,
    rule_kind: &str,
    ips: Vec<IpAddr>,
    out: &mut CodegenOutput,
) {
    let kind = format!("{}{}", ctx.kind_prefix, rule_kind);
    for (idx, chunk) in nrr_platform_api::wfp_slotting::pack_both(ips)
        .into_iter()
        .enumerate()
    {
        let weight = rule_weight(ctx.base_weight, pos, slot_base + idx as u64);
        let target = chunk.id_seg();
        let id = filter_id_for(sid, role_slug, rule.id.as_str(), &kind, &target);
        let mut spec = chunk_spec(&chunk, ale_layer(&chunk), ctx.action, weight, id);
        spec.user_sid = Some(sid.to_string());
        out.filters.push(spec);
        if ctx.is_block() {
            push_packed_packet_block_mirror(
                sid, role_slug, rule, &kind, &target, &chunk, weight, out,
            );
        }
    }
}

/// The ALE connect layer for a chunk's family.
pub(crate) fn ale_layer(chunk: &nrr_platform_api::wfp_slotting::FamilyChunk) -> WfpLayerKey {
    match chunk {
        nrr_platform_api::wfp_slotting::FamilyChunk::V4(_) => WfpLayerKey::AleAuthConnectV4,
        nrr_platform_api::wfp_slotting::FamilyChunk::V6(_) => WfpLayerKey::AleAuthConnectV6,
    }
}

/// The packet layer for a chunk's family.
pub(crate) fn packet_layer(chunk: &nrr_platform_api::wfp_slotting::FamilyChunk) -> WfpLayerKey {
    match chunk {
        nrr_platform_api::wfp_slotting::FamilyChunk::V4(_) => WfpLayerKey::OutboundIpPacketV4,
        nrr_platform_api::wfp_slotting::FamilyChunk::V6(_) => WfpLayerKey::OutboundIpPacketV6,
    }
}

/// One packed chunk as a filter spec — the family decides which address-set
/// field carries it, and nothing else about the filter changes.
pub(crate) fn chunk_spec(
    chunk: &nrr_platform_api::wfp_slotting::FamilyChunk,
    layer: WfpLayerKey,
    action: WfpAction,
    weight: u64,
    id: nrr_platform_api::types::WfpFilterId,
) -> WfpFilterSpec {
    use nrr_platform_api::wfp_slotting::FamilyChunk;
    WfpFilterSpec {
        layer,
        action,
        remote_ip: None,
        remote_ip_set: match chunk {
            FamilyChunk::V4(c) => c.members.clone(),
            FamilyChunk::V6(_) => Vec::new(),
        },
        remote_ip_set_v6: match chunk {
            FamilyChunk::V6(c) => c.members.clone(),
            FamilyChunk::V4(_) => Vec::new(),
        },
        remote_port: None,
        weight,
        id,
        user_sid: None,
        app_pattern: None,
        local_interface_luid: None,
        remote_subnet: None,
        remote_subnet_v6: None,
        ip_protocol: None,
    }
}

/// Packet-layer mirror of a packed Block chunk. Same reasoning as the
/// per-address mirror it replaces: the ALE layer does not classify ICMP and
/// friends, so an explicit Block needs its packet-layer twin.
#[allow(clippy::too_many_arguments)]
fn push_packed_packet_block_mirror(
    sid: &str,
    role_slug: &str,
    rule: &CanonicalRule,
    kind: &str,
    target: &str,
    chunk: &nrr_platform_api::wfp_slotting::FamilyChunk,
    weight: u64,
    out: &mut CodegenOutput,
) {
    let pkt_kind = format!("{kind}-pkt");
    let id = filter_id_for(sid, role_slug, rule.id.as_str(), &pkt_kind, target);
    out.filters.push(chunk_spec(
        chunk,
        packet_layer(chunk),
        WfpAction::Block,
        weight,
        id,
    ));
}

fn default_block_spec(sid: &str) -> WfpFilterSpec {
    let id = filter_id_for(sid, "default", "", "default", "block-all");
    WfpFilterSpec {
        layer: WfpLayerKey::AleAuthConnectV4,
        action: WfpAction::Block,
        remote_ip: None,
        remote_ip_set: Vec::new(),
        remote_ip_set_v6: Vec::new(),
        remote_port: None,
        weight: DEFAULT_BLOCK_WEIGHT,
        id,
        user_sid: Some(sid.to_string()),
        app_pattern: None,
        local_interface_luid: None,
        remote_subnet: None,
        remote_subnet_v6: None,
        ip_protocol: None,
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn role_slug(role: RouteRole) -> &'static str {
    match role {
        RouteRole::Primary => "primary",
        RouteRole::Secondary => "secondary",
    }
}

/// FNV-1a over the deterministic 5-tuple
/// `sid / role / rule_id / rule_kind / target`. The forward-slash
/// separator can't appear in any well-formed component (SIDs use
/// hyphens, rule ids use `r-` prefix + alphanumerics, kinds are
/// fixed slugs, targets are dotted-quads / paths) — so the encoding
/// has no ambiguity.
pub fn filter_id_for(
    sid: &str,
    role: &str,
    rule_id: &str,
    rule_kind: &str,
    target: &str,
) -> WfpFilterId {
    let mut hash: u64 = 0xcbf29ce484222325;
    for part in [sid, role, rule_id, rule_kind, target] {
        for byte in part.as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x100000001b3);
        }
        hash ^= b'/' as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    WfpFilterId { raw: hash }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
