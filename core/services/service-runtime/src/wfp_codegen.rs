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
//! | Block rules     | `0x0060_0000 + pos * SLOTS_PER_RULE + fanout_idx` | `RuleAction::Block` rules (hard drop, role-independent, above the kill-switch permit band) |
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

use std::net::Ipv4Addr;

use nrr_domain::canonical::{
    CanonicalAddressMatch, CanonicalAppMatch, CanonicalAppPattern, CanonicalRule,
    CanonicalRuleBook, RuleAction,
};
use nrr_platform_api::types::{WfpAction, WfpFilterId, WfpFilterSpec, WfpLayerKey};
use nrr_shared::{RouteBehaviorMode, RouteRole};

use crate::app_observation_lookup::AppObservationLookup;
use crate::fqdn_cache_lookup::FqdnCacheLookup;

// ── Constants ───────────────────────────────────────────────────────────────

/// Base WFP weight for `primary`-route rules. Above the secondary
/// band so explicit primary rules outrank more general secondary
/// rules. Each rule occupies a 256-slot range starting at
/// `BASE_PRIMARY + pos * SLOTS_PER_RULE`.
const BASE_PRIMARY: u64 = 0x0020_0000;
/// Base WFP weight for `secondary`-route rules.
const BASE_SECONDARY: u64 = 0x0010_0000;
/// Base WFP weight for per-rule **Block**-action filters. Placed ABOVE the
/// kill-switch permit band (`KILLSWITCH_PERMIT_BASE = 0x0040_0000`) so an
/// explicit user Block beats even the kill-switch's egress-conditional permit
/// and every route-rule Permit band. The hard veto itself comes from
/// `FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT`, which `wfp_filter.rs` stamps on every
/// `WfpAction::Block` filter automatically. Block filters are role-independent
/// (drop regardless of primary/secondary set membership).
const BASE_BLOCK: u64 = 0x0060_0000;
/// Weight of the fail-closed catch-all filter. Below every per-rule
/// weight so a rule-driven `Permit` always wins.
const DEFAULT_BLOCK_WEIGHT: u64 = 0x0000_FFFF;
/// How many fan-out targets a single rule may emit before its weight
/// range collides with the next rule's range.
pub const SLOTS_PER_RULE: u64 = 256;
/// Bounded fan-out cap for the number of resolved exe **paths** a single
/// `Application` rule may emit an `ALE_APP_ID` filter for. A name/glob can
/// resolve to several concrete binaries (32/64-bit installs, per-user +
/// per-machine copies, a glob matching a family); the cap keeps a pathological
/// glob from exhausting the per-rule weight band. Resolved-path filters occupy
/// slots `0..APP_PATH_FANOUT_CAP`; the observed-IP `/32` mirrors start AFTER
/// them (see [`emit_for_app_match`]). Invariant:
/// `APP_PATH_FANOUT_CAP + 1 + PER_HOSTNAME_IP_CAP (16 + 1 + 64 = 81) <
/// SLOTS_PER_RULE (256)`.
pub const APP_PATH_FANOUT_CAP: u64 = 16;
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
    /// emission order. This is exactly the set the per-destination
    /// kill-switch protects: if the secondary adapter drops, these must be blocked
    /// rather than leak out the primary NIC. Primary-rule destinations
    /// are deliberately excluded — they are meant to use the primary
    /// adapter and must never be killed.
    pub secondary_dest_ips: Vec<Ipv4Addr>,
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
    pub primary_dest_ips: Vec<Ipv4Addr>,
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
        for (pos, rule) in rule_set.rules().iter().enumerate() {
            generate_for_rule(
                input.sid,
                role,
                base,
                pos as u64,
                rule,
                cache_for_role,
                input.app_observations,
                input.app_resolver,
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
            .filter_map(|f| f.remote_ip)
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
            .filter_map(|f| f.remote_ip)
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
    app_observations: &dyn AppObservationLookup,
    app_resolver: &dyn nrr_platform_api::AppPathResolver,
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
        },
        RuleAction::Block => EmitContext {
            action: WfpAction::Block,
            base_weight: BASE_BLOCK,
            kind_prefix: "block-",
        },
    };

    if let Some(addr_match) = rule.address_match.as_ref() {
        emit_for_address_match(sid, role_slug, ctx, pos, rule, addr_match, cache, out);
    } else if let Some(app) = rule.app_match.as_ref() {
        emit_for_app_match(
            sid,
            role_slug,
            ctx,
            pos,
            rule,
            app,
            app_observations,
            app_resolver,
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
    out: &mut CodegenOutput,
) {
    match addr_match {
        CanonicalAddressMatch::ExactIp(addr) => {
            emit_single_ip_filter(sid, role_slug, ctx, pos, 0, rule, "exact-ip", *addr, out);
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
            for (i, ip) in ips.into_iter().take(PER_HOSTNAME_IP_CAP).enumerate() {
                emit_single_ip_filter(
                    sid,
                    role_slug,
                    ctx,
                    pos,
                    i as u64,
                    rule,
                    "exact-fqdn",
                    ip,
                    out,
                );
            }
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
                out,
                |id, z| CodegenDiagnostic::ZoneEmpty {
                    rule_id: id,
                    zone: z,
                },
            );
        }
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
    let mut fanout_idx: u64 = 0;
    for sub in subdomains {
        let ips = cache.ips_for_hostname(&sub);
        if ips.is_empty() {
            // The hostname is in the cache (e.g. observed-only) but
            // has no IPs we can pin a filter to. Skip silently —
            // this is normal during DNS refresh windows and would
            // be noisy to surface per-subdomain.
            continue;
        }
        for ip in ips.into_iter().take(PER_HOSTNAME_IP_CAP) {
            // Weight slots exist to keep ADJACENT rules' bands from
            // overlapping; within one rule every fan-out target carries the
            // same Permit/Block action, so their relative order is
            // irrelevant. Targets beyond the band therefore share the band's
            // top slot instead of being dropped — filter identity stays
            // unique via the (subdomain, ip) target in the id derivation.
            let slot = fanout_idx.min(SLOTS_PER_RULE - 1);
            emit_subdomain_ip_filter(
                sid, role_slug, ctx, pos, slot, rule, rule_kind, &sub, ip, out,
            );
            fanout_idx += 1;
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn emit_for_app_match(
    sid: &str,
    role_slug: &str,
    ctx: EmitContext,
    pos: u64,
    rule: &CanonicalRule,
    app: &CanonicalAppMatch,
    app_observations: &dyn AppObservationLookup,
    app_resolver: &dyn nrr_platform_api::AppPathResolver,
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
                remote_port: None,
                weight: ctx.base_weight + pos * SLOTS_PER_RULE + k as u64,
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
    let ips = app_observations.ips_for_app(&pattern_str);
    if ips.is_empty() {
        out.diagnostics.push(CodegenDiagnostic::AppUnobserved {
            rule_id: rule.id.as_str().to_string(),
            app: pattern_str,
        });
    } else {
        for (i, ip) in ips.into_iter().take(PER_HOSTNAME_IP_CAP).enumerate() {
            emit_single_ip_filter(
                sid,
                role_slug,
                ctx,
                pos,
                APP_PATH_FANOUT_CAP + 1 + i as u64,
                rule,
                "application",
                ip,
                out,
            );
        }
    }
}

// ── Filter constructors ─────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn emit_single_ip_filter(
    sid: &str,
    role_slug: &str,
    ctx: EmitContext,
    pos: u64,
    fanout_idx: u64,
    rule: &CanonicalRule,
    rule_kind: &str,
    addr: Ipv4Addr,
    out: &mut CodegenOutput,
) {
    let target = addr.to_string();
    let kind = format!("{}{}", ctx.kind_prefix, rule_kind);
    let weight = ctx.base_weight + pos * SLOTS_PER_RULE + fanout_idx;
    let id = filter_id_for(sid, role_slug, rule.id.as_str(), &kind, &target);
    out.filters.push(WfpFilterSpec {
        layer: WfpLayerKey::AleAuthConnectV4,
        action: ctx.action,
        remote_ip: Some(addr),
        remote_port: None,
        weight,
        id,
        user_sid: Some(sid.to_string()),
        app_pattern: None,
        local_interface_luid: None,
        remote_subnet: None,
        remote_subnet_v6: None,
        ip_protocol: None,
    });
    if ctx.is_block() {
        push_packet_block_mirror(sid, role_slug, rule, &kind, &target, addr, weight, out);
    }
}

#[allow(clippy::too_many_arguments)]
fn emit_subdomain_ip_filter(
    sid: &str,
    role_slug: &str,
    ctx: EmitContext,
    pos: u64,
    fanout_idx: u64,
    rule: &CanonicalRule,
    rule_kind: &str,
    subdomain: &str,
    addr: Ipv4Addr,
    out: &mut CodegenOutput,
) {
    // Target encodes both the subdomain and the resolved IP so two
    // subdomains that happen to resolve to the same IP under the
    // same suffix rule still get distinct filter ids.
    let target = format!("{subdomain}|{addr}");
    let kind = format!("{}{}", ctx.kind_prefix, rule_kind);
    let weight = ctx.base_weight + pos * SLOTS_PER_RULE + fanout_idx;
    let id = filter_id_for(sid, role_slug, rule.id.as_str(), &kind, &target);
    out.filters.push(WfpFilterSpec {
        layer: WfpLayerKey::AleAuthConnectV4,
        action: ctx.action,
        remote_ip: Some(addr),
        remote_port: None,
        weight,
        id,
        user_sid: Some(sid.to_string()),
        app_pattern: None,
        local_interface_luid: None,
        remote_subnet: None,
        remote_subnet_v6: None,
        ip_protocol: None,
    });
    if ctx.is_block() {
        push_packet_block_mirror(sid, role_slug, rule, &kind, &target, addr, weight, out);
    }
}

/// Mirrors a Block rule's ALE (connect-layer) block with a packet-layer
/// (`OUTBOUND_IPPACKET_V4`) block for the same destination IP, so the drop also
/// covers ICMP/ping and other non-TCP/UDP protocols — the ALE connect layer
/// only sees TCP/UDP. `ip_protocol = None` blocks all protocols to `addr`.
///
/// ⚠ The packet layer does NOT expose `ALE_USER_ID`, so `user_sid` MUST be
/// `None` (the block is system-wide for that destination); the id is still
/// seeded with `sid`/role/rule for deterministic cleanup tracking. The filter
/// kind is suffixed `-pkt` so it never collides with the ALE block's id.
#[allow(clippy::too_many_arguments)]
fn push_packet_block_mirror(
    sid: &str,
    role_slug: &str,
    rule: &CanonicalRule,
    kind: &str,
    target: &str,
    addr: Ipv4Addr,
    weight: u64,
    out: &mut CodegenOutput,
) {
    let pkt_kind = format!("{kind}-pkt");
    let id = filter_id_for(sid, role_slug, rule.id.as_str(), &pkt_kind, target);
    out.filters.push(WfpFilterSpec {
        layer: WfpLayerKey::OutboundIpPacketV4,
        action: WfpAction::Block,
        remote_ip: Some(addr),
        remote_port: None,
        weight,
        id,
        user_sid: None,
        app_pattern: None,
        local_interface_luid: None,
        remote_subnet: None,
        remote_subnet_v6: None,
        ip_protocol: None,
    });
}

fn default_block_spec(sid: &str) -> WfpFilterSpec {
    let id = filter_id_for(sid, "default", "", "default", "block-all");
    WfpFilterSpec {
        layer: WfpLayerKey::AleAuthConnectV4,
        action: WfpAction::Block,
        remote_ip: None,
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
mod tests {
    use super::*;
    use crate::app_observation_lookup::MockAppObservationLookup;
    use crate::fqdn_cache_lookup::MockFqdnCacheLookup;
    use nrr_domain::canonical::{CanonicalAppMatch, CanonicalAppPattern, CanonicalRuleSet};
    use nrr_domain::RuleId;
    use nrr_platform_api::types::{WfpAction, WfpLayerKey};
    use nrr_platform_api::{MockAppPathResolver, NoopAppPathResolver};
    use std::path::PathBuf;

    // ── Fixture helpers ─────────────────────────────────────────────────────

    fn exact_ip_rule(id: &str, addr: Ipv4Addr) -> CanonicalRule {
        CanonicalRule {
            id: RuleId(id.into()),
            enabled: true,
            address_match: Some(CanonicalAddressMatch::ExactIp(addr)),
            app_match: None,
            comment: String::new(),
            action: nrr_domain::RuleAction::Route,
            origin: None,
        }
    }

    fn exact_fqdn_rule(id: &str, name: &str) -> CanonicalRule {
        CanonicalRule {
            id: RuleId(id.into()),
            enabled: true,
            address_match: Some(CanonicalAddressMatch::ExactFqdn(name.into())),
            app_match: None,
            comment: String::new(),
            action: nrr_domain::RuleAction::Route,
            origin: None,
        }
    }

    fn suffix_rule(id: &str, suffix: &str) -> CanonicalRule {
        CanonicalRule {
            id: RuleId(id.into()),
            enabled: true,
            address_match: Some(CanonicalAddressMatch::SuffixDomain(suffix.into())),
            app_match: None,
            comment: String::new(),
            action: nrr_domain::RuleAction::Route,
            origin: None,
        }
    }

    fn zone_rule(id: &str, zone: &str) -> CanonicalRule {
        CanonicalRule {
            id: RuleId(id.into()),
            enabled: true,
            address_match: Some(CanonicalAddressMatch::Zone(zone.into())),
            app_match: None,
            comment: String::new(),
            action: nrr_domain::RuleAction::Route,
            origin: None,
        }
    }

    fn app_rule(id: &str, process: &str, include_children: bool) -> CanonicalRule {
        CanonicalRule {
            id: RuleId(id.into()),
            enabled: true,
            address_match: None,
            app_match: Some(CanonicalAppMatch {
                pattern: CanonicalAppPattern::Exact(process.into()),
                include_child_processes: include_children,
            }),
            comment: String::new(),
            action: nrr_domain::RuleAction::Route,
            origin: None,
        }
    }

    fn glob_app_rule(id: &str, glob: &str) -> CanonicalRule {
        CanonicalRule {
            id: RuleId(id.into()),
            enabled: true,
            address_match: None,
            app_match: Some(CanonicalAppMatch {
                pattern: CanonicalAppPattern::Glob(glob.into()),
                include_child_processes: false,
            }),
            comment: String::new(),
            action: nrr_domain::RuleAction::Route,
            origin: None,
        }
    }

    fn disabled_rule(id: &str, addr: Ipv4Addr) -> CanonicalRule {
        let mut r = exact_ip_rule(id, addr);
        r.enabled = false;
        r
    }

    fn book(primary: Vec<CanonicalRule>, secondary: Vec<CanonicalRule>) -> CanonicalRuleBook {
        CanonicalRuleBook {
            primary: CanonicalRuleSet::from_rules(primary),
            secondary: CanonicalRuleSet::from_rules(secondary),
        }
    }

    // ── ExactIp ─────────────────────────────────────────────────────────────

    #[test]
    fn exact_ip_rule_emits_single_filter_with_remote_ip() {
        let cache = MockFqdnCacheLookup::new();
        let rule_book = book(
            vec![exact_ip_rule("r-1", Ipv4Addr::new(203, 0, 113, 5))],
            vec![],
        );
        let out = generate_filters(CodegenInput {
            sid: "S-1-5-21-A",
            rule_book: &rule_book,
            behavior_mode: RouteBehaviorMode::PreferPrimary,
            fqdn_cache: &cache,
            app_observations: &MockAppObservationLookup::new(),
            app_resolver: &NoopAppPathResolver,
            secondary_ip_denylist: &std::collections::HashSet::new(),
        });
        assert_eq!(out.filters.len(), 1);
        let f = &out.filters[0];
        assert_eq!(f.action, WfpAction::Permit);
        assert_eq!(f.layer, WfpLayerKey::AleAuthConnectV4);
        assert_eq!(f.remote_ip, Some(Ipv4Addr::new(203, 0, 113, 5)));
        assert_eq!(f.user_sid.as_deref(), Some("S-1-5-21-A"));
        assert!(f.app_pattern.is_none());
        assert!(out.diagnostics.is_empty());
    }

    // ── ExactFqdn ───────────────────────────────────────────────────────────

    #[test]
    fn exact_fqdn_rule_fans_out_over_cached_ips() {
        let cache = MockFqdnCacheLookup::new();
        cache.set_ips(
            "api.example.com",
            vec![
                Ipv4Addr::new(203, 0, 113, 1),
                Ipv4Addr::new(203, 0, 113, 2),
                Ipv4Addr::new(203, 0, 113, 3),
            ],
        );
        let rule_book = book(vec![exact_fqdn_rule("r-1", "api.example.com")], vec![]);
        let out = generate_filters(CodegenInput {
            sid: "S",
            rule_book: &rule_book,
            behavior_mode: RouteBehaviorMode::PreferPrimary,
            fqdn_cache: &cache,
            app_observations: &MockAppObservationLookup::new(),
            app_resolver: &NoopAppPathResolver,
            secondary_ip_denylist: &std::collections::HashSet::new(),
        });
        assert_eq!(out.filters.len(), 3, "one filter per cached IP");
        let ips: Vec<_> = out.filters.iter().filter_map(|f| f.remote_ip).collect();
        assert_eq!(
            ips,
            vec![
                Ipv4Addr::new(203, 0, 113, 1),
                Ipv4Addr::new(203, 0, 113, 2),
                Ipv4Addr::new(203, 0, 113, 3),
            ]
        );
        assert!(out.diagnostics.is_empty());
    }

    // ── Behavioral-equivalence characterisation ──────────────────────────
    // Ties the neutral behavioral-equivalence oracle
    // (`nrr_platform_api::wfp_behavioral`) to the REAL codegen output: the
    // current `generate_filters` is deterministic (re-apply = no churn, the
    // idempotency the no-hash-gate design relies on) and the oracle accepts it as
    // self-equivalent while still telling two different scenarios apart. It
    // is checked against this oracle instead of literal weight/id assertions.
    #[test]
    fn codegen_output_is_deterministic_and_behaviorally_self_equivalent() {
        use nrr_platform_api::wfp_behavioral::{
            arbitration_order_preserved, behaviorally_equivalent,
        };

        let cache = MockFqdnCacheLookup::new();
        cache.set_ips(
            "api.example.com",
            vec![Ipv4Addr::new(203, 0, 113, 1), Ipv4Addr::new(203, 0, 113, 2)],
        );
        // A mixed scenario: a primary ExactIp permit + a secondary ExactFqdn
        // fan-out — a multi-filter, multi-role output.
        let rule_book = book(
            vec![exact_ip_rule("p-1", Ipv4Addr::new(198, 51, 100, 7))],
            vec![exact_fqdn_rule("s-1", "api.example.com")],
        );
        // Hoisted so the closure below can borrow them (a returned `CodegenInput`
        // cannot reference temporaries created inside the closure).
        let app_obs = MockAppObservationLookup::new();
        let denylist = std::collections::HashSet::new();
        let input = || CodegenInput {
            sid: "S-1-5-21-A",
            rule_book: &rule_book,
            behavior_mode: RouteBehaviorMode::PreferPrimary,
            fqdn_cache: &cache,
            app_observations: &app_obs,
            app_resolver: &NoopAppPathResolver,
            secondary_ip_denylist: &denylist,
        };

        let first = generate_filters(input());
        let second = generate_filters(input());

        // Determinism = re-apply-no-churn: identical filters INCLUDING weight/id
        // (same build → same FNV-1a ids), so a re-apply is a WFP no-op.
        assert_eq!(
            first, second,
            "codegen must be deterministic (re-apply = no churn)"
        );
        // The oracle accepts the real output as self-equivalent (and preserves
        // its own arbitration order).
        assert!(behaviorally_equivalent(&first.filters, &second.filters));
        assert!(arbitration_order_preserved(&first.filters, &second.filters));

        // Teeth on real output: a DIFFERENT scenario is NOT equivalent.
        let other_book = book(
            vec![exact_ip_rule("p-1", Ipv4Addr::new(10, 0, 0, 9))],
            vec![],
        );
        let other = generate_filters(CodegenInput {
            sid: "S-1-5-21-A",
            rule_book: &other_book,
            behavior_mode: RouteBehaviorMode::PreferPrimary,
            fqdn_cache: &cache,
            app_observations: &MockAppObservationLookup::new(),
            app_resolver: &NoopAppPathResolver,
            secondary_ip_denylist: &std::collections::HashSet::new(),
        });
        assert!(
            !behaviorally_equivalent(&first.filters, &other.filters),
            "the oracle must distinguish different enforcement"
        );
    }

    #[test]
    fn exact_fqdn_rule_with_cold_cache_emits_diagnostic_no_filter() {
        let cache = MockFqdnCacheLookup::new();
        let rule_book = book(vec![exact_fqdn_rule("r-cold", "uncached.example")], vec![]);
        let out = generate_filters(CodegenInput {
            sid: "S",
            rule_book: &rule_book,
            behavior_mode: RouteBehaviorMode::PreferPrimary,
            fqdn_cache: &cache,
            app_observations: &MockAppObservationLookup::new(),
            app_resolver: &NoopAppPathResolver,
            secondary_ip_denylist: &std::collections::HashSet::new(),
        });
        assert!(out.filters.is_empty());
        assert_eq!(
            out.diagnostics,
            vec![CodegenDiagnostic::HostnameUnresolved {
                rule_id: "r-cold".into(),
                hostname: "uncached.example".into()
            }]
        );
    }

    // ── SuffixDomain ────────────────────────────────────────────────────────

    #[test]
    fn suffix_domain_fans_out_over_cached_subdomains_and_their_ips() {
        let cache = MockFqdnCacheLookup::new();
        cache.set_ips("api.example.com", vec![Ipv4Addr::new(1, 1, 1, 1)]);
        cache.set_ips(
            "www.example.com",
            vec![Ipv4Addr::new(2, 2, 2, 2), Ipv4Addr::new(2, 2, 2, 3)],
        );
        let rule_book = book(vec![suffix_rule("r-suf", "example.com")], vec![]);
        let out = generate_filters(CodegenInput {
            sid: "S",
            rule_book: &rule_book,
            behavior_mode: RouteBehaviorMode::PreferPrimary,
            fqdn_cache: &cache,
            app_observations: &MockAppObservationLookup::new(),
            app_resolver: &NoopAppPathResolver,
            secondary_ip_denylist: &std::collections::HashSet::new(),
        });
        // 1 (api) + 2 (www) = 3 filters
        assert_eq!(out.filters.len(), 3);
        let ips: Vec<_> = out.filters.iter().filter_map(|f| f.remote_ip).collect();
        assert!(ips.contains(&Ipv4Addr::new(1, 1, 1, 1)));
        assert!(ips.contains(&Ipv4Addr::new(2, 2, 2, 2)));
        assert!(ips.contains(&Ipv4Addr::new(2, 2, 2, 3)));
    }

    #[test]
    fn suffix_domain_fan_out_includes_the_apex() {
        //  — `*.example.com` covers "example.com" itself, so the apex
        // must get a filter. Enforcement has to agree with the decision engine
        // here: a matched host with no filter is exactly the silent leak apex
        // coverage exists to close.
        let cache = MockFqdnCacheLookup::new();
        cache.set_ips("example.com", vec![Ipv4Addr::new(9, 9, 9, 9)]);
        cache.set_ips("www.example.com", vec![Ipv4Addr::new(2, 2, 2, 2)]);
        let rule_book = book(vec![suffix_rule("r-suf", "example.com")], vec![]);
        let out = generate_filters(CodegenInput {
            sid: "S",
            rule_book: &rule_book,
            behavior_mode: RouteBehaviorMode::PreferPrimary,
            fqdn_cache: &cache,
            app_observations: &MockAppObservationLookup::new(),
            app_resolver: &NoopAppPathResolver,
            secondary_ip_denylist: &std::collections::HashSet::new(),
        });
        let ips: Vec<_> = out.filters.iter().filter_map(|f| f.remote_ip).collect();
        assert!(ips.contains(&Ipv4Addr::new(9, 9, 9, 9)), "apex IP: {ips:?}");
        assert!(ips.contains(&Ipv4Addr::new(2, 2, 2, 2)));
    }

    #[test]
    fn zone_fan_out_still_excludes_the_bare_zone_label() {
        // Zone semantics are untouched: a host literally named "test" is not a
        // member of the zone "test".
        let cache = MockFqdnCacheLookup::new();
        cache.set_ips("test", vec![Ipv4Addr::new(9, 9, 9, 9)]);
        cache.set_ips("a.test", vec![Ipv4Addr::new(2, 2, 2, 2)]);
        let rule_book = book(vec![zone_rule("r-zone", "test")], vec![]);
        let out = generate_filters(CodegenInput {
            sid: "S",
            rule_book: &rule_book,
            behavior_mode: RouteBehaviorMode::PreferPrimary,
            fqdn_cache: &cache,
            app_observations: &MockAppObservationLookup::new(),
            app_resolver: &NoopAppPathResolver,
            secondary_ip_denylist: &std::collections::HashSet::new(),
        });
        let ips: Vec<_> = out.filters.iter().filter_map(|f| f.remote_ip).collect();
        assert_eq!(ips, vec![Ipv4Addr::new(2, 2, 2, 2)]);
    }

    #[test]
    fn suffix_domain_with_only_a_cached_apex_still_emits_a_filter() {
        let cache = MockFqdnCacheLookup::new();
        cache.set_ips("example.com", vec![Ipv4Addr::new(9, 9, 9, 9)]);
        let rule_book = book(vec![suffix_rule("r-suf", "example.com")], vec![]);
        let out = generate_filters(CodegenInput {
            sid: "S",
            rule_book: &rule_book,
            behavior_mode: RouteBehaviorMode::PreferPrimary,
            fqdn_cache: &cache,
            app_observations: &MockAppObservationLookup::new(),
            app_resolver: &NoopAppPathResolver,
            secondary_ip_denylist: &std::collections::HashSet::new(),
        });
        assert_eq!(out.filters.len(), 1);
        assert!(out.diagnostics.is_empty());
    }

    #[test]
    fn suffix_domain_with_no_cached_subdomains_emits_diagnostic() {
        let cache = MockFqdnCacheLookup::new();
        let rule_book = book(vec![suffix_rule("r-suf", "example.com")], vec![]);
        let out = generate_filters(CodegenInput {
            sid: "S",
            rule_book: &rule_book,
            behavior_mode: RouteBehaviorMode::PreferPrimary,
            fqdn_cache: &cache,
            app_observations: &MockAppObservationLookup::new(),
            app_resolver: &NoopAppPathResolver,
            secondary_ip_denylist: &std::collections::HashSet::new(),
        });
        assert!(out.filters.is_empty());
        assert_eq!(
            out.diagnostics,
            vec![CodegenDiagnostic::SuffixEmpty {
                rule_id: "r-suf".into(),
                suffix: "example.com".into()
            }]
        );
    }

    #[test]
    fn suffix_domain_beyond_slots_per_rule_keeps_every_host_with_clamped_weights() {
        // 300 cached hosts — past the old 256-slot cap. Every host must get a
        // filter (nothing dropped), no truncation diagnostic, and every weight
        // must stay inside this rule's band so the next rule cannot collide.
        let cache = MockFqdnCacheLookup::new();
        let hosts = 300usize;
        for i in 0..hosts {
            cache.set_ips(
                &format!("h{i}.example.com"),
                vec![Ipv4Addr::new(10, 0, (i / 256) as u8, (i % 256) as u8)],
            );
        }
        let rule_book = book(vec![suffix_rule("r-suf", "example.com")], vec![]);
        let out = generate_filters(CodegenInput {
            sid: "S",
            rule_book: &rule_book,
            behavior_mode: RouteBehaviorMode::PreferPrimary,
            fqdn_cache: &cache,
            app_observations: &MockAppObservationLookup::new(),
            app_resolver: &NoopAppPathResolver,
            secondary_ip_denylist: &std::collections::HashSet::new(),
        });
        assert_eq!(out.filters.len(), hosts, "no host may lose its filter");
        assert!(
            !out.diagnostics
                .iter()
                .any(|d| matches!(d, CodegenDiagnostic::SuffixTruncated { .. })),
            "300 hosts are far below the backstop — no truncation, got {:?}",
            out.diagnostics
        );
        let band_top = BASE_PRIMARY + SLOTS_PER_RULE - 1;
        assert!(
            out.filters.iter().all(|f| f.weight <= band_top),
            "every weight must stay inside the first rule's band"
        );
        let at_top = out.filters.iter().filter(|f| f.weight == band_top).count();
        assert_eq!(
            at_top,
            hosts - (SLOTS_PER_RULE as usize - 1),
            "targets beyond the band share the band's top slot"
        );
    }

    #[test]
    fn suffix_domain_at_backstop_emits_truncated_diagnostic() {
        let cache = MockFqdnCacheLookup::new();
        for i in 0..SUFFIX_FANOUT_BACKSTOP {
            cache.set_ips(
                &format!("h{i}.example.com"),
                vec![Ipv4Addr::new(
                    10,
                    (i / 65536) as u8,
                    (i / 256) as u8,
                    (i % 256) as u8,
                )],
            );
        }
        let rule_book = book(vec![suffix_rule("r-suf", "example.com")], vec![]);
        let out = generate_filters(CodegenInput {
            sid: "S",
            rule_book: &rule_book,
            behavior_mode: RouteBehaviorMode::PreferPrimary,
            fqdn_cache: &cache,
            app_observations: &MockAppObservationLookup::new(),
            app_resolver: &NoopAppPathResolver,
            secondary_ip_denylist: &std::collections::HashSet::new(),
        });
        assert!(
            out.diagnostics
                .contains(&CodegenDiagnostic::SuffixTruncated {
                    rule_id: "r-suf".into(),
                    suffix: "example.com".into(),
                    cap: SUFFIX_FANOUT_BACKSTOP,
                }),
            "expected SuffixTruncated diagnostic when cached hosts >= backstop, got {:?}",
            out.diagnostics
        );
    }

    // ── Zone ────────────────────────────────────────────────────────────────

    #[test]
    fn zone_fans_out_over_cached_hosts_under_tld() {
        let cache = MockFqdnCacheLookup::new();
        cache.set_ips("vk.ru", vec![Ipv4Addr::new(87, 240, 190, 78)]);
        cache.set_ips("ya.ru", vec![Ipv4Addr::new(77, 88, 8, 8)]);
        let rule_book = book(vec![zone_rule("r-zone", "ru")], vec![]);
        let out = generate_filters(CodegenInput {
            sid: "S",
            rule_book: &rule_book,
            behavior_mode: RouteBehaviorMode::PreferPrimary,
            fqdn_cache: &cache,
            app_observations: &MockAppObservationLookup::new(),
            app_resolver: &NoopAppPathResolver,
            secondary_ip_denylist: &std::collections::HashSet::new(),
        });
        assert_eq!(out.filters.len(), 2);
    }

    #[test]
    fn zone_with_no_cached_hosts_emits_zone_empty_diagnostic() {
        let cache = MockFqdnCacheLookup::new();
        let rule_book = book(vec![zone_rule("r-zone", "ru")], vec![]);
        let out = generate_filters(CodegenInput {
            sid: "S",
            rule_book: &rule_book,
            behavior_mode: RouteBehaviorMode::PreferPrimary,
            fqdn_cache: &cache,
            app_observations: &MockAppObservationLookup::new(),
            app_resolver: &NoopAppPathResolver,
            secondary_ip_denylist: &std::collections::HashSet::new(),
        });
        assert!(out.filters.is_empty());
        assert_eq!(
            out.diagnostics,
            vec![CodegenDiagnostic::ZoneEmpty {
                rule_id: "r-zone".into(),
                zone: "ru".into()
            }]
        );
    }

    // ── Application ─────────────────────────────────────────────────────────

    #[test]
    fn application_rule_emits_filter_with_app_pattern_and_no_remote_ip() {
        let cache = MockFqdnCacheLookup::new();
        let resolver = MockAppPathResolver::new()
            .with("chrome.exe", vec![PathBuf::from(r"C:\Apps\chrome.exe")]);
        let rule_book = book(vec![app_rule("r-app", "chrome.exe", false)], vec![]);
        let out = generate_filters(CodegenInput {
            sid: "S",
            rule_book: &rule_book,
            behavior_mode: RouteBehaviorMode::PreferPrimary,
            fqdn_cache: &cache,
            app_observations: &MockAppObservationLookup::new(),
            app_resolver: &resolver,
            secondary_ip_denylist: &std::collections::HashSet::new(),
        });
        // The name resolves to one concrete path → one app-id filter carrying the
        // RESOLVED PATH (not the raw name) so `FwpmGetAppIdFromFileName0` can key
        // on it at apply time.
        assert_eq!(out.filters.len(), 1);
        let f = &out.filters[0];
        assert!(f.remote_ip.is_none());
        assert_eq!(f.app_pattern.as_deref(), Some(r"C:\Apps\chrome.exe"));
        assert_eq!(f.action, WfpAction::Permit);
    }

    // ── Built-in VPN glob resolution ──────────────────────────────────────

    #[test]
    fn builtin_vpn_globs_resolve_to_concrete_paths_never_leaving_a_glob() {
        // A resolver that maps one built-in glob (`openvpn*`) to a real path and
        // knows nothing about the other built-ins.
        let cache = MockFqdnCacheLookup::new();
        let resolver = MockAppPathResolver::new()
            .with("openvpn.exe", vec![PathBuf::from(r"C:\Tools\openvpn.exe")]);
        // No app rules — we are exercising ONLY the built-in exempt resolution.
        let rule_book = book(vec![], vec![]);
        let out = generate_filters(CodegenInput {
            sid: "S",
            rule_book: &rule_book,
            behavior_mode: RouteBehaviorMode::PreferPrimary,
            fqdn_cache: &cache,
            app_observations: &MockAppObservationLookup::new(),
            app_resolver: &resolver,
            secondary_ip_denylist: &std::collections::HashSet::new(),
        });
        // `openvpn*` matched the seeded `openvpn.exe` → its concrete path surfaces.
        assert_eq!(
            out.vpn_default_exempt_paths,
            vec![r"C:\Tools\openvpn.exe".to_string()],
            "a resolvable built-in glob yields its on-disk path",
        );
        // No glob character ever survives into the exempt path set — that is the
        // whole point (a glob stamped into ALE_APP_ID is silently dropped at apply).
        assert!(
            out.vpn_default_exempt_paths
                .iter()
                .all(|p| !p.contains('*') && !p.contains('?')),
            "no glob may leave the resolver",
        );
    }

    #[test]
    fn builtin_vpn_globs_unresolved_yield_empty_exempt_set() {
        // NoopAppPathResolver resolves every built-in glob to nothing.
        let cache = MockFqdnCacheLookup::new();
        let rule_book = book(vec![], vec![]);
        let out = generate_filters(CodegenInput {
            sid: "S",
            rule_book: &rule_book,
            behavior_mode: RouteBehaviorMode::PreferPrimary,
            fqdn_cache: &cache,
            app_observations: &MockAppObservationLookup::new(),
            app_resolver: &NoopAppPathResolver,
            secondary_ip_denylist: &std::collections::HashSet::new(),
        });
        assert!(
            out.vpn_default_exempt_paths.is_empty(),
            "unresolvable built-in globs contribute nothing (they never enforced anyway)",
        );
    }

    #[test]
    fn builtin_vpn_exempt_paths_are_deduped_and_sorted() {
        // `openvpn.exe` is matched by BOTH `*vpn*` and `openvpn*`, so its path is
        // resolved twice across the built-in globs — the union must dedup it. A
        // second client resolves to an alphabetically-earlier path to prove sorting.
        let cache = MockFqdnCacheLookup::new();
        let resolver = MockAppPathResolver::from_seed([
            (
                "openvpn.exe".to_string(),
                vec![PathBuf::from(r"C:\Z\vpn.exe")],
            ),
            (
                "wireguard.exe".to_string(),
                vec![PathBuf::from(r"C:\A\wg.exe")],
            ),
        ]);
        let rule_book = book(vec![], vec![]);
        let out = generate_filters(CodegenInput {
            sid: "S",
            rule_book: &rule_book,
            behavior_mode: RouteBehaviorMode::PreferPrimary,
            fqdn_cache: &cache,
            app_observations: &MockAppObservationLookup::new(),
            app_resolver: &resolver,
            secondary_ip_denylist: &std::collections::HashSet::new(),
        });
        // Deduped (openvpn.exe seen via two globs) and sorted ascending.
        assert_eq!(
            out.vpn_default_exempt_paths,
            vec![r"C:\A\wg.exe".to_string(), r"C:\Z\vpn.exe".to_string()],
        );
    }

    #[test]
    fn app_rule_with_unresolved_exe_emits_diagnostic_and_no_app_id_filter() {
        let cache = MockFqdnCacheLookup::new();
        // The resolver knows nothing → the name resolves to zero paths.
        let resolver = MockAppPathResolver::new();
        // …but the app HAS observed destinations, so the /32 mirrors still emit.
        let app_obs = MockAppObservationLookup::new();
        app_obs.set_ips("chrome.exe", vec![Ipv4Addr::new(203, 0, 113, 7)]);
        let rule_book = book(vec![], vec![app_rule("r-app", "chrome.exe", false)]);
        let out = generate_filters(CodegenInput {
            sid: "S",
            rule_book: &rule_book,
            behavior_mode: RouteBehaviorMode::PreferPrimary,
            fqdn_cache: &cache,
            app_observations: &app_obs,
            app_resolver: &resolver,
            secondary_ip_denylist: &std::collections::HashSet::new(),
        });
        // No ALE_APP_ID (app_pattern) filter — the WFP condition needs a real
        // path, which an unresolved name cannot supply.
        assert!(
            out.filters.iter().all(|f| f.app_pattern.is_none()),
            "an unresolved app emits no ALE_APP_ID filter"
        );
        // The observed /32 mirror is still emitted (independent of resolution).
        assert_eq!(
            out.filters.iter().filter(|f| f.remote_ip.is_some()).count(),
            1
        );
        // And the diagnostic explains why the app-id filter is missing.
        assert!(out.diagnostics.contains(&CodegenDiagnostic::AppUnresolved {
            rule_id: "r-app".into(),
            app: "chrome.exe".into(),
        }));
    }

    #[test]
    fn glob_app_rule_fans_out_one_app_id_filter_per_resolved_path() {
        let cache = MockFqdnCacheLookup::new();
        // A glob unions two distinct installs.
        let resolver = MockAppPathResolver::from_seed([
            (
                "disko.exe".to_string(),
                vec![PathBuf::from(r"C:\Y\disko.exe")],
            ),
            (
                "diskosync.exe".to_string(),
                vec![PathBuf::from(r"C:\Y\diskosync.exe")],
            ),
        ]);
        let rule_book = book(vec![], vec![glob_app_rule("r-g", "disko*.exe")]);
        let out = generate_filters(CodegenInput {
            sid: "S",
            rule_book: &rule_book,
            behavior_mode: RouteBehaviorMode::PreferPrimary,
            fqdn_cache: &cache,
            app_observations: &MockAppObservationLookup::new(),
            app_resolver: &resolver,
            secondary_ip_denylist: &std::collections::HashSet::new(),
        });
        // One ALE_APP_ID filter per resolved path.
        let app_id_filters: Vec<_> = out
            .filters
            .iter()
            .filter(|f| f.app_pattern.is_some())
            .collect();
        assert_eq!(app_id_filters.len(), 2);
        let patterns: Vec<String> = app_id_filters
            .iter()
            .filter_map(|f| f.app_pattern.clone())
            .collect();
        assert!(patterns.contains(&r"C:\Y\disko.exe".to_string()));
        assert!(patterns.contains(&r"C:\Y\diskosync.exe".to_string()));
        // Distinct weights (no collision) and distinct ids per path.
        assert_ne!(app_id_filters[0].weight, app_id_filters[1].weight);
        assert_ne!(app_id_filters[0].id.raw, app_id_filters[1].id.raw);
    }

    #[test]
    fn resolved_app_id_weight_sits_below_shifted_observation_mirrors() {
        let cache = MockFqdnCacheLookup::new();
        let resolver = MockAppPathResolver::new()
            .with("chrome.exe", vec![PathBuf::from(r"C:\Apps\chrome.exe")]);
        let app_obs = MockAppObservationLookup::new();
        app_obs.set_ips("chrome.exe", vec![Ipv4Addr::new(203, 0, 113, 7)]);
        let rule_book = book(vec![app_rule("r-app", "chrome.exe", false)], vec![]);
        let out = generate_filters(CodegenInput {
            sid: "S",
            rule_book: &rule_book,
            behavior_mode: RouteBehaviorMode::PreferPrimary,
            fqdn_cache: &cache,
            app_observations: &app_obs,
            app_resolver: &resolver,
            secondary_ip_denylist: &std::collections::HashSet::new(),
        });
        let app_id = out
            .filters
            .iter()
            .find(|f| f.app_pattern.is_some())
            .expect("app-id filter");
        let mirror = out
            .filters
            .iter()
            .find(|f| f.remote_ip.is_some())
            .expect("observation /32 mirror");
        // The app-id band (slots 0..APP_PATH_FANOUT_CAP) sits strictly below the
        // observation-mirror band (slots APP_PATH_FANOUT_CAP + 1 + i) — no
        // weight collision between the two fan-outs of the same rule.
        assert!(app_id.weight < mirror.weight);
        assert_eq!(mirror.weight - app_id.weight, APP_PATH_FANOUT_CAP + 1);
    }

    // ── Default behaviour modes ─────────────────────────────────────────────

    #[test]
    fn strict_secondary_fail_closed_emits_block_catch_all() {
        let cache = MockFqdnCacheLookup::new();
        let rule_book = book(vec![], vec![]);
        let out = generate_filters(CodegenInput {
            sid: "S",
            rule_book: &rule_book,
            behavior_mode: RouteBehaviorMode::StrictSecondaryFailClosed,
            fqdn_cache: &cache,
            app_observations: &MockAppObservationLookup::new(),
            app_resolver: &NoopAppPathResolver,
            secondary_ip_denylist: &std::collections::HashSet::new(),
        });
        assert_eq!(out.filters.len(), 1);
        let f = &out.filters[0];
        assert_eq!(f.action, WfpAction::Block);
        assert!(f.remote_ip.is_none());
        assert_eq!(f.weight, DEFAULT_BLOCK_WEIGHT);
        assert_eq!(
            out.diagnostics,
            vec![CodegenDiagnostic::FailClosedDefaultEmitted]
        );
    }

    #[test]
    fn prefer_primary_does_not_emit_default_block() {
        let cache = MockFqdnCacheLookup::new();
        let rule_book = book(vec![], vec![]);
        let out = generate_filters(CodegenInput {
            sid: "S",
            rule_book: &rule_book,
            behavior_mode: RouteBehaviorMode::PreferPrimary,
            fqdn_cache: &cache,
            app_observations: &MockAppObservationLookup::new(),
            app_resolver: &NoopAppPathResolver,
            secondary_ip_denylist: &std::collections::HashSet::new(),
        });
        assert!(out.filters.is_empty());
    }

    #[test]
    fn prefer_secondary_when_available_does_not_emit_default_block() {
        let cache = MockFqdnCacheLookup::new();
        let rule_book = book(vec![], vec![]);
        let out = generate_filters(CodegenInput {
            sid: "S",
            rule_book: &rule_book,
            behavior_mode: RouteBehaviorMode::PreferSecondaryWhenAvailable,
            fqdn_cache: &cache,
            app_observations: &MockAppObservationLookup::new(),
            app_resolver: &NoopAppPathResolver,
            secondary_ip_denylist: &std::collections::HashSet::new(),
        });
        assert!(out.filters.is_empty());
    }

    // ── Disabled rules ──────────────────────────────────────────────────────

    #[test]
    fn disabled_rule_is_skipped_with_diagnostic() {
        let cache = MockFqdnCacheLookup::new();
        let rule_book = book(
            vec![disabled_rule("r-off", Ipv4Addr::new(1, 1, 1, 1))],
            vec![],
        );
        let out = generate_filters(CodegenInput {
            sid: "S",
            rule_book: &rule_book,
            behavior_mode: RouteBehaviorMode::PreferPrimary,
            fqdn_cache: &cache,
            app_observations: &MockAppObservationLookup::new(),
            app_resolver: &NoopAppPathResolver,
            secondary_ip_denylist: &std::collections::HashSet::new(),
        });
        assert!(out.filters.is_empty());
        assert_eq!(
            out.diagnostics,
            vec![CodegenDiagnostic::SkippedDisabled {
                rule_id: "r-off".into()
            }]
        );
    }

    // ── Determinism / weights ───────────────────────────────────────────────

    #[test]
    fn repeated_generation_produces_identical_filter_ids() {
        let cache = MockFqdnCacheLookup::new();
        cache.set_ips("a.test", vec![Ipv4Addr::new(1, 1, 1, 1)]);
        let rule_book = book(
            vec![
                exact_fqdn_rule("r-1", "a.test"),
                exact_ip_rule("r-2", Ipv4Addr::new(2, 2, 2, 2)),
            ],
            vec![app_rule("r-3", "chrome.exe", false)],
        );
        let ids =
            |out: &CodegenOutput| -> Vec<u64> { out.filters.iter().map(|f| f.id.raw).collect() };
        let a = generate_filters(CodegenInput {
            sid: "S",
            rule_book: &rule_book,
            behavior_mode: RouteBehaviorMode::PreferPrimary,
            fqdn_cache: &cache,
            app_observations: &MockAppObservationLookup::new(),
            app_resolver: &NoopAppPathResolver,
            secondary_ip_denylist: &std::collections::HashSet::new(),
        });
        let b = generate_filters(CodegenInput {
            sid: "S",
            rule_book: &rule_book,
            behavior_mode: RouteBehaviorMode::PreferPrimary,
            fqdn_cache: &cache,
            app_observations: &MockAppObservationLookup::new(),
            app_resolver: &NoopAppPathResolver,
            secondary_ip_denylist: &std::collections::HashSet::new(),
        });
        assert_eq!(ids(&a), ids(&b));
    }

    #[test]
    fn primary_filters_outrank_secondary_filters_by_weight() {
        let cache = MockFqdnCacheLookup::new();
        let rule_book = book(
            vec![exact_ip_rule("r-p", Ipv4Addr::new(1, 1, 1, 1))],
            vec![exact_ip_rule("r-s", Ipv4Addr::new(2, 2, 2, 2))],
        );
        let out = generate_filters(CodegenInput {
            sid: "S",
            rule_book: &rule_book,
            behavior_mode: RouteBehaviorMode::PreferPrimary,
            fqdn_cache: &cache,
            app_observations: &MockAppObservationLookup::new(),
            app_resolver: &NoopAppPathResolver,
            secondary_ip_denylist: &std::collections::HashSet::new(),
        });
        let primary_weight = out
            .filters
            .iter()
            .find(|f| f.remote_ip == Some(Ipv4Addr::new(1, 1, 1, 1)))
            .unwrap()
            .weight;
        let secondary_weight = out
            .filters
            .iter()
            .find(|f| f.remote_ip == Some(Ipv4Addr::new(2, 2, 2, 2)))
            .unwrap()
            .weight;
        assert!(
            primary_weight > secondary_weight,
            "primary {primary_weight:#x} must outrank secondary {secondary_weight:#x}"
        );
    }

    #[test]
    fn per_sid_user_sid_stamped_on_every_filter() {
        let cache = MockFqdnCacheLookup::new();
        let rule_book = book(
            vec![exact_ip_rule("r-1", Ipv4Addr::new(1, 1, 1, 1))],
            vec![exact_ip_rule("r-2", Ipv4Addr::new(2, 2, 2, 2))],
        );
        let out = generate_filters(CodegenInput {
            sid: "S-1-5-21-XYZ",
            rule_book: &rule_book,
            behavior_mode: RouteBehaviorMode::StrictSecondaryFailClosed,
            fqdn_cache: &cache,
            app_observations: &MockAppObservationLookup::new(),
            app_resolver: &NoopAppPathResolver,
            secondary_ip_denylist: &std::collections::HashSet::new(),
        });
        for f in &out.filters {
            assert_eq!(f.user_sid.as_deref(), Some("S-1-5-21-XYZ"));
        }
    }

    #[test]
    fn different_sids_produce_different_filter_ids() {
        let cache = MockFqdnCacheLookup::new();
        let rule_book = book(
            vec![exact_ip_rule("r-1", Ipv4Addr::new(1, 1, 1, 1))],
            vec![],
        );
        let a = generate_filters(CodegenInput {
            sid: "S-1-5-21-A",
            rule_book: &rule_book,
            behavior_mode: RouteBehaviorMode::PreferPrimary,
            fqdn_cache: &cache,
            app_observations: &MockAppObservationLookup::new(),
            app_resolver: &NoopAppPathResolver,
            secondary_ip_denylist: &std::collections::HashSet::new(),
        });
        let b = generate_filters(CodegenInput {
            sid: "S-1-5-21-B",
            rule_book: &rule_book,
            behavior_mode: RouteBehaviorMode::PreferPrimary,
            fqdn_cache: &cache,
            app_observations: &MockAppObservationLookup::new(),
            app_resolver: &NoopAppPathResolver,
            secondary_ip_denylist: &std::collections::HashSet::new(),
        });
        assert_ne!(a.filters[0].id.raw, b.filters[0].id.raw);
    }

    #[test]
    fn primary_and_secondary_rule_with_same_id_produce_different_filter_ids() {
        let cache = MockFqdnCacheLookup::new();
        // Same id "r-1" in both lists is legal — they're separate
        // namespaces per role. Filter ids must still differ.
        let rule_book = book(
            vec![exact_ip_rule("r-1", Ipv4Addr::new(1, 1, 1, 1))],
            vec![exact_ip_rule("r-1", Ipv4Addr::new(2, 2, 2, 2))],
        );
        let out = generate_filters(CodegenInput {
            sid: "S",
            rule_book: &rule_book,
            behavior_mode: RouteBehaviorMode::PreferPrimary,
            fqdn_cache: &cache,
            app_observations: &MockAppObservationLookup::new(),
            app_resolver: &NoopAppPathResolver,
            secondary_ip_denylist: &std::collections::HashSet::new(),
        });
        let ids: Vec<u64> = out.filters.iter().map(|f| f.id.raw).collect();
        assert_eq!(ids.len(), 2);
        assert_ne!(ids[0], ids[1]);
    }

    #[test]
    fn fanout_idx_keeps_filter_ids_unique_for_multi_ip_hostname() {
        let cache = MockFqdnCacheLookup::new();
        cache.set_ips(
            "x.test",
            vec![
                Ipv4Addr::new(1, 1, 1, 1),
                Ipv4Addr::new(1, 1, 1, 2),
                Ipv4Addr::new(1, 1, 1, 3),
            ],
        );
        let rule_book = book(vec![exact_fqdn_rule("r-1", "x.test")], vec![]);
        let out = generate_filters(CodegenInput {
            sid: "S",
            rule_book: &rule_book,
            behavior_mode: RouteBehaviorMode::PreferPrimary,
            fqdn_cache: &cache,
            app_observations: &MockAppObservationLookup::new(),
            app_resolver: &NoopAppPathResolver,
            secondary_ip_denylist: &std::collections::HashSet::new(),
        });
        let ids: std::collections::HashSet<u64> = out.filters.iter().map(|f| f.id.raw).collect();
        assert_eq!(ids.len(), 3, "fan-out per IP must yield distinct ids");
    }

    #[test]
    fn no_rule_no_strict_mode_yields_empty_output() {
        let cache = MockFqdnCacheLookup::new();
        let rule_book = book(vec![], vec![]);
        let out = generate_filters(CodegenInput {
            sid: "S",
            rule_book: &rule_book,
            behavior_mode: RouteBehaviorMode::PreferPrimary,
            fqdn_cache: &cache,
            app_observations: &MockAppObservationLookup::new(),
            app_resolver: &NoopAppPathResolver,
            secondary_ip_denylist: &std::collections::HashSet::new(),
        });
        assert!(out.is_empty());
        assert!(out.diagnostics.is_empty());
    }

    // ── secondary_dest_ips (block 16.18.vpn kill-switch) ────────────────────

    #[test]
    fn secondary_dest_ips_collects_only_secondary_rule_ips() {
        let cache = MockFqdnCacheLookup::new();
        let rule_book = book(
            vec![exact_ip_rule("r-p", Ipv4Addr::new(10, 0, 0, 1))],
            vec![exact_ip_rule("r-s", Ipv4Addr::new(203, 0, 113, 9))],
        );
        let out = generate_filters(CodegenInput {
            sid: "S",
            rule_book: &rule_book,
            behavior_mode: RouteBehaviorMode::PreferPrimary,
            fqdn_cache: &cache,
            app_observations: &MockAppObservationLookup::new(),
            app_resolver: &NoopAppPathResolver,
            secondary_ip_denylist: &std::collections::HashSet::new(),
        });
        assert_eq!(
            out.secondary_dest_ips,
            vec![Ipv4Addr::new(203, 0, 113, 9)],
            "only the secondary rule's IP is protected; the primary rule's is excluded"
        );
    }

    #[test]
    fn secondary_dest_ips_dedupes_across_rules_and_fanout() {
        let cache = MockFqdnCacheLookup::new();
        cache.set_ips("a.test", vec![Ipv4Addr::new(5, 5, 5, 5)]);
        cache.set_ips("b.test", vec![Ipv4Addr::new(5, 5, 5, 5)]); // same IP
        let rule_book = book(
            vec![],
            vec![
                exact_fqdn_rule("r-1", "a.test"),
                exact_fqdn_rule("r-2", "b.test"),
                exact_ip_rule("r-3", Ipv4Addr::new(5, 5, 5, 5)), // same IP again
            ],
        );
        let out = generate_filters(CodegenInput {
            sid: "S",
            rule_book: &rule_book,
            behavior_mode: RouteBehaviorMode::PreferPrimary,
            fqdn_cache: &cache,
            app_observations: &MockAppObservationLookup::new(),
            app_resolver: &NoopAppPathResolver,
            secondary_ip_denylist: &std::collections::HashSet::new(),
        });
        assert_eq!(
            out.secondary_dest_ips,
            vec![Ipv4Addr::new(5, 5, 5, 5)],
            "the same resolved IP across three secondary rules collapses to one"
        );
    }

    #[test]
    fn secondary_dest_ips_skips_app_match_rules() {
        let cache = MockFqdnCacheLookup::new();
        let resolver = MockAppPathResolver::new()
            .with("chrome.exe", vec![PathBuf::from(r"C:\Apps\chrome.exe")]);
        let rule_book = book(vec![], vec![app_rule("r-app", "chrome.exe", false)]);
        let out = generate_filters(CodegenInput {
            sid: "S",
            rule_book: &rule_book,
            behavior_mode: RouteBehaviorMode::PreferPrimary,
            fqdn_cache: &cache,
            app_observations: &MockAppObservationLookup::new(),
            app_resolver: &resolver,
            secondary_ip_denylist: &std::collections::HashSet::new(),
        });
        // The resolved app-id filter carries an `app_pattern` but no `remote_ip`,
        // so it contributes nothing to the kill-switch's protected dest set.
        assert!(
            out.filters.iter().any(|f| f.app_pattern.is_some()),
            "the resolved app-id filter is emitted"
        );
        assert!(
            out.secondary_dest_ips.is_empty(),
            "an UNOBSERVED app rule has no IP destination to protect yet"
        );
    }

    #[test]
    fn app_rule_routes_observed_ips_as_secondary_dest() {
        let cache = MockFqdnCacheLookup::new();
        let resolver = MockAppPathResolver::new()
            .with("chrome.exe", vec![PathBuf::from(r"C:\Apps\chrome.exe")]);
        let app_obs = MockAppObservationLookup::new();
        app_obs.set_ips(
            "chrome.exe",
            vec![Ipv4Addr::new(203, 0, 113, 7), Ipv4Addr::new(203, 0, 113, 8)],
        );
        let rule_book = book(vec![], vec![app_rule("r-app", "chrome.exe", false)]);
        let out = generate_filters(CodegenInput {
            sid: "S",
            rule_book: &rule_book,
            behavior_mode: RouteBehaviorMode::PreferPrimary,
            fqdn_cache: &cache,
            app_observations: &app_obs,
            app_resolver: &resolver,
            secondary_ip_denylist: &std::collections::HashSet::new(),
        });
        // The app's observed IPs become secondary /32 destinations the
        // kill-switch protects — same as a domain rule's resolved IPs.
        assert_eq!(
            out.secondary_dest_ips,
            vec![Ipv4Addr::new(203, 0, 113, 7), Ipv4Addr::new(203, 0, 113, 8)]
        );
        // Two /32 Permits (one per observed IP), each carrying remote_ip,
        // plus the per-process Permit (no remote_ip).
        assert_eq!(
            out.filters.iter().filter(|f| f.remote_ip.is_some()).count(),
            2
        );
    }

    #[test]
    fn secondary_app_patterns_collects_secondary_route_apps() {
        let cache = MockFqdnCacheLookup::new();
        let resolver = MockAppPathResolver::new()
            .with("chrome.exe", vec![PathBuf::from(r"C:\Apps\chrome.exe")]);
        // An UNOBSERVED secondary app rule still emits the per-process app-id
        // Permit (for each resolved path), so its RESOLVED PATH is collected for
        // the per-app kill-switch regardless of whether any destination has been
        // observed yet.
        let rule_book = book(vec![], vec![app_rule("r-app", "chrome.exe", false)]);
        let out = generate_filters(CodegenInput {
            sid: "S",
            rule_book: &rule_book,
            behavior_mode: RouteBehaviorMode::PreferPrimary,
            fqdn_cache: &cache,
            app_observations: &MockAppObservationLookup::new(),
            app_resolver: &resolver,
            secondary_ip_denylist: &std::collections::HashSet::new(),
        });
        // The resolved path — not the raw name — is what the per-app kill-switch
        // pins, so `secondary_app_patterns` now carries it.
        assert_eq!(
            out.secondary_app_patterns,
            vec![r"C:\Apps\chrome.exe".to_string()]
        );
    }

    #[test]
    fn secondary_app_patterns_excludes_primary_and_block_apps() {
        let cache = MockFqdnCacheLookup::new();
        let resolver = MockAppPathResolver::from_seed([
            (
                "primary.exe".to_string(),
                vec![PathBuf::from(r"C:\Apps\primary.exe")],
            ),
            (
                "secondary.exe".to_string(),
                vec![PathBuf::from(r"C:\Apps\secondary.exe")],
            ),
            (
                "evil.exe".to_string(),
                vec![PathBuf::from(r"C:\Apps\evil.exe")],
            ),
        ]);
        let mut blocked_app = app_rule("r-block-app", "evil.exe", false);
        blocked_app.action = nrr_domain::RuleAction::Block;
        let rule_book = book(
            vec![app_rule("r-prim", "primary.exe", false)],
            vec![app_rule("r-sec", "secondary.exe", false), blocked_app],
        );
        let out = generate_filters(CodegenInput {
            sid: "S",
            rule_book: &rule_book,
            behavior_mode: RouteBehaviorMode::PreferPrimary,
            fqdn_cache: &cache,
            app_observations: &MockAppObservationLookup::new(),
            app_resolver: &resolver,
            secondary_ip_denylist: &std::collections::HashSet::new(),
        });
        // Only the secondary ROUTE app is protected: the primary app uses the
        // primary NIC (never killed), and the block app is being dropped, not
        // routed via the secondary adapter. The pattern carried is the RESOLVED PATH.
        assert_eq!(
            out.secondary_app_patterns,
            vec![r"C:\Apps\secondary.exe".to_string()]
        );
    }

    // ── Block action ─────────────────────────────────────────────────────────

    fn block_exact_ip_rule(id: &str, addr: Ipv4Addr) -> CanonicalRule {
        let mut r = exact_ip_rule(id, addr);
        r.action = nrr_domain::RuleAction::Block;
        r
    }

    #[test]
    fn block_rule_emits_ale_and_packet_block_at_block_band() {
        let cache = MockFqdnCacheLookup::new();
        let addr = Ipv4Addr::new(203, 0, 113, 5);
        // Block rule lives in the secondary set — membership is irrelevant.
        let rule_book = book(vec![], vec![block_exact_ip_rule("r-1", addr)]);
        let out = generate_filters(CodegenInput {
            sid: "S-1-5-21-A",
            rule_book: &rule_book,
            behavior_mode: RouteBehaviorMode::PreferPrimary,
            fqdn_cache: &cache,
            app_observations: &MockAppObservationLookup::new(),
            app_resolver: &NoopAppPathResolver,
            secondary_ip_denylist: &std::collections::HashSet::new(),
        });
        // Exactly two filters: an ALE-layer block and a packet-layer mirror.
        assert_eq!(out.filters.len(), 2);
        assert!(out.filters.iter().all(|f| f.action == WfpAction::Block));
        assert!(out.filters.iter().all(|f| f.remote_ip == Some(addr)));
        let ale = out
            .filters
            .iter()
            .find(|f| f.layer == WfpLayerKey::AleAuthConnectV4)
            .expect("ALE block");
        let pkt = out
            .filters
            .iter()
            .find(|f| f.layer == WfpLayerKey::OutboundIpPacketV4)
            .expect("packet-layer block (ICMP parity)");
        // Block band beats the kill-switch permit band (0x0040_0000).
        assert!(
            ale.weight >= BASE_BLOCK,
            "block must use the BASE_BLOCK band"
        );
        // ALE block is SID-scoped; packet layer has no ALE_USER_ID → system-wide.
        assert_eq!(ale.user_sid.as_deref(), Some("S-1-5-21-A"));
        assert!(pkt.user_sid.is_none());
        assert_ne!(
            ale.id, pkt.id,
            "block filter ids must be distinct per layer"
        );
    }

    #[test]
    fn block_rule_ip_is_excluded_from_secondary_dest_ips() {
        let cache = MockFqdnCacheLookup::new();
        let routed = Ipv4Addr::new(203, 0, 113, 9);
        let blocked = Ipv4Addr::new(203, 0, 113, 5);
        let rule_book = book(
            vec![],
            vec![
                exact_ip_rule("r-route", routed),
                block_exact_ip_rule("r-block", blocked),
            ],
        );
        let out = generate_filters(CodegenInput {
            sid: "S",
            rule_book: &rule_book,
            behavior_mode: RouteBehaviorMode::PreferPrimary,
            fqdn_cache: &cache,
            app_observations: &MockAppObservationLookup::new(),
            app_resolver: &NoopAppPathResolver,
            secondary_ip_denylist: &std::collections::HashSet::new(),
        });
        // Only the routed (Permit) destination is protected by the kill-switch;
        // a dropped destination must never be handed to it.
        assert_eq!(out.secondary_dest_ips, vec![routed]);
        assert!(!out.secondary_dest_ips.contains(&blocked));
    }

    #[test]
    fn block_filter_ids_are_deterministic_across_reapply() {
        let cache = MockFqdnCacheLookup::new();
        let rule_book = book(
            vec![],
            vec![block_exact_ip_rule("r-1", Ipv4Addr::new(203, 0, 113, 5))],
        );
        let mk = || {
            generate_filters(CodegenInput {
                sid: "S",
                rule_book: &rule_book,
                behavior_mode: RouteBehaviorMode::PreferPrimary,
                fqdn_cache: &cache,
                app_observations: &MockAppObservationLookup::new(),
                app_resolver: &NoopAppPathResolver,
                secondary_ip_denylist: &std::collections::HashSet::new(),
            })
        };
        let a = mk();
        let b = mk();
        assert_eq!(a.filters, b.filters);
    }
}
