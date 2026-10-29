//! Windows-only: the neutral plan lowered for WFP is what a pass installs for
//! its rules. `generate_filters` still runs beside it for the destination sets
//! and diagnostics the pass reads, and is held to the installed filters here.

use super::*;

/// What the shadow comparison found: how many filters each pipeline produced,
/// and whether they describe the same enforcement in the same arbitration order.
///
/// Windows-only, like the comparison itself — off-Windows there is no WFP
/// filter set to compare against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct NeutralPlanVerdict {
    pub(super) live: usize,
    pub(super) neutral: usize,
    pub(super) same_set: bool,
    pub(super) same_order: bool,
    /// What KIND of filters each side has and the other does not, grouped and
    /// counted — no address, path or interface, so the default log can say why
    /// the plans differ.
    differs_live: String,
    differs_neutral: String,
    /// A few of those filters with their addresses, for the verbose log. Bounded:
    /// a set that diverges wholesale is answered by the counts alone.
    only_live: String,
    only_neutral: String,
}

/// The comparison runs at most this often per SID: it costs a full plan plus a
/// lowering, on the path that also carries DNS answers.
pub(super) const SHADOW_COMPARE_EVERY: std::time::Duration =
    std::time::Duration::from_secs(15 * 60);

/// At most this many differing filters are named per side. Enough to identify
/// a category; past it the counts already say the sets diverge wholesale.
const NEUTRAL_DIFF_SAMPLE: usize = 4;

/// Render a multiset difference as one short line, addresses included.
fn render_difference(
    entries: &[(nrr_platform_api::wfp_behavioral::BehavioralKey, usize)],
) -> String {
    if entries.is_empty() {
        return String::new();
    }
    let mut parts: Vec<String> = entries
        .iter()
        .take(NEUTRAL_DIFF_SAMPLE)
        .map(|(key, count)| {
            let key = key.addresses();
            if *count > 1 {
                format!("{key} x{count}")
            } else {
                format!("{key}")
            }
        })
        .collect();
    if entries.len() > NEUTRAL_DIFF_SAMPLE {
        parts.push(format!("(+{} more)", entries.len() - NEUTRAL_DIFF_SAMPLE));
    }
    parts.join("; ")
}

/// Render a multiset difference by filter kind: every differing filter is
/// counted under its shape, most frequent first.
fn render_shapes(entries: &[(nrr_platform_api::wfp_behavioral::BehavioralKey, usize)]) -> String {
    let mut by_shape: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for (key, count) in entries {
        *by_shape.entry(key.shape().to_string()).or_default() += count;
    }
    let mut shapes: Vec<(String, usize)> = by_shape.into_iter().collect();
    shapes.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    shapes
        .into_iter()
        .map(|(shape, count)| format!("{shape} x{count}"))
        .collect::<Vec<_>>()
        .join("; ")
}

impl NeutralPlanVerdict {
    /// Both halves must hold. Same filters in a different arbitration order is
    /// a different policy, not a cosmetic difference: WFP resolves overlapping
    /// filters by weight, so reordering changes which one decides.
    fn agrees(&self) -> bool {
        self.same_set && self.same_order
    }
}

/// The rule-driven part of a pass, planned neutrally.
pub(super) struct NeutralRules {
    pub(super) flows: Vec<nrr_platform_api::enforcement::FlowRule>,
    pub(super) report: crate::enforcement_planner::PlanReport,
    /// `flows` lowered for WFP: what the pass installs for the rules.
    pub(super) filters: Vec<nrr_platform_api::types::WfpFilterSpec>,
}

impl NeutralRules {
    /// What the rest of the pass reads about the rules besides their filters,
    /// written over `out`: the kill switch pins, the main link's networks, the
    /// programs the additional link carries and the VPN clients it spares. The
    /// report is handed back for what the pass tells the user.
    pub(super) fn describe(
        self,
        out: &mut crate::wfp_codegen::CodegenOutput,
        resolver: &dyn nrr_platform_api::AppPathResolver,
        reference: Option<&crate::wfp_codegen::CodegenOutput>,
    ) -> crate::enforcement_planner::PlanReport {
        use crate::enforcement_planner as planner;
        use nrr_shared::RouteRole::{Primary, Secondary};
        let secondary_dest_ips = planner::route_destinations(&self.flows, Secondary);
        let primary_dest_networks = planner::route_networks(&self.flows, Primary);
        let secondary_app_patterns = planner::route_app_paths(&self.flows, Secondary);
        let vpn_default_exempt_paths = planner::vpn_default_exempt_paths(resolver);
        // Every test of the pass doubles as the check that the plan describes
        // what the codegen described, until the codegen is gone.
        #[cfg(not(test))]
        let _ = reference;
        #[cfg(test)]
        if let Some(reference) = reference {
            // Packed into pins sorted, so the order is no one's business.
            let sorted = |ips: &[std::net::IpAddr]| {
                let mut ips = ips.to_vec();
                ips.sort_unstable();
                ips
            };
            assert_eq!(
                sorted(&secondary_dest_ips),
                sorted(&reference.secondary_dest_ips),
                "secondary destinations"
            );
            assert_eq!(
                primary_dest_networks, reference.primary_dest_networks,
                "main networks"
            );
            assert_eq!(
                secondary_app_patterns, reference.secondary_app_patterns,
                "programs"
            );
            assert_eq!(
                self.report.app_guarded_additional, reference.app_observed_secondary_ips,
                "app-guarded destinations"
            );
            assert_eq!(
                vpn_default_exempt_paths, reference.vpn_default_exempt_paths,
                "VPN clients"
            );
        }
        out.filters = self.filters;
        out.secondary_dest_ips = secondary_dest_ips;
        out.primary_dest_networks = primary_dest_networks;
        out.secondary_app_patterns = secondary_app_patterns;
        out.app_observed_secondary_ips = self.report.app_guarded_additional.clone();
        out.vpn_default_exempt_paths = vpn_default_exempt_paths;
        self.report
    }
}

/// What the pass installs and what `generate_filters` would have installed,
/// compared as WFP sees them.
pub(super) fn verdict_of(
    installed: &[nrr_platform_api::types::WfpFilterSpec],
    previous: &[nrr_platform_api::types::WfpFilterSpec],
) -> NeutralPlanVerdict {
    use nrr_platform_api::wfp_behavioral::{
        arbitration_order_preserved, behavioral_difference, behaviorally_equivalent,
    };
    let difference = behavioral_difference(installed, previous);
    NeutralPlanVerdict {
        live: installed.len(),
        neutral: previous.len(),
        same_set: behaviorally_equivalent(installed, previous),
        same_order: arbitration_order_preserved(installed, previous),
        differs_live: render_shapes(&difference.only_in_a),
        differs_neutral: render_shapes(&difference.only_in_b),
        only_live: render_difference(&difference.only_in_a),
        only_neutral: render_difference(&difference.only_in_b),
    }
}

impl PerSidApplyOrchestrator {
    /// The rule-driven part of the pass from the neutral plan: its flows, its
    /// report and the filters lowered for WFP. `None` for a principal the plan
    /// cannot name (the baseline sentinel), whose codegen set stands.
    ///
    /// Fed the pass's own readings, the cache snapshot and the observations the
    /// codegen and the arbiter also read, so what the pass derives besides
    /// these filters describes these filters.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn neutral_route_filters(
        &self,
        sid: &str,
        rule_book: &nrr_domain::canonical::CanonicalRuleBook,
        fqdn_cache: &dyn crate::fqdn_cache_lookup::FqdnCacheLookup,
        app_observations: &dyn crate::app_observation_lookup::AppObservationLookup,
        secondary_ip_denylist: &std::collections::HashSet<std::net::Ipv4Addr>,
        zone_priority_over_ip: bool,
        app_takeover: bool,
        ipv6: crate::enforcement_planner::Ipv6Guard,
    ) -> Option<NeutralRules> {
        use nrr_platform_api::enforcement::{EnforcementPlan, UserPrincipal};

        let principal = UserPrincipal::from_windows_sid(sid).ok()?;
        let input = crate::enforcement_planner::PlannerInput {
            fqdn_cache,
            app_resolver: self.app_resolver.as_ref(),
            app_observations,
            zone_priority_over_ip,
            app_rules_take_all_addresses: app_takeover,
            // The set the pass hid from the tunnel: the routes and the census
            // decline the same shared addresses.
            secondary_ip_denylist,
            ipv6,
            packet_blocks: super::PACKET_BLOCKS,
        };
        let (flows, report) = crate::enforcement_planner::plan_route_rules(rule_book, sid, &input);
        let plan = EnforcementPlan {
            principal,
            flows,
            routes: Vec::new(),
            policy_rules: Vec::new(),
        };
        let filters = nrr_platform_windows::lower_windows::lower_route_rules(&plan);
        Some(NeutralRules {
            flows: plan.flows,
            report,
            filters,
        })
    }

    /// Whether `fingerprint` is new evidence for `sid`: a different input,
    /// and the sampling window passed since the last one.
    pub(super) fn compare_due(&self, sid: &str, fingerprint: u64) -> bool {
        let mut seen = self
            .shadow_compare_seen
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if let Some((last, at)) = seen.get(sid) {
            if *last == fingerprint || at.elapsed() < SHADOW_COMPARE_EVERY {
                return false;
            }
        }
        seen.insert(sid.to_string(), (fingerprint, std::time::Instant::now()));
        true
    }

    /// Hold the installed filters against the ones `generate_filters` still
    /// computes, sampled. The pass reads the codegen's destination sets and
    /// diagnostics until they move to the planner; a difference means those
    /// describe other filters than the ones in force. Returns whether it ran.
    pub(super) fn compare_with_codegen(
        &self,
        sid: &str,
        installed: &[nrr_platform_api::types::WfpFilterSpec],
        codegen: &[nrr_platform_api::types::WfpFilterSpec],
    ) -> bool {
        if !self.compare_due(sid, shadow_compare_fingerprint(codegen)) {
            return false;
        }
        self.report_comparison(sid, installed, codegen);
        true
    }

    /// [`Self::compare_with_codegen`] for a caller that sampled already.
    pub(super) fn report_comparison(
        &self,
        sid: &str,
        installed: &[nrr_platform_api::types::WfpFilterSpec],
        codegen: &[nrr_platform_api::types::WfpFilterSpec],
    ) {
        report(sid, &verdict_of(installed, codegen));
    }

    /// The neutral plan held against `live`, built from the orchestrator's own
    /// readings; sampled like [`Self::compare_with_codegen`].
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(super) fn shadow_compare_neutral_plan(
        &self,
        sid: &str,
        rule_book: &nrr_domain::canonical::CanonicalRuleBook,
        fqdn_cache: &dyn crate::fqdn_cache_lookup::FqdnCacheLookup,
        secondary_ip_denylist: &std::collections::HashSet<std::net::Ipv4Addr>,
        zone_priority_over_ip: bool,
        app_takeover: bool,
        ipv6: crate::enforcement_planner::Ipv6Guard,
        live: &[nrr_platform_api::types::WfpFilterSpec],
    ) -> bool {
        if !self.compare_due(sid, shadow_compare_fingerprint(live)) {
            return false;
        }
        let Some(verdict) = self.neutral_plan_verdict(
            sid,
            rule_book,
            fqdn_cache,
            secondary_ip_denylist,
            zone_priority_over_ip,
            app_takeover,
            ipv6,
            live,
        ) else {
            return false;
        };
        report(sid, &verdict);
        true
    }

    /// The comparison itself, for a test to assert on. `None` when the SID is
    /// not a principal the plan can name.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(super) fn neutral_plan_verdict(
        &self,
        sid: &str,
        rule_book: &nrr_domain::canonical::CanonicalRuleBook,
        fqdn_cache: &dyn crate::fqdn_cache_lookup::FqdnCacheLookup,
        secondary_ip_denylist: &std::collections::HashSet<std::net::Ipv4Addr>,
        zone_priority_over_ip: bool,
        app_takeover: bool,
        ipv6: crate::enforcement_planner::Ipv6Guard,
        live: &[nrr_platform_api::types::WfpFilterSpec],
    ) -> Option<NeutralPlanVerdict> {
        let neutral = self.neutral_route_filters(
            sid,
            rule_book,
            fqdn_cache,
            self.app_observations.as_ref(),
            secondary_ip_denylist,
            zone_priority_over_ip,
            app_takeover,
            ipv6,
        )?;
        Some(verdict_of(live, &neutral.filters))
    }
}

/// One log line per comparison: debug when the two agree, WARN when they do
/// not, the one signal that the codegen's side outputs drifted from the
/// filters in force.
fn report(sid: &str, verdict: &NeutralPlanVerdict) {
    if verdict.agrees() {
        tracing::debug!(
            target: "nrr::enforcement-plan",
            sid,
            filters = verdict.live,
            "installed filters match the codegen's",
        );
        return;
    }
    tracing::warn!(
        target: "nrr::enforcement-plan",
        msg_key = "persid-shadow-plan-differs",
        sid,
        live = verdict.live,
        neutral = verdict.neutral,
        same_set = verdict.same_set,
        same_order = verdict.same_order,
        differs_live = %verdict.differs_live,
        differs_neutral = %verdict.differs_neutral,
        only_live = %verdict.only_live,
        only_neutral = %verdict.only_neutral,
        "installed filters (neutral plan) DIFFER from the codegen's, whose destination sets this pass still reads",
    );
}

/// What the shadow compare would run on, as one number.
///
/// The installed filter set IS the comparison's input: it is derived from the
/// same rule book, cache and app resolutions the neutral plan re-derives, so an
/// unchanged set means unchanged inputs. Ids are content-addressed, which is
/// what makes them safe to fold; the weight goes in too, because arbitration
/// order is half of what the comparison checks.
pub(super) fn shadow_compare_fingerprint(live: &[nrr_platform_api::types::WfpFilterSpec]) -> u64 {
    // FNV-1a, the same hash the filter ids themselves are built with.
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = OFFSET;
    let mut fold = |value: u64| {
        for byte in value.to_le_bytes() {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(PRIME);
        }
    };
    fold(live.len() as u64);
    for spec in live {
        fold(spec.id.raw);
        fold(spec.weight);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_platform_api::types::{WfpAction, WfpFilterId, WfpFilterSpec, WfpLayerKey};
    use nrr_platform_api::wfp_behavioral::behavioral_key;
    use std::net::Ipv4Addr;

    fn block(remote: [u8; 4], app: Option<&str>) -> WfpFilterSpec {
        WfpFilterSpec {
            layer: WfpLayerKey::OutboundIpPacketV4,
            action: WfpAction::Block,
            remote_ip: Some(Ipv4Addr::from(remote)),
            remote_ip_set: Vec::new(),
            remote_ip_set_v6: Vec::new(),
            remote_port: None,
            weight: 1,
            id: WfpFilterId::from_raw(1),
            user_sid: None,
            app_pattern: app.map(str::to_string),
            local_interface_luid: None,
            remote_subnet: None,
            remote_subnet_v6: None,
            ip_protocol: None,
            remote_subnet_set: Vec::new(),
        }
    }

    /// The default log line names the kind and count of the differing filters
    /// and nothing that identifies a destination or an application.
    #[test]
    fn the_shape_summary_groups_by_kind_without_values() {
        let entries = vec![
            (behavioral_key(&block([198, 51, 100, 1], None)), 2),
            (behavioral_key(&block([198, 51, 100, 2], None)), 1),
            (
                behavioral_key(&block([203, 0, 113, 9], Some(r"C:\app.exe"))),
                1,
            ),
        ];
        let line = render_shapes(&entries);
        assert_eq!(line, "pkt4/block ip x3; pkt4/block ip app x1");

        let detail = render_difference(&entries);
        assert!(detail.contains("198.51.100.1"));
        assert!(
            !detail.contains("app.exe"),
            "the verbose line carries no path: {detail}"
        );
    }
}
