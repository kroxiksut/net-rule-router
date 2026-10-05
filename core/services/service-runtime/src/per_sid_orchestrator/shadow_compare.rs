//! Windows-only: runs the neutral enforcement-plan pipeline alongside the
//! live WFP one on real input and reports whether they agree. Evidence-only —
//! nothing here reaches the kernel, and a disagreement never affects what the
//! live pass installs.

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

impl PerSidApplyOrchestrator {
    /// Run the neutral pipeline alongside the live one and report whether they
    /// agree. Compares only — nothing here reaches the kernel.
    ///
    /// Returns whether the comparison actually RAN: `false` means the input was
    /// the one already evidenced and the work was skipped.
    ///
    /// This is the evidence step of moving enforcement onto the neutral plan.
    /// The equivalence is already proven by oracle tests over hand-built rule
    /// books; what those cannot cover is the shape of a real user's rules, with
    /// its own cache contents, app resolutions and fan-outs. So the two run
    /// side by side on live input first, and only a silent log promotes the
    /// neutral one to the path that enforces.
    ///
    /// Deliberately narrow: rule-driven flows only, and only what the planner
    /// models today. The fake-IP augmentation is folded in by the caller AFTER
    /// this returns, and the kill-switch classes are compared by their own
    /// oracle tests — widening this to them before they are modelled would
    /// report a difference that means nothing.
    pub(super) fn shadow_compare_neutral_plan(
        &self,
        sid: &str,
        behavior_mode: nrr_domain::RouteBehaviorMode,
        rule_book: &nrr_domain::canonical::CanonicalRuleBook,
        fqdn_cache: &dyn crate::fqdn_cache_lookup::FqdnCacheLookup,
        secondary_ip_denylist: &std::collections::HashSet<std::net::Ipv4Addr>,
        live: &[nrr_platform_api::types::WfpFilterSpec],
    ) -> bool {
        // Same input, same verdict — and the verdict is already in the log.
        // Re-deriving it costs a full plan plus a lowering on a path that also
        // carries DNS answers and the GUI's own requests.
        let fingerprint = shadow_compare_fingerprint(behavior_mode, live);
        {
            let mut seen = self
                .shadow_compare_seen
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            if let Some((last, at)) = seen.get(sid) {
                // The filter set changes with every learned address; evidence
                // sampled every few minutes says as much as evidence per change.
                if *last == fingerprint || at.elapsed() < SHADOW_COMPARE_EVERY {
                    return false;
                }
            }
            seen.insert(sid.to_string(), (fingerprint, std::time::Instant::now()));
        }
        let Some(verdict) = self.neutral_plan_verdict(
            sid,
            behavior_mode,
            rule_book,
            fqdn_cache,
            secondary_ip_denylist,
            live,
        ) else {
            return false;
        };
        if verdict.agrees() {
            tracing::debug!(
                target: "nrr::enforcement-plan",
                sid,
                filters = verdict.live,
                "neutral plan matches the filters actually installed",
            );
            return true;
        }
        // A difference is the whole reason this runs on live input. WARN, not
        // debug: it is the one signal that says the neutral path is not ready
        // to take over, and it must not be discoverable only by someone
        // grepping for it.
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
            "neutral plan DIFFERS from the filters actually installed — enforcement is unaffected (the live path applied), but the neutral path cannot take over until this is explained",
        );
        true
    }

    /// The comparison itself, separated from the logging so a test can assert
    /// the outcome. A verdict that only ever reaches a log line is a verdict
    /// nothing can hold to account.
    ///
    /// `None` when the SID is not a principal this build can model.
    pub(super) fn neutral_plan_verdict(
        &self,
        sid: &str,
        behavior_mode: nrr_domain::RouteBehaviorMode,
        rule_book: &nrr_domain::canonical::CanonicalRuleBook,
        fqdn_cache: &dyn crate::fqdn_cache_lookup::FqdnCacheLookup,
        secondary_ip_denylist: &std::collections::HashSet<std::net::Ipv4Addr>,
        live: &[nrr_platform_api::types::WfpFilterSpec],
    ) -> Option<NeutralPlanVerdict> {
        use nrr_platform_api::enforcement::{EnforcementPlan, UserPrincipal};
        use nrr_platform_api::wfp_behavioral::{
            arbitration_order_preserved, behaviorally_equivalent,
        };

        let principal = UserPrincipal::from_windows_sid(sid).ok()?;
        // The SAME cache reading the live path used — not a fresh look at the
        // live cache. The pass takes one snapshot precisely because the DNS
        // observer keeps writing; comparing a plan built from the snapshot with
        // one built from the cache as it stands milliseconds later reports the
        // clock, not the pipelines. It is why `only_neutral` was never empty
        // and `only_live` always was: the second reader simply saw more.
        let input = crate::enforcement_planner::PlannerInput {
            fqdn_cache,
            app_resolver: self.app_resolver.as_ref(),
            app_observations: self.app_observations.as_ref(),
            zone_priority_over_ip: false,
            // The set the live pass hid from the tunnel. Comparing against a
            // plan that never saw it was comparing a pipeline WITH the
            // shared-IP policy to one without: every secondary rule then
            // carried different addresses, and with them different ordinals,
            // so the two plans could not agree on anything downstream.
            secondary_ip_denylist,
            // The drift check compares the neutral plan with what the live pass
            // produced, and the live pass is the one that decides whether a link
            // can carry IPv6. Naming the family here would compare two different
            // questions.
            ipv6: crate::enforcement_planner::Ipv6Guard::Off,
        };
        let plan = EnforcementPlan {
            principal,
            // The report is the GUI's business, and this is the shadow
            // comparison — it looks at filters only.
            flows: crate::enforcement_planner::plan_route_rules(
                rule_book,
                sid,
                behavior_mode,
                &input,
            )
            .0,
            routes: Vec::new(),
            policy_rules: Vec::new(),
        };
        let lowered = nrr_platform_windows::lower_windows::lower_route_rules(&plan);

        // `live` is exactly `generate_filters`' output: rule-driven only. The
        // leak-guard and kill-switch classes are appended by the caller further
        // down, after this returns, so no filtering is needed here — and doing
        // any would silently narrow what the comparison covers.
        let difference = nrr_platform_api::wfp_behavioral::behavioral_difference(live, &lowered);
        Some(NeutralPlanVerdict {
            live: live.len(),
            neutral: lowered.len(),
            same_set: behaviorally_equivalent(live, &lowered),
            same_order: arbitration_order_preserved(live, &lowered),
            differs_live: render_shapes(&difference.only_in_a),
            differs_neutral: render_shapes(&difference.only_in_b),
            only_live: render_difference(&difference.only_in_a),
            only_neutral: render_difference(&difference.only_in_b),
        })
    }
}

/// What the shadow compare would run on, as one number.
///
/// The installed filter set IS the comparison's input: it is derived from the
/// same rule book, cache and app resolutions the neutral plan re-derives, so an
/// unchanged set means unchanged inputs. Ids are content-addressed, which is
/// what makes them safe to fold; the weight goes in too, because arbitration
/// order is half of what the comparison checks.
fn shadow_compare_fingerprint(
    behavior_mode: nrr_domain::RouteBehaviorMode,
    live: &[nrr_platform_api::types::WfpFilterSpec],
) -> u64 {
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
    fold(behavior_mode as u64);
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
