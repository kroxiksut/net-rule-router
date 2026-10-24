//! What a user who bound no connection still gets: their denies.
//!
//! A deny installs no route and arms no guard, so it has no reason to wait for
//! one. Everything else the rule book says needs a connection and stays off.

use super::*;
use crate::enforcement_planner::Ipv6Guard;

impl PerSidApplyOrchestrator {
    /// The deny filters of a user with no route policy, from the same codegen
    /// the policy path uses; [`ComputedFilterSet::NoPolicy`] when there are none.
    pub(super) fn compute_deny_filters_without_policy(
        &self,
        sid: &str,
        log_unresolved: bool,
        rules_override: Option<&ActiveRulesSnapshot>,
        intent: ComputeIntent,
    ) -> Result<ComputedFilterSet, OrchestratorError> {
        let rules = match rules_override
            .cloned()
            .map_or_else(|| self.rules_provider.rules_read_for(sid), RulesRead::Rules)
        {
            RulesRead::Rules(r) => r,
            RulesRead::Unreadable(reason) => {
                return Err(OrchestratorError::RulesUnreadable(reason));
            }
            RulesRead::NoPolicy => return Ok(ComputedFilterSet::NoPolicy),
        };
        if !crate::rule_book_facts::has_deny_rules(&rules.rule_book) {
            return Ok(ComputedFilterSet::NoPolicy);
        }
        let cache_snapshot = self.fqdn_cache.snapshot_for_compute();
        let fqdn_cache = crate::fqdn_cache_lookup::snapshot_or_live(
            cache_snapshot.as_ref(),
            self.fqdn_cache.as_ref(),
        );
        let denylist = crate::secondary_ip_policy::secondary_ip_denylist(
            &rules.rule_book.secondary,
            fqdn_cache,
            nrr_domain::shared_ip::SharedIpPolicy::default(),
        );
        let machine = (self.machine_reader)();
        let ipv6 = Ipv6Guard::from_links(machine.adapters().unwrap_or_default(), None, &[]);
        let out = generate_filters(CodegenInput {
            sid,
            rule_book: &rules.rule_book,
            fqdn_cache,
            app_observations: self.app_observations.as_ref(),
            app_resolver: self.app_resolver.as_ref(),
            secondary_ip_denylist: &denylist,
            zone_priority_over_ip: false,
            app_rules_take_all_addresses: false,
            families: ipv6.families(),
            packet_blocks: self.rules_provider.rules_are_baseline_for(sid),
        });
        let unresolved_apps: Vec<String> = out
            .diagnostics
            .iter()
            .filter_map(|d| match d {
                crate::wfp_codegen::CodegenDiagnostic::AppUnresolved { app, .. } => {
                    Some(app.clone())
                }
                _ => None,
            })
            .collect();
        if log_unresolved && !unresolved_apps.is_empty() {
            tracing::warn!(
                target: "nrr::app-resolver",
                msg_key = "persid-plan-app-rules-unresolved",
                sid = %sid,
                count = unresolved_apps.len(),
                apps = %unresolved_apps.join(", "),
                "application rules not enforced: no installed/running exe matched (checked App Paths, running processes, Program Files) — the per-app filters were not built",
            );
        }
        if let Some(status) = self
            .app_enforcement_status
            .as_ref()
            .filter(|_| intent.publishes())
        {
            status.set_unresolved(sid, unresolved_apps.clone());
            let mut conflicts = crate::app_enforcement_status::rule_conflicts_from(
                &out.diagnostics,
                &rules.rule_book,
            );
            conflicts.extend(crate::rule_conflicts::protected_rule_dtos(
                &self.rules_provider.withheld_rules_for(sid),
            ));
            status.set_rule_conflicts(sid, conflicts);
        }
        // Route permits ride a route, and there is none here; a narrower rule
        // inside a deny is already cut out of it by the codegen. A program
        // deny's loopback permit is a hole in its own block, so it stays.
        let filters: Vec<WfpFilterSpec> = out
            .filters
            .into_iter()
            .filter(|f| {
                f.action == WfpAction::Block || crate::wfp_codegen::is_deny_loopback_permit(f)
            })
            .collect();
        if !filters.iter().any(|f| f.action == WfpAction::Block) {
            return Ok(ComputedFilterSet::NoPolicy);
        }
        if intent.publishes() {
            self.update_killswitch_registry(
                sid,
                KillswitchBlockIds {
                    rule_blocks: rule_block_ids(&filters),
                    ..KillswitchBlockIds::default()
                },
            );
        }
        Ok(ComputedFilterSet::Install(ComputedPlan {
            filters,
            unresolved_apps,
        }))
    }
}
