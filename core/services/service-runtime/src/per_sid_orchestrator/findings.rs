//! What a pass tells the user and the log about the rules, besides enforcing
//! them: rules that enforce nothing yet, contradictions, caps reached.

use std::net::Ipv4Addr;

use crate::address_ownership::AppTrafficElsewhere;
use crate::rule_conflicts::RuleConflict;
use crate::wfp_codegen::CodegenDiagnostic;

#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct PassFindings {
    /// Application rules whose program resolved to nothing on disk.
    pub unresolved_apps: Vec<String>,
    /// Application rules and folders past the fan-out cap, as the log names them.
    pub over_capped: Vec<String>,
    /// Hosts, suffixes and zones with no confirmed address yet.
    pub unresolved_hosts: Vec<String>,
    /// `(rule_id, suffix, cap)` for fan-outs stopped at the backstop.
    pub truncated_suffixes: Vec<(String, String, usize)>,
    /// `(app, address)` an application rule left to a main-link rule.
    pub claimed_by_main: Vec<(String, Ipv4Addr)>,
    /// `(app, address)` an application rule left alone: other programs use it.
    pub shared_with_others: Vec<(String, Ipv4Addr)>,
    /// Application rules whose program carries none of its traffic.
    pub unrouted_apps: Vec<(String, AppTrafficElsewhere)>,
    /// `"<rule_id> (<reason>)"` for rule shapes enforcement cannot carry out.
    pub unsupported_shapes: Vec<String>,
    /// Network rules carved into more pieces than the cap.
    pub networks_over_cap: Vec<RuleConflict>,
    /// Everything the Overlaps screen lists, in rule order.
    pub conflicts: Vec<RuleConflict>,
}

impl PassFindings {
    pub(super) fn from_codegen(diagnostics: &[CodegenDiagnostic]) -> Self {
        let mut out = Self::default();
        for diag in diagnostics {
            match diag {
                CodegenDiagnostic::AppUnresolved { app, .. } => {
                    out.unresolved_apps.push(app.clone());
                }
                CodegenDiagnostic::HostnameUnresolved { hostname, .. } => {
                    out.unresolved_hosts.push(hostname.clone());
                }
                // A suffix/zone with nothing cached under it: the apex is the
                // one name worth asking about.
                CodegenDiagnostic::SuffixEmpty { suffix, .. } => {
                    out.unresolved_hosts.push(suffix.clone());
                }
                CodegenDiagnostic::ZoneEmpty { zone, .. } => {
                    out.unresolved_hosts.push(zone.clone());
                }
                CodegenDiagnostic::AppOverCapped {
                    app, resolved, cap, ..
                } => out.over_capped.push(over_capped_app(
                    app,
                    usize::try_from(*cap).unwrap_or(usize::MAX),
                    *resolved,
                )),
                CodegenDiagnostic::AppFolderOverCap {
                    folder, covered, ..
                } => out.over_capped.push(over_capped_folder(folder, *covered)),
                CodegenDiagnostic::AppDestinationClaimedByPrimary { app, ip, .. } => {
                    out.claimed_by_main.push((app.clone(), *ip));
                }
                CodegenDiagnostic::AppDestinationUsedByOtherProcess { app, ip, .. } => {
                    out.shared_with_others.push((app.clone(), *ip));
                }
                CodegenDiagnostic::AppTrafficTakenElsewhere { app, reason, .. } => {
                    out.unrouted_apps.push((app.clone(), *reason));
                }
                CodegenDiagnostic::SuffixTruncated {
                    rule_id,
                    suffix,
                    cap,
                } => out
                    .truncated_suffixes
                    .push((rule_id.clone(), suffix.clone(), *cap)),
                CodegenDiagnostic::UnsupportedRuleShape { rule_id, reason } => {
                    out.unsupported_shapes.push(format!("{rule_id} ({reason})"));
                }
                CodegenDiagnostic::NetworkCarvingOverCap { .. } => {
                    out.networks_over_cap.extend(diag.rule_conflict());
                }
                _ => {}
            }
        }
        out.conflicts = diagnostics
            .iter()
            .filter_map(CodegenDiagnostic::rule_conflict)
            .collect();
        out
    }

    /// Windows only for now: elsewhere the pass still reads the codegen.
    #[cfg(windows)]
    pub(super) fn from_plan(report: &crate::enforcement_planner::PlanReport) -> Self {
        let mut over_capped: Vec<String> = report
            .over_capped_apps
            .iter()
            .map(|(app, cap, resolved)| over_capped_app(app, *cap, *resolved))
            .collect();
        over_capped.extend(
            report
                .over_capped_folders
                .iter()
                .map(|(folder, covered)| over_capped_folder(folder, *covered)),
        );
        let mut unsupported_shapes = Vec::new();
        let mut networks_over_cap = Vec::new();
        for conflict in &report.conflicts {
            match conflict {
                RuleConflict::UnsupportedRuleShape { rule_id, reason } => {
                    unsupported_shapes.push(format!("{rule_id} ({reason})"));
                }
                RuleConflict::NetworkCarvingOverCap { .. } => {
                    networks_over_cap.push(conflict.clone());
                }
                _ => {}
            }
        }
        Self {
            unresolved_apps: report.unresolved_apps.clone(),
            over_capped,
            unresolved_hosts: report.unresolved_hosts.clone(),
            truncated_suffixes: report.truncated_suffixes.clone(),
            claimed_by_main: report.claimed_by_main.clone(),
            shared_with_others: report.used_by_others.clone(),
            unrouted_apps: report.unrouted_apps.clone(),
            unsupported_shapes,
            networks_over_cap,
            conflicts: report.conflicts.clone(),
        }
    }

    /// The same findings in an order the log and the screen do not depend on:
    /// each list is sorted, or kept in rule order, by its reader.
    #[cfg(all(test, windows))]
    pub(super) fn normalized(mut self) -> Self {
        self.over_capped.sort();
        self.unresolved_hosts.sort();
        self.unresolved_hosts.dedup();
        self.claimed_by_main.sort();
        self.claimed_by_main.dedup();
        self.shared_with_others.sort();
        self.shared_with_others.dedup();
        self
    }
}

fn over_capped_app(app: &str, cap: usize, resolved: usize) -> String {
    format!("{app} ({cap}/{resolved})")
}

fn over_capped_folder(folder: &str, covered: usize) -> String {
    format!("{folder} ({covered}/{covered}+)")
}
