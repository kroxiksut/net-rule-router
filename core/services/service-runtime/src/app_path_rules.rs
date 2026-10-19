//! A rule by program path, turned into what enforcement acts on.
//!
//! The WFP codegen and the neutral planner both ask the platform which
//! programs a path rule covers for its owner, judge the place the disk
//! revealed by the protection of system programs and folders, and tell the
//! observations where the rule really is. Both read the answer from here, so
//! the two mechanisms cannot disagree about one rule.
//!
//! The disk is judged again on purpose: the rules file names `C:\Tools\*`,
//! which passes, while `C:\Tools` may be a junction into `C:\Windows`. The
//! place the programs really live at is what decides.

use std::path::PathBuf;

use nrr_domain::protected_places::{
    critical_processes_covered, protection_verdict, AppTarget, OverrideAsk, ProtectedPlaces,
    ProtectionReason, ProtectionVerdict, RuleEffect,
};
use nrr_platform_api::app_folders::{AppPath, PathOutcome};
use nrr_platform_api::AppPathResolver;

use crate::address_ownership::AppDestinationGate;

/// What one path rule enforces for one owner this pass.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathRuleTargets {
    /// The key the rule's observations are kept under: its canonical spelling.
    pub key: String,
    /// Real paths of the programs it covers.
    pub programs: Vec<PathBuf>,
    /// The folder holds more programs than one rule covers.
    pub over_cap: bool,
    pub outcome: PathOutcome,
    /// The place the disk revealed is protected: the rule applies nothing.
    pub refused: Option<ProtectionReason>,
    /// Refused, and the rule asks to apply anyway: it waits for its owner's
    /// confirmation (none yet, or one that no longer covers what it takes).
    pub override_pending: bool,
}

/// The programs `path` covers for `owner` under `effect`, judged against
/// `places`. The real place is handed to the observations through `gate`.
/// A rule that asks to apply anyway (`override_requested`) does so where its
/// owner's confirmation still covers the critical programs the place holds.
#[must_use]
pub fn path_rule_targets(
    path: &AppPath,
    owner: &str,
    effect: RuleEffect,
    override_requested: bool,
    resolver: &dyn AppPathResolver,
    gate: &AppDestinationGate<'_>,
    places: &ProtectedPlaces,
) -> PathRuleTargets {
    let key = path.as_str().to_string();
    let found = resolver.path_programs(path, owner);
    if let Some(place) = found.place.as_ref() {
        let target = AppTarget::of_path(place);
        if let ProtectionVerdict::Refused(reason) = protection_verdict(target, effect, places) {
            // A confirmation covers the place the rule names; a link that
            // leads somewhere protected otherwise is refused outright.
            let pending = override_requested
                && reason.overridable()
                && protection_verdict(AppTarget::of_path(path), effect, places)
                    == ProtectionVerdict::Refused(reason);
            let confirmed = pending && {
                let programs: Vec<String> = found
                    .programs
                    .iter()
                    .map(|p| p.to_string_lossy().into_owned())
                    .collect();
                let critical = critical_processes_covered(target, &programs, places.platform());
                crate::override_grants::honoured(
                    owner,
                    &OverrideAsk {
                        value: &key,
                        effect,
                        reason,
                        critical: &critical,
                    },
                )
            };
            if !confirmed {
                return PathRuleTargets {
                    key,
                    programs: Vec::new(),
                    over_cap: false,
                    outcome: found.outcome,
                    refused: Some(reason),
                    override_pending: pending,
                };
            }
        }
        gate.note_path_places(&key, std::slice::from_ref(place));
    }
    let programs = if found.outcome == PathOutcome::Found {
        found.programs
    } else {
        Vec::new()
    };
    PathRuleTargets {
        key,
        programs,
        over_cap: found.over_cap,
        outcome: found.outcome,
        refused: None,
        override_pending: false,
    }
}

#[cfg(test)]
mod tests;
