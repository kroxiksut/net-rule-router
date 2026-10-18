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
    protection_verdict, AppTarget, ProtectedPlaces, ProtectionReason, ProtectionVerdict, RuleEffect,
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
}

/// The programs `path` covers for `owner` under `effect`, judged against
/// `places`. The real place is handed to the observations through `gate`.
#[must_use]
pub fn path_rule_targets(
    path: &AppPath,
    owner: &str,
    effect: RuleEffect,
    resolver: &dyn AppPathResolver,
    gate: &AppDestinationGate<'_>,
    places: &ProtectedPlaces,
) -> PathRuleTargets {
    let key = path.as_str().to_string();
    let found = resolver.path_programs(path, owner);
    if let Some(place) = found.place.as_ref() {
        if let ProtectionVerdict::Refused(reason) =
            protection_verdict(AppTarget::of_path(place), effect, places)
        {
            return PathRuleTargets {
                key,
                programs: Vec::new(),
                over_cap: false,
                outcome: found.outcome,
                refused: Some(reason),
            };
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
    }
}

#[cfg(test)]
mod tests;
