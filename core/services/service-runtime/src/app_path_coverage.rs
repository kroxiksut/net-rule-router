//! What a rule by program path would cover for one person, asked while the
//! rule form is open, and whether a rule names a folder in another user's
//! profile.
//!
//! The form asks after a pause in typing. The answer is one read of the
//! platform port within one rule's bounds: nothing is remembered or watched
//! for a rule that does not exist yet, and nothing of it reaches a pass. A
//! place in another user's profile is refused before the disk is touched; a
//! protected place is refused before it is listed.

use std::path::Path;
use std::sync::Arc;

use nrr_domain::protected_places::{
    protection_verdict, AppTarget, ProtectedPlaces, ProtectionVerdict, RuleEffect,
};
use nrr_domain::rule_value_validation::protection_message_key;
use nrr_platform_api::app_folders::{
    path_programs_once, AppPath, PathOutcome, PathPrograms, ProgramFolders,
};
use nrr_shared::app_path::is_path_value;
use nrr_shared::ipc_payloads::{
    AppPathCoverageRequest, AppPathCoverageResponse, APP_PATH_COVERAGE_FOUND,
    APP_PATH_COVERAGE_INVALID, APP_PATH_COVERAGE_MISSING, APP_PATH_COVERAGE_NOT_A_PATH,
    APP_PATH_COVERAGE_REFUSED, APP_PATH_COVERAGE_UNSUPPORTED,
};
use nrr_shared::preset_parser::without_rule_flags;

/// Why the form refuses a path in another user's profile.
pub const OTHER_USERS_FOLDER_KEY: &str =
    "rules.validation.match-value-invalid.path-in-other-users-profile";

/// The one-off reads behind `rules.app-path-coverage.get` and the check of a
/// submitted book for other users' folders.
pub struct AppPathCoverage {
    folders: Arc<dyn ProgramFolders>,
    applies: bool,
}

impl AppPathCoverage {
    /// `applies`: whether this platform carries rules by path out
    /// (`EnforcementCapabilities::app_path_rules`).
    #[must_use]
    pub fn new(folders: Arc<dyn ProgramFolders>, applies: bool) -> Self {
        Self { folders, applies }
    }

    /// What the rule `request` describes would cover for `owner` now, judged
    /// by the machine's protected places.
    #[must_use]
    pub fn coverage(
        &self,
        request: &AppPathCoverageRequest,
        owner: &str,
    ) -> AppPathCoverageResponse {
        self.coverage_in(request, owner, crate::protected_rules::places())
    }

    fn coverage_in(
        &self,
        request: &AppPathCoverageRequest,
        owner: &str,
        places: &ProtectedPlaces,
    ) -> AppPathCoverageResponse {
        let style = self.folders.path_style();
        let value = without_rule_flags(request.value.trim());
        if !is_path_value(&value, style) {
            let form = if value.contains('*') {
                "name-glob"
            } else {
                "name"
            };
            return answer(form, APP_PATH_COVERAGE_NOT_A_PATH);
        }
        let path = match AppPath::parse(&value, style) {
            Ok(path) => path,
            Err(problem) => return answer(problem.slug(), APP_PATH_COVERAGE_INVALID),
        };
        let form = path.kind().slug();
        if !self.applies {
            return answer(form, APP_PATH_COVERAGE_UNSUPPORTED);
        }
        let effect =
            RuleEffect::from_route_slug(&request.route).unwrap_or(RuleEffect::PrimaryRoute);
        let mut out = answer(form, APP_PATH_COVERAGE_MISSING);
        match protection_verdict(AppTarget::of_path(&path), effect, places) {
            ProtectionVerdict::Refused(reason) => {
                return refused(out, protection_message_key(reason));
            }
            ProtectionVerdict::Warn(reason) => out.warning_key = protection_message_key(reason),
            ProtectionVerdict::Allowed => {}
        }
        let found = path_programs_once(self.folders.as_ref(), &path, owner);
        match found.outcome {
            PathOutcome::OtherUsersFolder => return refused(out, OTHER_USERS_FOLDER_KEY.into()),
            PathOutcome::Unsupported => {
                out.outcome = APP_PATH_COVERAGE_UNSUPPORTED.into();
                return out;
            }
            PathOutcome::Missing | PathOutcome::Found => {}
        }
        // The place the disk revealed, behind links: a junction into a
        // system folder is judged where it leads.
        if let Some(real) = found.place.as_ref() {
            match protection_verdict(AppTarget::of_path(real), effect, places) {
                ProtectionVerdict::Refused(reason) => {
                    return refused(out, protection_message_key(reason));
                }
                ProtectionVerdict::Warn(reason) if out.warning_key.is_empty() => {
                    out.warning_key = protection_message_key(reason);
                }
                ProtectionVerdict::Warn(_) | ProtectionVerdict::Allowed => {}
            }
        }
        let own = found.place.clone().or_else(|| self.for_owner(&path, owner));
        if let Some(own) = own.as_ref() {
            out.place = own.as_str().to_string();
            out.anyone_can_write = self.folders.writable_by_anyone(Path::new(own.place()));
        }
        fill_found(out, found)
    }

    /// `path` as `owner` has it: a profile folder resolved to theirs.
    fn for_owner(&self, path: &AppPath, owner: &str) -> Option<AppPath> {
        if path.profile_folder().is_none() {
            return Some(path.clone());
        }
        let profile = self.folders.owner_profile(owner)?;
        path.for_profile(&profile.to_string_lossy()).ok()
    }

    /// Whether `path`, written as a full path, lies in a profile `principal`
    /// does not own. For the shared baseline every user's profile is someone
    /// else's: it names each user's own folder through a profile folder.
    #[must_use]
    pub fn names_foreign_profile(&self, path: &AppPath, principal: &str) -> bool {
        path.profile_folder().is_none()
            && self
                .folders
                .foreign_profile(Path::new(path.place()), principal)
    }
}

fn answer(form: &str, outcome: &str) -> AppPathCoverageResponse {
    AppPathCoverageResponse {
        form: form.to_string(),
        outcome: outcome.to_string(),
        ..AppPathCoverageResponse::default()
    }
}

fn refused(mut out: AppPathCoverageResponse, key: String) -> AppPathCoverageResponse {
    out.outcome = APP_PATH_COVERAGE_REFUSED.into();
    out.refusal_key = key;
    out
}

fn fill_found(mut out: AppPathCoverageResponse, found: PathPrograms) -> AppPathCoverageResponse {
    if found.outcome == PathOutcome::Found {
        out.outcome = APP_PATH_COVERAGE_FOUND.into();
        out.programs = u32::try_from(found.programs.len()).unwrap_or(u32::MAX);
        out.truncated = found.over_cap;
    }
    out
}

#[cfg(test)]
mod tests;
