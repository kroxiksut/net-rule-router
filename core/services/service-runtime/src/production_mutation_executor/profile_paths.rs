//! A rule edit naming a folder in another user's profile is refused where the
//! submission lands. One person's rule never decides for another person's
//! programs, and enforcement would leave such a folder unread anyway; the
//! shared baseline names each user's own folder through a profile folder
//! (`%LOCALAPPDATA%`, `~`), never through one user's full path. A rules file
//! read in is not refused whole for such a line: it is kept, and enforcement
//! leaves the folder unread.

use std::collections::HashSet;

use nrr_domain::canonical::{CanonicalAppPattern, CanonicalRuleBook};
use nrr_platform_api::app_folders::AppPath;

use super::*;

/// The GUI's `errors.<code>` for a rule naming another user's folder.
pub const PATH_IN_OTHER_USERS_PROFILE_CODE: &str = "path-in-other-users-profile";

/// Every rule by path in `book`, with the rule's id.
fn app_paths(book: &CanonicalRuleBook) -> impl Iterator<Item = (&str, &AppPath)> {
    book.primary
        .rules()
        .iter()
        .chain(book.secondary.rules())
        .filter_map(|rule| match &rule.app_match.as_ref()?.pattern {
            CanonicalAppPattern::Path(path) => Some((rule.id.as_str(), path.as_ref())),
            CanonicalAppPattern::Exact(_) | CanonicalAppPattern::Glob(_) => None,
        })
}

impl ProductionMutationExecutor {
    /// The first rule `rules_json` newly holds that names a folder in a
    /// profile `principal` does not own. A path the book in force already
    /// holds is spared: a book written before the check must stay editable.
    pub(super) fn foreign_profile_refusal(
        &self,
        rules_json: &str,
        principal: &str,
    ) -> Option<OperationError> {
        let coverage = self.path_coverage.as_ref()?;
        let incoming = decode_rule_book(rules_json, self.host_platform)?;
        let carried = self
            .coordinator
            .rules_json_in_force_for(principal)
            .and_then(|json| decode_rule_book(&json, self.host_platform));
        let held: HashSet<&str> = carried
            .iter()
            .flat_map(app_paths)
            .map(|(_, path)| path.as_str())
            .collect();
        let (rule_id, path) = app_paths(&incoming).find(|(_, path)| {
            !held.contains(path.as_str()) && coverage.names_foreign_profile(path, principal)
        })?;
        Some(OperationError {
            args: std::collections::BTreeMap::from([
                ("rule".to_owned(), rule_id.to_owned()),
                ("path".to_owned(), path.as_str().to_owned()),
            ]),
            code: PATH_IN_OTHER_USERS_PROFILE_CODE.into(),
            message: format!(
                "rule {rule_id}: {} lies in another user's profile; start the path from a profile folder",
                path.as_str()
            ),
        })
    }
}
