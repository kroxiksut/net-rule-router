//! Wire DTOs for the FILE↔SERVICE rules merge preview (`rules.merge-preview`).
//!
//! These mirror the pure merge core in `nrr_domain::merge` but live in
//! `nrr-shared` so both the service handler and the GUI/tray clients share one
//! wire vocabulary. The domain→DTO conversion lives in the service handler
//! (`nrr-shared` deliberately does **not** depend on `nrr-domain`).
//!
//! Slugs are kept byte-identical to the domain slugs (`union` / `file-wins` /
//! `service-wins`, `file` / `service` / `unresolved`, `file-only` /
//! `service-only` / `both`) so the merge-conflict-policy preference, the wire,
//! and `nrr_domain::merge::MergePolicy::slug`/`from_slug` all agree.

use serde::{Deserialize, Serialize};

use crate::rules_json::RuleAction;
use crate::RouteRole;

/// How the merge resolves rules present on both sides but differing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MergePolicyDto {
    /// Keep both sides; flag every both-sides-differ case for a user decision.
    #[default]
    Union,
    /// The linked file wins conflicts.
    FileWins,
    /// The active service revision wins conflicts.
    ServiceWins,
}

impl MergePolicyDto {
    /// Stable slug shared with `nrr_domain::merge::MergePolicy::slug`.
    pub fn slug(self) -> &'static str {
        match self {
            Self::Union => "union",
            Self::FileWins => "file-wins",
            Self::ServiceWins => "service-wins",
        }
    }

    /// Parse a wire/preference slug; unknown input falls back to the safe
    /// [`MergePolicyDto::Union`] default (mirrors the domain parser).
    pub fn from_slug(slug: &str) -> Self {
        match slug {
            "file-wins" => Self::FileWins,
            "service-wins" => Self::ServiceWins,
            _ => Self::Union,
        }
    }
}

/// Which side(s) a merged rule came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MergeOriginDto {
    /// Present only in the linked file.
    FileOnly,
    /// Present only in the service revision.
    ServiceOnly,
    /// Present on both sides (identical, or a resolved conflict).
    Both,
}

/// Which side a conflict was resolved in favour of.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConflictSideDto {
    /// The linked file's version.
    File,
    /// The service revision's version.
    Service,
    /// Not auto-resolved (Union policy) — awaiting a user choice.
    Unresolved,
}

/// One rule in a merge bucket (`file-only` / `service-only`), rendered as
/// type + value + route with a block badge when `action == Block`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct MergedRuleEntryDto {
    /// Display value (host / `*.suffix` / zone / IPv4 / app pattern).
    pub value: String,
    /// Coarse rule-type slug shared with the rules list
    /// (`domain` / `zone` / `exact-ip` / `application`).
    pub type_slug: String,
    /// Route the rule binds to.
    pub route: RouteRole,
    /// Enabled state.
    pub enabled: bool,
    /// Enforcement action (route vs. hard block).
    pub action: RuleAction,
    /// User comment (empty string when none).
    pub comment: String,
    /// Which side(s) the rule came from.
    pub origin: MergeOriginDto,
    /// `true` when this entry came from a both-sides-differ conflict.
    pub was_conflict: bool,
}

/// One side of a conflict.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ConflictRuleDto {
    /// Route this side binds the rule to.
    pub route: RouteRole,
    /// Enabled state on this side.
    pub enabled: bool,
    /// Enforcement action on this side.
    pub action: RuleAction,
    /// Comment on this side.
    pub comment: String,
}

/// A rule present on both sides but with a different route, enabled state,
/// action, or comment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct MergeConflictDto {
    /// Opaque content identity, echoed back with the user's pick.
    pub identity_key: String,
    /// Display value (equal on both sides — the match is the identity).
    pub value: String,
    /// Coarse rule-type slug (see [`MergedRuleEntryDto::type_slug`]).
    pub type_slug: String,
    /// The file-side version.
    pub file: ConflictRuleDto,
    /// The service-side version.
    pub service: ConflictRuleDto,
    /// Which side the merge chose (or `unresolved` under Union).
    pub resolved: ConflictSideDto,
}

/// The full merge-preview result: three buckets, the conflicts, and the
/// provisional/final merged book serialised as canonical rules-json for the
/// review + apply flow.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct MergeResultDto {
    /// Policy the preview ran under.
    pub policy: MergePolicyDto,
    /// `true` when the two books were already identical (nothing to merge).
    pub noop: bool,
    /// Count of conflicts still awaiting a user decision.
    pub unresolved: u32,
    /// Rules present only in the linked file.
    pub file_only: Vec<MergedRuleEntryDto>,
    /// Rules present only in the service revision.
    pub service_only: Vec<MergedRuleEntryDto>,
    /// Both-sides-differ conflicts.
    pub conflicts: Vec<MergeConflictDto>,
    /// The merged book as canonical rules-json (feeds `startRulesReviewFlow`).
    pub merged_rules_json: String,
}

/// A single per-conflict user pick, echoed back on the second preview call.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ConflictResolutionDto {
    /// The conflict's opaque identity key (from [`MergeConflictDto::identity_key`]).
    pub identity_key: String,
    /// The side the user chose.
    pub side: ConflictSideDto,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_slug_matches_domain_vocabulary() {
        assert_eq!(MergePolicyDto::Union.slug(), "union");
        assert_eq!(MergePolicyDto::FileWins.slug(), "file-wins");
        assert_eq!(MergePolicyDto::ServiceWins.slug(), "service-wins");
        assert_eq!(MergePolicyDto::from_slug("nonsense"), MergePolicyDto::Union);
        assert_eq!(MergePolicyDto::default(), MergePolicyDto::Union);
        for p in [
            MergePolicyDto::Union,
            MergePolicyDto::FileWins,
            MergePolicyDto::ServiceWins,
        ] {
            assert_eq!(MergePolicyDto::from_slug(p.slug()), p);
        }
    }

    #[test]
    fn enums_serialise_with_kebab_case_slugs() {
        assert_eq!(
            serde_json::to_string(&MergeOriginDto::FileOnly).unwrap(),
            "\"file-only\""
        );
        assert_eq!(
            serde_json::to_string(&MergeOriginDto::ServiceOnly).unwrap(),
            "\"service-only\""
        );
        assert_eq!(
            serde_json::to_string(&ConflictSideDto::Unresolved).unwrap(),
            "\"unresolved\""
        );
        assert_eq!(
            serde_json::to_string(&MergePolicyDto::ServiceWins).unwrap(),
            "\"service-wins\""
        );
    }

    #[test]
    fn result_dto_round_trips() {
        let dto = MergeResultDto {
            policy: MergePolicyDto::Union,
            noop: false,
            unresolved: 1,
            file_only: vec![MergedRuleEntryDto {
                value: "example.com".into(),
                type_slug: "domain".into(),
                route: RouteRole::Secondary,
                enabled: true,
                action: RuleAction::Route,
                comment: String::new(),
                origin: MergeOriginDto::FileOnly,
                was_conflict: false,
            }],
            service_only: Vec::new(),
            conflicts: vec![MergeConflictDto {
                identity_key: "k".into(),
                value: "1.2.3.4".into(),
                type_slug: "exact-ip".into(),
                file: ConflictRuleDto {
                    route: RouteRole::Secondary,
                    enabled: true,
                    action: RuleAction::Route,
                    comment: String::new(),
                },
                service: ConflictRuleDto {
                    route: RouteRole::Secondary,
                    enabled: true,
                    action: RuleAction::Block,
                    comment: String::new(),
                },
                resolved: ConflictSideDto::Unresolved,
            }],
            merged_rules_json: "{}".into(),
        };
        let json = serde_json::to_string(&dto).unwrap();
        assert!(json.contains("\"file-only\""));
        assert!(json.contains("\"type-slug\""));
        assert!(json.contains("\"merged-rules-json\""));
        let back: MergeResultDto = serde_json::from_str(&json).unwrap();
        assert_eq!(back, dto);
    }
}
