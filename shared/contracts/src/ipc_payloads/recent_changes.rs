use super::*;

// ── What the caller changed in their rules lately ────────────────────────────

/// How far back `rules.recent-changes.list` looks, whatever the request asks:
/// the longest period the clients offer.
pub const RECENT_RULE_CHANGES_MAX_LOOKBACK_SECS: i64 = 7 * 86_400;

/// Most entries one answer carries; the rest is reported as `truncated`.
pub const MAX_RECENT_RULE_CHANGES: usize = 500;

/// Most rules a replaced set lists; `count` still says how many it holds.
pub const MAX_RECENT_REPLACED_MEMBERS: usize = 100;

/// Most bytes of rule values and comments one answer carries, so the reply
/// stays well inside one frame whatever the comments hold.
pub const RECENT_RULE_CHANGES_TEXT_BUDGET: usize = 256 * 1024;

/// `rules.recent-changes.list` — the caller's own rule changes since a moment.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RulesRecentChangesRequest {
    /// Unix seconds. The service looks back no further than
    /// [`RECENT_RULE_CHANGES_MAX_LOOKBACK_SECS`].
    #[serde(default)]
    pub since: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RecentRuleChangeKind {
    /// The rule was not in the set at the start of the period.
    Added,
    /// The rule's route, `?` or switch differs from the start of the period.
    Changed,
    /// The rule left the set during the period.
    Deleted,
    /// The whole set was replaced (an import or a rules file taken over).
    Replaced,
}

/// What a changed rule was at the start of the period.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RecentRulePreviousDto {
    /// `"primary"`, `"secondary"` or `"block"`, as in [`RuleRowEntry`].
    pub target_route: String,
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub verify: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RecentRuleChangeDto {
    pub kind: RecentRuleChangeKind,
    /// Unix seconds the revision carrying the change was applied.
    pub at: i64,
    /// The rule as it is now (added, changed) or as it was just before it
    /// went (deleted). Absent for a replaced set. Its `id` names nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<RuleRowEntry>,
    /// A changed rule at the start of the period.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous: Option<RecentRulePreviousDto>,
    /// A deleted rule's type and value are in the set in force now.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub exists_now: bool,
    /// A replaced set: how many rules it holds.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub count: u32,
    /// A replaced set: its rules, at most [`MAX_RECENT_REPLACED_MEMBERS`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<RuleRowEntry>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RulesRecentChangesResponse {
    /// Newest first.
    #[serde(default)]
    pub changes: Vec<RecentRuleChangeDto>,
    /// Set when the stored history begins after the requested moment: what
    /// changed before this cannot be told.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history_starts_at: Option<i64>,
    /// More changed than one answer carries; the oldest are left out.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,
}

fn is_zero_u32(value: &u32) -> bool {
    *value == 0
}
