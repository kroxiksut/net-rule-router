use super::*;

// ── Confirming a rule the protection of system programs refuses ──────────────

/// How long a confirmation lasts. A closed list: no client can ask for a term
/// the confirmation never offered.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OverrideTerm {
    OneHour,
    #[default]
    OneDay,
    OneWeek,
    /// Until the owner takes it back, or a reset does.
    UntilRevoked,
}

impl OverrideTerm {
    /// Every term, in the order the confirmation offers them.
    pub const ALL: [Self; 4] = [
        Self::OneHour,
        Self::OneDay,
        Self::OneWeek,
        Self::UntilRevoked,
    ];

    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::OneHour => "one-hour",
            Self::OneDay => "one-day",
            Self::OneWeek => "one-week",
            Self::UntilRevoked => "until-revoked",
        }
    }

    /// Length of a timed term; `None` for one that waits to be revoked.
    #[must_use]
    pub const fn window_ms(self) -> Option<i64> {
        const HOUR_MS: i64 = 3_600_000;
        match self {
            Self::OneHour => Some(HOUR_MS),
            Self::OneDay => Some(24 * HOUR_MS),
            Self::OneWeek => Some(7 * 24 * HOUR_MS),
            Self::UntilRevoked => None,
        }
    }
}

/// The rule may be confirmed.
pub const RULE_OVERRIDE_READY: &str = "ready";
/// Already confirmed; the grant rides `granted`.
pub const RULE_OVERRIDE_GRANTED: &str = "granted";
/// No rule with this value and route in the caller's applied rules, or one
/// without `+override`: save the rule with the request first.
pub const RULE_OVERRIDE_NOT_REQUESTED: &str = "not-requested";
/// The protection does not refuse the rule: nothing to confirm.
pub const RULE_OVERRIDE_NOT_PROTECTED: &str = "not-protected";
/// The protection refuses it for good (the disk root, our own programs), or
/// the place on disk is protected differently from what the rule names.
pub const RULE_OVERRIDE_NOT_ALLOWED: &str = "not-allowed";
/// The service cannot keep a confirmation it could trust (no signing key).
pub const RULE_OVERRIDE_UNAVAILABLE: &str = "unavailable";

pub const RULE_OVERRIDE_STATUSES: [&str; 6] = [
    RULE_OVERRIDE_READY,
    RULE_OVERRIDE_GRANTED,
    RULE_OVERRIDE_NOT_REQUESTED,
    RULE_OVERRIDE_NOT_PROTECTED,
    RULE_OVERRIDE_NOT_ALLOWED,
    RULE_OVERRIDE_UNAVAILABLE,
];

/// The longest rule value a confirmation request may name, flags included.
pub const RULE_OVERRIDE_MAX_VALUE_BYTES: usize = 4096;

/// `rules.override.preview`: what confirming the caller's rule would let it
/// take.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RuleOverridePreviewRequest {
    /// The application value as the rules table shows it, flags allowed.
    pub value: String,
    /// `secondary` or `block`: what the rule does.
    pub route: String,
}

/// The answer to [`RuleOverridePreviewRequest`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RuleOverridePreviewResponse {
    /// One of [`RULE_OVERRIDE_STATUSES`].
    pub status: String,
    /// Hands this preview to the grant; empty unless `ready`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub token: String,
    /// The value the confirmation is for, as the rule names it (no flags):
    /// what the person types to confirm.
    pub value: String,
    pub route: String,
    /// Why the protection refuses the rule
    /// (`nrr_domain::protected_places::ProtectionReason` slug).
    #[serde(default)]
    pub reason: String,
    /// Programs the rule takes.
    #[serde(default)]
    pub programs: u32,
    #[serde(default)]
    pub programs_over_cap: bool,
    /// Critical processes it takes, as match keys.
    #[serde(default)]
    pub critical_processes: Vec<String>,
    /// Service accounts running what it takes, in stored principal form.
    #[serde(default)]
    pub service_accounts: Vec<String>,
    /// Other users running what it takes.
    #[serde(default)]
    pub other_users: u32,
    /// What stops working (`rules.override.breaks.<slug>`).
    #[serde(default)]
    pub breaks: Vec<String>,
    /// Confirming takes an administrator: it reaches past the caller.
    #[serde(default)]
    pub needs_administrator: bool,
    /// How long `token` stays good, in milliseconds.
    #[serde(default)]
    pub token_ttl_ms: i64,
    /// The standing confirmation, when there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub granted: Option<RuleOverrideDto>,
}

/// `rules.override.grant`: confirm the previewed rule.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RuleOverrideGrantRequest {
    pub token: String,
    /// The rule's value as the person typed it; it must name the same value.
    pub typed_value: String,
    #[serde(default)]
    pub term: OverrideTerm,
}

/// The answer to [`RuleOverrideGrantRequest`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RuleOverrideGrantResponse {
    pub granted: RuleOverrideDto,
}

/// `rules.override.revoke`: take a confirmation back.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RuleOverrideRevokeRequest {
    pub value: String,
    pub route: String,
}

/// The answer to [`RuleOverrideRevokeRequest`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RuleOverrideRevokeResponse {
    /// `false` when there was none to take back.
    pub revoked: bool,
}

/// One standing confirmation, as the rules list marks its rule.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RuleOverrideDto {
    /// The rule's value as the rule names it (no flags).
    pub value: String,
    /// `secondary` or `block`.
    pub route: String,
    pub reason: String,
    /// UTC ms the confirmation ends at; absent until revoked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until_ms: Option<i64>,
    pub granted_at_ms: i64,
}
