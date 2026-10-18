use super::*;

// ── Connection history ───────────────────────────────────────────────────────

/// The longest program filter a `conn-history.list` request may carry: a long
/// path, not a page of text.
pub const CONN_HISTORY_MAX_PROGRAM_FILTER: usize = 1024;

/// The verdicts a `conn-history.list` request may filter by.
pub const CONN_HISTORY_VERDICTS: [&str; 3] = ["permit", "block", "unknown"];

/// `conn-history.list` — the caller's connections over a period, one row per
/// program and destination with the attempts added up.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ConnHistoryListRequest {
    /// Unix ms; `0` reads from the oldest kept hour.
    #[serde(default)]
    pub from_unix_ms: i64,
    /// Unix ms; absent reads up to now.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_unix_ms: Option<i64>,
    /// Part of the program path, case-insensitive. At most
    /// [`CONN_HISTORY_MAX_PROGRAM_FILTER`] bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub program: Option<String>,
    /// One of [`CONN_HISTORY_VERDICTS`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verdict: Option<String>,
    #[serde(default)]
    pub pagination: PaginationParams,
}

/// One program's connections to one destination over the period.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ConnHistoryEntryDto {
    /// Executable name (e.g. `browser.exe`), or `?` when unknown.
    pub process: String,
    /// Full executable path, or empty when unknown.
    #[serde(default)]
    pub process_path: String,
    /// The name the address was answered for, or empty.
    #[serde(default)]
    pub host: String,
    pub remote_ip: String,
    /// Egress-role slug, as the trace's `egress_role`.
    pub route: String,
    /// Verdict slug, as the trace's `verdict`.
    pub verdict: String,
    /// `netrulerouter`, `other` or empty, as the trace's `blocked_by`.
    #[serde(default)]
    pub blocked_by: String,
    /// Block-reason slug of the latest block, or empty.
    #[serde(default)]
    pub block_reason: String,
    pub first_seen_ms: i64,
    pub last_seen_ms: i64,
    pub attempts: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ConnHistoryListResponse {
    pub page: PageResult<ConnHistoryEntryDto>,
    /// Whether the history is kept for the caller.
    pub enabled: bool,
    /// Days the caller's history is kept.
    pub retention_days: u32,
    /// The longest period the caller may choose.
    pub max_retention_days: u32,
    /// Whether the history store is open; `false` means "cannot keep a
    /// history right now", not "nothing happened".
    pub available: bool,
    /// Entries removed to keep the history within its size limit, so the
    /// period reads shorter than chosen. Nonzero means the GUI must say so.
    #[serde(default)]
    pub removed: u64,
    /// Connections not recorded because they came faster than the history
    /// could take them.
    #[serde(default)]
    pub skipped: u64,
}

/// `conn-history.clear` — erase the caller's own history.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ConnHistoryClearRequest {}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ConnHistoryClearResponse {
    /// Entries erased.
    pub erased: u64,
}

/// `conn-history.settings.set` — the caller's own choices. An absent field
/// keeps its current value.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ConnHistorySettingsSetRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// `1..=max-retention-days`; anything else is refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention_days: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ConnHistorySettingsSetResponse {
    pub enabled: bool,
    pub retention_days: u32,
}
