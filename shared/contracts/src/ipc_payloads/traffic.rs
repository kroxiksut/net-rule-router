use super::*;

// ── Traffic counter ───────────────────────────────────────────────────────

/// One per-adapter, per-role traffic total (bytes) on the wire.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TrafficRowDto {
    pub adapter_key: String,
    pub display_name: String,
    /// `TrafficCategory` slug — `primary` / `secondary` / `loopback` / `virtual`.
    pub role: String,
    pub in_bytes: u64,
    pub out_bytes: u64,
    /// Last observed local IPv4 address behind this adapter, from a
    /// user-requested external-IP probe (`interfaces.refresh`). Absent when
    /// no probe has resolved one for this adapter yet. Defaulted so an older
    /// service/GUI pair still parses the payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_ip: Option<String>,
    /// Last observed external (internet-facing) IPv4 address behind this
    /// adapter, from the same probe.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_ip: Option<String>,
    /// Epoch-ms timestamp of the observation above.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_ip_observed_at_ms: Option<i64>,
}

/// Service-global traffic-statistics settings on the wire.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TrafficStatsSettingsDto {
    pub enabled: bool,
    pub count_loopback: bool,
    pub count_virtual: bool,
    pub retention_days: u32,
}

/// `traffic-stats.get` request — the day for "today" totals plus an optional
/// inclusive CSV export range (epoch-days, computed by the client in local time).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TrafficStatsGetRequest {
    pub day: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub export_from_day: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub export_to_day: Option<i64>,
    /// Byte-count unit slug for the exported received/sent columns — `bytes`
    /// (default) / `kb` / `mb` / `gb`. Absent or unrecognised exports raw
    /// bytes, so an export is never silently mislabelled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub export_unit: Option<String>,
}

/// `traffic-stats.get` response — today + session totals, current settings, and
/// an optional CSV blob (present iff both export bounds were supplied).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TrafficStatsGetResponse {
    pub today: Vec<TrafficRowDto>,
    pub session: Vec<TrafficRowDto>,
    /// All-time totals per adapter+role, summed over every retained day
    /// (bounded by the retention sweep). Defaulted so an older service reads
    /// as "no aggregate available" rather than failing to parse.
    #[serde(default)]
    pub all_time: Vec<TrafficRowDto>,
    /// Whether an additional-adapter session is live right now. `false` means
    /// `session` is the frozen snapshot of the last session (empty when no
    /// session happened since service start). Defaulted so an older service
    /// reads as "no live session" rather than failing to parse.
    #[serde(default)]
    pub session_active: bool,
    pub settings: TrafficStatsSettingsDto,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub csv: Option<String>,
    /// The pending merge question, when there is one. Rides on the read the
    /// traffic screen already makes: the question is about two of the rows on
    /// that screen, and that is the only place the user has the context to
    /// answer it. Defaulted, so an older window simply never sees it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history_merge: Option<TrafficHistoryMergeDto>,
}

/// `traffic-stats.set` request — the new service-global settings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TrafficStatsSetRequest {
    pub settings: TrafficStatsSettingsDto,
}

/// The one-time question "did this connection's history continue as that one's?".
///
/// Present only when the service has evidence for it: one key stopped being
/// seen, another appeared in its place, and the two names share a word that
/// means something. Absent is the normal state — the GUI shows nothing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TrafficHistoryMergeDto {
    /// Ledger key that went quiet — the history that would be continued.
    pub old_key: String,
    /// Name to show for it. The keys are identity, not something to read out.
    pub old_name: String,
    /// Ledger key that appeared.
    pub new_key: String,
    pub new_name: String,
    /// The word both names share, so the question can say why it is being asked
    /// instead of presenting a bare pair.
    pub shared_token: String,
}

/// `traffic-stats.history-merge.set` — the user's answer.
///
/// `merged: false` is an answer, not a dismissal: the pair is recorded as
/// decided and never offered again.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TrafficHistoryMergeSetRequest {
    pub old_key: String,
    pub new_key: String,
    pub merged: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TrafficHistoryMergeSetResponse {
    /// Echoed so the window can confirm which pair the service recorded.
    pub old_key: String,
    pub new_key: String,
    pub merged: bool,
}
