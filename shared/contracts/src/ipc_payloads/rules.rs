use super::*;

// ── RulesList ────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RulesRouteFilter {
    Primary,
    Secondary,
    #[default]
    All,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RulesListRequest {
    #[serde(default)]
    pub route: RulesRouteFilter,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RulesListResponse {
    pub rows: Vec<RuleRowEntry>,
    /// Stable rule-type slugs supported by the current revision
    /// (`"zone"`, `"domain"`, `"exact-ip"`, `"application"`).
    pub supported_rule_types: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_revision_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RuleRowEntry {
    pub id: String,
    pub rule_type: String,
    pub match_value: String,
    /// Display route slug: `"primary"`, `"secondary"`, or `"block"`. The
    /// producer emits `"block"` for a `RuleAction::Block` rule regardless of
    /// which bucket it lives in; the GUI maps it back to the «Блокировать»
    /// label and its own bucket-plus-`action` wire form on save.
    pub target_route: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    pub enabled: bool,
    /// `"ok"` / `"warning"` / `"error"` — derived from
    /// `rule_value_validation::validate_rule_value`.
    pub validation_status: String,
    /// What the last main-link check found for this rule's address:
    /// `"answered"`, `"silent"`, or absent when it was never checked.
    ///
    /// A FACT about reachability, never advice: a site can answer on the main
    /// link and still refuse to serve the user there, which is the very reason
    /// the rule exists. The GUI words it accordingly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub main_route: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validation_message_key: Option<String>,
    /// Read-only annotation: when the OS `hosts` file pins this rule's
    /// hostname to an address, the service fills this so the GUI can show
    /// a "Blocked in hosts" / "Redirected by system" badge. The `hosts`
    /// file is applied by the resolver BEFORE traffic reaches NRR, so NRR
    /// cannot override it — this is purely informational. Additive +
    /// optional: older peers and non-hostname rules simply omit it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hosts_override: Option<HostsOverrideDto>,
    /// Provenance of a rule the application authored on the user's behalf,
    /// carried straight through from
    /// [`RuleDto::origin`](crate::rules_json::RuleDto::origin) so the rules
    /// table can mark the row and name the site it belongs to. `None` — the
    /// overwhelmingly common case — means the user typed the rule. Additive
    /// and optional: a peer that predates the field simply omits it, and no
    /// row loses its identity for the lack of it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<RuleOrigin>,
    /// Read-only annotation for an application rule: the addresses it is
    /// currently holding on the additional link, learned from watching the
    /// application.
    ///
    /// It is shown because the holding is MACHINE-WIDE — a route cannot be
    /// scoped to a process, so every one of these addresses travels the
    /// additional link for every program on the computer. Without the list a
    /// user has no way to connect "this site went strange" to the application
    /// rule that took it. Absent for rules that are not application rules, and
    /// for those holding nothing.
    ///
    /// Capped at [`MAX_PINNED_DESTINATIONS_PER_ROW`]; `pinned_destinations_total`
    /// carries the real count when the list was cut.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pinned_destinations: Option<Vec<String>>,
    /// How many addresses the rule actually holds, when that is more than the
    /// list above carries.
    ///
    /// The GUI renders a sample and a COUNT, and the count has to be the true
    /// one — a user reading "12 addresses" from a truncated list would be told
    /// something false about what their machine is doing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pinned_destinations_total: Option<usize>,
}

/// Ceiling on the addresses one rule row carries on the wire.
///
/// `rules.list` is deliberately NOT paginated: the window needs the whole set
/// at once — it renders the table and hashes the set for drift detection — and
/// the IPC client runs one request at a time, so splitting the read into pages
/// would trade a bounded response for a chain of round-trips on the lane every
/// other call is queued behind. What was actually unbounded is this per-row
/// list of observed addresses, and that is what gets a ceiling. Above the 20 a
/// row ever displays, so nothing visible is lost.
pub const MAX_PINNED_DESTINATIONS_PER_ROW: usize = 32;

/// Read-only OS `hosts`-file override annotation for one rule row.
///
/// Populated only when a rule's exact hostname matches an entry in the OS
/// `hosts` file. `blocking` is `true` when the pinned IP is loopback
/// (`127.0.0.0/8`) or unspecified (`0.0.0.0`) — the ad-block "black-hole"
/// convention; `false` for a real redirect target.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct HostsOverrideDto {
    /// The IPv4 address the `hosts` file maps the hostname to, as a string
    /// (e.g. `"127.0.0.1"`, `"203.0.113.7"`).
    pub ip: String,
    /// `true` → the hostname is blocked (loopback/unspecified); `false` →
    /// redirected to the real `ip`.
    pub blocking: bool,
}

// ── PresetImport ─────────────────────────────────────────────────────────────

/// Wire payload schema for `MutationKind::PresetImport`.
///
/// Carries the bytes of one or both rules-file presets plus the host-side
/// settings needed to canonicalize them. Service-side deserialization +
/// validation lives in `nrr-service-runtime::production_mutation_executor`.
///
/// # Single-route vs both-routes
///
/// - **Single-route import**: exactly one of `primary_bytes_b64` /
///   `secondary_bytes_b64` is `Some`. The `route` field disambiguates if
///   both could have been intended (and the other route's rules in the
///   resulting revision are carried over from the current active config).
/// - **Both-routes import**: both `*_bytes_b64` fields are `Some`. One
///   revision covers both routes. `route` is ignored.
/// - At least one of the two byte fields must be `Some`; an empty payload
///   is rejected with `payload-invalid`.
///
/// # Byte encoding
///
/// File bytes are base64-encoded (RFC 4648 standard alphabet, padding
/// required). The service decodes them with [`base64::engine::general_purpose::STANDARD`]
/// and then runs them through `validate_preset_bytes` — which enforces
/// the 1 MiB cap and UTF-8 encoding before parse.
///
/// # Idempotency
///
/// Optional `content_hash_*` fields let the client pre-compute the SHA-256
/// of the file bytes (over canonical bytes) so the executor can skip the
/// activation when the hash matches the current active revision's hash
/// for that route. This is a fast path for auto-open-on-launch where the
/// file hasn't changed; the executor still falls back to a full
/// re-canonicalize-and-compare when the hash is `None`.
///
/// # Correlation
///
/// `correlation_id` is the client-issued identifier surfaced in
/// `StatusUpdateEvent::MutationProgress` push events. When absent, the
/// service generates one.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct PresetImportPayload {
    /// Target route for single-route import. Required when exactly one of
    /// `primary_bytes_b64` / `secondary_bytes_b64` is `Some` **and** the
    /// caller wants to be explicit (omitting it is allowed if the present
    /// byte field unambiguously names the target). Ignored when both byte
    /// fields are `Some`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<RouteRole>,

    /// Base64-encoded UTF-8 bytes for the primary route's rules file.
    /// When `Some`, primary's rules are replaced by these bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_bytes_b64: Option<String>,

    /// Base64-encoded UTF-8 bytes for the secondary route's rules file.
    /// When `Some`, secondary's rules are replaced by these bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secondary_bytes_b64: Option<String>,

    /// Mirrors `UiPreferences::include_child_processes`. Threads through
    /// to `canonicalize_preset_rules` so application rules are matched
    /// against child processes consistently with GUI-edited rules.
    pub include_child_processes: bool,

    /// When `true`, rules that are *disabled* in the source preset
    /// (commented recognizable lines, e.g. application rules left off
    /// pending per-process routing) are dropped during import instead of
    /// stored as toggled-off rules. Backs the GUI "import only active
    /// rules" toggle. Defaults to `false` (import everything, including
    /// disabled) for back-compat when an older client omits the field.
    #[serde(default)]
    pub import_only_active: bool,

    /// Optional SHA-256 hex of the primary file's canonical bytes,
    /// computed client-side. Enables idempotent skip when it matches the
    /// active revision's hash for primary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_hash_primary: Option<String>,

    /// Optional SHA-256 hex of the secondary file's canonical bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_hash_secondary: Option<String>,

    /// Optional GUI-issued correlation ID. Surfaced verbatim in
    /// `MutationProgress` push events for end-to-end tracing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
}

/// Decoded import target after [`PresetImportPayload::target`] validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PresetImportTarget {
    /// Only one of the two byte fields is populated. The variant carries
    /// the route the bytes belong to.
    SingleRoute(RouteRole),
    /// Both byte fields are populated. The resulting revision replaces
    /// rules for both routes in one atomic submit.
    BothRoutes,
}

/// Why a [`PresetImportPayload`] failed structural validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PresetImportPayloadError {
    /// Neither `primary_bytes_b64` nor `secondary_bytes_b64` is `Some` —
    /// nothing to import.
    NoBytesSupplied,
    /// Exactly one of the byte fields is `Some`, the caller specified a
    /// `route`, and the `route` does not match the populated byte field.
    /// (e.g. `route = Secondary` but only `primary_bytes_b64` is set.)
    RouteMismatch,
}

impl PresetImportPayload {
    /// Resolves the import target from the byte-field combination,
    /// cross-checking the explicit `route` hint when supplied.
    pub fn target(&self) -> Result<PresetImportTarget, PresetImportPayloadError> {
        match (
            self.primary_bytes_b64.as_ref(),
            self.secondary_bytes_b64.as_ref(),
        ) {
            (None, None) => Err(PresetImportPayloadError::NoBytesSupplied),
            (Some(_), Some(_)) => Ok(PresetImportTarget::BothRoutes),
            (Some(_), None) => match self.route {
                None | Some(RouteRole::Primary) => {
                    Ok(PresetImportTarget::SingleRoute(RouteRole::Primary))
                }
                Some(RouteRole::Secondary) => Err(PresetImportPayloadError::RouteMismatch),
            },
            (None, Some(_)) => match self.route {
                None | Some(RouteRole::Secondary) => {
                    Ok(PresetImportTarget::SingleRoute(RouteRole::Secondary))
                }
                Some(RouteRole::Primary) => Err(PresetImportPayloadError::RouteMismatch),
            },
        }
    }
}

// ── PresetExportGet ──────────────────────────────────────────────────────────

/// Read-only export of the active revision's rules for
/// one route as a canonical rules-file txt blob.
///
/// The service:
/// 1. Loads the active revision via `RevisionsRepository::get_active`.
/// 2. Decodes the relevant route's `rules_json` via
///    [`crate::rules_json::CanonicalRuleSet::from_canonical_string`].
/// 3. Maps the canonical rule set back to a `RulesFileParsed`.
/// 4. Serialises through `nrr_domain::rules_file::write_rules_file`,
///    optionally prepending preset metadata.
/// 5. Wraps the resulting UTF-8 bytes in base64 (standard alphabet,
///    padded) for wire framing.
///
/// Extended sections from the original import are **not** preserved in this
/// revision (the canonical store drops them). Round-trip preservation is a
/// follow-up.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct PresetExportGetRequest {
    /// Which route's rules to export.
    pub route: RouteRole,
    /// When `true`, prepend `# NetRuleRouter preset — version 1` and any
    /// available preset metadata headers (name/description/author/preset-version).
    /// When `false`, the output starts directly with the first section.
    #[serde(default)]
    pub include_metadata: bool,
    /// Sections this build does not parse (`--- Linux`, `--- CIDR`, ...),
    /// keyed by section name, valued by the raw body the caller captured when
    /// the file was imported.
    ///
    /// The service cannot supply these itself: the canonical revision store
    /// keeps only rules it understands, so a plain re-export drops every
    /// foreign-OS and forward-compatibility block the user's file carried.
    /// The caller that holds them (the GUI's own sidecar) passes them back
    /// here and gets a lossless file. Absent means "the caller has none",
    /// which is the honest default — omitting it can only lose what the
    /// service never had.
    #[serde(default)]
    pub passthrough_sections: std::collections::BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct PresetExportGetResponse {
    /// Base64-encoded canonical txt bytes of the rules file for the
    /// requested route. UTF-8 inside the base64 wrapper.
    pub file_bytes_b64: String,
    /// SHA-256 hex of the unwrapped UTF-8 bytes. The GUI uses this as
    /// `last_file_synced_hash_<role>` for divergence detection on
    /// subsequent close-window events.
    pub content_hash: String,
}

// ── SettingsExportFull ───────────────────────────────────────────────────────

/// Read-only export of the full user settings as a YAML
/// blob conforming to docs/en/rules-file-format.md Settings Export Format
///
/// Includes: adapter bindings (system ID, user label, confirmation
/// status), rules file paths (paths only — the on-disk content lives in
/// the txt files separately), behavior settings (route mode).
///
/// Excludes: UI preferences (theme, language, accessibility, route
/// display labels) — device-specific, set again on each device;
/// internal revision metadata; runtime probe state.
///
/// # Client-supplied fields
///
/// The service is the source of truth for adapter bindings and route
/// behavior mode, but NOT for the user's chosen rules-file paths on
/// disk (those live in `UiPreferences::last_saved_path_<role>` —
/// device-local). The caller forwards the paths in this request; the
/// service splices them into the YAML at the `rules_files:` block.
/// When omitted, the corresponding YAML field is left empty.
///
/// # Migration note
///
/// `file_change_behavior` and `include_child_processes` (per docs/en/rules-file-format.md Settings Export Format) are GUI preferences that are migrating to per-SID service
/// storage but are not yet wired. This export emits the YAML without
/// those keys; they'll be added as a follow-up once that storage settles.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct SettingsExportFullRequest {
    /// User-chosen path of the primary rules file (from
    /// `UiPreferences::last_saved_path_primary`). Empty/omitted ⇒ no
    /// path written to YAML.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules_file_path_primary: Option<String>,
    /// Same for secondary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules_file_path_secondary: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct SettingsExportFullResponse {
    /// Base64-encoded UTF-8 YAML bytes. Top-level key is
    /// `nrr_settings_export` per docs/en/rules-file-format.md Settings Export Format The GUI writes these
    /// to the user-chosen path via `Qt.labs.platform.FileDialog::Save`.
    pub yaml_bytes_b64: String,
    /// SHA-256 hex of the unwrapped UTF-8 YAML bytes. Reserved for
    /// future "save back" symmetry with preset exports; not used yet,
    /// but plumbed now so a later round doesn't need a wire bump.
    pub content_hash: String,
}

// ── RulesMergePreview ─────────────────────────────────────────────────────────

/// Request for the two-way merge preview op
/// (`rules.merge-preview`). The service reconciles the caller's linked
/// rules-file *text* against its OWN active revision (resolved per-SID with
/// read-through to the shared baseline, like `rules.list`), so the request
/// carries only the file text, the conflict policy, and any per-conflict
/// resolutions the user has picked. Called twice: first with an empty
/// `resolutions` list (buckets + unresolved conflicts under Union), then again
/// with the picks (final merged rules-json).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct MergePreviewRequest {
    /// Canonical rules-file text of the primary bound file. Parsed and
    /// canonicalised by the domain parser (NOT the raw preset parser) so its
    /// rules pair with the already-canonical service revision by identity.
    #[serde(default)]
    pub primary_text: String,
    /// Canonical rules-file text of the secondary bound file.
    #[serde(default)]
    pub secondary_text: String,
    /// Conflict-resolution policy. Defaults to
    /// [`crate::merge_dto::MergePolicyDto::Union`].
    #[serde(default)]
    pub policy: crate::merge_dto::MergePolicyDto,
    /// Per-conflict user picks. Empty on the first (preview) call.
    #[serde(default)]
    pub resolutions: Vec<crate::merge_dto::ConflictResolutionDto>,
    /// Identity keys of matches named in BOTH route sets of one book where the
    /// user wants the ADDITIONAL route's copy kept instead of the primary one.
    /// The other half of the same dialog's answers, replayed with them.
    #[serde(default)]
    pub keep_secondary: Vec<String>,
    /// The current global "apply rules to child processes" setting, applied
    /// uniformly to app rules during file canonicalisation (must match the
    /// value used at import time so identity keys pair).
    #[serde(default)]
    pub include_child_processes: bool,
}

/// Response for `rules.merge-preview`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct MergePreviewResponse {
    /// The merge outcome: three buckets, the conflicts, and the merged book
    /// serialised as canonical rules-json for `startRulesReviewFlow`.
    pub result: crate::merge_dto::MergeResultDto,
}

// ── MutationSubmit ───────────────────────────────────────────────────────────

/// Stable kind tag. The wire layer doesn't validate the per-kind
/// payload schema — that's the responsibility of the
/// `MutationExecutor` impl in `nrr-service-runtime`, which owns the
/// kind-specific validation and storage.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MutationKind {
    RulesUpdate,
    RouteBindingsUpdate,
    /// Import a preset txt file (one route or both). Payload
    /// schema: [`PresetImportPayload`].
    PresetImport,
    /// Deprecated — use the read-only IPC op
    /// `PresetExportGet` instead. The mutation-submit variant is wire-stable
    /// but unused; new clients must not send it.
    #[deprecated(
        since = "0.1.0",
        note = "use IpcOperationName::PresetExportGet (read-only) instead; \
                this variant is wire-stable for backwards compatibility but \
                handlers return `not-implemented`"
    )]
    PresetExport,
    /// Deprecated — use the read-only IPC op
    /// `SettingsExportFull` instead. The mutation-submit variant is
    /// wire-stable but unused.
    #[deprecated(
        since = "0.1.0",
        note = "use IpcOperationName::SettingsExportFull (read-only) instead; \
                this variant is wire-stable for backwards compatibility but \
                handlers return `not-implemented`"
    )]
    SettingsExport,
    /// Acknowledge a security alert. Wire payload schema:
    /// `{alert-id: string, reason?: string}`. Acknowledgement creates a
    /// new audit event and updates the alert state to `Acknowledged`.
    SecurityAlertAck,
    /// Resolve a security alert. Wire payload schema:
    /// `{alert-id: string, reason?: string}`. Resolution is the terminal
    /// state and creates a new audit event.
    SecurityAlertResolve,
    /// Discard the caller principal's own per-SID rule
    /// divergence and fall back to the admin baseline (read-through
    /// resumes). Wire payload schema: `{correlation-id?: string}` — reset
    /// carries no content. Routed as a `user-scoped-mutation` (the user
    /// resets *its own* rules; non-elevated). The server derives the
    /// target principal from the caller SID, so a reset can only ever
    /// clear the caller's own partition, never the baseline.
    RulesResetToBaseline,
}

impl MutationKind {
    /// Whether this kind changes which traffic goes where — i.e. whether the
    /// administrative rules lock applies to it.
    ///
    /// Declared once, next to the enum, so a new variant is decided here
    /// rather than being silently omitted by whichever gate happens to list
    /// kinds. Security-alert acknowledgement and the deprecated export kinds
    /// are not rule changes: a locked-down user must still be able to clear an
    /// alert banner, and refusing that would only teach them to ignore it.
    #[allow(deprecated)] // the export variants stay wire-stable
    pub fn changes_rules(self) -> bool {
        match self {
            Self::RulesUpdate
            | Self::PresetImport
            | Self::RulesResetToBaseline
            | Self::RouteBindingsUpdate => true,
            Self::PresetExport
            | Self::SettingsExport
            | Self::SecurityAlertAck
            | Self::SecurityAlertResolve => false,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct MutationSubmitRequest {
    pub mutation_kind: MutationKind,
    pub payload: serde_json::Value,
    /// `true` ⇒ compute review summary, return a confirmation token,
    /// don't persist anything. `false` ⇒ resolve the
    /// envelope-level `confirmation_token` against the token store,
    /// execute the mutation, return an `operation_id`.
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReviewRiskLevel {
    Low,
    Medium,
    High,
    /// Reserved for catastrophic configurations
    /// (lock-out scenarios). No production scoring path emits this
    /// today; the level exists so the wire contract is stable when
    /// future binding-aware detection lands.
    Critical,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ReviewSummaryResponse {
    pub diff_summary: String,
    pub provenance: String,
    pub risk_level: ReviewRiskLevel,
    pub requires_review: bool,
    pub changed_fields: Vec<String>,
    /// Structured risk signals the codegen surfaced
    /// for this candidate. Each signal carries a `kind` discriminator
    /// (kebab-case) and zero or more typed payload fields. Emitted in
    /// the order `score_candidate` produces them so the review UI can
    /// render them as a deterministic, sorted list. Empty vector when
    /// `risk_level == Low` (no signals contributed).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub risk_signals: Vec<RiskSignalDto>,
    /// Per-rule diff buckets projected from the
    /// domain `ReviewSummary`. Rendered in the GUI's
    /// `ReviewDiffDialog` as three columns: Added | Removed |
    /// Modified+Retargeted. Each `RuleSummaryEntryDto` carries a
    /// stable `id`, a pre-formatted `display` string, and the
    /// `route` slug (`"primary"` / `"secondary"`).
    ///
    /// All four vectors are sorted deterministically (Added →
    /// Removed → Modified → Retargeted, lexicographic by id within
    /// each bucket) so two equal inputs always produce the same
    /// wire bytes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules_added: Vec<RuleSummaryEntryDto>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules_removed: Vec<RuleSummaryEntryDto>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules_modified: Vec<RuleSummaryEntryDto>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules_retargeted: Vec<RuleSummaryEntryDto>,
    /// unsupported sections preserved verbatim from the
    /// imported preset file. Each entry names a section (e.g. `CIDR`,
    /// `Ports`) that the Free edition parses but does not apply, plus
    /// the number of entries it carries. The GUI renders them in the
    /// review diff with a "not applied" badge so the user knows the file
    /// contains unsupported rules being preserved unchanged.
    ///
    /// Currently always empty — the active revision storage drops
    /// unknown sections. The wire field is plumbed now so a future
    /// schema-bump that adds `unknown_sections_json` to the `revisions`
    /// table requires only server-side population — the GUI is ready.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extended_sections: Vec<ExtendedSectionSummaryDto>,
    /// Rules the candidate names in BOTH route sets with both copies enabled.
    ///
    /// Not an error and not resolved server-side: both copies claim the same
    /// traffic for different routes, and only the user knows which they meant.
    /// Empty (and omitted on the wire) when there is nothing to ask about.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cross_set_duplicates: Vec<CrossSetDuplicateDto>,
}

/// One rule written into both route sets, both copies enabled.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CrossSetDuplicateDto {
    /// Content identity of the pair, echoed back by the merge dialog to say
    /// which copy should stay enabled. Defaulted rather than required so a
    /// window built before this field still parses the payload.
    #[serde(default)]
    pub identity_key: String,
    pub primary_rule_id: String,
    pub secondary_rule_id: String,
    /// What both copies match, as the user wrote it — what a person recognises
    /// on screen, unlike the two ids.
    pub match_summary: String,
}

/// One unsupported section preserved from the imported
/// preset file. See [`ReviewSummaryResponse::extended_sections`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ExtendedSectionSummaryDto {
    /// Raw section name as it appeared in the file, e.g. `"CIDR"`,
    /// `"Ports"`. Not localized — readers display it verbatim.
    pub name: String,
    /// Number of rule entries (active + disabled) in this section.
    /// Displayed as "<name>: N rules preserved as-is (unsupported feature)".
    pub preserved_count: u32,
}

/// Wire-form of `nrr_domain::review::RuleSummaryEntry`.
///
/// One row in the review diff. `display` is pre-formatted server-
/// side via `nrr_domain::review::RuleSummary` (e.g.
/// `"api.example.com"` for ExactFqdn, `"*.example.com"` for
/// SuffixDomain, `"chrome.exe (app)"` for application rules, with
/// the `(from → to)` suffix for retargets). The GUI renders the
/// string as-is — locale-agnostic.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RuleSummaryEntryDto {
    /// Stable rule id (e.g. `"r-001"`).
    pub id: String,
    /// Human-readable display for the review UI.
    pub display: String,
    /// `"primary"` or `"secondary"`. For retargeted rules: the
    /// destination route.
    pub route: String,
    /// Whether the rule takes part in routing. A disabled rule is a
    /// real diff entry (it is stored and shipped to the service) but
    /// enforces nothing, so the review UI marks it instead of listing
    /// it as an ordinary change.
    ///
    /// Additive on the wire: an omitted field reads as `true` and an
    /// enabled entry serialises exactly as before this field existed,
    /// so a peer on either side of the upgrade sees unchanged bytes
    /// for the common case.
    #[serde(
        default = "rule_summary_enabled_default",
        skip_serializing_if = "rule_summary_enabled_is_default"
    )]
    pub enabled: bool,
}

/// Wire default for [`RuleSummaryEntryDto::enabled`] — a peer that
/// predates the field only ever reported rules it would enforce.
fn rule_summary_enabled_default() -> bool {
    true
}

/// Keeps the default out of the serialised form (see the field docs).
fn rule_summary_enabled_is_default(enabled: &bool) -> bool {
    *enabled == rule_summary_enabled_default()
}

/// Wire-form mirror of `nrr_domain::risk::RiskSignal`.
///
/// Tagged enum with kebab-case `kind` discriminator: `broad-suffix-scope`,
/// `moderate-suffix-scope`, `default-behavior-changed`,
/// `mass-change-count`, `secondary-reroute`,
/// `unstable-interface-binding`, `unknown-source`,
/// `linked-suspicious-delta`, `rule-set-emptied`, `high-removal-ratio`,
/// `overlapping-rules`, `fail-closed-activation`.
///
/// Field names use kebab-case at the JSON layer. Payloads carry the
/// minimum metadata the GUI needs to render a localized message
/// (label / count / apex / prev_total / removed_pct).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
// `rename_all_fields = "kebab-case"` is essential: the QML reads
// e.g. `signal["rule-count"]`, but without this attribute the
// serializer would keep `rule_count` (snake_case) on the wire and
// the GUI's substitution `{rule-count}` → value silently no-ops.
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "kebab-case"
)]
pub enum RiskSignalDto {
    BroadSuffixScope {
        label: String,
    },
    ModerateSuffixScope {
        label: String,
    },
    DefaultBehaviorChanged,
    MassChangeCount {
        count: u32,
    },
    SecondaryReroute {
        rule_count: u32,
    },
    UnstableInterfaceBinding,
    UnknownSource,
    LinkedSuspiciousDelta,
    /// Previous active revision had `prev_total`
    /// rules and the candidate has zero.
    RuleSetEmptied {
        prev_total: u32,
    },
    /// `removed_pct` % of the previous revision's
    /// rules are being removed.
    HighRemovalRatio {
        removed_pct: u8,
    },
    /// `apex` has both an `ExactFqdn` rule and a
    /// `SuffixDomain` rule in the candidate.
    OverlappingRules {
        apex: String,
    },
    /// `behavior_mode` is transitioning to
    /// `StrictSecondaryFailClosed`.
    FailClosedActivation,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct MutationDryRunResponse {
    pub review_summary: ReviewSummaryResponse,
    pub confirmation_token: String,
    pub review_risk_level: ReviewRiskLevel,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct MutationConfirmResponse {
    pub operation_id: String,
}
