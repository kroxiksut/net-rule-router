use nrr_shared::{
    load_locale_catalog, AppSection, LogLevel, RouteBehaviorMode, RulesEnabledFilter,
    RulesFileChangeBehavior, RulesTypeFilter, RulesViewSort, ThemeMode,
};
use std::env;
use std::fs;
use std::io;
#[cfg(windows)]
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::process::Command;
use std::sync::OnceLock;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

pub const MANAGED_STORAGE_POLICY_NOTE: &str =
    "UI preferences are application-managed local state. Policy-affecting data remains service-owned.";
const STABLE_PREFERENCES_FILE_NAME: &str = "ui-preferences.conf";
const LEGACY_PREFERENCES_FILE_NAMES: [&str; 1] = ["ui-preferences-v1.conf"];

/// Schema version written by this build into every saved preferences file.
///
/// # Compatibility policy
///
/// - **Absent** (legacy v0): file was written by a pre-versioning build.
///   All known fields are loaded as-is; the file is upgraded to the current
///   schema version on the next save. No silent reset of any field.
/// - **Equal to `CURRENT_UI_PREFS_SCHEMA_VERSION`**: normal load path.
/// - **Greater than `CURRENT_UI_PREFS_SCHEMA_VERSION`** (future version):
///   file was written by a newer build. Known fields are loaded; fields
///   introduced in newer schema versions are silently ignored. A diagnostic
///   is emitted to stderr. The file is **not** downgraded on save — the
///   caller decides whether to overwrite.
pub const CURRENT_UI_PREFS_SCHEMA_VERSION: u32 = 11;

/// Bounds and default for [`UiPreferences::settings_autosave_secs`]. This is the
/// authoritative range: the spin box in the settings UI mirrors it, but any
/// value arriving from a hand-edited file or an older build is clamped here.
pub const SETTINGS_AUTOSAVE_MIN_SECS: u32 = 15;

/// Bounds and default for [`UiPreferences::admin_auto_revoke_minutes`] — how
/// long the elevated broker session may sit UNUSED before the launcher
/// retires it (the next privileged action prompts UAC again). These are the
/// SSOT bounds: the GUI SpinBox mirrors them for convenience, the parse path
/// below enforces them.
pub const ADMIN_AUTO_REVOKE_MIN_MINUTES: u32 = 1;
pub const ADMIN_AUTO_REVOKE_MAX_MINUTES: u32 = 180;
pub const ADMIN_AUTO_REVOKE_DEFAULT_MINUTES: u32 = 15;
pub const SETTINGS_AUTOSAVE_MAX_SECS: u32 = 600;
pub const SETTINGS_AUTOSAVE_DEFAULT_SECS: u32 = 60;

/// Accepted byte units for the traffic CSV export, and the default. Megabytes
/// read best for a monthly report; the exporter still accepts every slug here.
pub const TRAFFIC_EXPORT_UNITS: [&str; 4] = ["bytes", "kb", "mb", "gb"];
pub const TRAFFIC_EXPORT_UNIT_DEFAULT: &str = "mb";

/// Accepted privacy tiers for the diagnostics support archive, and the
/// default. `"standard"` is the redacted tier every user can share; the
/// `"diagnostics"` tier keeps extra cache/storage/decision detail and is meant
/// for a support hand-off. This list is the authoritative allow-list — the
/// radio group in the GUI mirrors it, and any other slug arriving from a
/// hand-edited file or an older build falls back to the default.
pub const DIAGNOSTICS_ARCHIVE_REDACTION_LEVELS: [&str; 2] = ["standard", "diagnostics"];
pub const DIAGNOSTICS_ARCHIVE_REDACTION_LEVEL_DEFAULT: &str = "standard";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UiPreferences {
    pub launch_window_on_startup: bool,
    pub minimize_to_tray_instead_of_close: bool,
    pub show_notifications: bool,
    /// Per-kind mute for the "the suggestions list changed" stripe, under the
    /// master [`Self::show_notifications`] switch. Its own flag because that
    /// stripe is the one users meet often enough to want silenced on its own,
    /// and silencing it must not cost them every other notification.
    pub notify_suggestion_changes: bool,
    /// Per-kind mute for the "connection blocked" notice, under the master
    /// [`Self::show_notifications`] switch. Default `true` — this is the
    /// kind of event a user wants to know about unless they opt out.
    pub notify_block_notices: bool,
    /// Redacts the destination host/IP from the "connection blocked" notice
    /// body while still showing that a block happened. Default `false`.
    pub hide_block_notice_addresses: bool,
    pub reopen_last_section_on_startup: bool,
    pub first_run_completed: bool,
    /// The highest EULA revision the user has accepted on this device, or
    /// `nrr_shared::eula::EULA_NOT_ACCEPTED` (0) if they never have. The GUI
    /// first-run gate re-shows the agreement whenever this is below
    /// `nrr_shared::eula::CURRENT_EULA_VERSION`. Device-local (per-install
    /// consent record), never exported.
    pub accepted_eula_version: u32,
    pub theme_mode: ThemeMode,
    pub accessibility_high_contrast: bool,
    pub accessibility_ui_font_scale_percent: u16,
    pub accessibility_system_font: SystemFontFamily,
    pub accessibility_enhanced_focus_indicator: bool,
    pub accessibility_simplified_labels: bool,
    pub tooltips_enabled: bool,
    pub language: String,
    pub route_primary_label: String,
    pub route_secondary_label: String,
    pub show_bluetooth_adapters: bool,
    /// Display toggle for professional users: show the security-audit viewing
    /// tab in the Logs area. `false` (default) hides the tab; the audit trail
    /// is recorded regardless of this setting — it only controls whether the
    /// read-only viewer tab is offered. Pure device-local UI display preference.
    pub show_audit_tab: bool,
    /// Idle delay, in seconds, before a settings panel that owns draft state
    /// commits it without an explicit press. Clamped to
    /// [`SETTINGS_AUTOSAVE_MIN_SECS`]..=[`SETTINGS_AUTOSAVE_MAX_SECS`] on read;
    /// out-of-range or unparsable values fall back to
    /// [`SETTINGS_AUTOSAVE_DEFAULT_SECS`]. Device-local UI preference.
    pub settings_autosave_secs: u32,
    /// Opt-out of the administrator-rights idle auto-revoke: `true` keeps the
    /// elevated broker session alive until app exit or a manual revoke.
    /// Default `false` — rights ARE auto-revoked after sitting unused
    /// (security: an elevated helper should not outlive the work it was
    /// approved for). Device-local UI preference.
    pub admin_auto_revoke_disabled: bool,
    /// Minutes of NON-USE after which the elevated broker session is retired
    /// (idle timer: every privileged operation restarts it). Clamped to
    /// [`ADMIN_AUTO_REVOKE_MIN_MINUTES`]..=[`ADMIN_AUTO_REVOKE_MAX_MINUTES`]
    /// on read; unparsable/out-of-range falls back to
    /// [`ADMIN_AUTO_REVOKE_DEFAULT_MINUTES`]. Ignored while
    /// `admin_auto_revoke_disabled` is `true`. Device-local UI preference.
    pub admin_auto_revoke_minutes: u32,
    /// Experimental opt-in: reveal the legacy kill-switch mode A (reactive)
    /// option in the routing settings. `false` (default) hides mode A from the
    /// selector unless it happens to be the currently active mode. Mode A is a
    /// non-maintained historical fallback; mode B is the supported mechanism.
    /// Pure device-local UI display preference.
    pub allow_mode_a_killswitch: bool,
    /// Experimental opt-in: reveal the "pre-flight, then all-or-nothing"
    /// apply-failure policy option in the routing settings. `false` (default)
    /// hides it from the picker unless it is already the selected policy —
    /// a previously-saved choice is always shown regardless of this flag.
    /// Its pre-flight checks are still in development. Pure device-local UI
    /// display preference.
    pub pre_flight_apply_policy_opt_in: bool,
    /// Reveals the individual DNS-via-secondary / fast-DNS-answers / fake-IP /
    /// fake-IP-UDP-relay / fake-IP-instant-reset toggles in the routing
    /// settings screen. `false` (default) hides them and the built-in defaults
    /// apply; this flag only controls visibility, never the toggles' own
    /// saved values. Pure device-local UI display preference.
    pub routing_detailed_mode: bool,
    /// Display toggle: show "remembered but currently absent" ghost rows in
    /// the Interfaces section for confirmed primary/secondary bindings whose
    /// adapter is not among the live adapters (e.g. a VPN TAP that removes
    /// itself when the tunnel is down). Default `true` so a user can confirm
    /// a remembered binding at a glance. Pure device-local UI display
    /// preference.
    pub show_remembered_adapters: bool,
    /// Auto-confirm a reinstalled additional adapter (new GUID) when its
    /// saved name uniquely matches a live adapter. `true` (default) =
    /// auto-heal silently; `false` = show the manual re-confirm banner.
    /// Device-local UI preference.
    pub auto_confirm_adapter_id_change: bool,
    /// Show the "leak protection is blocking unknown traffic (secondary
    /// adapter unavailable)" banner while the service
    /// reports an armed fail-closed block-all. `true` (default) = warn;
    /// `false` = stay silent — deliberately running the service at OS start
    /// with the VPN down is a legitimate setup and must not nag. Pure
    /// device-local display preference (the posture itself is service-owned).
    pub warn_kill_switch_block_all: bool,
    /// Persisted acknowledgement of the "leak protection is blocking unknown
    /// traffic" banner. `true` = the user dismissed the banner via its close
    /// button, so it stays hidden across restarts while the block-all posture
    /// remains armed. Cleared back to `false` by the GUI the moment that
    /// posture stops being armed, so the NEXT activation shows the banner
    /// again. Pure device-local display state (the posture itself is
    /// service-owned), never exported.
    pub kill_switch_banner_acknowledged: bool,
    /// Persisted acknowledgement of the "additional adapter not found" banner.
    /// `true` = the user dismissed the amber banner via its close button, so it
    /// stays hidden across restarts while the confirmed secondary adapter stays
    /// unresolvable. Cleared back to `false` by the GUI the moment that adapter
    /// resolves again, so a later disappearance shows the banner anew. Pure
    /// device-local display state, never exported.
    pub missing_secondary_banner_acknowledged: bool,
    /// Selected period for the traffic-statistics panel: `"today"` (default)
    /// or `"session"`. Pure device-local UI display state; the GUI normalizes
    /// any other value back to `"today"`.
    pub traffic_stats_period: String,
    /// Byte unit the traffic CSV export was last written in: `"bytes"`,
    /// `"kb"`, `"mb"` (default) or `"gb"`. Remembered so a user who works in
    /// one unit does not re-pick it on every export. Pure device-local UI
    /// state; the exporter re-validates the slug and falls back on its own.
    pub traffic_export_unit: String,
    /// Privacy tier the diagnostics support archive is exported at:
    /// `"standard"` (default, redacted) or `"diagnostics"` (extra detail).
    /// Both export surfaces share this one choice; persisting it means a user
    /// preparing several archives for support does not re-pick the tier after
    /// every restart. Validated against
    /// [`DIAGNOSTICS_ARCHIVE_REDACTION_LEVELS`] on read — an unknown slug falls
    /// back to [`DIAGNOSTICS_ARCHIVE_REDACTION_LEVEL_DEFAULT`], so the archive
    /// can never be produced at a tier the exporter does not implement. Pure
    /// device-local UI state, never exported.
    pub diagnostics_archive_redaction_level: String,
    /// Companion to [`diagnostics_archive_redaction_level`]: when `true`
    /// (default) the support archive only carries log entries from the current
    /// GUI session, keeping rotated history out of a routine hand-off.
    /// Unchecked exports the full retained history. Pure device-local UI state,
    /// never exported.
    pub diagnostics_archive_session_only: bool,
    /// Cap, in MiB, on the raw service log files attached to a support archive.
    /// `0` (the default) means UNLIMITED: every log file inside the export's
    /// time window is attached whole. A non-zero value trims the oldest
    /// attachments away so the archive stays mailable. Pure device-local UI
    /// state, never exported.
    pub archive_log_budget_mib: u32,
    /// Persisted dismiss signature for the "app rules aren't active yet"
    /// notification: the SORTED unresolved-app set joined with `|`, exactly
    /// as `Main.qml::_unenforcedAppRulesSig` computes it. Persisting the
    /// signature (rather than only tracking dismissal for the session) keeps
    /// it dismissed until the SET changes (a new unresolved app → new
    /// signature → notice re-fires). Empty = never dismissed. Device-local UI
    /// state, never exported.
    pub unenforced_apps_ack_signature: String,
    /// Device-local record of the executable the user pointed out as their
    /// VPN in the onboarding dialog. Captured so it can
    /// later be turned into an "Application -> primary route" rule (which the
    /// service already treats as a kill-switch exemption). Empty = not set.
    /// Single line only (line-oriented prefs file). Device-local, never exported.
    pub confirmed_vpn_exe_path: String,
    /// Multi-select companion to [`confirmed_vpn_exe_path`]: the FULL set of
    /// executables the user confirmed as their VPN in the onboarding dialog,
    /// as a semicolon-joined list of absolute paths (`""` = none). Users often
    /// run several processes as one VPN setup (e.g. OpenVPN + hide.me, or a
    /// client plus its background service and CLI); each listed exe stays
    /// exempted from the kill-switch. `confirmed_vpn_exe_path` mirrors the
    /// FIRST entry for back-compat with single-path readers. Single line only.
    /// Device-local, never exported.
    pub confirmed_vpn_exe_paths: String,

    // The fields below MIRROR per-SID routing-policy toggles owned by the
    // service DB. They exist purely so a user's choice survives a service-DB
    // wipe (schema bump): the service DB is authoritative, but on load the GUI
    // re-seeds the toggle from this mirror when the service reports the default.
    // Persisted additively through the manual `key=value` parser/formatter in
    // this file — a missing key resolves to `Default`, so older preference
    // files load cleanly (same additive contract `#[serde(default)]` gives a
    // serde struct; note `UiPreferences` is not serde-derived).
    /// Mirror of the per-SID service toggle `route_include_subdomains`.
    /// Default `true` — a rule for a site also covers that site's
    /// subdomains. See the block comment above for the seed-on-default
    /// semantics.
    pub route_include_subdomains: bool,
    /// Mirror of the per-SID service toggle `route_shared_ip_policy` (slug,
    /// default `"majority-of-ip"`). See the block comment above for the
    /// seed-on-default semantics.
    pub route_shared_ip_policy: String,
    /// Mirror of the per-SID service toggle `route_kill_switch_block_all`.
    /// Default `false`. See the block comment above for the seed-on-default
    /// semantics.
    pub route_kill_switch_block_all: bool,
    /// Mirror of the per-SID service toggle `route_kill_switch_fail_closed`
    /// (leak-protection posture). Default `true` (fail-closed). See the block
    /// comment above for the seed-on-default semantics.
    pub route_kill_switch_fail_closed: bool,
    /// Mirror of the per-SID service toggle `route_kill_switch_protocols`
    /// (IP-protocol bitmask the emergency block cuts: TCP=1 … Other=64).
    /// Default `127` (all). See the block comment above.
    pub route_kill_switch_protocols: u32,
    /// Mirror of the per-SID MASTER toggle `route_kill_switch_enabled`.
    /// `false` (default) = kill-switch OFF, so NO fail-closed blocking
    /// happens at all (full opt-in; any leak is then the user's explicit
    /// choice). The other kill-switch mirrors above are only meaningful when
    /// this is `true`.
    pub route_kill_switch_enabled: bool,
    /// Mirror of the per-SID `route_allow_dns_over_primary` toggle (keep DNS
    /// resolving over the primary link while the kill-switch block-all is
    /// engaged). Default `true` — DNS-cut block-all is a total blackout;
    /// strict users opt out.
    pub route_allow_dns_over_primary: bool,
    /// Mirror of the per-SID Mode-A coverage strategy (slug: `"per-ip"` |
    /// `"fail-closed-unknown"` (default) | `"zone-widening"`). See the block
    /// comment above for the seed-on-default semantics.
    pub route_mode_a_coverage_strategy: String,
    /// Mirror of the per-SID `resolve_hosts_bypass` posture (resolve rule
    /// hosts bypassing the OS hosts/adblock file). Default `true`.
    pub route_resolve_hosts_bypass: bool,
    /// Mirror of the GLOBAL service enforcement mode (service-stability config,
    /// not per-SID): `"reactive"` (Mode A, default) | `"resolver"` (Mode B).
    /// See the block comment above for the seed-on-default semantics.
    pub route_enforcement_mode: String,
    /// Mirror of the GLOBAL service "secondary tunnel liveness window"
    /// (service-stability config, not per-SID). Active ICMP-probe liveness
    /// window in SECONDS before the kill-switch fail-closes on a continuously
    /// unreachable tunnel next-hop. `0` = disabled (never fail-closes; safe
    /// default); any non-zero value is clamped to `[5, 3600]`. See the block
    /// comment above for the seed-on-default semantics.
    pub route_liveness_window_secs: u32,
    /// Pending OFFLINE routing-settings intents: a compact single-line JSON
    /// object `{"<field>": <value>, …}` recorded
    /// when the user edits a service-owned routing setting while the service
    /// is unreachable. On the next backend connect the GUI shows an explicit
    /// "apply pending changes?" dialog and clears this on apply/discard.
    /// Empty string = none. Opaque to Rust (structural sanity checks only —
    /// the QML side owns the schema). Device-local, never exported.
    pub route_pending_offline_json: String,
    /// Diagnostics cache-viewer column widths: a compact single-line JSON
    /// object `{"ip":120,"freshness":110,"source":120}` persisting the user's
    /// resized table columns across sessions. Empty string = defaults. Opaque
    /// to Rust (structural sanity checks only — the QML side owns the schema).
    /// Device-local UI preference, never exported.
    pub cache_table_column_widths: String,
    /// Last-known values of the settings the background service owns
    /// (per-SID route policy + the shared service-stability config), as a
    /// compact single-line JSON object
    /// `{"route-policy":{…},"stability":{…}}`. Written by the GUI whenever a
    /// live read from the service succeeds, and read back when the service is
    /// stopped so every panel shows the user's real values instead of the
    /// neutral UI defaults. Empty string = nothing mirrored yet. Purely a
    /// DISPLAY cache — the service stays authoritative and nothing is ever
    /// pushed from this field. Opaque to Rust (structural sanity checks only —
    /// the QML side owns the schema). Device-local, never exported.
    pub service_backed_mirror_json: String,

    /// What the user asked the service-owned settings to BE, in the same
    /// compact `{"route-policy":{…},"stability":{…}}` shape as the mirror
    /// above. Only keys the user actually touched appear here.
    ///
    /// The mirror answers "what did the service last report"; this answers
    /// "what did the user decide", and the two are not the same fact. A
    /// service whose state DB was wiped reports its own defaults, and without
    /// a record of intent the GUI had no way to tell "the user wants fake-IP
    /// off" from "this service has never been told anything" — it accepted the
    /// defaults and the user's settings silently evaporated. Intent is what
    /// the GUI replays on connect; the mirror stays display-only.
    ///
    /// Empty string = the user has never changed a service-owned setting.
    /// Opaque to Rust (structural sanity checks only — the QML side owns the
    /// schema). Device-local, never exported.
    pub service_intent_json: String,

    // -------------------------------------------------------------------------
    // Preview: policy-affecting fields — to be migrated to service-owned state.
    //
    // The five fields below belong to `ActiveConfiguration` in `nrr-domain` and
    // must be owned by the background service, not the UI runtime. They live here
    // temporarily during the scaffold phase to support the preview GUI before
    // real service integration. They will eventually be removed from
    // `UiPreferences` and managed exclusively through the service-owned revision
    // store. See `nrr_domain::PolicyOwnershipBoundary` for the full boundary spec.
    // -------------------------------------------------------------------------
    /// **Migrated to service-owned per-SID storage.**
    /// Read via IPC `SnapshotInitial.routePolicy.primary.stableId`.
    /// Kept in struct only for backward-compat deserialisation of older
    /// `preferences.json` files; the launcher migration flow zeroes it via
    /// `cleanup_legacy_policy_fields` after successful `RoutePolicyUpdate`.
    #[deprecated(
        since = "0.2.0",
        note = "Migrated to service-owned per-SID route_bindings (block 16.8.1). \
                Read via IPC SnapshotInitial.routePolicy.primary.stableId."
    )]
    pub selected_primary_interface_id: String,
    /// **Migrated** — display hint only. See `selected_primary_interface_id`.
    #[deprecated(
        since = "0.2.0",
        note = "Migrated to service-owned per-SID route_bindings (block 16.8.1)."
    )]
    pub selected_primary_interface_name: String,
    /// **Migrated** — see `selected_primary_interface_id`.
    #[deprecated(
        since = "0.2.0",
        note = "Migrated to service-owned per-SID route_bindings (block 16.8.1)."
    )]
    pub primary_role_user_confirmed: bool,
    /// **Migrated** — see `selected_primary_interface_id`.
    #[deprecated(
        since = "0.2.0",
        note = "Migrated to service-owned per-SID route_bindings (block 16.8.1)."
    )]
    pub selected_secondary_interface_id: String,
    /// **Migrated** — display hint only.
    #[deprecated(
        since = "0.2.0",
        note = "Migrated to service-owned per-SID route_bindings (block 16.8.1)."
    )]
    pub selected_secondary_interface_name: String,
    /// **Migrated** — see `selected_primary_interface_id`.
    #[deprecated(
        since = "0.2.0",
        note = "Migrated to service-owned per-SID route_bindings (block 16.8.1)."
    )]
    pub secondary_role_user_confirmed: bool,
    /// **Migrated** — see `selected_primary_interface_id`.
    #[deprecated(
        since = "0.2.0",
        note = "Migrated to service-owned per-SID behavior_mode (block 16.8.1)."
    )]
    pub route_behavior_mode: RouteBehaviorMode,
    /// **Migrated** — orthogonal flag (applies on top of any mode), see
    /// `selected_primary_interface_id`.
    #[deprecated(
        since = "0.2.0",
        note = "Migrated to service-owned per-SID secondary_block_policy (block 16.8.1)."
    )]
    pub block_secondary_traffic_when_unavailable: bool,
    pub last_opened_section: AppSection,
    /// Preferred sort order for the rules table view. UI preference only — does not
    /// affect the rule file on disk. Persisted per device.
    pub rules_view_sort: RulesViewSort,
    /// Preferred enabled/disabled filter for the rules table view.
    /// Not persisted — resets to `All` on application restart.
    pub rules_enabled_filter: RulesEnabledFilter,
    /// Preferred rule-type filter for the rules table view.
    /// Not persisted — resets to `All` on application restart.
    pub rules_type_filter: RulesTypeFilter,
    /// How the application responds when the external rules file changes on disk.
    /// Persisted per device.
    pub rules_file_change_behavior: RulesFileChangeBehavior,
    /// **Preview** — will move to a service-owned revision store.
    ///
    /// SHA-256 hex hash of the `rules_primary.txt` file at the time it was last
    /// applied. On startup the service compares this with the current file hash
    /// to detect changes. Empty string = not recorded yet.
    pub last_rules_primary_file_hash: String,
    /// **Preview** — will move to a service-owned revision store.
    ///
    /// SHA-256 hex hash of the `rules_secondary.txt` file at the time it was
    /// last applied. On startup the service compares this with the current file
    /// hash to detect changes. Empty string = not recorded yet.
    pub last_rules_secondary_file_hash: String,
    /// When `true`, the import file picker opens two dialogs — one per route —
    /// and imports both files as a single pending revision.
    ///
    /// Default: `false` (import one route at a time).
    /// See [`nrr_domain::preset_contract::IMPORT_BOTH_FILES_TOGETHER_DEFAULT`].
    pub import_both_files_together: bool,

    /// When `true`, Zone rules are evaluated before ExactIp rules in the same
    /// tier. Default: `false` (ExactIp wins, as the more specific address
    /// match takes priority over zone-level routing).
    ///
    /// Maps to `ZonePriorityPolicy { prefer_ip: !zone_priority_over_ip }` when
    /// constructing a `DecisionRequest`.
    pub zone_priority_over_ip: bool,
    /// Verbosity level for the diagnostic log store and Logs screen.
    /// Default: [`LogLevel::Info`].
    pub log_level: LogLevel,
    /// When `true`, the experimental browser-stub routing path is enabled.
    /// Populated into `DecisionFeatureFlags::browser_stub_experimental` by the
    /// service layer before invoking the decision pipeline.
    /// Default: `false`.
    pub browser_stub_experimental_enabled: bool,

    // Tracks the GUI's "last-known" sync state between the active rules
    // revision (service-owned) and the user's on-disk preset files
    // (device-local). Drives:
    //   - The SaveBeforeCloseDialog (divergence detection per route)
    //   - Auto-open-on-launch (file vs active hash comparison)
    //   - Discard & rollback (last_file_synced_revision_id_<role>)
    //
    // All four pairs default to None; v1 preference files load with all
    // four as None (schema-tolerant migration via missing-key → default).
    /// Most recent on-disk path the primary route's preset was written to,
    /// or `None` if the user has never exported / imported primary rules
    /// on this device. Used as the default Save target for divergence.
    pub last_saved_path_primary: Option<String>,
    /// Same as [`last_saved_path_primary`] but for the secondary route.
    pub last_saved_path_secondary: Option<String>,

    /// Display-only record of the file the primary route's rules most
    /// recently CAME FROM (import or export). Unlike
    /// [`last_saved_path_primary`] it is never used as a write target, so it
    /// MAY point inside the read-only bundled presets tree — the Rules
    /// section's "Source:" indicator renders it verbatim.
    pub last_loaded_path_primary: Option<String>,
    /// Same as [`last_loaded_path_primary`] but for the secondary route.
    pub last_loaded_path_secondary: Option<String>,

    /// Path of a primary preset file that should be auto-imported on
    /// next launch. Set only when the user opted in to the
    /// "Open these rules on next launch" checkbox in Save As. `None` ⇒
    /// no auto-open for primary.
    pub auto_open_on_launch_path_primary: Option<String>,
    /// Same as [`auto_open_on_launch_path_primary`] but for secondary.
    pub auto_open_on_launch_path_secondary: Option<String>,

    /// Revision ID that was active at the time the primary file was last
    /// written (or imported). `Discard & rollback` in SaveBeforeCloseDialog
    /// calls `RollbackRequest` with this ID; `None` ⇒ rollback to empty
    /// revision (service creates an empty `RulesRevisionContent`).
    pub last_file_synced_revision_id_primary: Option<String>,
    /// Same for secondary.
    pub last_file_synced_revision_id_secondary: Option<String>,

    /// SHA-256 hex of the primary file content at the time of last sync.
    /// Used at close-time to detect "active revision ≠ on-disk file" → the
    /// SaveBeforeCloseDialog asks the user whether to write back, save as,
    /// discard, or cancel. `None` ⇒ no recorded sync; fresh state.
    pub last_file_synced_hash_primary: Option<String>,
    /// Same for secondary.
    pub last_file_synced_hash_secondary: Option<String>,

    // The first-launch install dialog (and the connection-banner "Install
    // Service" action) trigger UAC. When the user clicks "No" the GUI must
    // NOT re-prompt automatically — re-prompting on every launch is the
    // single most-cited UX anti-pattern in Win32 service-installer UX. We
    // record the latest decline timestamp + a session counter so the
    // dialog logic can downgrade to a passive banner (and eventually
    // suppress the banner entirely after 3+ declines in 7 days).
    /// Wall-clock epoch seconds when the user declined the install UAC
    /// most recently. `None` ⇒ never declined.
    pub service_install_uac_declined_at_epoch: Option<i64>,
    /// Number of UAC declines for the install flow seen in this session.
    /// Resets when the user successfully installs (operation completes
    /// with success) or when the GUI process restarts. `0` ⇒ never
    /// declined since last successful state.
    pub service_install_uac_declined_count: u32,

    /// When `false`, the GUI does NOT auto-open the last-saved / auto-open
    /// rules files on startup even if `last_saved_path_*` is populated.
    /// Default `true`. The companion "Forget file binding" action clears the
    /// path fields outright; this toggle lets a user who switches between
    /// attached/detached workflows disable auto-load without losing the
    /// remembered paths.
    pub auto_load_rules_on_launch: bool,

    /// Persisted default for the "Include rule comments" checkbox in the
    /// export dialog. Default `true`. Promotes the former session-only
    /// stickiness to a real preference that survives restarts.
    pub export_include_comments: bool,

    /// Persisted default for the "Import only active rules" checkbox in the
    /// import flow. Default `true`: rules disabled in the source preset
    /// (commented recognizable lines — e.g. application rules left off
    /// pending per-process routing) are dropped on import instead of
    /// brought in as toggled-off rows. Unchecking imports everything.
    pub import_only_active: bool,

    /// Controls when the GUI↔service protocol-mismatch banner shows:
    /// `"auto"` (default — only on mismatch), `"always"`, or `"never"`.
    /// Stored as a slug string (mirrors `language`); the GUI constrains
    /// the value via a dropdown and treats any unknown value as `"auto"`.
    pub compat_banner_mode: String,
    /// Optional override for the URL the compat banner's "Open updates
    /// page" button opens. Empty ⇒ fall back to the bundled project
    /// releases URL.
    pub update_page_url: String,

    /// When `false`, the Rules section hides the bundled-preset quick-load
    /// row. The "Hide" button on that row sets this `false`; a "Show bundled
    /// presets" toggle in Settings re-enables it. Default `true` (the row is
    /// shown, preserving prior behaviour).
    pub show_bundled_presets: bool,

    /// Absolute path of a folder the user keeps their OWN rule sets in. When
    /// non-empty the quick-load dropdown in Rules enumerates this folder
    /// instead of the sets shipped with the app; empty (the default) keeps the
    /// shipped sets. Two folder layouts are accepted: one subfolder per set, or
    /// `rules_primary.txt` / `rules_secondary.txt` directly in the folder.
    /// Free-form single-line path (the preferences file is line-oriented).
    /// Device-local UI state — never part of an exported settings bundle.
    pub user_presets_dir: String,
    /// The user ticked "do not ask again" on the warning shown when saving a
    /// rule set INTO the folder that ships with the app. That location is
    /// overwritten by an application update, so the first attempt asks; once
    /// acknowledged the warning stays out of the way. Default `false` (ask).
    /// Device-local UI state.
    pub allow_saving_into_bundled_presets: bool,
    /// The user dismissed the one-time "keep your rule sets in this folder?"
    /// offer that appears after saving or loading a rule file while no folder
    /// is configured. Once set, the offer never returns — re-asking on every
    /// save is the nagging the offer is designed to avoid. Default `false`.
    /// Device-local UI state.
    pub rules_folder_suggestion_dismissed: bool,
    /// The rule set the quick-load dropdown is left on, so it reopens on the
    /// user's choice instead of being re-derived every time the Rules screen is
    /// shown. Format is `<source>:<label>` where source is `user` (a set from
    /// the folder above) or `bundled` (a set that ships with the app): the two
    /// lists can hold identical labels, and a remembered choice must not leak
    /// across them when the folder is repointed. Empty (the default) means "no
    /// choice yet" — only then does the shipped-set list fall back to picking by
    /// system locale. Free-form single line; the GUI ignores a value whose set
    /// is no longer present. Device-local UI state.
    pub selected_preset_set: String,

    /// Per-adapter acknowledgment for the VPN-split informational
    /// banner. Holds the display name of the secondary (VPN-like) adapter the
    /// user dismissed the banner for. The blue banner stays hidden while the
    /// active secondary adapter's name equals this; a different adapter (empty /
    /// mismatch) re-shows it once. Empty string = never acknowledged (default).
    /// Device-specific UI state (like theme/font) — persisted locally, not part
    /// of the exported settings.
    pub secondary_split_ack_adapter_name: String,
    //
    /// Governs how the file↔service merge preview resolves rules present on
    /// both sides but differing. Stored as a slug; the GUI constrains the
    /// value via a dropdown and treats any unknown value as `"union"`:
    /// - `"union"` (default): keep both sides and flag each conflict for the
    ///   user to resolve per-rule in the merge dialog.
    /// - `"file-wins"`: the linked file is authoritative for conflicts.
    /// - `"service-wins"`: the active service revision is authoritative.
    pub merge_conflict_policy: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SystemFontFamily {
    SystemDefault,
    SegoeUi,
    Arial,
    Tahoma,
    Verdana,
}

impl SystemFontFamily {
    pub const fn slug(self) -> &'static str {
        match self {
            Self::SystemDefault => "system-default",
            Self::SegoeUi => "segoe-ui",
            Self::Arial => "arial",
            Self::Tahoma => "tahoma",
            Self::Verdana => "verdana",
        }
    }
}

impl std::fmt::Display for SystemFontFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.slug())
    }
}

impl std::str::FromStr for SystemFontFamily {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "system-default" | "system_default" => Ok(Self::SystemDefault),
            "segoe-ui" | "segoe_ui" | "segoe" => Ok(Self::SegoeUi),
            "arial" => Ok(Self::Arial),
            "tahoma" => Ok(Self::Tahoma),
            "verdana" => Ok(Self::Verdana),
            _ => Err("unknown system font family"),
        }
    }
}

// `Default::default()` constructs a `UiPreferences` with the deprecated
// policy-affecting fields zeroed at their type defaults. The
// `allow(deprecated)` is contained to this fn because
// the policy fields are part of the struct's persisted shape; new
// readers should use `bridge.snapshotInitial.routePolicy` from IPC,
// not these.
#[allow(deprecated)]
impl Default for UiPreferences {
    fn default() -> Self {
        let language = detected_system_language();
        let (route_primary_label, route_secondary_label) = default_route_labels(&language);
        Self {
            launch_window_on_startup: true,
            minimize_to_tray_instead_of_close: true,
            show_notifications: true,
            notify_suggestion_changes: true,
            notify_block_notices: true,
            hide_block_notice_addresses: false,
            reopen_last_section_on_startup: true,
            first_run_completed: false,
            accepted_eula_version: nrr_shared::eula::EULA_NOT_ACCEPTED,
            theme_mode: ThemeMode::System,
            accessibility_high_contrast: false,
            accessibility_ui_font_scale_percent: 100,
            accessibility_system_font: SystemFontFamily::SystemDefault,
            accessibility_enhanced_focus_indicator: false,
            accessibility_simplified_labels: false,
            tooltips_enabled: true,
            language,
            route_primary_label,
            route_secondary_label,
            show_bluetooth_adapters: false,
            show_audit_tab: false,
            settings_autosave_secs: SETTINGS_AUTOSAVE_DEFAULT_SECS,
            admin_auto_revoke_disabled: false,
            admin_auto_revoke_minutes: ADMIN_AUTO_REVOKE_DEFAULT_MINUTES,
            allow_mode_a_killswitch: false,
            pre_flight_apply_policy_opt_in: false,
            routing_detailed_mode: false,
            show_remembered_adapters: true,
            auto_confirm_adapter_id_change: true,
            warn_kill_switch_block_all: true,
            kill_switch_banner_acknowledged: false,
            missing_secondary_banner_acknowledged: false,
            traffic_stats_period: "today".to_string(),
            traffic_export_unit: TRAFFIC_EXPORT_UNIT_DEFAULT.to_string(),
            diagnostics_archive_redaction_level: DIAGNOSTICS_ARCHIVE_REDACTION_LEVEL_DEFAULT
                .to_string(),
            diagnostics_archive_session_only: true,
            archive_log_budget_mib: 0,
            unenforced_apps_ack_signature: String::new(),
            confirmed_vpn_exe_path: String::new(),
            confirmed_vpn_exe_paths: String::new(),
            selected_primary_interface_id: String::new(),
            selected_primary_interface_name: String::new(),
            primary_role_user_confirmed: false,
            selected_secondary_interface_id: String::new(),
            selected_secondary_interface_name: String::new(),
            secondary_role_user_confirmed: false,
            route_behavior_mode: RouteBehaviorMode::default_when_secondary_unbound(),
            block_secondary_traffic_when_unavailable: false,
            // Device-local mirrors of per-SID policy toggles. Defaults match
            // the service DB defaults so a fresh install (or post-wipe seed)
            // starts neutral. Subdomain coverage defaults ON (matches the
            // service default); widening only adds coverage towards the
            // route the rule already names.
            route_include_subdomains: true,
            route_shared_ip_policy: route_shared_ip_policy_default(),
            route_kill_switch_block_all: false,
            route_kill_switch_fail_closed: true,
            route_kill_switch_protocols: 127,
            route_kill_switch_enabled: false,
            route_allow_dns_over_primary: true,
            // Matches the service default (leak protection holds even while
            // the pin set is incomplete) and the hosts-bypass default.
            route_mode_a_coverage_strategy: route_mode_a_coverage_strategy_default(),
            route_resolve_hosts_bypass: true,
            // Kept in sync with `EnforcementMode::default().as_slug()`.
            route_enforcement_mode: String::from("resolver"),
            route_liveness_window_secs: 0,
            route_pending_offline_json: String::new(),
            allow_saving_into_bundled_presets: false,
            rules_folder_suggestion_dismissed: false,
            cache_table_column_widths: String::new(),
            service_backed_mirror_json: String::new(),
            service_intent_json: String::new(),
            last_opened_section: AppSection::InterfacesAndRoutes,
            rules_view_sort: RulesViewSort::default(),
            rules_enabled_filter: RulesEnabledFilter::default(),
            rules_type_filter: RulesTypeFilter::default(),
            rules_file_change_behavior: RulesFileChangeBehavior::default(),
            last_rules_primary_file_hash: String::new(),
            last_rules_secondary_file_hash: String::new(),
            import_both_files_together: false,
            zone_priority_over_ip: false,
            log_level: LogLevel::Info,
            browser_stub_experimental_enabled: false,
            // File-source state defaults. All None until the user performs
            // their first import / export.
            last_saved_path_primary: None,
            last_saved_path_secondary: None,
            last_loaded_path_primary: None,
            last_loaded_path_secondary: None,
            auto_open_on_launch_path_primary: None,
            auto_open_on_launch_path_secondary: None,
            last_file_synced_revision_id_primary: None,
            last_file_synced_revision_id_secondary: None,
            last_file_synced_hash_primary: None,
            last_file_synced_hash_secondary: None,
            service_install_uac_declined_at_epoch: None,
            service_install_uac_declined_count: 0,
            // New toggles default to the pre-existing behaviour (auto-load
            // on, comments on, banner auto, no custom URL).
            auto_load_rules_on_launch: true,
            export_include_comments: true,
            import_only_active: true,
            compat_banner_mode: String::from("auto"),
            update_page_url: String::new(),
            show_bundled_presets: true,
            // Empty means "list the rule sets shipped with the app".
            user_presets_dir: String::new(),
            // Empty means "the user has not picked a set yet", which is the only
            // state where the shipped-set list may choose one by system locale.
            selected_preset_set: String::new(),
            secondary_split_ack_adapter_name: String::new(),
            // Default to the safe interactive "union" policy: the merge
            // keeps both sides and asks the user to resolve conflicts.
            merge_conflict_policy: String::from("union"),
        }
    }
}

/// Default slug for the `route_shared_ip_policy` mirror. Kept as a free
/// helper (module scope) so both `impl Default` and any
/// future serde surface share one source of truth for the default value.
fn route_shared_ip_policy_default() -> String {
    "majority-of-ip".to_string()
}

/// Default slug for the `route_mode_a_coverage_strategy` mirror. This is a
/// MIRROR of a service-owned policy field, so it never spells the slug itself —
/// it defers to the wire default in `nrr-shared`, which is normative.
fn route_mode_a_coverage_strategy_default() -> String {
    nrr_shared::ipc_payloads::mode_a_coverage_strategy_default()
}

/// Clamp the secondary tunnel liveness window (seconds) to the backend
/// contract: `0` stays `0` (disabled — the probe never fail-closes); any
/// non-zero value is clamped to `[5, 3600]`. Single source of truth shared by
/// the parser and any future serde surface.
fn clamp_liveness_window_secs(value: u32) -> u32 {
    if value == 0 {
        0
    } else {
        value.clamp(5, 3600)
    }
}

fn default_route_labels(language: &str) -> (String, String) {
    let base = language
        .split('-')
        .next()
        .filter(|item| !item.is_empty())
        .unwrap_or("en");
    if base == "ru" {
        ("Основной".to_string(), "Дополнительный".to_string())
    } else {
        ("Primary".to_string(), "Secondary".to_string())
    }
}

fn detected_system_language() -> String {
    static DETECTED_LANGUAGE: OnceLock<String> = OnceLock::new();
    DETECTED_LANGUAGE
        .get_or_init(detect_system_language_uncached)
        .clone()
}

fn detect_system_language_uncached() -> String {
    for key in [
        "NRR_UI_LANGUAGE",
        "LC_ALL",
        "LC_MESSAGES",
        "LANGUAGE",
        "LANG",
    ] {
        if let Ok(value) = env::var(key) {
            if let Some(language) = parse_language_hint(&value) {
                return language;
            }
        }
    }

    #[cfg(windows)]
    {
        if let Ok(output) = Command::new("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "[System.Globalization.CultureInfo]::CurrentUICulture.TwoLetterISOLanguageName",
            ])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
        {
            if output.status.success() {
                let value = String::from_utf8_lossy(&output.stdout);
                if let Some(language) = parse_language_hint(&value) {
                    return language;
                }
            }
        }
    }

    preferred_available_language("en")
}

pub fn canonicalize_language_id(value: &str) -> Option<String> {
    let normalized = value.trim().to_ascii_lowercase().replace('_', "-");
    let trimmed = normalized
        .split('.')
        .next()
        .unwrap_or_default()
        .split('@')
        .next()
        .unwrap_or_default()
        .trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn parse_language_hint(value: &str) -> Option<String> {
    let normalized = canonicalize_language_id(value)?;
    Some(preferred_available_language(&normalized))
}

/// Base language subtags of CIS system locales that have no bundled
/// translation of their own. Russian is
/// the regionally-understood default for these; every other unmatched locale
/// falls back to English. Deliberately excludes `ro` (base subtag cannot
/// distinguish Moldova from Romania) and `ka` (Georgia).
const CIS_RU_FALLBACK_LANGS: &[&str] = &["be", "uk", "kk", "ky", "uz", "tg", "tk", "az", "hy"];

fn preferred_available_language(requested: &str) -> String {
    let catalog = load_locale_catalog();
    if catalog.contains_key(requested) {
        return requested.to_string();
    }

    let base = requested
        .split('-')
        .next()
        .filter(|item| !item.is_empty())
        .unwrap_or("en");
    if catalog.contains_key(base) {
        return base.to_string();
    }

    // CIS locales without a bundled translation default to Russian (both
    // the app UI and the user agreement follow this choice; one button in
    // the agreement window switches everything to English).
    if CIS_RU_FALLBACK_LANGS.contains(&base) && catalog.contains_key("ru") {
        return "ru".to_string();
    }

    if catalog.contains_key("en") {
        return "en".to_string();
    }

    catalog
        .keys()
        .next()
        .cloned()
        .unwrap_or_else(|| "en".to_string())
}

pub struct UiPreferencesStore {
    path: PathBuf,
    legacy_paths: Vec<PathBuf>,
    is_profile_persistent: bool,
}

impl UiPreferencesStore {
    pub fn managed_local() -> io::Result<Self> {
        let storage = resolve_storage_location()?;
        let legacy_paths = legacy_preference_paths(storage.root.clone());
        Ok(Self {
            path: storage.root.join(STABLE_PREFERENCES_FILE_NAME),
            legacy_paths,
            is_profile_persistent: storage.is_profile_persistent,
        })
    }

    pub fn for_path(path: PathBuf) -> Self {
        Self {
            path,
            legacy_paths: Vec::new(),
            is_profile_persistent: true,
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn is_profile_persistent(&self) -> bool {
        self.is_profile_persistent
    }

    pub fn load(&self) -> io::Result<UiPreferences> {
        self.try_migrate_legacy_file()?;
        match fs::read_to_string(&self.path) {
            Ok(content) => {
                check_schema_version_compat(&content);
                Ok(parse_preferences(&content))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(UiPreferences::default()),
            Err(error) => Err(error),
        }
    }

    pub fn save(&self, preferences: &UiPreferences) -> io::Result<()> {
        self.try_migrate_legacy_file()?;
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Write-then-rename: `fs::rename` replaces the destination in one step
        // on every supported OS, so a process killed at any point leaves either
        // the old file or the new one — never a truncated one. Deleting the
        // destination first would open exactly that window, and it buys
        // nothing.
        let temporary_path = self.path.with_extension("tmp");
        let payload = format_preferences(preferences);
        fs::write(&temporary_path, payload)?;
        fs::rename(&temporary_path, &self.path)
    }

    fn try_migrate_legacy_file(&self) -> io::Result<()> {
        if self.path.exists() {
            return Ok(());
        }

        for legacy_path in &self.legacy_paths {
            if !legacy_path.exists() {
                continue;
            }

            if let Some(parent) = self.path.parent() {
                fs::create_dir_all(parent)?;
            }

            match fs::rename(legacy_path, &self.path) {
                Ok(_) => return Ok(()),
                Err(_) => {
                    // Cross-volume move fallback.
                    fs::copy(legacy_path, &self.path)?;
                    fs::remove_file(legacy_path)?;
                    return Ok(());
                }
            }
        }

        Ok(())
    }
}

struct StorageLocation {
    root: PathBuf,
    is_profile_persistent: bool,
}

fn resolve_storage_location() -> io::Result<StorageLocation> {
    let mut candidates: Vec<(PathBuf, bool)> = Vec::new();
    if let Some(app_data) = env::var_os("APPDATA") {
        candidates.push((PathBuf::from(app_data), true));
    }
    if let Some(local_app_data) = env::var_os("LOCALAPPDATA") {
        candidates.push((PathBuf::from(local_app_data), true));
    }
    candidates.push((env::temp_dir(), false));

    let mut last_error = None;
    for (base, is_profile_persistent) in candidates {
        let managed_path = base.join("NetRuleRouter").join("managed");
        match fs::create_dir_all(&managed_path) {
            Ok(_) => {
                return Ok(StorageLocation {
                    root: managed_path,
                    is_profile_persistent,
                });
            }
            Err(error) => {
                last_error = Some(error);
            }
        }
    }

    if let Some(error) = last_error {
        Err(error)
    } else {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "No candidate path is available for managed UI storage.",
        ))
    }
}

fn legacy_preference_paths(root: PathBuf) -> Vec<PathBuf> {
    let mut paths = LEGACY_PREFERENCES_FILE_NAMES
        .iter()
        .map(|name| root.join(name))
        .collect::<Vec<_>>();
    let temp_root = env::temp_dir().join("NetRuleRouter").join("managed");
    paths.extend(
        LEGACY_PREFERENCES_FILE_NAMES
            .iter()
            .map(|name| temp_root.join(name)),
    );
    paths.push(temp_root.join(STABLE_PREFERENCES_FILE_NAME));
    paths
}

/// Scans `content` for a `schema_version` key and emits a stderr diagnostic
/// when the file declares a version newer than this build supports.
///
/// Called by [`UiPreferencesStore::load`] before the full parse pass. Absent
/// `schema_version` means a legacy v0 file — loaded silently without warning.
fn check_schema_version_compat(content: &str) {
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("schema_version=") {
            if let Ok(v) = rest.trim().parse::<u32>() {
                if v > CURRENT_UI_PREFS_SCHEMA_VERSION {
                    eprintln!(
                        "nrr: ui-preferences file declares schema_version={v}; \
                         this build supports up to {CURRENT_UI_PREFS_SCHEMA_VERSION}. \
                         Known fields will be loaded; fields from newer schema versions are ignored."
                    );
                }
            }
            return;
        }
    }
    // No schema_version key: legacy v0 file — load as-is, no warning.
}

// `parse_preferences` continues to deserialise the legacy policy-affecting
// fields for backward-compat with older files. New readers should consume
// IPC `SnapshotInitial.routePolicy` instead.
#[allow(deprecated)]
fn parse_preferences(content: &str) -> UiPreferences {
    let mut preferences = UiPreferences::default();

    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let Some((raw_key, raw_value)) = line.split_once('=') else {
            continue;
        };
        let key = raw_key.trim();
        let value = raw_value.trim();

        match key {
            "schema_version" => {
                // Parsed by `check_schema_version_compat`; ignore here.
            }
            "launch_window_on_startup" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.launch_window_on_startup = parsed;
                }
            }
            "minimize_to_tray_instead_of_close" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.minimize_to_tray_instead_of_close = parsed;
                }
            }
            "show_notifications" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.show_notifications = parsed;
                }
            }
            "notify_suggestion_changes" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.notify_suggestion_changes = parsed;
                }
            }
            "notify_block_notices" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.notify_block_notices = parsed;
                }
            }
            "hide_block_notice_addresses" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.hide_block_notice_addresses = parsed;
                }
            }
            "reopen_last_section_on_startup" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.reopen_last_section_on_startup = parsed;
                }
            }
            "first_run_completed" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.first_run_completed = parsed;
                }
            }
            "accepted_eula_version" => {
                if let Ok(parsed) = value.parse::<u32>() {
                    preferences.accepted_eula_version = parsed;
                }
            }
            "theme_mode" => {
                if let Ok(parsed) = value.parse::<ThemeMode>() {
                    preferences.theme_mode = parsed;
                }
            }
            "accessibility_high_contrast" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.accessibility_high_contrast = parsed;
                }
            }
            "accessibility_ui_font_scale_percent" => {
                if let Some(parsed) = parse_font_scale_percent(value) {
                    preferences.accessibility_ui_font_scale_percent = parsed;
                }
            }
            "accessibility_system_font" => {
                if let Ok(parsed) = value.parse::<SystemFontFamily>() {
                    preferences.accessibility_system_font = parsed;
                }
            }
            "accessibility_enhanced_focus_indicator" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.accessibility_enhanced_focus_indicator = parsed;
                }
            }
            "accessibility_simplified_labels" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.accessibility_simplified_labels = parsed;
                }
            }
            "tooltips_enabled" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.tooltips_enabled = parsed;
                }
            }
            "language" => {
                if let Some(parsed) = canonicalize_language_id(value) {
                    preferences.language = parsed;
                }
            }
            "last_opened_section" => {
                if let Ok(parsed) = value.parse::<AppSection>() {
                    preferences.last_opened_section = parsed;
                }
            }
            "route_primary_label" => {
                if !value.is_empty() {
                    preferences.route_primary_label = value.to_string();
                }
            }
            "route_secondary_label" => {
                if !value.is_empty() {
                    preferences.route_secondary_label = value.to_string();
                }
            }
            "show_bluetooth_adapters" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.show_bluetooth_adapters = parsed;
                }
            }
            "show_audit_tab" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.show_audit_tab = parsed;
                }
            }
            "admin_auto_revoke_disabled" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.admin_auto_revoke_disabled = parsed;
                }
            }
            "admin_auto_revoke_minutes" => {
                preferences.admin_auto_revoke_minutes = value
                    .parse::<u32>()
                    .ok()
                    .filter(|m| {
                        (ADMIN_AUTO_REVOKE_MIN_MINUTES..=ADMIN_AUTO_REVOKE_MAX_MINUTES).contains(m)
                    })
                    .unwrap_or(ADMIN_AUTO_REVOKE_DEFAULT_MINUTES);
            }
            "settings_autosave_secs" => {
                preferences.settings_autosave_secs = value
                    .parse::<u32>()
                    .ok()
                    .filter(|secs| {
                        (SETTINGS_AUTOSAVE_MIN_SECS..=SETTINGS_AUTOSAVE_MAX_SECS).contains(secs)
                    })
                    .unwrap_or(SETTINGS_AUTOSAVE_DEFAULT_SECS);
            }
            "allow_mode_a_killswitch" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.allow_mode_a_killswitch = parsed;
                }
            }
            "pre_flight_apply_policy_opt_in" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.pre_flight_apply_policy_opt_in = parsed;
                }
            }
            "routing_detailed_mode" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.routing_detailed_mode = parsed;
                }
            }
            "show_remembered_adapters" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.show_remembered_adapters = parsed;
                }
            }
            "auto_confirm_adapter_id_change" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.auto_confirm_adapter_id_change = parsed;
                }
            }
            // Block-all banner opt-out. Missing key resolves to the ON
            // default via `defaults()`.
            "warn_kill_switch_block_all" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.warn_kill_switch_block_all = parsed;
                }
            }
            // Persisted acknowledgement of the block-all banner. Missing key
            // (pre-existing file) resolves to the `false` default via `defaults()`.
            "kill_switch_banner_acknowledged" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.kill_switch_banner_acknowledged = parsed;
                }
            }
            // Persisted acknowledgement of the "additional adapter not found"
            // banner. Missing key (pre-existing file) resolves to the `false`
            // default via `defaults()`.
            "missing_secondary_banner_acknowledged" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.missing_secondary_banner_acknowledged = parsed;
                }
            }
            // Selected traffic-statistics period slug. Non-empty gate so a
            // missing key keeps the `"today"` default; the GUI normalizes any
            // unexpected slug back to `"today"`.
            "traffic_stats_period" => {
                if !value.is_empty() {
                    preferences.traffic_stats_period = value.to_string();
                }
            }
            // Remembered CSV export unit. Only a known slug is accepted, so a
            // hand-edited or older file cannot leave the panel on a unit the
            // exporter does not implement.
            "traffic_export_unit" => {
                if TRAFFIC_EXPORT_UNITS.contains(&value) {
                    preferences.traffic_export_unit = value.to_string();
                }
            }
            // Remembered support-archive privacy tier. Only a known slug is
            // accepted, so a hand-edited or older file cannot leave the export
            // pointing at a tier the archive writer does not implement.
            "diagnostics_archive_redaction_level" => {
                if DIAGNOSTICS_ARCHIVE_REDACTION_LEVELS.contains(&value) {
                    preferences.diagnostics_archive_redaction_level = value.to_string();
                }
            }
            // Remembered "current session only" archive scope. Missing key
            // (pre-existing file) resolves to the `true` default.
            "diagnostics_archive_session_only" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.diagnostics_archive_session_only = parsed;
                }
            }
            // Raw-log attachment cap in MiB; `0` = unlimited. A missing key
            // (pre-existing file) resolves to the unlimited default, and an
            // unparsable value keeps whatever is already there rather than
            // silently capping an export the user expected to be complete.
            "archive_log_budget_mib" => {
                if let Ok(parsed) = value.parse::<u32>() {
                    preferences.archive_log_budget_mib = parsed;
                }
            }
            // Persisted notification-dismiss signature. Free-form single-line
            // value (sorted exe patterns joined with `|`); empty is a valid
            // "never dismissed" state, so no non-empty gate.
            "unenforced_apps_ack_signature" => {
                preferences.unenforced_apps_ack_signature = value.to_string();
            }
            // Confirmed VPN executable path. Free-form single-line value;
            // empty is the valid "not set" state, so no non-empty gate.
            "confirmed_vpn_exe_path" => {
                preferences.confirmed_vpn_exe_path = value.to_string();
            }
            // Semicolon-joined list of confirmed VPN executables. Free-form
            // single-line value; empty is the valid "none" state, so no
            // non-empty gate.
            "confirmed_vpn_exe_paths" => {
                preferences.confirmed_vpn_exe_paths = value.to_string();
            }
            "selected_primary_interface_name" => {
                preferences.selected_primary_interface_name = value.to_string();
            }
            "selected_primary_interface_id" => {
                preferences.selected_primary_interface_id = value.to_string();
            }
            "primary_role_user_confirmed" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.primary_role_user_confirmed = parsed;
                }
            }
            "selected_secondary_interface_name" => {
                preferences.selected_secondary_interface_name = value.to_string();
            }
            "selected_secondary_interface_id" => {
                preferences.selected_secondary_interface_id = value.to_string();
            }
            "secondary_role_user_confirmed" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.secondary_role_user_confirmed = parsed;
                }
            }
            "route_behavior_mode" => {
                if let Ok(parsed) = value.parse::<RouteBehaviorMode>() {
                    preferences.route_behavior_mode = parsed;
                }
            }
            "block_secondary_traffic_when_unavailable" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.block_secondary_traffic_when_unavailable = parsed;
                }
            }
            "rules_view_sort" => {
                if let Ok(parsed) = value.parse::<RulesViewSort>() {
                    preferences.rules_view_sort = parsed;
                }
            }
            "rules_file_change_behavior" => {
                if let Ok(parsed) = value.parse::<RulesFileChangeBehavior>() {
                    preferences.rules_file_change_behavior = parsed;
                }
            }
            "last_rules_primary_file_hash" => {
                preferences.last_rules_primary_file_hash = value.to_string();
            }
            "last_rules_secondary_file_hash" => {
                preferences.last_rules_secondary_file_hash = value.to_string();
            }
            "import_both_files_together" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.import_both_files_together = parsed;
                }
            }
            "zone_priority_over_ip" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.zone_priority_over_ip = parsed;
                }
            }
            "log_level" => {
                if let Ok(parsed) = value.parse::<LogLevel>() {
                    preferences.log_level = parsed;
                }
            }
            "browser_stub_experimental_enabled" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.browser_stub_experimental_enabled = parsed;
                }
            }
            // File-source state. Empty value parses as `None` (the sentinel
            // for "not yet recorded"); any non-empty string parses as
            // `Some`.
            "last_saved_path_primary" => {
                preferences.last_saved_path_primary = parse_optional_string(value);
            }
            "last_saved_path_secondary" => {
                preferences.last_saved_path_secondary = parse_optional_string(value);
            }
            // Display-only source paths (may point inside the bundled tree).
            "last_loaded_path_primary" => {
                preferences.last_loaded_path_primary = parse_optional_string(value);
            }
            "last_loaded_path_secondary" => {
                preferences.last_loaded_path_secondary = parse_optional_string(value);
            }
            "auto_open_on_launch_path_primary" => {
                preferences.auto_open_on_launch_path_primary = parse_optional_string(value);
            }
            "auto_open_on_launch_path_secondary" => {
                preferences.auto_open_on_launch_path_secondary = parse_optional_string(value);
            }
            "last_file_synced_revision_id_primary" => {
                preferences.last_file_synced_revision_id_primary = parse_optional_string(value);
            }
            "last_file_synced_revision_id_secondary" => {
                preferences.last_file_synced_revision_id_secondary = parse_optional_string(value);
            }
            "last_file_synced_hash_primary" => {
                preferences.last_file_synced_hash_primary = parse_optional_string(value);
            }
            "last_file_synced_hash_secondary" => {
                preferences.last_file_synced_hash_secondary = parse_optional_string(value);
            }
            "service_install_uac_declined_at_epoch" => {
                preferences.service_install_uac_declined_at_epoch = parse_optional_i64(value);
            }
            "service_install_uac_declined_count" => {
                if let Ok(parsed) = value.parse::<u32>() {
                    preferences.service_install_uac_declined_count = parsed;
                }
            }
            "auto_load_rules_on_launch" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.auto_load_rules_on_launch = parsed;
                }
            }
            "export_include_comments" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.export_include_comments = parsed;
                }
            }
            "import_only_active" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.import_only_active = parsed;
                }
            }
            "compat_banner_mode" => {
                // Constrain to the known slugs; anything else falls back
                // to the default already in `preferences`.
                if matches!(value, "auto" | "always" | "never") {
                    preferences.compat_banner_mode = value.to_string();
                }
            }
            "update_page_url" => {
                preferences.update_page_url = value.to_string();
            }
            "show_bundled_presets" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.show_bundled_presets = parsed;
                }
            }
            // User-owned rule-set folder for the quick-load dropdown.
            // Free-form single-line path; empty is the valid "use the sets
            // shipped with the app" state, so no non-empty gate.
            "user_presets_dir" => {
                preferences.user_presets_dir = value.to_string();
            }
            // The remembered quick-load selection, `<source>:<label>`. Kept
            // free-form: the label is a folder name the user controls, and the
            // GUI already ignores a value whose set is gone.
            "selected_preset_set" => {
                preferences.selected_preset_set = value.to_string();
            }
            // Persisted per-adapter VPN-split banner ack. Free-form adapter
            // display name; empty = never acknowledged.
            "secondary_split_ack_adapter_name" => {
                preferences.secondary_split_ack_adapter_name = value.to_string();
            }
            // Merge-conflict resolution policy. Constrain to the known
            // slugs; anything else keeps the default ("union").
            "merge_conflict_policy" => {
                if matches!(value, "union" | "file-wins" | "service-wins") {
                    preferences.merge_conflict_policy = value.to_string();
                }
            }
            // Device-local mirrors of per-SID policy toggles. Missing keys
            // fall through to the struct defaults.
            "route_include_subdomains" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.route_include_subdomains = parsed;
                }
            }
            "route_shared_ip_policy" => {
                if !value.is_empty() {
                    preferences.route_shared_ip_policy = value.to_string();
                }
            }
            "route_kill_switch_block_all" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.route_kill_switch_block_all = parsed;
                }
            }
            "route_kill_switch_fail_closed" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.route_kill_switch_fail_closed = parsed;
                }
            }
            "route_kill_switch_protocols" => {
                if let Ok(parsed) = value.parse::<u32>() {
                    preferences.route_kill_switch_protocols = parsed & 0x7F;
                }
            }
            "route_kill_switch_enabled" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.route_kill_switch_enabled = parsed;
                }
            }
            "route_allow_dns_over_primary" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.route_allow_dns_over_primary = parsed;
                }
            }
            "route_mode_a_coverage_strategy" => {
                if matches!(value, "per-ip" | "fail-closed-unknown" | "zone-widening") {
                    preferences.route_mode_a_coverage_strategy = value.to_string();
                }
            }
            "route_resolve_hosts_bypass" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.route_resolve_hosts_bypass = parsed;
                }
            }
            "route_enforcement_mode" => {
                if matches!(value, "reactive" | "resolver") {
                    preferences.route_enforcement_mode = value.to_string();
                }
            }
            "route_liveness_window_secs" => {
                if let Ok(parsed) = value.parse::<u32>() {
                    preferences.route_liveness_window_secs = clamp_liveness_window_secs(parsed);
                }
            }
            "route_pending_offline_json" => {
                if is_plausible_pending_offline_json(value) {
                    preferences.route_pending_offline_json = value.to_string();
                }
            }
            "allow_saving_into_bundled_presets" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.allow_saving_into_bundled_presets = parsed;
                }
            }
            "rules_folder_suggestion_dismissed" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.rules_folder_suggestion_dismissed = parsed;
                }
            }
            "cache_table_column_widths" => {
                if is_plausible_pending_offline_json(value) {
                    preferences.cache_table_column_widths = value.to_string();
                }
            }
            // Last-known service-owned values, mirrored for display while the
            // service is stopped. Same opaque single-line-object gate as the
            // two blobs above.
            "service_backed_mirror_json" => {
                if is_plausible_pending_offline_json(value) {
                    preferences.service_backed_mirror_json = value.to_string();
                }
            }
            // What the user decided the service-owned settings should be.
            // Same opaque single-line-object gate as the mirror above.
            "service_intent_json" => {
                if is_plausible_pending_offline_json(value) {
                    preferences.service_intent_json = value.to_string();
                }
            }
            _ => {}
        }
    }

    normalize_theme_preferences(&mut preferences);
    preferences
}

/// Structural sanity gate for the opaque pending-offline JSON blob
/// (ui-support deliberately has no JSON dependency; the QML
/// side owns the schema). Accepts an empty string (= none) or a single-line
/// `{…}` object up to 8 KiB — plenty for every routing field with headroom,
/// small enough that a corrupted preferences file cannot balloon memory.
/// Rejects any embedded newline (L3 review-fix): the value lives on ONE
/// `key=value` line, so a `\n`/`\r` would split it into bogus extra lines on
/// the next read — reject rather than corrupt the line-oriented file.
fn is_plausible_pending_offline_json(value: &str) -> bool {
    value.is_empty()
        || (value.len() <= 8 * 1024
            && value.starts_with('{')
            && value.ends_with('}')
            && !value.contains(['\n', '\r']))
}

fn normalize_theme_preferences(preferences: &mut UiPreferences) {
    // Backward compatibility: legacy persisted flag may still be true even when
    // theme_mode was stored before high-contrast became a dedicated mode.
    if preferences.accessibility_high_contrast && preferences.theme_mode != ThemeMode::HighContrast
    {
        preferences.theme_mode = ThemeMode::HighContrast;
    }

    // Keep compatibility flag as a derived mirror of selected mode.
    preferences.accessibility_high_contrast = preferences.theme_mode == ThemeMode::HighContrast;
}

// `format_preferences` continues to write the legacy policy-affecting
// fields. After `cleanup_legacy_policy_fields` zeroes them, the persisted
// file carries only default values for those keys; older readers (if any
// survive) parse them as defaults without misbehaviour. Removing the keys
// from disk is a future concern.
#[allow(deprecated)]
fn format_preferences(preferences: &UiPreferences) -> String {
    format!(
        concat!(
            "# NetRuleRouter managed UI preferences\n",
            "schema_version={}\n",
            "launch_window_on_startup={}\n",
            "minimize_to_tray_instead_of_close={}\n",
            "show_notifications={}\n",
            "notify_suggestion_changes={}\n",
            "reopen_last_section_on_startup={}\n",
            "first_run_completed={}\n",
            "accepted_eula_version={}\n",
            "theme_mode={}\n",
            "accessibility_high_contrast={}\n",
            "accessibility_ui_font_scale_percent={}\n",
            "accessibility_system_font={}\n",
            "accessibility_enhanced_focus_indicator={}\n",
            "accessibility_simplified_labels={}\n",
            "tooltips_enabled={}\n",
            "language={}\n",
            "route_primary_label={}\n",
            "route_secondary_label={}\n",
            "show_bluetooth_adapters={}\n",
            "show_audit_tab={}\n",
            "admin_auto_revoke_disabled={}\n",
            "admin_auto_revoke_minutes={}\n",
            "settings_autosave_secs={}\n",
            "allow_mode_a_killswitch={}\n",
            "routing_detailed_mode={}\n",
            "show_remembered_adapters={}\n",
            "selected_primary_interface_id={}\n",
            "selected_primary_interface_name={}\n",
            "primary_role_user_confirmed={}\n",
            "selected_secondary_interface_id={}\n",
            "selected_secondary_interface_name={}\n",
            "secondary_role_user_confirmed={}\n",
            "route_behavior_mode={}\n",
            "block_secondary_traffic_when_unavailable={}\n",
            "last_opened_section={}\n",
            "rules_view_sort={}\n",
            "rules_file_change_behavior={}\n",
            "last_rules_primary_file_hash={}\n",
            "last_rules_secondary_file_hash={}\n",
            "import_both_files_together={}\n",
            "zone_priority_over_ip={}\n",
            "log_level={}\n",
            "browser_stub_experimental_enabled={}\n",
            "last_saved_path_primary={}\n",
            "last_saved_path_secondary={}\n",
            "auto_open_on_launch_path_primary={}\n",
            "auto_open_on_launch_path_secondary={}\n",
            "last_file_synced_revision_id_primary={}\n",
            "last_file_synced_revision_id_secondary={}\n",
            "last_file_synced_hash_primary={}\n",
            "last_file_synced_hash_secondary={}\n",
            "service_install_uac_declined_at_epoch={}\n",
            "service_install_uac_declined_count={}\n",
            "auto_load_rules_on_launch={}\n",
            "export_include_comments={}\n",
            "import_only_active={}\n",
            "compat_banner_mode={}\n",
            "update_page_url={}\n",
            "show_bundled_presets={}\n",
            "user_presets_dir={}\n",
            "selected_preset_set={}\n",
            "merge_conflict_policy={}\n",
            "auto_confirm_adapter_id_change={}\n",
            "warn_kill_switch_block_all={}\n",
            "kill_switch_banner_acknowledged={}\n",
            "missing_secondary_banner_acknowledged={}\n",
            "traffic_stats_period={}\n",
            "traffic_export_unit={}\n",
            "diagnostics_archive_redaction_level={}\n",
            "diagnostics_archive_session_only={}\n",
            "archive_log_budget_mib={}\n",
            "secondary_split_ack_adapter_name={}\n",
            "route_include_subdomains={}\n",
            "route_shared_ip_policy={}\n",
            "route_kill_switch_block_all={}\n",
            "route_kill_switch_fail_closed={}\n",
            "route_kill_switch_protocols={}\n",
            "route_kill_switch_enabled={}\n",
            "route_allow_dns_over_primary={}\n",
            "route_mode_a_coverage_strategy={}\n",
            "route_resolve_hosts_bypass={}\n",
            "route_enforcement_mode={}\n",
            "route_liveness_window_secs={}\n",
            "route_pending_offline_json={}\n",
            "allow_saving_into_bundled_presets={}\n",
            "rules_folder_suggestion_dismissed={}\n",
            "cache_table_column_widths={}\n",
            "service_backed_mirror_json={}\n",
            "service_intent_json={}\n",
            "unenforced_apps_ack_signature={}\n",
            "confirmed_vpn_exe_path={}\n",
            "confirmed_vpn_exe_paths={}\n",
            "last_loaded_path_primary={}\n",
            "last_loaded_path_secondary={}\n",
            "notify_block_notices={}\n",
            "hide_block_notice_addresses={}\n",
            "pre_flight_apply_policy_opt_in={}\n"
        ),
        CURRENT_UI_PREFS_SCHEMA_VERSION,
        preferences.launch_window_on_startup,
        preferences.minimize_to_tray_instead_of_close,
        preferences.show_notifications,
        preferences.notify_suggestion_changes,
        preferences.reopen_last_section_on_startup,
        preferences.first_run_completed,
        preferences.accepted_eula_version,
        preferences.theme_mode,
        preferences.accessibility_high_contrast,
        preferences.accessibility_ui_font_scale_percent,
        preferences.accessibility_system_font,
        preferences.accessibility_enhanced_focus_indicator,
        preferences.accessibility_simplified_labels,
        preferences.tooltips_enabled,
        preferences.language,
        preferences.route_primary_label,
        preferences.route_secondary_label,
        preferences.show_bluetooth_adapters,
        preferences.show_audit_tab,
        preferences.admin_auto_revoke_disabled,
        preferences.admin_auto_revoke_minutes,
        preferences.settings_autosave_secs,
        preferences.allow_mode_a_killswitch,
        preferences.routing_detailed_mode,
        preferences.show_remembered_adapters,
        preferences.selected_primary_interface_id,
        preferences.selected_primary_interface_name,
        preferences.primary_role_user_confirmed,
        preferences.selected_secondary_interface_id,
        preferences.selected_secondary_interface_name,
        preferences.secondary_role_user_confirmed,
        preferences.route_behavior_mode,
        preferences.block_secondary_traffic_when_unavailable,
        preferences.last_opened_section,
        preferences.rules_view_sort,
        preferences.rules_file_change_behavior,
        preferences.last_rules_primary_file_hash,
        preferences.last_rules_secondary_file_hash,
        preferences.import_both_files_together,
        preferences.zone_priority_over_ip,
        preferences.log_level,
        preferences.browser_stub_experimental_enabled,
        optional_string_field(&preferences.last_saved_path_primary),
        optional_string_field(&preferences.last_saved_path_secondary),
        optional_string_field(&preferences.auto_open_on_launch_path_primary),
        optional_string_field(&preferences.auto_open_on_launch_path_secondary),
        optional_string_field(&preferences.last_file_synced_revision_id_primary),
        optional_string_field(&preferences.last_file_synced_revision_id_secondary),
        optional_string_field(&preferences.last_file_synced_hash_primary),
        optional_string_field(&preferences.last_file_synced_hash_secondary),
        optional_i64_field(preferences.service_install_uac_declined_at_epoch),
        preferences.service_install_uac_declined_count,
        preferences.auto_load_rules_on_launch,
        preferences.export_include_comments,
        preferences.import_only_active,
        preferences.compat_banner_mode,
        preferences.update_page_url,
        preferences.show_bundled_presets,
        preferences.user_presets_dir,
        preferences.selected_preset_set,
        preferences.merge_conflict_policy,
        preferences.auto_confirm_adapter_id_change,
        preferences.warn_kill_switch_block_all,
        preferences.kill_switch_banner_acknowledged,
        preferences.missing_secondary_banner_acknowledged,
        preferences.traffic_stats_period,
        preferences.traffic_export_unit,
        preferences.diagnostics_archive_redaction_level,
        preferences.diagnostics_archive_session_only,
        preferences.archive_log_budget_mib,
        preferences.secondary_split_ack_adapter_name,
        preferences.route_include_subdomains,
        preferences.route_shared_ip_policy,
        preferences.route_kill_switch_block_all,
        preferences.route_kill_switch_fail_closed,
        preferences.route_kill_switch_protocols,
        preferences.route_kill_switch_enabled,
        preferences.route_allow_dns_over_primary,
        preferences.route_mode_a_coverage_strategy,
        preferences.route_resolve_hosts_bypass,
        preferences.route_enforcement_mode,
        preferences.route_liveness_window_secs,
        preferences.route_pending_offline_json,
        preferences.allow_saving_into_bundled_presets,
        preferences.rules_folder_suggestion_dismissed,
        preferences.cache_table_column_widths,
        preferences.service_backed_mirror_json,
        preferences.service_intent_json,
        preferences.unenforced_apps_ack_signature,
        preferences.confirmed_vpn_exe_path,
        preferences.confirmed_vpn_exe_paths,
        optional_string_field(&preferences.last_loaded_path_primary),
        optional_string_field(&preferences.last_loaded_path_secondary),
        preferences.notify_block_notices,
        preferences.hide_block_notice_addresses,
        preferences.pre_flight_apply_policy_opt_in
    )
}

/// Format an `Option<i64>` for the preferences file. `None` → empty
/// string; `Some(n)` → decimal. Matching parser is [`parse_optional_i64`].
fn optional_i64_field(value: Option<i64>) -> String {
    match value {
        None => String::new(),
        Some(n) => n.to_string(),
    }
}

/// Format an `Option<String>` for the preferences file. `None` → empty
/// string; `Some(s)` → trimmed value as-is. The matching parser
/// ([`parse_optional_string`]) treats empty as `None`.
fn optional_string_field(value: &Option<String>) -> &str {
    value.as_deref().unwrap_or("")
}

/// Parse an `Option<String>` from a preferences value. Empty string (and
/// pure whitespace) → `None`; otherwise the trimmed value wrapped in
/// `Some`. Mirrors the on-disk convention that absent = empty `key=`
/// line = "not recorded yet".
fn parse_optional_string(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Parse an `Option<i64>` from a preferences value. Empty string →
/// `None`; non-empty parsed via `str::parse::<i64>`. A malformed value
/// also yields `None` (silently — same lenient policy the rest of the
/// parser follows).
fn parse_optional_i64(value: &str) -> Option<i64> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        trimmed.parse::<i64>().ok()
    }
}

fn parse_bool(value: &str) -> Option<bool> {
    match value {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

fn parse_font_scale_percent(value: &str) -> Option<u16> {
    let parsed = value.parse::<u16>().ok()?;
    if (80..=300).contains(&parsed) {
        Some(parsed)
    } else {
        None
    }
}

/// Reset the eight policy-affecting fields that were migrated into
/// service-owned per-SID storage. After this call every legacy policy
/// field on `prefs` matches `Default::default()`, so a subsequent
/// `format_preferences` produces a file without stale data (or,
/// equivalently, with zero/empty values that older readers parse as
/// defaults).
///
/// The launcher's GUI migration flow calls this **after** a successful
/// `RoutePolicyUpdate` + `MigrationMarkComplete` round-trip. Idempotent:
/// calling it on already-cleaned-up preferences is a no-op.
///
/// The eight fields covered:
/// 1. `selected_primary_interface_id`
/// 2. `selected_primary_interface_name`
/// 3. `primary_role_user_confirmed`
/// 4. `selected_secondary_interface_id`
/// 5. `selected_secondary_interface_name`
/// 6. `secondary_role_user_confirmed`
/// 7. `route_behavior_mode`
/// 8. `block_secondary_traffic_when_unavailable`
///
/// Non-policy UI preferences (theme, language, fonts, route labels,
/// section selections, rules-view filters, …) are **not** touched.
#[allow(deprecated)]
pub fn cleanup_legacy_policy_fields(prefs: &mut UiPreferences) {
    prefs.selected_primary_interface_id = String::new();
    prefs.selected_primary_interface_name = String::new();
    prefs.primary_role_user_confirmed = false;
    prefs.selected_secondary_interface_id = String::new();
    prefs.selected_secondary_interface_name = String::new();
    prefs.secondary_role_user_confirmed = false;
    prefs.route_behavior_mode = RouteBehaviorMode::default_when_secondary_unbound();
    prefs.block_secondary_traffic_when_unavailable = false;
}

/// Snapshot of the eight legacy policy-affecting fields, used by the
/// launcher migration flow to decide whether the user has any
/// pre-16.8 data worth migrating before running cleanup.
///
/// Returns `true` if **any** of the eight fields is set to a non-default
/// value — i.e. the user previously configured route bindings, behavior
/// mode, or the secondary-block flag through the legacy GUI path.
#[allow(deprecated)]
pub fn has_legacy_policy_fields(prefs: &UiPreferences) -> bool {
    !prefs.selected_primary_interface_id.is_empty()
        || !prefs.selected_primary_interface_name.is_empty()
        || prefs.primary_role_user_confirmed
        || !prefs.selected_secondary_interface_id.is_empty()
        || !prefs.selected_secondary_interface_name.is_empty()
        || prefs.secondary_role_user_confirmed
        || prefs.route_behavior_mode != RouteBehaviorMode::default_when_secondary_unbound()
        || prefs.block_secondary_traffic_when_unavailable
}

#[cfg(test)]
#[allow(deprecated)] // Tests exercise the legacy policy fields directly;
                     // new readers should use IPC SnapshotInitial.routePolicy.
mod tests {
    use super::{
        check_schema_version_compat, cleanup_legacy_policy_fields, has_legacy_policy_fields,
        parse_preferences, preferred_available_language, SystemFontFamily, UiPreferences,
        UiPreferencesStore, CURRENT_UI_PREFS_SCHEMA_VERSION, LEGACY_PREFERENCES_FILE_NAMES,
        STABLE_PREFERENCES_FILE_NAME,
    };
    use nrr_shared::{
        AppSection, LogLevel, RouteBehaviorMode, RulesEnabledFilter, RulesFileChangeBehavior,
        RulesTypeFilter, RulesViewSort, ThemeMode,
    };
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn defaults_are_loaded_when_store_file_is_missing() {
        let (_dir, path) = test_path("missing.conf");
        let store = UiPreferencesStore::for_path(path);
        let loaded = store
            .load()
            .unwrap_or_else(|error| panic!("load should succeed for missing file: {error}"));
        assert_eq!(loaded, UiPreferences::default());
    }

    #[test]
    fn parser_ignores_unknown_keys_and_preserves_known_values() {
        let parsed = parse_preferences(concat!(
            "theme_mode=high-contrast\n",
            "accessibility_high_contrast=true\n",
            "accessibility_ui_font_scale_percent=125\n",
            "accessibility_system_font=segoe-ui\n",
            "accessibility_enhanced_focus_indicator=true\n",
            "accessibility_simplified_labels=true\n",
            "tooltips_enabled=true\n",
            "first_run_completed=true\n",
            "language=en\n",
            "route_primary_label=Main\n",
            "route_secondary_label=Alternative\n",
            "last_opened_section=logs\n",
            "unknown_key=ignored\n"
        ));
        assert_eq!(parsed.theme_mode, ThemeMode::HighContrast);
        assert!(parsed.accessibility_high_contrast);
        assert_eq!(parsed.accessibility_ui_font_scale_percent, 125);
        assert_eq!(parsed.accessibility_system_font, SystemFontFamily::SegoeUi);
        assert!(parsed.accessibility_enhanced_focus_indicator);
        assert!(parsed.accessibility_simplified_labels);
        assert!(parsed.tooltips_enabled);
        assert!(parsed.first_run_completed);
        assert_eq!(parsed.language, "en");
        assert_eq!(parsed.route_primary_label, "Main");
        assert_eq!(parsed.route_secondary_label, "Alternative");
        assert_eq!(parsed.last_opened_section, AppSection::Logs);
    }

    #[test]
    fn accepted_eula_version_defaults_to_zero_and_round_trips() {
        // Absent key → not accepted (0), so a pre-EULA preferences file
        // re-prompts the agreement on load.
        let none = parse_preferences("theme_mode=system\n");
        assert_eq!(
            none.accepted_eula_version,
            nrr_shared::eula::EULA_NOT_ACCEPTED
        );
        assert!(!nrr_shared::eula::is_accepted(none.accepted_eula_version));

        // Present key parses; a garbage value leaves the default untouched.
        let accepted = parse_preferences("accepted_eula_version=1\n");
        assert_eq!(accepted.accepted_eula_version, 1);
        let garbage = parse_preferences("accepted_eula_version=not-a-number\n");
        assert_eq!(
            garbage.accepted_eula_version,
            nrr_shared::eula::EULA_NOT_ACCEPTED
        );
    }

    #[test]
    fn block_notice_prefs_default_when_key_absent() {
        // A file saved before these keys existed must still load cleanly,
        // with both fields falling back to their type defaults.
        let parsed = parse_preferences("theme_mode=system\n");
        assert!(parsed.notify_block_notices);
        assert!(!parsed.hide_block_notice_addresses);
    }

    #[test]
    fn block_notice_prefs_parse_explicit_values() {
        let parsed = parse_preferences(concat!(
            "notify_block_notices=false\n",
            "hide_block_notice_addresses=true\n"
        ));
        assert!(!parsed.notify_block_notices);
        assert!(parsed.hide_block_notice_addresses);
    }

    #[test]
    fn pre_flight_apply_policy_opt_in_defaults_when_key_absent() {
        // A file saved before this key existed must still load cleanly,
        // with the field falling back to its type default (opted out).
        let parsed = parse_preferences("theme_mode=system\n");
        assert!(!parsed.pre_flight_apply_policy_opt_in);
    }

    #[test]
    fn pre_flight_apply_policy_opt_in_parses_explicit_value() {
        let parsed = parse_preferences("pre_flight_apply_policy_opt_in=true\n");
        assert!(parsed.pre_flight_apply_policy_opt_in);
    }

    #[test]
    fn parser_reads_confirmed_role_fields() {
        let parsed = parse_preferences(concat!(
            "show_bluetooth_adapters=true\n",
            "selected_primary_interface_id=win-adapter:ethernet\n",
            "selected_primary_interface_name=Ethernet\n",
            "primary_role_user_confirmed=true\n",
            "selected_secondary_interface_id=win-adapter:vpn\n",
            "selected_secondary_interface_name=VPN\n",
            "secondary_role_user_confirmed=true\n"
        ));
        assert!(parsed.show_bluetooth_adapters);
        assert_eq!(parsed.selected_primary_interface_id, "win-adapter:ethernet");
        assert_eq!(parsed.selected_primary_interface_name, "Ethernet");
        assert!(parsed.primary_role_user_confirmed);
        assert_eq!(parsed.selected_secondary_interface_id, "win-adapter:vpn");
        assert_eq!(parsed.selected_secondary_interface_name, "VPN");
        assert!(parsed.secondary_role_user_confirmed);
    }

    #[test]
    fn save_then_load_roundtrip_is_stable() {
        let (_dir, path) = test_path("roundtrip.conf");
        let store = UiPreferencesStore::for_path(path.clone());
        let expected = UiPreferences {
            launch_window_on_startup: false,
            minimize_to_tray_instead_of_close: true,
            show_notifications: false,
            notify_suggestion_changes: false,
            // Non-default (default is true) — proves the field persists.
            notify_block_notices: false,
            // Non-default (default is false) — proves the field persists.
            hide_block_notice_addresses: true,
            reopen_last_section_on_startup: true,
            first_run_completed: true,
            accepted_eula_version: 1,
            theme_mode: ThemeMode::HighContrast,
            accessibility_high_contrast: true,
            accessibility_ui_font_scale_percent: 140,
            accessibility_system_font: SystemFontFamily::Verdana,
            accessibility_enhanced_focus_indicator: true,
            accessibility_simplified_labels: true,
            tooltips_enabled: true,
            language: "en".to_string(),
            route_primary_label: "Main".to_string(),
            route_secondary_label: "Alternative".to_string(),
            show_bluetooth_adapters: true,
            // Non-default (default is false) — proves the field persists.
            show_audit_tab: true,
            // Non-default (default is 60) — proves the field persists.
            settings_autosave_secs: 120,
            admin_auto_revoke_disabled: true,
            admin_auto_revoke_minutes: 45,
            // Non-default (default is false) — proves the field persists.
            allow_mode_a_killswitch: true,
            // Non-default (default is false) — proves the field persists.
            pre_flight_apply_policy_opt_in: true,
            // Non-default (default is false) — proves the field persists.
            routing_detailed_mode: true,
            // Non-default (default is true) so the round-trip test proves the
            // field actually persists rather than reading the default.
            show_remembered_adapters: false,
            auto_confirm_adapter_id_change: false,
            // Non-default (default is true) — proves the field persists.
            warn_kill_switch_block_all: false,
            // Non-default (default is false) — proves the field persists.
            kill_switch_banner_acknowledged: true,
            // Non-default (default is false) — proves the field persists.
            missing_secondary_banner_acknowledged: true,
            // Non-default (default is "today") — proves the field persists.
            traffic_stats_period: "session".to_string(),
            // Non-default (default is "mb") — proves the field persists.
            traffic_export_unit: "gb".to_string(),
            // Non-default values (defaults: "standard" / true) — prove the
            // support-archive export options persist across save/load.
            diagnostics_archive_redaction_level: "diagnostics".to_string(),
            diagnostics_archive_session_only: false,
            // Non-default (default is 0 = unlimited) — proves the field persists.
            archive_log_budget_mib: 64,
            selected_primary_interface_id: "win-adapter:ethernet".to_string(),
            selected_primary_interface_name: "Ethernet".to_string(),
            primary_role_user_confirmed: true,
            selected_secondary_interface_id: "win-adapter:vpn".to_string(),
            selected_secondary_interface_name: "VPN".to_string(),
            secondary_role_user_confirmed: true,
            route_behavior_mode: RouteBehaviorMode::PreferSecondaryWhenAvailable,
            block_secondary_traffic_when_unavailable: true,
            last_opened_section: AppSection::Settings,
            rules_view_sort: RulesViewSort::ByMatchValue,
            // Non-persisted — always resets to default on reload.
            rules_enabled_filter: RulesEnabledFilter::default(),
            rules_type_filter: RulesTypeFilter::default(),
            rules_file_change_behavior: RulesFileChangeBehavior::AutoApply,
            last_rules_primary_file_hash: "aabbcc".repeat(10).chars().take(64).collect(),
            last_rules_secondary_file_hash: String::new(),
            import_both_files_together: true,
            zone_priority_over_ip: true,
            log_level: LogLevel::Debug,
            browser_stub_experimental_enabled: true,
            // File-source state. Mixed Some/None so the round-trip
            // exercises both serialise paths.
            last_saved_path_primary: Some(r"C:\rules_primary.txt".to_string()),
            last_saved_path_secondary: None,
            // Display-only source paths — a bundled-tree path is legal here
            // (read-only source), so the round-trip proves it persists.
            last_loaded_path_primary: Some(
                r"C:\Program Files\NetRuleRouter\presets\ru\pack\rules_primary.txt".to_string(),
            ),
            last_loaded_path_secondary: None,
            auto_open_on_launch_path_primary: Some(r"C:\rules_primary.txt".to_string()),
            auto_open_on_launch_path_secondary: None,
            last_file_synced_revision_id_primary: Some("rev-abc-123".to_string()),
            last_file_synced_revision_id_secondary: None,
            last_file_synced_hash_primary: Some("deadbeef".repeat(8)),
            last_file_synced_hash_secondary: None,
            // Exercise both serialise paths for the UAC decline state.
            service_install_uac_declined_at_epoch: Some(1_700_000_123),
            service_install_uac_declined_count: 2,
            // Non-default values so the round-trip proves they persist.
            auto_load_rules_on_launch: false,
            export_include_comments: false,
            import_only_active: false,
            compat_banner_mode: "always".to_string(),
            update_page_url: "https://example.test/releases".to_string(),
            show_bundled_presets: false,
            // Non-default path (with spaces + backslashes) so the round-trip
            // proves the user-owned rule-set folder persists.
            user_presets_dir: "D:\\My Rule Sets".to_string(),
            // A label with a space and a colon-free body, so the round-trip
            // proves the `<source>:<label>` selection survives verbatim.
            selected_preset_set: "user:My corporate set".to_string(),
            allow_saving_into_bundled_presets: true,
            rules_folder_suggestion_dismissed: true,
            // Non-default value so the round-trip proves the merge-conflict
            // policy persists.
            merge_conflict_policy: "service-wins".to_string(),
            // Non-default value so the round-trip proves the VPN-split
            // banner ack persists.
            secondary_split_ack_adapter_name: "hidemy.name VPN 3.0".to_string(),
            // Non-default values so the round-trip proves the per-SID
            // policy mirrors persist across save/load. Subdomain coverage
            // defaults to `true`, so `false` is the non-default value this
            // round-trip must prove persists.
            route_include_subdomains: false,
            route_shared_ip_policy: "any-rule-domain".to_string(),
            route_kill_switch_block_all: true,
            route_kill_switch_fail_closed: false,
            route_kill_switch_protocols: 123,
            route_kill_switch_enabled: true,
            // Default is true; false is the non-default value the
            // round-trip must prove persists.
            route_allow_dns_over_primary: false,
            // Non-default values (defaults: fail-closed-unknown / true) so
            // the round-trip proves these mirrors persist.
            route_mode_a_coverage_strategy: "per-ip".to_string(),
            route_resolve_hosts_bypass: false,
            route_enforcement_mode: "resolver".to_string(),
            // Non-default value inside the clamp range so the round-trip
            // proves the liveness window persists across save/load.
            route_liveness_window_secs: 90,
            // Non-empty compact JSON so the round-trip proves the
            // pending-offline intents blob persists.
            route_pending_offline_json:
                r#"{"killSwitchEnabled":true,"enforcementMode":"resolver"}"#.to_string(),
            // Cache-viewer column widths — non-empty compact JSON so the
            // round-trip proves the persisted column widths survive save/load.
            cache_table_column_widths: r#"{"ip":140,"freshness":90,"source":160}"#.to_string(),
            // Non-empty compact JSON so the round-trip proves the last-known
            // service-owned values survive save/load (the display source while
            // the service is stopped).
            service_backed_mirror_json:
                r#"{"route-policy":{"doh-lockdown-enabled":true},"stability":{"fake-ip-enabled":true}}"#
                    .to_string(),
            // Non-empty compact JSON so the round-trip proves the user's
            // service-setting intent survives save/load — losing it is what
            // let a wiped service DB overwrite the user's choices.
            service_intent_json:
                r#"{"stability":{"verbose-logging":true,"fake-ip-enabled":true}}"#.to_string(),
            // Non-empty signature so the round-trip proves the
            // notification-dismiss state persists across GUI restarts.
            unenforced_apps_ack_signature: "2gis.exe|hidemy.name VPN 3.0.exe".to_string(),
            // Non-empty path (with spaces + backslashes) so the round-trip
            // proves the confirmed VPN executable persists.
            confirmed_vpn_exe_path: "C:\\Program Files\\Example VPN\\vpn.exe".to_string(),
            // Non-empty semicolon-joined list so the round-trip proves the
            // multi-select VPN set persists. First entry mirrors
            // `confirmed_vpn_exe_path`.
            confirmed_vpn_exe_paths:
                "C:\\Program Files\\Example VPN\\vpn.exe;C:\\Program Files\\OpenVPN\\openvpn.exe"
                    .to_string(),
        };

        store
            .save(&expected)
            .unwrap_or_else(|error| panic!("save should succeed: {error}"));
        let loaded = store
            .load()
            .unwrap_or_else(|error| panic!("load should succeed after save: {error}"));
        assert_eq!(loaded, expected);

        if path.exists() {
            let _ = fs::remove_file(path);
        }
    }

    #[test]
    fn cis_locales_without_bundled_translation_fall_back_to_russian() {
        // A CIS system locale with no bundled translation resolves to
        // Russian; anything else unmatched resolves to English; exact
        // matches still win.
        assert_eq!(preferred_available_language("kk-kz"), "ru");
        assert_eq!(preferred_available_language("be"), "ru");
        assert_eq!(preferred_available_language("uz-latn-uz"), "ru");
        assert_eq!(preferred_available_language("de-de"), "en");
        assert_eq!(preferred_available_language("ro-md"), "en");
        assert_eq!(preferred_available_language("ru-ru"), "ru");
        assert_eq!(preferred_available_language("en-us"), "en");
    }

    #[test]
    fn parser_reads_block_secondary_and_rules_view_sort() {
        let parsed = parse_preferences(concat!(
            "block_secondary_traffic_when_unavailable=true\n",
            "rules_view_sort=by-match-value\n"
        ));
        assert!(parsed.block_secondary_traffic_when_unavailable);
        assert_eq!(parsed.rules_view_sort, RulesViewSort::ByMatchValue);
        // Non-persisted filters always reset to default.
        assert_eq!(parsed.rules_enabled_filter, RulesEnabledFilter::default());
        assert_eq!(parsed.rules_type_filter, RulesTypeFilter::default());
    }

    #[test]
    fn parser_gates_pending_offline_json_structurally() {
        // A single-line object blob is stored verbatim.
        let parsed = parse_preferences("route_pending_offline_json={\"a\":1}\n");
        assert_eq!(parsed.route_pending_offline_json, "{\"a\":1}");
        // Non-object junk is dropped (field stays at its empty default).
        let junk = parse_preferences("route_pending_offline_json=not-json\n");
        assert!(junk.route_pending_offline_json.is_empty());
        // Oversized payloads are dropped.
        let big = format!("route_pending_offline_json={{{}}}\n", "x".repeat(9000));
        assert!(parse_preferences(&big)
            .route_pending_offline_json
            .is_empty());
    }

    #[test]
    fn selected_preset_set_remembers_the_source_it_came_from() {
        // No choice yet is the only state that lets the shipped-set list pick
        // one by system locale, so the default must be empty.
        assert!(
            UiPreferences::default().selected_preset_set.is_empty(),
            "a fresh install has no remembered rule-set choice"
        );
        // The `<source>:<label>` pair is stored verbatim — labels are folder
        // names the user controls, spaces included.
        let parsed = parse_preferences("selected_preset_set=user:My corporate set\n");
        assert_eq!(parsed.selected_preset_set, "user:My corporate set");
        // The two lists can hold identical labels, so the source prefix is what
        // keeps a remembered choice from leaking across them.
        let bundled = parse_preferences("selected_preset_set=bundled:ru_osnovnoy-i-zarubezh\n");
        assert_eq!(
            bundled.selected_preset_set,
            "bundled:ru_osnovnoy-i-zarubezh"
        );
        // Explicit empty = "forget the choice"; key absent (older preferences
        // file) falls back to the same default.
        assert!(parse_preferences("selected_preset_set=\n")
            .selected_preset_set
            .is_empty());
        assert!(parse_preferences("theme_mode=light\n")
            .selected_preset_set
            .is_empty());
    }

    #[test]
    fn user_presets_dir_defaults_to_the_shipped_sets() {
        // Empty default = "list the sets shipped with the app".
        assert!(
            UiPreferences::default().user_presets_dir.is_empty(),
            "a fresh install must keep listing the shipped rule sets"
        );
        // A configured folder is stored verbatim, backslashes and spaces
        // included (Windows paths are the common case).
        let parsed = parse_preferences("user_presets_dir=D:\\My Rule Sets\\corp\n");
        assert_eq!(parsed.user_presets_dir, "D:\\My Rule Sets\\corp");
        // An explicit empty value is the honest "back to the shipped sets" state.
        assert!(parse_preferences("user_presets_dir=\n")
            .user_presets_dir
            .is_empty());
        // Key absent (older preferences file) falls back to the default.
        assert!(parse_preferences("theme_mode=light\n")
            .user_presets_dir
            .is_empty());
    }

    #[test]
    fn parser_gates_service_backed_mirror_structurally() {
        // The last-known service values ride the same opaque single-line-object
        // gate: a well-formed blob is stored verbatim, junk and oversized
        // payloads are dropped rather than corrupting the line-oriented file.
        let parsed = parse_preferences(
            "service_backed_mirror_json={\"stability\":{\"fake-ip-enabled\":true}}\n",
        );
        assert_eq!(
            parsed.service_backed_mirror_json,
            "{\"stability\":{\"fake-ip-enabled\":true}}"
        );
        let junk = parse_preferences("service_backed_mirror_json=not-json\n");
        assert!(junk.service_backed_mirror_json.is_empty());
        let big = format!("service_backed_mirror_json={{{}}}\n", "x".repeat(9000));
        assert!(parse_preferences(&big)
            .service_backed_mirror_json
            .is_empty());
    }

    #[test]
    fn parser_gates_service_intent_structurally() {
        // The user's service-setting intent rides the same opaque gate as the
        // mirror: it is replayed to the service on connect, so a corrupted
        // blob must degrade to "no intent recorded" rather than to a partial
        // object the QML side would replay as if the user had asked for it.
        let parsed =
            parse_preferences("service_intent_json={\"stability\":{\"verbose-logging\":true}}\n");
        assert_eq!(
            parsed.service_intent_json,
            "{\"stability\":{\"verbose-logging\":true}}"
        );
        let junk = parse_preferences("service_intent_json=not-json\n");
        assert!(junk.service_intent_json.is_empty());
        let big = format!("service_intent_json={{{}}}\n", "x".repeat(9000));
        assert!(parse_preferences(&big).service_intent_json.is_empty());
    }

    #[test]
    fn parser_reads_rules_file_change_behavior() {
        let parsed = parse_preferences("rules_file_change_behavior=auto-apply\n");
        assert_eq!(
            parsed.rules_file_change_behavior,
            RulesFileChangeBehavior::AutoApply
        );
        // Default is Notify.
        let defaults = parse_preferences("");
        assert_eq!(
            defaults.rules_file_change_behavior,
            RulesFileChangeBehavior::Notify
        );
    }

    #[test]
    fn legacy_high_contrast_flag_upgrades_theme_mode() {
        let parsed = parse_preferences(concat!(
            "theme_mode=light\n",
            "accessibility_high_contrast=true\n"
        ));
        assert_eq!(parsed.theme_mode, ThemeMode::HighContrast);
        assert!(parsed.accessibility_high_contrast);
    }

    #[test]
    fn legacy_file_is_migrated_to_stable_file_name() {
        let dir_handle = test_dir("migration-dir");
        let dir = dir_handle.path();
        let store = UiPreferencesStore {
            path: dir.join(STABLE_PREFERENCES_FILE_NAME),
            legacy_paths: vec![dir.join(LEGACY_PREFERENCES_FILE_NAMES[0])],
            is_profile_persistent: true,
        };
        let legacy_payload = "theme_mode=light\nlanguage=en\nroute_primary_label=Primary\nroute_secondary_label=Secondary\n";
        fs::write(&store.legacy_paths[0], legacy_payload)
            .unwrap_or_else(|error| panic!("legacy file write should succeed: {error}"));

        let loaded = store
            .load()
            .unwrap_or_else(|error| panic!("load should migrate and succeed: {error}"));
        assert_eq!(loaded.theme_mode, ThemeMode::Light);
        assert_eq!(loaded.language, "en");
        assert!(store.path.exists());
        assert!(!store.legacy_paths[0].exists());
    }

    #[test]
    fn schema_version_constant_is_current() {
        // Each schema bump is additive: older files load with the new
        // fields defaulted via the "missing key → default" path in
        // `parse_preferences`.
        assert_eq!(CURRENT_UI_PREFS_SCHEMA_VERSION, 11);
    }

    #[test]
    fn schema_version_written_on_save_is_parsed_without_panic() {
        // Verify that a freshly saved file has schema_version and loads back cleanly.
        let (_dir, path) = test_path("schema-version-roundtrip.conf");
        let store = UiPreferencesStore::for_path(path.clone());
        let prefs = UiPreferences::default();
        store
            .save(&prefs)
            .unwrap_or_else(|e| panic!("save should succeed: {e}"));
        let content =
            fs::read_to_string(&path).unwrap_or_else(|e| panic!("read should succeed: {e}"));
        let expected_version = format!("schema_version={CURRENT_UI_PREFS_SCHEMA_VERSION}");
        assert!(
            content.contains(&expected_version),
            "saved file must contain {expected_version}; got:\n{content}"
        );
        // No panic and no version warning for a known version.
        check_schema_version_compat(&content);
        // `_dir` drops here, removing the scratch directory and the conf file
        // together — no manual `fs::remove_file` needed.
    }

    /// A v1 preference file must load with the new fields all set to
    /// `None`. This is the migration-tolerant path: a schema bump
    /// doesn't require touching old files; missing keys parse as field
    /// defaults via the catch-all `_ => {}` arm in `parse_preferences`.
    #[test]
    fn v1_file_without_new_fields_loads_with_defaults() {
        let legacy_v1 = "\
schema_version=1
theme_mode=dark
language=ru
first_run_completed=true
";
        let parsed = parse_preferences(legacy_v1);
        // Fields present in the legacy file populate as expected.
        assert_eq!(parsed.theme_mode, ThemeMode::Dark);
        assert_eq!(parsed.language, "ru");
        assert!(parsed.first_run_completed);
        // Fields absent from the legacy file all default to None.
        assert!(parsed.last_saved_path_primary.is_none());
        assert!(parsed.last_saved_path_secondary.is_none());
        assert!(parsed.auto_open_on_launch_path_primary.is_none());
        assert!(parsed.auto_open_on_launch_path_secondary.is_none());
        assert!(parsed.last_file_synced_revision_id_primary.is_none());
        assert!(parsed.last_file_synced_revision_id_secondary.is_none());
        assert!(parsed.last_file_synced_hash_primary.is_none());
        assert!(parsed.last_file_synced_hash_secondary.is_none());
    }

    /// Empty value parses as `None` (sentinel for "not recorded"),
    /// matching the format-side convention.
    #[test]
    fn empty_value_for_optional_string_parses_as_none() {
        let input = "last_saved_path_primary=\nlast_saved_path_secondary=\n";
        let parsed = parse_preferences(input);
        assert!(parsed.last_saved_path_primary.is_none());
        assert!(parsed.last_saved_path_secondary.is_none());
    }

    #[test]
    fn nonempty_value_for_optional_string_parses_as_some() {
        let input = "last_saved_path_primary=C:\\rules_primary.txt\n";
        let parsed = parse_preferences(input);
        assert_eq!(
            parsed.last_saved_path_primary.as_deref(),
            Some("C:\\rules_primary.txt")
        );
    }

    /// A v2 preference file must load with the two UAC-state fields
    /// defaulting to their zero values. Missing keys parse via the
    /// catch-all `_ => {}` arm and the struct's `Default` impl fills the
    /// holes.
    #[test]
    fn v2_file_without_new_fields_loads_with_defaults() {
        let legacy_v2 = "\
schema_version=2
theme_mode=dark
language=ru
first_run_completed=true
last_saved_path_primary=C:\\rules_primary.txt
";
        let parsed = parse_preferences(legacy_v2);
        assert_eq!(parsed.theme_mode, ThemeMode::Dark);
        assert_eq!(parsed.language, "ru");
        assert!(parsed.first_run_completed);
        assert_eq!(
            parsed.last_saved_path_primary.as_deref(),
            Some("C:\\rules_primary.txt")
        );
        assert!(parsed.service_install_uac_declined_at_epoch.is_none());
        assert_eq!(parsed.service_install_uac_declined_count, 0);
        // Newer toggles default (auto-load + comments ON, banner auto, no
        // custom URL) even though the v2 file omits them.
        assert!(parsed.auto_load_rules_on_launch);
        assert!(parsed.export_include_comments);
        assert_eq!(parsed.compat_banner_mode, "auto");
        assert!(parsed.update_page_url.is_empty());
    }

    /// A v3 file (UAC fields present, newer toggles absent) loads the
    /// toggles at their `true`/`auto`/empty defaults, and an unknown
    /// `compat_banner_mode` slug falls back to the default rather than
    /// corrupting the value.
    #[test]
    fn v3_file_without_new_toggles_loads_with_defaults() {
        let legacy_v3 = "\
schema_version=3
theme_mode=dark
service_install_uac_declined_count=1
";
        let parsed = parse_preferences(legacy_v3);
        assert_eq!(parsed.service_install_uac_declined_count, 1);
        assert!(parsed.auto_load_rules_on_launch);
        assert!(parsed.export_include_comments);
        assert_eq!(parsed.compat_banner_mode, "auto");
        assert!(parsed.update_page_url.is_empty());
    }

    #[test]
    fn unknown_compat_banner_mode_falls_back_to_default() {
        let parsed = parse_preferences("compat_banner_mode=bogus\n");
        assert_eq!(parsed.compat_banner_mode, "auto");
        let ok = parse_preferences("compat_banner_mode=never\n");
        assert_eq!(ok.compat_banner_mode, "never");
    }

    /// The store owns the allow-list for the support-archive privacy tier: a
    /// hand-edited or unknown slug must not leave the exporter pointing at a
    /// tier it cannot produce.
    #[test]
    fn unknown_diagnostics_archive_redaction_level_falls_back_to_default() {
        let parsed = parse_preferences("diagnostics_archive_redaction_level=everything\n");
        assert_eq!(
            parsed.diagnostics_archive_redaction_level,
            crate::ui_preferences::DIAGNOSTICS_ARCHIVE_REDACTION_LEVEL_DEFAULT
        );
        let ok = parse_preferences("diagnostics_archive_redaction_level=diagnostics\n");
        assert_eq!(ok.diagnostics_archive_redaction_level, "diagnostics");
    }

    /// Empty value for `service_install_uac_declined_at_epoch` parses as
    /// `None`. Non-empty value parses as `Some(i64)`.
    #[test]
    fn empty_uac_declined_at_epoch_parses_as_none() {
        let input = "service_install_uac_declined_at_epoch=\n";
        let parsed = parse_preferences(input);
        assert!(parsed.service_install_uac_declined_at_epoch.is_none());
    }

    #[test]
    fn nonempty_uac_declined_at_epoch_parses_as_some() {
        let input = "service_install_uac_declined_at_epoch=1700000123\nservice_install_uac_declined_count=2\n";
        let parsed = parse_preferences(input);
        assert_eq!(
            parsed.service_install_uac_declined_at_epoch,
            Some(1_700_000_123)
        );
        assert_eq!(parsed.service_install_uac_declined_count, 2);
    }

    #[test]
    fn legacy_v0_file_loads_without_schema_version_field() {
        // A file written before schema_version was introduced must load cleanly.
        let parsed = parse_preferences("theme_mode=dark\nlanguage=ru\n");
        assert_eq!(parsed.theme_mode, ThemeMode::Dark);
        assert_eq!(parsed.language, "ru");
        // check_schema_version_compat should not panic on absent key.
        check_schema_version_compat("theme_mode=dark\nlanguage=ru\n");
    }

    #[test]
    fn parser_accepts_schema_version_key_without_affecting_preferences() {
        let parsed = parse_preferences("schema_version=1\ntheme_mode=dark\nlanguage=en\n");
        assert_eq!(parsed.theme_mode, ThemeMode::Dark);
        assert_eq!(parsed.language, "en");
    }

    /// Allocate a fresh scratch path under a `TempDir`. The caller MUST keep
    /// the returned `TempDir` binding alive — dropping it removes the
    /// directory recursively, so no test invocation leaks a scratch
    /// directory.
    fn test_path(file_name: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = test_dir("files");
        let path = dir.path().join(file_name);
        (dir, path)
    }

    fn test_dir(prefix: &str) -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix(&format!("nrr-ui-preferences-tests-{prefix}-"))
            .tempdir()
            .unwrap_or_else(|error| panic!("failed to create temp dir: {error}"))
    }

    fn populate_legacy_policy_fields(prefs: &mut UiPreferences) {
        prefs.selected_primary_interface_id = "Wi-Fi".into();
        prefs.selected_primary_interface_name = "Wireless".into();
        prefs.primary_role_user_confirmed = true;
        prefs.selected_secondary_interface_id = "TAP".into();
        prefs.selected_secondary_interface_name = "OpenVPN TAP".into();
        prefs.secondary_role_user_confirmed = true;
        prefs.route_behavior_mode = RouteBehaviorMode::StrictSecondaryFailClosed;
        prefs.block_secondary_traffic_when_unavailable = true;
    }

    #[test]
    fn has_legacy_policy_fields_returns_false_for_default_preferences() {
        let prefs = UiPreferences::default();
        assert!(!has_legacy_policy_fields(&prefs));
    }

    #[test]
    fn has_legacy_policy_fields_returns_true_for_each_individually_set_field() {
        for setter in [
            (|p: &mut UiPreferences| p.selected_primary_interface_id = "x".into())
                as fn(&mut UiPreferences),
            |p| p.selected_primary_interface_name = "x".into(),
            |p| p.primary_role_user_confirmed = true,
            |p| p.selected_secondary_interface_id = "x".into(),
            |p| p.selected_secondary_interface_name = "x".into(),
            |p| p.secondary_role_user_confirmed = true,
            |p| p.route_behavior_mode = RouteBehaviorMode::StrictSecondaryFailClosed,
            |p| p.block_secondary_traffic_when_unavailable = true,
        ] {
            let mut prefs = UiPreferences::default();
            setter(&mut prefs);
            assert!(
                has_legacy_policy_fields(&prefs),
                "setter must trigger legacy detection"
            );
        }
    }

    #[test]
    fn cleanup_legacy_policy_fields_zeroes_only_eight_policy_fields() {
        let mut prefs = UiPreferences::default();
        // Populate every legacy policy field plus a sample of UI-only
        // fields; the cleanup must zero the former without touching the
        // latter.
        populate_legacy_policy_fields(&mut prefs);
        prefs.theme_mode = ThemeMode::Dark;
        prefs.language = "ru".into();
        prefs.route_primary_label = "Прямое".into();
        prefs.tooltips_enabled = false;
        prefs.last_opened_section = AppSection::Diagnostics;
        prefs.rules_view_sort = RulesViewSort::ByMatchValue;
        prefs.log_level = LogLevel::Debug;

        cleanup_legacy_policy_fields(&mut prefs);

        // Eight fields → defaults.
        assert!(!has_legacy_policy_fields(&prefs));
        assert_eq!(prefs.selected_primary_interface_id, "");
        assert_eq!(prefs.selected_primary_interface_name, "");
        assert!(!prefs.primary_role_user_confirmed);
        assert_eq!(prefs.selected_secondary_interface_id, "");
        assert_eq!(prefs.selected_secondary_interface_name, "");
        assert!(!prefs.secondary_role_user_confirmed);
        assert_eq!(
            prefs.route_behavior_mode,
            RouteBehaviorMode::default_when_secondary_unbound()
        );
        assert!(!prefs.block_secondary_traffic_when_unavailable);

        // UI-only fields preserved.
        assert_eq!(prefs.theme_mode, ThemeMode::Dark);
        assert_eq!(prefs.language, "ru");
        assert_eq!(prefs.route_primary_label, "Прямое");
        assert!(!prefs.tooltips_enabled);
        assert_eq!(prefs.last_opened_section, AppSection::Diagnostics);
        assert_eq!(prefs.rules_view_sort, RulesViewSort::ByMatchValue);
        assert_eq!(prefs.log_level, LogLevel::Debug);
    }

    #[test]
    fn cleanup_legacy_policy_fields_is_idempotent() {
        let mut prefs = UiPreferences::default();
        populate_legacy_policy_fields(&mut prefs);
        cleanup_legacy_policy_fields(&mut prefs);
        let after_first = prefs.clone();
        cleanup_legacy_policy_fields(&mut prefs);
        assert_eq!(prefs, after_first);
    }
}
