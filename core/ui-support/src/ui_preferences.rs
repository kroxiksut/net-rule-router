use nrr_shared::{
    load_locale_catalog, AppSection, RouteBehaviorMode, RulesEnabledFilter,
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

/// The managed-configuration root beside the product name it is named after.
/// Two independent copies of this path existed in this file alone, and a third
/// in `nrr-shared::localization`; all three now read the identity SSOT.
const MANAGED_ROOT_FOLDER: &str = nrr_shared::product_identity::PRODUCT_NAME;
const MANAGED_SUBFOLDER: &str = "managed";

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

pub const MANAGED_STORAGE_POLICY_NOTE: &str =
    "UI preferences are application-managed local state. Policy-affecting data remains service-owned.";
const STABLE_PREFERENCES_FILE_NAME: &str = "ui-preferences.conf";
/// Distinguishes two saves from the same process, so their scratch files
/// cannot collide either.
static SAVE_SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
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
///   file was written by a newer build. Known fields are loaded; keys this
///   build has no field for are carried verbatim in
///   [`UiPreferences::forward_compat`] and written back on save, and the
///   version stamp is never lowered. So the file is not downgraded, and a
///   user who starts an older build once does not lose the settings only the
///   newer one knows about. A diagnostic is emitted to stderr.
pub const CURRENT_UI_PREFS_SCHEMA_VERSION: u32 = 11;

/// Bounds and default for [`UiPreferences::settings_autosave_secs`]. This is the
/// authoritative range: the spin box in the settings UI mirrors it, but any
/// value arriving from a hand-edited file or an older build is clamped here.
/// Ceiling for every opaque JSON blob the preferences file stores
/// (`route_pending_offline_json`, `cache_table_column_widths`,
/// `service_backed_mirror_json`, `service_intent_json`). One declaration: the
/// parse side and the QML payload side both gate against it.
/// Ceiling for the free-form string fields that GROW on their own: the
/// acknowledgement signatures (a `|`-join of every unenforced app / kept
/// overlap pair) and the confirmed-VPN executable list. Every other string here
/// is something a user typed into a bounded control.
///
/// The file is rewritten in full every 500 ms during a settings burst, so an
/// unbounded string is a write-amplification defect, not just disk. A value over
/// the ceiling is refused rather than truncated: half a signature matches
/// nothing, and a signature that matches nothing is a banner the user has to
/// acknowledge again — a truncated one would ALSO look like a valid answer.
pub const MAX_STORED_STRING_BYTES: usize = 16 * 1024;

/// `value` when it fits on one line within [`MAX_STORED_STRING_BYTES`],
/// otherwise `fallback` plus a diagnostic.
pub fn storable_line_or(field: &str, value: String, fallback: String) -> String {
    if value.len() <= MAX_STORED_STRING_BYTES && !value.contains(['\n', '\r']) {
        return value;
    }
    eprintln!(
        "nrr: keeping the stored {field}: the incoming value is {} bytes or spans lines \
         (ceiling {MAX_STORED_STRING_BYTES})",
        value.len()
    );
    fallback
}

/// Accepted slugs for the compatibility banner, and the default. Authoritative
/// list: the parse side and the QML payload side both resolve against it, and
/// the settings UI mirrors it.
pub const COMPAT_BANNER_MODES: [&str; 3] = ["auto", "always", "never"];
pub const COMPAT_BANNER_MODE_DEFAULT: &str = "auto";

/// Accepted slugs for the file-to-service merge-conflict policy, and the
/// default. Same authority as [`COMPAT_BANNER_MODES`].
pub const MERGE_CONFLICT_POLICIES: [&str; 3] = ["union", "file-wins", "service-wins"];
pub const MERGE_CONFLICT_POLICY_DEFAULT: &str = "union";

/// `value` when it is one of `allowed`, otherwise `fallback`.
///
/// The two sides of the round-trip filtered differently: the QML payload wrote
/// a slug verbatim while the parser dropped anything off the list, so a value
/// the app honoured all session quietly reverted at the next start. One
/// resolver, called by both, is what keeps that from coming back.
pub fn allowed_slug_or(value: &str, allowed: &[&str], fallback: &str) -> String {
    if allowed.contains(&value) {
        value.to_string()
    } else {
        fallback.to_string()
    }
}

pub const MAX_STORED_JSON_BLOB_BYTES: usize = 8 * 1024;

pub const SETTINGS_AUTOSAVE_MIN_SECS: u32 = 15;

/// Bounds and default for [`UiPreferences::admin_auto_revoke_minutes`] — how
/// long the elevated broker session may sit UNUSED before the launcher
/// retires it (the next privileged action prompts UAC again). These are the
/// SSOT bounds: the GUI SpinBox mirrors them for convenience, the parse path
/// below enforces them.
pub const ADMIN_AUTO_REVOKE_MIN_MINUTES: u32 = 1;
pub const ADMIN_AUTO_REVOKE_MAX_MINUTES: u32 = 180;
pub const ADMIN_AUTO_REVOKE_DEFAULT_MINUTES: u32 = 15;
/// Bounds and default for [`UiPreferences::tray_notice_opacity_percent`]. SSOT
/// for the four places that used to spell `40` and `100` out: this parser, the
/// `apply_over` clamp, the QML binding and the settings SpinBox.
pub const TRAY_NOTICE_OPACITY_MIN_PERCENT: u16 = 40;
pub const TRAY_NOTICE_OPACITY_MAX_PERCENT: u16 = 100;

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
    /// Show the tray notice when the active rules name the same traffic on
    /// both routes. Default `true`: the condition is invisible everywhere else,
    /// and evaluation order — not the user — is deciding.
    pub notify_rule_duplicates: bool,
    /// Redacts the destination host/IP from the "connection blocked" notice
    /// body while still showing that a block happened. Default `false`.
    pub hide_block_notice_addresses: bool,
    /// Opacity of the tray notice window, in percent. Clamped to 40..=100 on
    /// the way in; 100 is the opaque default. The notice is our own window,
    /// not a system balloon, so this is ours to honour.
    pub tray_notice_opacity_percent: u16,
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
    /// Overlap pairs the user chose to keep, as `route:apex>route:host`
    /// entries joined with `|`. The rules screen offers to delete an exact
    /// rule a wildcard already covers; a pair listed here is never offered
    /// again. Device-local UI state, never exported.
    pub rules_overlap_keep_signature: String,
    /// DISPLAY only: the first of [`confirmed_vpn_exe_paths`], shown as
    /// "Your VPN client" in Settings. Nothing keys behaviour on it — the set
    /// below is what reseeds the service. Kept because a single name reads
    /// better in a label than a semicolon-joined list. Empty = not set.
    /// Single line only (line-oriented prefs file). Device-local, never exported.
    pub confirmed_vpn_exe_path: String,
    /// The FULL set of executables the user confirmed as their VPN in the
    /// onboarding dialog, semicolon-joined absolute paths (`""` = none). Users
    /// often run several processes as one VPN setup (a client plus its
    /// background service and CLI); each listed exe stays exempted from the
    /// kill-switch.
    ///
    /// The service-side `route_link_provider_apps` table is authoritative, but
    /// this is NOT a passive mirror: when the service comes back with an empty
    /// provider set (a schema bump wiped it), `Main.qml` reseeds the service
    /// from this list. That is the whole reason the app keeps its own copy, and
    /// it is why the value is behaviour, not decoration. Single line only.
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
    /// not per-SID): `"reactive"` (Mode A) | `"resolver"` (Mode B, default).
    /// The default is taken from `nrr_shared::ipc_payloads::
    /// ENFORCEMENT_MODE_DEFAULT`, not retyped: this doc used to name the other
    /// mode, and a mirror that disagrees with the wire is how a user ends up in
    /// a mode nobody chose. See the block comment above for the seed-on-default
    /// semantics.
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
    // Adapter bindings. The service owns the authoritative per-SID copy and is
    // what actually enforces; these eight are the app's own store of the same
    // facts and what every panel shows while the service is stopped.
    //
    // The two are reconciled in one direction only: an EMPTY slot here is
    // seeded from `SnapshotInitial.routePolicy` on cold start, and a slot that
    // disagrees raises a banner asking the user which side stands. A snapshot
    // never overwrites a filled slot — the app's value is the user's own
    // choice, and only they know which of the two is the stale one.
    // -------------------------------------------------------------------------
    /// The adapter the user picked for the main route. The interfaces screen
    /// writes it and `route.policy.update` is built from it; the service holds
    /// the same fact per-SID and reports it in
    /// `SnapshotInitial.routePolicy.primary.stableId`.
    pub selected_primary_interface_id: String,
    /// Display hint for the id above. See `selected_primary_interface_id`.
    pub selected_primary_interface_name: String,
    /// Whether the user confirmed the main-route role by hand.
    pub primary_role_user_confirmed: bool,
    /// The adapter picked for the additional route. See
    /// `selected_primary_interface_id`.
    pub selected_secondary_interface_id: String,
    /// Display hint for the id above.
    pub selected_secondary_interface_name: String,
    /// Whether the user confirmed the additional-route role by hand.
    pub secondary_role_user_confirmed: bool,
    /// Which route unmatched traffic takes. See
    /// `selected_primary_interface_id`.
    pub route_behavior_mode: RouteBehaviorMode,
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
    /// The user said "stop offering to install the service". A deliberate
    /// answer, unlike closing the dialog, so it holds until they turn the offer
    /// back on in Settings. Separate from the decline budget on purpose: three
    /// dismissals mean "not now", not "never".
    pub service_install_prompt_suppressed: bool,

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
    /// What the loaded file said that this build has no field for. Carried
    /// through the round-trip so an older build saving over a newer build's
    /// file does not silently erase its settings.
    pub forward_compat: ForwardCompat,
}

/// The part of a preferences file this build does not understand.
///
/// Only populated when the file declares a schema version ABOVE
/// [`CURRENT_UI_PREFS_SCHEMA_VERSION`]: an unknown key in a file of our own
/// version is a leftover of a key we removed, and re-writing those forever is
/// how a settings file never shrinks.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ForwardCompat {
    /// Version the file declared, when it was newer than ours.
    pub newer_schema_version: Option<u32>,
    /// Unrecognised `key=value` lines, verbatim and in file order.
    pub unknown_lines: Vec<String>,
}

impl ForwardCompat {
    /// Version to stamp on save: never lower than what the file already
    /// declared, which is what "the file is not downgraded on save" means.
    fn schema_stamp(&self) -> u32 {
        self.newer_schema_version
            .unwrap_or(CURRENT_UI_PREFS_SCHEMA_VERSION)
            .max(CURRENT_UI_PREFS_SCHEMA_VERSION)
    }
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

// The route-policy fields start at their type defaults, like every other one.
// They are the application's own store and what the window shows while the
// service is stopped — not a legacy shape to be read past.
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
            notify_rule_duplicates: true,
            hide_block_notice_addresses: false,
            tray_notice_opacity_percent: 100,
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
            rules_overlap_keep_signature: String::new(),
            confirmed_vpn_exe_path: String::new(),
            confirmed_vpn_exe_paths: String::new(),
            selected_primary_interface_id: String::new(),
            selected_primary_interface_name: String::new(),
            primary_role_user_confirmed: false,
            selected_secondary_interface_id: String::new(),
            selected_secondary_interface_name: String::new(),
            secondary_role_user_confirmed: false,
            route_behavior_mode: RouteBehaviorMode::default_when_secondary_unbound(),
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
            route_enforcement_mode: nrr_shared::ipc_payloads::enforcement_mode_default(),
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
            service_install_prompt_suppressed: false,
            // New toggles default to the pre-existing behaviour (auto-load
            // on, comments on, banner auto, no custom URL).
            auto_load_rules_on_launch: true,
            export_include_comments: true,
            import_only_active: true,
            compat_banner_mode: String::from(COMPAT_BANNER_MODE_DEFAULT),
            update_page_url: String::new(),
            show_bundled_presets: true,
            // Empty means "list the rule sets shipped with the app".
            user_presets_dir: String::new(),
            // Empty means "the user has not picked a set yet", which is the only
            // state where the shipped-set list may choose one by system locale.
            selected_preset_set: String::new(),
            secondary_split_ack_adapter_name: String::new(),
            // The safe interactive policy: the merge keeps both sides and asks
            // the user to resolve conflicts.
            merge_conflict_policy: String::from(MERGE_CONFLICT_POLICY_DEFAULT),
            forward_compat: ForwardCompat::default(),
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

/// What a session got when it opened the preferences store.
///
/// The distinction that matters is whether the store may be WRITTEN. `load`
/// already falls back to the `.bak` copy, so a read that still fails means
/// neither file could be read — a lock held by a scanner or a profile sync,
/// not an empty file. Writing through such a store replaces settings that were
/// merely unavailable with defaults, and the user meets the first-run wizard
/// and the EULA again.
pub enum SessionPreferences {
    /// The file was read; write-through is safe.
    Writable {
        store: UiPreferencesStore,
        preferences: UiPreferences,
    },
    /// The file could not be read. Defaults are used for THIS session and
    /// nothing is written back, so the file survives to be read next time.
    ReadOnly {
        preferences: UiPreferences,
        error: io::Error,
    },
}

/// Open `store` for a session: read it, and keep the write handle only if the
/// read worked. Both shells (GUI and launcher) go through this so the rule
/// cannot be half-applied in one of them.
pub fn open_for_session(store: UiPreferencesStore) -> SessionPreferences {
    match store.load() {
        Ok(preferences) => SessionPreferences::Writable { store, preferences },
        Err(error) => SessionPreferences::ReadOnly {
            preferences: UiPreferences::default(),
            error,
        },
    }
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
            Ok(content) if has_preference_lines(&content) => {
                let parsed = parse_preferences(&content);
                warn_if_written_by_a_newer_build(&parsed);
                Ok(without_expired_parked_intents(parsed, unix_now_ms()))
            }
            // The file exists but holds no `key=value` line: a dirty-shutdown
            // artifact (power cut after the rename committed but before the
            // data flushed leaves an empty or NUL-filled file). Silently
            // starting with defaults here is what cost a user their EULA
            // acceptance and every local setting — recover from the backup.
            Ok(_) => Ok(self.load_backup().unwrap_or_default()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                Ok(self.load_backup().unwrap_or_default())
            }
            Err(error) => match self.load_backup() {
                Some(preferences) => Ok(preferences),
                None => Err(error),
            },
        }
    }

    /// The previous good file, kept by [`Self::save`]. `None` when it is
    /// absent or just as gutted as the primary.
    fn load_backup(&self) -> Option<UiPreferences> {
        let content = fs::read_to_string(self.backup_path()).ok()?;
        if !has_preference_lines(&content) {
            return None;
        }
        let parsed = parse_preferences(&content);
        warn_if_written_by_a_newer_build(&parsed);
        Some(without_expired_parked_intents(parsed, unix_now_ms()))
    }

    fn backup_path(&self) -> PathBuf {
        self.path.with_extension("bak")
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
        // The scratch name is unique per writer. Both the GUI and the tray save
        // preferences, and a single `<path>.tmp` shared between them lets the
        // second writer truncate the first one's file mid-write — the first
        // then renames the other's half-written payload into place, defeating
        // the very swap this dance exists for.
        let temporary_path = self.path.with_extension(format!(
            "{}-{}.tmp",
            std::process::id(),
            SAVE_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        ));
        let payload = format_preferences(preferences);
        {
            use std::io::Write;
            let mut file = fs::File::create(&temporary_path)?;
            file.write_all(payload.as_bytes())?;
            // The rename survives a process kill, but not a power cut: the
            // journal can commit the rename while the data blocks are still
            // in the write-behind cache, and recovery then produces an empty
            // file under the final name. Flush the data before the swap.
            file.sync_all()?;
        }
        // Keep the outgoing file as the fallback `load` recovers from — but
        // never let a gutted primary overwrite a good backup.
        if let Ok(current) = fs::read_to_string(&self.path) {
            if has_preference_lines(&current) {
                let _ = fs::write(self.backup_path(), current);
            }
        }
        let renamed = fs::rename(&temporary_path, &self.path);
        if renamed.is_err() {
            // Nothing else will ever look at this name again, so a failed swap
            // must not leave it behind.
            let _ = fs::remove_file(&temporary_path);
        }
        renamed
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
        let managed_path = base.join(MANAGED_ROOT_FOLDER).join(MANAGED_SUBFOLDER);
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
    let temp_root = env::temp_dir()
        .join(MANAGED_ROOT_FOLDER)
        .join(MANAGED_SUBFOLDER);
    paths.extend(
        LEGACY_PREFERENCES_FILE_NAMES
            .iter()
            .map(|name| temp_root.join(name)),
    );
    paths.push(temp_root.join(STABLE_PREFERENCES_FILE_NAME));
    paths
}

/// Whether `content` carries at least one `key=value` line — what separates a
/// real preferences file (ours always leads with `schema_version=`, a legacy
/// one has its settings) from the empty or NUL-filled husk a dirty shutdown
/// leaves behind.
fn has_preference_lines(content: &str) -> bool {
    content.lines().any(|raw| {
        let line = raw.trim();
        !line.is_empty() && !line.starts_with('#') && line.contains('=')
    })
}

/// Says on stderr that the file came from a newer build, once per load.
///
/// Nothing else can be done about it and nothing needs to be: the unknown keys
/// ride along in [`ForwardCompat`] and are written back, so the file is not
/// downgraded. The line is here for a support archive, not for a decision.
fn warn_if_written_by_a_newer_build(preferences: &UiPreferences) {
    if let Some(v) = preferences.forward_compat.newer_schema_version {
        let carried = preferences.forward_compat.unknown_lines.len();
        eprintln!(
            "nrr: ui-preferences file declares schema_version={v}; this build supports up to \
             {CURRENT_UI_PREFS_SCHEMA_VERSION}. Known fields are loaded, {carried} unknown \
             setting(s) are carried through unchanged."
        );
    }
}

/// The `schema_version` the file declares, if any.
///
/// Absent means a legacy v0 file — every known field loads as-is. Read in its
/// own pass because the unknown-key capture in [`parse_preferences`] has to
/// know the verdict before it reaches the first unknown key, and a hand-edited
/// file may not lead with the version the way ours do.
fn declared_schema_version(content: &str) -> Option<u32> {
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("schema_version=") {
            return rest.trim().parse::<u32>().ok();
        }
    }
    None
}

fn parse_preferences(content: &str) -> UiPreferences {
    let mut preferences = UiPreferences::default();
    let newer_schema =
        declared_schema_version(content).filter(|v| *v > CURRENT_UI_PREFS_SCHEMA_VERSION);
    preferences.forward_compat.newer_schema_version = newer_schema;
    // The defaults were built from the SYSTEM language, which is not the one
    // the user picked. Whether the file carried its own values decides whether
    // they get recomputed below.
    let mut language_seen = false;
    let mut labels_seen = false;

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
                // Read ahead of the loop, and re-stamped on save.
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
            "notify_rule_duplicates" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.notify_rule_duplicates = parsed;
                }
            }
            "hide_block_notice_addresses" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.hide_block_notice_addresses = parsed;
                }
            }
            "tray_notice_opacity_percent" => {
                if let Some(parsed) = parse_tray_notice_opacity_percent(value) {
                    preferences.tray_notice_opacity_percent = parsed;
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
            // Resolved against the catalog, not just canonicalised: a tag no
            // catalog carries (`zz`, a typo) left every `tr()` on its English
            // fallback, which reads as "the app forgot my language".
            "language" => {
                if let Some(parsed) = parse_language_hint(value) {
                    preferences.language = parsed;
                    language_seen = true;
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
                    labels_seen = true;
                }
            }
            "route_secondary_label" => {
                if !value.is_empty() {
                    preferences.route_secondary_label = value.to_string();
                    labels_seen = true;
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
            // Clamped, not reverted: an out-of-range value is a user who wanted
            // the extreme, and silently substituting the default moves a
            // security-relevant timer to a number nobody asked for. Garbage
            // (unparseable) keeps the current value, like every other number here.
            "admin_auto_revoke_minutes" => {
                if let Ok(parsed) = value.parse::<u32>() {
                    preferences.admin_auto_revoke_minutes =
                        parsed.clamp(ADMIN_AUTO_REVOKE_MIN_MINUTES, ADMIN_AUTO_REVOKE_MAX_MINUTES);
                }
            }
            "settings_autosave_secs" => {
                if let Ok(parsed) = value.parse::<u32>() {
                    preferences.settings_autosave_secs =
                        parsed.clamp(SETTINGS_AUTOSAVE_MIN_SECS, SETTINGS_AUTOSAVE_MAX_SECS);
                }
            }
            "allow_mode_a_killswitch" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.allow_mode_a_killswitch = parsed;
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
                preferences.unenforced_apps_ack_signature = storable_line_or(
                    key,
                    value.to_string(),
                    std::mem::take(&mut preferences.unenforced_apps_ack_signature),
                );
            }
            // Overlap pairs the user asked to keep. Free-form single-line
            // value; empty is the valid "nothing kept" state.
            "rules_overlap_keep_signature" => {
                preferences.rules_overlap_keep_signature = storable_line_or(
                    key,
                    value.to_string(),
                    std::mem::take(&mut preferences.rules_overlap_keep_signature),
                );
            }
            // Confirmed VPN executable path. Free-form single-line value;
            // empty is the valid "not set" state, so no non-empty gate.
            "confirmed_vpn_exe_path" => {
                preferences.confirmed_vpn_exe_path = storable_line_or(
                    key,
                    value.to_string(),
                    std::mem::take(&mut preferences.confirmed_vpn_exe_path),
                );
            }
            // Semicolon-joined list of confirmed VPN executables. Free-form
            // single-line value; empty is the valid "none" state, so no
            // non-empty gate.
            "confirmed_vpn_exe_paths" => {
                preferences.confirmed_vpn_exe_paths = storable_line_or(
                    key,
                    value.to_string(),
                    std::mem::take(&mut preferences.confirmed_vpn_exe_paths),
                );
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
            "service_install_prompt_suppressed" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.service_install_prompt_suppressed = parsed;
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
                preferences.compat_banner_mode =
                    allowed_slug_or(value, &COMPAT_BANNER_MODES, &preferences.compat_banner_mode);
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
            "merge_conflict_policy" => {
                preferences.merge_conflict_policy = allowed_slug_or(
                    value,
                    &MERGE_CONFLICT_POLICIES,
                    &preferences.merge_conflict_policy,
                );
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
                // Masking a nonsense value invents a meaning for it: `128 &
                // 0x7F` is 0, and an empty protocol mask makes the codegen emit
                // no filter at all — the kill switch reads as ON and blocks
                // nothing. A value outside the mask, or one that selects
                // nothing, is not a preference; it is a damaged line, and the
                // default (every protocol) is the safe reading.
                if let Ok(parsed) = value.parse::<u32>() {
                    if parsed != 0 && parsed & !0x7F == 0 {
                        preferences.route_kill_switch_protocols = parsed;
                    }
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
                preferences.route_pending_offline_json =
                    storable_json_blob_or_empty(key, value.to_string());
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
                preferences.cache_table_column_widths =
                    storable_json_blob_or_empty(key, value.to_string());
            }
            // Last-known service-owned values, mirrored for display while the
            // service is stopped. Same opaque single-line-object gate as the
            // two blobs above.
            "service_backed_mirror_json" => {
                preferences.service_backed_mirror_json =
                    storable_json_blob_or_empty(key, value.to_string());
            }
            // What the user decided the service-owned settings should be.
            // Same opaque single-line-object gate as the mirror above.
            "service_intent_json" => {
                preferences.service_intent_json =
                    storable_json_blob_or_empty(key, value.to_string());
            }
            // A key this build has none for. From a NEWER file it is a setting
            // the user made in a build that has one, so it is kept verbatim and
            // written back; from a file of our own version it is the residue of
            // a key we removed, and dropping it is how the file shrinks.
            _ => {
                if newer_schema.is_some() {
                    preferences
                        .forward_compat
                        .unknown_lines
                        .push(line.to_string());
                }
            }
        }
    }

    // A file that named a language but no labels was written before the labels
    // existed; deriving them from the system language then hands a Russian-UI
    // user "Primary"/"Secondary".
    if language_seen && !labels_seen {
        let (primary, secondary) = default_route_labels(&preferences.language);
        preferences.route_primary_label = primary;
        preferences.route_secondary_label = secondary;
    }

    normalize_theme_preferences(&mut preferences);
    preferences
}

/// Structural sanity gate for the opaque pending-offline JSON blob
/// (ui-support deliberately has no JSON dependency; the QML
/// side owns the schema). Accepts an empty string (= none) or a single-line
/// `{…}` object up to [`MAX_STORED_JSON_BLOB_BYTES`] — plenty for every routing
/// field with headroom, small enough that a corrupted preferences file cannot
/// balloon memory. Public because the QML payload path applies the SAME gate on
/// the way in: five hand-copied versions of it lived here and in `ui_surface`,
/// and one threshold drifting apart from the rest loses a blob silently.
/// Rejects any embedded newline (L3 review-fix): the value lives on ONE
/// `key=value` line, so a `\n`/`\r` would split it into bogus extra lines on
/// the next read — reject rather than corrupt the line-oriented file.
pub fn is_storable_json_blob(value: &str) -> bool {
    value.is_empty()
        || (value.len() <= MAX_STORED_JSON_BLOB_BYTES
            && value.starts_with('{')
            && value.ends_with('}')
            && !value.contains(['\n', '\r']))
}

/// A blob that passes [`is_storable_json_blob`], or `""` plus a diagnostic.
///
/// Both sides of the round-trip reduce a rejected blob to "none", and both used
/// to do it silently — so `service_intent_json`, the only record of what the
/// user decided, could evaporate in exactly the way the field exists to
/// prevent. `field` names the key so the line is actionable.
pub fn storable_json_blob_or_empty(field: &str, value: String) -> String {
    if is_storable_json_blob(&value) {
        return value;
    }
    eprintln!(
        "nrr: dropping {field} ({} bytes): not a single-line JSON object within \
         {MAX_STORED_JSON_BLOB_BYTES} bytes",
        value.len()
    );
    String::new()
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

/// Renders one preference value so it cannot become two lines.
///
/// The file is `key=value` per line and the parser splits on the first `=`, so
/// a value carrying a newline used to write a SECOND, forged pair — a label of
/// `Main` plus a newline plus `first_run_completed=false` restarted the setup
/// wizard on the next launch. The reader rejected such values on some paths;
/// the writer accepted every one of them. A preset directory whose name
/// contains a newline is perfectly legal on Linux, so this is not hypothetical.
///
/// Control characters are replaced rather than dropped: what the user typed
/// stays recognisable, and the file stays parseable.
fn one_line(value: &impl std::fmt::Display) -> String {
    let rendered = value.to_string();
    if rendered.contains(['\r', '\n']) {
        rendered.replace(['\r', '\n'], " ")
    } else {
        rendered
    }
}

fn format_preferences(preferences: &UiPreferences) -> String {
    let mut rendered = format!(
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
            "last_opened_section={}\n",
            "rules_view_sort={}\n",
            "rules_file_change_behavior={}\n",
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
            "service_install_prompt_suppressed={}\n",
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
            "rules_overlap_keep_signature={}\n",
            "confirmed_vpn_exe_path={}\n",
            "confirmed_vpn_exe_paths={}\n",
            "last_loaded_path_primary={}\n",
            "last_loaded_path_secondary={}\n",
            "notify_block_notices={}\n",
            "notify_rule_duplicates={}\n",
            "hide_block_notice_addresses={}\n",
            "tray_notice_opacity_percent={}\n"
        ),
        preferences.forward_compat.schema_stamp(),
        one_line(&preferences.launch_window_on_startup),
        one_line(&preferences.minimize_to_tray_instead_of_close),
        one_line(&preferences.show_notifications),
        one_line(&preferences.notify_suggestion_changes),
        one_line(&preferences.reopen_last_section_on_startup),
        one_line(&preferences.first_run_completed),
        one_line(&preferences.accepted_eula_version),
        one_line(&preferences.theme_mode),
        one_line(&preferences.accessibility_high_contrast),
        one_line(&preferences.accessibility_ui_font_scale_percent),
        one_line(&preferences.accessibility_system_font),
        one_line(&preferences.accessibility_enhanced_focus_indicator),
        one_line(&preferences.accessibility_simplified_labels),
        one_line(&preferences.tooltips_enabled),
        one_line(&preferences.language),
        one_line(&preferences.route_primary_label),
        one_line(&preferences.route_secondary_label),
        one_line(&preferences.show_bluetooth_adapters),
        one_line(&preferences.show_audit_tab),
        one_line(&preferences.admin_auto_revoke_disabled),
        one_line(&preferences.admin_auto_revoke_minutes),
        one_line(&preferences.settings_autosave_secs),
        one_line(&preferences.allow_mode_a_killswitch),
        one_line(&preferences.routing_detailed_mode),
        one_line(&preferences.show_remembered_adapters),
        one_line(&preferences.selected_primary_interface_id),
        one_line(&preferences.selected_primary_interface_name),
        one_line(&preferences.primary_role_user_confirmed),
        one_line(&preferences.selected_secondary_interface_id),
        one_line(&preferences.selected_secondary_interface_name),
        one_line(&preferences.secondary_role_user_confirmed),
        one_line(&preferences.route_behavior_mode),
        one_line(&preferences.last_opened_section),
        one_line(&preferences.rules_view_sort),
        one_line(&preferences.rules_file_change_behavior),
        optional_string_field(&preferences.last_saved_path_primary),
        optional_string_field(&preferences.last_saved_path_secondary),
        optional_string_field(&preferences.auto_open_on_launch_path_primary),
        optional_string_field(&preferences.auto_open_on_launch_path_secondary),
        optional_string_field(&preferences.last_file_synced_revision_id_primary),
        optional_string_field(&preferences.last_file_synced_revision_id_secondary),
        optional_string_field(&preferences.last_file_synced_hash_primary),
        optional_string_field(&preferences.last_file_synced_hash_secondary),
        optional_i64_field(preferences.service_install_uac_declined_at_epoch),
        one_line(&preferences.service_install_uac_declined_count),
        one_line(&preferences.service_install_prompt_suppressed),
        one_line(&preferences.auto_load_rules_on_launch),
        one_line(&preferences.export_include_comments),
        one_line(&preferences.import_only_active),
        one_line(&preferences.compat_banner_mode),
        one_line(&preferences.update_page_url),
        one_line(&preferences.show_bundled_presets),
        one_line(&preferences.user_presets_dir),
        one_line(&preferences.selected_preset_set),
        one_line(&preferences.merge_conflict_policy),
        one_line(&preferences.auto_confirm_adapter_id_change),
        one_line(&preferences.warn_kill_switch_block_all),
        one_line(&preferences.kill_switch_banner_acknowledged),
        one_line(&preferences.missing_secondary_banner_acknowledged),
        one_line(&preferences.traffic_stats_period),
        one_line(&preferences.traffic_export_unit),
        one_line(&preferences.diagnostics_archive_redaction_level),
        one_line(&preferences.diagnostics_archive_session_only),
        one_line(&preferences.archive_log_budget_mib),
        one_line(&preferences.secondary_split_ack_adapter_name),
        one_line(&preferences.route_include_subdomains),
        one_line(&preferences.route_shared_ip_policy),
        one_line(&preferences.route_kill_switch_block_all),
        one_line(&preferences.route_kill_switch_fail_closed),
        one_line(&preferences.route_kill_switch_protocols),
        one_line(&preferences.route_kill_switch_enabled),
        one_line(&preferences.route_allow_dns_over_primary),
        one_line(&preferences.route_mode_a_coverage_strategy),
        one_line(&preferences.route_resolve_hosts_bypass),
        one_line(&preferences.route_enforcement_mode),
        one_line(&preferences.route_liveness_window_secs),
        one_line(&preferences.route_pending_offline_json),
        one_line(&preferences.allow_saving_into_bundled_presets),
        one_line(&preferences.rules_folder_suggestion_dismissed),
        one_line(&preferences.cache_table_column_widths),
        one_line(&preferences.service_backed_mirror_json),
        one_line(&preferences.service_intent_json),
        one_line(&preferences.unenforced_apps_ack_signature),
        one_line(&preferences.rules_overlap_keep_signature),
        one_line(&preferences.confirmed_vpn_exe_path),
        one_line(&preferences.confirmed_vpn_exe_paths),
        optional_string_field(&preferences.last_loaded_path_primary),
        optional_string_field(&preferences.last_loaded_path_secondary),
        one_line(&preferences.notify_block_notices),
        one_line(&preferences.notify_rule_duplicates),
        one_line(&preferences.hide_block_notice_addresses),
        preferences.tray_notice_opacity_percent
    );

    for line in &preferences.forward_compat.unknown_lines {
        rendered.push_str(&one_line(line));
        rendered.push('\n');
    }
    rendered
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

/// Clamped, not rejected. Rejecting made an out-of-range value load as the
/// DEFAULT, and the default is the maximum — so `20` ("nearly transparent")
/// came back as 100, fully opaque, the opposite of what was asked. The
/// write path clamps for exactly this reason; the read path now agrees.
fn parse_tray_notice_opacity_percent(value: &str) -> Option<u16> {
    let parsed = value.parse::<u16>().ok()?;
    Some(parsed.clamp(
        TRAY_NOTICE_OPACITY_MIN_PERCENT,
        TRAY_NOTICE_OPACITY_MAX_PERCENT,
    ))
}

fn parse_font_scale_percent(value: &str) -> Option<u16> {
    let parsed = value.parse::<u16>().ok()?;
    if (80..=300).contains(&parsed) {
        Some(parsed)
    } else {
        None
    }
}

/// Drop parked offline intents the user made more than
/// [`PARKED_INTENT_TTL_SECONDS`] ago.
///
/// Applied on load rather than on read: an intent nobody will act on should not
/// reach the GUI at all, and the next save writes the store out empty.
fn without_expired_parked_intents(mut prefs: UiPreferences, now_ms: i64) -> UiPreferences {
    if nrr_shared::parked_intents_expired(&prefs.route_pending_offline_json, now_ms) {
        prefs.route_pending_offline_json.clear();
    }
    prefs
}

/// Current Unix epoch in milliseconds; `0` when the clock is before the epoch,
/// which only makes every park look fresh.
fn unix_now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {

    /// Three copies of this default disagreed: the wire said `resolver`, the
    /// field doc said `reactive`, and the QML mirror normalised a MISSING value
    /// to `reactive` — a mode the code itself calls an unsupported historical
    /// fallback, saved by the next `emitPrefs()`. The mirror derives it now;
    /// this is the test that keeps the two from drifting apart again.
    #[test]
    fn the_enforcement_mode_mirror_starts_at_the_wire_default() {
        assert_eq!(
            UiPreferences::default().route_enforcement_mode,
            nrr_shared::ipc_payloads::ENFORCEMENT_MODE_DEFAULT,
        );
    }

    /// The writer used to accept what the reader refuses. A value with a
    /// newline wrote a second `key=value` pair, and the next load read it as a
    /// setting the user never touched — the wizard flag being the loudest one.
    #[test]
    fn a_value_with_a_newline_cannot_forge_a_second_setting() {
        let prefs = UiPreferences {
            first_run_completed: true,
            route_primary_label: "Main\nfirst_run_completed=false".to_string(),
            user_presets_dir: "/home/u/my\rrules".to_string(),
            ..UiPreferences::default()
        };

        let rendered = format_preferences(&prefs);
        let parsed = parse_preferences(&rendered);

        assert!(
            parsed.first_run_completed,
            "a label must not be able to rewrite another setting"
        );
        assert_eq!(parsed.route_primary_label, "Main first_run_completed=false");
        assert_eq!(parsed.user_presets_dir, "/home/u/my rules");
        // Every line the writer produced is still one key and one value.
        for line in rendered.lines() {
            assert!(
                !line.contains(['\r', '\n']),
                "no stray control character: {line:?}"
            );
        }
    }

    /// Out of range must land at the nearest bound, not at the default — and
    /// the default here is the MAXIMUM, so rejecting `20` ("nearly
    /// transparent") produced 100, fully opaque.
    #[test]
    fn an_out_of_range_opacity_clamps_instead_of_reverting_to_the_default() {
        let load = |raw: &str| {
            let text = format!(
                "tray_notice_opacity_percent={raw}
"
            );
            super::parse_preferences(&text).tray_notice_opacity_percent
        };
        assert_eq!(load("20"), super::TRAY_NOTICE_OPACITY_MIN_PERCENT);
        assert_eq!(load("400"), super::TRAY_NOTICE_OPACITY_MAX_PERCENT);
        assert_eq!(load("55"), 55);
        // Not a number at all is still a rejection: there is no nearest bound.
        assert_eq!(
            load("transparent"),
            UiPreferences::default().tray_notice_opacity_percent
        );
    }

    /// A read that failed after the `.bak` fallback must not hand back a
    /// writable store: the file was unavailable, not empty, and the next save
    /// would replace it with defaults.
    #[test]
    fn a_failed_read_opens_the_session_read_only() {
        let dir = tempfile::tempdir().expect("temp dir");
        // A DIRECTORY where the preferences file belongs: readable metadata,
        // unreadable content, on every platform.
        let path = dir.path().join("prefs.conf");
        std::fs::create_dir(&path).expect("dir in place of file");
        let store = UiPreferencesStore::for_path(path);
        match super::open_for_session(store) {
            super::SessionPreferences::ReadOnly { preferences, .. } => {
                assert_eq!(preferences, UiPreferences::default());
            }
            super::SessionPreferences::Writable { .. } => {
                panic!("an unreadable file must not yield a writable store")
            }
        }
    }
    use super::{
        declared_schema_version, format_preferences, parse_preferences,
        preferred_available_language, without_expired_parked_intents, ForwardCompat,
        SystemFontFamily, UiPreferences, UiPreferencesStore, ADMIN_AUTO_REVOKE_MAX_MINUTES,
        ADMIN_AUTO_REVOKE_MIN_MINUTES, CURRENT_UI_PREFS_SCHEMA_VERSION,
        LEGACY_PREFERENCES_FILE_NAMES, MAX_STORED_JSON_BLOB_BYTES, MAX_STORED_STRING_BYTES,
        SETTINGS_AUTOSAVE_MIN_SECS, STABLE_PREFERENCES_FILE_NAME,
    };
    use nrr_shared::{
        AppSection, RouteBehaviorMode, RulesEnabledFilter, RulesFileChangeBehavior,
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

    /// Two writers save at once (the GUI and the tray both do). With one
    /// shared `<path>.tmp` the second truncates the first one's file mid-write
    /// and the first renames the other's half-written payload into place; the
    /// surviving file must be one of the two, whole.
    #[test]
    fn concurrent_saves_never_leave_a_blended_file() {
        let (dir, path) = test_path("concurrent.conf");
        let store = UiPreferencesStore::for_path(path);
        let short = UiPreferences {
            route_primary_label: "a".repeat(8),
            ..UiPreferences::default()
        };
        let long = UiPreferences {
            route_primary_label: "b".repeat(4096),
            ..UiPreferences::default()
        };

        std::thread::scope(|scope| {
            for prefs in [&short, &long] {
                scope.spawn(|| {
                    for _ in 0..20 {
                        store.save(prefs).expect("save");
                    }
                });
            }
        });

        let label = store.load().expect("load").route_primary_label;
        assert!(
            label == short.route_primary_label || label == long.route_primary_label,
            "the saved file blends two writers: {} chars",
            label.len(),
        );
        // No scratch file outlives the writes.
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .expect("read dir")
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".tmp"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "scratch files left behind: {leftovers:?}"
        );
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
            // Non-default (default is false) — proves the field persists.
            service_install_prompt_suppressed: true,
            // Non-default (default is true) — proves the field persists.
            notify_block_notices: false,
            notify_rule_duplicates: false,
            // Non-default (default is false) — proves the field persists.
            hide_block_notice_addresses: true,
            // Non-default (default is 100) — proves the field persists.
            tray_notice_opacity_percent: 80,
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
            last_opened_section: AppSection::Settings,
            rules_view_sort: RulesViewSort::ByMatchValue,
            // Non-persisted — always resets to default on reload.
            rules_enabled_filter: RulesEnabledFilter::default(),
            rules_type_filter: RulesTypeFilter::default(),
            rules_file_change_behavior: RulesFileChangeBehavior::AutoApply,
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
            forward_compat: ForwardCompat::default(),
            // Non-default value so the round-trip proves the VPN-split
            // banner ack persists.
            secondary_split_ack_adapter_name: "SwiftVPN 3.0".to_string(),
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
            unenforced_apps_ack_signature: "citymap.exe|SwiftVPN 3.0.exe".to_string(),
            // Non-empty so the round-trip proves a kept overlap pair survives
            // a GUI restart.
            rules_overlap_keep_signature: "secondary:example.com>primary:api.example.com"
                .to_string(),
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
    fn a_newer_files_unknown_settings_survive_a_save_by_this_build() {
        let future = CURRENT_UI_PREFS_SCHEMA_VERSION + 3;
        let content = format!(
            "schema_version={future}\ntheme_mode=dark\nsomething_from_the_future=42\n\
             another_future_key=on\n"
        );

        let parsed = parse_preferences(&content);
        assert_eq!(parsed.forward_compat.newer_schema_version, Some(future));
        assert_eq!(
            parsed.forward_compat.unknown_lines,
            vec![
                "something_from_the_future=42".to_string(),
                "another_future_key=on".to_string(),
            ]
        );

        // Saving must neither drop those settings nor lower the stamp: the next
        // start of the newer build has to find its own file intact.
        let rendered = format_preferences(&parsed);
        assert!(rendered.contains(&format!("schema_version={future}\n")));
        assert!(rendered.contains("something_from_the_future=42\n"));
        assert!(rendered.contains("another_future_key=on\n"));
        assert_eq!(
            parse_preferences(&rendered).forward_compat,
            parsed.forward_compat
        );
    }

    #[test]
    fn route_labels_follow_the_chosen_language_not_the_system_one() {
        // A file from before the labels existed carries `language=` and no
        // labels. Deriving them from the system language is how a Russian-UI
        // user ended up with "Primary"/"Secondary".
        let parsed = parse_preferences("language=ru\ntheme_mode=dark\n");
        assert_eq!(parsed.route_primary_label, "Основной");
        assert_eq!(parsed.route_secondary_label, "Дополнительный");

        // Labels the user actually set are never recomputed.
        let parsed = parse_preferences("language=ru\nroute_primary_label=Дом\n");
        assert_eq!(parsed.route_primary_label, "Дом");
    }

    #[test]
    fn a_language_no_catalog_carries_resolves_instead_of_being_stored() {
        assert_eq!(parse_preferences("language=zz\n").language, "en");
        assert_eq!(parse_preferences("language=ru-RU\n").language, "ru");
    }

    #[test]
    fn out_of_range_numbers_clamp_and_garbage_keeps_the_current_value() {
        // Reverting to the default moved a security-relevant timer to a number
        // nobody chose; the range ends are what the user actually asked for.
        let parsed = parse_preferences("admin_auto_revoke_minutes=9999\n");
        assert_eq!(
            parsed.admin_auto_revoke_minutes,
            ADMIN_AUTO_REVOKE_MAX_MINUTES
        );
        let parsed = parse_preferences("admin_auto_revoke_minutes=0\n");
        assert_eq!(
            parsed.admin_auto_revoke_minutes,
            ADMIN_AUTO_REVOKE_MIN_MINUTES
        );
        let parsed = parse_preferences("settings_autosave_secs=1\n");
        assert_eq!(parsed.settings_autosave_secs, SETTINGS_AUTOSAVE_MIN_SECS);

        // Unparseable is not a value at all — keep what is already there.
        let parsed = parse_preferences("admin_auto_revoke_minutes=abc\n");
        assert_eq!(
            parsed.admin_auto_revoke_minutes,
            UiPreferences::default().admin_auto_revoke_minutes
        );
    }

    #[test]
    fn a_signature_past_the_ceiling_keeps_the_stored_one() {
        let oversized = "a".repeat(MAX_STORED_STRING_BYTES + 1);
        let parsed = parse_preferences(&format!("unenforced_apps_ack_signature={oversized}\n"));
        // Refused, not truncated: half a signature matches nothing but still
        // looks like an answer.
        assert!(parsed.unenforced_apps_ack_signature.is_empty());

        let at_ceiling = "b".repeat(MAX_STORED_STRING_BYTES);
        let parsed = parse_preferences(&format!("unenforced_apps_ack_signature={at_ceiling}\n"));
        assert_eq!(parsed.unenforced_apps_ack_signature, at_ceiling);
    }

    #[test]
    fn every_stored_blob_passes_the_same_gate() {
        // The gate lived in five hand-copied places; the risk was one of them
        // drifting. This pins all four keys to the single declaration.
        let oversized = format!("{{{}}}", "x".repeat(MAX_STORED_JSON_BLOB_BYTES));
        let content = format!(
            "route_pending_offline_json={{\"a\":1}}\n\
             cache_table_column_widths=not-an-object\n\
             service_backed_mirror_json={oversized}\n\
             service_intent_json={{\"mode\":\"resolver\"}}\n"
        );
        let parsed = parse_preferences(&content);

        assert_eq!(parsed.route_pending_offline_json, "{\"a\":1}");
        assert_eq!(parsed.service_intent_json, "{\"mode\":\"resolver\"}");
        assert!(parsed.cache_table_column_widths.is_empty());
        assert!(parsed.service_backed_mirror_json.is_empty());
    }

    #[test]
    fn an_unknown_key_in_a_current_file_is_dropped_not_carried() {
        // Negative control for the carry above: at our own version an unknown
        // key is the residue of a key we removed, and it must not live forever.
        let content = format!(
            "schema_version={CURRENT_UI_PREFS_SCHEMA_VERSION}\ntheme_mode=dark\nretired_key=1\n"
        );
        let parsed = parse_preferences(&content);
        assert_eq!(parsed.forward_compat, ForwardCompat::default());
        assert!(!format_preferences(&parsed).contains("retired_key"));
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
        // A file of our own version carries nothing forward.
        assert_eq!(
            parse_preferences(&content).forward_compat,
            ForwardCompat::default()
        );
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
        // An absent key is a legacy v0 file: nothing to carry, no warning.
        assert!(declared_schema_version("theme_mode=dark\nlanguage=ru\n").is_none());
        assert_eq!(parsed.forward_compat, ForwardCompat::default());
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

    #[test]
    fn a_gutted_primary_file_recovers_from_the_backup() {
        // A power cut can commit the rename while the data blocks are still
        // unflushed: the primary survives as an empty (or NUL-filled) husk.
        let (_dir, path) = test_path("gutted.conf");
        let store = UiPreferencesStore::for_path(path.clone());
        let expected = UiPreferences {
            theme_mode: ThemeMode::Light,
            first_run_completed: true,
            ..UiPreferences::default()
        };
        store.save(&expected).expect("first save");
        store
            .save(&expected)
            .expect("second save writes the backup");

        for husk in ["", "\0\0\0\0", "# NetRuleRouter managed UI preferences\n"] {
            fs::write(&path, husk).expect("plant the husk");
            let loaded = store.load().expect("load must recover");
            assert!(
                loaded.first_run_completed,
                "husk {husk:?} must fall back to the backup, not to defaults"
            );
            assert_eq!(loaded.theme_mode, ThemeMode::Light);
        }
    }

    #[test]
    fn a_missing_primary_file_recovers_from_the_backup() {
        let (_dir, path) = test_path("missing.conf");
        let store = UiPreferencesStore::for_path(path.clone());
        let expected = UiPreferences {
            accepted_eula_version: 1,
            ..UiPreferences::default()
        };
        store.save(&expected).expect("first save");
        store
            .save(&expected)
            .expect("second save writes the backup");
        fs::remove_file(&path).expect("drop the primary");

        let loaded = store.load().expect("load must recover");
        assert_eq!(loaded.accepted_eula_version, 1);
    }

    #[test]
    fn a_gutted_primary_never_overwrites_a_good_backup() {
        // After the husk was loaded as defaults, the very next save must not
        // copy the husk over the last good backup.
        let (_dir, path) = test_path("preserve-bak.conf");
        let store = UiPreferencesStore::for_path(path.clone());
        let good = UiPreferences {
            first_run_completed: true,
            ..UiPreferences::default()
        };
        store.save(&good).expect("first save");
        store.save(&good).expect("second save writes the backup");

        fs::write(&path, "").expect("plant the husk");
        store
            .save(&UiPreferences::default())
            .expect("save over the husk");
        let backup = fs::read_to_string(path.with_extension("bak")).expect("backup exists");
        assert!(
            backup.contains("first_run_completed=true"),
            "the good backup must survive a save over a gutted primary"
        );
    }

    #[test]
    fn first_launch_with_no_files_still_defaults() {
        let (_dir, path) = test_path("fresh.conf");
        let store = UiPreferencesStore::for_path(path);
        let loaded = store.load().expect("fresh load");
        assert!(!loaded.first_run_completed);
    }

    fn test_dir(prefix: &str) -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix(&format!("nrr-ui-preferences-tests-{prefix}-"))
            .tempdir()
            .unwrap_or_else(|error| panic!("failed to create temp dir: {error}"))
    }

    /// A damaged protocol mask used to be masked into meaning: `128 & 0x7F` is
    /// zero, an empty mask makes the codegen emit no filter, and the kill
    /// switch then reads as ON while blocking nothing — and the value is seeded
    /// back into the service after its database is cleared.
    #[test]
    fn a_nonsense_protocol_mask_keeps_the_default_instead_of_disarming() {
        let default = UiPreferences::default().route_kill_switch_protocols;
        for garbage in ["128", "256", "0", "4294967295", "-1", "seven"] {
            let parsed = parse_preferences(&format!("route_kill_switch_protocols={garbage}\n"));
            assert_eq!(
                parsed.route_kill_switch_protocols, default,
                "{garbage:?} must not redefine the protocol mask",
            );
        }
        // A legitimate selection still round-trips.
        let parsed = parse_preferences("route_kill_switch_protocols=5\n");
        assert_eq!(parsed.route_kill_switch_protocols, 5);
    }

    #[test]
    fn a_parked_intent_past_its_window_does_not_survive_the_load() {
        let day_ms = 24 * 60 * 60 * 1000_i64;
        let prefs = UiPreferences {
            route_pending_offline_json:
                r#"{"parked-at-ms":1000,"route-policy":{"kill-switch":true}}"#.to_string(),
            ..UiPreferences::default()
        };

        let fresh = without_expired_parked_intents(prefs.clone(), 1000 + day_ms);
        assert!(
            !fresh.route_pending_offline_json.is_empty(),
            "a day-old intent is still the decision the user made"
        );

        let stale = without_expired_parked_intents(prefs, 1000 + 8 * day_ms);
        assert!(
            stale.route_pending_offline_json.is_empty(),
            "a week-old 'block everything' must not land on the next connect"
        );
    }
}
