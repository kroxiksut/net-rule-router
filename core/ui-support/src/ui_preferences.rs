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
    /// Experimental opt-in: reveal the Rules -> Virtual machines screen.
    /// `false` (default) hides the screen and its sidebar entry; hypervisor
    /// routing is unverified. Pure device-local UI display preference.
    pub show_virtual_machines_section: bool,
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
    /// Overlaps between the two routes the user confirmed, as the keys the
    /// overlap detector reports joined with `|`. A confirmed pair drops out of
    /// the Overlaps count. Device-local UI state, never exported.
    pub route_overlaps_confirmed_signature: String,
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

mod defaults;
pub use defaults::*;
mod store;
pub use store::*;
mod file_format;
pub use file_format::*;

#[cfg(test)]
mod tests;
