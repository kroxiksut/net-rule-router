//! Stub for the Free-edition full settings export format (v1).
//!
//! [`SettingsExportV1`] is the top-level type for the YAML settings export used
//! for Free → Pro migration and for backup/restore. Serialization and
//! deserialization are not yet wired.
//!
//! # What is included
//!
//! - Adapter bindings: system ID (`mac + ifindex` composite), user label,
//!   confirmation status.
//! - Rule file paths (not embedded rule content — only the file paths).
//! - Behavior settings: route mode, file-change behavior, child-process option.
//! - UI preferences: theme, language, route display labels, accessibility.
//!
//! # What is NOT included
//!
//! - The actual content of the rule files — those are separate files at the
//!   stored paths.
//! - Internal revision metadata (revision IDs, content hashes, audit events).
//! - Device-specific runtime state (connectivity probes, external IP).
//!
//! # Adapter system ID format
//!
//! `"mac=AA:BB:CC:DD:EE:FF;ifindex=3"` — composite key that is stable on the
//! same device. On import to a different device, the GUI presents an
//! adapter-selection dialog when the stored ID is not found.
//!
//! # On import — file not found
//!
//! If a rule file path in the export does not exist at import time, the GUI
//! presents a dialog with three choices:
//! - **Browse** — locate the file at a new path.
//! - **Skip** — start with empty rules for that route.
//! - **Cancel** — abort the import.

/// Adapter binding record within a settings export.
pub struct ExportedAdapterBinding {
    /// Composite system identifier: `"mac=AA:BB:CC:DD:EE:FF;ifindex=3"`.
    ///
    /// Stable on the same device. Used to restore the binding on re-import
    /// without relying on adapter names, which can change across reboots.
    pub system_id: String,
    /// User-assigned display label (e.g. `"Основная сеть"` or `"VPN"`).
    pub user_label: String,
    /// `true` when the user explicitly confirmed this adapter for the role.
    pub user_confirmed: bool,
}

/// Rule file path records within a settings export.
///
/// Files are NOT embedded in the export — only their absolute paths are stored.
/// This keeps the export small and avoids duplicating potentially large rule files.
pub struct ExportedRuleFiles {
    /// Absolute path to the primary route rule file.
    /// Empty string means no file is currently configured for this route.
    pub primary_path: String,
    /// Absolute path to the secondary route rule file.
    /// Empty string means no file is currently configured for this route.
    pub secondary_path: String,
}

/// Behavior settings within a settings export.
pub struct ExportedBehaviorSettings {
    /// Route behavior mode slug (e.g. `"prefer-primary"`).
    /// Corresponds to `RouteBehaviorMode::slug()`.
    pub route_mode: String,
    /// File-change behavior slug (e.g. `"notify"` or `"auto-apply"`).
    /// Corresponds to `RulesFileChangeBehavior::slug()`.
    pub file_change_behavior: String,
    /// Whether rules are applied to direct child processes of a matched application.
    /// Controlled by "Apply rules to child processes" in GUI Settings.
    pub include_child_processes: bool,
}

/// UI preference fields within a settings export.
///
/// These are the visual and interaction preferences that should follow the user
/// to a new device or Pro installation. Device-specific runtime state is excluded.
pub struct ExportedUiPreferences {
    /// Theme slug (`"light"`, `"dark"`, `"system"`, or `"high-contrast"`).
    pub theme: String,
    /// Language code (`"ru"`, `"en"`, etc.).
    pub language: String,
    /// User display label for the primary route (e.g. `"Основная"`).
    pub route_primary_label: String,
    /// User display label for the secondary route (e.g. `"VPN"`).
    pub route_secondary_label: String,
    /// Whether Bluetooth adapters are shown in the adapter list (default: `false`).
    pub show_bluetooth_adapters: bool,
}

/// Top-level Free-edition settings export (v1).
///
/// Full YAML serialization/deserialization is not yet wired.
/// This struct defines the data boundary only and carries no serde derives.
///
/// # Pro migration
///
/// A Pro installation can import this export as its starting configuration.
/// Adapter bindings, rule file paths, and behavior settings are migrated
/// directly. UI preferences are applied if the Pro version supports them.
pub struct SettingsExportV1 {
    /// Schema version. Always [`SettingsExportV1::VERSION`] for this struct.
    pub version: u32,
    /// Primary adapter binding. `None` when no adapter has been assigned yet.
    pub primary_adapter: Option<ExportedAdapterBinding>,
    /// Secondary adapter binding. `None` when no adapter has been assigned yet.
    pub secondary_adapter: Option<ExportedAdapterBinding>,
    /// Paths to the rule files for each route.
    pub rule_files: ExportedRuleFiles,
    /// Routing behavior settings.
    pub behavior: ExportedBehaviorSettings,
    /// User interface preferences.
    pub ui_preferences: ExportedUiPreferences,
}

impl SettingsExportV1 {
    /// The schema version this struct represents.
    pub const VERSION: u32 = 1;
}
