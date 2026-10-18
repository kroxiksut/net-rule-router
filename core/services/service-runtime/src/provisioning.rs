//! Files an administrator hands the installer: rules for both routes, a
//! settings export and install options, applied once at the service's first
//! start into the shared baseline every user reads through.
//!
//! ```text
//!  installer ──► provision-check / provision-stage (this binary) ──► <provision dir>
//!                        same bytes validated and written                  │
//!  service start ──► read (bounded) ──► check ──► PresetImport → baseline ─┤
//!                                                 install policy           │
//!                                     audit + alert on refusal ──► *.applied / *.refused
//! ```
//!
//! The source path is never remembered: a file read later from a path given at
//! install time could have been swapped. The files are hostile bytes like any
//! import, so they meet the same bounded parser and the same submission gates;
//! the two readers of their own (settings, options) have a fuzz target.

mod apply;
pub mod bundle;
pub mod cli;
mod folder;

#[cfg(test)]
mod tests;

pub use apply::{apply_staged, ProvisionApplier, ProvisionApplyOutcome};
pub use bundle::{
    check_bundle, BundleBytes, CheckedBundle, InstallOptions, ProvisionPart, ProvisionRefusal,
    SettingsFacts,
};
pub use folder::{mark_processed, read_bundle, read_source_file, stage_bundle, ProcessedAs};

/// Names inside the provisioning folder. Fixed: the folder holds nothing else
/// the service reads.
pub const PRIMARY_FILE: &str = "rules_primary.txt";
pub const SECONDARY_FILE: &str = "rules_secondary.txt";
pub const SETTINGS_FILE: &str = "settings.yaml";
pub const OPTIONS_FILE: &str = "options.conf";

/// A settings export is a few hundred bytes; this leaves room for comments.
pub const SETTINGS_MAX_BYTES: usize = 64 * 1024;
pub const OPTIONS_MAX_BYTES: usize = 4 * 1024;
/// The import limit: a provisioned file is an import.
pub const RULES_MAX_BYTES: usize = nrr_domain::import::IMPORT_FILE_SIZE_LIMIT_BYTES as usize;

/// Exit codes of the `provision-check` and `provision-stage` verbs. The
/// installers pass them through to their logs; the documentation names them.
pub mod exit {
    pub const OK: u8 = 0;
    /// No file given, an unknown option, or a value missing.
    pub const USAGE: u8 = 2;
    pub const PRIMARY_REFUSED: u8 = 10;
    pub const SECONDARY_REFUSED: u8 = 11;
    pub const SETTINGS_REFUSED: u8 = 12;
    pub const OPTION_REFUSED: u8 = 13;
    /// The protected folder could not be prepared or written.
    pub const STAGE_FAILED: u8 = 14;
}
