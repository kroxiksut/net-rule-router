//! Install/update/uninstall configuration types.
//!
//! The service runs as `NT AUTHORITY\LocalSystem`: route-table changes
//! (`CreateIpForwardEntry2`) and WFP filter management (`FwpmEngineOpen0` /
//! `FwpmFilterAdd0`) both need an elevated admin token, which `LocalService`
//! does not have. A dedicated Administrators-group account would be equivalent
//! privilege with a better audit trail.
//!
//! ## Configuration types
//!
//! [`InstallConfig`], [`UpdateConfig`], and [`UninstallConfig`] carry the
//! parameters for the three lifecycle flows. The OS mechanism they drive lives
//! behind `nrr_platform_api::service_control::ServiceControlPort`; this module
//! is pure Rust and fully unit-testable without admin or a real service
//! manager.
//!
//! The install parameters, the start mode and the recovery policy are the
//! port's own vocabulary and are defined there — re-exported here under their
//! established names so callers keep one spelling. What stays local is the part
//! the port deliberately does not own: an uninstall *flow* additionally decides
//! whether to export diagnostics first, and an update flow decides whether to
//! back up the state database.

use std::path::PathBuf;

use nrr_platform_api::service_control::ServiceUninstallSpec;
pub use nrr_platform_api::service_control::{
    RecoveryPolicy, ServiceInstallReport as InstallOutcome, ServiceInstallSpec as InstallConfig,
    ServiceStartMode,
};

// ── Update configuration ──────────────────────────────────────────────────────

/// Parameters for the update (in-place upgrade) flow.
#[derive(Clone, Debug)]
pub struct UpdateConfig {
    /// Path to the new binary that should replace the registered one.
    pub new_binary_path: PathBuf,
    /// Seconds to wait for the service to drain in-flight requests before
    /// forcing a stop.
    pub drain_timeout_secs: u64,
    /// Whether to create a `.bak` copy of `nrr_service_state.db` before
    /// applying migrations.
    pub backup_state_db: bool,
    /// Whether to restart the service automatically after binary replacement.
    pub restart_after_update: bool,
}

impl UpdateConfig {
    pub fn default_for(new_binary_path: PathBuf) -> Self {
        Self {
            new_binary_path,
            drain_timeout_secs: 30,
            backup_state_db: true,
            restart_after_update: true,
        }
    }
}

// ── Uninstall configuration ───────────────────────────────────────────────────

/// Parameters for the uninstall flow.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UninstallConfig {
    /// When `true`, the service-owned data directories
    /// (`%ProgramData%\NetRuleRouter\`) are deleted after the service is
    /// removed. When `false`, they are left for the user / administrator.
    pub remove_service_owned_data: bool,
    /// When `true`, the user's rule files (typically in `%AppData%` or the
    /// path configured in settings) are preserved even if
    /// `remove_service_owned_data` is `true`. Rule files belong to the user,
    /// not the service, and must never be silently deleted.
    pub preserve_user_rule_files: bool,
}

impl UninstallConfig {
    /// Keep everything — the default, and what removing the service alone
    /// means: the service registration goes away, the data stays. Nothing is
    /// rescued ahead of time because nothing is destroyed.
    pub fn keep_data() -> Self {
        Self {
            remove_service_owned_data: false,
            preserve_user_rule_files: true,
        }
    }

    /// Remove service-owned data as well. This is the application-removal
    /// path (the installer's), not the service-removal path: user rule files
    /// still live outside the tree and are preserved.
    pub fn purge_data() -> Self {
        Self {
            remove_service_owned_data: true,
            preserve_user_rule_files: true,
        }
    }

    /// The part of this flow the OS actually performs. User rule files live
    /// outside the service-owned tree, so that promise never reaches the
    /// service manager.
    pub fn port_spec(&self) -> ServiceUninstallSpec {
        ServiceUninstallSpec {
            remove_service_owned_data: self.remove_service_owned_data,
        }
    }
}

// ── Outcomes ──────────────────────────────────────────────────────────────────

/// Result of a completed update flow.
#[derive(Clone, Debug)]
pub struct UpdateOutcome {
    /// Path of the state DB backup, if one was created.
    pub state_db_backup: Option<PathBuf>,
    /// Whether the service was restarted after the update.
    pub service_restarted: bool,
}

/// Result of a completed uninstall flow.
#[derive(Clone, Debug)]
pub struct UninstallOutcome {
    /// Whether service-owned data directories were deleted.
    pub data_removed: bool,
    /// Whether user rule files were explicitly preserved (not touched).
    pub rule_files_preserved: bool,
    /// Whether the enforcement state left on the machine (packet filters, DNS
    /// redirection) was swept before the registration went away. `None` where
    /// the platform does not sweep during removal.
    pub machine_state_cleared: Option<bool>,
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uninstall_keep_data_preserves_everything() {
        let cfg = UninstallConfig::keep_data();
        assert!(!cfg.remove_service_owned_data);
        assert!(cfg.preserve_user_rule_files);
    }

    #[test]
    fn uninstall_purge_still_preserves_user_rules() {
        let cfg = UninstallConfig::purge_data();
        assert!(cfg.remove_service_owned_data);
        assert!(
            cfg.preserve_user_rule_files,
            "user rule files must never be silently deleted"
        );
    }

    #[test]
    fn uninstall_port_spec_carries_only_what_the_os_performs() {
        // User rule files live outside the service-owned tree, so that promise
        // must not leak into what the service manager is told to do.
        let cfg = UninstallConfig::purge_data();
        assert!(cfg.port_spec().remove_service_owned_data);
        assert!(
            !UninstallConfig::keep_data()
                .port_spec()
                .remove_service_owned_data
        );
    }

    #[test]
    fn update_config_defaults_backup_and_restart() {
        let cfg = UpdateConfig::default_for(PathBuf::from("v2.exe"));
        assert!(cfg.backup_state_db);
        assert!(cfg.restart_after_update);
        assert!(cfg.drain_timeout_secs > 0);
    }
}
