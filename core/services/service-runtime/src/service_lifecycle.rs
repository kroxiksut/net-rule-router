//! Service identity policy, privilege matrix, and install/update/uninstall
//! configuration types.
//!
//! ## Service identity decision
//!
//! Both `CreateIpForwardEntry2` (route table) and `FwpmEngineOpen0`/`FwpmFilterAdd0`
//! (WFP) require an **elevated admin token** on Windows Vista+.
//! `NT AUTHORITY\LocalService` is insufficient for either operation.
//!
//! **Resolved decision: the service must run as `NT AUTHORITY\LocalSystem`.**
//! See [`required_service_identity`] for the authoritative value with
//! justification. `PRELIMINARY_IDENTITY` retains its `LocalService` value for
//! reference; it was the optimistic initial candidate before the privilege
//! survey.
//!
//! `LocalSystem` is acceptable here because:
//! - Both route-table and WFP operations require it on Windows Vista+.
//! - There is no viable non-admin path (SeNetworkServicePrivilege alone
//!   is insufficient for `CreateIpForwardEntry2` on Vista+).
//! - A dedicated Administrators-group service account is equivalent privilege
//!   for these operations — a post-MVP improvement if fine-grained auditing
//!   is desired.
//!
//! ## Privilege matrix
//!
//! [`PRIVILEGE_MATRIX`] lists every service operation alongside the
//! minimum Windows right required, the candidate identity, and a
//! fallback strategy. The matrix is the authoritative reference for the
//! least-privilege handoff.
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

// ── Service identity ──────────────────────────────────────────────────────────

/// Candidate service account, ranked least → most privileged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServiceIdentityDecision {
    /// `NT AUTHORITY\LocalService`. No network credentials, very limited
    /// local filesystem access.
    ///
    /// **Insufficient for route-table and WFP operations.** Retained as a
    /// variant for documentation purposes and for components that
    /// genuinely run as LocalService (IPC pipe, storage).
    LocalService,
    /// A dedicated Windows managed service account (gMSA or sMSA).
    /// Same effective privilege as `LocalService` with a better per-service
    /// audit trail.
    DedicatedAccount { account_name: String },
    /// `NT AUTHORITY\LocalSystem`. Unrestricted local access and implicit
    /// admin. Required for `CreateIpForwardEntry2` (route table) and
    /// `FwpmEngineOpen0`/`FwpmFilterAdd0` (WFP) on Windows Vista+.
    ///
    /// **This is the resolved identity for this service** — see
    /// [`required_service_identity`] and `PRIVILEGE_MATRIX`.
    LocalSystem { justification: String },
}

impl ServiceIdentityDecision {
    /// Returns `true` when this identity has unrestricted local privilege.
    pub fn is_full_local_privilege(&self) -> bool {
        matches!(self, Self::LocalSystem { .. })
    }

    /// Returns `true` when the identity is considered minimal.
    pub fn is_minimal(&self) -> bool {
        matches!(self, Self::LocalService | Self::DedicatedAccount { .. })
    }
}

/// Optimistic preliminary identity considered before the Win32 privilege
/// survey. Retained for reference. The **actual resolved identity** is
/// `required_service_identity()`.
///
/// See module doc for the full rationale.
pub const PRELIMINARY_IDENTITY: ServiceIdentityDecision = ServiceIdentityDecision::LocalService;

/// The resolved service identity, from the Win32 privilege survey.
///
/// Both `CreateIpForwardEntry2` (route table) and `FwpmEngineOpen0`
/// (WFP filter management) require an elevated admin token on Windows
/// Vista+. `LocalService` cannot perform these operations.
pub fn required_service_identity() -> ServiceIdentityDecision {
    ServiceIdentityDecision::LocalSystem {
        justification: concat!(
            "Block 15.2 survey: CreateIpForwardEntry2 (IPv4 route add/delete) and ",
            "FwpmEngineOpen0/FwpmFilterAdd0 (WFP dynamic filter management) both require ",
            "an elevated admin token on Windows Vista+. NT AUTHORITY\\LocalService is ",
            "insufficient for either operation. LocalSystem provides the required privilege ",
            "level. A dedicated Administrators-group account is an equivalent post-MVP option ",
            "for improved auditability."
        )
        .to_string(),
    }
}

/// Windows account name string for `NT AUTHORITY\LocalService`.
/// Retained for documentation; not used for the apply layer.
pub const NT_LOCAL_SERVICE_ACCOUNT: &str = "NT AUTHORITY\\LocalService";

// ── Privilege matrix ──────────────────────────────────────────────────────────

/// Minimum privilege requirement for one service operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityRequirement {
    /// `NT AUTHORITY\LocalService` suffices.
    LocalService,
    /// Local admin group membership required (installer-time operations).
    LocalAdmin,
    /// `NT AUTHORITY\LocalSystem` or equivalent full local privilege.
    LocalSystem,
}

/// One row in the privilege matrix.
pub struct PrivilegeMatrixEntry {
    /// Short name for the operation.
    pub operation: &'static str,
    /// Specific Windows right / capability required.
    pub required_right: &'static str,
    /// The minimum service identity that satisfies this requirement.
    pub min_identity: IdentityRequirement,
    /// Why this right is needed.
    pub justification: &'static str,
    /// What happens if the right is unavailable.
    pub fallback: &'static str,
}

/// The full privilege matrix for the `nrr-windows-service` baseline.
pub static PRIVILEGE_MATRIX: &[PrivilegeMatrixEntry] = &[
    PrivilegeMatrixEntry {
        operation: "read/write service-owned SQLite DBs",
        required_right: "filesystem read+write to %ProgramData%\\NetRuleRouter\\",
        min_identity: IdentityRequirement::LocalService,
        justification: "SQLite stores active revision, LKG pointer, cache, and security alerts",
        fallback: "service fails to start with RecoveryRequired; operator must fix ACLs",
    },
    PrivilegeMatrixEntry {
        operation: "create %ProgramData%\\NetRuleRouter\\ directory tree",
        required_right: "SeCreateDirectoryPrivilege / write to %ProgramData%",
        min_identity: IdentityRequirement::LocalAdmin,
        justification: "installer runs elevated; service only needs existing dirs at runtime",
        fallback: "installer aborts with clear error; no silent partial install",
    },
    PrivilegeMatrixEntry {
        operation: "create/listen on named pipe for GUI/tray IPC",
        required_right: "FILE_CREATE_PIPE_INSTANCE on \\\\.\\pipe\\NrrService",
        min_identity: IdentityRequirement::LocalService,
        justification: "named pipe server in LocalService context; pipe ACL restricts clients",
        fallback: "IPC unavailable; GUI/tray show 'service not reachable' banner",
    },
    PrivilegeMatrixEntry {
        operation: "write Windows Event Log entries",
        required_right: "Event Log write access to Application or custom source",
        min_identity: IdentityRequirement::LocalService,
        justification: "service lifecycle events (start/stop/crash) go to Event Log for admins",
        fallback: "Event Log write skipped; NDJSON audit still captures events",
    },
    PrivilegeMatrixEntry {
        operation: "register/deregister service with SCM (install/uninstall)",
        required_right: "ServiceManagerAccess::CREATE_SERVICE | DELETE",
        min_identity: IdentityRequirement::LocalAdmin,
        justification: "SCM registration requires admin; installer runs elevated",
        fallback: "install/uninstall aborts; service not registered or removed",
    },
    PrivilegeMatrixEntry {
        operation: "modify Windows routing table (IPv4 route add/delete)",
        required_right: "Elevated admin token; CreateIpForwardEntry2 requires admin on Vista+",
        min_identity: IdentityRequirement::LocalSystem,
        justification: concat!(
            "Block 15.2: CreateIpForwardEntry2 / DeleteIpForwardEntry2 require an elevated ",
            "admin token on Windows Vista+. SeNetworkServicePrivilege alone is NOT sufficient ",
            "on Vista+ (it was on XP). LocalSystem satisfies this requirement. IPv6 routes ",
            "are out of scope — only IPv4 route entries are ever added."
        ),
        fallback: concat!(
            "Service starts but transitions to RecoveryRequired with health status ",
            "'insufficient privileges for routing operations'; apply operations are blocked ",
            "until service runs under LocalSystem or an Administrators-group account."
        ),
    },
    PrivilegeMatrixEntry {
        operation: "WFP dynamic filter management (Fail-Closed blocking, application rules)",
        required_right: "Elevated admin token; FwpmEngineOpen0 requires admin for dynamic objects",
        min_identity: IdentityRequirement::LocalSystem,
        justification: concat!(
            "Block 15.2: FwpmEngineOpen0 with dynamic (volatile) session requires an admin token ",
            "on Windows Vista+. Persistent WFP objects also require admin. ",
            "We use volatile filters (non-persistent) so filters auto-remove on session close — ",
            "this provides automatic orphan cleanup on service crash. ",
            "No kernel-mode WFP callout driver is used in MVP (Pro feature)."
        ),
        fallback: concat!(
            "Fail-Closed enforcement and application-rule blocking become unavailable. ",
            "Service warns in health status; secondary-route rules fall back to FailOpen behavior ",
            "which may leak traffic. GUI/tray surfaces 'WFP unavailable — Fail-Closed disabled' ",
            "banner."
        ),
    },
];

// ── ACL / directory requirements ─────────────────────────────────────────────

/// Directories the installer must create and the service must be able to
/// access at runtime.
pub struct ServiceDirectory {
    /// Path relative to `%ProgramData%\NetRuleRouter\`.
    pub relative_path: &'static str,
    /// Who can read this directory.
    pub read_access: &'static str,
    /// Who can write to this directory.
    pub write_access: &'static str,
    /// Purpose of this directory.
    pub purpose: &'static str,
}

/// Canonical set of directories the service owns.
pub static SERVICE_DIRECTORIES: &[ServiceDirectory] = &[
    ServiceDirectory {
        relative_path: "",
        read_access: "LocalService, SYSTEM, Administrators",
        write_access: "LocalService, SYSTEM, Administrators",
        purpose: "root service data directory",
    },
    ServiceDirectory {
        relative_path: "logs",
        read_access: "LocalService, SYSTEM, Administrators",
        write_access: "LocalService, SYSTEM",
        purpose: "operational NDJSON log files",
    },
    ServiceDirectory {
        relative_path: "audit",
        read_access: "LocalService, SYSTEM, Administrators",
        write_access: "LocalService, SYSTEM",
        purpose: "append-only NDJSON audit trail",
    },
    ServiceDirectory {
        relative_path: "backup",
        read_access: "LocalService, SYSTEM, Administrators",
        write_access: "LocalService, SYSTEM",
        purpose: "pre-migration state DB backups",
    },
];

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
}

// ── Security checklist ────────────────────────────────────────────────────────

/// Manual security checklist items for the service identity security review.
///
/// These are human-readable invariants, not executable tests. Reviewed by
/// the security team; validated in production by the smoke script
/// (`scripts/service-smoke.ps1`).
///
/// # Checklist
///
/// 1. **No LocalSystem by default.**
///    `install_service()` MUST use `NT AUTHORITY\LocalService` (or a
///    dedicated managed service account) unless a specific operation
///    documented in [`PRIVILEGE_MATRIX`] requires higher privilege.
///
/// 2. **No user-writable source of truth.**
///    The service-owned DB files (`nrr_service_state.db`,
///    `nrr_fqdn_ip_cache.db`) live in `%ProgramData%` with ACLs that
///    prevent unprivileged users from modifying them.  GUI/tray processes
///    running as a normal user MUST NOT be able to write these files
///    directly — all mutations go through the named-pipe IPC boundary.
///
/// 3. **Named pipe ACL restricted.**
///    `\\\\.\\pipe\\NrrService` MUST have a DACL that allows only:
///    the service itself (LocalService), SYSTEM, Administrators, and
///    interactive user sessions (read/write for GUI/tray).  Anonymous
///    access MUST be denied.
///
/// 4. **GUI cannot write service state.**
///    No code path from `nrr-desktop-gui`, `nrr-desktop-tray`, or
///    `nrr-launcher` may import `nrr-service-runtime` (enforced by
///    `dependency_boundary.rs`). Mutations go through
///    `IpcOperationClass::MutationRequest` with a confirmation token.
///
/// 5. **Repeated-crash backstop.**
///    SCM recovery actions MUST cap at [`RecoveryPolicy::max_auto_restarts`]
///    consecutive restarts. After that, the service remains stopped so an
///    operator can investigate rather than entering an infinite crash loop
///    that could corrupt the state DB.
pub struct SecurityChecklist;

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preliminary_identity_is_local_service_for_historical_reference() {
        // PRELIMINARY_IDENTITY is the optimistic value considered before
        // the privilege survey. The resolved identity is
        // required_service_identity() = LocalSystem.
        assert!(PRELIMINARY_IDENTITY.is_minimal());
        assert!(!PRELIMINARY_IDENTITY.is_full_local_privilege());
    }

    #[test]
    fn required_identity_is_local_system_with_justification() {
        let identity = required_service_identity();
        assert!(
            identity.is_full_local_privilege(),
            "block 15.2 resolved identity must be LocalSystem"
        );
        // Justification must mention both operations that require admin.
        if let ServiceIdentityDecision::LocalSystem { justification } = &identity {
            assert!(
                justification.contains("CreateIpForwardEntry2"),
                "justification must reference route-table operation"
            );
            assert!(
                justification.contains("FwpmEngineOpen0"),
                "justification must reference WFP operation"
            );
        } else {
            panic!("required_service_identity() must return LocalSystem");
        }
    }

    #[test]
    fn local_system_is_full_privilege() {
        let ls = ServiceIdentityDecision::LocalSystem {
            justification: "test".to_string(),
        };
        assert!(ls.is_full_local_privilege());
        assert!(!ls.is_minimal());
    }

    #[test]
    fn privilege_matrix_is_non_empty_and_covers_storage_and_ipc() {
        assert!(!PRIVILEGE_MATRIX.is_empty());
        let ops: Vec<&str> = PRIVILEGE_MATRIX.iter().map(|e| e.operation).collect();
        assert!(
            ops.iter().any(|op| op.contains("SQLite")),
            "matrix must cover storage access"
        );
        assert!(
            ops.iter().any(|op| op.contains("named pipe")),
            "matrix must cover IPC pipe"
        );
        assert!(
            ops.iter()
                .any(|op| op.contains("WFP") || op.contains("routing")),
            "matrix must cover platform apply operations"
        );
    }

    #[test]
    fn privilege_matrix_has_no_tbd_entries_after_block_15_2() {
        // TBDBlock15 variant has been removed from IdentityRequirement.
        // All entries must have a concrete resolved identity.
        for entry in PRIVILEGE_MATRIX {
            // If any entry still has a justification referencing TODO:,
            // it was not properly resolved.
            assert!(
                !entry.justification.starts_with("TODO(block-15)"),
                "entry '{}' still has an unresolved TODO(block-15) justification",
                entry.operation
            );
        }
    }

    #[test]
    fn routing_and_wfp_entries_require_local_system() {
        // Routing and WFP operations must resolve to LocalSystem.
        let route_entry = PRIVILEGE_MATRIX
            .iter()
            .find(|e| e.operation.contains("routing table"))
            .expect("routing table entry must exist in matrix");
        assert_eq!(
            route_entry.min_identity,
            IdentityRequirement::LocalSystem,
            "IPv4 route modification must require LocalSystem"
        );

        let wfp_entry = PRIVILEGE_MATRIX
            .iter()
            .find(|e| e.operation.contains("WFP"))
            .expect("WFP entry must exist in matrix");
        assert_eq!(
            wfp_entry.min_identity,
            IdentityRequirement::LocalSystem,
            "WFP filter management must require LocalSystem"
        );
    }

    #[test]
    fn service_directories_all_have_service_write_access() {
        for dir in SERVICE_DIRECTORIES {
            assert!(
                dir.write_access.contains("LocalService") || dir.write_access.contains("SYSTEM"),
                "directory '{}' must be writable by LocalService or SYSTEM",
                dir.relative_path
            );
        }
    }

    #[test]
    fn service_directories_gui_cannot_write_directly() {
        for dir in SERVICE_DIRECTORIES {
            let write = dir.write_access.to_lowercase();
            assert!(
                !write.contains("users") && !write.contains("everyone"),
                "directory '{}' must not grant write to unprivileged users",
                dir.relative_path
            );
        }
    }

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

    #[test]
    fn nt_local_service_account_constant_is_correct() {
        // The string must match what Windows expects for account_name
        // in ServiceInfo when registering a service to run as LocalService.
        assert_eq!(NT_LOCAL_SERVICE_ACCOUNT, "NT AUTHORITY\\LocalService");
    }
}
