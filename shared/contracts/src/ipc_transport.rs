use serde::{Deserialize, Serialize};

use crate::ipc::IpcOperationName;

/// Local IPC transport mechanism. The wire codec (4-byte BE u32 length +
/// UTF-8 JSON, `IPC_MAX_MESSAGE_BYTES`) is identical across variants — only
/// the OS mechanism that carries the framed bytes differs. The active
/// variant is selected per-OS via [`IPC_TRANSPORT_KIND`]; this is the
/// policy/mechanism seam for cross-platform IPC, NOT a runtime choice.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IpcTransportKind {
    /// Windows `\\.\pipe\…` named pipe, DACL-protected, message mode.
    WindowsNamedPipes,
    /// Unix `AF_UNIX` filesystem socket, `0700`-dir protected, peer-cred
    /// (`SO_PEERCRED` → uid) for caller identity.
    UnixDomainSocket,
}

/// Canonical error codes exposed in the response envelope. The
/// transport layer never invents new codes; everything funnels
/// through this enum. Defined here (not in `nrr-service-runtime`) so
/// that `nrr-ipc-client` (forbidden from depending on
/// `nrr-service-runtime`) can preserve the typed code instead of
/// collapsing every server failure into a generic catch-all.
/// `nrr-service-runtime` re-exports this enum under its own path for
/// existing call sites.
///
/// Wire format: serde-encoded as `snake_case` (e.g. `"forbidden"`,
/// `"precondition_failed"`, `"recovery_required"`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpcErrorCode {
    /// Caller could not be authenticated (no/invalid token).
    Unauthorized,
    /// Caller is authenticated but is not allowed to invoke this
    /// operation class (typically: non-admin GUI tries a privileged
    /// mutation).
    Forbidden,
    /// An administrator has frozen rule authoring on this machine and the
    /// caller is not elevated. Distinct from [`Self::Forbidden`] on purpose:
    /// this is the one refusal a client must render as a durable, explained
    /// state (rules read-only, edit affordances disabled) rather than as a
    /// transient failure of the attempted action. It is returned by every
    /// rule-changing operation — submit, preset import, reset-to-baseline,
    /// rollback — so a client that maps this code once covers all of them.
    RulesLocked,
    /// Request envelope's `protocol_version` is incompatible with
    /// this service binary. Client should call `ContractNegotiate`.
    InvalidVersion,
    /// Envelope failed schema validation (missing field, wrong
    /// type, payload too big, etc.).
    MalformedRequest,
    /// Service is busy with another mutation for this caller class
    /// and rejected the request to avoid conflicts. Client may
    /// retry after backing off.
    BusyConflict,
    /// A documented precondition was violated (e.g. mutation
    /// submitted before review confirmation).
    PreconditionFailed,
    /// Service is in `Degraded` health and cannot fulfil the
    /// request right now. Caller should observe `ServiceHealth`
    /// and retry.
    ServiceDegraded,
    /// Service is in `RecoveryRequired` and requires user action
    /// before privileged operations resume. The error payload
    /// carries the recovery action slug.
    RecoveryRequired,
    /// Catch-all for unexpected internal failures. The payload
    /// carries a diagnostic id so an operator can correlate with
    /// the audit trail; no implementation detail is leaked.
    Internal,
}

impl IpcTransportKind {
    pub const fn slug(self) -> &'static str {
        match self {
            Self::WindowsNamedPipes => "windows-named-pipes",
            Self::UnixDomainSocket => "unix-domain-socket",
        }
    }
}

/// Transport mechanism for the host OS. Windows uses named pipes; every
/// Unix target (Linux, macOS) uses an `AF_UNIX` socket. Selected at compile
/// time — there is exactly one correct mechanism per OS, so this is a `cfg`
/// seam, not a feature flag.
#[cfg(windows)]
pub const IPC_TRANSPORT_KIND: IpcTransportKind = IpcTransportKind::WindowsNamedPipes;
#[cfg(unix)]
pub const IPC_TRANSPORT_KIND: IpcTransportKind = IpcTransportKind::UnixDomainSocket;

/// Canonical local IPC endpoint address for the `service-v1` protocol,
/// selected per-OS mechanism. Both ends — the client (`nrr-ipc-client`) and
/// the service — MUST derive their address from here so the two can never
/// drift. The `-v1` / `service-v1` version suffix lets a future protocol
/// migration bind a fresh address without colliding with running clients
/// during an upgrade.
///
/// - Windows: a DACL-protected named pipe under `\\.\pipe\NetRuleRouter\`.
/// - Unix: a filesystem socket under `/run/netrulerouter/` (the parent dir
///   carries the `0700` owner-only protection the pipe DACL provides on
///   Windows).
#[cfg(windows)]
pub const SERVICE_ENDPOINT_ADDRESS: &str = r"\\.\pipe\NetRuleRouter\service-v1";
#[cfg(unix)]
pub const SERVICE_ENDPOINT_ADDRESS: &str = "/run/netrulerouter/service-v1.sock";

/// Maximum size of a single wire-format frame (request or response),
/// in bytes. Both client (`nrr-ipc-client`) and server
/// (`nrr-windows-service`) enforce this limit. Frames larger than this
/// are rejected at the transport boundary with a malformed-request error.
///
/// Set to 1 MiB because `MutationSubmit` with `MutationKind::PresetImport`
/// carries the raw preset bytes (base64-wrapped) in the payload, and
/// `PresetExportGet` / `SettingsExportFull` responses ship base64-wrapped
/// file content. The ceiling mirrors
/// `nrr_domain::import::IMPORT_FILE_SIZE_LIMIT_BYTES` — the parse-stage
/// validator rejects files exceeding that cap before they reach the wire,
/// so the two boundaries agree.
///
/// Re-exported as `nrr_service_runtime::IPC_MAX_MESSAGE_BYTES` to keep
/// the import path stable for existing callers.
pub const IPC_MAX_MESSAGE_BYTES: usize = 1024 * 1024;

// ── Operation class ──────────────────────────────────────────────────────────

/// Coarse operation class. Drives:
/// - whether the request bypasses the mutation queue (`ReadSnapshot`,
///   `DiagnosticQuery` are read-only);
/// - whether elevation is required;
/// - whether a confirmation token must be carried (`MutationRequest`,
///   `RecoveryAction`, `SafeDisable`).
///
/// Declared here, alongside the wire format, because BOTH sides need the same
/// answer and neither may derive its own: the class is what the service's
/// admission checks are made of, so a second opinion is a way past them. See
/// [`canonical_operation_class`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IpcOperationClass {
    ReadSnapshot,
    DiagnosticQuery,
    DiagnosticAction,
    MutationRequest,
    ReviewConfirmation,
    RecoveryAction,
    SafeDisable,
    /// per-SID user configuration write. Mutating (flows through the mutation
    /// queue, audited before execution) but does **not** require client
    /// elevation — the data is the user's own per-SID configuration, not
    /// service-global policy. Single-step (no two-phase confirmation token).
    UserScopedConfiguration,
    /// per-principal rules/preset mutation. Like [`Self::MutationRequest`] it is
    /// two-phase (a confirmation token from a prior dry-run is mandatory), flows
    /// through the mutation queue, and is audited before execution — but it does
    /// **not** require client elevation. The target principal is the caller's own
    /// SID, never the service-global baseline, so a non-admin GUI session can
    /// commit *its own* rules. Editing the admin baseline still goes through
    /// [`Self::MutationRequest`] (elevation required).
    UserScopedMutation,
}

impl IpcOperationClass {
    /// Whether this class flows through the single-writer mutation queue.
    /// `false` for read-only and lightweight diagnostic queries.
    pub const fn is_mutating(self) -> bool {
        match self {
            Self::ReadSnapshot | Self::DiagnosticQuery => false,
            Self::DiagnosticAction
            | Self::MutationRequest
            | Self::ReviewConfirmation
            | Self::RecoveryAction
            | Self::SafeDisable
            | Self::UserScopedConfiguration
            | Self::UserScopedMutation => true,
        }
    }

    /// Whether the caller's process token must be elevated. Read-only
    /// operations, diagnostic actions that persist nothing (e.g. an on-demand
    /// adapter re-enumeration), and per-SID user configuration writes are safe
    /// for non-admin GUI sessions; everything else requires an elevated client.
    pub const fn requires_elevation(self) -> bool {
        !matches!(
            self,
            Self::ReadSnapshot
                | Self::DiagnosticQuery
                | Self::DiagnosticAction
                | Self::UserScopedConfiguration
                | Self::UserScopedMutation
        )
    }

    /// Whether the request envelope must carry a `confirmation_token` (issued by
    /// an earlier dry-run response). Dangerous classes require explicit two-step
    /// acknowledgement to prevent accidental network-policy mutation from a
    /// stuck GUI.
    pub const fn requires_confirmation_token(self) -> bool {
        matches!(
            self,
            Self::MutationRequest
                | Self::RecoveryAction
                | Self::SafeDisable
                | Self::UserScopedMutation
        )
    }

    pub const fn slug(self) -> &'static str {
        match self {
            Self::ReadSnapshot => "read-snapshot",
            Self::DiagnosticQuery => "diagnostic-query",
            Self::DiagnosticAction => "diagnostic-action",
            Self::MutationRequest => "mutation-request",
            Self::ReviewConfirmation => "review-confirmation",
            Self::RecoveryAction => "recovery-action",
            Self::SafeDisable => "safe-disable",
            Self::UserScopedConfiguration => "user-scoped-configuration",
            Self::UserScopedMutation => "user-scoped-mutation",
        }
    }
}

/// The class an operation ACTUALLY has, decided from the operation itself (and,
/// for the two-phase operations, the payload that distinguishes their phases).
///
/// This is what the service admits requests by. The class must never be taken
/// from the envelope the caller sent: the confirmation-token gate, the elevation
/// gate, the pre-execution audit record and the single-writer queue are all
/// selected by it, so a caller that names its own class names its own checks.
/// The envelope still carries a class for readability on the wire, and the
/// service compares the two — a mismatch is a bug in the caller, not a vote.
pub fn canonical_operation_class(
    op: IpcOperationName,
    payload: &serde_json::Value,
) -> IpcOperationClass {
    // Two-phase operations: the dry-run pass is classified read-only so it can
    // MINT the confirmation token the confirm pass is then required to carry.
    if matches!(op, IpcOperationName::ProductImpactDisableTemporary) {
        return if dry_run_flag(payload) {
            IpcOperationClass::ReadSnapshot
        } else {
            IpcOperationClass::SafeDisable
        };
    }
    if matches!(op, IpcOperationName::MutationSubmit) {
        if dry_run_flag(payload) {
            return IpcOperationClass::ReadSnapshot;
        }
        // An admin "set baseline" edit opts out of the per-principal path and
        // confirms as an elevation-gated service-global mutation. The flag only
        // steers the class here; the target principal is always resolved by the
        // service, never carried in the payload.
        let admin_baseline = payload
            .get("payload")
            .and_then(|p| p.get("admin-baseline"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if admin_baseline {
            return IpcOperationClass::MutationRequest;
        }
        // Per-principal rules / preset edits: two-phase but NOT elevation-gated,
        // so a non-admin session can commit its own rules. Everything else stays
        // service-global.
        let kind = payload.get("mutation-kind").and_then(|v| v.as_str());
        if matches!(
            kind,
            Some("rules-update") | Some("preset-import") | Some("rules-reset-to-baseline")
        ) {
            return IpcOperationClass::UserScopedMutation;
        }
        return IpcOperationClass::MutationRequest;
    }
    fixed_operation_class(op)
}

/// `dry-run: true` in the envelope payload.
fn dry_run_flag(payload: &serde_json::Value) -> bool {
    payload
        .get("dry-run")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

/// The class of every operation whose class does not depend on its payload.
/// Exhaustive on purpose: a new operation does not compile until it is
/// classified, which is the only way this table stays complete.
fn fixed_operation_class(op: IpcOperationName) -> IpcOperationClass {
    match op {
        // ContractNegotiate / ServiceHealthGet / snapshots / status polls /
        // operation-status are all read-only — no mutation, no token.
        IpcOperationName::ContractNegotiate
        | IpcOperationName::ServiceHealthGet
        | IpcOperationName::SnapshotInitialGet
        | IpcOperationName::SnapshotInterfacesGet
        | IpcOperationName::SnapshotDiagnosticsGet
        | IpcOperationName::StatusUpdatesPoll
        | IpcOperationName::OperationStatusGet
        | IpcOperationName::LogsList
        | IpcOperationName::AuditList
        | IpcOperationName::SecurityAlertsList
        | IpcOperationName::RulesList
        | IpcOperationName::MigrationStatusGet
        | IpcOperationName::RetentionSettingsGet
        // Read log/audit retention config.
        | IpcOperationName::LogRetentionConfigGet
        | IpcOperationName::ApplyFailurePolicyGet
        | IpcOperationName::StorageUsageGet
        | IpcOperationName::RoutingPauseGet
        | IpcOperationName::AutostartGet
        // All read-only diagnostics ops + the export (which writes a derived
        // artifact but does not mutate domain state).
        | IpcOperationName::ExplainGet
        | IpcOperationName::DiagnosticsExportArchive
        | IpcOperationName::ServiceStabilityConfigGet
        // Read-only preset export.
        | IpcOperationName::PresetExportGet
        // Read-only settings export.
        | IpcOperationName::SettingsExportFull
        // Read-only paginated cache-entries viewer.
        | IpcOperationName::CacheEntriesList
        // Read-only paginated connection-trace viewer.
        | IpcOperationName::ConnTraceEntriesList
        // Read-only attribution + integrity of shipped third-party binaries.
        | IpcOperationName::ThirdPartyComponentsList
        // Read-only two-way merge preview (no mutation queue).
        | IpcOperationName::RulesMergePreview
        // Read the shared DoH resolver baseline list.
        | IpcOperationName::DohResolversGet
        // Read-only traffic-stats query.
        | IpcOperationName::TrafficStatsGet
        // Read the caller's pending companion-domain suggestions.
        | IpcOperationName::AutoRuleCandidatesList
        // Read the caller's declined companion-domain suggestions.
        | IpcOperationName::AutoRuleDismissedList => IpcOperationClass::ReadSnapshot,
        // StatusUpdatesSubscribe sets up a long-lived push channel —
        // classified as DiagnosticQuery (no mutation queue, no elevation).
        IpcOperationName::StatusUpdatesSubscribe => IpcOperationClass::DiagnosticQuery,
        // Privileged mutations: enter the mutation queue, require token.
        IpcOperationName::MutationSubmit => IpcOperationClass::MutationRequest,
        // Re-enumerating adapters (and, when the user asks for it, probing each
        // adapter's external address) changes nothing persisted, so it must not
        // enter the single-writer mutation queue: a heavy policy apply in the
        // queue can hold the refresh past its own call deadline, and the user
        // sees a timeout instead of addresses. DiagnosticQuery dispatches
        // immediately and still requires no elevation.
        IpcOperationName::InterfacesRefreshRequest => IpcOperationClass::DiagnosticQuery,
        IpcOperationName::RollbackRequest => IpcOperationClass::RecoveryAction,
        IpcOperationName::ProductImpactDisableTemporary => IpcOperationClass::SafeDisable,
        // Per-SID user configuration writes go through the mutation queue
        // (single-writer invariant) but do not require client elevation.
        // Slug differs from `mutation-request` so handlers can distinguish.
        IpcOperationName::RoutePolicyUpdate
        // Link-provider app set: same per-SID user-scoped write pattern as
        // RoutePolicyUpdate.
        | IpcOperationName::RouteLinkProviderSet
        | IpcOperationName::MigrationMarkComplete
        | IpcOperationName::RoutingPauseToggle
        | IpcOperationName::AutostartToggle => IpcOperationClass::UserScopedConfiguration,
        // Service-global mutations admin-gated upstream. Service stability
        // config shares the same envelope class as other service-global
        // settings writes.
        IpcOperationName::RetentionSettingsSet
        | IpcOperationName::ApplyFailurePolicySet
        // Log/audit retention write, service-global settings class.
        | IpcOperationName::LogRetentionConfigSet
        | IpcOperationName::ServiceStabilityConfigSet => IpcOperationClass::UserScopedConfiguration,
        // LogsClear is a destructive maintenance op but does not mutate routing
        // policy or rules — same class as the other settings writes.
        IpcOperationName::LogsClear => IpcOperationClass::UserScopedConfiguration,
        // CacheClear clears the rebuildable FQDN/IP cache — same class as the
        // other GUI-only maintenance / settings writes.
        IpcOperationName::CacheClear => IpcOperationClass::UserScopedConfiguration,
        // DiagnosticModeSet toggles an in-memory diagnostic session; a
        // GUI-only maintenance command, same envelope class.
        IpcOperationName::DiagnosticModeSet => IpcOperationClass::UserScopedConfiguration,
        // DoH resolver baseline replace. Machine-wide config write; the
        // elevation gate lives in the catalog
        // (`requires_service_mutation_privilege`), the envelope class matches the
        // other settings writes.
        IpcOperationName::DohResolversSet => IpcOperationClass::UserScopedConfiguration,
        // Opt-in browser-history seed; a GUI-only maintenance command like
        // CacheClear / DiagnosticModeSet.
        IpcOperationName::SeedFromBrowserHistory => IpcOperationClass::UserScopedConfiguration,
        // Service-global traffic-stats settings write / reset (admin-gated in
        // the catalog); same envelope class as other settings writes.
        IpcOperationName::TrafficStatsSet | IpcOperationName::TrafficStatsClear => {
            IpcOperationClass::UserScopedConfiguration
        }
        // Accepting a companion-domain suggestion writes the caller's OWN
        // rules and refusing one writes their own refusal record. Both are
        // per-SID user configuration: they enter the single-writer mutation
        // queue but require no elevation.
        IpcOperationName::AutoRuleCandidatesAccept
        | IpcOperationName::AutoRuleCandidatesDismiss => IpcOperationClass::UserScopedConfiguration,
        // Restoring a declined suggestion writes the caller's own refusal
        // record (a delete), and erasing one drops their own pending/refusal
        // rows — same per-SID user-configuration class.
        IpcOperationName::AutoRuleDismissedRestore
        | IpcOperationName::AutoRuleCandidatesForget => IpcOperationClass::UserScopedConfiguration,
        // Read the caller's own block-notice mutes.
        IpcOperationName::BlockNoticeMutesList => IpcOperationClass::ReadSnapshot,
        // Setting/removing/clearing a mute writes the caller's OWN durable
        // mute row(s) — per-SID user configuration, no elevation, same shape
        // as the companion-domain refusal writes above.
        IpcOperationName::BlockNoticeMutesSet
        | IpcOperationName::BlockNoticeMutesRemove
        | IpcOperationName::BlockNoticeMutesClear => IpcOperationClass::UserScopedConfiguration,
        // Turning a block notice into a rule writes the caller's OWN rules
        // through the same authoring path AutoRuleCandidatesAccept uses —
        // same per-SID user-configuration class.
        IpcOperationName::BlockNoticeRouteToSecondary => IpcOperationClass::UserScopedConfiguration,
        // Full reset purges the caller's OWN auxiliary state — per-SID user
        // configuration, no elevation, same class as BlockNoticeMutesClear.
        IpcOperationName::PrincipalDataPurge => IpcOperationClass::UserScopedConfiguration,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IpcEndpointAccessClass {
    ReadOnly,
    PrivilegedMutation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CallerIdentityCheck {
    ProcessTokenUserSid,
    SessionIdMatch,
    IntegrityLevelPolicy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IpcAclPrincipal {
    LocalSystem,
    BuiltinAdministrators,
    InteractiveUserSession,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IpcAclPolicy {
    pub allowed_principals: &'static [IpcAclPrincipal],
    pub deny_network_logon: bool,
    pub restrict_to_local_machine: bool,
}

const ACL_ALLOWED_PRINCIPALS: [IpcAclPrincipal; 3] = [
    IpcAclPrincipal::LocalSystem,
    IpcAclPrincipal::BuiltinAdministrators,
    IpcAclPrincipal::InteractiveUserSession,
];

pub const IPC_ACL_POLICY: IpcAclPolicy = IpcAclPolicy {
    allowed_principals: &ACL_ALLOWED_PRINCIPALS,
    deny_network_logon: true,
    restrict_to_local_machine: true,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IpcCallerIdentityPolicy {
    pub checks: &'static [CallerIdentityCheck],
    pub require_interactive_user_session_for_mutations: bool,
}

const CALLER_IDENTITY_CHECKS: [CallerIdentityCheck; 3] = [
    CallerIdentityCheck::ProcessTokenUserSid,
    CallerIdentityCheck::SessionIdMatch,
    CallerIdentityCheck::IntegrityLevelPolicy,
];

pub const IPC_CALLER_IDENTITY_POLICY: IpcCallerIdentityPolicy = IpcCallerIdentityPolicy {
    checks: &CALLER_IDENTITY_CHECKS,
    require_interactive_user_session_for_mutations: true,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IpcEndpointName {
    ServiceReadOnly,
    ServiceMutating,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IpcEndpointSecuritySpec {
    pub endpoint: IpcEndpointName,
    pub access_class: IpcEndpointAccessClass,
    pub requires_caller_identity_verification: bool,
}

const IPC_ENDPOINT_SECURITY_SPECS: [IpcEndpointSecuritySpec; 2] = [
    IpcEndpointSecuritySpec {
        endpoint: IpcEndpointName::ServiceReadOnly,
        access_class: IpcEndpointAccessClass::ReadOnly,
        requires_caller_identity_verification: true,
    },
    IpcEndpointSecuritySpec {
        endpoint: IpcEndpointName::ServiceMutating,
        access_class: IpcEndpointAccessClass::PrivilegedMutation,
        requires_caller_identity_verification: true,
    },
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IpcFailureMode {
    ServiceUnavailable,
    PermissionDenied,
    IncompatibleContractVersion,
    Timeout,
    StaleSession,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IpcDegradationBehavior {
    FailFast,
    RetryWithBackoff,
    RequireReauthAndRetry,
    RefreshSessionAndReplayReadOnly,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IpcFailurePolicyRule {
    pub mode: IpcFailureMode,
    pub behavior: IpcDegradationBehavior,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IpcFailureAndDegradationPolicy {
    pub rules: &'static [IpcFailurePolicyRule],
}

const IPC_FAILURE_POLICY_RULES: [IpcFailurePolicyRule; 5] = [
    IpcFailurePolicyRule {
        mode: IpcFailureMode::ServiceUnavailable,
        behavior: IpcDegradationBehavior::RetryWithBackoff,
    },
    IpcFailurePolicyRule {
        mode: IpcFailureMode::PermissionDenied,
        behavior: IpcDegradationBehavior::RequireReauthAndRetry,
    },
    IpcFailurePolicyRule {
        mode: IpcFailureMode::IncompatibleContractVersion,
        behavior: IpcDegradationBehavior::FailFast,
    },
    IpcFailurePolicyRule {
        mode: IpcFailureMode::Timeout,
        behavior: IpcDegradationBehavior::RetryWithBackoff,
    },
    IpcFailurePolicyRule {
        mode: IpcFailureMode::StaleSession,
        behavior: IpcDegradationBehavior::RefreshSessionAndReplayReadOnly,
    },
];

pub const IPC_FAILURE_AND_DEGRADATION_POLICY: IpcFailureAndDegradationPolicy =
    IpcFailureAndDegradationPolicy {
        rules: &IPC_FAILURE_POLICY_RULES,
    };

pub fn ipc_endpoint_security_specs() -> &'static [IpcEndpointSecuritySpec] {
    &IPC_ENDPOINT_SECURITY_SPECS
}

#[cfg(test)]
#[allow(clippy::assertions_on_constants)]
mod tests {
    use super::{
        ipc_endpoint_security_specs, IpcAclPrincipal, IpcDegradationBehavior,
        IpcEndpointAccessClass, IpcEndpointName, IpcErrorCode, IpcFailureMode, IpcTransportKind,
        IPC_ACL_POLICY, IPC_CALLER_IDENTITY_POLICY, IPC_FAILURE_AND_DEGRADATION_POLICY,
        IPC_TRANSPORT_KIND, SERVICE_ENDPOINT_ADDRESS,
    };

    #[test]
    fn transport_kind_matches_the_host_os_mechanism() {
        // The mechanism is selected per-OS at compile time: named pipes on
        // Windows, AF_UNIX everywhere else.
        #[cfg(windows)]
        assert_eq!(IPC_TRANSPORT_KIND, IpcTransportKind::WindowsNamedPipes);
        #[cfg(unix)]
        assert_eq!(IPC_TRANSPORT_KIND, IpcTransportKind::UnixDomainSocket);
    }

    #[test]
    fn transport_kind_slugs_are_stable_and_distinct() {
        assert_eq!(
            IpcTransportKind::WindowsNamedPipes.slug(),
            "windows-named-pipes"
        );
        assert_eq!(
            IpcTransportKind::UnixDomainSocket.slug(),
            "unix-domain-socket"
        );
        assert_ne!(
            IpcTransportKind::WindowsNamedPipes.slug(),
            IpcTransportKind::UnixDomainSocket.slug()
        );
    }

    #[test]
    fn service_endpoint_address_is_platform_shaped_and_versioned() {
        #[cfg(windows)]
        {
            assert!(SERVICE_ENDPOINT_ADDRESS.starts_with(r"\\.\pipe\"));
            assert!(SERVICE_ENDPOINT_ADDRESS.ends_with("service-v1"));
        }
        #[cfg(unix)]
        {
            assert!(SERVICE_ENDPOINT_ADDRESS.starts_with('/'));
            assert!(SERVICE_ENDPOINT_ADDRESS.ends_with("service-v1.sock"));
        }
    }

    #[test]
    fn acl_and_caller_identity_policies_are_explicit() {
        assert!(IPC_ACL_POLICY
            .allowed_principals
            .contains(&IpcAclPrincipal::InteractiveUserSession));
        assert!(IPC_ACL_POLICY.deny_network_logon);
        assert!(IPC_ACL_POLICY.restrict_to_local_machine);
        assert!(IPC_CALLER_IDENTITY_POLICY.checks.len() >= 2);
        assert!(IPC_CALLER_IDENTITY_POLICY.require_interactive_user_session_for_mutations);
    }

    #[test]
    fn endpoint_security_split_is_read_only_vs_privileged_mutation() {
        let specs = ipc_endpoint_security_specs();
        assert!(specs.iter().any(|item| {
            item.endpoint == IpcEndpointName::ServiceReadOnly
                && item.access_class == IpcEndpointAccessClass::ReadOnly
        }));
        assert!(specs.iter().any(|item| {
            item.endpoint == IpcEndpointName::ServiceMutating
                && item.access_class == IpcEndpointAccessClass::PrivilegedMutation
        }));
    }

    #[test]
    fn failure_policy_covers_required_unavailable_permission_version_timeout_and_session_cases() {
        let rules = IPC_FAILURE_AND_DEGRADATION_POLICY.rules;
        assert!(rules
            .iter()
            .any(|rule| rule.mode == IpcFailureMode::ServiceUnavailable));
        assert!(rules
            .iter()
            .any(|rule| rule.mode == IpcFailureMode::PermissionDenied));
        assert!(rules
            .iter()
            .any(|rule| rule.mode == IpcFailureMode::IncompatibleContractVersion));
        assert!(rules
            .iter()
            .any(|rule| rule.mode == IpcFailureMode::Timeout));
        assert!(rules
            .iter()
            .any(|rule| rule.mode == IpcFailureMode::StaleSession));
        assert!(rules.iter().any(|rule| {
            rule.mode == IpcFailureMode::IncompatibleContractVersion
                && rule.behavior == IpcDegradationBehavior::FailFast
        }));
    }

    /// The administrative rules lock needs its own code, not a shade of
    /// `Forbidden`: a client has to tell "you may never edit rules here" apart
    /// from "that particular action was refused" to put the section into a
    /// permanent read-only state instead of showing a transient error.
    #[test]
    fn rules_locked_is_a_distinct_wire_code() {
        assert_eq!(
            serde_json::to_string(&IpcErrorCode::RulesLocked).expect("serialise"),
            "\"rules_locked\""
        );
        let back: IpcErrorCode = serde_json::from_str("\"rules_locked\"").expect("deserialise");
        assert_eq!(back, IpcErrorCode::RulesLocked);
        assert_ne!(IpcErrorCode::RulesLocked, IpcErrorCode::Forbidden);
    }
}
