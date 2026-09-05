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
///
/// The product name inside both spellings is the one in
/// [`crate::product_identity`]. It is written out here because a `const` string
/// cannot be concatenated on stable Rust without pulling in another crate, and
/// `the_endpoint_address_is_built_from_the_product_identity` is what holds the
/// two together — this crate IS the identity SSOT, so its own address
/// disagreeing with it is the one drift no other module can catch.
#[cfg(windows)]
pub const SERVICE_ENDPOINT_ADDRESS: &str = r"\\.\pipe\NetRuleRouter\service-v1";
#[cfg(unix)]
pub const SERVICE_ENDPOINT_ADDRESS: &str = "/run/netrulerouter/service-v1.sock";

/// The rules-lock refusal as CLIENTS spell it.
///
/// Two spellings of one condition are legitimate here — the envelope carries
/// serde's `snake_case` [`IpcErrorCode::RulesLocked`], while the client-facing
/// slug and the `code` field of a failed mutation are kebab — but they were
/// two hand-typed literals in two crates, one of them documented as
/// "mirrors" the other while differing from it. Both sides read this
/// constant instead, so a rename cannot silently split the durable
/// rules-read-only state into two unrelated errors.
pub const RULES_LOCKED_CLIENT_SLUG: &str = "rules-locked";

/// Maximum size of a single wire-format frame (request or response),
/// in bytes. Both client (`nrr-ipc-client`) and server
/// (`nrr-windows-service`) enforce this limit. Frames larger than this
/// are rejected at the transport boundary with a malformed-request error.
///
/// Set to 1 MiB because `MutationSubmit` with `MutationKind::PresetImport`
/// carries the raw preset bytes (base64-wrapped) in the payload, and
/// `PresetExportGet` / `SettingsExportFull` responses ship base64-wrapped
/// file content.
///
/// This is the OUTER limit: `nrr_domain::import::IMPORT_FILE_SIZE_LIMIT_BYTES`
/// is derived from it, backing out the base64 expansion and envelope overhead,
/// so a file the domain accepts always fits a frame and the refusal a user sees
/// comes from the layer that understands what they did.
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
    /// Erasing data that belongs to the MACHINE rather than to the caller.
    /// Requires elevation for the plain reason that the caller is deciding for
    /// everyone: traffic totals come from adapter counters, which carry no user
    /// dimension at all, so "clear mine" is not a thing the data supports.
    /// Single-step — there is nothing to dry-run, only something to confirm in
    /// the UI before asking for rights.
    MachineScopedAction,
}

/// Editing the policy every user falls back to. The one operation where a
/// mistake reaches somebody who never asked for it.
pub const ACTION_EDIT_BASELINE: &str = "netrulerouter.edit-baseline";
/// Taking the machine's networking apart to get it back: dropping owned routes
/// and filters wholesale.
pub const ACTION_RECOVER_NETWORK: &str = "netrulerouter.recover-network";
/// Turning protection off on purpose. Named apart from recovery because an
/// administrator may well allow one and not the other.
pub const ACTION_DISABLE_PROTECTION: &str = "netrulerouter.disable-protection";
/// Wiping data the whole machine shares. Named apart from the three above
/// because it destroys history rather than changing policy, and an
/// administrator may well take a different view of the two.
pub const ACTION_CLEAR_SHARED_DATA: &str = "netrulerouter.clear-shared-data";

impl IpcOperationClass {
    /// Every class, so a caller that has to reason about all of them (the
    /// polkit action file, an audit of the gates) cannot miss one added later.
    pub const ALL: [Self; 10] = [
        Self::ReadSnapshot,
        Self::DiagnosticQuery,
        Self::DiagnosticAction,
        Self::MutationRequest,
        Self::ReviewConfirmation,
        Self::RecoveryAction,
        Self::SafeDisable,
        Self::UserScopedConfiguration,
        Self::UserScopedMutation,
        Self::MachineScopedAction,
    ];

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
            | Self::UserScopedMutation
            | Self::MachineScopedAction => true,
        }
    }

    /// The authorization action an unelevated caller must be granted before
    /// this class is allowed, or `None` when no elevation is needed at all.
    ///
    /// Windows answers the elevation question before the request arrives — the
    /// broker holds the rights. Where the privileged process is the service
    /// itself, the question is asked here instead, and this is the name it is
    /// asked under. Three names rather than one, because an administrator
    /// writing a rule wants to distinguish "may edit the shared baseline" from
    /// "may take the network apart to recover it".
    pub const fn authorization_action(self) -> Option<&'static str> {
        match self {
            Self::MutationRequest | Self::ReviewConfirmation => Some(ACTION_EDIT_BASELINE),
            Self::RecoveryAction => Some(ACTION_RECOVER_NETWORK),
            Self::SafeDisable => Some(ACTION_DISABLE_PROTECTION),
            Self::MachineScopedAction => Some(ACTION_CLEAR_SHARED_DATA),
            Self::ReadSnapshot
            | Self::DiagnosticQuery
            | Self::DiagnosticAction
            | Self::UserScopedConfiguration
            | Self::UserScopedMutation => None,
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
            Self::MachineScopedAction => "machine-scoped-action",
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
            .get(MUTATION_PAYLOAD_FIELD)
            .and_then(|p| p.get(ADMIN_BASELINE_FIELD))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if admin_baseline {
            return IpcOperationClass::MutationRequest;
        }
        // Per-principal rules / preset edits: two-phase but NOT elevation-gated,
        // so a non-admin session can commit its own rules. Everything else stays
        // service-global.
        //
        // Decided on the DESERIALISED variant, never on a hand-typed spelling:
        // the wire names come from `#[serde(rename_all = "kebab-case")]`, so a
        // renamed variant used to compile green here and silently reclassify
        // the operation. A kind that does not deserialise falls through to the
        // stricter class below.
        let kind: Option<crate::ipc_payloads::MutationKind> = payload
            .get(MUTATION_KIND_FIELD)
            .and_then(|v| serde_json::from_value(v.clone()).ok());
        if matches!(
            kind,
            Some(
                crate::ipc_payloads::MutationKind::RulesUpdate
                    | crate::ipc_payloads::MutationKind::PresetImport
                    | crate::ipc_payloads::MutationKind::RulesResetToBaseline
            )
        ) {
            return IpcOperationClass::UserScopedMutation;
        }
        return IpcOperationClass::MutationRequest;
    }
    fixed_operation_class(op)
}

/// Wire field names this classifier reads out of a raw payload.
///
/// Named constants rather than inline literals so the test below can point at
/// the same strings it checks against a serialised `MutationSubmitRequest`.
/// The classifier works on `serde_json::Value` because it runs BEFORE the
/// payload is typed — it decides which gates apply, so it cannot wait for the
/// handler that would parse it.
const DRY_RUN_FIELD: &str = "dry-run";
const MUTATION_KIND_FIELD: &str = "mutation-kind";
const MUTATION_PAYLOAD_FIELD: &str = "payload";
/// Not a field of `MutationSubmitRequest` — it lives inside the kind-specific
/// payload, whose schema the wire layer deliberately does not own.
const ADMIN_BASELINE_FIELD: &str = "admin-baseline";

/// `dry-run: true` in the envelope payload.
fn dry_run_flag(payload: &serde_json::Value) -> bool {
    payload
        .get(DRY_RUN_FIELD)
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
        // All read-only diagnostics ops.
        | IpcOperationName::ExplainGet
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
        // Read the caller's local-network exemptions and what we discovered.
        | IpcOperationName::LocalNetworksGet
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
        // Maintenance of what the service OBSERVED, not of what it enforces:
        // clearing operational logs, discarding the rebuildable FQDN/IP cache,
        // toggling an in-memory diagnostic session. Mutating and queued like the
        // settings writes, but they configure nothing, which is the distinction
        // `DiagnosticAction` names.
        IpcOperationName::LogsClear
        | IpcOperationName::CacheClear
        | IpcOperationName::DiagnosticModeSet
        // The export writes a FILE, and at `redaction-level: diagnostics` that
        // file holds unredacted hostnames, addresses and an audit summary. As a
        // read it was not audited at all, while `DiagnosticModeSet` — which
        // lifts the same redaction for on-screen viewers only — was. Same
        // class: no elevation, no token, but a record that it happened.
        | IpcOperationName::DiagnosticsExportArchive => IpcOperationClass::DiagnosticAction,
        // DoH resolver baseline replace. Machine-wide config write kept at the
        // settings class. NOTE: `requires_service_mutation_privilege` in the
        // catalog is a declaration, not a gate — nothing reads it at runtime, so
        // it must not be cited as one.
        IpcOperationName::DohResolversSet => IpcOperationClass::UserScopedConfiguration,
        // Opt-in browser-history seed; a GUI-only maintenance command like
        // CacheClear / DiagnosticModeSet.
        IpcOperationName::SeedFromBrowserHistory => IpcOperationClass::UserScopedConfiguration,
        // Service-global traffic-stats settings write / reset (admin-gated in
        // the catalog); same envelope class as other settings writes.
        // Traffic-stats settings write. Machine-global, but a settings write, not
        // a wipe — it stays where the other settings writes are.
        IpcOperationName::TrafficStatsSet => IpcOperationClass::UserScopedConfiguration,
        // Wiping the traffic ledger. The numbers come from adapter counters and
        // carry no user dimension, so this erases everyone's history — and the
        // caller must hold the rights to decide that for everyone.
        IpcOperationName::TrafficStatsClear => IpcOperationClass::MachineScopedAction,
        // Probing the caller's own suggestions writes evidence about them, not
        // policy — but it is still a per-SID action the service performs on the
        // caller's behalf, so it travels the same envelope as their other
        // configuration commands.
        IpcOperationName::AutoRuleCandidatesProbe => IpcOperationClass::UserScopedConfiguration,
        // Marking a site as refusing main-link addresses records the caller's
        // own observation about their own site: per-SID configuration.
        IpcOperationName::RefusingAnchorSet => IpcOperationClass::UserScopedConfiguration,
        // The caller's own local-network exemptions: per-SID configuration,
        // same envelope class as the other route-policy writes.
        IpcOperationName::LocalNetworksSet => IpcOperationClass::UserScopedConfiguration,
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
        // Read the caller's own block-notice mutes, and the notices raised
        // for them while nothing was listening.
        IpcOperationName::BlockNoticeMutesList
        | IpcOperationName::BlockNoticeJournalList => IpcOperationClass::ReadSnapshot,
        // Acknowledging shown notices deletes the caller's OWN backlog rows.
        IpcOperationName::BlockNoticeJournalAck => IpcOperationClass::UserScopedConfiguration,
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
        // Full reset purges the caller's OWN state — per-SID user configuration,
        // no elevation, same class as BlockNoticeMutesClear. NOT only auxiliary
        // state: with `include-rules-history` it also drops the caller's
        // revisions, active pointer and unconsumed mutation tokens. That is
        // audited (the class is mutating) and GUI-only, but it carries no
        // dry-run token, while editing a SINGLE rule does. Elevation is the
        // wrong gate to add here: an elevated relay runs under the ADMIN's
        // identity, so a standard user's reset would purge the wrong principal.
        // The gate this wants is a confirmation token, which needs the reset
        // flow to dry-run first.
        IpcOperationName::PrincipalDataPurge => IpcOperationClass::UserScopedConfiguration,
        // A count of other principals, no identities and no writes.
        IpcOperationName::PrincipalDataCount => IpcOperationClass::ReadSnapshot,
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
        fixed_operation_class, ipc_endpoint_security_specs, IpcAclPrincipal,
        IpcDegradationBehavior, IpcEndpointAccessClass, IpcEndpointName, IpcErrorCode,
        IpcFailureMode, IpcOperationClass, IpcTransportKind, ACTION_CLEAR_SHARED_DATA,
        ACTION_DISABLE_PROTECTION, ACTION_EDIT_BASELINE, ACTION_RECOVER_NETWORK, IPC_ACL_POLICY,
        IPC_CALLER_IDENTITY_POLICY, IPC_FAILURE_AND_DEGRADATION_POLICY, IPC_TRANSPORT_KIND,
        SERVICE_ENDPOINT_ADDRESS,
    };
    use crate::ipc::IpcOperationName;

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

    /// The action names are the product's, so they must be derived from its
    /// unix spelling rather than typed independently. The test pins the SHAPE:
    /// a rename reaches them, a typo does not survive.
    #[test]
    fn authorization_actions_are_named_after_the_product() {
        for action in [
            ACTION_EDIT_BASELINE,
            ACTION_RECOVER_NETWORK,
            ACTION_DISABLE_PROTECTION,
        ] {
            assert!(
                action.starts_with(crate::product_identity::PRODUCT_NAME_UNIX),
                "{action} does not carry the product's own name",
            );
            assert!(action.len() > crate::product_identity::PRODUCT_NAME_UNIX.len() + 1);
        }
    }

    /// A class no operation has is a gate nobody passes through: its rules read
    /// as policy while enforcing nothing, and the next reader has to grep the
    /// whole catalog to find that out. Payload-dependent classes are excluded —
    /// they are reached through [`canonical_operation_class`]'s dry-run branch,
    /// which this table cannot see.
    #[test]
    fn every_fixed_class_is_claimed_by_at_least_one_operation() {
        for class in [
            IpcOperationClass::ReadSnapshot,
            IpcOperationClass::DiagnosticQuery,
            IpcOperationClass::DiagnosticAction,
            IpcOperationClass::RecoveryAction,
            IpcOperationClass::SafeDisable,
            IpcOperationClass::UserScopedConfiguration,
            IpcOperationClass::MachineScopedAction,
        ] {
            assert!(
                IpcOperationName::ALL
                    .iter()
                    .any(|op| fixed_operation_class(*op) == class),
                "{class:?} is declared but no operation has it",
            );
        }
    }

    /// Wiping the traffic ledger erases what the whole machine did, because the
    /// numbers come from adapter counters and carry no user dimension — there is
    /// no "clear only mine" for this data to give. So it asks for rights, and it
    /// asks under its own name: an administrator may allow erasing shared
    /// history while still refusing to let policy be edited.
    #[test]
    fn clearing_the_shared_traffic_ledger_needs_rights_of_its_own() {
        let class = fixed_operation_class(IpcOperationName::TrafficStatsClear);
        assert_eq!(class, IpcOperationClass::MachineScopedAction);
        assert!(class.requires_elevation());
        assert_eq!(class.authorization_action(), Some(ACTION_CLEAR_SHARED_DATA));
        assert!(class.is_mutating(), "the wipe is audited before it happens");
        assert!(
            !class.requires_confirmation_token(),
            "there is nothing to dry-run — the UI confirms, then rights are asked for"
        );
        // Writing the settings is not wiping the history, and must not inherit
        // the prompt.
        assert!(
            !fixed_operation_class(IpcOperationName::TrafficStatsSet).requires_elevation(),
            "a settings write is not a data wipe"
        );
    }

    /// Every class that needs elevation must be askable about; a class that
    /// needs none must not invent a prompt. Without this pairing a new class
    /// would silently become either unaskable or gratuitously interactive.
    #[test]
    fn every_elevated_class_has_an_action_and_no_other_does() {
        for class in [
            IpcOperationClass::ReadSnapshot,
            IpcOperationClass::DiagnosticQuery,
            IpcOperationClass::DiagnosticAction,
            IpcOperationClass::MutationRequest,
            IpcOperationClass::ReviewConfirmation,
            IpcOperationClass::RecoveryAction,
            IpcOperationClass::SafeDisable,
            IpcOperationClass::UserScopedConfiguration,
            IpcOperationClass::UserScopedMutation,
        ] {
            assert_eq!(
                class.requires_elevation(),
                class.authorization_action().is_some(),
                "{class:?}: elevation and an authorization action must agree",
            );
        }
    }
    /// The classifier reads a RAW payload, so it names wire fields by hand.
    /// This is the other end of that: the names must be the ones serde
    /// actually emits for `MutationSubmitRequest`, or every gate the class
    /// selects is chosen from fields that are never there.
    #[test]
    fn the_wire_fields_the_classifier_reads_exist_on_the_request() {
        let request = crate::ipc_payloads::MutationSubmitRequest {
            mutation_kind: crate::ipc_payloads::MutationKind::RulesUpdate,
            payload: serde_json::json!({}),
            dry_run: true,
        };
        let value = serde_json::to_value(&request).expect("request serialises");
        let object = value.as_object().expect("request is an object");
        for field in [
            super::DRY_RUN_FIELD,
            super::MUTATION_KIND_FIELD,
            super::MUTATION_PAYLOAD_FIELD,
        ] {
            assert!(
                object.contains_key(field),
                "`{field}` is not a field of a serialised MutationSubmitRequest;                  keys are {:?}",
                object.keys().collect::<Vec<_>>()
            );
        }
    }

    /// Every kind that must classify as user-scoped, addressed by its wire
    /// spelling rather than its variant — the direction a peer sends.
    #[test]
    fn per_principal_kinds_classify_as_user_scoped_by_their_wire_spelling() {
        use crate::ipc_payloads::MutationKind;
        for kind in [
            MutationKind::RulesUpdate,
            MutationKind::PresetImport,
            MutationKind::RulesResetToBaseline,
        ] {
            let payload = serde_json::json!({
                "mutation-kind": serde_json::to_value(kind).expect("kind serialises"),
                "payload": {},
                "dry-run": false,
            });
            assert_eq!(
                super::canonical_operation_class(IpcOperationName::MutationSubmit, &payload),
                IpcOperationClass::UserScopedMutation,
                "{kind:?}"
            );
        }
        // Positive control on the other direction: a kind outside the list, and
        // an unparsable one, both land on the stricter class.
        for payload in [
            serde_json::json!({"mutation-kind": "route-bindings-update", "payload": {}}),
            serde_json::json!({"mutation-kind": "no-such-kind", "payload": {}}),
            serde_json::json!({"payload": {}}),
        ] {
            assert_eq!(
                super::canonical_operation_class(IpcOperationName::MutationSubmit, &payload),
                IpcOperationClass::MutationRequest,
                "{payload}"
            );
        }
    }
    /// The endpoint address carries the product name. Both are declared in this
    /// crate, and nothing outside it can notice when they part company.
    #[test]
    fn the_endpoint_address_is_built_from_the_product_identity() {
        use crate::product_identity::{PRODUCT_NAME, PRODUCT_NAME_UNIX};

        #[cfg(windows)]
        {
            let expected = format!(r"\\.\pipe\{PRODUCT_NAME}\service-v1");
            assert_eq!(super::SERVICE_ENDPOINT_ADDRESS, expected);
        }
        #[cfg(unix)]
        {
            let expected = format!("/run/{PRODUCT_NAME_UNIX}/service-v1.sock");
            assert_eq!(super::SERVICE_ENDPOINT_ADDRESS, expected);
        }
        // Referenced on both platforms so neither name goes unused.
        assert!(!PRODUCT_NAME.is_empty() && !PRODUCT_NAME_UNIX.is_empty());
    }
}
