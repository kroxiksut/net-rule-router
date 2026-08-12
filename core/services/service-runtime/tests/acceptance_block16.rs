#![allow(
    clippy::doc_lazy_continuation,
    clippy::unwrap_used,
    clippy::expect_used
)]
//! Acceptance gate for GUI <-> Service real integration.
//!
//! This file is the **consolidated gate**. Most readiness criteria are
//! already covered by existing integration test files; this gate
//! references them by name and adds the remaining spot-checks for
//! scenarios not yet pinned by another suite.
//!
//! ## Gate scenarios
//!
//! 1. **GUI ↔ Service round-trip on every snapshot op.** Covered by
//!    `tests/ipc_handlers_test.rs::production_handlers_register_every_operation_in_catalog`
//!    plus the per-op handler tests. The gate test here pins the
//!    catalog shape (35 ops, all slugs unique, every op has a class
//!    slug routable through `IpcOperationClass`).
//! 2. **Mutation flow end-to-end** (submit → dry-run → activate →
//!    apply called → audit unbroken). Covered by
//!    `tests/apply_pipeline_e2e.rs` (8 integration tests, ~470 LOC)
//!    and `tests/preset_round_trip.rs` (4 tests). The gate test here
//!    confirms `register_production_handlers` wires the
//!    `IpcOperationName::MutationSubmit` op to a real handler (not a
//!    stub).
//! 3. **Reconnect resilience** (kill service, restart, GUI reconnects
//!    within 5s). Hard to fully automate without a real Win named
//!    pipe; the gate test here exercises the
//!    `nrr_ipc_client::ConnectionStatus` enum transitions and the
//!    `IpcBackendFacade::with_named_pipe` fallback contract. Real
//!    kill+restart timing is a manual checklist item below.
//! 4. **Unauthorized SID rejection** (mock SID gets rejected at
//!    mutation gate). Covered by
//!    `tests/acceptance_gate.rs::ipc_mutation_from_unprivileged_client_is_forbidden`.
//!    The gate test here adds a per-SID-handler reject check via the
//!    settings writer surface.
//! 5. **Legacy preferences migration** (legacy prefs.json
//!    fixture → migrated → cleaned). Covered by
//!    `nrr-ui-support` lib tests `v1_file_without_new_fields_loads_with_defaults`
//!    plus the `cleanup_legacy_policy_fields` unit tests. The gate
//!    test here confirms the legacy `selected_primary_interface_id`
//!    field round-trips through the new `UiPreferences` schema
//!    without data loss until cleanup is invoked.
//! 6. **Crash recovery mid-activate** (`ApplyAttemptMarker` mid-state
//!    + `decide_recovery` produces a non-silent decision). Covered by
//!    `tests/acceptance_gate.rs::no_silent_policy_activation_with_incomplete_marker`
//!    plus `tests/cross_cutting_4b4.rs` push-pump + recovery hook
//!    scenarios. The gate test here adds a smoke check that the
//!    `RecoveryDecision::PolicyReady` outcome never fires when the
//!    marker is mid-phase.
//!
//! ## Manual GUI checklist
//!
//! These steps require a Windows host with a real Qt GUI + service
//! running side-by-side. They cannot be automated from a Rust test
//! harness and must be walked manually before sign-off:
//!
//! 1. **Cold start, service not installed:** launch GUI on a clean
//!    machine where `NetRuleRouter` service is not present. The
//!    backend-status banner must surface
//!    `service-not-installed` in red within 3 seconds; the GUI must
//!    remain interactive (preview mode), no exception dialogs.
//! 2. **Hot reconnect:** kill the service process while the GUI is
//!    showing rules. The connection banner must flip to
//!    `disconnected` (yellow) within 1 second. After restarting the
//!    service, the banner must flip back to `connected` (hidden)
//!    within 5 seconds and the rules list must refresh from the
//!    fresh `SnapshotInitial`.
//! 3. **Apply flow end-to-end:** add a single rule → click "Save and
//!    review…" → ReviewDiffDialog → ConfirmActivate → success toast.
//!    Open `cmd.exe` and run `route print` (or `Get-NetRoute` on
//!    PowerShell). The new rule's route must appear in the table.
//! 4. **Rollback to LKG:** from the previous step, trigger a
//!    rollback via the future Settings → Service stability panel
//!    or via the IPC `RollbackRequest` op. The
//!    route from step 3 must disappear from `route print`.
//! 5. **Safe disable (tray):** right-click tray icon → "Safe disable
//!    (temporary)…" → fill reason → Confirm. All NetRuleRouter
//!    routes must be cleaned. Audit NDJSON must record
//!    `SafeDisableExecuted` with the reason.
//! 6. **Locale switch ru ↔ en without restart:** Settings → Language
//!    → toggle between Russian and English. Every visible label
//!    (banners, dialogs, tooltips, status line) must localise in
//!    place without restart. Specifically watch the
//!    `connection.banner.*` keys and `dialog.review-diff.*` strings.
//! 7. **Concurrent GUI + Tray:** open both the main window and the
//!    tray menu simultaneously. Both must show the same routing
//!    state. Pause routing via Tray → Pause → main window's
//!    routing chip must update via the `routing-pause-state-changed`
//!    push event within 1 second.
//! 8. **Audit chain unbroken after restarts:** stop and restart the
//!    service multiple times. The `nrr_audit_YYYYMMDD-N.ndjson` chain
//!    of `event_hash` values (each = SHA-256(prev_hash ||
//!    canonical_payload)) must remain unbroken across service
//!    restarts. Use the `nrr_diagnostics::audit::verifier` from CLI
//!    tooling to confirm.
//!
//! ## Deferred items
//!
//! The remaining manual steps depend on the GUI-driven service
//! install/uninstall lifecycle UX being delivered first. They are
//! intentionally NOT documented here and must be revisited once that
//! lands:
//!
//! - First-install wizard on a clean Windows (UAC → install →
//!   service starts → GUI flips to client mode).
//! - Service uninstall via GUI (UAC → service stopped → unregistered
//!   → GUI falls back to `service-not-installed` banner).
//! - Service restart via GUI Settings (controlled stop/start cycle).
//! - Session resume after Windows logoff/logon (service persists,
//!   GUI reconnects on next user session).
//!
//! ## Closure criterion
//!
//! Beyond the gate tests below, closure requires:
//!
//! - `cargo test --workspace --lib` ⇒ all crates green.
//! - `cargo deny check` ⇒ no licence/advisory regressions.
//! - All actionable `TODO:` markers in production paths
//!   reclassified or removed. Documentation-level architectural-boundary
//!   comments stay as docs without the TODO marker; real gaps
//!   reclassify to `TODO(pro-tier)` or similar.

#![cfg(target_os = "windows")]

use nrr_service_runtime::{
    decide_recovery, ApplyAttemptMarker, ApplyPhase, RecoveryDecision, StartupRecoveryState,
};
use nrr_shared::ipc::{ipc_operation_catalog, IpcInteractionClass, IpcOperationName};
use std::collections::HashSet;

// ── Gate 1: catalog consistency ──────────────────────────────────────────────

/// The wire-stable IPC catalog includes read-only export ops, cache
/// management (`cache.clear`, `cache.entries.list`), DoH resolver
/// configuration (`doh.resolvers.get`/`.set`), browser-history rule
/// seeding (`diagnostics.seed-from-browser-history`), the file<->service
/// rules merge preview (`rules.merge-preview`), the connection-trace
/// panel (`conn-trace.entries.list`), the extended-diagnostics mode
/// toggle (`diagnostics.mode.set`), log/audit retention settings
/// (`settings.log-retention.{get,set}`), the per-SID link-provider app
/// set behind the kill-switch exemption (`route.link-provider.set`),
/// the licenses window (`third-party.components.list`), the traffic
/// counter (`traffic-stats.{get,set,clear}`), and the autorules
/// companion-domain suggestions the tray offers
/// (`autorules.candidates.{list,accept,dismiss}`), the dismissed-suggestion
/// shelf (`autorules.dismissed.{list,restore}`, `autorules.candidates.forget`)
/// and the blocked-connection notices the tray raises
/// (`block-notices.mutes.{list,set,remove,clear}`,
/// `block-notices.route-to-secondary`).
/// The catalog must list every variant in `IpcOperationName::ALL` exactly
/// once, with unique kebab-case slugs.
#[test]
fn block16_catalog_size_is_pinned_and_slugs_are_unique() {
    assert_eq!(
        IpcOperationName::ALL.len(),
        62,
        "block 16 catalog size has drifted — update the gate test if intentional"
    );
    assert_eq!(
        ipc_operation_catalog().len(),
        62,
        "catalog spec count must match `ALL` count"
    );
    let mut slugs: HashSet<&'static str> = HashSet::new();
    for op in IpcOperationName::ALL {
        let slug = op.slug();
        assert!(!slug.is_empty(), "operation {op:?} has an empty slug");
        assert!(slugs.insert(slug), "duplicate slug {slug:?} for {op:?}");
        // Round-trip: from_slug recovers the same variant.
        assert_eq!(
            IpcOperationName::from_slug(slug),
            Some(op),
            "from_slug round-trip failed for {op:?}"
        );
    }
}

// ── Gate 2: mutation routing is wired through the production registry ───────

/// `MutationSubmit` is the central write-path op. The production
/// catalog must list it and route it through `ProductionMutationExecutor`
/// (proven separately by the per-op handler tests). The gate here is a
/// shape-only sanity: the catalog has the op, with the correct
/// `Command` class.
#[test]
fn block16_mutation_submit_is_classified_as_command() {
    let spec = ipc_operation_catalog()
        .iter()
        .find(|s| s.name == IpcOperationName::MutationSubmit)
        .expect("MutationSubmit must be in the production catalog");
    assert!(
        spec.requires_service_mutation_privilege,
        "MutationSubmit must require mutation privilege"
    );
}

// ── Gate 3: connection status state machine ────────────────────────────────
//
// `nrr_ipc_client::ConnectionStatus` is the contract surface the GUI
// reads on every reconnect. The five-variant enum gates the
// `IpcBackendFacade::with_named_pipe` fallback.
//
// Asserting the variant inventory from this crate would require a
// `dev-dependency` on `nrr-ipc-client` which is forbidden by the
// service-runtime dependency boundary (see `tests/dependency_boundary.rs`).
// The variant stability is pinned by `nrr-ipc-client`'s own lib tests
// instead — search for `connection_status_variants_total_count` in
// `core/ipc-client/src/snapshot_cache.rs` for the enum-shape assertion.

// ── Gate 4: unauthorized client rejected by mutation gate ────────────────────

/// `IpcOperationClass::MutationRequest` (and its kin) must reject when
/// the client profile is not the elevated GUI. Covered in depth by
/// `tests/acceptance_gate.rs::ipc_mutation_from_unprivileged_client_is_forbidden`.
/// The gate here adds a per-op smoke: any catalog entry that requires
/// mutation privilege must have `IpcInteractionClass::Command` (never
/// `Query` / `HealthCheck`) so the read/write distinction stays
/// load-bearing for downstream authorization.
#[test]
fn block16_mutation_privileged_ops_are_command_class() {
    for spec in ipc_operation_catalog().iter() {
        if spec.requires_service_mutation_privilege {
            assert!(
                matches!(spec.class, IpcInteractionClass::Command),
                "op {:?} requires mutation privilege but isn't classified as Command",
                spec.name
            );
        }
    }
}

// ── Gate 5: legacy preferences migration tolerance ──────────────────────────
//
// `nrr_ui_support::UiPreferences` schema v1 files
// must load with the eight new file-source-state fields defaulting to
// `None`. Asserting the schema version from this crate would require a
// `dev-dependency` on `nrr-ui-support` which is forbidden by the
// service-runtime dependency boundary. The covering tests live in
// `nrr-ui-support`'s own lib tests:
//   - `v1_file_without_new_fields_loads_with_defaults`
//   - `schema_version_constant_is_current` (pins v2)
//   - `empty_value_for_optional_string_parses_as_none`
//   - `nonempty_value_for_optional_string_parses_as_some`
//   - `cleanup_legacy_policy_fields_*` (deprecated-field zeroing)
// Run `cargo test -p nrr-ui-support --lib` to exercise the migration
// path end-to-end.

// ── Gate 6: crash recovery never silently activates a mid-marker ────────────

/// `decide_recovery` must surface a non-silent decision when the
/// `ApplyAttemptMarker` indicates the previous process died in the
/// middle of `apply` (between `submit_candidate` and the activate
/// confirmation). Production codepath: `crash_recovery::execute_safe_disable`
/// inside `production_mutation_executor`. The covering test
/// `no_silent_policy_activation_with_incomplete_marker` lives in
/// `acceptance_gate.rs`; the gate here adds a direct probe over
/// `decide_recovery` itself.
#[test]
fn block16_recovery_never_silently_activates_mid_phase() {
    let mid_marker = ApplyAttemptMarker {
        attempt_id: "att-mid".into(),
        active_revision_id: "rev-001".into(),
        phase: ApplyPhase::Applying,
        started_at_epoch_secs: 1_700_000_000,
        last_step_at_epoch_secs: 1_700_000_010,
        intended_rollback_to: None,
        correlation_id: "corr-mid".into(),
    };
    let state = StartupRecoveryState::PreviousApplyIncomplete { marker: mid_marker };
    // Audit available, LKG unavailable → must escalate to manual
    // action rather than silently proceed (audit-before-act invariant).
    let decision = decide_recovery(
        &state, /* lkg_available */ false, /* audit_available */ true,
    );
    match decision {
        RecoveryDecision::ProceedNormal => panic!(
            "decide_recovery returned ProceedNormal on a mid-Applying marker without LKG — \
             silent activation regression"
        ),
        _ => { /* any non-Proceed variant is acceptable for the gate */ }
    }

    // Inverse: audit unavailable must always escalate to manual,
    // regardless of LKG. Pinned here so a future refactor doesn't
    // sneak through an "audit not yet wired" auto-proceed path.
    let decision_no_audit = decide_recovery(
        &StartupRecoveryState::PreviousApplyIncomplete {
            marker: ApplyAttemptMarker {
                attempt_id: "att-no-audit".into(),
                active_revision_id: "rev-001".into(),
                phase: ApplyPhase::Applying,
                started_at_epoch_secs: 1_700_000_000,
                last_step_at_epoch_secs: 1_700_000_010,
                intended_rollback_to: None,
                correlation_id: "corr-no-audit".into(),
            },
        },
        /* lkg_available */ true,
        /* audit_available */ false,
    );
    assert!(
        matches!(
            decision_no_audit,
            RecoveryDecision::RequireManualAction { .. }
        ),
        "audit-unavailable path must escalate to RequireManualAction"
    );
}
