#![allow(clippy::assertions_on_constants)]

use super::{
    ipc_lifecycle_stages, ipc_operation_catalog, CompatibilityClientBehavior, IpcClientProfile,
    IpcExecutionModel, IpcInteractionClass, IpcOperationName, IpcOperationSpec,
    VersionCompatibilityCase, IPC_CONTRACT_VERSION_POLICY, IPC_CORRELATION_MODEL,
    IPC_ENVELOPE_PAYLOAD_BOUNDARY, IPC_RETRY_POLICY, IPC_STATE_UPDATE_MODEL,
    IPC_VERSION_COMPATIBILITY_MATRIX,
};
use std::collections::HashSet;
use std::str::FromStr;

#[test]
fn taxonomy_contains_required_interaction_classes() {
    let classes = IpcInteractionClass::ALL;
    assert!(classes.contains(&IpcInteractionClass::Query));
    assert!(classes.contains(&IpcInteractionClass::Command));
    assert!(classes.contains(&IpcInteractionClass::LongRunningOperation));
    assert!(classes.contains(&IpcInteractionClass::EventUpdate));
    assert!(classes.contains(&IpcInteractionClass::HealthCheck));
}

#[test]
fn catalog_uses_canonical_operation_names_and_non_empty_client_sets() {
    let catalog = ipc_operation_catalog();
    let mut names = HashSet::new();
    for item in catalog {
        assert!(!item.allowed_clients.is_empty());
        assert!(names.insert(item.name.slug()));
    }
    assert_eq!(catalog.len(), IpcOperationName::ALL.len());
}

fn open_to(item: &IpcOperationSpec, profile: IpcClientProfile) -> bool {
    item.allowed_clients.contains(&profile)
}

/// `is_within` places the tray and the terminal inside the window, and that is
/// only true while every operation open to either is also open to the window.
/// The day a tray-only or terminal-only operation lands, the order is fiction
/// again — and `narrowed_by` would then quietly take a capability away from a
/// caller that declared itself the narrower surface.
#[test]
fn no_operation_is_open_to_a_narrower_surface_but_closed_to_the_gui() {
    for narrower in [IpcClientProfile::TrayLightweight, IpcClientProfile::Tui] {
        for item in ipc_operation_catalog() {
            if item.allowed_clients.contains(&narrower) {
                assert!(
                    open_to(item, IpcClientProfile::GuiInteractive),
                    "{} is open to {} but not the window",
                    item.name.slug(),
                    narrower.slug(),
                );
            }
        }
    }
}

/// A declaration can only ever narrow. The console case always held; the
/// window declaring itself the tray did not — it fell through to "whatever
/// the OS proved" and kept window capabilities.
#[test]
fn a_declaration_narrows_and_never_widens() {
    use IpcClientProfile::{AdminConsole, GuiInteractive, TrayLightweight, Tui};
    // Proven window, declared tray: taken at its word.
    assert_eq!(GuiInteractive.narrowed_by(TrayLightweight), TrayLightweight);
    // Proven tray, declared window: the proof stands.
    assert_eq!(TrayLightweight.narrowed_by(GuiInteractive), TrayLightweight);
    // The terminal sits inside the window the same way.
    assert_eq!(GuiInteractive.narrowed_by(Tui), Tui);
    assert_eq!(Tui.narrowed_by(GuiInteractive), Tui);
    // Tray and terminal each hold what the other lacks: only the console is
    // inside both.
    assert_eq!(TrayLightweight.narrowed_by(Tui), AdminConsole);
    assert_eq!(Tui.narrowed_by(TrayLightweight), AdminConsole);
    // The console is narrowest from either side.
    for profile in IpcClientProfile::ALL {
        assert_eq!(profile.narrowed_by(AdminConsole), AdminConsole);
        assert_eq!(AdminConsole.narrowed_by(profile), AdminConsole);
    }
    // A profile narrowed by itself is itself.
    for profile in IpcClientProfile::ALL {
        assert_eq!(profile.narrowed_by(profile), profile);
    }
}

/// The narrowing never hands out an operation either side lacks.
#[test]
fn narrowing_keeps_only_what_both_profiles_may_invoke() {
    for proven in IpcClientProfile::ALL {
        for declared in IpcClientProfile::ALL {
            let narrowed = proven.narrowed_by(declared);
            for item in ipc_operation_catalog() {
                if item.allowed_clients.contains(&narrowed) {
                    assert!(
                        item.allowed_clients.contains(&proven)
                            && item.allowed_clients.contains(&declared),
                        "{proven:?} narrowed by {declared:?} reaches {}",
                        item.name.slug(),
                    );
                }
            }
        }
    }
}

/// The terminal is the window's policy surface minus the desktop session:
/// exactly these are closed to it, and nothing else the window may do.
#[test]
fn the_terminal_has_every_window_operation_but_the_desktop_session_ones() {
    let desktop_only = [
        IpcOperationName::AutostartGet,
        IpcOperationName::AutostartToggle,
        IpcOperationName::MigrationStatusGet,
        IpcOperationName::MigrationMarkComplete,
    ];
    for item in ipc_operation_catalog() {
        let gui = open_to(item, IpcClientProfile::GuiInteractive);
        let tui = open_to(item, IpcClientProfile::Tui);
        if desktop_only.contains(&item.name) {
            assert!(gui && !tui, "{}", item.name.slug());
        } else {
            assert_eq!(gui, tui, "{}", item.name.slug());
        }
    }
}

/// The window and the terminal may be prompted for elevation; the tray and the
/// console never are.
#[test]
fn only_the_window_and_the_terminal_may_be_prompted_for_elevation() {
    for profile in IpcClientProfile::ALL {
        assert_eq!(
            profile.may_prompt_for_elevation(),
            matches!(
                profile,
                IpcClientProfile::GuiInteractive | IpcClientProfile::Tui
            ),
            "{}",
            profile.slug()
        );
    }
}

#[test]
fn gui_and_tray_profiles_have_different_capabilities() {
    // The distinction is real and enforced (see the dispatcher's
    // `allowed_clients` check): there are operations only the window may
    // invoke. Pinned as a PROPERTY of the catalogue rather than to one
    // operation — pinning `StatusUpdatesSubscribe` said the tray may not
    // subscribe to push events, which is how the tray works, and the field
    // was not enforced at the time so nothing contradicted it.
    let catalog = ipc_operation_catalog();
    let gui_only: Vec<_> = catalog
        .iter()
        .filter(|item| {
            !item
                .allowed_clients
                .contains(&IpcClientProfile::TrayLightweight)
        })
        .collect();
    assert!(
        !gui_only.is_empty(),
        "the tray is meant to be the narrower surface"
    );
    // Every one of them still admits the window.
    assert!(gui_only.iter().all(|item| item
        .allowed_clients
        .contains(&IpcClientProfile::GuiInteractive)));
}

#[test]
fn interfaces_refresh_request_does_not_require_mutation_privilege() {
    // The external-IP probe / adapter refresh persists nothing and must
    // be callable by a non-elevated GUI or tray session without a UAC
    // prompt. Regression pin for the catalog flag driving the
    // service-side elevation gate.
    let catalog = ipc_operation_catalog();
    let spec = catalog
        .iter()
        .find(|item| item.name == IpcOperationName::InterfacesRefreshRequest)
        .expect("InterfacesRefreshRequest must be in the catalog");
    assert!(!spec.requires_service_mutation_privilege);
}

#[test]
#[allow(clippy::expect_used)]
fn auto_rule_candidate_ops_are_tray_reachable_and_never_elevated() {
    // The tray is the surface that OFFERS a companion-domain suggestion and
    // the surface the user answers it on, so every op — including
    // reviewing and undoing a past refusal — must admit the tray profile.
    // None of them may require elevation: they read and write the
    // caller's own rules, and a UAC prompt in that flow would make the
    // feature unusable for the non-admin session it exists for.
    let catalog = ipc_operation_catalog();
    for name in [
        IpcOperationName::AutoRuleCandidatesList,
        IpcOperationName::AutoRuleCandidatesAccept,
        IpcOperationName::AutoRuleCandidatesDismiss,
        IpcOperationName::AutoRuleDismissedList,
        IpcOperationName::AutoRuleDismissedRestore,
        IpcOperationName::AutoRuleCandidatesForget,
    ] {
        let spec = catalog
            .iter()
            .find(|item| item.name == name)
            .expect("auto-rule op must be in the catalog");
        assert!(
            spec.allowed_clients
                .contains(&IpcClientProfile::TrayLightweight),
            "{} must be callable from the tray",
            name.slug()
        );
        assert!(
            !spec.requires_service_mutation_privilege,
            "{} must not require elevation",
            name.slug()
        );
        assert_eq!(IpcOperationName::from_slug(name.slug()), Some(name));
    }
}

#[test]
#[allow(clippy::expect_used)]
fn block_notice_ops_are_tray_reachable_and_never_elevated() {
    // The tray is the surface the block notice — and its mute / "route
    // this" actions — appear on, so every op must admit the tray profile
    // and none may require elevation: they act on the caller's own
    // notices and their own rules.
    let catalog = ipc_operation_catalog();
    for name in [
        IpcOperationName::BlockNoticeJournalList,
        IpcOperationName::BlockNoticeJournalAck,
        IpcOperationName::BlockNoticeMutesList,
        IpcOperationName::BlockNoticeMutesSet,
        IpcOperationName::BlockNoticeMutesRemove,
        IpcOperationName::BlockNoticeMutesClear,
        IpcOperationName::BlockNoticeRouteToSecondary,
    ] {
        let spec = catalog
            .iter()
            .find(|item| item.name == name)
            .expect("block-notice op must be in the catalog");
        assert!(
            spec.allowed_clients
                .contains(&IpcClientProfile::TrayLightweight),
            "{} must be callable from the tray",
            name.slug()
        );
        assert!(
            !spec.requires_service_mutation_privilege,
            "{} must not require elevation",
            name.slug()
        );
        assert_eq!(IpcOperationName::from_slug(name.slug()), Some(name));
    }
}

#[test]
fn async_operations_return_operation_handle_when_required() {
    let catalog = ipc_operation_catalog();
    assert!(catalog.iter().any(|item| {
        item.name == IpcOperationName::MutationSubmit
            && item.execution == IpcExecutionModel::AsyncWithOperationHandle
    }));
}

#[test]
fn lifecycle_and_version_policy_are_explicit() {
    assert_eq!(ipc_lifecycle_stages().len(), 5);
    assert!(IPC_CONTRACT_VERSION_POLICY.contract_version_in_envelope);
    assert!(IPC_CONTRACT_VERSION_POLICY.explicit_negotiation_required);
    assert!(IPC_CONTRACT_VERSION_POLICY.reject_incompatible_versions);
    assert!(IPC_STATE_UPDATE_MODEL.default_model == super::IpcUpdateModel::Hybrid);
}

#[test]
fn correlation_model_requires_request_operation_source_and_contract_version() {
    assert!(IPC_CORRELATION_MODEL.request_id_required);
    assert!(IPC_CORRELATION_MODEL.operation_id_required_for_async);
    assert!(IPC_CORRELATION_MODEL.causation_source_required);
    assert!(IPC_CORRELATION_MODEL.contract_version_required);
    assert_eq!(IPC_CORRELATION_MODEL.allowed_sources.len(), 3);
}

#[test]
fn idempotency_and_retry_policy_are_explicit_for_ambiguous_timeouts() {
    assert!(IPC_RETRY_POLICY.require_idempotency_key_for_mutations);
    assert!(IPC_RETRY_POLICY.timeout_outcome_is_ambiguous);
    assert!(IPC_RETRY_POLICY.require_status_read_after_ambiguous_timeout);
    assert_eq!(IPC_RETRY_POLICY.max_safe_retry_attempts, 3);
}

#[test]
fn transport_envelope_boundary_is_separate_from_payload() {
    assert!(IPC_ENVELOPE_PAYLOAD_BOUNDARY.payload_is_transport_agnostic);
    assert!(IPC_ENVELOPE_PAYLOAD_BOUNDARY.forbid_transport_metadata_inside_payload);
    assert!(IPC_ENVELOPE_PAYLOAD_BOUNDARY.envelope_fields.len() >= 6);
}

/// Every profile the SSOT can WRITE, it must also be able to READ. The
/// console's spelling was missing from the parser, so the one profile that
/// exists to be restricted could not survive a round trip through text.
#[test]
fn every_client_profile_round_trips_through_its_slug() {
    for profile in IpcClientProfile::ALL {
        assert_eq!(
            IpcClientProfile::from_str(profile.slug()),
            Ok(profile),
            "{} does not parse back",
            profile.slug()
        );
    }
    assert_eq!(
        IpcClientProfile::from_str("console"),
        Ok(IpcClientProfile::AdminConsole)
    );
    assert!(IpcClientProfile::from_str("nonsense").is_err());
}

#[test]
fn version_compatibility_matrix_defines_client_behavior_per_case() {
    let rules = IPC_VERSION_COMPATIBILITY_MATRIX.rules;
    assert!(rules.iter().any(|rule| {
        rule.case == VersionCompatibilityCase::OlderService
            && rule.behavior == CompatibilityClientBehavior::ProceedWithCompatibleSubset
    }));
    assert!(rules.iter().any(|rule| {
        rule.case == VersionCompatibilityCase::NewerService
            && rule.behavior == CompatibilityClientBehavior::RequireCapabilityNegotiation
    }));
    assert!(rules.iter().any(|rule| {
        rule.case == VersionCompatibilityCase::IncompatibleContract
            && rule.behavior == CompatibilityClientBehavior::HardFailAndPromptUpgrade
    }));
}
