use nrr_shared::{
    gui_shell_v1, AppAction, AppSection, FirstRunScenarioId, FirstRunStepId, GuiDialog, GuiWindow,
    MenuAvailability, MenuGroupId, NavigationStyle, SecondaryLaunchBehavior,
    SetupActionAvailability,
};

#[test]
fn main_window_sections_match_block_2_1_baseline() {
    let shell = gui_shell_v1();
    assert_eq!(
        shell.information_architecture.main_window_sections,
        &[
            AppSection::InterfacesAndRoutes,
            AppSection::Rules,
            AppSection::Diagnostics,
            AppSection::Logs,
            AppSection::Settings
        ]
    );
}

#[test]
fn tray_only_actions_are_security_sensitive_controls() {
    let shell = gui_shell_v1();
    assert_eq!(
        shell.information_architecture.tray_only_actions,
        &[
            AppAction::SafeRollback,
            AppAction::TemporarilyDisableProductImpact
        ]
    );
}

#[test]
fn window_and_dialog_map_contains_required_entries() {
    let shell = gui_shell_v1();
    assert_eq!(
        shell.windows,
        &[
            GuiWindow::MainWindow,
            GuiWindow::FirstRunWizard,
            GuiWindow::RuleListLoadWindow,
            GuiWindow::RuleListEditWindow,
            GuiWindow::AboutWindow
        ]
    );
    assert_eq!(
        shell.dialogs,
        &[
            GuiDialog::ConfirmReplaceCurrentList,
            GuiDialog::ReviewReplaceCurrentList,
            GuiDialog::ConfirmDiscardUnsavedChanges,
            GuiDialog::ConfirmClearLogs,
            GuiDialog::ConfirmRollback,
            GuiDialog::ConfirmDisableProductImpact
        ]
    );
}

#[test]
fn menu_groups_and_preview_states_are_fixed() {
    let shell = gui_shell_v1();
    assert_eq!(
        shell
            .menu_bar
            .iter()
            .map(|group| group.id)
            .collect::<Vec<_>>(),
        vec![
            MenuGroupId::File,
            MenuGroupId::View,
            MenuGroupId::Tools,
            MenuGroupId::Help
        ]
    );

    let file_group = shell
        .menu_bar
        .iter()
        .find(|group| group.id == MenuGroupId::File)
        .unwrap_or_else(|| panic!("file group must exist"));

    assert_eq!(file_group.items[0].action, AppAction::LoadRuleList);
    assert_eq!(file_group.items[0].availability, MenuAvailability::Preview);
    assert_eq!(file_group.items[3].action, AppAction::ExitApplication);
    assert!(file_group.items[3].availability.is_enabled());
}

#[test]
fn navigation_and_single_instance_policy_are_fixed() {
    let shell = gui_shell_v1();
    assert_eq!(
        shell.navigation.style,
        NavigationStyle::SidebarWithStackedViews
    );
    assert!(shell.navigation.back_cancel_apply_supported);
    assert!(shell.navigation.tray_opening_reuses_main_window);
    assert_eq!(
        shell.single_instance.behavior,
        SecondaryLaunchBehavior::FocusExistingInstanceAndOpenRequestedSection
    );
}

#[test]
fn first_run_contract_covers_block_2_2_baseline() {
    let shell = gui_shell_v1();
    assert_eq!(
        shell
            .first_run
            .steps
            .iter()
            .map(|step| step.id)
            .collect::<Vec<_>>(),
        vec![
            FirstRunStepId::Welcome,
            FirstRunStepId::BasicScenarioSelection,
            FirstRunStepId::RoutesSetup,
            FirstRunStepId::RulesSetup,
            FirstRunStepId::DiagnosticsPreview,
            FirstRunStepId::Finish
        ]
    );
    assert!(shell.first_run.steps.iter().all(|step| step.required));
    assert_eq!(
        shell.first_run.scenarios,
        &[
            FirstRunScenarioId::QuickStart,
            FirstRunScenarioId::GuidedDefault
        ]
    );
    assert_eq!(
        shell.first_run.default_scenario,
        FirstRunScenarioId::QuickStart
    );
    assert_eq!(
        shell.first_run.quick_start_path_sections,
        &[
            AppSection::InterfacesAndRoutes,
            AppSection::Rules,
            AppSection::Diagnostics
        ]
    );
    assert!(shell
        .first_run
        .startup_states
        .iter()
        .any(|entry| entry.section == AppSection::Rules && entry.state.title() == "empty"));
    assert!(shell.first_run.startup_states.iter().any(|entry| {
        entry.section == AppSection::InterfacesAndRoutes && entry.state.title() == "semi-empty"
    }));
    let export_gate = shell
        .first_run
        .action_gates_before_completion
        .iter()
        .find(|gate| gate.action == AppAction::ExportCurrentRuleList)
        .unwrap_or_else(|| panic!("export action gate must be present"));
    assert_eq!(
        export_gate.before_completion,
        SetupActionAvailability::BlockedUntilWizardCompletion
    );
    let rules_gate = shell
        .first_run
        .action_gates_before_completion
        .iter()
        .find(|gate| gate.action == AppAction::OpenSection(AppSection::Rules))
        .unwrap_or_else(|| panic!("rules section gate must be present"));
    assert_eq!(
        rules_gate.before_completion,
        SetupActionAvailability::SoftGuided
    );
    assert!(shell
        .first_run
        .list_editing_preview_notice
        .contains("preview/setup only"));
    assert!(shell
        .first_run
        .completion_notice
        .contains("interfaces/routes"));
}

/// A client that cannot complete the handshake cannot do anything at all, so
/// the catalogue has to admit every profile to it. The console was not on that
/// list: it declared itself, was refused `contract.negotiate`, and its one
/// wired operation (asking the service for a diagnostics archive) was
/// unreachable — a defect the profile enforcement made visible only once the
/// Linux transport stopped handing every caller the GUI profile.
#[test]
fn every_client_profile_may_complete_the_handshake() {
    use nrr_shared::ipc::{ipc_operation_spec, IpcOperationName};
    use nrr_shared::IpcClientProfile;
    let spec = ipc_operation_spec(IpcOperationName::ContractNegotiate)
        .expect("contract.negotiate is in the catalogue");
    for profile in IpcClientProfile::ALL {
        assert!(
            spec.allowed_clients.contains(&profile),
            "{} cannot negotiate, so it can never reach any operation",
            profile.slug()
        );
    }
}

/// Every operation a profile is allowed to invoke must also be one its class
/// permits: two independent tables saying different things about the same
/// caller is how the console ended up able to ask for nothing.
#[test]
fn the_catalogue_never_admits_a_client_its_class_rule_would_refuse() {
    use nrr_shared::ipc::{ipc_operation_spec, IpcOperationName};
    use nrr_shared::ipc_transport::canonical_operation_class;
    // The dry-run phase of a two-phase operation is classified from its
    // payload; an empty one asks for the phase that gates hardest.
    let payload = serde_json::Value::Null;
    for op in IpcOperationName::ALL {
        let Some(spec) = ipc_operation_spec(op) else {
            continue;
        };
        let class = canonical_operation_class(op, &payload);
        for profile in spec.allowed_clients {
            assert!(
                profile.permits(class),
                "{} is allowed to invoke {} but its class {} says otherwise",
                profile.slug(),
                op.slug(),
                class.slug()
            );
        }
    }
}
