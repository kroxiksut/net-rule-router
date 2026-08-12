use nrr_shared::{
    gui_shell_v1, AppAction, AppSection, FirstRunScenarioId, FirstRunStepId, GuiDialog, GuiWindow,
    MainWindowLayoutZone, MenuAvailability, MenuGroupId, NavigationStyle, SecondaryLaunchBehavior,
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
fn main_window_shell_layout_and_shared_flows_are_fixed() {
    let shell = gui_shell_v1();
    assert_eq!(shell.main_window_shell.window_title, "NetRuleRouter");
    assert_eq!(
        shell.main_window_shell.layout_zones,
        &[
            MainWindowLayoutZone::TitleBar,
            MainWindowLayoutZone::MenuBar,
            MainWindowLayoutZone::Sidebar,
            MainWindowLayoutZone::Workspace,
            MainWindowLayoutZone::StatusBar,
            MainWindowLayoutZone::ActionBar
        ]
    );
    assert_eq!(
        shell.main_window_shell.sidebar_sections,
        &[
            AppSection::InterfacesAndRoutes,
            AppSection::Rules,
            AppSection::Diagnostics,
            AppSection::Logs,
            AppSection::Settings
        ]
    );
    assert_eq!(
        shell.main_window_shell.shared_shell_sections,
        &[AppSection::Settings, AppSection::Diagnostics]
    );
    assert_eq!(
        shell.main_window_shell.shared_shell_review_dialogs,
        &[
            GuiDialog::ReviewReplaceCurrentList,
            GuiDialog::ConfirmReplaceCurrentList
        ]
    );
    assert!(shell.main_window_shell.apply_cancel_actions_visible);
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
