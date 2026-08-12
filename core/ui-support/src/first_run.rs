use nrr_shared::{
    AppAction, AppSection, AppShellModel, FirstRunScenarioId, FirstRunStepSpec,
    SectionStartupState, SetupActionAvailability, SetupActionGate,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FirstRunFlowSnapshot {
    pub wizard_required: bool,
    pub selected_scenario: FirstRunScenarioId,
    pub available_scenarios: &'static [FirstRunScenarioId],
    pub steps: &'static [FirstRunStepSpec],
    pub startup_states: &'static [SectionStartupState],
    pub quick_start_path_sections: &'static [AppSection],
    pub action_gates_before_completion: &'static [SetupActionGate],
    pub list_editing_preview_notice: &'static str,
    pub completion_notice: &'static str,
}

pub fn first_run_flow_snapshot(
    shell: &AppShellModel,
    first_run_completed: bool,
    selected_scenario: Option<FirstRunScenarioId>,
) -> FirstRunFlowSnapshot {
    let selected_scenario = selected_scenario
        .filter(|candidate| shell.first_run.scenarios.contains(candidate))
        .unwrap_or(shell.first_run.default_scenario);

    FirstRunFlowSnapshot {
        wizard_required: !first_run_completed,
        selected_scenario,
        available_scenarios: shell.first_run.scenarios,
        steps: shell.first_run.steps,
        startup_states: shell.first_run.startup_states,
        quick_start_path_sections: shell.first_run.quick_start_path_sections,
        action_gates_before_completion: shell.first_run.action_gates_before_completion,
        list_editing_preview_notice: shell.first_run.list_editing_preview_notice,
        completion_notice: shell.first_run.completion_notice,
    }
}

pub fn setup_action_availability(
    shell: &AppShellModel,
    action: AppAction,
    first_run_completed: bool,
) -> SetupActionAvailability {
    if first_run_completed {
        return SetupActionAvailability::Allowed;
    }

    shell
        .first_run
        .action_gates_before_completion
        .iter()
        .find(|gate| gate.action == action)
        .map(|gate| gate.before_completion)
        .unwrap_or(SetupActionAvailability::Allowed)
}

pub fn section_after_first_run_completion(shell: &AppShellModel) -> AppSection {
    shell
        .first_run
        .quick_start_path_sections
        .first()
        .copied()
        .unwrap_or(AppSection::InterfacesAndRoutes)
}

pub fn resolve_entry_section_for_first_run(
    shell: &AppShellModel,
    requested: AppSection,
    first_run_completed: bool,
) -> (AppSection, SetupActionAvailability) {
    let availability = setup_action_availability(
        shell,
        AppAction::OpenSection(requested),
        first_run_completed,
    );
    if first_run_completed || matches!(availability, SetupActionAvailability::Allowed) {
        (requested, availability)
    } else {
        (section_after_first_run_completion(shell), availability)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        first_run_flow_snapshot, resolve_entry_section_for_first_run,
        section_after_first_run_completion, setup_action_availability,
    };
    use nrr_shared::{
        gui_shell_v1, AppAction, AppSection, FirstRunScenarioId, SetupActionAvailability,
    };

    #[test]
    fn snapshot_requires_wizard_until_completed_and_uses_default_scenario() {
        let shell = gui_shell_v1();
        let snapshot = first_run_flow_snapshot(&shell, false, None);
        assert!(snapshot.wizard_required);
        assert_eq!(snapshot.selected_scenario, FirstRunScenarioId::QuickStart);
        assert!(!snapshot.steps.is_empty());
        assert!(!snapshot.startup_states.is_empty());
        assert!(!snapshot.quick_start_path_sections.is_empty());
    }

    #[test]
    fn setup_action_availability_is_relaxed_after_wizard_completion() {
        let shell = gui_shell_v1();
        let before = setup_action_availability(&shell, AppAction::SafeRollback, false);
        assert_eq!(
            before,
            SetupActionAvailability::BlockedUntilWizardCompletion
        );
        let after = setup_action_availability(&shell, AppAction::SafeRollback, true);
        assert_eq!(after, SetupActionAvailability::Allowed);
    }

    #[test]
    fn soft_guided_or_blocked_sections_redirect_to_quick_start_entry() {
        let shell = gui_shell_v1();
        let quick_start_entry = section_after_first_run_completion(&shell);

        let (requested_routes, routes_state) =
            resolve_entry_section_for_first_run(&shell, AppSection::InterfacesAndRoutes, false);
        assert_eq!(requested_routes, AppSection::InterfacesAndRoutes);
        assert_eq!(routes_state, SetupActionAvailability::Allowed);

        let (requested_rules, rules_state) =
            resolve_entry_section_for_first_run(&shell, AppSection::Rules, false);
        assert_eq!(requested_rules, quick_start_entry);
        assert_eq!(rules_state, SetupActionAvailability::SoftGuided);
    }
}
