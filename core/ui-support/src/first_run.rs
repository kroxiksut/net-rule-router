use nrr_shared::{AppAction, AppSection, AppShellModel, SetupActionAvailability};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FirstRunFlowSnapshot {
    pub completion_notice: &'static str,
}

pub fn first_run_flow_snapshot(shell: &AppShellModel) -> FirstRunFlowSnapshot {
    FirstRunFlowSnapshot {
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
    use nrr_shared::{gui_shell_v1, AppAction, AppSection, SetupActionAvailability};

    #[test]
    fn snapshot_carries_the_shell_first_run_model() {
        let shell = gui_shell_v1();
        let snapshot = first_run_flow_snapshot(&shell);
        assert_eq!(
            snapshot.completion_notice,
            shell.first_run.completion_notice
        );
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
