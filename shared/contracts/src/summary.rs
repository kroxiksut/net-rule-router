use crate::{AppShellModel, GuiDialog, VisibilityScope};

pub fn format_shell_summary(shell: &AppShellModel) -> String {
    let sections = shell
        .information_architecture
        .main_window_sections
        .iter()
        .map(|section| section.slug())
        .collect::<Vec<_>>()
        .join(", ");
    let tray_only = shell
        .information_architecture
        .tray_only_actions
        .iter()
        .map(|action| action.id())
        .collect::<Vec<_>>()
        .join(", ");
    let menu_groups = shell
        .menu_bar
        .iter()
        .map(|group| group.id.title())
        .collect::<Vec<_>>()
        .join(", ");

    format!(
        "Sections: [{sections}] | Tray-only actions: [{tray_only}] | Menus: [{menu_groups}] | Single-instance key: {}",
        shell.single_instance.instance_key
    )
}

pub fn format_main_window_shell_summary(shell: &AppShellModel) -> String {
    let zones = shell
        .main_window_shell
        .layout_zones
        .iter()
        .map(|zone| zone.title())
        .collect::<Vec<_>>()
        .join(", ");
    let shared_sections = shell
        .main_window_shell
        .shared_shell_sections
        .iter()
        .map(|section| section.title())
        .collect::<Vec<_>>()
        .join(", ");
    let review_dialogs = shell
        .main_window_shell
        .shared_shell_review_dialogs
        .iter()
        .map(|dialog| match dialog {
            GuiDialog::ConfirmReplaceCurrentList => "Confirm replace current list",
            GuiDialog::ReviewReplaceCurrentList => "Review replace current list",
            GuiDialog::ConfirmDiscardUnsavedChanges => "Confirm discard unsaved changes",
            GuiDialog::ConfirmClearLogs => "Confirm clear logs",
            GuiDialog::ConfirmRollback => "Confirm rollback",
            GuiDialog::ConfirmDisableProductImpact => "Confirm disable product impact",
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "Main window shell: title={} | zones=[{}] | shared_sections=[{}] | review_dialogs=[{}] | apply_cancel_actions={}",
        shell.main_window_shell.window_title,
        zones,
        shared_sections,
        review_dialogs,
        shell.main_window_shell.apply_cancel_actions_visible
    )
}

pub fn format_settings_summary(shell: &AppShellModel) -> String {
    let section_titles = shell
        .settings
        .sections
        .iter()
        .map(|section| section.id.title())
        .collect::<Vec<_>>()
        .join(", ");

    format!(
        "Settings sections: [{section_titles}] | Storage: {}",
        shell.settings.storage_backend_hint
    )
}

pub fn format_about_summary(shell: &AppShellModel) -> String {
    format!(
        "{} {} | License: {} | Channel: {}",
        shell.about.product_name,
        shell.about.edition,
        shell.about.license,
        shell.about.build_channel
    )
}

pub fn format_security_visibility_summary(shell: &AppShellModel) -> String {
    let always_visible = shell
        .security_visibility
        .rules
        .iter()
        .filter(|rule| matches!(rule.scope, VisibilityScope::AlwaysVisible))
        .map(|rule| rule.indicator.title())
        .collect::<Vec<_>>()
        .join(", ");
    let screen_only = shell
        .security_visibility
        .rules
        .iter()
        .filter(|rule| matches!(rule.scope, VisibilityScope::ScreenOnly))
        .map(|rule| rule.indicator.title())
        .collect::<Vec<_>>()
        .join(", ");

    format!("Security visibility: always=[{always_visible}] | screen-only=[{screen_only}]")
}

pub fn format_tooltip_policy_summary(shell: &AppShellModel) -> String {
    format!(
        "Tooltips: enabled_by_default={} | supplemental_only={}",
        shell.tooltip_policy.enabled_by_default, shell.tooltip_policy.supplemental_only
    )
}

pub fn format_accessibility_baseline_summary(shell: &AppShellModel) -> String {
    let mandatory = shell
        .accessibility_baseline
        .requirements
        .iter()
        .filter(|requirement| requirement.mandatory)
        .map(|requirement| requirement.id.title())
        .collect::<Vec<_>>()
        .join(", ");
    format!("Accessibility baseline (mandatory): [{mandatory}]")
}

pub fn format_ui_surface_contract_summary(shell: &AppShellModel) -> String {
    let surfaces = shell
        .ui_surface_contract
        .surfaces
        .iter()
        .map(|surface| surface.id.title())
        .collect::<Vec<_>>()
        .join(", ");
    format!("GUI surfaces (field baseline): [{surfaces}]")
}

pub fn format_interfaces_routes_summary(shell: &AppShellModel) -> String {
    let fields = shell
        .interfaces_routes
        .field_readiness
        .iter()
        .map(|entry| format!("{}={}", entry.field.title(), entry.readiness.title()))
        .collect::<Vec<_>>()
        .join(", ");
    let snapshot_status = shell
        .interfaces_routes
        .field_snapshot_status
        .iter()
        .map(|entry| format!("{}={}", entry.field.title(), entry.availability.title()))
        .collect::<Vec<_>>()
        .join(", ");
    let scopes = shell
        .interfaces_routes
        .field_usage_scopes
        .iter()
        .map(|entry| format!("{}={}", entry.field.title(), entry.scope.title()))
        .collect::<Vec<_>>()
        .join(", ");
    let modes = shell
        .interfaces_routes
        .supported_behavior_modes
        .iter()
        .map(|mode| mode.user_label())
        .collect::<Vec<_>>()
        .join(", ");
    let states = shell
        .interfaces_routes
        .route_state_placeholders
        .iter()
        .map(|state| state.title())
        .collect::<Vec<_>>()
        .join(", ");
    let enriched = shell.interfaces_routes.enriched_fields.join(", ");
    let connectivity_states = shell
        .interfaces_routes
        .connectivity_states
        .iter()
        .map(|state| state.title())
        .collect::<Vec<_>>()
        .join(", ");
    let external_ip_states = shell
        .interfaces_routes
        .external_ip_statuses
        .iter()
        .map(|status| status.title())
        .collect::<Vec<_>>()
        .join(", ");
    let recommendation_classes = shell
        .interfaces_routes
        .recommendation_classes
        .iter()
        .map(|item| item.title())
        .collect::<Vec<_>>()
        .join(", ");
    let bluetooth_signals = shell
        .interfaces_routes
        .bluetooth_detection_signals
        .join(", ");
    format!(
        "Interfaces/routes: preview_only={} | fields=[{}] | snapshot_status=[{}] | usage_scopes=[{}] | enriched=[{}] | connectivity_states=[{}] | external_ip_statuses=[{}] | recommendation_classes=[{}] | bluetooth_default_visible={} | bluetooth_signals=[{}] | unknown_marker='{}' | behavior_modes=[{}] | states=[{}]",
        shell.interfaces_routes.preview_only_selection,
        fields,
        snapshot_status,
        scopes,
        enriched,
        connectivity_states,
        external_ip_states,
        recommendation_classes,
        shell.interfaces_routes.show_bluetooth_adapters_default,
        bluetooth_signals,
        shell.interfaces_routes.display_format.unknown_value_marker,
        modes,
        states
    )
}

pub fn format_rules_summary(shell: &AppShellModel) -> String {
    let rule_types = shell
        .rules
        .supported_free_rule_types
        .iter()
        .map(|kind| kind.title())
        .collect::<Vec<_>>()
        .join(", ");
    let scenarios = shell
        .rules
        .placeholder_scenarios
        .iter()
        .map(|scenario| scenario.title())
        .collect::<Vec<_>>()
        .join(", ");
    let list_types = shell
        .rules
        .supported_free_list_types
        .iter()
        .map(|list_type| list_type.title())
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "Rules: types=[{}] | scenarios=[{}] | list_types=[{}] | review_before_replace={}",
        rule_types, scenarios, list_types, shell.rules.load_list_requires_review_before_replace
    )
}

pub fn format_first_run_summary(shell: &AppShellModel) -> String {
    let steps = shell
        .first_run
        .steps
        .iter()
        .map(|step| step.id.title())
        .collect::<Vec<_>>()
        .join(", ");
    let scenarios = shell
        .first_run
        .scenarios
        .iter()
        .map(|scenario| scenario.title())
        .collect::<Vec<_>>()
        .join(", ");
    let quick_start_path = shell
        .first_run
        .quick_start_path_sections
        .iter()
        .map(|section| section.title())
        .collect::<Vec<_>>()
        .join(" -> ");
    let startup_states = shell
        .first_run
        .startup_states
        .iter()
        .map(|entry| format!("{}={}", entry.section.title(), entry.state.title()))
        .collect::<Vec<_>>()
        .join(", ");
    let action_gates = shell
        .first_run
        .action_gates_before_completion
        .iter()
        .map(|gate| format!("{}={}", gate.action.id(), gate.before_completion.title()))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "First-run: default_scenario={} | steps=[{}] | scenarios=[{}] | quick_start=[{}] | startup_states=[{}] | action_gates=[{}]",
        shell.first_run.default_scenario.title(),
        steps,
        scenarios,
        quick_start_path,
        startup_states,
        action_gates
    )
}
