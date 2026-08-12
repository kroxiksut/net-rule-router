use nrr_shared::{gui_shell_v1, UiSurfaceId};

#[test]
fn ui_surface_contract_covers_windows_and_dialogs_field_baseline() {
    let shell = gui_shell_v1();
    let required_surfaces = [
        UiSurfaceId::MainWindow,
        UiSurfaceId::FirstRunWizard,
        UiSurfaceId::InterfacesAndRoutesScreen,
        UiSurfaceId::RulesScreen,
        UiSurfaceId::LoadListDialog,
        UiSurfaceId::EditListDialog,
        UiSurfaceId::EditRuleDialog,
        UiSurfaceId::RuleReplaceReviewDialog,
        UiSurfaceId::DiagnosticsScreen,
        UiSurfaceId::LogsScreen,
        UiSurfaceId::AboutWindow,
        UiSurfaceId::ConfirmationDialogs,
    ];
    for surface in required_surfaces {
        let spec = shell
            .ui_surface_contract
            .surfaces
            .iter()
            .find(|candidate| candidate.id == surface)
            .unwrap_or_else(|| panic!("required surface is missing"));
        assert!(!spec.fields.is_empty());
    }
}
