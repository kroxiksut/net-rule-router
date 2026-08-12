use nrr_shared::{gui_shell_v1, AccessibilityRequirementId};

#[test]
fn accessibility_baseline_is_mandatory_and_not_deferred() {
    let shell = gui_shell_v1();
    let required = [
        AccessibilityRequirementId::AccessibleMetadata,
        AccessibilityRequirementId::KeyboardFirstNavigation,
        AccessibilityRequirementId::VisibleFocusIndicator,
        AccessibilityRequirementId::ScalableText,
        AccessibilityRequirementId::SystemFontSelection,
        AccessibilityRequirementId::DedicatedHighContrastTheme,
        AccessibilityRequirementId::TooltipsAreSupplementalOnly,
    ];
    for id in required {
        assert!(shell
            .accessibility_baseline
            .requirements
            .iter()
            .any(|r| r.id == id && r.mandatory));
    }
}
