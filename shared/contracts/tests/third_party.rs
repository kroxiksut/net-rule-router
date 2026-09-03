/// Every `required_for` slug a shipped component declares must have its own
/// branch in the panel that renders it.
///
/// The panel spells the keys out rather than composing them, because the
/// localization gate reads string literals and cannot see a key built by
/// concatenation. That makes the branch list the thing that can fall behind:
/// a third component would have reached the About window as a raw slug.
#[test]
fn every_third_party_feature_slug_has_a_branch_in_the_panel() {
    let panel = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../apps/desktop/qml/components/ThirdPartyComponentsPanel.qml"),
    )
    .expect("read ThirdPartyComponentsPanel.qml");

    for component in nrr_shared::third_party::THIRD_PARTY_BINARY_COMPONENTS
        .iter()
        .chain(nrr_shared::third_party::THIRD_PARTY_ASSET_COMPONENTS)
    {
        let slug = component.required_for;
        assert!(
            panel.contains(&format!("slug === \"{slug}\"")),
            "`{slug}` (from {}) has no branch in ThirdPartyComponentsPanel.qml, so the \
             About window would show the slug itself",
            component.key
        );
        assert!(
            panel.contains(&format!("dialog.third-party.feature.{slug}")),
            "`{slug}` has no locale key literal the localization gate can see"
        );
    }
}
