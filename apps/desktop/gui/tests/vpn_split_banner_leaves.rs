//! The blue "your additional adapter is carrying exactly what you asked"
//! banner asks nothing, so it must leave by itself once read: it sat over the
//! window until clicked, and read as a problem left unanswered. Gone for that
//! adapter until the app restarts, and never counted down while the user is
//! pointing at it, focused on it, or not looking at the window.

use std::path::{Path, PathBuf};

fn qml(rel: &str) -> String {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../qml")
        .join(rel);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
        .replace("\r\n", "\n")
}

#[test]
fn the_explainer_counts_down_only_while_read_and_then_stays_away_for_that_adapter() {
    let main = qml("Main.qml");
    let from = main
        .find("readonly property bool secondaryBannerVisible:")
        .unwrap_or_else(|| panic!("secondaryBannerVisible not found"));
    let rest = &main[from..];
    let binding = &rest[..rest.find("\n\n").unwrap_or(rest.len())];
    assert!(
        binding.contains(
            "_vpnSplitShownFor !== interfacesRolesController._vpnConflictSecondaryDisplayName()"
        ),
        "the explainer does not stay away once it has left:\n{binding}"
    );

    let stack = qml("components/TopBannerStack.qml");
    let timer_at = stack
        .find("onTriggered: root._vpnSplitShownFor =")
        .unwrap_or_else(|| panic!("the explainer never leaves by itself"));
    let timer = &stack[stack[..timer_at].rfind("Timer {").unwrap_or(0)..timer_at];
    for held_by in [
        "secondaryAdapterBanner.explainerShown",
        "root.active",
        "!secondaryBannerHover.hovered",
        "!vpnSplitCloseButton.activeFocus",
    ] {
        assert!(
            timer.contains(held_by),
            "the countdown ignores `{held_by}`:\n{timer}"
        );
    }
}
