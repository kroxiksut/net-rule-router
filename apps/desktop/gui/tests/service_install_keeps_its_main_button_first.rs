#![allow(clippy::expect_used)]

//! The service-install offer laid its buttons left to right with the main one
//! last, so in Russian on a 1280x720 screen "Install and start the service"
//! was the button that wrapped alone onto a second row, under the ones that
//! decline the offer. The row runs right to left from the main action: a wrap
//! moves the secondary buttons instead.

use std::path::Path;

#[test]
fn a_wrapping_row_never_moves_the_main_button() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../qml/components/FirstLaunchInstallDialog.qml");
    let source = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
        .replace("\r\n", "\n");
    let row = source
        .split("id: actionsFlow")
        .nth(1)
        .expect("the action row");
    assert!(
        row.contains("layoutDirection: Qt.RightToLeft"),
        "the row fills from the left, so its last button is the one that wraps"
    );
    let first_button = row
        .split("ThemedButton {")
        .nth(1)
        .expect("a button in the row");
    assert!(
        first_button.contains("dialog.first-launch-install.install-button"),
        "the main button is not the one the row starts from:\n{first_button}"
    );
}
