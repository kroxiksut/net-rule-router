//! The leak-protection protocol picker never reaches a selection that blocks
//! nothing: the last ticked box that blocks something is locked (the stored
//! bit 64 has no box and does not block), and a stored or reported mask that blocks nothing reads as every
//! protocol. Runs the real `pure.js`.

#[path = "support/js.rs"]
mod js;

use std::path::{Path, PathBuf};

fn repo_file(relative: &str) -> String {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

#[test]
fn the_picker_locks_its_boxes_through_the_shared_helper() {
    let source = repo_file("apps/desktop/qml/sections/settings/RoutingSettings.qml");
    assert!(
        source.contains("Pure.killSwitchProtocolLocked("),
        "RoutingSettings.qml no longer locks the last protocol box through pure.js"
    );
    assert!(
        source.contains("settings.routing.kill-switch.protocols.last-one-hint"),
        "the locked box lost its visible explanation"
    );
    assert!(
        source.contains("Pure.killSwitchProtocolsAtLastOne("),
        "the explanation no longer follows the shared lock rule"
    );
}

#[test]
fn the_picker_has_no_other_box_and_keeps_the_stored_bit() {
    let source = repo_file("apps/desktop/qml/sections/settings/RoutingSettings.qml");
    assert!(
        !source.contains("slug: \"other\""),
        "the legacy Other box is back in the picker"
    );
    assert!(
        source.contains("panel.ksProtocols = m & 0x7F"),
        "toggling a box must keep the stored bit 64 as is"
    );
}

#[test]
fn only_the_last_ticked_box_that_blocks_something_is_locked() {
    let harness = format!(
        "{source}\n\
         console.log([killSwitchProtocolLocked(1, 1), killSwitchProtocolLocked(3, 1),\n\
                      killSwitchProtocolLocked(4, 1), killSwitchProtocolLocked(127, 4),\n\
                      killSwitchProtocolLocked(65, 1), killSwitchProtocolLocked(65, 64),\n\
                      killSwitchProtocolLocked(64, 64)].join(','));\n\
         console.log([killSwitchProtocolsAtLastOne(1), killSwitchProtocolsAtLastOne(65),\n\
                      killSwitchProtocolsAtLastOne(3), killSwitchProtocolsAtLastOne(127)].join(','));\n",
        source = repo_file("apps/desktop/qml/lib/pure.js").replace(".pragma library", ""),
    );
    let output = js::run_js(&harness);
    let lines: Vec<&str> = output.lines().collect();
    assert_eq!(
        lines,
        [
            "true,false,false,false,true,false,false",
            "true,true,false,false"
        ],
        "{output}"
    );
}

#[test]
fn a_mask_that_blocks_nothing_reads_as_every_protocol() {
    let harness = format!(
        "{source}\n\
         console.log([0, 64, 128, 133, undefined, null, 5, 65, 127]\n\
             .map(function (v) {{ return routePolicyCoerce('kill-switch-protocols', v) }})\n\
             .join(','));\n",
        source = repo_file("apps/desktop/qml/lib/pure.js").replace(".pragma library", ""),
    );
    let output = js::run_js(&harness);
    assert_eq!(
        output.trim(),
        "127,127,127,127,127,127,5,65,127",
        "{output}"
    );
}
