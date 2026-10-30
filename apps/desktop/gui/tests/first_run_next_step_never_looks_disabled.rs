#![allow(clippy::expect_used)]

//! The owner's machine, one Wi-Fi link: the welcome window picked it for him,
//! and "Set as main" looked greyed out. It was pressable; the pulse that
//! points at the next step faded the button's own colour, and a faded button
//! reads as a disabled one. The pick is confirmed in one press, and the
//! pulse is a ring round the button that leaves the button as it is.

#[path = "support/first_run.rs"]
mod first_run;

/// A file under `apps/desktop/qml`, line endings normalised.
fn qml(relative: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../qml")
        .join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
        .replace("\r\n", "\n")
}

#[test]
fn a_picked_connection_is_set_as_main_in_one_press() {
    let output = first_run::run(
        "rows = [wire('wifi', 'Wireless Network', { 'kind': 'wifi' })];\n\
         _suggestPicks();\n\
         var i = _modelIndexOfKey(pickedPrimaryKey);\n\
         console.log('picked ' + pickedPrimaryKey + ' offered ' + _offeredFor(i, 'primary')\n\
             + ' next ' + _pulseTarget());\n\
         _assignFromPage('primary', i);\n\
         console.log('page ' + step);",
    );
    assert!(
        output.contains("picked wifi offered true next primary-assign"),
        "{output}"
    );
    assert!(output.contains("assign primary wifi"), "{output}");
    assert!(output.contains("page 1"), "{output}");
}

/// Lines of `source` that dim something with the window's pulse.
fn dimmed_by_the_pulse(source: &str) -> Vec<usize> {
    source
        .lines()
        .enumerate()
        .filter(|(_, line)| {
            let code = line.split("//").next().unwrap_or_default().trim_start();
            code.starts_with("opacity:") && code.contains("pulse")
        })
        .map(|(at, _)| at + 1)
        .collect()
}

#[test]
fn the_pulse_never_fades_a_button() {
    let source = qml("components/FirstRunWindow.qml");
    let dimmed = dimmed_by_the_pulse(&source);
    assert!(dimmed.is_empty(), "dimmed by the pulse at lines {dimmed:?}");
    assert!(
        source.contains("attention: enabled && firstRunWindow.pulseTarget === \"primary-assign\""),
        "the next step is still pointed at"
    );
    let button = qml("components/ThemedButton.qml");
    assert!(
        button.contains("property real attention")
            && button.contains("opacity: root.attention")
            && button.contains("border.color: root.theme.colorButtonOutline"),
        "the pulse is a ring in the focus purple"
    );
}

#[test]
fn a_button_faded_by_the_pulse_is_caught() {
    let old = "ThemedButton {\n    opacity: enabled && firstRunWindow.pulseTarget === \"next\"\n        ? firstRunWindow.pulse : 1\n}\n";
    assert_eq!(dimmed_by_the_pulse(old), vec![2]);
}
