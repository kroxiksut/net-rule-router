#![allow(clippy::expect_used)]

//! The licence window is the first thing a new user sees. Switching the
//! agreement to another language switched only the agreement: the title, the
//! heading, the tick box and the decision buttons stayed in the language the
//! user had just turned away from. And on a 1280x720 screen the window, frame
//! included, reached under the taskbar and hid the buttons that let the user
//! go on. Runs the window's own functions against a stand-in.

#[path = "support/js.rs"]
mod js;
#[path = "support/qml_functions.rs"]
mod qml_functions;

const FILE: &str = "components/EulaAgreementWindow.qml";

#[test]
fn the_whole_window_speaks_the_language_the_agreement_is_shown_in() {
    let output = js::run_js(&format!(
        "var selectedLanguage = '';\n\
         var ownerRoot = {{\n\
             tr: function(key) {{ return 'window-language ' + key }},\n\
             resolveCatalogText: function(lang, key) {{ return lang + ' ' + key }}\n\
         }};\n\
         {}\n\
         console.log(tr('dialog.eula.accept', 'Accept and continue'));\n\
         selectedLanguage = 'ru';\n\
         console.log(tr('dialog.eula.accept', 'Accept and continue'));",
        qml_functions::functions(FILE, &["tr"])
    ));
    assert_eq!(
        output, "window-language dialog.eula.accept\nru dialog.eula.accept\n",
        "before the switch the window's language, after it the agreement's"
    );
}

#[test]
fn the_buttons_stay_above_the_taskbar_on_a_small_screen() {
    // 1280x720 with a 48 px taskbar; the window opened centred on a main
    // window that sits lower on the screen.
    for (free_height, opened_at) in [(672, 60), (672, 0), (600, 30), (720, 40)] {
        let output = js::run_js(&format!(
            "var Screen = {{ virtualX: 0, virtualY: 0, width: 1280, height: 720,\n\
                 desktopAvailableWidth: 1280, desktopAvailableHeight: {free_height} }};\n\
             var _designWidth = 820, _designHeight = 640, _frameAllowance = 40;\n\
             var minimumWidth = 560, minimumHeight = 420;\n\
             var x = 230, y = {opened_at}, width = _designWidth, height = _designHeight;\n\
             {}\n\
             _fitOnScreen();\n\
             console.log(y - _frameAllowance, y + height, x, x + width);",
            qml_functions::functions(FILE, &["_fitOnScreen"])
        ));
        let edges: Vec<i64> = output
            .split_whitespace()
            .map(|n| n.parse().expect("a number"))
            .collect();
        let (frame_top, bottom, left, right) = (edges[0], edges[1], edges[2], edges[3]);
        assert!(frame_top >= 0, "title bar off the screen: {output}");
        assert!(
            bottom + 8 <= free_height,
            "the buttons are under the taskbar (free {free_height}): {output}"
        );
        assert!(left >= 0 && right <= 1280, "{output}");
    }
}

#[test]
fn the_window_is_fitted_when_shown_and_when_the_taskbar_moves() {
    let source = qml_functions::read(FILE);
    let on_visible = source
        .split("onVisibleChanged:")
        .nth(1)
        .expect("onVisibleChanged")
        .split("\n    }\n")
        .next()
        .expect("handler body")
        .to_owned();
    assert!(on_visible.contains("_fitOnScreen()"), "{on_visible}");
    assert!(
        source.contains("Screen.onDesktopAvailableHeightChanged: if (visible) _fitOnScreen()"),
        "a taskbar that appears later is not taken into account"
    );
}
