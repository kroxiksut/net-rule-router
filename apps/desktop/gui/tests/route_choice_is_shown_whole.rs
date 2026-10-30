#![allow(clippy::expect_used)]

//! The default-route choice is a sentence ("Main connection — chosen sites over
//! the additional one"), and the closed combo boxes on Interfaces and routes
//! and in the routing settings were narrower than it: the user saw «Основное
//! подключение — выбранные сайты ч…» and had to open the list to learn which
//! route was in force. Runs the window's sizing against a stand-in font.

#[path = "support/js.rs"]
mod js;
#[path = "support/qml_functions.rs"]
mod qml_functions;

#[test]
fn the_box_is_as_wide_as_its_longest_choice() {
    let output = js::run_js(&format!(
        "{}\n\
         function measuredTextWidth(text) {{ return String(text).length * 7 }}\n\
         function popupAvailableWidth() {{ return 1200 }}\n\
         var modes = [{{ id: 'prefer-primary' }}, {{ id: 'prefer-secondary' }}];\n\
         var labels = {{ 'prefer-primary': 'Основное подключение — выбранные сайты через дополнительное',\n\
                         'prefer-secondary': 'Дополнительное' }};\n\
         {}\n\
         console.log(comboFitWidth({{}}, modes, 'id', function(m) {{ return labels[m.id] }}, 340));\n\
         console.log(comboFitWidth({{}}, [{{ id: 'prefer-secondary' }}], 'id', function(m) {{ return labels[m.id] }}, 340));",
        qml_functions::pure(),
        qml_functions::functions("Main.qml", &["comboFitWidth"])
    ));
    let widths: Vec<i64> = output
        .lines()
        .map(|l| l.parse().expect("a width"))
        .collect();
    let longest = "Основное подключение — выбранные сайты через дополнительное"
        .chars()
        .count() as i64
        * 7;
    assert!(widths[0] > longest, "the longest choice is cut: {output}");
    assert_eq!(widths[1], 340, "a short list keeps the usual width");
}

#[test]
fn both_route_boxes_are_sized_by_their_choices() {
    for (file, combo) in [
        ("sections/InterfacesRoutesSection.qml", "behaviorCombo"),
        ("sections/settings/RoutingSettings.qml", "defaultRouteCombo"),
    ] {
        let source = qml_functions::read(file);
        assert!(
            source.contains(&format!(
                "root.comboFitWidth({combo}, root.behaviorModeModel"
            )),
            "{file}: {combo} has a fixed width shorter than its choices"
        );
    }
}
