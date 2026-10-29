//! What the eye has to find stays findable in every theme: a banner's words
//! read at WCAG AA (4.5:1) on its fill, and keyboard focus on a button filled
//! with the accent or the danger colour shows (3:1) both against that fill and
//! against the panel around it. A white ring on the contrast theme's yellow
//! main button read at 1.4:1.

use std::path::{Path, PathBuf};

/// Theme order of a three-way token: `isHighContrast ? hc : isDark ? dark : light`.
const THEMES: [&str; 3] = ["high contrast", "dark", "light"];

fn qml_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../qml")
}

fn read(relative: &str) -> String {
    let path = qml_dir().join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
        .replace("\r\n", "\n")
}

/// A token's colour in each theme, following plain aliases to other tokens.
fn token(tokens: &str, name: &str) -> [String; 3] {
    let head = format!("readonly property color {name}: ");
    let expr = tokens
        .lines()
        .find_map(|l| l.trim().strip_prefix(&head))
        .unwrap_or_else(|| panic!("{name} is not a colour token"));
    let expr = expr.split("//").next().unwrap_or_default().trim();
    resolve(tokens, name, expr)
}

fn resolve(tokens: &str, name: &str, expr: &str) -> [String; 3] {
    let literal = |s: &str| {
        let s = s.trim();
        (s.starts_with("\"#") && s.ends_with('"')).then(|| s.trim_matches('"').to_owned())
    };
    if let Some(hex) = literal(expr) {
        return [hex.clone(), hex.clone(), hex];
    }
    let alias = expr.trim();
    if alias.chars().all(|c| c.is_ascii_alphanumeric()) {
        return token(tokens, alias);
    }
    let Some(rest) = expr.strip_prefix("isHighContrast ?") else {
        panic!("{name}: cannot read `{expr}`");
    };
    let (hc, others) = rest
        .split_once(':')
        .unwrap_or_else(|| panic!("{name}: `{expr}`"));
    let hc = literal(hc).unwrap_or_else(|| panic!("{name}: `{expr}`"));
    let others = others.trim();
    let (dark, light) = match others.strip_prefix("isDark ?") {
        Some(pair) => {
            let (d, l) = pair
                .split_once(':')
                .unwrap_or_else(|| panic!("{name}: `{expr}`"));
            (literal(d), literal(l))
        }
        None => {
            let both = resolve(tokens, name, others);
            (Some(both[1].clone()), Some(both[2].clone()))
        }
    };
    match (dark, light) {
        (Some(dark), Some(light)) => [hc, dark, light],
        _ => panic!("{name}: cannot read `{expr}`"),
    }
}

fn luminance(hex: &str) -> f64 {
    let v = u32::from_str_radix(hex.trim_start_matches('#'), 16)
        .unwrap_or_else(|e| panic!("{hex}: {e}"));
    let channel = |shift: u32| {
        let c = f64::from((v >> shift) & 0xff) / 255.0;
        if c <= 0.039_28 {
            c / 12.92
        } else {
            ((c + 0.055) / 1.055).powf(2.4)
        }
    };
    0.2126 * channel(16) + 0.7152 * channel(8) + 0.0722 * channel(0)
}

fn contrast(a: &str, b: &str) -> f64 {
    let (la, lb) = (luminance(a), luminance(b));
    (la.max(lb) + 0.05) / (la.min(lb) + 0.05)
}

/// Banner fills the source paints, and colours it writes out instead of
/// asking the theme (which then miss the contrast theme).
fn banner_faults(tokens: &str, banners: &str) -> Vec<String> {
    let mut faults = Vec::new();
    let mut fills: Vec<&str> = banners
        .match_indices("uiTheme.banner")
        .map(|(at, _)| {
            let name = &banners[at + "uiTheme.".len()..];
            let end = name
                .find(|c: char| !c.is_ascii_alphanumeric())
                .unwrap_or(name.len());
            &name[..end]
        })
        .filter(|name| name.ends_with("Fill"))
        .collect();
    fills.sort_unstable();
    fills.dedup();
    if fills.is_empty() {
        faults.push("no banner fill comes from the theme".to_owned());
    }
    let text = token(tokens, "bannerText");
    for fill in fills {
        let bg = token(tokens, fill);
        for (i, theme) in THEMES.iter().enumerate() {
            let ratio = contrast(&text[i], &bg[i]);
            if ratio < 4.5 {
                faults.push(format!(
                    "{theme}: bannerText {} on {fill} {} reads at {ratio:.2}:1",
                    text[i], bg[i]
                ));
            }
        }
    }
    for (at, line) in banners.lines().enumerate() {
        let code = line.split("//").next().unwrap_or_default();
        let written = code.contains("color: \"#")
            || code.contains("color: \"") && !code.contains("\"transparent\"");
        if written {
            faults.push(format!(
                "line {}: a colour written out: {}",
                at + 1,
                line.trim()
            ));
        }
    }
    faults
}

#[test]
fn banner_words_read_on_their_fill_in_every_theme() {
    let faults = banner_faults(
        &read("theme/ThemeTokens.qml"),
        &read("components/TopBannerStack.qml"),
    );
    assert!(faults.is_empty(), "{}", faults.join("\n"));
}

#[test]
fn a_banner_amber_too_light_for_white_or_a_written_out_colour_is_caught() {
    let tokens = "readonly property color bannerText: \"#ffffff\"\n\
                  readonly property color bannerWarningFill: isHighContrast ? \"#000000\" : \"#d97706\"\n";
    let banners = "Rectangle {\n    color: root.uiTheme.bannerWarningFill\n}\n\
                   Rectangle {\n    color: \"#c0392b\"\n}\n";
    let faults = banner_faults(tokens, banners);
    assert_eq!(faults.len(), 3, "{faults:#?}");
}

/// The ring colours a file draws round a focused filled control, and how
/// well the best of them stands out against the fill and against the panel.
fn filled_focus_faults(tokens: &str, file: &str, source: &str, fills: &[&str]) -> Vec<String> {
    let rings: Vec<&str> = tokens
        .lines()
        .filter_map(|l| l.trim().strip_prefix("readonly property color "))
        .filter_map(|l| l.split(':').next())
        .filter(|name| name.starts_with("stateFocused") && name.ends_with("OnFill"))
        .filter(|name| source.contains(&format!(".{name}")))
        .collect();
    if rings.is_empty() {
        return vec![format!("{file}: draws no focus ring for a filled control")];
    }
    let mut faults = Vec::new();
    let best = |against: &[String; 3], i: usize| {
        rings
            .iter()
            .map(|r| contrast(&token(tokens, r)[i], &against[i]))
            .fold(0.0_f64, f64::max)
    };
    let around = [
        ("the panel round it", "colorPanel"),
        ("the window round it", "colorWindow"),
    ];
    let inside = fills.iter().map(|fill| ("the fill", *fill));
    for (what, against) in inside.chain(around) {
        let colours = token(tokens, against);
        for (i, theme) in THEMES.iter().enumerate() {
            let ratio = best(&colours, i);
            if ratio < 3.0 {
                faults.push(format!(
                    "{file}, {theme}: focus ring {rings:?} against {what} {against} {} at best {ratio:.2}:1",
                    colours[i]
                ));
            }
        }
    }
    faults
}

#[test]
fn focus_on_a_filled_button_shows_in_every_theme() {
    let tokens = read("theme/ThemeTokens.qml");
    let mut faults = Vec::new();
    for (file, fills) in [
        (
            "components/ThemedButton.qml",
            &["colorAccent", "colorDanger"][..],
        ),
        ("components/NavigationSidebar.qml", &["colorAccent"][..]),
        ("components/SidebarSubNavButton.qml", &["colorAccent"][..]),
        // A ticked box of the tray prompt is filled with the accent.
        ("components/TrayPromptWindow.qml", &["colorAccent"][..]),
    ] {
        faults.extend(filled_focus_faults(&tokens, file, &read(file), fills));
    }
    assert!(faults.is_empty(), "{}", faults.join("\n"));
}

/// A one-pixel change of border colour is the whole focus cue a section
/// button gave; the ring is the theme's focus width on every one of them.
fn ring_width_fault(source: &str) -> Option<&'static str> {
    let lines: Vec<&str> = source.lines().map(str::trim).collect();
    let widens = lines.iter().enumerate().any(|(at, l)| {
        if !l.starts_with("border.width:") {
            return false;
        }
        let mut expr = (*l).to_owned();
        for next in &lines[at + 1..] {
            if !(next.starts_with('?') || next.starts_with(':')) {
                break;
            }
            expr.push_str(next);
        }
        expr.contains("activeFocus") && expr.contains("focusBorderWidth")
    });
    (!widens).then_some("focus does not widen the border to focusBorderWidth")
}

#[test]
fn every_section_button_draws_the_focus_ring() {
    let mut faults = Vec::new();
    for file in [
        "components/ThemedButton.qml",
        "components/NavigationSidebar.qml",
        "components/SidebarSubNavButton.qml",
        "components/SidebarGlyphButton.qml",
    ] {
        if let Some(fault) = ring_width_fault(&read(file)) {
            faults.push(format!("{file}: {fault}"));
        }
    }
    assert!(faults.is_empty(), "{}", faults.join("\n"));
}

/// The focus ring of a control that is not filled, against the control's own
/// background and the surfaces it sits on.
fn input_focus_faults(tokens: &str, file: &str, source: &str, background: &str) -> Vec<String> {
    let mut faults: Vec<String> = ring_width_fault(source)
        .map(|f| format!("{file}: {f}"))
        .into_iter()
        .collect();
    let ring = "stateFocusedBorder";
    let draws = source
        .match_indices(&format!(".{ring}"))
        .any(|(at, m)| !source[at + m.len()..].starts_with(|c: char| c.is_ascii_alphanumeric()));
    if !draws {
        faults.push(format!("{file}: focus is not drawn in the theme's {ring}"));
        return faults;
    }
    let colours = token(tokens, ring);
    for against in [background, "colorPanel", "colorWindow"] {
        let bg = token(tokens, against);
        for (i, theme) in THEMES.iter().enumerate() {
            let ratio = contrast(&colours[i], &bg[i]);
            if ratio < 3.0 {
                faults.push(format!(
                    "{file}, {theme}: focus ring {} against {against} {} at {ratio:.2}:1",
                    colours[i], bg[i]
                ));
            }
        }
    }
    faults
}

/// Typing into the wrong field because its focus was a one-pixel recolour:
/// every input, the help button and the tray prompt's tick boxes draw the
/// theme's focus ring at its full width, readable on what is behind it.
#[test]
fn every_input_draws_a_focus_ring_that_shows_in_every_theme() {
    let tokens = read("theme/ThemeTokens.qml");
    let mut faults = Vec::new();
    for (file, background) in [
        ("components/ThemedTextField.qml", "colorBase"),
        ("components/ThemedTextArea.qml", "colorBase"),
        ("components/ThemedComboBox.qml", "colorBase"),
        ("components/ThemedSpinBox.qml", "colorBase"),
        ("components/ThemedRadioButton.qml", "colorBase"),
        ("components/HelpButton.qml", "colorPanel"),
        // An unticked box is transparent over the prompt window.
        ("components/TrayPromptWindow.qml", "colorWindow"),
    ] {
        faults.extend(input_focus_faults(&tokens, file, &read(file), background));
    }
    assert!(faults.is_empty(), "{}", faults.join("\n"));
}

const RINGED_INPUTS: [&str; 6] = [
    "ThemedTextField",
    "ThemedTextArea",
    "ThemedComboBox",
    "ThemedSpinBox",
    "ThemedRadioButton",
    "HelpButton",
];

/// Instances that swap the wrapper's background for one that ignores focus.
fn ring_dropping_overrides(source: &str) -> Vec<usize> {
    let lines: Vec<&str> = source.lines().collect();
    let mut found = Vec::new();
    for (at, line) in lines.iter().enumerate() {
        let head = line.trim();
        let instance = line.starts_with(char::is_whitespace)
            && RINGED_INPUTS.iter().any(|w| head == format!("{w} {{"));
        if !instance {
            continue;
        }
        let mut depth = 0i32;
        for (offset, body) in lines[at..].iter().enumerate() {
            let trimmed = body.trim_start();
            if depth == 1 && trimmed.starts_with("background:") && !trimmed.contains("activeFocus")
            {
                found.push(at + offset + 1);
            }
            depth += body.matches('{').count() as i32 - body.matches('}').count() as i32;
            if depth <= 0 {
                break;
            }
        }
    }
    found
}

#[test]
fn no_input_drops_its_focus_ring_for_a_plain_background() {
    let mut files = Vec::new();
    let mut stack = vec![qml_dir()];
    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
        for path in entries.flatten().map(|e| e.path()) {
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "qml") {
                files.push(path);
            }
        }
    }
    let mut faults = Vec::new();
    for path in files {
        let source = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
            .replace("\r\n", "\n");
        for line in ring_dropping_overrides(&source) {
            faults.push(format!("{}:{line}", path.display()));
        }
    }
    assert!(
        faults.is_empty(),
        "a background without the focus ring:\n{}",
        faults.join("\n")
    );
}

#[test]
fn a_text_area_on_a_plain_card_is_caught() {
    let source =
        "Item {\n    ThemedTextArea {\n        background: CardSurface { theme: t }\n    }\n}\n";
    assert_eq!(ring_dropping_overrides(source), vec![3]);
}

#[test]
fn a_button_whose_focus_only_recolours_one_pixel_is_caught() {
    let source = "background: PanelSurface {\n    border.color: control.activeFocus ? a : b\n}\n";
    assert!(ring_width_fault(source).is_some());
}
