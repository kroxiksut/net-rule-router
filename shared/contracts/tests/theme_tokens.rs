use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn main_qml_uses_centralized_theme_layer_and_reusable_surfaces() {
    // Main.qml is a thin shell: it owns the theme layer and the shell
    // surfaces, while card-level surfaces live in the extracted section
    // files. Assert each guarantee where it lives.
    let main_qml = read_file("apps/desktop/qml/Main.qml");
    assert!(main_qml.contains("import \"theme\""));
    assert!(main_qml.contains("import \"components\""));
    assert!(main_qml.contains("ThemeTokens {"));
    assert!(main_qml.contains("effectiveThemeMode"));
    assert!(main_qml.contains("resolveThemeModeForPrefs"));
    assert!(main_qml.contains("PanelSurface"));

    assert!(
        any_qml_file_contains("apps/desktop/qml/sections", "CardSurface"),
        "no extracted section uses the reusable CardSurface"
    );

    let tray_qml = read_file("apps/desktop/qml/Tray.qml");
    assert!(tray_qml.contains("property var theme"));
    assert!(tray_qml.contains("iconFileUrl"));
}

/// Whether any `.qml` file under `relative_dir` (recursive) contains `needle`.
fn any_qml_file_contains(relative_dir: &str, needle: &str) -> bool {
    fn scan(dir: &Path, needle: &str) -> bool {
        let Ok(entries) = fs::read_dir(dir) else {
            return false;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if scan(&path, needle) {
                    return true;
                }
            } else if path.extension().is_some_and(|e| e == "qml")
                && fs::read_to_string(&path).is_ok_and(|text| text.contains(needle))
            {
                return true;
            }
        }
        false
    }
    scan(&workspace_root().join(relative_dir), needle)
}

#[test]
fn theme_token_contract_documents_required_sets() {
    let tokens_doc = read_file("configs/theme/TOKENS.md");
    for marker in [
        "Color Tokens",
        "Typography Tokens",
        "Density And Shape Tokens",
        "Component State Tokens",
        "must not define direct colors",
    ] {
        assert!(
            tokens_doc.contains(marker),
            "missing marker '{marker}' in theme token contract"
        );
    }
}

#[test]
fn high_contrast_policy_and_assets_are_present() {
    let tokens_qml = read_file("apps/desktop/qml/theme/ThemeTokens.qml");
    for marker in [
        "pairTextOnWindowFg",
        "pairTextOnPanelFg",
        "pairFocusRingFg",
        "pairSelectionFg",
    ] {
        assert!(
            tokens_qml.contains(marker),
            "missing high-contrast contrast pair token '{marker}'"
        );
    }

    let policy = read_file("configs/theme/HIGH_CONTRAST.md");
    assert!(policy.contains("supported theme mode"));
    assert!(policy.contains("Mandatory Contrast Pairs"));

    for relative_path in [
        "assets/icons/tray/tray-default-hc.ico",
        "assets/icons/tray/tray-warning-hc.ico",
        "assets/icons/tray/tray-error-hc.ico",
    ] {
        let full_path = workspace_root().join(relative_path);
        assert!(
            full_path.exists(),
            "expected high-contrast tray icon asset: '{}'",
            full_path.display()
        );
    }
}

fn read_file(relative_path: &str) -> String {
    let path = workspace_root().join(relative_path);
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read '{}': {error}", path.display()))
}

fn workspace_root() -> PathBuf {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .join("../..")
        .canonicalize()
        .unwrap_or_else(|error| {
            panic!(
                "failed to resolve workspace root from '{}': {error}",
                manifest_dir.display()
            )
        })
}

/// Status text a reader with low vision can read: every warning, error,
/// success and muted line clears WCAG AA (4.5:1) on every surface of every
/// theme. The light theme's amber warning read at 2.8:1 on its base.
#[test]
fn status_text_is_readable_on_every_surface_of_every_theme() {
    let tokens = read_file("apps/desktop/qml/theme/ThemeTokens.qml");
    let three = |name: &str| -> [String; 3] {
        let head = format!("readonly property color {name}: isHighContrast ? \"");
        let at = tokens
            .find(&head)
            .unwrap_or_else(|| panic!("{name} is not a three-theme token"));
        let line = tokens[at..].lines().next().unwrap_or_default();
        let colors: Vec<String> = line
            .split('"')
            .skip(1)
            .step_by(2)
            .map(str::to_owned)
            .collect();
        assert_eq!(colors.len(), 3, "{line}");
        [colors[0].clone(), colors[1].clone(), colors[2].clone()]
    };
    let luminance = |hex: &str| -> f64 {
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
    };
    let contrast = |a: &str, b: &str| {
        let (la, lb) = (luminance(a), luminance(b));
        (la.max(lb) + 0.05) / (la.min(lb) + 0.05)
    };
    let themes = ["high contrast", "dark", "light"];
    for text in [
        "colorWarning",
        "colorDanger",
        "colorSuccess",
        "colorTextMuted",
    ] {
        for surface in ["colorWindow", "colorPanel", "colorBase"] {
            let (fg, bg) = (three(text), three(surface));
            for (i, theme) in themes.iter().enumerate() {
                let ratio = contrast(&fg[i], &bg[i]);
                assert!(
                    ratio >= 4.5,
                    "{theme}: {text} {} on {surface} {} reads at {ratio:.2}:1",
                    fg[i],
                    bg[i]
                );
            }
        }
    }
}
