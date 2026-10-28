#![allow(clippy::expect_used)]

//! Qt is not shipped in the Linux packages; the window takes the system's. On
//! a system whose Qt is older than the window needs, the package manager must
//! refuse the GUI package and name what is missing, and the documentation must
//! name the same version it refuses below. A floor raised in the build but not
//! in the package installs a window that cannot start.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn repo_file(relative: &str) -> String {
    let path = repo_root().join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
        .replace("\r\n", "\n")
}

const DOCS: [&str; 4] = [
    "docs/en/packaging-linux.md",
    "docs/ru/packaging-linux.md",
    "docs/en/supported-systems.md",
    "docs/ru/supported-systems.md",
];

/// The Qt version the native host refuses to build below.
fn build_floor(cmake: &str) -> Option<String> {
    let call = cmake
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .find_map(|line| line.split_once("find_package(Qt6 "))?
        .1;
    let version = call.split_whitespace().next()?;
    version
        .chars()
        .all(|c| c.is_ascii_digit() || c == '.')
        .then(|| version.to_owned())
}

/// Every `Qt 6.N` floor a text names; a full release such as `Qt 6.10.2` is a
/// fact about one system, not a floor.
fn named_floors(text: &str) -> Vec<String> {
    let mut floors = Vec::new();
    let mut rest = text;
    while let Some(at) = rest.find("Qt 6.") {
        rest = &rest[at + "Qt ".len()..];
        let minor: String = rest["6.".len()..]
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        if minor.is_empty() {
            continue;
        }
        let after = &rest["6.".len() + minor.len()..];
        let is_release = after.starts_with('.')
            && after[1..]
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_digit());
        if !is_release {
            floors.push(format!("6.{minor}"));
        }
    }
    floors
}

/// Why a system with a Qt older than the window needs could take the GUI
/// package, or read a different floor than the one enforced, if it could.
fn qt_floor_flaw(cmake: &str, script: &str, docs: &[(&str, String)]) -> Option<String> {
    let Some(floor) = build_floor(cmake) else {
        return Some("CMakeLists.txt: no `find_package(Qt6 <version> ...)`".into());
    };
    let deb_floor = format!("qt_floor=\"{floor}\"");
    if !script.contains(&deb_floor) {
        return Some(format!(
            "package-linux.sh: the .deb floor is not `{deb_floor}`"
        ));
    }
    // Every QML module the .deb depends on carries the floor.
    if !script.contains("qt_modules=\"$qt_modules, $module (>= $qt_floor)\"") {
        return Some("package-linux.sh: the .deb Qt modules lost their version floor".into());
    }
    let rpm_floor = format!("rpm_qt_floor=\"$(printf '{floor}\\n%s\\n'");
    if !script.contains(&rpm_floor) {
        return Some(format!(
            "package-linux.sh: the .rpm floor does not start at {floor}"
        ));
    }
    for package in ["qt6-qtbase-gui", "qt6-qtdeclarative"] {
        if !script.contains(&format!("\"Requires: {package} >= $rpm_qt_floor\"")) {
            return Some(format!(
                "package-linux.sh: the .rpm requires {package} without the floor"
            ));
        }
    }
    let texts = std::iter::once(("scripts/package-linux.sh", script))
        .chain(docs.iter().map(|(name, text)| (*name, text.as_str())));
    for (name, text) in texts {
        if let Some(other) = named_floors(text).into_iter().find(|v| *v != floor) {
            return Some(format!("{name} names Qt {other}, the build needs {floor}"));
        }
    }
    None
}

fn docs() -> Vec<(&'static str, String)> {
    DOCS.iter().map(|name| (*name, repo_file(name))).collect()
}

#[test]
fn a_system_with_an_older_qt_is_refused_the_window_by_name() {
    assert_eq!(
        qt_floor_flaw(
            &repo_file("apps/desktop/qt-host/native/CMakeLists.txt"),
            &repo_file("scripts/package-linux.sh"),
            &docs(),
        ),
        None
    );
}

/// The check above must see each break it exists for.
#[test]
fn each_qt_floor_regression_is_seen() {
    let cmake = repo_file("apps/desktop/qt-host/native/CMakeLists.txt");
    let script = repo_file("scripts/package-linux.sh");
    let docs = docs();
    let edit = |text: &str, from: &str, to: &str| {
        assert!(text.contains(from), "{from:?} is gone");
        text.replacen(from, to, 1)
    };

    let raised_build = edit(&cmake, "find_package(Qt6 6.6 ", "find_package(Qt6 6.8 ");
    assert!(qt_floor_flaw(&raised_build, &script, &docs).is_some());
    let unversioned_modules = edit(&script, " (>= $qt_floor)\"", "\"");
    assert!(qt_floor_flaw(&cmake, &unversioned_modules, &docs).is_some());
    let unversioned_rpm = edit(
        &script,
        "\"Requires: qt6-qtdeclarative >= $rpm_qt_floor\"",
        "\"Requires: qt6-qtdeclarative\"",
    );
    assert!(qt_floor_flaw(&cmake, &unversioned_rpm, &docs).is_some());
    let mut stale_docs = docs.clone();
    stale_docs[1].1 = edit(&stale_docs[1].1, "Qt 6.6", "Qt 6.5");
    assert!(qt_floor_flaw(&cmake, &script, &stale_docs).is_some());

    assert_eq!(named_floors("Qt 6.10.2 and Qt 6.6. Qt 6 alone"), ["6.6"]);
}
