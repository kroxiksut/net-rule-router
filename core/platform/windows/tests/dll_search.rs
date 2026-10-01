//! Every executable we ship on Windows narrows its DLL search before anything
//! else in `main` runs, through the one shared function.

#![allow(clippy::expect_used)]

use std::path::{Path, PathBuf};

const SHARED_CALL: &str = "nrr_platform_windows::dll_search::restrict_dll_search()";

/// Built for Linux only, where the loader settles its search before `main`.
const NOT_BUILT_FOR_WINDOWS: &[&str] = &["nrr-serviced"];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("core/platform/windows sits three levels below the root")
        .to_path_buf()
}

/// `(binary name, main source)` for every binary target in the workspace,
/// asked of cargo so that a new `[[bin]]` cannot slip past this test.
fn binary_mains() -> Vec<(String, PathBuf)> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let output = std::process::Command::new(cargo)
        .args([
            "metadata",
            "--no-deps",
            "--offline",
            "--format-version",
            "1",
        ])
        .current_dir(workspace_root())
        .output()
        .expect("cargo metadata must run");
    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let meta: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("cargo metadata must be JSON");
    let mut mains = Vec::new();
    for package in meta["packages"].as_array().expect("packages") {
        for target in package["targets"].as_array().expect("targets") {
            let is_bin = target["kind"]
                .as_array()
                .expect("kind")
                .iter()
                .any(|kind| kind == "bin");
            if is_bin {
                mains.push((
                    target["name"].as_str().expect("name").to_string(),
                    PathBuf::from(target["src_path"].as_str().expect("src_path")),
                ));
            }
        }
    }
    mains
}

/// The first line of the body of `opening` that is code: blank lines, comments,
/// `#[cfg]` attributes and preprocessor conditionals are skipped.
fn first_statement_after(source: &str, opening: &str) -> String {
    let start = source.find(opening).expect("entry point present");
    let body = &source[start..];
    let brace = body.find('{').expect("entry point has a body");
    body[brace + 1..]
        .lines()
        .map(str::trim)
        .find(|line| {
            !line.is_empty()
                && !line.starts_with("//")
                && !line.starts_with("#[cfg(")
                && !line.starts_with("#if")
        })
        .expect("entry point body is not empty")
        .to_string()
}

#[test]
fn every_windows_main_restricts_the_dll_search_first() {
    let mains = binary_mains();
    for expected in [
        "nrr-service",
        "NetRuleRouter",
        "NetRuleRouterTray",
        "nrr-cli",
    ] {
        assert!(
            mains.iter().any(|(name, _)| name == expected),
            "{expected} not among the workspace binaries: {mains:?}"
        );
    }
    for (name, path) in mains {
        if NOT_BUILT_FOR_WINDOWS.contains(&name.as_str()) {
            continue;
        }
        let source = std::fs::read_to_string(&path).expect("main source readable");
        let first = first_statement_after(&source, "fn main(");
        if first.contains(SHARED_CALL) {
            continue;
        }
        // A crate that keeps its OS choice in one module calls a shim there,
        // which in turn must be the shared function.
        let shim = first
            .strip_suffix("::restrict_dll_search();")
            .unwrap_or_else(|| {
                panic!("{name}: `main` must start with {SHARED_CALL}, starts with `{first}`")
            });
        let module = path
            .parent()
            .expect("main has a directory")
            .join(format!("{shim}.rs"));
        let shim_source = std::fs::read_to_string(&module)
            .unwrap_or_else(|e| panic!("{name}: shim {} unreadable: {e}", module.display()));
        assert!(
            shim_source.contains(SHARED_CALL),
            "{name}: {} must delegate to {SHARED_CALL}",
            module.display()
        );
    }
}

#[test]
fn the_qt_host_restricts_the_dll_search_and_pins_qt_before_loading_anything() {
    let path = workspace_root().join("apps/desktop/qt-host/native/src/main.cpp");
    let source = std::fs::read_to_string(&path).expect("host main readable");
    let first = first_statement_after(&source, "int main(");
    assert!(
        first.contains("restrictDllSearch()"),
        "the host's `main` must start with restrictDllSearch(), starts with `{first}`"
    );
    let before = |earlier: &str, later: &str| {
        let e = source
            .find(earlier)
            .unwrap_or_else(|| panic!("`{earlier}` missing"));
        let l = source
            .find(later)
            .unwrap_or_else(|| panic!("`{later}` missing"));
        assert!(e < l, "`{earlier}` must come before `{later}`");
    };
    // The platform plugin loads inside the QApplication constructor.
    before(
        "pinQtPluginPaths(executableDirectory())",
        "QApplication application(",
    );
    before(
        "engine.setImportPathList(pinnedQmlImportPaths(",
        "engine.load(",
    );
}

#[cfg(windows)]
#[test]
#[allow(unsafe_code)]
fn after_the_restriction_a_dll_in_the_current_directory_is_not_found() {
    use windows::core::w;
    use windows::Win32::Foundation::FreeLibrary;
    use windows::Win32::System::LibraryLoader::LoadLibraryW;

    let system32 = PathBuf::from(std::env::var("SystemRoot").expect("SystemRoot")).join("System32");
    let dir = tempfile::tempdir().expect("temp dir");
    for name in ["nrr_cwd_probe_before.dll", "nrr_cwd_probe_after.dll"] {
        std::fs::copy(system32.join("version.dll"), dir.path().join(name)).expect("copy probe");
    }
    let original = std::env::current_dir().expect("current dir");
    std::env::set_current_dir(dir.path()).expect("enter temp dir");

    // Positive control: without the restriction the current directory is searched.
    // SAFETY: a copy of a system DLL loaded by a static NUL-terminated name.
    let before = unsafe { LoadLibraryW(w!("nrr_cwd_probe_before.dll")) };
    let before = before.expect("the default search finds a DLL in the current directory");
    // SAFETY: the handle came from the successful load just above.
    unsafe { FreeLibrary(before) }.expect("unload probe");

    nrr_platform_windows::dll_search::restrict_dll_search().expect("restriction succeeds");

    // SAFETY: as above; expected to fail without loading anything.
    let after = unsafe { LoadLibraryW(w!("nrr_cwd_probe_after.dll")) };
    // SAFETY: a system DLL by bare name, which System32 still serves.
    let system = unsafe { LoadLibraryW(w!("version.dll")) };
    std::env::set_current_dir(original).expect("leave temp dir");

    assert!(after.is_err(), "a DLL in the current directory was loaded");
    assert!(system.is_ok(), "System32 is no longer searched");
}
