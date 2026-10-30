#![allow(clippy::expect_used)]

//! An install over a complete removal by an older build must start clean. Those
//! builds erased the service's data folder but left the record of the active
//! rules beside the signing key, in the service account's profile; the new
//! install's empty database then disagreed with it, the first start raised a
//! security alert and the welcome wizard's rule set was refused. The installer
//! drops that record before the service first starts, and only when no state
//! database exists: an upgrade keeps it, and the service's own check is not
//! relaxed.

use std::path::{Path, PathBuf};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(relative: &str) -> String {
    let text = std::fs::read_to_string(repo().join(relative)).expect("a repository file");
    text.trim_start_matches('\u{feff}').replace("\r\n", "\n")
}

/// Lines of `script` that are not comments.
fn code(script: &str) -> String {
    script
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The value of `const <name>: &str = "...";` in the Windows key store.
fn key_store_file(name: &str) -> String {
    let source = read("core/platform/windows/src/key_store.rs");
    let line = source
        .lines()
        .find(|l| l.contains(&format!("const {name}: &str = \"")))
        .unwrap_or_else(|| panic!("{name} is gone from the key store"));
    line.split('"')
        .nth(1)
        .expect("a quoted file name")
        .to_owned()
}

/// The state database's file name as the storage layer derives it.
fn state_db_file() -> String {
    let source = read("core/storage/src/profile.rs");
    let line = source
        .lines()
        .find(|l| l.contains("state_db_path: data_dir.join(\""))
        .expect("the state database path in the storage profile");
    line.split('"')
        .nth(1)
        .expect("a quoted file name")
        .to_owned()
}

/// The body of the `'<action>' { ... }` branch of setup-actions.ps1's switch.
fn action_branch(script: &str, action: &str) -> String {
    let start = script
        .find(&format!("    '{action}' {{"))
        .unwrap_or_else(|| panic!("setup-actions.ps1 has no {action} action"));
    let rest = &script[start..];
    let end = rest[1..].find("\n    '").map_or(rest.len(), |i| i + 1);
    rest[..end].to_owned()
}

const CLEAR: &str = "Clear-NrrOrphanedKeyCompanions";

#[test]
fn the_files_beside_the_key_are_removed_by_one_definition_shared_by_removal_and_install() {
    let lib = code(&read("scripts/lib/service-paths.ps1"));
    let purge = code(&read("scripts/purge-data.ps1"));
    let setup = code(&read("packaging/windows/setup-actions.ps1"));

    assert_eq!(
        lib.matches("function Remove-KeyCompanions").count(),
        1,
        "service-paths.ps1 holds the one definition"
    );
    for (name, script) in [("purge-data.ps1", &purge), ("setup-actions.ps1", &setup)] {
        assert!(
            !script.contains("function Remove-KeyCompanions"),
            "{name} keeps a second copy of the removal"
        );
    }
    assert!(
        purge.contains("Remove-KeyCompanions"),
        "a complete removal takes the files beside the key"
    );
    assert!(
        lib.contains(&format!("function {CLEAR}")) && lib.contains("Remove-KeyCompanions -KeyDir"),
        "the install step goes through the same removal"
    );
    assert!(
        lib.contains("systemprofile"),
        "the key lives in the service account's profile"
    );
    for name in ["RULES_ANCHOR_FILE_NAME", "RESIGN_MARKER_FILE_NAME"] {
        let file = key_store_file(name);
        assert!(lib.contains(&format!("'{file}'")), "{file} is left behind");
    }
    let key = key_store_file("KEY_FILE_NAME");
    for (name, script) in [
        ("service-paths.ps1", &lib),
        ("purge-data.ps1", &purge),
        ("setup-actions.ps1", &setup),
    ] {
        assert!(
            !script.contains(&format!("'{key}'")),
            "{name} names the key: it stays, the audit trail's seals are derived from it"
        );
    }
}

#[test]
fn the_install_step_looks_for_the_database_the_service_opens() {
    let lib = code(&read("scripts/lib/service-paths.ps1"));
    let db = state_db_file();
    assert!(
        lib.contains(&format!("'{db}'")),
        "the install step must test for {db}, the file the service opens"
    );
    assert!(
        lib.contains("GetFolderPath('CommonApplicationData')"),
        "the data folder comes from Windows, as for the service's ProgramData root"
    );
}

#[test]
fn both_installers_drop_the_record_before_the_service_first_starts() {
    let setup = code(&read("packaging/windows/setup-actions.ps1"));
    let register = action_branch(&setup, "Register");
    let clear = register
        .find(CLEAR)
        .expect("Register drops a removed store's record");
    let start = register
        .find("@('reinstall')")
        .expect("Register starts the service through nrr-cli reinstall");
    assert!(
        clear < start,
        "the record goes before the service's first start"
    );
    for action in [
        "Stop",
        "Resume",
        "MarkStop",
        "Unregister",
        "Rollback",
        "Provision",
    ] {
        assert!(
            !action_branch(&setup, action).contains(CLEAR),
            "{action} must not drop the record: only an install, before the first start"
        );
    }

    // The EXE: Register is the one step that starts the service on install.
    let iss = read("packaging/windows/NetRuleRouter.iss");
    assert!(
        iss.contains("'-Action Register'"),
        "Setup runs Register after the files are in place"
    );

    // The MSI: no ServiceControl starts the service; Register, after the files, does.
    let wxs = read("packaging/windows/NetRuleRouter.wxs");
    for tag in wxs.split('<').filter(|t| t.starts_with("ServiceControl")) {
        assert!(
            !tag.contains("Start="),
            "the MSI starts the service before Register: {tag}"
        );
    }
    assert!(
        wxs.contains("-Action Register\" />"),
        "the MSI runs Register"
    );
    assert!(
        wxs.contains("<Custom Action=\"NrrRegister\" After=\"NrrProvision\"")
            && wxs.contains("<Custom Action=\"NrrProvision\" After=\"InstallFiles\""),
        "Register runs once the files are in place"
    );
}

/// Runs the install step for real over a fake layout: `data_root` stands for
/// `%ProgramData%\NetRuleRouter`, `key_dir` for the service account's folder.
#[cfg(windows)]
fn run_install_step(data_root: &Path, key_dir: &Path) {
    let lib = repo().join("scripts/lib/service-paths.ps1");
    let command = format!(
        "$ErrorActionPreference = 'Stop'; . '{}'; {CLEAR} -DataRoot '{}' -KeyDir '{}' | Out-Null",
        lib.display(),
        data_root.display(),
        key_dir.display()
    );
    let status = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            &command,
        ])
        .status()
        .expect("powershell starts");
    assert!(status.success(), "the install step failed: {status}");
}

#[cfg(windows)]
fn key_dir_with_record(root: &Path) -> PathBuf {
    let key_dir = root.join("key");
    std::fs::create_dir_all(&key_dir).expect("key dir");
    for name in [
        "KEY_FILE_NAME",
        "RULES_ANCHOR_FILE_NAME",
        "RESIGN_MARKER_FILE_NAME",
    ] {
        std::fs::write(key_dir.join(key_store_file(name)), b"x").expect("a file beside the key");
    }
    key_dir
}

#[cfg(windows)]
fn left(key_dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(key_dir)
        .expect("key dir")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[cfg(windows)]
#[test]
fn an_install_over_a_removed_data_folder_keeps_only_the_key() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let key_dir = key_dir_with_record(tmp.path());
    run_install_step(&tmp.path().join("data-gone"), &key_dir);
    assert_eq!(left(&key_dir), vec![key_store_file("KEY_FILE_NAME")]);
}

#[cfg(windows)]
#[test]
fn an_install_over_a_data_folder_without_its_database_keeps_only_the_key() {
    // What an older removal leaves (the audit trail) and what provisioning
    // stages before the first start: a folder, but no store.
    let tmp = tempfile::tempdir().expect("tempdir");
    let data_root = tmp.path().join("data");
    std::fs::create_dir_all(data_root.join("audit")).expect("audit");
    std::fs::create_dir_all(data_root.join("provision")).expect("provision");
    let key_dir = key_dir_with_record(tmp.path());
    run_install_step(&data_root, &key_dir);
    assert_eq!(left(&key_dir), vec![key_store_file("KEY_FILE_NAME")]);
}

#[cfg(windows)]
#[test]
fn an_upgrade_keeps_the_record_of_the_database_it_keeps() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let data_root = tmp.path().join("data");
    std::fs::create_dir_all(&data_root).expect("data");
    std::fs::write(data_root.join(state_db_file()), b"db").expect("state db");
    let key_dir = key_dir_with_record(tmp.path());
    let before = left(&key_dir);
    run_install_step(&data_root, &key_dir);
    assert_eq!(
        left(&key_dir),
        before,
        "an upgrade touches nothing beside the key"
    );
}

#[cfg(windows)]
#[test]
fn a_key_folder_that_is_a_link_is_not_followed() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let target = key_dir_with_record(tmp.path());
    let link = tmp.path().join("linked-key");
    let made = std::process::Command::new("cmd.exe")
        .args(["/C", "mklink", "/J"])
        .arg(&link)
        .arg(&target)
        .output()
        .expect("cmd starts");
    assert!(made.status.success(), "junction: {made:?}");
    let before = left(&target);
    run_install_step(&tmp.path().join("data-gone"), &link);
    assert_eq!(
        left(&target),
        before,
        "an elevated delete went through a link"
    );
}
