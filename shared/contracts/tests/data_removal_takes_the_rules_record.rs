#![allow(clippy::expect_used)]

//! Removing the service's data (a complete uninstall, a clean start) must take
//! the record of the active rules with it. The record lives beside the signing
//! key, which on Windows is in the service account's own profile, outside the
//! data folder: a removal that left it made the next install's empty database
//! disagree with it, and the first start raised a security alert that blocked
//! the welcome wizard's rule set. The key itself stays: the audit trail's seals
//! are derived from it.

use std::path::Path;

fn read(relative: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative);
    let text = std::fs::read_to_string(&path).expect("a repository file");
    text.trim_start_matches('\u{feff}').replace("\r\n", "\n")
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

/// Lines of `script` that are not comments.
fn code(script: &str) -> String {
    script
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn the_windows_removal_takes_the_record_and_the_resign_marker_and_keeps_the_key() {
    // The removal itself lives in the library the installers share.
    let purge = code(&read("scripts/purge-data.ps1"));
    assert!(
        purge.contains("Remove-KeyCompanions"),
        "purge-data.ps1 leaves the files beside the key behind"
    );
    let script = code(&read("scripts/lib/service-paths.ps1"));
    assert!(
        script.contains("systemprofile"),
        "the files beside the key live in the service account's profile"
    );
    for name in ["RULES_ANCHOR_FILE_NAME", "RESIGN_MARKER_FILE_NAME"] {
        let file = key_store_file(name);
        assert!(
            script.contains(&format!("'{file}'")),
            "the removal leaves {file} behind"
        );
    }
    let key = key_store_file("KEY_FILE_NAME");
    assert!(
        !script.contains(&format!("'{key}'")) && !purge.contains(&format!("'{key}'")),
        "the key itself stays, as on Linux"
    );
}

#[test]
fn the_linux_removal_keeps_only_the_key_and_the_audit_trail() {
    let script = code(&read("scripts/purge-data.sh"));
    assert!(
        script.contains("! -name audit ! -name db-mac-key.bin -exec rm -rf"),
        "the state folder, record included, goes; only the key and the audit trail stay"
    );
}
