//! A sidecar left in the roaming profile is adopted by the production open.
//!
//! Its own binary because it rewrites process-wide environment variables.

#![cfg(target_os = "windows")]
#![allow(clippy::expect_used)]

use nrr_storage_sidecar::{RuleSignature, SidecarDb, NRR_SIDECAR_PATH_ENV};

#[test]
fn open_default_finds_comments_left_in_the_roaming_profile() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let roaming = tmp.path().join("roaming");
    let local = tmp.path().join("local");
    let legacy_dir = roaming.join("NetRuleRouter");
    std::fs::create_dir_all(&legacy_dir).expect("legacy dir");
    std::fs::create_dir_all(&local).expect("local dir");

    let sig = RuleSignature::build("zone", "example", "primary").expect("signature");
    {
        let legacy = SidecarDb::open(legacy_dir.join("gui_metadata.db")).expect("legacy open");
        legacy
            .write_comment(&sig, "typed by the user")
            .expect("write");
    }

    std::env::remove_var(NRR_SIDECAR_PATH_ENV);
    std::env::set_var("APPDATA", &roaming);
    std::env::set_var("LOCALAPPDATA", &local);

    let db = SidecarDb::open_default().expect("open_default");
    assert_eq!(
        db.path(),
        local.join("NetRuleRouter").join("gui_metadata.db"),
        "the local path is what gets opened"
    );
    let comments = db.read_all_comments().expect("read");
    assert_eq!(
        comments.get("zone|example|primary").map(String::as_str),
        Some("typed by the user")
    );
    assert!(
        !legacy_dir.join("gui_metadata.db").exists(),
        "moved, not copied"
    );
}
