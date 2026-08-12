//! End-to-end smoke test exercising every DAO against one sidecar.
//!
//! The unit tests cover each table in isolation. This integration
//! test catches schema-wide regressions (e.g. a future migration
//! adds a column to one table that breaks another DAO's prepared
//! statements) by walking through a realistic GUI session: open DB,
//! capture some comments, capture passthrough sections, park a
//! pending-apply, reopen, verify everything survives, then GC and
//! VACUUM.

#![allow(clippy::expect_used)] // tests panic to surface intent

use std::collections::BTreeMap;

use nrr_storage_sidecar::{
    rule_metadata::sanitize_comment, RuleSignature, SidecarDb, SidecarResult,
};

const T0: i64 = 1_700_000_000_000;

#[test]
fn full_gui_session_round_trip() -> SidecarResult<()> {
    let tmp = tempfile::tempdir()?;
    let path = tmp.path().join("gui_metadata.db");

    // ── Session A: user imports a preset, edits two comments, parks
    //    pending-apply because the service was offline, then closes. ──
    {
        let db = SidecarDb::open(&path)?;
        // Initial state — nothing recorded yet.
        assert!(db
            .read_comment(&RuleSignature::build("zone", "ru", "primary"))?
            .is_none());
        assert!(db.read_passthrough("primary")?.is_empty());
        assert!(db.read_pending_apply_at(T0)?.is_none());

        // Capture comments matching the country-preset shape we ship.
        db.write_comment(
            &RuleSignature::build("zone", "рф", "primary"),
            &sanitize_comment("Российская Федерация (.рф, Punycode xn--p1ai)"),
        )?;
        db.write_comment(
            &RuleSignature::build("zone", "ru", "primary"),
            &sanitize_comment("Российская Федерация (.ru)"),
        )?;

        // Capture passthrough sections that the GUI doesn't understand
        // on Windows but must preserve verbatim.
        let mut passthrough = BTreeMap::new();
        passthrough.insert(
            "Linux".to_string(),
            "# (reserved - not applied on Windows)\nfirefox\nchromium\n".to_string(),
        );
        passthrough.insert(
            "MacOS".to_string(),
            "# (reserved - not applied on Windows)\nSafari\n".to_string(),
        );
        db.write_passthrough("primary", &passthrough)?;

        // User clicks "Work without service" → park the snapshot.
        db.write_pending_apply_at(
            r#"{"schema-version":1,"primary":[{"id":"R-0001"}],"secondary":[]}"#,
            r#"{"added":1,"modified":0,"removed":0}"#,
            "abc123",
            T0,
        )?;
    }

    // ── Session B: launcher reopens and verifies every DAO ──
    {
        let db = SidecarDb::open(&path)?;
        // Comments survive.
        let rf_comment = db
            .read_comment(&RuleSignature::build("zone", "рф", "primary"))?
            .expect("рф comment must persist across reopen");
        assert!(rf_comment.contains("Российская"));
        assert!(rf_comment.contains("xn--p1ai"));
        let ru_comment = db
            .read_comment(&RuleSignature::build("zone", "ru", "primary"))?
            .expect("ru comment must persist across reopen");
        assert!(ru_comment.contains(".ru"));

        // Passthrough sections survive byte-identical (within
        // BTreeMap's alphabetical ordering on read).
        let ptr = db.read_passthrough("primary")?;
        assert_eq!(ptr.len(), 2);
        assert_eq!(
            ptr.get("Linux").map(String::as_str),
            Some("# (reserved - not applied on Windows)\nfirefox\nchromium\n"),
        );
        assert_eq!(
            ptr.get("MacOS").map(String::as_str),
            Some("# (reserved - not applied on Windows)\nSafari\n"),
        );

        // Pending-apply readable but treated as expired past TTL.
        let pending = db
            .read_pending_apply_at(T0 + 1_000)?
            .expect("pending row should be fresh 1 s after write");
        assert_eq!(pending.content_hash, "abc123");
        assert!(db
            .read_pending_apply_at(T0 + 8 * 24 * 60 * 60 * 1000)?
            .is_none());

        // ── GC: user removed the rf rule via the GUI; comment becomes
        //    orphan. Pass only the surviving signature. ──
        let removed = db.gc_orphans(&[RuleSignature::build("zone", "ru", "primary")])?;
        assert_eq!(removed, 1);
        assert!(db
            .read_comment(&RuleSignature::build("zone", "рф", "primary"))?
            .is_none());
        assert!(db
            .read_comment(&RuleSignature::build("zone", "ru", "primary"))?
            .is_some());

        // ── Vacuum: explicit, no conditions. Confirms VACUUM works
        //    with live data in every table and updates the throttle row. ──
        db.vacuum_now_at(T0 + 100)?;
        assert_eq!(db.read_last_vacuum_at_ms()?, T0 + 100);
    }

    Ok(())
}

#[test]
fn env_override_resolution_creates_file_at_chosen_path() -> SidecarResult<()> {
    // Exercise `resolve_path_with` end-to-end (without mutating the
    // process environment, which is unsafe under modern Rust). The
    // resolver returns a usable path that we then open with the real
    // `SidecarDb::open` to confirm there's no lingering coupling
    // between the resolver and the opener.
    let tmp = tempfile::tempdir()?;
    let override_path = tmp.path().join("nested").join("custom.db");
    let resolved =
        nrr_storage_sidecar::resolve_path_with(Some(override_path.clone().into_os_string()), None)?;
    assert_eq!(resolved, override_path);

    let db = SidecarDb::open(&resolved)?;
    let sig = RuleSignature::build("domain", "example.com", "primary");
    db.write_comment(&sig, "round-trip")?;
    assert_eq!(db.read_comment(&sig)?.as_deref(), Some("round-trip"));
    Ok(())
}

#[test]
fn schema_survives_three_reopens() -> SidecarResult<()> {
    let tmp = tempfile::tempdir()?;
    let path = tmp.path().join("sidecar.db");
    for _ in 0..3 {
        let db = SidecarDb::open(&path)?;
        // last_migration should report a no-op after the first open.
        let summary = db.last_migration();
        assert!(
            summary.migrations_applied.is_empty()
                || summary.migrations_applied
                    == vec!["initial_sidecar_schema", "external_ip_cache"],
            "reopen should either be a no-op or the very first open",
        );
    }
    Ok(())
}
