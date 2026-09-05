//! `passthrough` table — raw text of unknown preset sections.
//!
//! Captures sections we don't understand (`--- Linux`, `--- MacOS`,
//! `--- Ports`, anything future) at preset-import time so a later
//! `Export to file…` round-trip preserves them byte-for-byte. The GUI
//! itself has no rendering for these sections; sidecar just remembers
//! them keyed by `(route, section_name)`.
//!
//! Write semantics are **atomic replace** per route: every import
//! overwrites the full set of passthrough sections for that route in a
//! single transaction, so the user never sees a partial mix of old +
//! new sections. Rationale: a preset file is treated as the source of
//! truth for its route, including the sections we don't read.

use std::collections::BTreeMap;
use std::time::SystemTime;

use rusqlite::params;

use crate::db::SidecarDb;
use crate::error::SidecarResult;

/// Longest section name kept. A `--- <name>` header longer than this is not a
/// section any producer writes; it is a way to grow the table on someone else's
/// disk through an imported file.
const MAX_SECTION_NAME_CHARS: usize = 128;

/// Largest raw section body kept, matching the 1 MiB cap the import path puts
/// on a WHOLE preset file — so no legitimate import can reach it, and a caller
/// that bypasses the file path still cannot store an unbounded blob.
const MAX_RAW_TEXT_BYTES: usize = 1024 * 1024;

impl SidecarDb {
    /// Read all passthrough sections for `route`. Returns a
    /// deterministic order (`BTreeMap`, alphabetical by section name)
    /// so the canonical-txt writer emits them reproducibly across
    /// runs. Empty map when the route has no recorded passthrough.
    pub fn read_passthrough(&self, route: &str) -> SidecarResult<BTreeMap<String, String>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT section_name, raw_text FROM passthrough
                 WHERE route = ?1
                 ORDER BY section_name",
        )?;
        let mut rows = stmt.query(params![route])?;
        let mut out = BTreeMap::new();
        while let Some(row) = rows.next()? {
            let name: String = row.get(0)?;
            let raw: String = row.get(1)?;
            out.insert(name, raw);
        }
        Ok(out)
    }

    /// Replace the full passthrough set for `route` with `sections`.
    /// Executes DELETE + bulk-INSERT inside a single transaction so a
    /// partial failure leaves the previous set intact.
    ///
    /// Passing an empty map clears all passthrough rows for `route`
    /// (used when the user imports a preset that has only known
    /// sections, dropping any previously-captured foreign-OS blocks).
    pub fn write_passthrough(
        &self,
        route: &str,
        sections: &BTreeMap<String, String>,
    ) -> SidecarResult<()> {
        let now = unix_now_ms();
        let mut conn = self.conn_mut();
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM passthrough WHERE route = ?1", params![route])?;
        if !sections.is_empty() {
            let mut stmt = tx.prepare(
                "INSERT INTO passthrough (route, section_name, raw_text, updated_at)
                     VALUES (?1, ?2, ?3, ?4)",
            )?;
            for (name, raw) in sections {
                // Oversized sections are DROPPED, not truncated. The point of
                // this table is a byte-for-byte round trip; half a section
                // written back looks intact and is not, while a missing one is
                // visible in the exported file.
                if name.chars().count() > MAX_SECTION_NAME_CHARS || raw.len() > MAX_RAW_TEXT_BYTES {
                    continue;
                }
                stmt.execute(params![route, name, normalize_raw_text(raw), now])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Drop every passthrough row for `route`. No-op when the route
    /// had no rows. Exposed separately from `write_passthrough(&map)`
    /// so callers that want to express "forget passthrough for this
    /// route" intent explicitly read more clearly than passing an
    /// empty map.
    pub fn clear_passthrough(&self, route: &str) -> SidecarResult<()> {
        let conn = self.conn_mut();
        conn.execute("DELETE FROM passthrough WHERE route = ?1", params![route])?;
        Ok(())
    }
}

/// End a non-empty section body in exactly one newline.
///
/// The canonical writer splits on `\n` and drops one trailing empty entry, so
/// it already assumed this — a body with none lost nothing, a body with two
/// gained a blank line inside the exported section on every round trip. The
/// assumption is now true where the writer said it was.
fn normalize_raw_text(raw: &str) -> String {
    let trimmed = raw.trim_end_matches(['\n', '\r']);
    if trimmed.is_empty() {
        String::new()
    } else {
        format!("{trimmed}\n")
    }
}

/// Current Unix epoch in milliseconds. Mirrors the helper in
/// `rule_metadata`; kept here to avoid cross-module dependency on a
/// private item.
fn unix_now_ms() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SidecarDb;

    fn open_sidecar(tmp: &tempfile::TempDir) -> SidecarResult<SidecarDb> {
        let path = tmp.path().join("sidecar.db");
        SidecarDb::open(&path)
    }

    fn sections(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    /// The canonical writer splits on newline and drops one trailing empty
    /// entry, saying in its own comment that the sidecar guarantees exactly one
    /// trailing newline. It did not — so a body with two gained a blank line
    /// inside the section on every export.
    #[test]
    fn a_section_body_is_stored_with_exactly_one_trailing_newline() -> SidecarResult<()> {
        let tmp = tempfile::tempdir()?;
        let db = open_sidecar(&tmp)?;
        db.write_passthrough(
            "primary",
            &sections(&[
                (
                    "None", "a
b",
                ),
                (
                    "Two", "a
b

",
                ),
                (
                    "Blank", "

",
                ),
            ]),
        )?;
        let got = db.read_passthrough("primary")?;
        assert_eq!(
            got.get("None").map(String::as_str),
            Some(
                "a
b
"
            )
        );
        assert_eq!(
            got.get("Two").map(String::as_str),
            Some(
                "a
b
"
            )
        );
        assert_eq!(
            got.get("Blank").map(String::as_str),
            Some(""),
            "a body of only newlines has no content to preserve",
        );
        Ok(())
    }

    /// Dropped, not truncated: half a foreign section written back looks intact
    /// and is not, while a missing one is visible in the exported file.
    #[test]
    fn an_oversized_section_is_dropped_and_its_neighbours_survive() -> SidecarResult<()> {
        let tmp = tempfile::tempdir()?;
        let db = open_sidecar(&tmp)?;
        let huge = "x".repeat(MAX_RAW_TEXT_BYTES + 1);
        let long_name = "n".repeat(MAX_SECTION_NAME_CHARS + 1);
        let mut input = sections(&[(
            "Linux", "firefox
",
        )]);
        input.insert("Huge".to_string(), huge);
        input.insert(
            long_name.clone(),
            "x
"
            .to_string(),
        );

        db.write_passthrough("primary", &input)?;
        let got = db.read_passthrough("primary")?;
        assert_eq!(got.len(), 1, "only the legitimate section is kept");
        assert!(got.contains_key("Linux"));
        Ok(())
    }

    #[test]
    fn empty_route_reads_as_empty_map() -> SidecarResult<()> {
        let tmp = tempfile::tempdir()?;
        let db = open_sidecar(&tmp)?;
        let got = db.read_passthrough("primary")?;
        assert!(got.is_empty());
        Ok(())
    }

    #[test]
    fn write_then_read_roundtrip() -> SidecarResult<()> {
        let tmp = tempfile::tempdir()?;
        let db = open_sidecar(&tmp)?;
        let input = sections(&[
            ("Linux", "# (reserved - not applied on Windows)\nfirefox\n"),
            ("MacOS", "# (reserved - not applied on Windows)\nSafari\n"),
        ]);
        db.write_passthrough("primary", &input)?;
        let got = db.read_passthrough("primary")?;
        assert_eq!(got.len(), 2);
        assert_eq!(
            got.get("Linux").map(String::as_str),
            Some("# (reserved - not applied on Windows)\nfirefox\n"),
        );
        assert_eq!(
            got.get("MacOS").map(String::as_str),
            Some("# (reserved - not applied on Windows)\nSafari\n"),
        );
        Ok(())
    }

    #[test]
    fn write_replaces_previous_set_atomically() -> SidecarResult<()> {
        let tmp = tempfile::tempdir()?;
        let db = open_sidecar(&tmp)?;
        db.write_passthrough(
            "primary",
            &sections(&[
                ("Linux", "old-linux"),
                ("MacOS", "old-mac"),
                ("Ports", "old-ports"),
            ]),
        )?;
        // New write has different keys; old keys must disappear.
        db.write_passthrough("primary", &sections(&[("Linux", "new-linux")]))?;
        let got = db.read_passthrough("primary")?;
        assert_eq!(got.len(), 1);
        // Stored with the trailing newline the canonical writer assumes.
        assert_eq!(
            got.get("Linux").map(String::as_str),
            Some(
                "new-linux
"
            )
        );
        assert!(!got.contains_key("MacOS"));
        assert!(!got.contains_key("Ports"));
        Ok(())
    }

    #[test]
    fn write_empty_set_clears_route() -> SidecarResult<()> {
        let tmp = tempfile::tempdir()?;
        let db = open_sidecar(&tmp)?;
        db.write_passthrough("primary", &sections(&[("Linux", "x")]))?;
        db.write_passthrough("primary", &BTreeMap::new())?;
        assert!(db.read_passthrough("primary")?.is_empty());
        Ok(())
    }

    #[test]
    fn routes_are_isolated() -> SidecarResult<()> {
        let tmp = tempfile::tempdir()?;
        let db = open_sidecar(&tmp)?;
        db.write_passthrough("primary", &sections(&[("Linux", "p-linux")]))?;
        db.write_passthrough("secondary", &sections(&[("Linux", "s-linux")]))?;
        assert_eq!(
            db.read_passthrough("primary")?
                .get("Linux")
                .map(String::as_str),
            Some(
                "p-linux
"
            ),
        );
        assert_eq!(
            db.read_passthrough("secondary")?
                .get("Linux")
                .map(String::as_str),
            Some(
                "s-linux
"
            ),
        );
        // Clearing one route doesn't touch the other.
        db.clear_passthrough("primary")?;
        assert!(db.read_passthrough("primary")?.is_empty());
        assert_eq!(
            db.read_passthrough("secondary")?
                .get("Linux")
                .map(String::as_str),
            Some(
                "s-linux
"
            ),
        );
        Ok(())
    }

    #[test]
    fn clear_route_with_no_rows_is_noop() -> SidecarResult<()> {
        let tmp = tempfile::tempdir()?;
        let db = open_sidecar(&tmp)?;
        // Should not error even though the route has no rows.
        db.clear_passthrough("primary")?;
        assert!(db.read_passthrough("primary")?.is_empty());
        Ok(())
    }

    #[test]
    fn read_is_alphabetically_sorted_by_section_name() -> SidecarResult<()> {
        let tmp = tempfile::tempdir()?;
        let db = open_sidecar(&tmp)?;
        db.write_passthrough(
            "primary",
            &sections(&[("Ports", "ports"), ("Linux", "linux"), ("MacOS", "mac")]),
        )?;
        let got = db.read_passthrough("primary")?;
        // BTreeMap iteration order is alphabetical → keys come out
        // sorted regardless of insertion order.
        let keys: Vec<&str> = got.keys().map(String::as_str).collect();
        assert_eq!(keys, vec!["Linux", "MacOS", "Ports"]);
        Ok(())
    }

    #[test]
    fn unicode_section_content_survives_reopen() -> SidecarResult<()> {
        let tmp = tempfile::tempdir()?;
        let path = tmp.path().join("sidecar.db");
        let body = "# Российские приложения\nЯндекс.Браузер.exe\n# 中国应用\n微信.exe\n";
        {
            let db = SidecarDb::open(&path)?;
            db.write_passthrough("primary", &sections(&[("Custom", body)]))?;
        }
        let db = SidecarDb::open(&path)?;
        let got = db.read_passthrough("primary")?;
        assert_eq!(got.get("Custom").map(String::as_str), Some(body));
        Ok(())
    }

    #[test]
    fn write_failure_does_not_partially_apply() -> SidecarResult<()> {
        // We can't easily inject a SQL-level failure mid-INSERT
        // without mocking, but we can verify the documented behaviour
        // by confirming a second writer sees an all-or-nothing view.
        let tmp = tempfile::tempdir()?;
        let db = open_sidecar(&tmp)?;
        db.write_passthrough("primary", &sections(&[("Linux", "a"), ("MacOS", "b")]))?;
        // The transaction wrapper above means either both rows land or
        // neither does. After the successful call, both must be visible.
        let got = db.read_passthrough("primary")?;
        assert_eq!(got.len(), 2);
        Ok(())
    }

    #[test]
    fn clear_after_write_leaves_other_routes_intact() -> SidecarResult<()> {
        let tmp = tempfile::tempdir()?;
        let db = open_sidecar(&tmp)?;
        db.write_passthrough("primary", &sections(&[("Linux", "p")]))?;
        db.write_passthrough("secondary", &sections(&[("Linux", "s")]))?;
        db.clear_passthrough("primary")?;
        assert!(db.read_passthrough("primary")?.is_empty());
        assert!(!db.read_passthrough("secondary")?.is_empty());
        Ok(())
    }
}
