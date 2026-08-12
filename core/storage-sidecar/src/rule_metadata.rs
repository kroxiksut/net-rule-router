//! `rule_metadata` table — user-typed rule comments.
//!
//! Comments are GUI/file decoration only; the routing engine and the
//! service-side audit log are deliberately blind to them. They live in
//! the per-user sidecar so they can be displayed alongside snapshot
//! rules without crossing the IPC boundary.
//!
//! The table is sparse — rules without a comment have no row. This
//! keeps `gc_orphans` cheap on machines with many rules and few
//! comments and avoids surprising the user with an empty-string
//! comment when they never wrote one.

use std::collections::{BTreeMap, HashSet};
use std::time::SystemTime;

use rusqlite::{params, OptionalExtension};

use crate::db::SidecarDb;
use crate::error::SidecarResult;

/// Stable identifier for a rule, used as the primary key in
/// `rule_metadata`. Constructed by lowercasing the match value and
/// joining type/value/route with `|` so two rules with the same
/// routing intent collide on a single comment entry.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RuleSignature(pub String);

impl RuleSignature {
    /// Build a signature from the three rule identity axes.
    ///
    /// The match value is lowercased (case-insensitive for FQDNs and
    /// app filenames; IPv4 octets are unaffected). The `|` delimiter
    /// is safe because canonical rule values never contain it.
    pub fn build(rule_type: &str, match_value: &str, target_route: &str) -> Self {
        let mut s =
            String::with_capacity(rule_type.len() + match_value.len() + target_route.len() + 2);
        s.push_str(rule_type);
        s.push('|');
        for ch in match_value.chars() {
            for lower in ch.to_lowercase() {
                s.push(lower);
            }
        }
        s.push('|');
        s.push_str(target_route);
        Self(s)
    }

    /// Borrow the underlying string for SQL parameter binding.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Maximum comment length the sidecar accepts. Matches the canonical
/// txt one-line-per-rule format which has no hard limit but degrades
/// in usability past a screen-width of text.
pub const COMMENT_MAX_LEN: usize = 1024;

/// Strip characters that would break the one-line txt round-trip and
/// trim trailing whitespace. Preserves Unicode (Cyrillic / CJK / IDN
/// comments) and the tab character (used for column alignment in
/// some user-authored presets).
pub fn sanitize_comment(input: &str) -> String {
    let mut out = String::with_capacity(input.len().min(COMMENT_MAX_LEN));
    for ch in input.chars() {
        match ch {
            // Newline variants collapse to a single space so we never
            // ship a comment that breaks the one-line preset format.
            '\r' | '\n' => out.push(' '),
            // Tab survives — it's useful for alignment inside comments.
            '\t' => out.push('\t'),
            // Every other ASCII control byte is stripped silently.
            c if (c as u32) < 0x20 => continue,
            c => out.push(c),
        }
    }
    // Trim trailing whitespace and cap at the documented max length.
    let trimmed = out.trim_end().to_string();
    if trimmed.chars().count() <= COMMENT_MAX_LEN {
        trimmed
    } else {
        trimmed.chars().take(COMMENT_MAX_LEN).collect()
    }
}

impl SidecarDb {
    /// Read the comment for `signature`. `Ok(None)` when the rule has
    /// no recorded comment (which is the default — the table is sparse).
    pub fn read_comment(&self, signature: &RuleSignature) -> SidecarResult<Option<String>> {
        let conn = self.conn();
        let value: Option<String> = conn
            .query_row(
                "SELECT comment FROM rule_metadata WHERE rule_signature = ?1",
                params![signature.as_str()],
                |r| r.get(0),
            )
            .optional()?;
        // A stored empty string is treated as "no comment" — the GUI
        // never persists empty comments (they're meaningless), but a
        // legacy/edge import could; treating them as absent keeps
        // gc_orphans honest and avoids rendering empty hint rows.
        Ok(value.filter(|s| !s.is_empty()))
    }

    /// Persist `comment` for `signature`, replacing any previous value.
    /// The caller is expected to have sanitised the comment with
    /// [`sanitize_comment`] beforehand.
    ///
    /// Writing an empty string **deletes** the row — the table stays
    /// sparse and the GUI doesn't have to special-case "comment cleared"
    /// vs "comment never set" downstream.
    pub fn write_comment(&self, signature: &RuleSignature, comment: &str) -> SidecarResult<()> {
        if comment.is_empty() {
            return self.delete_comment(signature);
        }
        let now = unix_now_ms();
        let conn = self.conn_mut();
        // INSERT ... ON CONFLICT preserves `created_at` on the first
        // row so we can show "last edited" vs "first written" in a
        // future UI; the upsert path bumps only `updated_at`.
        conn.execute(
            "INSERT INTO rule_metadata (rule_signature, comment, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?3)
             ON CONFLICT(rule_signature) DO UPDATE SET
                 comment    = excluded.comment,
                 updated_at = excluded.updated_at",
            params![signature.as_str(), comment, now],
        )?;
        Ok(())
    }

    /// +4 — bulk read every stored comment as a
    /// `signature → text` map. The GUI calls this once after the
    /// snapshot bind and overlays the comments onto `rulesModel`
    /// rows; one RPC round-trip instead of N. Empty-string comments
    /// are filtered out (treated as absent, same as
    /// [`Self::read_comment`]).
    ///
    /// Returns a `BTreeMap` for deterministic iteration order — keeps
    /// integration test output stable; the GUI looks rows up by key.
    pub fn read_all_comments(&self) -> SidecarResult<BTreeMap<String, String>> {
        let conn = self.conn();
        let mut stmt = conn.prepare("SELECT rule_signature, comment FROM rule_metadata")?;
        let mut rows = stmt.query([])?;
        let mut out = BTreeMap::new();
        while let Some(row) = rows.next()? {
            let sig: String = row.get(0)?;
            let comment: String = row.get(1)?;
            if !comment.is_empty() {
                out.insert(sig, comment);
            }
        }
        Ok(out)
    }

    /// Remove the comment row for `signature`. No-op when the row was
    /// already absent.
    pub fn delete_comment(&self, signature: &RuleSignature) -> SidecarResult<()> {
        let conn = self.conn_mut();
        conn.execute(
            "DELETE FROM rule_metadata WHERE rule_signature = ?1",
            params![signature.as_str()],
        )?;
        Ok(())
    }

    /// Delete every comment whose signature is not in
    /// `active_signatures`. Returns the number of rows removed.
    ///
    /// Called once at GUI startup after `rulesModel` finishes loading
    /// from the service snapshot. The sweep is bounded by the number
    /// of rows actually in `rule_metadata` (almost always small) so we
    /// scan the table fully rather than building a parameterised
    /// `NOT IN (...)` query which has a SQLite parameter-count cap of
    /// 32766.
    pub fn gc_orphans(&self, active_signatures: &[RuleSignature]) -> SidecarResult<usize> {
        let active: HashSet<&str> = active_signatures.iter().map(|s| s.as_str()).collect();
        let mut conn = self.conn_mut();
        // Transaction requires &mut Connection; conn must remain `mut`.
        let tx = conn.transaction()?;
        // Collect the orphan signatures inside a scope so the
        // statement is dropped before the transaction is committed.
        let mut to_delete: Vec<String> = Vec::new();
        {
            let mut stmt = tx.prepare("SELECT rule_signature FROM rule_metadata")?;
            let mut rows = stmt.query([])?;
            while let Some(row) = rows.next()? {
                let sig: String = row.get(0)?;
                if !active.contains(sig.as_str()) {
                    to_delete.push(sig);
                }
            }
        }
        let removed = to_delete.len();
        if !to_delete.is_empty() {
            let mut delete_stmt =
                tx.prepare("DELETE FROM rule_metadata WHERE rule_signature = ?1")?;
            for sig in &to_delete {
                delete_stmt.execute(params![sig])?;
            }
        }
        tx.commit()?;
        Ok(removed)
    }
}

/// Current Unix epoch in milliseconds. A clock before the epoch yields
/// zero rather than panicking — the timestamps are informational only.
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

    #[test]
    fn signature_lowercases_match_value_only() {
        let sig = RuleSignature::build("zone", "Пример.РФ", "primary");
        assert_eq!(sig.as_str(), "zone|пример.рф|primary");
    }

    #[test]
    fn sanitize_replaces_newlines_with_space() {
        let out = sanitize_comment("line one\r\nline two");
        assert_eq!(out, "line one  line two");
    }

    #[test]
    fn sanitize_strips_control_chars_but_keeps_tab() {
        let out = sanitize_comment("a\x01b\tc\x1fd");
        assert_eq!(out, "ab\tcd");
    }

    #[test]
    fn sanitize_caps_length() {
        let input = "x".repeat(COMMENT_MAX_LEN + 100);
        let out = sanitize_comment(&input);
        assert_eq!(out.chars().count(), COMMENT_MAX_LEN);
    }

    #[test]
    fn sanitize_trims_trailing_whitespace() {
        assert_eq!(sanitize_comment("hello   "), "hello");
        assert_eq!(sanitize_comment("hello\n   "), "hello");
    }

    #[test]
    fn missing_comment_reads_as_none() -> SidecarResult<()> {
        let tmp = tempfile::tempdir()?;
        let db = open_sidecar(&tmp)?;
        let sig = RuleSignature::build("zone", "ru", "primary");
        assert!(db.read_comment(&sig)?.is_none());
        Ok(())
    }

    #[test]
    fn write_then_read_roundtrip() -> SidecarResult<()> {
        let tmp = tempfile::tempdir()?;
        let db = open_sidecar(&tmp)?;
        let sig = RuleSignature::build("zone", "рф", "primary");
        db.write_comment(&sig, "Россия — зона .рф (xn--p1ai)")?;
        let got = db.read_comment(&sig)?;
        assert_eq!(got.as_deref(), Some("Россия — зона .рф (xn--p1ai)"));
        Ok(())
    }

    #[test]
    fn write_overwrites_previous() -> SidecarResult<()> {
        let tmp = tempfile::tempdir()?;
        let db = open_sidecar(&tmp)?;
        let sig = RuleSignature::build("domain", "example.com", "primary");
        db.write_comment(&sig, "first")?;
        db.write_comment(&sig, "second")?;
        assert_eq!(db.read_comment(&sig)?.as_deref(), Some("second"));
        Ok(())
    }

    #[test]
    fn writing_empty_string_deletes_row() -> SidecarResult<()> {
        let tmp = tempfile::tempdir()?;
        let db = open_sidecar(&tmp)?;
        let sig = RuleSignature::build("domain", "example.com", "primary");
        db.write_comment(&sig, "x")?;
        db.write_comment(&sig, "")?;
        assert!(db.read_comment(&sig)?.is_none());
        Ok(())
    }

    #[test]
    fn explicit_delete_is_idempotent() -> SidecarResult<()> {
        let tmp = tempfile::tempdir()?;
        let db = open_sidecar(&tmp)?;
        let sig = RuleSignature::build("domain", "example.com", "primary");
        // Delete with no row present.
        db.delete_comment(&sig)?;
        // Write then delete then delete again.
        db.write_comment(&sig, "x")?;
        db.delete_comment(&sig)?;
        db.delete_comment(&sig)?;
        assert!(db.read_comment(&sig)?.is_none());
        Ok(())
    }

    #[test]
    fn read_all_returns_every_non_empty_row() -> SidecarResult<()> {
        let tmp = tempfile::tempdir()?;
        let db = open_sidecar(&tmp)?;
        let s1 = RuleSignature::build("zone", "ru", "primary");
        let s2 = RuleSignature::build("domain", "vk.com", "secondary");
        let s3 = RuleSignature::build("zone", "su", "primary");
        db.write_comment(&s1, "ru-comment")?;
        db.write_comment(&s2, "vk-comment")?;
        // s3 written then cleared — should not surface in read_all.
        db.write_comment(&s3, "doomed")?;
        db.write_comment(&s3, "")?;
        let all = db.read_all_comments()?;
        assert_eq!(all.len(), 2);
        assert_eq!(all.get(s1.as_str()).map(String::as_str), Some("ru-comment"));
        assert_eq!(all.get(s2.as_str()).map(String::as_str), Some("vk-comment"));
        assert!(!all.contains_key(s3.as_str()));
        Ok(())
    }

    #[test]
    fn read_all_is_empty_on_fresh_db() -> SidecarResult<()> {
        let tmp = tempfile::tempdir()?;
        let db = open_sidecar(&tmp)?;
        assert!(db.read_all_comments()?.is_empty());
        Ok(())
    }

    #[test]
    fn gc_orphans_removes_only_unlisted() -> SidecarResult<()> {
        let tmp = tempfile::tempdir()?;
        let db = open_sidecar(&tmp)?;
        let s1 = RuleSignature::build("zone", "ru", "primary");
        let s2 = RuleSignature::build("zone", "рф", "primary");
        let s3 = RuleSignature::build("domain", "vk.com", "primary");
        db.write_comment(&s1, "ru")?;
        db.write_comment(&s2, "rf")?;
        db.write_comment(&s3, "vk")?;
        // Keep s1 and s3, drop s2.
        let removed = db.gc_orphans(&[s1.clone(), s3.clone()])?;
        assert_eq!(removed, 1);
        assert!(db.read_comment(&s1)?.is_some());
        assert!(db.read_comment(&s2)?.is_none());
        assert!(db.read_comment(&s3)?.is_some());
        Ok(())
    }

    #[test]
    fn gc_orphans_with_empty_keep_set_clears_all() -> SidecarResult<()> {
        let tmp = tempfile::tempdir()?;
        let db = open_sidecar(&tmp)?;
        let s1 = RuleSignature::build("zone", "ru", "primary");
        let s2 = RuleSignature::build("zone", "рф", "primary");
        db.write_comment(&s1, "a")?;
        db.write_comment(&s2, "b")?;
        let removed = db.gc_orphans(&[])?;
        assert_eq!(removed, 2);
        assert!(db.read_comment(&s1)?.is_none());
        assert!(db.read_comment(&s2)?.is_none());
        Ok(())
    }

    #[test]
    fn gc_orphans_with_no_orphans_returns_zero() -> SidecarResult<()> {
        let tmp = tempfile::tempdir()?;
        let db = open_sidecar(&tmp)?;
        let s1 = RuleSignature::build("zone", "ru", "primary");
        db.write_comment(&s1, "a")?;
        let removed = db.gc_orphans(&[s1])?;
        assert_eq!(removed, 0);
        Ok(())
    }

    #[test]
    fn writing_unicode_persists_through_reopen() -> SidecarResult<()> {
        let tmp = tempfile::tempdir()?;
        let path = tmp.path().join("sidecar.db");
        let sig = RuleSignature::build("zone", "рф", "primary");
        {
            let db = SidecarDb::open(&path)?;
            db.write_comment(&sig, "中国 / 中國 / РФ")?;
        }
        let db = SidecarDb::open(&path)?;
        assert_eq!(db.read_comment(&sig)?.as_deref(), Some("中国 / 中國 / РФ"));
        Ok(())
    }

    #[test]
    fn empty_table_read_returns_none() -> SidecarResult<()> {
        let tmp = tempfile::tempdir()?;
        let db = open_sidecar(&tmp)?;
        let sig = RuleSignature::build("domain", "absent.example", "secondary");
        assert!(db.read_comment(&sig)?.is_none());
        Ok(())
    }
}
