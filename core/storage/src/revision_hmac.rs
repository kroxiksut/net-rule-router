//! HMAC-SHA256 over canonical revisions-row content for tamper detection.
//!
//! ## Threat model
//!
//! Detects external mutation of the state DB rows in `revisions`:
//! an admin (or a rogue process running with sufficient privilege)
//! opening the SQLite file directly and writing a tampered
//! `rules_json` (or any other column) outside the service's own
//! write paths. The HMAC key lives in DPAPI-protected per-user
//! storage owned by `LocalSystem`; without that key the attacker
//! cannot forge a matching `row_hmac`, so the next read by the
//! service surfaces the mismatch.
//!
//! Does NOT defend against:
//!
//! - **Local admin running `psexec -s`** to impersonate LocalSystem
//!   and decrypt the DPAPI blob. That's an explicit non-goal — the
//!   spec accepts this compromise to keep the key file inaccessible
//!   to ordinary admin tools that don't elevate to LocalSystem.
//! - **In-process tampering.** The HMAC is computed and stored by
//!   the same process that would tamper; the protection is for
//!   external mutation only.
//!
//! ## Algorithm
//!
//! Each row's HMAC input is a deterministic concatenation of every
//! field (except `row_hmac` itself — would be recursive). Fields
//! are fed into the HMAC in alphabetical order, length-prefixed so
//! `a + b` cannot collide with `aa + b'`. NULLs are encoded as a
//! single tag byte distinct from the present tag, so distinguishing
//! `superseded_by = NULL` from `superseded_by = ""` is preserved.
//!
//! ## Wire compatibility
//!
//! The HMAC is consumer-side only — never crosses the IPC boundary.
//! GUI never sees `row_hmac`. The verification status is surfaced
//! to service-runtime callers via the `HmacVerification` enum,
//! which feeds the `SecurityAlert` emitter.

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Length of an HMAC-SHA256 output in bytes. Stored verbatim in the
/// `row_hmac` BLOB column. Constant rather than relying on
/// `<HmacSha256 as Mac>::OutputSize` so callers can size buffers
/// statically.
pub const HMAC_BYTE_LEN: usize = 32;

/// Recommended HMAC key length. Equal to the SHA-256 block size —
/// shorter keys are accepted by HMAC (zero-padded internally) but
/// using 32 bytes maximises entropy at the cost of nothing.
pub const RECOMMENDED_KEY_BYTE_LEN: usize = 32;

/// One row's worth of HMAC input — every column of `revisions`
/// except `row_hmac` itself. Borrowed strings to avoid allocations
/// on the read path (HMAC computation is on every load).
#[derive(Clone, Debug)]
pub struct RowFields<'a> {
    /// The per-principal partition key (Windows SID or the baseline
    /// sentinel). Included in the HMAC so a row cannot be re-homed to a
    /// different principal without invalidating the tag.
    pub principal: &'a str,
    pub revision_id: &'a str,
    pub content_hash: &'a str,
    pub rules_json: &'a str,
    pub status: &'a str,
    pub source: &'a str,
    pub correlation_id: &'a str,
    pub created_at: i64,
    pub activated_at: Option<i64>,
    pub superseded_at: Option<i64>,
    pub superseded_by: Option<&'a str>,
    pub rejected_reason: Option<&'a str>,
    pub review_summary_json: Option<&'a str>,
    pub risk_level: Option<&'a str>,
}

/// Outcome of comparing a stored HMAC with one we just recomputed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HmacVerification {
    /// Stored HMAC matches the recomputed value byte-for-byte. Row
    /// is intact.
    Verified,
    /// Stored HMAC is the empty blob. The row predates the
    /// `row_hmac` column (lazy backfill from the v10→v11 migration)
    /// or was inserted by a path that didn't carry a key. The
    /// service-runtime caller decides whether to surface an alert.
    Unsigned,
    /// Stored HMAC is non-empty but doesn't match. Either the row
    /// was tampered with externally OR the key has been rotated
    /// without re-signing. Both cases surface as
    /// `SecurityAlert::DbTamperDetected`.
    Tampered,
}

/// Compute the HMAC for `row` using `key`. Returns 32 raw bytes
/// suitable for direct comparison against the `row_hmac` BLOB
/// column. The computation is deterministic — repeated calls with
/// the same inputs always produce the same output.
pub fn compute_hmac(row: &RowFields<'_>, key: &[u8]) -> [u8; HMAC_BYTE_LEN] {
    // `Mac::new_from_slice` never fails for `Hmac<Sha256>` — it
    // accepts arbitrary key lengths (HMAC pads / hashes oversize
    // keys internally). The `expect` covers a theoretical future
    // breaking change to the crate.
    #[allow(clippy::expect_used)]
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");

    // Feed every field. Order is alphabetical by column name — see
    // module doc-comment for the canonical-form rationale. Each
    // `feed_field` call writes a length-prefixed label and value
    // so adjacent fields cannot collide.
    feed_field_i64_opt(&mut mac, b"activated_at", row.activated_at);
    feed_field_bytes(&mut mac, b"content_hash", row.content_hash.as_bytes());
    feed_field_bytes(&mut mac, b"correlation_id", row.correlation_id.as_bytes());
    feed_field_i64(&mut mac, b"created_at", row.created_at);
    feed_field_bytes(&mut mac, b"principal", row.principal.as_bytes());
    feed_field_str_opt(&mut mac, b"rejected_reason", row.rejected_reason);
    feed_field_str_opt(&mut mac, b"review_summary_json", row.review_summary_json);
    feed_field_bytes(&mut mac, b"revision_id", row.revision_id.as_bytes());
    feed_field_str_opt(&mut mac, b"risk_level", row.risk_level);
    feed_field_bytes(&mut mac, b"rules_json", row.rules_json.as_bytes());
    feed_field_bytes(&mut mac, b"source", row.source.as_bytes());
    feed_field_bytes(&mut mac, b"status", row.status.as_bytes());
    feed_field_i64_opt(&mut mac, b"superseded_at", row.superseded_at);
    feed_field_str_opt(&mut mac, b"superseded_by", row.superseded_by);

    let mut out = [0u8; HMAC_BYTE_LEN];
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

/// Verify a `stored_hmac` blob against the row's recomputed HMAC
/// using `key`. Empty blob → [`HmacVerification::Unsigned`]; any
/// other length-mismatching blob is treated as tampered (the
/// column is NOT NULL but technically could carry truncated data).
pub fn verify(row: &RowFields<'_>, stored_hmac: &[u8], key: &[u8]) -> HmacVerification {
    if stored_hmac.is_empty() {
        return HmacVerification::Unsigned;
    }
    let expected = compute_hmac(row, key);
    // Constant-time comparison via `subtle` would be the textbook
    // move; for tamper-DETECTION (not authentication of an
    // attacker-supplied tag) ordinary equality is fine — the
    // attacker doesn't get a timing oracle into the cached HMAC.
    if stored_hmac.len() == expected.len() && stored_hmac == expected.as_slice() {
        HmacVerification::Verified
    } else {
        HmacVerification::Tampered
    }
}

// ── helpers ─────────────────────────────────────────────────────────────

fn feed_label(mac: &mut HmacSha256, label: &[u8]) {
    let len = (label.len() as u64).to_be_bytes();
    mac.update(&len);
    mac.update(label);
}

fn feed_field_bytes(mac: &mut HmacSha256, label: &[u8], value: &[u8]) {
    feed_label(mac, label);
    mac.update(&[1u8]); // present marker
    let len = (value.len() as u64).to_be_bytes();
    mac.update(&len);
    mac.update(value);
}

fn feed_field_str_opt(mac: &mut HmacSha256, label: &[u8], value: Option<&str>) {
    feed_label(mac, label);
    match value {
        Some(v) => {
            mac.update(&[1u8]); // present
            let bytes = v.as_bytes();
            let len = (bytes.len() as u64).to_be_bytes();
            mac.update(&len);
            mac.update(bytes);
        }
        None => {
            mac.update(&[0u8]); // null
        }
    }
}

fn feed_field_i64(mac: &mut HmacSha256, label: &[u8], value: i64) {
    feed_label(mac, label);
    mac.update(&[1u8]);
    let bytes = value.to_be_bytes();
    // 8 bytes is the fixed wire size — length prefix is implicit.
    mac.update(&bytes);
}

fn feed_field_i64_opt(mac: &mut HmacSha256, label: &[u8], value: Option<i64>) {
    feed_label(mac, label);
    match value {
        Some(v) => {
            mac.update(&[1u8]);
            mac.update(&v.to_be_bytes());
        }
        None => {
            mac.update(&[0u8]);
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn sample_row() -> RowFields<'static> {
        RowFields {
            principal: "__baseline__",
            revision_id: "rev-001",
            content_hash: "deadbeef",
            rules_json: r#"{"schema-version":1}"#,
            status: "candidate",
            source: "gui-rules-edit",
            correlation_id: "corr-1",
            created_at: 1_700_000_000,
            activated_at: None,
            superseded_at: None,
            superseded_by: None,
            rejected_reason: None,
            review_summary_json: Some(r#"{"risk":"low"}"#),
            risk_level: Some("low"),
        }
    }

    #[test]
    fn hmac_is_deterministic() {
        let key = [0x42u8; 32];
        let h1 = compute_hmac(&sample_row(), &key);
        let h2 = compute_hmac(&sample_row(), &key);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 32);
    }

    #[test]
    fn different_keys_produce_different_hmacs() {
        let key_a = [0x42u8; 32];
        let key_b = [0x43u8; 32];
        assert_ne!(
            compute_hmac(&sample_row(), &key_a),
            compute_hmac(&sample_row(), &key_b)
        );
    }

    #[test]
    fn tampering_any_field_changes_the_hmac() {
        let key = [0x42u8; 32];
        let h0 = compute_hmac(&sample_row(), &key);

        let mut r = sample_row();
        r.rules_json = r#"{"schema-version":2}"#;
        let h_rules = compute_hmac(&r, &key);
        assert_ne!(h0, h_rules, "rules_json edit must change HMAC");

        let mut r = sample_row();
        r.status = "active";
        let h_status = compute_hmac(&r, &key);
        assert_ne!(h0, h_status, "status edit must change HMAC");

        let mut r = sample_row();
        r.created_at = 1_700_000_001;
        let h_time = compute_hmac(&r, &key);
        assert_ne!(h0, h_time, "created_at edit must change HMAC");

        let mut r = sample_row();
        r.activated_at = Some(1_700_000_500);
        let h_act = compute_hmac(&r, &key);
        assert_ne!(h0, h_act, "activated_at None→Some must change HMAC");

        let mut r = sample_row();
        r.principal = "S-1-5-21-1-2-3-1001";
        let h_principal = compute_hmac(&r, &key);
        assert_ne!(
            h0, h_principal,
            "principal re-homing must change HMAC (block 16.19.1)"
        );
    }

    #[test]
    fn empty_vs_null_optionals_differ() {
        let key = [0x42u8; 32];
        let mut r_empty = sample_row();
        r_empty.superseded_by = Some("");
        let mut r_null = sample_row();
        r_null.superseded_by = None;
        // "" is a present-but-empty value; None encodes the null marker.
        // The HMACs MUST differ because the SQL row carries different
        // semantics (existence of a value vs absence).
        assert_ne!(compute_hmac(&r_empty, &key), compute_hmac(&r_null, &key));
    }

    #[test]
    fn adjacent_fields_cannot_collide() {
        // Pathological case: shuffle value bytes between adjacent
        // fields. Length-prefixing guards against a row where
        // status="ab" + source="cd" hashing the same as
        // status="abcd" + source="" (without prefixing).
        let key = [0x42u8; 32];
        let mut a = sample_row();
        a.status = "ab";
        a.source = "cd";
        let mut b = sample_row();
        b.status = "abcd";
        b.source = "";
        assert_ne!(compute_hmac(&a, &key), compute_hmac(&b, &key));
    }

    #[test]
    fn verify_known_good() {
        let key = [0x42u8; 32];
        let h = compute_hmac(&sample_row(), &key);
        assert_eq!(verify(&sample_row(), &h, &key), HmacVerification::Verified);
    }

    #[test]
    fn verify_empty_blob_is_unsigned() {
        let key = [0x42u8; 32];
        assert_eq!(verify(&sample_row(), &[], &key), HmacVerification::Unsigned);
    }

    #[test]
    fn verify_wrong_hmac_is_tampered() {
        let key = [0x42u8; 32];
        let bogus = [0u8; 32];
        assert_eq!(
            verify(&sample_row(), &bogus, &key),
            HmacVerification::Tampered
        );
    }

    #[test]
    fn verify_truncated_hmac_is_tampered() {
        let key = [0x42u8; 32];
        let truncated = [0x42u8; 31];
        assert_eq!(
            verify(&sample_row(), &truncated, &key),
            HmacVerification::Tampered
        );
    }

    #[test]
    fn verify_with_wrong_key_is_tampered() {
        let key_signed = [0x42u8; 32];
        let key_verifier = [0x43u8; 32];
        let h = compute_hmac(&sample_row(), &key_signed);
        assert_eq!(
            verify(&sample_row(), &h, &key_verifier),
            HmacVerification::Tampered
        );
    }
}
