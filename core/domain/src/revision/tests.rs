use super::*;

// ── RevisionId ────────────────────────────────────────────────────────────

#[test]
fn revision_id_accepts_valid_prefixed_string() {
    let id =
        RevisionId::from_prefixed_string("rev-550e8400-e29b-41d4-a716-446655440000".to_string());
    assert!(id.is_ok());
    let id = id.unwrap_or_else(|e| panic!("expected Ok: {e}"));
    assert_eq!(id.as_str(), "rev-550e8400-e29b-41d4-a716-446655440000");
    assert_eq!(id.uuid_part(), "550e8400-e29b-41d4-a716-446655440000");
}

#[test]
fn revision_id_rejects_missing_prefix() {
    assert!(
        RevisionId::from_prefixed_string("550e8400-e29b-41d4-a716-446655440000".to_string())
            .is_err()
    );
}

#[test]
fn revision_id_rejects_prefix_only() {
    assert!(RevisionId::from_prefixed_string("rev-".to_string()).is_err());
}

#[test]
fn revision_id_display_equals_full_string() {
    let id = RevisionId::from_prefixed_string("rev-abc-123".to_string())
        .unwrap_or_else(|e| panic!("expected Ok: {e}"));
    assert_eq!(id.to_string(), "rev-abc-123");
}

// ── ContentHash ───────────────────────────────────────────────────────────

#[test]
fn content_hash_roundtrip_via_hex() {
    let bytes = [0xabu8; 32];
    let hash = ContentHash::from_bytes(bytes);
    let hex = hash.to_hex_string();
    assert_eq!(hex.len(), 64);
    assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    let parsed =
        ContentHash::from_hex_string(&hex).unwrap_or_else(|e| panic!("hex roundtrip failed: {e}"));
    assert_eq!(hash, parsed);
}

#[test]
fn content_hash_rejects_wrong_length() {
    assert!(ContentHash::from_hex_string("ab").is_err());
    assert!(ContentHash::from_hex_string(&"ab".repeat(33)).is_err());
}

#[test]
fn content_hash_rejects_invalid_hex_chars() {
    let invalid = "zz".repeat(32);
    assert!(ContentHash::from_hex_string(&invalid).is_err());
}

#[test]
fn content_hash_accepts_uppercase_hex() {
    let upper = "AB".repeat(32);
    assert!(ContentHash::from_hex_string(&upper).is_ok());
}

#[test]
fn content_hash_all_zeros_is_valid() {
    let hash = ContentHash::from_bytes([0u8; 32]);
    assert_eq!(hash.to_hex_string(), "0".repeat(64));
}

// ── UnixTimestamp ─────────────────────────────────────────────────────────

#[test]
fn unix_timestamp_roundtrips() {
    let ts = UnixTimestamp::from_secs(1_700_000_000);
    assert_eq!(ts.as_secs(), 1_700_000_000);
    assert_eq!(ts.to_string(), "1700000000");
}

#[test]
fn unix_timestamp_ordering_is_chronological() {
    let earlier = UnixTimestamp::from_secs(100);
    let later = UnixTimestamp::from_secs(200);
    assert!(earlier < later);
}

// ── RiskLevel ─────────────────────────────────────────────────────────────

#[test]
fn risk_level_ordering_low_lt_medium_lt_high() {
    assert!(RiskLevel::Low < RiskLevel::Medium);
    assert!(RiskLevel::Medium < RiskLevel::High);
    assert!(RiskLevel::Low < RiskLevel::High);
}

#[test]
fn risk_level_display_is_lowercase_slug() {
    assert_eq!(RiskLevel::Low.to_string(), "low");
    assert_eq!(RiskLevel::Medium.to_string(), "medium");
    assert_eq!(RiskLevel::High.to_string(), "high");
}

#[test]
fn risk_level_equality_is_reflexive() {
    assert_eq!(RiskLevel::High, RiskLevel::High);
    assert_ne!(RiskLevel::Low, RiskLevel::High);
}

// ── RevisionSource ────────────────────────────────────────────────────────

#[test]
fn revision_source_direct_edit_and_file_sync_are_distinct() {
    assert_ne!(RevisionSource::DirectEdit, RevisionSource::FileSync);
}
