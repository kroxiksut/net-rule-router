//! Restarting a broken audit chain.
//!
//! The verifier checks the whole retention window, so one old break would keep
//! the trail reported as broken until its file ages out. An administrator who
//! has seen the breaks can restart the chain instead: the service appends an
//! `audit_chain_restarted` event naming what it papers over, and verification
//! starts again from the last such event.
//!
//! Whoever can write the audit directory can also compute SHA-256, so the
//! chain hash cannot tell the service's restart from a forged one. A restart
//! therefore carries a seal, an HMAC under a key only the service holds, and
//! counts only when the seal verifies AND the event links onto the event right
//! before it — a genuine restart copied to another position does not.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::audit::kind::AuditEventKind;
use crate::error::{DiagnosticsError, DiagnosticsResult};
use crate::event::AuditEvent;

type HmacSha256 = Hmac<Sha256>;

/// Domain separation: a seal must never double as a row signature.
const KEY_LABEL: &[u8] = b"nrr-audit-chain-restart-v1";

/// How many breaks a verification lists; the digest covers all of them.
pub const LISTED_BREAKS: usize = 32;

/// The key a chain restart is sealed with, derived from the service's
/// integrity key.
///
/// A new integrity key voids every earlier seal, so a break an old restart
/// covered is reported again until the chain is restarted under the new key.
#[derive(Clone)]
pub struct AuditRestartKey([u8; 32]);

impl AuditRestartKey {
    pub fn derive(integrity_key: &[u8]) -> Option<Self> {
        if integrity_key.is_empty() {
            return None;
        }
        let mut mac = HmacSha256::new_from_slice(integrity_key).ok()?;
        mac.update(KEY_LABEL);
        Some(Self(mac.finalize().into_bytes().into()))
    }

    fn mac_over(&self, bytes: &str) -> Option<HmacSha256> {
        let mut mac = HmacSha256::new_from_slice(&self.0).ok()?;
        mac.update(bytes.as_bytes());
        Some(mac)
    }

    fn seal(&self, bytes: &str) -> Option<String> {
        let tag = self.mac_over(bytes)?.finalize().into_bytes();
        Some(tag.iter().map(|b| format!("{b:02x}")).collect())
    }

    fn verifies(&self, bytes: &str, seal_hex: &str) -> bool {
        match (self.mac_over(bytes), decode_hex(seal_hex)) {
            (Some(mac), Some(tag)) => mac.verify_slice(&tag).is_ok(),
            _ => false,
        }
    }
}

impl std::fmt::Debug for AuditRestartKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuditRestartKey(<redacted>)")
    }
}

fn decode_hex(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(hex.get(i..i + 2)?, 16).ok())
        .collect()
}

/// What a seal covers: the whole event with neither seal nor hash.
fn unsealed_bytes(event: &AuditEvent) -> Option<String> {
    let mut bare = event.clone();
    bare.seal = None;
    bare.event_hash = String::new();
    serde_json::to_string(&bare).ok()
}

/// Seals `event`; its `event_hash` is computed afterwards, over the seal too.
pub(crate) fn seal_event(event: &mut AuditEvent, key: &AuditRestartKey) -> DiagnosticsResult<()> {
    let seal = unsealed_bytes(event)
        .and_then(|bytes| key.seal(&bytes))
        .ok_or_else(|| DiagnosticsError::AuditWriteFailed {
            reason: "cannot seal the chain restart".to_string(),
        })?;
    event.seal = Some(seal);
    Ok(())
}

/// Whether `event` is a restart sealed with `key`. Where it sits in the chain
/// is the caller's half of the check.
pub(crate) fn is_sealed_restart(event: &AuditEvent, key: Option<&AuditRestartKey>) -> bool {
    let (Some(key), Some(seal)) = (key, event.seal.as_deref()) else {
        return false;
    };
    event.kind == AuditEventKind::AuditChainRestarted.as_str()
        && unsealed_bytes(event).is_some_and(|bytes| key.verifies(&bytes, seal))
}

// ── Breaks ───────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditChainBreakKind {
    /// An event does not hash to what it stores.
    HashMismatch,
    /// A file does not continue from the one before it.
    Seam,
    /// A line is not an event at all.
    CorruptLine,
    UnreadableFile,
    /// The anchored last event is gone.
    TailTruncated,
}

impl AuditChainBreakKind {
    pub fn slug(self) -> &'static str {
        match self {
            Self::HashMismatch => "hash-mismatch",
            Self::Seam => "seam",
            Self::CorruptLine => "corrupt-line",
            Self::UnreadableFile => "unreadable-file",
            Self::TailTruncated => "tail-truncated",
        }
    }

    /// Whether the break is in the chain itself rather than in a line that
    /// never was an event.
    pub fn breaks_hashes(self) -> bool {
        matches!(self, Self::HashMismatch | Self::Seam)
    }
}

/// One place the chain does not verify.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditChainBreak {
    pub kind: AuditChainBreakKind,
    pub file_name: String,
    /// 1-based line in the file; 0 when the break is not a line.
    pub line: usize,
    pub seq: Option<u64>,
    pub expected_hash: Option<String>,
    /// What is there instead: the stored hash, or a corrupt line's own hash.
    pub actual_hash: Option<String>,
}

impl AuditChainBreak {
    pub(crate) fn corrupt_line(file_name: &str, line: usize, raw: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(raw.as_bytes());
        Self {
            kind: AuditChainBreakKind::CorruptLine,
            file_name: file_name.to_string(),
            line,
            seq: None,
            expected_hash: None,
            actual_hash: Some(format!("{:x}", hasher.finalize())),
        }
    }

    pub(crate) fn unreadable(file_name: &str) -> Self {
        Self {
            kind: AuditChainBreakKind::UnreadableFile,
            file_name: file_name.to_string(),
            line: 0,
            seq: None,
            expected_hash: None,
            actual_hash: None,
        }
    }

    /// Everything that identifies the break, hashes included: the same event
    /// edited a second time is a different break.
    fn record(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}|{}\n",
            self.kind.slug(),
            self.file_name,
            self.line,
            self.seq.map(|s| s.to_string()).unwrap_or_default(),
            self.expected_hash.as_deref().unwrap_or_default(),
            self.actual_hash.as_deref().unwrap_or_default(),
        )
    }
}

/// Breaks in chain order: the first [`LISTED_BREAKS`] kept, all of them
/// counted and digested, so a large corrupt file costs no memory.
#[derive(Clone, Default)]
pub(crate) struct BreakLog {
    pub listed: Vec<AuditChainBreak>,
    pub count: usize,
    digest: Sha256,
}

impl BreakLog {
    pub fn push(&mut self, found: AuditChainBreak) {
        self.digest.update(found.record().as_bytes());
        self.count += 1;
        if self.listed.len() < LISTED_BREAKS {
            self.listed.push(found);
        }
    }

    /// Appends another log's breaks after this one's.
    pub fn absorb(&mut self, other: &BreakLog) {
        if other.count == 0 {
            return;
        }
        self.digest
            .update(format!("{}:{}\n", other.count, other.fingerprint()).as_bytes());
        self.count += other.count;
        let room = LISTED_BREAKS.saturating_sub(self.listed.len());
        self.listed.extend(other.listed.iter().take(room).cloned());
    }

    pub fn fingerprint(&self) -> String {
        format!("{:x}", self.digest.clone().finalize())
    }
}

// ── Restart request ──────────────────────────────────────────────────────────

/// Who restarts the chain, and the event id and time to record.
pub struct AuditChainRestartRequest {
    pub event_id: String,
    pub created_at: i64,
    /// The acknowledging administrator, hashed.
    pub actor_id_hash: Option<String>,
}

#[derive(Debug)]
pub enum AuditChainRestartError {
    /// Nothing is broken, so there is nothing to restart over.
    Intact,
    /// The breaks differ from the ones the administrator was shown.
    ChangedSinceShown,
    Write(DiagnosticsError),
}

impl std::fmt::Display for AuditChainRestartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Intact => f.write_str("the audit chain is intact"),
            Self::ChangedSinceShown => {
                f.write_str("the audit chain breaks changed since they were shown")
            }
            Self::Write(e) => write!(f, "{e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_seal_verifies_only_under_its_own_key() {
        let key = AuditRestartKey::derive(b"service key").expect("key");
        let other = AuditRestartKey::derive(b"another key").expect("key");
        let seal = key.seal("event").expect("seal");
        assert!(key.verifies("event", &seal));
        assert!(!other.verifies("event", &seal));
        assert!(!key.verifies("edited", &seal));
        assert!(!key.verifies("event", "not hex"));
    }

    #[test]
    fn no_key_is_derived_from_an_empty_one() {
        assert!(AuditRestartKey::derive(&[]).is_none());
    }

    #[test]
    fn the_key_never_prints() {
        let key = AuditRestartKey::derive(b"service key").expect("key");
        assert_eq!(format!("{key:?}"), "AuditRestartKey(<redacted>)");
    }

    #[test]
    fn the_digest_covers_breaks_past_the_listed_ones() {
        let mut a = BreakLog::default();
        let mut b = BreakLog::default();
        for line in 0..LISTED_BREAKS + 5 {
            a.push(AuditChainBreak::corrupt_line("f", line, "x"));
            b.push(AuditChainBreak::corrupt_line("f", line, "x"));
        }
        assert_eq!(a.listed.len(), LISTED_BREAKS);
        assert_eq!(a.fingerprint(), b.fingerprint());
        b.push(AuditChainBreak::corrupt_line("f", 999, "x"));
        assert_ne!(a.fingerprint(), b.fingerprint());
    }
}
