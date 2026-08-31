//! Out-of-band anchor for the audit tail.
//!
//! The hash chain proves that no event was EDITED, and proves nothing about
//! events that were REMOVED: deleting the last K lines leaves a shorter but
//! perfectly self-consistent chain, and the writer would then continue from
//! the shortened tail — the removal heals itself and leaves no trace. The
//! anchor is the one piece of state kept outside the NDJSON files, so the
//! service can tell "nothing was written since" from "the tail is gone".

use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Identifies the last audit event the writer knows it committed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditChainAnchor {
    /// File name (not path) the event was written to.
    pub file_name: String,
    /// Sequence number within that file.
    pub seq: u64,
    /// The event's `event_hash` — what the next event chains onto.
    pub event_hash: String,
}

/// What the anchor says about the tail on disk.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum AuditTailIntegrity {
    /// No anchor was available — nothing can be said either way.
    #[default]
    Unknown,
    /// The anchored event is present on disk with the anchored hash.
    Intact,
    /// The anchored event is missing or carries a different hash.
    Truncated {
        anchor_seq: u64,
        /// Highest sequence number still present in the anchored file, if any.
        found_seq: Option<u64>,
    },
}

impl AuditTailIntegrity {
    pub fn is_truncated(&self) -> bool {
        matches!(self, Self::Truncated { .. })
    }
}

/// Persists the anchor. Implementations must be cheap: this is written once
/// per audit event, and audit events are rare by construction.
pub trait AuditChainAnchorStore: Send + Sync {
    fn load(&self) -> Option<AuditChainAnchor>;
    fn save(&self, anchor: &AuditChainAnchor);
}

/// Anchor kept as a small JSON sidecar beside the audit files.
///
/// This detects accidental loss — retention deleting a live file, a partial
/// write, a truncated copy — and denies the writer the ability to heal a
/// shortened chain. It does NOT claim to stop an administrator who can write
/// to the audit directory: they can rewrite the sidecar as easily as the
/// NDJSON. Raising that bar means a second trust domain, which the service
/// does not have at the point the audit writer opens.
pub struct FileAnchorStore {
    path: PathBuf,
}

impl FileAnchorStore {
    pub const FILE_NAME: &'static str = "nrr_audit_anchor.json";

    pub fn in_dir(audit_dir: impl AsRef<Path>) -> Self {
        Self {
            path: audit_dir.as_ref().join(Self::FILE_NAME),
        }
    }
}

impl AuditChainAnchorStore for FileAnchorStore {
    fn load(&self) -> Option<AuditChainAnchor> {
        let raw = std::fs::read_to_string(&self.path).ok()?;
        serde_json::from_str(&raw).ok()
    }

    fn save(&self, anchor: &AuditChainAnchor) {
        let Ok(json) = serde_json::to_string(anchor) else {
            return;
        };
        // Write in place and fsync: a torn anchor reads as "unknown", which
        // is the same posture as having no anchor at all, and never as
        // "truncated" — a false tamper alarm is worse than a missed one.
        let tmp = self.path.with_extension("tmp");
        let written = std::fs::File::create(&tmp).and_then(|mut f| {
            f.write_all(json.as_bytes())?;
            f.sync_all()
        });
        if written.is_ok() {
            let _ = std::fs::rename(&tmp, &self.path);
        } else {
            let _ = std::fs::remove_file(&tmp);
        }
    }
}

/// Compares the anchor against what is on disk.
pub fn check_tail(audit_dir: &Path, anchor: Option<&AuditChainAnchor>) -> AuditTailIntegrity {
    let Some(anchor) = anchor else {
        return AuditTailIntegrity::Unknown;
    };
    let path = audit_dir.join(&anchor.file_name);
    let Ok(content) = std::fs::read_to_string(&path) else {
        return AuditTailIntegrity::Truncated {
            anchor_seq: anchor.seq,
            found_seq: None,
        };
    };

    let mut highest_seq = None;
    let mut anchored_hash_seen = false;
    for line in content.lines().filter(|l| !l.trim().is_empty()) {
        let Ok(event) = serde_json::from_str::<crate::event::AuditEvent>(line) else {
            continue;
        };
        highest_seq = Some(highest_seq.map_or(event.seq, |s: u64| s.max(event.seq)));
        if event.seq == anchor.seq && event.event_hash == anchor.event_hash {
            anchored_hash_seen = true;
        }
    }

    if anchored_hash_seen {
        AuditTailIntegrity::Intact
    } else {
        AuditTailIntegrity::Truncated {
            anchor_seq: anchor.seq,
            found_seq: highest_seq,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn anchor(seq: u64, hash: &str) -> AuditChainAnchor {
        AuditChainAnchor {
            file_name: "nrr_audit_20260830-1.ndjson".into(),
            seq,
            event_hash: hash.into(),
        }
    }

    #[test]
    fn a_saved_anchor_reads_back() {
        let dir = tempfile::tempdir().expect("temp");
        let store = FileAnchorStore::in_dir(dir.path());
        assert_eq!(store.load(), None);
        store.save(&anchor(7, "abc"));
        assert_eq!(store.load(), Some(anchor(7, "abc")));
    }

    #[test]
    fn a_missing_file_is_truncation_not_silence() {
        let dir = tempfile::tempdir().expect("temp");
        assert_eq!(
            check_tail(dir.path(), Some(&anchor(3, "abc"))),
            AuditTailIntegrity::Truncated {
                anchor_seq: 3,
                found_seq: None
            }
        );
    }

    #[test]
    fn without_an_anchor_nothing_is_claimed() {
        let dir = tempfile::tempdir().expect("temp");
        assert_eq!(check_tail(dir.path(), None), AuditTailIntegrity::Unknown);
    }
}
