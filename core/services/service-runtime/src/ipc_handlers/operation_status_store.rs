//! In-memory tracker for asynchronous operations spawned by mutating
//! IPC handlers. The client receives an `operation_id` from
//! `MutationSubmit` (confirm) or `RollbackRequest` and polls
//! `OperationStatusGet` until the operation reaches a terminal state.
//!
//! Mutations execute synchronously inside the handler call,
//! so the operation reaches `Completed` (or `Failed`) before the
//! response is even returned to the client. The store is still used
//! end-to-end so:
//!
//! 1. The wire contract is ready for when mutations move
//!    to a worker thread and *do* spend time in `Queued`/`Running`.
//! 2. The client's poll loop shape matches what production will look
//!    like — a single poll round-trips through the store.
//!
//! Completed entries are retained for a fixed window
//! ([`DEFAULT_OPERATION_RETENTION`]) so a slow client still sees the
//! result. After the window the entry is GCed.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// Spec-mandated retention window for completed operations.
pub const DEFAULT_OPERATION_RETENTION: Duration = Duration::from_secs(5 * 60);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OperationState {
    Queued,
    Running,
    Completed,
    Failed,
}

impl OperationState {
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }

    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed)
    }
}

#[derive(Clone, Debug)]
pub struct OperationRecord {
    pub state: OperationState,
    pub progress_hint: Option<f32>,
    /// Set when `state == Completed`. Mutation-specific JSON.
    pub result: Option<serde_json::Value>,
    /// Set when `state == Failed`. Wire-friendly error.
    pub error: Option<OperationError>,
    /// When this record becomes eligible for GC. For non-terminal
    /// states, this is `None` (records hang around until a terminal
    /// transition resets the timer).
    pub retain_until: Option<Instant>,
    /// Who submitted the operation, in stored form. The result of a mutation
    /// belongs to the principal who asked for it: the pipe admits every
    /// authenticated local process, so without this an id is the only thing
    /// between one user and another user's mutation result.
    pub owner: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct OperationError {
    /// Slug recognisable by the GUI's i18n layer
    /// (e.g. `"mutation.rejected.policy-degraded"`).
    pub code: String,
    /// English operator-facing message.
    pub message: String,
}

/// Who owns an operation submitted through `ctx`, in stored form. `None` when
/// the transport could not attribute the caller.
#[must_use]
pub fn owner_of(ctx: &crate::ipc::IpcRequestContext) -> Option<String> {
    let stored = ctx.caller_stored();
    (!stored.is_empty()).then(|| stored.to_string())
}

#[derive(Default)]
pub struct OperationStatusStore {
    inner: Mutex<HashMap<String, OperationRecord>>,
}

static OPERATION_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Operation ids name a record that carries the RESULT of somebody's mutation,
/// so they must not be enumerable. The old suffix was
/// `Instant::now().elapsed()`, which is a few nanoseconds by construction —
/// the id was the counter and nothing else. The counter stays as the ordering
/// aid it always was; the randomness is what makes the id unguessable.
///
/// A failed draw falls back to the clock: an operation whose status cannot be
/// reported at all is worse than an id that is merely hard to guess, and the
/// record is owner-checked on read regardless.
fn next_operation_id() -> String {
    let n = OPERATION_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut bytes = [0u8; 8];
    let suffix: String = match getrandom::fill(&mut bytes) {
        Ok(()) => bytes.iter().map(|b| format!("{b:02x}")).collect(),
        Err(_) => format!(
            "{:016x}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0)
        ),
    };
    format!("op-{n:016x}{suffix}")
}

// State is `Mutex`-guarded; `lock().expect(...)` propagates poisoning (a prior
// panic) — deliberate, not a recoverable error.
#[allow(clippy::unwrap_used, clippy::expect_used)]
impl OperationStatusStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Reserve an operation id owned by `owner` and stash an initial `Queued`
    /// record. `None` means the transport could not attribute the caller; such
    /// a record is readable by nobody, which is the safe reading of "we do not
    /// know whose this is".
    pub fn enqueue_for(&self, owner: Option<String>) -> String {
        let id = next_operation_id();
        let mut g = self.inner.lock().expect("op store mutex poisoned");
        g.insert(
            id.clone(),
            OperationRecord {
                state: OperationState::Queued,
                progress_hint: None,
                result: None,
                error: None,
                retain_until: None,
                owner,
            },
        );
        id
    }

    /// Mark `op_id` as `Completed` with `result`. Sets a retention
    /// deadline of `now + DEFAULT_OPERATION_RETENTION`.
    pub fn complete(&self, op_id: &str, result: serde_json::Value, now: Instant) {
        let mut g = self.inner.lock().expect("op store mutex poisoned");
        if let Some(rec) = g.get_mut(op_id) {
            rec.state = OperationState::Completed;
            rec.result = Some(result);
            rec.error = None;
            rec.progress_hint = Some(1.0);
            rec.retain_until = Some(now + DEFAULT_OPERATION_RETENTION);
        }
    }

    /// Mark `op_id` as `Failed`.
    pub fn fail(&self, op_id: &str, error: OperationError, now: Instant) {
        let mut g = self.inner.lock().expect("op store mutex poisoned");
        if let Some(rec) = g.get_mut(op_id) {
            rec.state = OperationState::Failed;
            rec.error = Some(error);
            rec.result = None;
            rec.retain_until = Some(now + DEFAULT_OPERATION_RETENTION);
        }
    }

    /// Read the current snapshot of an operation. Returns `None` when
    /// the id has never been issued, or when its retention window has
    /// elapsed and a GC pass has dropped it.
    pub fn get(&self, op_id: &str) -> Option<OperationRecord> {
        self.inner
            .lock()
            .expect("op store mutex poisoned")
            .get(op_id)
            .cloned()
    }

    /// Read a record on behalf of `requester`. A record belonging to somebody
    /// else answers exactly like one that never existed — telling the caller
    /// "exists, not yours" would confirm the id for a guesser.
    pub fn get_for(&self, op_id: &str, requester: &str) -> Option<OperationRecord> {
        let rec = self.get(op_id)?;
        match rec.owner.as_deref() {
            Some(owner) if owner == requester && !requester.is_empty() => Some(rec),
            _ => None,
        }
    }

    /// Drop entries whose retention window has elapsed.
    pub fn gc_expired(&self, now: Instant) -> usize {
        let mut g = self.inner.lock().expect("op store mutex poisoned");
        let before = g.len();
        g.retain(|_, rec| match rec.retain_until {
            Some(deadline) => now < deadline,
            None => true,
        });
        before - g.len()
    }

    pub fn len(&self) -> usize {
        self.inner.lock().expect("op store mutex poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enqueue_returns_unique_ids_in_queued_state() {
        let s = OperationStatusStore::new();
        let id1 = s.enqueue_for(Some("S-1-5-21-owner".to_string()));
        let id2 = s.enqueue_for(Some("S-1-5-21-owner".to_string()));
        assert_ne!(id1, id2);
        assert_eq!(s.get(&id1).unwrap().state, OperationState::Queued);
    }

    #[test]
    fn complete_sets_result_and_terminal_state() {
        let s = OperationStatusStore::new();
        let id = s.enqueue_for(Some("S-1-5-21-owner".to_string()));
        s.complete(&id, serde_json::json!({ "ok": true }), Instant::now());
        let rec = s.get(&id).unwrap();
        assert_eq!(rec.state, OperationState::Completed);
        assert!(rec.state.is_terminal());
        assert_eq!(rec.result.unwrap()["ok"], true);
        assert!(rec.error.is_none());
    }

    #[test]
    fn fail_sets_error_and_terminal_state() {
        let s = OperationStatusStore::new();
        let id = s.enqueue_for(Some("S-1-5-21-owner".to_string()));
        s.fail(
            &id,
            OperationError {
                code: "mutation.rejected.policy-degraded".into(),
                message: "service is degraded".into(),
            },
            Instant::now(),
        );
        let rec = s.get(&id).unwrap();
        assert_eq!(rec.state, OperationState::Failed);
        assert_eq!(rec.error.unwrap().code, "mutation.rejected.policy-degraded");
    }

    #[test]
    fn gc_drops_terminal_entries_past_retention_only() {
        let s = OperationStatusStore::new();
        let now = Instant::now();
        let id_done = s.enqueue_for(Some("S-1-5-21-owner".to_string()));
        s.complete(&id_done, serde_json::json!({}), now);
        let id_running = s.enqueue_for(Some("S-1-5-21-owner".to_string()));

        // Just past retention.
        let dropped = s.gc_expired(now + DEFAULT_OPERATION_RETENTION + Duration::from_secs(1));
        assert_eq!(dropped, 1);
        assert!(s.get(&id_done).is_none());
        assert!(s.get(&id_running).is_some());
    }

    #[test]
    fn unknown_id_returns_none() {
        let s = OperationStatusStore::new();
        assert!(s.get("never-issued").is_none());
    }
}
