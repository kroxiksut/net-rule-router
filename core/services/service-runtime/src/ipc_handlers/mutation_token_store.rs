//! In-memory token store for the two-step `MutationSubmit` flow.
//!
//! When a client issues a `dry_run = true` request, the handler computes
//! a `ReviewSummary`, mints a confirmation token, and stashes the
//! mutation payload here under that token with a TTL.
//!
//! The follow-up `dry_run = false` request carries the token; the
//! handler [`MutationTokenStore::consume`]s it, validates that it has
//! not expired or been spent, and proceeds to execute the mutation.
//!
//! Tokens are one-shot — `consume` removes the entry whether it
//! succeeds or fails (expired, taken). This prevents replay attacks
//! against a captured token.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::ipc_handlers::payloads::{MutationKind, MutationSubmitRequest};

/// Default TTL for confirmation tokens. The spec target is 5 minutes;
/// shorter values risk surprising users on slow review screens, longer
/// values widen the replay window for an attacker who captured a token.
pub const DEFAULT_MUTATION_TOKEN_TTL: Duration = Duration::from_secs(5 * 60);

/// What we stash for each issued token: enough to execute the mutation
/// when the client confirms, without re-asking it for fields.
#[derive(Clone, Debug)]
pub struct StoredMutation {
    pub kind: MutationKind,
    pub payload: serde_json::Value,
    /// Caller-supplied correlation id extracted from
    /// the payload's `correlation-id` field at submit time. Used by
    /// [`ProductionMutationExecutor`](crate::ProductionMutationExecutor)
    /// to stamp `MutationProgress` push events so the GUI's
    /// `MutationsModel` can correlate the lifecycle to the original
    /// `rpcMutationSubmit` call. `None` when the payload didn't
    /// carry a correlation-id (older clients or non-rules kinds);
    /// the executor then suppresses progress emission for that
    /// mutation.
    pub correlation_id: Option<String>,
    /// String SID of the client that ran the dry-run
    /// (`IpcRequestContext.caller_stored()`). The confirm handler refuses a
    /// token whose stored `issuer_sid` differs from the confirming
    /// caller's SID, so a token minted for principal A cannot be
    /// replayed by principal B. Empty on non-Windows transports / test
    /// harnesses that omit the SID — the cross-principal check is then
    /// skipped (there is no principal to bind to).
    pub issuer_sid: String,
    /// Whether the transport authenticated the submitting caller as elevated.
    /// Rides along with the SID because the executor enforces the
    /// administrative rules lock and elevation — not the target partition — is
    /// what distinguishes an administrator editing their own rules from a
    /// restricted user doing the same thing.
    pub caller_is_elevated: bool,
}

impl StoredMutation {
    pub fn from_request(
        req: &MutationSubmitRequest,
        issuer_sid: &str,
        caller_is_elevated: bool,
    ) -> Self {
        let correlation_id = req
            .payload
            .get("correlation-id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        Self {
            kind: req.mutation_kind,
            payload: req.payload.clone(),
            correlation_id,
            issuer_sid: issuer_sid.to_string(),
            caller_is_elevated,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ConsumeError {
    /// No token by this id (expired and GCed, never issued, or already
    /// consumed). The caller surfaces `ConfirmationExpired` or
    /// `PreconditionFailed` depending on the operation.
    NotFound,
    /// Token exists but its TTL has elapsed.
    Expired,
}

#[derive(Default)]
pub struct MutationTokenStore {
    inner: Mutex<HashMap<String, Entry>>,
}

struct Entry {
    payload: StoredMutation,
    expires_at: Instant,
}

/// Monotonic counter feeding the token suffix. Tokens look like
/// `mut-tok-<hex>`; the prefix is opaque to clients.
static TOKEN_COUNTER: AtomicU64 = AtomicU64::new(1);

fn next_token() -> String {
    let n = TOKEN_COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = Instant::now().elapsed().subsec_nanos();
    format!("mut-tok-{n:016x}{nanos:08x}")
}

// State is `Mutex`-guarded; `lock().expect(...)` propagates poisoning (a prior
// panic) — deliberate, not a recoverable error.
#[allow(clippy::unwrap_used, clippy::expect_used)]
impl MutationTokenStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Issue a new token that expires at `expires_at`. Returns the
    /// opaque token id the client echoes on confirm.
    pub fn issue(&self, payload: StoredMutation, expires_at: Instant) -> String {
        let token = next_token();
        let mut g = self.inner.lock().expect("token store mutex poisoned");
        g.insert(
            token.clone(),
            Entry {
                payload,
                expires_at,
            },
        );
        token
    }

    /// One-shot consume. The entry is removed regardless of outcome —
    /// a captured-then-replayed token cannot be confirmed twice.
    pub fn consume(&self, token: &str, now: Instant) -> Result<StoredMutation, ConsumeError> {
        let mut g = self.inner.lock().expect("token store mutex poisoned");
        let entry = g.remove(token).ok_or(ConsumeError::NotFound)?;
        if now >= entry.expires_at {
            return Err(ConsumeError::Expired);
        }
        Ok(entry.payload)
    }

    /// Sweep entries whose TTL has elapsed. Cheap; callers can run it
    /// periodically (e.g. once per minute from the runtime loop).
    pub fn gc_expired(&self, now: Instant) -> usize {
        let mut g = self.inner.lock().expect("token store mutex poisoned");
        let before = g.len();
        g.retain(|_, e| now < e.expires_at);
        before - g.len()
    }

    pub fn len(&self) -> usize {
        self.inner.lock().expect("token store mutex poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload() -> StoredMutation {
        StoredMutation {
            kind: MutationKind::RulesUpdate,
            payload: serde_json::json!({}),
            correlation_id: None,
            issuer_sid: String::new(),
            caller_is_elevated: false,
        }
    }

    #[test]
    fn issue_returns_unique_tokens() {
        let s = MutationTokenStore::new();
        let now = Instant::now();
        let t1 = s.issue(payload(), now + DEFAULT_MUTATION_TOKEN_TTL);
        let t2 = s.issue(payload(), now + DEFAULT_MUTATION_TOKEN_TTL);
        assert_ne!(t1, t2);
        assert_eq!(s.len(), 2);
    }

    #[test]
    fn consume_returns_payload_and_removes_entry() {
        let s = MutationTokenStore::new();
        let now = Instant::now();
        let t = s.issue(payload(), now + DEFAULT_MUTATION_TOKEN_TTL);
        let p = s.consume(&t, now).expect("happy path");
        assert_eq!(p.kind, MutationKind::RulesUpdate);
        assert_eq!(s.len(), 0);
        // Second consume → NotFound (one-shot semantics).
        assert!(matches!(
            s.consume(&t, now).unwrap_err(),
            ConsumeError::NotFound
        ));
    }

    #[test]
    fn consume_expired_returns_expired() {
        let s = MutationTokenStore::new();
        let now = Instant::now();
        let t = s.issue(payload(), now + Duration::from_millis(1));
        let later = now + Duration::from_secs(60);
        assert!(matches!(
            s.consume(&t, later).unwrap_err(),
            ConsumeError::Expired
        ));
        // Removed regardless — no replay.
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn consume_unknown_returns_not_found() {
        let s = MutationTokenStore::new();
        assert!(matches!(
            s.consume("never-issued", Instant::now()).unwrap_err(),
            ConsumeError::NotFound
        ));
    }

    #[test]
    fn gc_drops_expired_entries_only() {
        let s = MutationTokenStore::new();
        let now = Instant::now();
        let _t1 = s.issue(payload(), now + Duration::from_millis(1));
        let _t2 = s.issue(payload(), now + Duration::from_secs(60));
        let dropped = s.gc_expired(now + Duration::from_secs(10));
        assert_eq!(dropped, 1);
        assert_eq!(s.len(), 1);
    }
}
