//! In-memory token store for the two-phase operations (`MutationSubmit`,
//! safe-disable, rollback).
//!
//! A `dry_run = true` request mints a confirmation token and stashes what
//! the confirm needs here under it, with a TTL. The follow-up request
//! carries the token back and [`MutationTokenStore::consume`]s it.
//!
//! Every token is bound to the operation that issued it: the operations
//! share this store, and a confirmation of one must never authorise another.
//! Tokens are one-shot — a consume removes the entry whatever the outcome,
//! so a captured token cannot be replayed.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use nrr_shared::ipc::IpcOperationName;

use crate::ipc::{IpcError, IpcErrorCode};
use crate::ipc_handlers::payloads::{MutationKind, MutationSubmitRequest};

/// Default TTL for confirmation tokens. The spec target is 5 minutes;
/// shorter values risk surprising users on slow review screens, longer
/// values widen the replay window for an attacker who captured a token.
pub const DEFAULT_MUTATION_TOKEN_TTL: Duration = Duration::from_secs(5 * 60);

/// Live tokens one principal may hold. A review needs one, a few abandoned
/// ones cover the rest; each parks up to a full IPC message, minted by an
/// unelevated call.
pub const MAX_TOKENS_PER_PRINCIPAL: usize = 8;

/// Live tokens across all principals, bounding the store's memory.
pub const MAX_TOKENS_TOTAL: usize = 64;

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

    /// What an operation other than `MutationSubmit` keeps for its confirm.
    /// `kind` is a placeholder there: the store's operation binding says what
    /// the token is for.
    pub fn confirmation_of(
        payload: serde_json::Value,
        issuer_sid: &str,
        caller_is_elevated: bool,
    ) -> Self {
        Self {
            kind: MutationKind::RulesUpdate,
            payload,
            correlation_id: None,
            issuer_sid: issuer_sid.to_string(),
            caller_is_elevated,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ConsumeError {
    /// No token by this id for this operation and caller (expired and GCed,
    /// never issued, already consumed, issued for another operation or
    /// principal). The last two are not told apart: a caller learns nothing
    /// about tokens that are not theirs.
    NotFound,
    /// Token exists but its TTL has elapsed.
    Expired,
}

/// One wire answer for every confirm handler: clients branch on the code.
impl From<ConsumeError> for IpcError {
    fn from(err: ConsumeError) -> Self {
        let (code, message) = match err {
            ConsumeError::NotFound => (
                IpcErrorCode::ConfirmationUnknown,
                "confirmation token unknown — re-run dry-run",
            ),
            ConsumeError::Expired => (
                IpcErrorCode::ConfirmationExpired,
                "confirmation token expired — re-run dry-run",
            ),
        };
        IpcError {
            code,
            message: message.into(),
            diagnostics_id: None,
        }
    }
}

#[derive(Default)]
pub struct MutationTokenStore {
    inner: Mutex<HashMap<String, Entry>>,
    /// Set by the first eviction, cleared once the store drains.
    eviction_logged: AtomicBool,
}

struct Entry {
    operation: IpcOperationName,
    payload: StoredMutation,
    expires_at: Instant,
    /// Issue order; the oldest token is the one evicted.
    seq: u64,
}

/// Monotonic counter feeding the token suffix. Tokens look like
/// `mut-tok-<hex>`; the prefix is opaque to clients.
static TOKEN_COUNTER: AtomicU64 = AtomicU64::new(1);

/// The token IS the authority for the confirm phase, so it must not be
/// derivable from another one. The old suffix was `Instant::now().elapsed()`,
/// which is a handful of nanoseconds by construction — in practice the token
/// was the counter. Same CSPRNG the coordinator's confirmation tokens use, with
/// the same reasoning about its fallback: a mutation that cannot be confirmed
/// at all is worse than a token that is merely hard to guess, and the token
/// stays single-use, principal-scoped and short-lived either way.
fn next_token() -> (u64, String) {
    let n = TOKEN_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut bytes = [0u8; 16];
    let suffix: String = match getrandom::fill(&mut bytes) {
        Ok(()) => bytes.iter().map(|b| format!("{b:02x}")).collect(),
        Err(_) => format!(
            "{:032x}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ),
    };
    (n, format!("mut-tok-{n:016x}{suffix}"))
}

/// Remove the oldest entry `pick` accepts. Expired ones are the oldest, so
/// they go first.
fn evict_oldest(entries: &mut HashMap<String, Entry>, pick: impl Fn(&Entry) -> bool) -> bool {
    let oldest = entries
        .iter()
        .filter(|(_, e)| pick(e))
        .min_by_key(|(_, e)| e.seq)
        .map(|(token, _)| token.clone());
    oldest.is_some_and(|token| entries.remove(&token).is_some())
}

// State is `Mutex`-guarded; `lock().expect(...)` propagates poisoning (a prior
// panic) — deliberate, not a recoverable error.
#[allow(clippy::unwrap_used, clippy::expect_used)]
impl MutationTokenStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Issue a token for `operation` that expires at `expires_at`. Returns the
    /// opaque token id the client echoes on confirm.
    /// Past [`MAX_TOKENS_PER_PRINCIPAL`] or [`MAX_TOKENS_TOTAL`] the oldest
    /// token is dropped; confirming it answers "unknown — re-run dry-run".
    pub fn issue(
        &self,
        operation: IpcOperationName,
        payload: StoredMutation,
        expires_at: Instant,
    ) -> String {
        let (seq, token) = next_token();
        let mut g = self.inner.lock().expect("token store mutex poisoned");
        let issuer = payload.issuer_sid.as_str();
        let held = g
            .values()
            .filter(|e| e.payload.issuer_sid == issuer)
            .count();
        let mut evicted = false;
        if held >= MAX_TOKENS_PER_PRINCIPAL {
            evicted |= evict_oldest(&mut g, |e| e.payload.issuer_sid == issuer);
        }
        if g.len() >= MAX_TOKENS_TOTAL {
            evicted |= evict_oldest(&mut g, |_| true);
        }
        if evicted && !self.eviction_logged.swap(true, Ordering::Relaxed) {
            tracing::warn!(
                target: "nrr::ipc",
                msg_key = "mutation-tokens-capped",
                held,
                total = g.len(),
                "confirmation-token cap reached — the oldest unconfirmed previews are dropped",
            );
        }
        g.insert(
            token.clone(),
            Entry {
                operation,
                payload,
                expires_at,
                seq,
            },
        );
        token
    }

    /// One-shot consume of a token `operation` issued. The entry is removed
    /// regardless of outcome — a captured-then-replayed token cannot be
    /// confirmed twice, nor retried against another operation.
    ///
    /// Leaves the principal to the caller: `MutationSubmit` binds it only for
    /// per-principal edits. Everything else uses [`Self::consume_for`].
    pub fn consume(
        &self,
        token: &str,
        operation: IpcOperationName,
        now: Instant,
    ) -> Result<StoredMutation, ConsumeError> {
        self.take(token, operation, None, now)
    }

    /// [`Self::consume`] that also requires the token to have been issued to
    /// `caller` (the stored-string principal, `""` when unauthenticated).
    pub fn consume_for(
        &self,
        token: &str,
        operation: IpcOperationName,
        caller: &str,
        now: Instant,
    ) -> Result<StoredMutation, ConsumeError> {
        self.take(token, operation, Some(caller), now)
    }

    fn take(
        &self,
        token: &str,
        operation: IpcOperationName,
        caller: Option<&str>,
        now: Instant,
    ) -> Result<StoredMutation, ConsumeError> {
        let mut g = self.inner.lock().expect("token store mutex poisoned");
        let entry = g.remove(token).ok_or(ConsumeError::NotFound)?;
        if entry.operation != operation || caller.is_some_and(|sid| sid != entry.payload.issuer_sid)
        {
            return Err(ConsumeError::NotFound);
        }
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
        if g.is_empty() {
            self.eviction_logged.store(false, Ordering::Relaxed);
        }
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

    const OP: IpcOperationName = IpcOperationName::MutationSubmit;

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
        let t1 = s.issue(OP, payload(), now + DEFAULT_MUTATION_TOKEN_TTL);
        let t2 = s.issue(OP, payload(), now + DEFAULT_MUTATION_TOKEN_TTL);
        assert_ne!(t1, t2);
        assert_eq!(s.len(), 2);
    }

    #[test]
    fn tokens_are_not_derivable_from_each_other() {
        // A suffix built from `Instant::now().elapsed()` would be near-constant
        // across two calls made moments apart, letting one token predict the
        // next; the random half must actually vary.
        let store = MutationTokenStore::new();
        let deadline = Instant::now() + Duration::from_secs(60);
        let first = store.issue(OP, payload(), deadline);
        let second = store.issue(OP, payload(), deadline);
        let suffix = |t: &str| t.trim_start_matches("mut-tok-")[16..].to_string();
        assert_ne!(
            suffix(&first),
            suffix(&second),
            "the random half must actually differ"
        );
        assert!(
            suffix(&first).len() >= 32,
            "128 bits, hex-encoded: {}",
            suffix(&first)
        );
    }

    #[test]
    fn consume_returns_payload_and_removes_entry() {
        let s = MutationTokenStore::new();
        let now = Instant::now();
        let t = s.issue(OP, payload(), now + DEFAULT_MUTATION_TOKEN_TTL);
        let p = s.consume(&t, OP, now).expect("happy path");
        assert_eq!(p.kind, MutationKind::RulesUpdate);
        assert_eq!(s.len(), 0);
        // Second consume → NotFound (one-shot semantics).
        assert!(matches!(
            s.consume(&t, OP, now).unwrap_err(),
            ConsumeError::NotFound
        ));
    }

    #[test]
    fn consume_expired_returns_expired() {
        let s = MutationTokenStore::new();
        let now = Instant::now();
        let t = s.issue(OP, payload(), now + Duration::from_millis(1));
        let later = now + Duration::from_secs(60);
        assert!(matches!(
            s.consume(&t, OP, later).unwrap_err(),
            ConsumeError::Expired
        ));
        // Removed regardless — no replay.
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn consume_unknown_returns_not_found() {
        let s = MutationTokenStore::new();
        assert!(matches!(
            s.consume("never-issued", OP, Instant::now()).unwrap_err(),
            ConsumeError::NotFound
        ));
    }

    fn payload_of(sid: &str) -> StoredMutation {
        StoredMutation {
            issuer_sid: sid.to_string(),
            ..payload()
        }
    }

    /// Dry-runs in a loop must not grow the store: past the per-principal
    /// cap the oldest token goes, the newest stay confirmable.
    #[test]
    fn a_principal_past_its_cap_loses_its_oldest_token() {
        let s = MutationTokenStore::new();
        let now = Instant::now();
        let deadline = now + DEFAULT_MUTATION_TOKEN_TTL;
        let tokens: Vec<String> = (0..MAX_TOKENS_PER_PRINCIPAL + 3)
            .map(|_| s.issue(OP, payload_of("S-1-5-21-1"), deadline))
            .collect();
        assert_eq!(s.len(), MAX_TOKENS_PER_PRINCIPAL);
        for evicted in &tokens[..3] {
            assert_eq!(
                s.consume(evicted, OP, now).unwrap_err(),
                ConsumeError::NotFound
            );
        }
        for kept in &tokens[3..] {
            assert!(
                s.consume(kept, OP, now).is_ok(),
                "the newest stay confirmable"
            );
        }
    }

    /// One principal flooding evicts only its own tokens.
    #[test]
    fn another_principals_token_survives_a_flood() {
        let s = MutationTokenStore::new();
        let now = Instant::now();
        let deadline = now + DEFAULT_MUTATION_TOKEN_TTL;
        let other = s.issue(OP, payload_of("S-1-5-21-2"), deadline);
        for _ in 0..MAX_TOKENS_TOTAL * 2 {
            s.issue(OP, payload_of("S-1-5-21-1"), deadline);
        }
        assert_eq!(s.len(), MAX_TOKENS_PER_PRINCIPAL + 1);
        assert!(s.consume(&other, OP, now).is_ok());
    }

    /// The total cap holds when many principals each stay under their own.
    #[test]
    fn the_store_never_exceeds_its_total_cap() {
        let s = MutationTokenStore::new();
        let deadline = Instant::now() + DEFAULT_MUTATION_TOKEN_TTL;
        for i in 0..MAX_TOKENS_TOTAL * 2 {
            s.issue(OP, payload_of(&format!("S-1-5-21-{i}")), deadline);
        }
        assert_eq!(s.len(), MAX_TOKENS_TOTAL);
    }

    #[test]
    fn gc_drops_expired_entries_only() {
        let s = MutationTokenStore::new();
        let now = Instant::now();
        let _t1 = s.issue(OP, payload(), now + Duration::from_millis(1));
        let _t2 = s.issue(OP, payload(), now + Duration::from_secs(60));
        let dropped = s.gc_expired(now + Duration::from_secs(10));
        assert_eq!(dropped, 1);
        assert_eq!(s.len(), 1);
    }

    /// The operations share one store; a token confirms only its own, and a
    /// try at another one spends it.
    #[test]
    fn a_token_confirms_only_the_operation_that_issued_it() {
        let s = MutationTokenStore::new();
        let now = Instant::now();
        let deadline = now + DEFAULT_MUTATION_TOKEN_TTL;
        let t = s.issue(
            IpcOperationName::ProductImpactDisableTemporary,
            payload(),
            deadline,
        );
        assert_eq!(
            s.consume(&t, IpcOperationName::RollbackRequest, now)
                .unwrap_err(),
            ConsumeError::NotFound
        );
        assert_eq!(
            s.consume(&t, IpcOperationName::ProductImpactDisableTemporary, now)
                .unwrap_err(),
            ConsumeError::NotFound,
            "the misdirected try burned it"
        );
        let t = s.issue(IpcOperationName::RollbackRequest, payload(), deadline);
        assert!(s
            .consume(&t, IpcOperationName::RollbackRequest, now)
            .is_ok());
    }

    #[test]
    fn a_principal_bound_consume_refuses_another_principal() {
        let s = MutationTokenStore::new();
        let now = Instant::now();
        let deadline = now + DEFAULT_MUTATION_TOKEN_TTL;
        let t = s.issue(OP, payload_of("S-1-5-21-1"), deadline);
        assert_eq!(
            s.consume_for(&t, OP, "S-1-5-21-2", now).unwrap_err(),
            ConsumeError::NotFound
        );
        assert_eq!(s.len(), 0, "the foreign try burned it");
        let t = s.issue(OP, payload_of("S-1-5-21-1"), deadline);
        assert_eq!(
            s.consume_for(&t, OP, "", now).unwrap_err(),
            ConsumeError::NotFound,
            "an unauthenticated caller is not the issuer either"
        );
        let t = s.issue(OP, payload_of("S-1-5-21-1"), deadline);
        assert!(s.consume_for(&t, OP, "S-1-5-21-1", now).is_ok());
    }
}
