//! The audit trail for privileged IPC requests.
//!
//! The router records every state-changing request its handler's precheck
//! accepted, BEFORE the handler acts, and treats a failed write as a refusal: an
//! operation that cannot be accounted for does not happen. A request refused by
//! its precheck leaves no record. That safeguard was inert — the only implementation of the
//! emitter trait in the tree was the no-op one, wired into both production
//! builds, so the trail existed on paper and nowhere else.
//!
//! What is written is deliberately thin: which operation, which class, whether
//! the caller was elevated, and a hash of who they are. The payload itself is
//! not — a rules payload carries the user's hostnames, and the audit file is a
//! security record, not a copy of their policy.
//!
//! An unelevated caller has a budget of records per hour. Past it its requests
//! are counted rather than written, and the count is written once the next
//! hour opens: a process looping on a cheap request would otherwise fill the
//! trail and push a year of history out through retention.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use nrr_diagnostics::audit::kind::AuditEventKind;
use nrr_diagnostics::audit::writer::AuditEventInput;
use nrr_diagnostics::reason;
use nrr_diagnostics::sink::AuditSink;
use nrr_diagnostics::{ActorKind, AuditEventResult};

use crate::ipc::{IpcAuditEmitter, IpcRequestContext, IpcRequestEnvelope};
use nrr_shared::ipc::IpcOperationName;

/// Writes privileged-request records into the audit NDJSON.
pub struct ProductionIpcAuditEmitter<S>
where
    S: AuditSink<Event = AuditEventInput>,
{
    sink: Arc<S>,
    spend: Mutex<HashMap<String, Spend>>,
    clock: fn() -> i64,
}

/// Records one unelevated principal writes per [`BUDGET_WINDOW_MS`]: far above
/// what a person clicks, far below what a loop sends.
const PRINCIPAL_BUDGET: u32 = 120;
const BUDGET_WINDOW_MS: i64 = 3_600_000;
/// Principals whose spending is remembered; past it the stalest is forgotten.
const MAX_TRACKED_PRINCIPALS: usize = 64;

#[derive(Default)]
struct Spend {
    window_start: i64,
    written: u32,
    unrecorded: BTreeMap<&'static str, u32>,
}

impl<S> ProductionIpcAuditEmitter<S>
where
    S: AuditSink<Event = AuditEventInput>,
{
    pub fn new(sink: Arc<S>) -> Self {
        Self {
            sink,
            spend: Mutex::new(HashMap::new()),
            clock: now_ms,
        }
    }

    #[cfg(test)]
    fn with_clock(mut self, clock: fn() -> i64) -> Self {
        self.clock = clock;
        self
    }

    /// Spends one record of `principal`'s budget. `Err` carries nothing to
    /// write (the request is counted); `Ok` carries the counts of a window
    /// that just closed, to be written first.
    fn spend(
        &self,
        principal: &str,
        operation: &'static str,
        now: i64,
    ) -> Result<BTreeMap<&'static str, u32>, ()> {
        let mut spend = self.spend.lock().unwrap_or_else(|p| p.into_inner());
        if !spend.contains_key(principal) && spend.len() >= MAX_TRACKED_PRINCIPALS {
            let stalest = spend
                .iter()
                .min_by_key(|(_, s)| s.window_start)
                .map(|(k, _)| k.clone());
            if let Some(stalest) = stalest {
                spend.remove(&stalest);
            }
        }
        let entry = spend.entry(principal.to_owned()).or_default();
        let mut closed = BTreeMap::new();
        if now.saturating_sub(entry.window_start) >= BUDGET_WINDOW_MS {
            closed = std::mem::take(&mut entry.unrecorded);
            entry.window_start = now;
            entry.written = 0;
        }
        if entry.written >= PRINCIPAL_BUDGET {
            *entry.unrecorded.entry(operation).or_default() += 1;
            return Err(());
        }
        entry.written += 1;
        Ok(closed)
    }

    fn append(
        &self,
        ctx: &IpcRequestContext,
        risk_level: Option<String>,
        summary: serde_json::Value,
        now: i64,
    ) -> Result<(), String> {
        self.sink
            .append(AuditEventInput {
                event_id: next_audit_event_id(),
                kind: AuditEventKind::PrivilegedRequestAdmitted,
                created_at: now,
                actor_kind: ActorKind::User,
                // Hashed, never the SID itself: the trail must survive being
                // read by someone who should not learn who is on this machine.
                actor_id_hash: nrr_diagnostics::audit::actor_id_hash(ctx.caller_stored()),
                revision_id: None,
                risk_level,
                result: AuditEventResult::Success,
                reason_code: reason::service::IPC_PRIVILEGED_REQUEST,
                payload_summary_json: Some(summary.to_string()),
            })
            .map_err(|e| e.to_string())
    }
}

impl<S> IpcAuditEmitter for ProductionIpcAuditEmitter<S>
where
    S: AuditSink<Event = AuditEventInput> + Send + Sync,
{
    fn record_request(
        &self,
        request: &IpcRequestEnvelope,
        ctx: &IpcRequestContext,
    ) -> Result<(), String> {
        let now = (self.clock)();
        let operation = request.operation.slug();
        if !ctx.caller_is_elevated {
            match self.spend(ctx.caller_stored(), operation, now) {
                // Counted: the window's total is written when it closes.
                Err(()) => return Ok(()),
                Ok(closed) if !closed.is_empty() => self.append(
                    ctx,
                    None,
                    serde_json::json!({
                        "unrecorded": closed,
                        "window-secs": BUDGET_WINDOW_MS / 1000,
                        "elevated": false,
                    }),
                    now,
                )?,
                Ok(_) => {}
            }
        }
        let summary = serde_json::json!({
            "operation": operation,
            "class": request.operation_class.slug(),
            "elevated": ctx.caller_is_elevated,
            "profile": format!("{:?}", ctx.client_profile),
        });
        self.append(ctx, risk_of(request), summary, now)
    }
}

/// Risk level for a request the pre-execution audit can judge from its payload.
///
/// A rule revision gets a full `RiskAssessment` through review; a route-policy
/// update never goes through review, so its risk is judged here. Leak
/// protection `everything` can hold all of the user's traffic (High); any
/// other change of behaviour mode is `DefaultBehaviorChanged` (Medium).
///
/// This reads the REQUESTED value, not a diff — a pre-execution entry records
/// what was asked for, which is what an operator reconstructing the day needs.
fn risk_of(request: &IpcRequestEnvelope) -> Option<String> {
    use nrr_domain::revision::RiskLevel;

    if request.operation != IpcOperationName::RoutePolicyUpdate {
        return None;
    }
    let payload = &request.payload;
    let mode = payload.get("mode").and_then(|v| v.as_str());
    let protection = payload.get("leak-protection").and_then(|v| v.as_str());

    let level = if protection == Some("everything") {
        RiskLevel::High
    } else if mode.is_some() {
        RiskLevel::Medium
    } else {
        return None;
    };
    Some(level.to_string())
}

/// `adt-<nanos>-<counter>`, matching what the other audit paths emit.
pub(crate) fn next_audit_event_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    format!("adt-{nanos:x}-{n:x}")
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct RecordingSink {
        events: Mutex<Vec<AuditEventInput>>,
        fail: bool,
    }

    impl AuditSink for RecordingSink {
        type Event = AuditEventInput;
        fn append(
            &self,
            input: AuditEventInput,
        ) -> Result<(), nrr_diagnostics::error::DiagnosticsError> {
            if self.fail {
                return Err(nrr_diagnostics::error::DiagnosticsError::AuditWriteFailed {
                    reason: "disk full".into(),
                });
            }
            self.events
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(input);
            Ok(())
        }
    }

    fn envelope() -> IpcRequestEnvelope {
        IpcRequestEnvelope {
            protocol_version: crate::IPC_PROTOCOL_VERSION,
            request_id: "r-1".into(),
            correlation_id: None,
            operation: nrr_shared::ipc::IpcOperationName::MutationSubmit,
            operation_class: crate::ipc::IpcOperationClass::MutationRequest,
            confirmation_token: Some("tok".into()),
            payload: serde_json::json!({"secret-host": "example.internal"}),
        }
    }

    fn ctx() -> IpcRequestContext {
        IpcRequestContext {
            client_profile: nrr_shared::ipc::IpcClientProfile::GuiInteractive,
            caller_is_elevated: true,
            caller_principal: nrr_domain::user_principal::UserPrincipal::from_windows_sid(
                "S-1-5-21-A",
            )
            .ok(),
            caller_pid: None,
        }
    }

    #[test]
    fn the_record_names_the_operation_and_never_the_payload() {
        let sink = Arc::new(RecordingSink::default());
        let emitter = ProductionIpcAuditEmitter::new(Arc::clone(&sink));
        emitter.record_request(&envelope(), &ctx()).expect("write");

        let events = sink.events.lock().unwrap_or_else(|p| p.into_inner());
        let summary = events[0].payload_summary_json.clone().expect("a summary");
        assert!(summary.contains("mutation.submit"));
        assert!(
            !summary.contains("example.internal"),
            "the audit file is a security record, not a copy of the user's policy: {summary}",
        );
        assert_ne!(
            events[0].actor_id_hash.as_deref(),
            Some("S-1-5-21-A"),
            "the actor is hashed, never stored raw",
        );
    }

    static CLOCK_MS: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);
    fn test_clock() -> i64 {
        CLOCK_MS.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// An unelevated process looping on a cheap request writes its budget and
    /// then only a count, so the trail's history is not pushed out by one
    /// program; the count is not lost but written when the hour closes. An
    /// elevated caller is never limited.
    #[test]
    fn an_unelevated_caller_writes_its_budget_and_then_a_count() {
        CLOCK_MS.store(10 * BUDGET_WINDOW_MS, std::sync::atomic::Ordering::SeqCst);
        let sink = Arc::new(RecordingSink::default());
        let emitter = ProductionIpcAuditEmitter::new(Arc::clone(&sink)).with_clock(test_clock);
        let user = IpcRequestContext {
            caller_is_elevated: false,
            ..ctx()
        };
        for _ in 0..PRINCIPAL_BUDGET + 30 {
            emitter
                .record_request(&envelope(), &user)
                .expect("accounted");
        }
        let written = || sink.events.lock().unwrap_or_else(|p| p.into_inner()).len();
        assert_eq!(written(), PRINCIPAL_BUDGET as usize);

        emitter.record_request(&envelope(), &ctx()).expect("admin");
        assert_eq!(
            written(),
            PRINCIPAL_BUDGET as usize + 1,
            "an admin is never limited"
        );

        CLOCK_MS.fetch_add(BUDGET_WINDOW_MS, std::sync::atomic::Ordering::SeqCst);
        emitter
            .record_request(&envelope(), &user)
            .expect("next hour");
        let events = sink.events.lock().unwrap_or_else(|p| p.into_inner());
        let count = events[events.len() - 2]
            .payload_summary_json
            .clone()
            .expect("summary");
        assert!(count.contains("\"mutation.submit\":30"), "{count}");
        assert!(events.last().is_some_and(|e| e
            .payload_summary_json
            .as_deref()
            .is_some_and(|s| s.contains("\"operation\""))));
    }

    #[test]
    fn a_failed_write_is_reported_so_the_router_can_refuse() {
        // The router turns this into a refusal: an operation that cannot be
        // accounted for does not happen.
        let sink = Arc::new(RecordingSink {
            fail: true,
            ..Default::default()
        });
        let emitter = ProductionIpcAuditEmitter::new(sink);
        assert!(emitter.record_request(&envelope(), &ctx()).is_err());
    }

    fn policy_envelope(payload: serde_json::Value) -> IpcRequestEnvelope {
        IpcRequestEnvelope {
            operation: IpcOperationName::RoutePolicyUpdate,
            operation_class: crate::ipc::IpcOperationClass::UserScopedConfiguration,
            confirmation_token: None,
            payload,
            ..envelope()
        }
    }

    #[test]
    fn arming_a_blocking_posture_is_recorded_as_high_risk() {
        for payload in [
            serde_json::json!({ "mode": "prefer-secondary-when-available", "leak-protection": "everything" }),
            serde_json::json!({ "mode": "prefer-primary", "leak-protection": "everything" }),
        ] {
            assert_eq!(
                risk_of(&policy_envelope(payload.clone())).as_deref(),
                Some("high"),
                "{payload} arms a posture that can cut the user's traffic"
            );
        }
    }

    #[test]
    fn an_ordinary_mode_change_is_medium_and_other_operations_carry_no_risk() {
        assert_eq!(
            risk_of(&policy_envelope(
                serde_json::json!({ "mode": "prefer-primary" })
            ))
            .as_deref(),
            Some("medium")
        );
        // `sites` holds only what the rules send through the tunnel.
        assert_eq!(
            risk_of(&policy_envelope(
                serde_json::json!({ "mode": "prefer-primary", "leak-protection": "sites" })
            ))
            .as_deref(),
            Some("medium")
        );
        // The emitter judges only what it can read from a payload it
        // understands; everything else stays unscored rather than guessed.
        assert_eq!(risk_of(&envelope()), None);
    }
}
