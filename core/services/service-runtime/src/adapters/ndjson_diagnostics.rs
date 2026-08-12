//! `NdjsonDiagnosticsPort` — production [`DiagnosticsPort`] implementation.
//!
//! Wraps an `Arc<LogWriter>` (operational NDJSON) and an `Arc<AuditWriter>`
//! (security audit NDJSON), and translates the three `DiagnosticsPort`
//! call sites into appropriate writes:
//!
//! | Call                      | Operational log              | Audit trail                                     |
//! |---------------------------|------------------------------|-------------------------------------------------|
//! | `emit_decision`           | `decision.route_selected` /  | —                                               |
//! |                           | `decision.default_route`     |                                                 |
//! | `emit_apply_attempt`      | `apply.started/completed/…`  | (deferred — security audit lives in revision    |
//! |                           |                              | flow, via `RecoveryAuditEmitter`)               |
//! | `emit_recovery_event`     | `service.degraded_mode`      | `recovery_action_requested` (always)            |
//!
//! ## Why operational log only for decisions and apply attempts?
//!
//! The audit trail is a security-critical, append-only chain — it is
//! reserved for the kinds in `AuditEventKind`: import/review/activate/
//! rollback, integrity events, recovery actions, tamper alerts. Every
//! decision being audited would flood the trail and make hash chain
//! verification expensive without security benefit. Decisions are operational
//! events; the apply layer's security-grade audit lives in the
//! revision-flow emitter (`RecoveryAuditEmitter`, the revision-activation
//! emitter).
//!
//! ## Failure handling
//!
//! Both writers are fire-and-forget (`emit` returns `()`, `append` returns
//! `Result` that we drop). Storage failures are silently absorbed — the
//! contract on `DiagnosticsPort` is "callers must not wait for the write".
//! `LogWriter` already increments `dropped_count` for write failures;
//! `AuditWriter` failures during recovery emission are tolerated by design
//! (the recovery action itself proceeds) — the same convention
//! `DiagnosticsRecoveryAuditEmitter` follows.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use nrr_diagnostics::audit::writer::{AuditEventInput, AuditWriter};
use nrr_diagnostics::audit::{ActorKind, AuditEventKind, AuditEventResult};
use nrr_diagnostics::event::LogEvent;
use nrr_diagnostics::logs::writer::LogWriter;
use nrr_diagnostics::reason;
use nrr_diagnostics::sink::DiagnosticsSink;
use nrr_diagnostics::taxonomy::EventCorrelation;
use nrr_diagnostics::AuditSink;

use nrr_domain::decision_engine::DecisionOutcome;

use crate::integration_ports::{ApplyRequest, ApplyResult, CorrelationId, DiagnosticsPort};

/// Production [`DiagnosticsPort`] backed by `nrr-diagnostics` writers.
pub struct NdjsonDiagnosticsPort {
    log: Arc<LogWriter>,
    audit: Arc<AuditWriter>,
}

impl NdjsonDiagnosticsPort {
    pub fn new(log: Arc<LogWriter>, audit: Arc<AuditWriter>) -> Self {
        Self { log, audit }
    }

    fn emit_log(&self, event: LogEvent) {
        self.log.emit(event);
    }
}

impl DiagnosticsPort for NdjsonDiagnosticsPort {
    fn emit_decision(&self, outcome: &DecisionOutcome, correlation: &CorrelationId) {
        // Decisions are operational, not security-grade. We pick a coarse
        // reason code based on whether the engine selected a route or
        // returned a fallback action. Detailed `kind` and per-rule tracing
        // live in the explain pipeline, not here.
        let reason_code = if outcome.final_action.is_forwarding() {
            reason::decision::ROUTE_SELECTED
        } else {
            reason::decision::DEFAULT_ROUTE
        };
        let event = LogEvent::new(next_log_event_id(), now_ms(), level_info(), reason_code)
            .with_correlation(correlation_envelope(correlation));
        self.emit_log(event);
    }

    fn emit_apply_attempt(
        &self,
        _request: &ApplyRequest,
        result: &ApplyResult,
        correlation: &CorrelationId,
    ) {
        let (reason_code, level) = match result {
            ApplyResult::Success { .. } => (reason::apply::COMPLETED, level_info()),
            ApplyResult::Failed { .. } => (reason::apply::FAILED, level_warn()),
            ApplyResult::VerificationFailed { .. } => {
                (reason::apply::VERIFICATION_FAILED, level_warn())
            }
            ApplyResult::RollbackStarted { .. } => (reason::apply::ROLLBACK_STARTED, level_warn()),
            ApplyResult::RollbackCompleted { .. } => {
                (reason::apply::ROLLBACK_COMPLETED, level_info())
            }
            ApplyResult::RequiresUserAction { .. } => (reason::apply::FAILED, level_warn()),
        };
        let event = LogEvent::new(next_log_event_id(), now_ms(), level, reason_code)
            .with_correlation(correlation_envelope(correlation));
        self.emit_log(event);
    }

    fn emit_recovery_event(&self, detail: &str, correlation: &CorrelationId) {
        // Operational mirror.
        let log_event = LogEvent::new(
            next_log_event_id(),
            now_ms(),
            level_warn(),
            reason::service::DEGRADED_MODE,
        )
        .with_correlation(correlation_envelope(correlation));
        self.emit_log(log_event);

        // Security-grade audit entry. Failure is tolerated — the recovery
        // action that triggered this call already proceeded, audit is best
        // effort here. Hash chain continuation is preserved by AuditWriter.
        let audit_input = AuditEventInput {
            event_id: next_audit_event_id(),
            kind: AuditEventKind::RecoveryActionRequested,
            created_at: now_ms(),
            actor_kind: ActorKind::Service,
            actor_id_hash: None,
            revision_id: None,
            risk_level: None,
            result: AuditEventResult::Success,
            reason_code: reason::service::DEGRADED_MODE,
            payload_summary_json: Some(payload_recovery(detail, &correlation.0)),
        };
        let _ = self.audit.append(audit_input);
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Build an `EventCorrelation` carrying the IPC-level correlation id in
/// `request_id` so `tracing` consumers can join logs by request.
fn correlation_envelope(correlation: &CorrelationId) -> EventCorrelation {
    EventCorrelation {
        request_id: Some(correlation.0.clone()),
        ..Default::default()
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn level_info() -> nrr_diagnostics::taxonomy::EventLevel {
    nrr_diagnostics::taxonomy::EventLevel::Info
}

fn level_warn() -> nrr_diagnostics::taxonomy::EventLevel {
    nrr_diagnostics::taxonomy::EventLevel::Warn
}

fn next_log_event_id() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    format!("evt-{nanos:020}-{n:08x}")
}

fn next_audit_event_id() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    format!("adt-{nanos:020}-{n:08x}")
}

fn payload_recovery(detail: &str, correlation_id: &str) -> String {
    // Hand-rolled JSON to avoid pulling serde_json::Value through the hot
    // path; mirrors the convention in `recovery_audit.rs`.
    format!(
        "{{\"detail\":{},\"correlation_id\":{}}}",
        json_string(detail),
        json_string(correlation_id),
    )
}

fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_diagnostics::audit::writer::AuditWriterConfig;
    use nrr_diagnostics::logs::writer::LogWriterConfig;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn build_port() -> (NdjsonDiagnosticsPort, TempDir) {
        let dir = TempDir::new().expect("temp");
        let logs_dir: PathBuf = dir.path().join("logs");
        let audit_dir: PathBuf = dir.path().join("audit");
        std::fs::create_dir_all(&logs_dir).unwrap();
        std::fs::create_dir_all(&audit_dir).unwrap();
        let log = Arc::new(LogWriter::open(LogWriterConfig::new(&logs_dir)));
        let audit = Arc::new(AuditWriter::open(AuditWriterConfig::new(&audit_dir)));
        let port = NdjsonDiagnosticsPort::new(log, audit);
        (port, dir)
    }

    fn count_lines(dir: &std::path::Path, prefix: &str) -> usize {
        let mut total = 0usize;
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if !name.starts_with(prefix) {
                    continue;
                }
                if let Ok(s) = std::fs::read_to_string(entry.path()) {
                    total += s.lines().count();
                }
            }
        }
        total
    }

    #[test]
    fn json_string_escapes_control_chars() {
        assert_eq!(json_string("a\nb"), "\"a\\nb\"");
        assert_eq!(json_string("\""), "\"\\\"\"");
        assert_eq!(json_string("\\"), "\"\\\\\"");
    }

    #[test]
    fn payload_recovery_is_valid_json() {
        let p = payload_recovery("ipc accept retired after 20 restarts", "corr-1");
        let parsed: serde_json::Value = serde_json::from_str(&p).expect("valid json");
        assert_eq!(parsed["detail"], "ipc accept retired after 20 restarts");
        assert_eq!(parsed["correlation_id"], "corr-1");
    }

    #[test]
    fn emit_recovery_event_writes_audit_and_log() {
        let (port, dir) = build_port();
        port.emit_recovery_event("test recovery", &CorrelationId("corr-recovery".to_string()));
        // One audit line + one log line.
        assert_eq!(count_lines(&dir.path().join("audit"), "nrr_audit_"), 1);
        assert_eq!(count_lines(&dir.path().join("logs"), "nrr_service_"), 1);
    }

    #[test]
    fn emit_apply_attempt_writes_log_only() {
        let (port, dir) = build_port();
        let req = ApplyRequest {
            correlation_id: CorrelationId("corr-apply".into()),
            revision_id: nrr_domain::revision::RevisionId::from_prefixed_string(
                "rev-11111111-2222-3333-4444-555555555555".to_string(),
            )
            .unwrap(),
            profile: dummy_profile(),
            safety_mode: crate::integration_ports::SafetyMode::FailOpen,
            dry_run: false,
        };
        let result = ApplyResult::Failed {
            reason: "wfp engine offline".into(),
            retryable: true,
        };
        port.emit_apply_attempt(&req, &result, &CorrelationId("corr-apply".into()));
        assert_eq!(count_lines(&dir.path().join("logs"), "nrr_service_"), 1);
        assert_eq!(count_lines(&dir.path().join("audit"), "nrr_audit_"), 0);
    }

    fn dummy_profile() -> nrr_domain::canonical::CanonicalProfile {
        // The simplest possible profile. The port doesn't inspect its
        // contents on the apply-attempt path — only the result.
        use nrr_domain::{
            AdapterIdentity, BindingSource, RouteBehaviorMode, RouteBinding, RouteRole,
        };
        nrr_domain::canonical::CanonicalProfile {
            primary: RouteBinding {
                role: RouteRole::Primary,
                adapter: AdapterIdentity {
                    stable_id: "eth0".into(),
                    display_name: "Ethernet".into(),
                },
                source: BindingSource::UserAssigned,
            },
            secondary: None,
            behavior_mode: RouteBehaviorMode::PreferPrimary,
            rule_book: Default::default(),
        }
    }
}
