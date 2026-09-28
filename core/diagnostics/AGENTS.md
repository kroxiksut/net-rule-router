# nrr-diagnostics

Storage files:

| File | Kind | Notes |
|------|------|-------|
| `nrr_audit_YYYYMMDD-N.ndjson` | Append-only NDJSON | Security audit trail; never deleted by user cleanup |
| `nrr_service_YYYYMMDD-N.ndjson` | Operational logs NDJSON | Rotated; user can clear |

Key design decisions:
- `DiagnosticRedactionLevel` lives in `nrr-storage`; `nrr-diagnostics` uses it via dependency.
- `tracing` + `tracing-subscriber`; custom NDJSON layer in `src/logs/tracing_layer.rs`. Production install via `install_ndjson_tracing` is called in `nrr-windows-service` (NOT inside `bootstrap()` — keeps lib clean for unit tests). Default `EnvFilter` is `nrr=info,info`; override via env `NRR_LOG`. Target prefilter drops non-`nrr::*` events with no allocation.
- Audit hash chain: `event_hash = SHA-256(prev_hash || canonical_payload_json)`. `AuditWriter::open()` reads the last hash from the tail of the most recent file to continue across service restarts.
- Retention defaults: operational logs 90 days / 50 MB; audit NDJSON 365 days / 50 MB. Configurable via Settings → «Диагностика и логи».
- `ExplainQuery` has two variants: `HistoricalDecision { decision_id }` and `Synthetic { input_sample }`. `HistoricalDecision` always answers `DecisionNotFound`: nothing produces per-decision snapshots, because enforcement is generated from the rule book rather than decided per connection.
- `SecretNeverLog<T>` deliberately does NOT implement `serde::Serialize` — compile error on accidental inclusion in any output.
- Archive format: `.zip` with `manifest.json` + `health.json` + `service-logs/` (the raw log files; the payload-stripped `logs.ndjson` listing ships only when they are absent) + `audit_summary.json` + `troubleshooting.md` + optional sections.
