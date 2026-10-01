# nrr-diagnostics

Storage files:

| File | Kind | Notes |
|------|------|-------|
| `nrr_audit_YYYYMMDD-N.ndjson` | Append-only NDJSON | Security audit trail; never deleted by user cleanup |
| `nrr_service_YYYYMMDD-N.ndjson` | Operational logs NDJSON | Rotated; user can clear |

Key design decisions:
- `DiagnosticRedactionLevel` lives in `nrr-storage`; `nrr-diagnostics` uses it via dependency.
- `tracing` + `tracing-subscriber`; custom NDJSON layer in `src/logs/tracing_layer.rs`. Production install via `install_ndjson_tracing` is called in `nrr-windows-service` (NOT inside `bootstrap()` — keeps lib clean for unit tests). Default `EnvFilter` is `nrr=info,info`; override via env `NRR_LOG`. Target prefilter drops non-`nrr::*` events with no allocation.
- Audit hash chain: `event_hash = SHA-256(prev_hash || canonical_payload_json)`. One writer per chain: the writer takes an OS lock on `nrr_audit.lock` before its first append and only then reads the last hash from the tail, so it continues across restarts and a second writer cannot fork the chain. A line is fsynced before the anchor records it, and a failed write is truncated back. `AuditChainVerifier` checks every file in retention, seams included, starting from the last `audit_chain_restarted` event; it reuses a file's verdict only under the SHA-256 of its bytes, never under length or mtime, which whoever edits the file also sets. A restart counts only when its `seal` (HMAC under a key derived from the service's integrity key) verifies and it links onto the event before it; the writer appends one only over the exact break digest an administrator was shown.
- Retention defaults: operational logs 90 days / 50 MB; audit NDJSON 365 days / 50 MB. Configurable via Settings → «Диагностика и логи».
- `ExplainQuery` has two variants: `HistoricalDecision { decision_id }` and `Synthetic { input_sample }`. `HistoricalDecision` always answers `DecisionNotFound`: nothing produces per-decision snapshots, because enforcement is generated from the rule book rather than decided per connection.
- No secret has a wrapper type. The integrity key stays behind `platform-api`'s `KeyStore` and never enters a structure that is logged or serialised; an event classed `PrivacyClass::SecretNeverLog` is dropped by the log layer, never redacted.
- Archive format: `.zip` with `manifest.json` + `health.json` + `service-logs/` (the raw log files; the payload-stripped `logs.ndjson` listing ships only when they are absent) + `audit_summary.json` + `troubleshooting.md` + optional sections.
