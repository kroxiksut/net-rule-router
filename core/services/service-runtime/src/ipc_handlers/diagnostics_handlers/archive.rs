//! Building a diagnostic archive and handing it to whoever asked — including
//! the naming, pruning and path rules the handover depends on.
//!
//! Split out of `diagnostics_handlers`; the code is unchanged.

use super::*;

// ── DiagnosticsExportArchiveHandler ──────────────────────────────────────────

/// How many historical
/// decisions `explain_samples.json` samples, most-recently-observed first.
const MAX_EXPLAIN_SAMPLES: usize = 20;

pub struct DiagnosticsExportArchiveHandler {
    diagnostics: Arc<dyn DiagnosticsFacade>,
    /// Per-user destination directory for the zip archives. Sibling
    /// of `logs/` and `audit/`, and closed to ordinary users like the rest of
    /// the tree; `file_handoff` opens the finished file to its requester.
    archives_dir: PathBuf,
    /// App version string baked into the archive manifest.
    app_version: String,
    /// Host system info for `system_info.json`. Collected
    /// once at the composition root; `None` writes a minimal section.
    system_info: Option<nrr_shared::system_info::SystemInfo>,
    /// Adapters snapshot provider for `health.json`'s `adapters_snapshot`
    /// field. Same provider the `SnapshotInterfacesGet` handler uses.
    adapters: Arc<dyn AdaptersSnapshotProvider>,
    /// Per-SID route policy provider for `health.json`'s `behavior_mode`
    /// field.
    route_policy: Arc<dyn RoutePolicyProvider>,
    /// `nrr_service_state.db` schema version, read once at the composition
    /// root. `None` when the state DB connection was unavailable at startup
    /// (degraded boot).
    state_schema_version: Option<u32>,
    /// Grants the requesting principal read on the archive that was just
    /// written. The service's own tree is closed to ordinary users, so without
    /// this the export is a file its requester cannot open.
    file_handoff: Arc<dyn nrr_platform_api::file_handoff::FileHandoffPort>,
}

impl DiagnosticsExportArchiveHandler {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        diagnostics: Arc<dyn DiagnosticsFacade>,
        archives_dir: PathBuf,
        app_version: String,
        system_info: Option<nrr_shared::system_info::SystemInfo>,
        adapters: Arc<dyn AdaptersSnapshotProvider>,
        route_policy: Arc<dyn RoutePolicyProvider>,
        state_schema_version: Option<u32>,
        file_handoff: Arc<dyn nrr_platform_api::file_handoff::FileHandoffPort>,
    ) -> Self {
        Self {
            diagnostics,
            archives_dir,
            app_version,
            system_info,
            adapters,
            route_policy,
            state_schema_version,
            file_handoff,
        }
    }

    /// Best-effort discovery of recent decision ids to seed
    /// `explain_samples.json`.
    ///
    /// Decision-id correlation is carried on operational LOG events
    /// (`EventCorrelation::decision_id`, surfaced as a `"decision:<id>"`
    /// token in `LogEntryDto.correlation_summary`) — the audit trail
    /// (`AuditEntryDto`) carries no decision correlation. Fetched
    /// independently of the wire request's `include_logs` flag (that flag
    /// only controls whether `logs.ndjson` ships in the archive; explain
    /// sampling is an internal need of the `explain_samples.json` section).
    ///
    /// `recent_log_entries` returns entries newest-first, so decision ids are
    /// already discovered most-recent-first — no tail walk needed. Bounded to
    /// the freshest [`MAX_PAGE_SIZE`] entries, so sampling stays on the most
    /// recent decisions rather than the stalest ones in the store. Never
    /// fails the caller — an unreadable log store yields an empty list.
    fn recent_decision_ids(&self, limit: usize, audience: &DiagnosticsAudience) -> Vec<String> {
        let entries = match self.diagnostics.recent_log_entries(
            &Default::default(),
            MAX_PAGE_SIZE as usize,
            audience,
        ) {
            Ok(items) => items,
            Err(e) => {
                tracing::warn!(
                    target: "nrr::diagnostics",
                    error = %e,
                    "diagnostics.export-archive: recent_decision_ids: recent_log_entries failed",
                );
                return Vec::new();
            }
        };
        let mut ids: Vec<String> = Vec::new();
        for entry in entries.iter() {
            for token in &entry.correlation_summary {
                if let Some(id) = token.strip_prefix("decision:") {
                    if ids.len() >= limit {
                        return ids;
                    }
                    if !ids.iter().any(|existing| existing == id) {
                        ids.push(id.to_string());
                    }
                }
            }
        }
        ids
    }

    /// Real explain payloads for `explain_samples.json`. Runs
    /// `ExplainQuery::HistoricalDecision` through the SAME facade the
    /// `ExplainGet` IPC op uses, so the archive reflects whatever the facade
    /// actually knows about each decision (currently `DecisionNotFound` until
    /// a historical-replay snapshot store lands — see
    /// `ProductionDiagnosticsFacade::get_explain` — but the wiring itself is
    /// real, not a hardcoded stub). A facade error on one decision is skipped
    /// (logged), never aborts the whole archive.
    fn collect_explain_samples(
        &self,
        level: ExplainDetailLevel,
        caller_sid: &str,
        audience: &DiagnosticsAudience,
    ) -> Vec<ExplainResponse> {
        self.recent_decision_ids(MAX_EXPLAIN_SAMPLES, audience)
            .into_iter()
            .filter_map(|decision_id| {
                let query = ExplainQuery::HistoricalDecision {
                    decision_id: DecisionId(decision_id.clone()),
                };
                match self.diagnostics.get_explain(&query, level, caller_sid) {
                    Ok(response) => Some(response),
                    Err(e) => {
                        tracing::warn!(
                            target: "nrr::diagnostics",
                            decision_id = %decision_id,
                            error = %e,
                            "diagnostics.export-archive: skipping explain sample (facade error)",
                        );
                        None
                    }
                }
            })
            .collect()
    }

    /// The tail of a file in the service's log directory, or `None` when it is
    /// absent or unreadable. For what no structured log line stands in for: the
    /// captured stderr, where a panic lands on the way down, and the elevation
    /// broker's log.
    fn read_log_tail(&self, file_name: &str) -> Option<String> {
        /// Enough for a panic and its backtrace; the file is bounded by the
        /// capture itself, this only guards a pathological one.
        const MAX_BYTES: u64 = 256 * 1024;
        let logs_dir = self
            .archives_dir
            .parent()
            .map(|root| root.join("logs"))
            .unwrap_or_else(|| self.archives_dir.join("logs"));

        // Seek to the tail rather than reading the file and trimming after: a
        // cap enforced only after the whole file is in memory is no cap at all,
        // and this runs inside the service.
        use std::io::{Read, Seek, SeekFrom};
        let mut file = std::fs::File::open(logs_dir.join(file_name)).ok()?;
        let len = file.metadata().ok()?.len();
        if len > MAX_BYTES {
            file.seek(SeekFrom::Start(len - MAX_BYTES)).ok()?;
        }
        let mut bytes = Vec::with_capacity(MAX_BYTES.min(len) as usize);
        file.take(MAX_BYTES).read_to_end(&mut bytes).ok()?;

        // The seek can land mid-character; drop the partial head.
        let text = match String::from_utf8(bytes) {
            Ok(text) => text,
            Err(e) => {
                let bytes = e.into_bytes();
                let start = bytes
                    .iter()
                    .position(|b| (*b as i8) >= -0x40)
                    .unwrap_or(bytes.len());
                String::from_utf8_lossy(&bytes[start..]).into_owned()
            }
        };
        Some(text)
    }

    /// `health.json` fields beyond the live status snapshot. Best-effort: a
    /// value that cannot be sourced at this call site stays `None` rather
    /// than being fabricated.
    fn collect_health_enrichment(&self, caller_sid: &str) -> DiagnosticArchiveHealthEnrichmentDto {
        let behavior_mode = self
            .route_policy
            .get_for_sid(caller_sid)
            .and_then(|policy| serde_json::to_value(policy.mode).ok())
            .and_then(|v| v.as_str().map(str::to_string));
        // `force_refresh = false` — the archive reads the adapter monitor's
        // current cached snapshot rather than forcing a synchronous
        // re-enumeration, keeping export latency independent of adapter
        // enumeration cost.
        let adapters_snapshot = Some(self.adapters.adapters_snapshot(false));
        DiagnosticArchiveHealthEnrichmentDto {
            behavior_mode,
            state_schema_version: self.state_schema_version,
            adapters_snapshot,
        }
    }
}

impl IpcHandler for DiagnosticsExportArchiveHandler {
    fn handle(&self, request: &IpcRequestEnvelope, ctx: &IpcRequestContext) -> HandlerOutcome {
        const OP: &str = "diagnostics.export-archive";
        let req: DiagnosticsExportArchiveRequest =
            serde_json::from_value(request.payload.clone()).map_err(|e| malformed(OP, e))?;

        // Collect data. We always include status; logs / audit are
        // gated on the request flags. Playbook inclusion lands as
        // optional sections inside `DiagnosticArchiveRequest`.
        let health = self.diagnostics.get_status();

        // Build the diagnostic-archive request object FIRST — it carries the
        // log entry ceiling + byte budget that bound the log fetch below.
        //
        // The optional `troubleshooting_playbooks` section flag in our wire
        // DTO doesn't directly map to `DiagnosticArchiveRequest`'s sections
        // (the playbooks markdown is always emitted by the builder). Honoring
        // the GUI flag is a follow-up; for now we always emit playbooks (low
        // cost, high signal for support).
        //
        // The redaction level picks the section set + redaction tier:
        // "diagnostics" ships the extra cache/storage/explain sections;
        // anything else (incl. absent / unknown) stays at the redacted
        // "standard" default. Fail-safe: a bad level never errors.
        let wants_diagnostics_detail =
            matches!(req.redaction_level.as_deref(), Some("diagnostics"));
        let mut archive_request = if wants_diagnostics_detail {
            DiagnosticArchiveRequest::diagnostics_export(self.app_version.clone())
        } else {
            DiagnosticArchiveRequest::default_export(self.app_version.clone())
        };
        // The one inclusion flag with no consumer until now: the wire promised
        // a choice the builder never read, so an operator who unticked it still
        // got the file.
        archive_request.include_troubleshooting = req.include_troubleshooting_playbooks;
        // "Current session only": the builder drops
        // `logs.ndjson` entries older than this cutoff (see the wire DTO doc).
        // The GUI sends its day floor; narrow it to the current service
        // session (latest start after >=30 min of downtime) so an evening
        // export does not carry the morning's unrelated runs. The refined
        // value is echoed in the response so the launcher trims its raw log
        // attachments to the identical window. Fails open to the day floor.
        let effective_logs_from_ms = req.logs_from_ms.map(|requested| {
            let logs_dir = self
                .archives_dir
                .parent()
                .map(|root| root.join("logs"))
                .unwrap_or_else(|| self.archives_dir.join("logs"));
            nrr_diagnostics::logs::session_window::refine_session_cutoff_ms(&logs_dir, requested)
        });
        archive_request.logs_from_ms = effective_logs_from_ms;

        // The archive answers to the same audience as the panels: an export is
        // not a way around the scoping, and the person exporting it is usually
        // about to send it to somebody else.
        let audience = ctx.diagnostics_audience();
        // The lines are scoped like everything else, so the log directory does
        // not need to be readable by every account. The user's cap applies;
        // `0` means UNLIMITED, as the preference promises, and the real bounds
        // are retention and the export's own window.
        let raw_log_budget = match req.raw_log_budget_bytes {
            Some(bytes) if bytes > 0 => bytes as usize,
            _ => usize::MAX,
        };
        let raw_log_files = if req.include_logs {
            self.diagnostics
                .recent_log_files_raw(raw_log_budget, effective_logs_from_ms, &audience)
                .map_err(|e| internal(OP, format!("recent_log_files_raw: {e}")))?
        } else {
            Vec::new()
        };
        // Beside the raw files the builder leaves `logs.ndjson` out, so there is
        // nothing to fetch. Otherwise the NEWEST entries, newest-first, trimmed
        // by the builder to `max_log_bytes`.
        let log_entries = if req.include_logs && raw_log_files.is_empty() {
            self.diagnostics
                .recent_log_entries(
                    &Default::default(),
                    archive_request.max_log_entries as usize,
                    &audience,
                )
                .map_err(|e| internal(OP, format!("recent_log_entries: {e}")))?
        } else {
            Vec::new()
        };
        let audit_entries = if req.include_audit_summary {
            // One newest-first page; the builder keeps its first `max_audit_entries`.
            let audit_page = PaginationParams {
                cursor: None,
                page_size: MAX_PAGE_SIZE,
            };
            self.diagnostics
                .list_audit_entries(&Default::default(), &audit_page, &audience)
                .map_err(|e| internal(OP, format!("list_audit_entries: {e}")))?
                .items
        } else {
            Vec::new()
        };
        // Raw, tamper-verifiable audit chain (audit_chain.ndjson) — ONLY in a
        // diagnostics-tier export, where raw payload_summary_json is permitted.
        // `AuditChain` is in the diagnostics_export section set but NOT the
        // default set, so the redaction gate and the section gate agree.
        // The RAW chain is machine-wide by construction: its value is that the
        // hashes link every event, and a subset cannot be verified. So it ships
        // only for a caller who may see the whole trail; everyone else gets the
        // scoped summary above and no chain, rather than a chain that would
        // fail its own verification.
        let audit_chain_lines = if wants_diagnostics_detail
            && req.include_audit_summary
            && audience.is_machine_wide()
        {
            self.diagnostics
                .recent_audit_chain_lines(archive_request.max_audit_chain_bytes as usize)
                .map_err(|e| internal(OP, format!("recent_audit_chain_lines: {e}")))?
        } else {
            Vec::new()
        };

        let caller_sid = ctx.caller_stored();
        // Only pay for decision-id discovery + N facade calls when the archive will
        // actually carry `explain_samples.json` (diagnostics-tier export).
        let explain_level = if wants_diagnostics_detail {
            ExplainDetailLevel::Diagnostics
        } else {
            ExplainDetailLevel::CompactUi
        };
        let explain_samples = if wants_diagnostics_detail {
            self.collect_explain_samples(explain_level, caller_sid, &audience)
        } else {
            Vec::new()
        };
        let health_enrichment = self.collect_health_enrichment(caller_sid);

        let now_ms = millis_since_epoch();
        std::fs::create_dir_all(&self.archives_dir)
            .map_err(|e| internal(OP, format!("create archives dir: {e}")))?;
        // Archive filename: app version + UTC timestamp + sub-second millis, made
        // unique against an existing file. The version lets a triager tell
        // builds apart before opening the zip.
        let dest_path = unique_archive_path(&self.archives_dir, &self.app_version, now_ms);

        let input = ArchiveInput {
            health,
            health_enrichment,
            log_entries,
            audit_entries,
            audit_chain_lines,
            raw_log_files,
            explain_samples,
            system_info: self.system_info.clone(),
            service_stderr: self.read_log_tail("nrr_service_stderr.log"),
            broker_logs: [
                nrr_platform_api::paths::BROKER_LOG_FILE,
                nrr_platform_api::paths::BROKER_PREVIOUS_LOG_FILE,
            ]
            .into_iter()
            .filter_map(|name| {
                self.read_log_tail(name).map(|text| AttachedLog {
                    name: name.to_string(),
                    text,
                })
            })
            .collect(),
            request: archive_request,
        };
        let result = ArchiveBuilder::build(input, &dest_path)
            .map_err(|e| internal(OP, format!("archive build: {e}")))?;

        // Hand the finished file to the caller. The service tree is closed to
        // ordinary users — deliberately, it holds every principal's rules and
        // the audit trail — so without this the archive the user just asked for
        // is one they cannot open, and the GUI reports a path that only an
        // administrator can reach. The grant is per FILE: another principal's
        // export in the same directory stays theirs.
        //
        // Best-effort: an export that succeeded is not failed over the handoff.
        // The caller finds out by the copy failing, which reports its own
        // reason, rather than by losing the archive that was already built.
        let caller = ctx.caller_stored();
        if !caller.is_empty() {
            if let Err(e) = self.file_handoff.grant_read(&result.path, caller) {
                tracing::warn!(
                    target: "nrr::diagnostics",
                    error = %e,
                    "diagnostics.export-archive: could not hand the archive to its requester",
                );
            }
        }

        // Retention: the service dir is not
        // user-deletable (ProgramData needs elevation), so without a cap old
        // archives accumulate forever. Keep the most recent
        // [`ARCHIVE_RETENTION_KEEP`]; the user-owned copy the launcher makes
        // in %TEMP%\NetRuleRouter is theirs to manage. Best-effort — a prune
        // failure never fails the export that just succeeded.
        prune_old_archives(&self.archives_dir, ARCHIVE_RETENTION_KEEP);

        let response = DiagnosticsExportArchiveResponse {
            archive_path: result.path.to_string_lossy().into_owned(),
            size_bytes: result.size_bytes,
            generated_at_ms: now_ms,
            logs_from_ms_effective: effective_logs_from_ms,
        };
        serialise(OP, &response)
    }
}

/// How many finished archives the service
/// keeps in its own `archives/` dir. Newest-first by modification time.
const ARCHIVE_RETENTION_KEEP: usize = 5;

/// Delete all but the newest `keep` `nrr-diagnostics-*.zip` files in `dir`.
/// Only files matching our own naming prefix are ever touched; anything else
/// in the directory is left alone. Best-effort (I/O errors are logged and
/// swallowed — retention must never break an export).
pub(super) fn prune_old_archives(dir: &std::path::Path, keep: usize) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut archives: Vec<(std::time::SystemTime, PathBuf)> = entries
        .flatten()
        .filter_map(|e| {
            let name = e.file_name();
            let name = name.to_string_lossy();
            if !(name.starts_with("nrr-diagnostics-") && name.ends_with(".zip")) {
                return None;
            }
            let modified = e.metadata().and_then(|m| m.modified()).ok()?;
            Some((modified, e.path()))
        })
        .collect();
    if archives.len() <= keep {
        return;
    }
    // Newest first; everything past `keep` goes.
    archives.sort_by(|a, b| b.0.cmp(&a.0));
    for (_, path) in archives.drain(keep..) {
        match std::fs::remove_file(&path) {
            Ok(()) => tracing::info!(
                target: "nrr::diagnostics",
                path = %path.display(),
                "archive retention: pruned old diagnostic archive",
            ),
            Err(e) => tracing::warn!(
                target: "nrr::diagnostics",
                path = %path.display(),
                error = %e,
                "archive retention: failed to prune old archive",
            ),
        }
    }
}

/// Build a UNIQUE archive path:
/// `nrr-diagnostics-v<version>-<YYYYMMDD-HHMMSS>-<mmm>.zip`, where `<mmm>` is
/// the sub-second millisecond. If a file with that name already exists (two
/// exports within the same millisecond), a `-<n>` counter is appended until a
/// free name is found. Embedding the app version lets a triager tell builds
/// apart from the filename alone.
pub(super) fn unique_archive_path(
    dir: &std::path::Path,
    app_version: &str,
    now_ms: i64,
) -> PathBuf {
    let ver = sanitize_for_filename(app_version);
    let ts = format_timestamp_for_filename(now_ms);
    let millis = now_ms.rem_euclid(1_000);
    let base = format!("nrr-diagnostics-v{ver}-{ts}-{millis:03}");
    let mut path = dir.join(format!("{base}.zip"));
    let mut n: u32 = 1;
    while path.exists() {
        path = dir.join(format!("{base}-{n}.zip"));
        n = n.saturating_add(1);
    }
    path
}

/// Reduce a version string to a filename-safe token (ASCII alphanumerics plus
/// `.`, `-`, `_`); every other character becomes `-`. Never empty.
pub(super) fn sanitize_for_filename(s: &str) -> String {
    let cleaned: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '-'
            }
        })
        .collect();
    if cleaned.is_empty() {
        "unknown".to_string()
    } else {
        cleaned
    }
}

/// Format `now_ms` as `YYYYMMDD-HHMMSS` for use in the archive
/// filename. Uses simple UTC date arithmetic — pulling `chrono` for
/// this single call site would inflate the dependency graph
/// (workspace policy: avoid optional deps that only one module uses).
pub(super) fn format_timestamp_for_filename(now_ms: i64) -> String {
    // Decompose ms → seconds, then days + time-of-day.
    let secs = now_ms / 1_000;
    let days_since_epoch = secs.div_euclid(86_400);
    let secs_of_day = secs.rem_euclid(86_400);
    let hour = (secs_of_day / 3600) as u32;
    let minute = ((secs_of_day % 3600) / 60) as u32;
    let second = (secs_of_day % 60) as u32;
    // Civil calendar conversion (Howard Hinnant). Public domain;
    // converts days-since-1970-01-01 into (year, month, day).
    let z = days_since_epoch + 719_468;
    let era = z.div_euclid(146_097);
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe as i64 - (365 * yoe as i64 + yoe as i64 / 4 - yoe as i64 / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    format!(
        "{:04}{:02}{:02}-{:02}{:02}{:02}",
        year, m, d, hour, minute, second
    )
}
