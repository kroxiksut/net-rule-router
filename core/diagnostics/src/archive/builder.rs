//! Diagnostic archive builder.
//!
//! # Workflow
//!
//! 1. Caller provides [`ArchiveInput`] (pre-collected DTOs, no raw files).
//! 2. [`ArchiveBuilder::build`] writes each section to a temp directory.
//! 3. Section files are packaged into a `.zip` at the destination path.
//! 4. Temp directory is cleaned up on both success and failure.
//!
//! # No-backup guarantee
//!
//! The builder only serialises DTOs provided by the caller.  It never reads
//! raw SQLite files, credential stores, or full policy backups.  The
//! [`DiagnosticArchiveManifest::NO_BACKUP_GUARANTEE`] string is included in
//! every archive manifest.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use chrono::{Datelike, Timelike};
use serde_json::json;

use crate::archive::manifest::{
    DiagnosticArchiveManifest, RedactionReport, MANIFEST_SCHEMA_VERSION,
};
use crate::archive::playbooks::{all_playbooks, render_playbooks_markdown};
use crate::archive::request::{ArchiveSection, DiagnosticArchiveRequest};
use crate::error::{DiagnosticsError, DiagnosticsResult};
use crate::explain::ExplainResponse;
use crate::facade::dto::{
    AuditEntryDto, DiagnosticArchiveHealthEnrichmentDto, DiagnosticsStatusDto, LogEntryDto,
};

// ── ArchiveInput ──────────────────────────────────────────────────────────────

/// Pre-collected data provided to the archive builder.
///
/// The caller is responsible for applying redaction (using `RedactionMode`)
/// before populating these fields.  The builder treats the data as already
/// safe to include.
pub struct ArchiveInput {
    pub health: DiagnosticsStatusDto,
    /// Fields merged into `health.json` alongside `health` (behavior mode,
    /// state-schema version, adapters snapshot). Defaults to an all-`None` DTO, which
    /// serializes as no additional keys — existing callers that don't
    /// populate this field keep producing the pre-enrichment `health.json`
    /// shape.
    pub health_enrichment: DiagnosticArchiveHealthEnrichmentDto,
    pub log_entries: Vec<LogEntryDto>,
    pub audit_entries: Vec<AuditEntryDto>,
    /// Raw audit NDJSON lines (verbatim, chain fields intact) for the
    /// [`ArchiveSection::AuditChain`] section. Only populated by the caller for
    /// Diagnostics / DeveloperLocal exports; empty otherwise. The builder writes
    /// them only when the section is present, byte-capped by
    /// `request.max_audit_chain_bytes`.
    pub audit_chain_lines: Vec<String>,
    /// Raw operational-log NDJSON, payloads intact, kept in the FILES the
    /// service wrote them to and scoped by the facade to the requester. Ships as
    /// the `service-logs/` directory and, when present, replaces the
    /// payload-stripped `logs.ndjson` listing of the same lines.
    pub raw_log_files: Vec<crate::logs::reader::RawLogFile>,
    pub explain_samples: Vec<ExplainResponse>,
    /// Host system information (OS/CPU/RAM) for `system_info.json`.
    /// `None` writes a minimal record noting it was
    /// unavailable, so the section is still present for a consistent archive.
    pub system_info: Option<nrr_shared::system_info::SystemInfo>,
    /// The service's captured stderr, if the caller could read it. This is
    /// where a panic lands — the one failure mode that produces no structured
    /// log line at all, because the process was already on its way down. `None`
    /// or empty writes no section.
    pub service_stderr: Option<String>,
    /// The elevation broker's own log files; empty ones write nothing.
    pub broker_logs: Vec<AttachedLog>,
    pub request: DiagnosticArchiveRequest,
}

/// A small log file shipped verbatim at the archive root, under its own name.
pub struct AttachedLog {
    pub name: String,
    pub text: String,
}

// ── BuildResult ───────────────────────────────────────────────────────────────

/// Result of a successful archive build.
pub struct BuildResult {
    /// Destination path of the `.zip` file.
    pub path: PathBuf,
    /// Manifest embedded in the archive.
    pub manifest: DiagnosticArchiveManifest,
    /// Approximate size of the resulting zip file (bytes).
    pub size_bytes: u64,
}

// ── ArchiveBuilder ────────────────────────────────────────────────────────────

/// Stateless archive builder.  All state lives on the stack or in `input`.
pub struct ArchiveBuilder;

impl ArchiveBuilder {
    /// Builds a diagnostic archive at `dest_path`.
    ///
    /// Uses a temp directory for staging.  The temp directory is always
    /// cleaned up, regardless of whether the build succeeds or fails.
    ///
    /// # Errors
    ///
    /// Returns `DiagnosticsError::ExportFailed` on any I/O or serialization error.
    pub fn build(input: ArchiveInput, dest_path: &Path) -> DiagnosticsResult<BuildResult> {
        // Create temp directory (cleaned up via Drop).
        let temp_dir = tempfile::tempdir().map_err(|e| DiagnosticsError::ExportFailed {
            reason: format!("cannot create temp dir: {e}"),
        })?;

        // Write section files.
        let staged = write_sections(&input, temp_dir.path())?;
        let mut sections_written = staged.files;
        if input
            .request
            .all_sections()
            .contains(&ArchiveSection::RedactionReport)
        {
            sections_written.push(write_redaction_report(
                &input,
                temp_dir.path(),
                &sections_written,
            )?);
        }

        // Build manifest.
        let created_at = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);

        let manifest = DiagnosticArchiveManifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
            created_at,
            app_version: input.request.app_version.clone(),
            redaction_mode: redaction_mode_slug(input.request.redaction_mode),
            included_sections: sections_written.clone(),
            // What the archive CARRIES, not what was offered: both sections
            // are capped as they are staged.
            log_entry_count: staged.log_entries,
            audit_entry_count: staged.audit_entries,
            // The manifest lives INSIDE the zip, so it cannot state the zip's
            // own size. What it can state truthfully is the staged content it
            // describes; the compressed size comes back in `BuildResult`.
            total_size_bytes_approx: staged_bytes(temp_dir.path()),
            contains_diagnostic_detail: input.request.redaction_mode
                > crate::privacy::RedactionMode::Default,
            no_backup_guarantee: DiagnosticArchiveManifest::NO_BACKUP_GUARANTEE.to_string(),
            build_commit: DiagnosticArchiveManifest::BUILD_COMMIT.to_string(),
            build_profile: DiagnosticArchiveManifest::BUILD_PROFILE.to_string(),
            build_target: DiagnosticArchiveManifest::BUILD_TARGET.to_string(),
        };

        // Validate manifest before packaging.
        manifest
            .validate()
            .map_err(|e| DiagnosticsError::ExportFailed {
                reason: format!("manifest validation failed: {e}"),
            })?;

        // Write manifest.json.
        let manifest_json = serde_json::to_string_pretty(&manifest).map_err(|e| {
            DiagnosticsError::ExportFailed {
                reason: format!("manifest serialization failed: {e}"),
            }
        })?;
        std::fs::write(temp_dir.path().join("manifest.json"), &manifest_json).map_err(|e| {
            DiagnosticsError::ExportFailed {
                reason: format!("cannot write manifest.json: {e}"),
            }
        })?;

        // Package into zip.
        let size_bytes = write_zip(temp_dir.path(), dest_path)?;

        // Temp dir is dropped and cleaned up here.
        drop(temp_dir);

        Ok(BuildResult {
            path: dest_path.to_path_buf(),
            manifest,
            size_bytes,
        })
    }
}

// ── Section writers ───────────────────────────────────────────────────────────

/// Name of the captured-stderr section inside the archive.
const SERVICE_STDERR_FILENAME: &str = "nrr_service_stderr.log";
/// Directory the service's own log files are shipped in, one file per
/// rotation exactly as it sits on disk. A day of logs is several files, and
/// which file a line came from is how a reader navigates it — the single
/// flattened `service-logs.ndjson` this replaces threw that away, and with it
/// any sense of where one run ended and the next began.
pub(crate) const SERVICE_LOGS_DIRNAME: &str = "service-logs";

/// Room left for the sections written after the logs (captured stderr, the
/// redaction report) once the raw log files have taken their share.
const TAIL_SECTION_HEADROOM_BYTES: u64 = 1024 * 1024;

/// What the staged sections actually carry.
///
/// The counts are read off the files that were written, not off what the
/// caller offered: both `logs.ndjson` and `audit_summary.json` are capped as
/// they are staged (a byte budget and an entry cap), so the offered figure
/// describes an archive nobody received. A manifest that overstates its own
/// contents sends a triager looking for lines that were never shipped.
#[derive(Default)]
struct StagedSections {
    files: Vec<String>,
    log_entries: u32,
    audit_entries: u32,
}

/// The raw log files carry every line `logs.ndjson` would list, payloads
/// included, so the listing is not written beside them.
fn raw_logs_replace_listing(input: &ArchiveInput) -> bool {
    !input.raw_log_files.is_empty()
}

/// `name` reduced to a bare file name: the names come from our own log
/// directory, but they still end up joined to a path.
fn bare_file_name(name: &str) -> String {
    std::path::Path::new(name)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn write_sections(input: &ArchiveInput, dir: &Path) -> DiagnosticsResult<StagedSections> {
    let mut staged = StagedSections::default();
    let written = &mut staged.files;

    for section in input.request.all_sections() {
        // The report describes the sections around it, so it is written last,
        // once there is something to describe.
        if section == ArchiveSection::RedactionReport {
            continue;
        }
        if section == ArchiveSection::Logs && raw_logs_replace_listing(input) {
            continue;
        }
        let outcome = write_section(input, dir, section)?;
        if let Some(entries) = outcome.entries {
            match section {
                ArchiveSection::Logs => staged.log_entries = entries,
                ArchiveSection::AuditSummary => staged.audit_entries = entries,
                _ => {}
            }
        }
        if outcome.written {
            written.push(section.filename().to_string());
        }
    }

    // Also not an `ArchiveSection`: the service's own log lines, verbatim —
    // what a support bundle is read for. They replace `logs.ndjson`, which would
    // only repeat them without payloads, so the manifest counts them instead.
    // They used to be appended by the launcher reading the log directory off
    // disk — which is why that directory had to be readable by every account on
    // the machine, and why one user's bundle carried everyone's lines.
    if !input.raw_log_files.is_empty() {
        let log_dir = dir.join(SERVICE_LOGS_DIRNAME);
        std::fs::create_dir_all(&log_dir).map_err(|e| DiagnosticsError::ExportFailed {
            reason: format!("cannot create {SERVICE_LOGS_DIRNAME}: {e}"),
        })?;
        // How much of the log history a user gets is THEIR choice — the
        // facade already trimmed these files to the budget the diagnostics
        // panel names (`0` there means unlimited, and it must keep meaning it).
        // The only bound applied here is the archive's own hard cap: without
        // it, a full-history export of a large log directory fails outright and
        // the user ends up with nothing instead of a slightly shorter bundle.
        // Newest first, so what drops is the oldest end.
        let already_staged = staged_bytes(dir);
        let cap = crate::archive::request::MAX_ARCHIVE_SIZE_BYTES
            .saturating_sub(already_staged)
            .saturating_sub(TAIL_SECTION_HEADROOM_BYTES);
        let mut used: u64 = 0;
        for file in input.raw_log_files.iter().rev() {
            let name = bare_file_name(&file.name);
            if name.is_empty() {
                continue;
            }
            let mut content = String::new();
            for line in &file.lines {
                content.push_str(line);
                content.push('\n');
            }
            let size = content.len() as u64;
            // The newest file always ships whole: half a file is not evidence.
            if used > 0 && used + size > cap {
                break;
            }
            used += size;
            std::fs::write(log_dir.join(&name), content).map_err(|e| {
                DiagnosticsError::ExportFailed {
                    reason: format!("cannot write {SERVICE_LOGS_DIRNAME}/{name}: {e}"),
                }
            })?;
            written.push(format!("{SERVICE_LOGS_DIRNAME}/{name}"));
            staged.log_entries += file.lines.len() as u32;
        }
    }

    // Not an `ArchiveSection`: it is not a rendering of our own data but a
    // verbatim copy of what the process wrote on its way down, present only
    // when there was something to copy. A crash report with the crash missing
    // is the one thing this archive must not be.
    if let Some(text) = input
        .service_stderr
        .as_deref()
        .filter(|t| !t.trim().is_empty())
    {
        let text =
            crate::privacy::redact::mask_user_paths_in_text(text, input.request.redaction_mode);
        std::fs::write(dir.join(SERVICE_STDERR_FILENAME), text).map_err(|e| {
            DiagnosticsError::ExportFailed {
                reason: format!("cannot write {SERVICE_STDERR_FILENAME}: {e}"),
            }
        })?;
        written.push(SERVICE_STDERR_FILENAME.to_string());
    }

    for log in &input.broker_logs {
        let name = bare_file_name(&log.name);
        if name.is_empty() || log.text.trim().is_empty() {
            continue;
        }
        let text = crate::privacy::redact::mask_user_paths_in_text(
            &log.text,
            input.request.redaction_mode,
        );
        std::fs::write(dir.join(&name), text).map_err(|e| DiagnosticsError::ExportFailed {
            reason: format!("cannot write {name}: {e}"),
        })?;
        written.push(name);
    }

    Ok(staged)
}

/// One section's contribution: whether its file was staged, and — for the two
/// sections the manifest counts — how many entries it actually carries.
#[derive(Default)]
struct SectionWrite {
    written: bool,
    entries: Option<u32>,
}

impl SectionWrite {
    const SKIPPED: Self = Self {
        written: false,
        entries: None,
    };

    const fn staged() -> Self {
        Self {
            written: true,
            entries: None,
        }
    }

    const fn staged_with(entries: u32) -> Self {
        Self {
            written: true,
            entries: Some(entries),
        }
    }
}

fn write_section(
    input: &ArchiveInput,
    dir: &Path,
    section: ArchiveSection,
) -> DiagnosticsResult<SectionWrite> {
    let path = dir.join(section.filename());
    match section {
        ArchiveSection::Health => {
            // Merge `health` (the live DiagnosticsStatusDto snapshot) with
            // `health_enrichment` (behavior mode / state-schema version /
            // adapters snapshot) into a single flat JSON object. Both sides
            // serialize as objects; enrichment keys are only present when
            // populated (`skip_serializing_if = "Option::is_none"`), so an
            // unpopulated enrichment DTO leaves `health.json` byte-identical
            // to the pre-enrichment shape.
            let mut merged = serde_json::to_value(&input.health).map_err(ser_err)?;
            let mut enrichment_dto = input.health_enrichment.clone();
            if let Some(snapshot) = enrichment_dto.adapters_snapshot.as_mut() {
                redact_adapters_snapshot(snapshot, input.request.redaction_mode);
            }
            let enrichment = serde_json::to_value(&enrichment_dto).map_err(ser_err)?;
            if let (serde_json::Value::Object(base), serde_json::Value::Object(extra)) =
                (&mut merged, enrichment)
            {
                base.extend(extra);
            }
            let json = serde_json::to_string_pretty(&merged).map_err(ser_err)?;
            write_file(&path, json.as_bytes())?;
        }
        ArchiveSection::Logs => {
            // Cap `logs.ndjson` by BYTES (5 MiB default), not
            // a fixed entry count: the archive is compressed, so a byte budget
            // gives far more history at trivial on-disk cost. `max_log_entries`
            // remains a hard safety ceiling. Entries are taken in the order the
            // caller supplied (the handler passes the facade's recent-first
            // page), so the newest lines are kept; the tail beyond the budget is
            // dropped.
            let mut content = String::new();
            let mut entries: u32 = 0;
            let budget = input.request.max_log_bytes as usize;
            // Session-only trimming: entries older than
            // `logs_from_ms` (when set) never enter the archive, regardless of
            // the entry/byte budgets. `logs_to_ms` closes the window the same
            // way for completeness.
            let from = input.request.logs_from_ms;
            let to = input.request.logs_to_ms;
            for entry in input
                .log_entries
                .iter()
                .filter(|entry| from.is_none_or(|ms| entry.created_at >= ms))
                .filter(|entry| to.is_none_or(|ms| entry.created_at <= ms))
                .take(input.request.max_log_entries as usize)
            {
                let line = serde_json::to_string(entry).map_err(ser_err)?;
                // Always allow the first line; then stop before overrunning the
                // byte budget (accounting for the trailing newline).
                if !content.is_empty() && content.len() + line.len() + 1 > budget {
                    break;
                }
                content.push_str(&line);
                content.push('\n');
                entries += 1;
            }
            write_file(&path, content.as_bytes())?;
            return Ok(SectionWrite::staged_with(entries));
        }
        ArchiveSection::SystemInfo => {
            // Host OS/CPU/RAM + our app version. Best-effort: when the collector
            // was unavailable, still emit the section with the app version and
            // an availability flag so the archive shape is stable.
            let payload = match &input.system_info {
                Some(si) => json!({
                    "app_version": input.request.app_version,
                    "system_info_available": true,
                    "os": si.os,
                    "os_version": si.os_version,
                    "arch": si.arch,
                    "cpu_model": si.cpu_model,
                    "cpu_logical_cores": si.cpu_logical_cores,
                    "total_ram_bytes": si.total_ram_bytes,
                }),
                None => json!({
                    "app_version": input.request.app_version,
                    "system_info_available": false,
                }),
            };
            write_file(
                &path,
                serde_json::to_string_pretty(&payload)
                    .map_err(ser_err)?
                    .as_bytes(),
            )?;
        }
        ArchiveSection::AuditSummary => {
            let entries: Vec<&AuditEntryDto> = input
                .audit_entries
                .iter()
                .take(input.request.max_audit_entries as usize)
                .collect();
            let json = serde_json::to_string_pretty(&entries).map_err(ser_err)?;
            write_file(&path, json.as_bytes())?;
            return Ok(SectionWrite::staged_with(entries.len() as u32));
        }
        ArchiveSection::AuditChain => {
            // Nothing to ship: the caller withholds the raw chain from an
            // export it may not verify (a subset of a hash chain proves
            // nothing). Say the section is ABSENT rather than shipping a zero-
            // byte file the reader has to interpret — the redaction report
            // lists what is missing, and "not here" is a fact, while "here but
            // empty" could mean unreadable, truncated or genuinely nothing.
            if input.audit_chain_lines.is_empty() {
                return Ok(SectionWrite::SKIPPED);
            }
            // Raw audit NDJSON verbatim (chain fields intact). The caller only
            // supplies lines for a Diagnostics/DeveloperLocal export, and this
            // section is only in that tier's set — a default export never
            // reaches here. Lines arrive oldest-first (a contiguous chain
            // suffix); write them within the byte budget, keeping the newest
            // when over. The first line is always allowed so the section is
            // never empty when input exists.
            let mut content = String::new();
            let budget = input.request.max_audit_chain_bytes as usize;
            for line in &input.audit_chain_lines {
                if !content.is_empty() && content.len() + line.len() + 1 > budget {
                    break;
                }
                content.push_str(line);
                content.push('\n');
            }
            write_file(&path, content.as_bytes())?;
        }
        ArchiveSection::ExplainSamples => {
            // Same rule as the chain above: an empty `[]` reads as an answer,
            // and it is not one.
            if input.explain_samples.is_empty() {
                return Ok(SectionWrite::SKIPPED);
            }
            let json = serde_json::to_string_pretty(&input.explain_samples).map_err(ser_err)?;
            write_file(&path, json.as_bytes())?;
        }
        ArchiveSection::CacheHealth => {
            let summary = json!({
                "healthy": input.health.cache_health.healthy,
                "entry_count": input.health.cache_health.entry_count,
            });
            write_file(
                &path,
                serde_json::to_string_pretty(&summary)
                    .map_err(ser_err)?
                    .as_bytes(),
            )?;
        }
        ArchiveSection::StorageHealth => {
            let summary = json!({
                "logs_dir_writable": input.health.log_health.dir_writable,
                "log_file_count": input.health.log_health.file_count,
                "log_total_size_bytes": input.health.log_health.total_size_bytes,
                "dropped_count": input.health.log_health.dropped_count,
                "audit_chain_ok": input.health.security_status.audit_chain_ok,
            });
            write_file(
                &path,
                serde_json::to_string_pretty(&summary)
                    .map_err(ser_err)?
                    .as_bytes(),
            )?;
        }
        ArchiveSection::Troubleshooting => {
            let playbooks = all_playbooks();
            let md = render_playbooks_markdown(&playbooks);
            write_file(&path, md.as_bytes())?;
        }
        ArchiveSection::RedactionReport => {
            // Written by `write_redaction_report` after the other sections
            // exist; there is nothing to measure before then.
            return Ok(SectionWrite::SKIPPED);
        }
    }
    Ok(SectionWrite::staged())
}

/// Writes `redaction_report.json` from what the staged sections actually
/// contain.
///
/// The counters are measured, not asserted: they count the redaction MARKERS
/// present in the staged files. A hostname shortened to eTLD+1 leaves no
/// marker and is therefore not counted — `redaction_mode` is what states that
/// shortening was applied. Reporting a measured floor beats the flat zeros
/// this section carried before, which told the reader the opposite of the
/// truth.
fn write_redaction_report(
    input: &ArchiveInput,
    dir: &Path,
    sections_written: &[String],
) -> DiagnosticsResult<String> {
    let counts = count_markers(dir);
    let excluded: Vec<String> = ArchiveSection::ALL
        .iter()
        .map(|s| s.filename())
        .filter(|name| {
            *name != ArchiveSection::RedactionReport.filename()
                && !sections_written.iter().any(|w| w == name)
                // Replaced by the raw files, not withheld.
                && !(*name == ArchiveSection::Logs.filename() && raw_logs_replace_listing(input))
        })
        .map(|name| name.to_string())
        .collect();

    let report = RedactionReport {
        redaction_mode: redaction_mode_slug(input.request.redaction_mode),
        diagnostic_mode_active: input.health.diagnostic_mode.active,
        hostnames_redacted: counts.hostnames,
        ips_redacted: counts.ips,
        paths_redacted: counts.paths,
        excluded_sections: excluded,
        always_hidden_fields: RedactionReport::always_hidden(),
    };
    let json = serde_json::to_string_pretty(&report).map_err(ser_err)?;
    let name = ArchiveSection::RedactionReport.filename();
    write_file(&dir.join(name), json.as_bytes())?;
    Ok(name.to_string())
}

#[derive(Default)]
struct MarkerCounts {
    hostnames: u32,
    ips: u32,
    paths: u32,
}

fn count_markers(dir: &Path) -> MarkerCounts {
    use crate::privacy::redact::{
        MARKER_MASKED_IPV4, MARKER_MASKED_PATH, MARKER_PRIVATE_IPV4, MARKER_PUBLIC_IPV4,
        MARKER_REDACTED,
    };

    let mut counts = MarkerCounts::default();
    // Every staged file, subdirectories included — the service's own logs ship
    // as one, and a report that skipped them would undercount what it claims to
    // describe.
    for (name, _) in staged_files(dir) {
        let Ok(text) = std::fs::read_to_string(dir.join(name)) else {
            continue;
        };
        counts.hostnames += text.matches(MARKER_REDACTED).count() as u32;
        counts.ips += (text.matches(MARKER_MASKED_IPV4).count()
            + text.matches(MARKER_PRIVATE_IPV4).count()
            + text.matches(MARKER_PUBLIC_IPV4).count()) as u32;
        counts.paths += text.matches(MARKER_MASKED_PATH).count() as u32;
    }
    counts
}

fn redaction_mode_slug(mode: crate::privacy::RedactionMode) -> String {
    match mode {
        crate::privacy::RedactionMode::Default => "default".into(),
        crate::privacy::RedactionMode::Diagnostics => "diagnostics".into(),
        crate::privacy::RedactionMode::DeveloperLocal => "developer_local".into(),
    }
}

/// Reduces the adapter snapshot embedded in `health.json` to what the chosen
/// redaction mode allows.
///
/// The snapshot carries MAC addresses, local addresses, gateways and DNS
/// servers, and it went into every default export untouched while the
/// manifest in the same zip promised no credential-like content. The adapter
/// redaction helper written for exactly this shape had no production caller.
fn redact_adapters_snapshot(
    snapshot: &mut nrr_shared::ipc_payloads::SnapshotInterfacesResponse,
    mode: crate::privacy::RedactionMode,
) {
    use crate::privacy::redact::{redact_adapter_id, redact_ipv4_str};

    if mode.shows_ip() {
        return;
    }
    let hide_addresses = |value: &mut String| {
        // A field can hold several addresses (`dns_servers` is a joined list);
        // redact each so one unparseable entry does not leak the rest.
        *value = value
            .split(&[',', ' '][..])
            .filter(|part| !part.is_empty())
            .map(|part| redact_ipv4_str(part, mode).display_or_marker())
            .collect::<Vec<_>>()
            .join(", ");
    };

    for adapter in &mut snapshot.adapters {
        adapter.persistent_id =
            redact_adapter_id(&adapter.persistent_id, Some(&adapter.adapter_name), mode)
                .display_or_marker();
        adapter.physical_address = None;
    }
    for row in &mut snapshot.rows {
        row.persistent_id = redact_adapter_id(&row.persistent_id, Some(&row.adapter_name), mode)
            .display_or_marker();
        hide_addresses(&mut row.local_ip);
        hide_addresses(&mut row.gateway);
        hide_addresses(&mut row.dns_servers);
    }
}

fn write_file(path: &Path, content: &[u8]) -> DiagnosticsResult<()> {
    std::fs::write(path, content).map_err(|e| DiagnosticsError::ExportFailed {
        reason: format!("cannot write {}: {e}", path.display()),
    })
}

fn ser_err(e: serde_json::Error) -> DiagnosticsError {
    DiagnosticsError::ExportFailed {
        reason: format!("serialization error: {e}"),
    }
}

// ── ZIP packaging ─────────────────────────────────────────────────────────────

/// Returns the current wall-clock time, converted to a `zip::DateTime`.
///
/// The ZIP format's MS-DOS date/time fields carry no timezone: extractors
/// render whatever value is stored as local time. Stamping entries with the
/// machine's local time (rather than UTC) is what makes the displayed
/// modified time match the user's clock. Falls back to the zip crate's
/// built-in default (UTC "now", or the 1980 epoch if even that is
/// unavailable) if the local time cannot be represented in the DOS
/// date/time range.
fn local_zip_timestamp() -> zip::DateTime {
    let now = chrono::Local::now();
    zip::DateTime::from_date_and_time(
        // `from_date_and_time` accepts years [1980, 2107]; `chrono::Datelike::year`
        // returns `i32`, so an out-of-range value is rejected by the `u16`
        // conversion rather than silently wrapping.
        match u16::try_from(now.year()) {
            Ok(year) => year,
            Err(_) => return zip::DateTime::default_for_write(),
        },
        now.month() as u8,
        now.day() as u8,
        now.hour() as u8,
        now.minute() as u8,
        now.second() as u8,
    )
    .unwrap_or_else(|_| zip::DateTime::default_for_write())
}

/// Total uncompressed size of everything staged for the archive.
fn staged_bytes(dir: &Path) -> u64 {
    staged_files(dir).iter().map(|(_, size)| size).sum()
}

/// Every staged file as `(path relative to the staging root, size)`, sorted so
/// a build is reproducible. Recursive because the service's own logs ship as a
/// directory; a flat walk would silently drop them from both the size figure
/// and the zip.
fn staged_files(dir: &Path) -> Vec<(String, u64)> {
    fn walk(root: &Path, dir: &Path, out: &mut Vec<(String, u64)>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if path.is_dir() {
                walk(root, &path, out);
                continue;
            }
            let Ok(relative) = path.strip_prefix(root) else {
                continue;
            };
            // Zip entries are separated by '/' on every platform.
            let name = relative.to_string_lossy().replace('\\', "/");
            let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
            out.push((name, size));
        }
    }

    let mut out = Vec::new();
    walk(dir, dir, &mut out);
    out.sort();
    out
}

/// Packages `source_dir` into `dest_path`.
///
/// Built under a `.part` name and renamed on success: `File::create` truncates
/// its target up front, so writing straight to `dest_path` meant any failure
/// mid-build — including hitting the size cap — left the user a truncated,
/// unopenable zip that archive retention then counted as a good one and
/// evicted a valid archive to make room for.
fn write_zip(source_dir: &Path, dest_path: &Path) -> DiagnosticsResult<u64> {
    let partial = dest_path.with_extension("part");
    match write_zip_into(source_dir, &partial) {
        Ok(()) => {
            std::fs::rename(&partial, dest_path).map_err(|e| DiagnosticsError::ExportFailed {
                reason: format!("cannot publish archive: {e}"),
            })?;
            Ok(std::fs::metadata(dest_path).map(|m| m.len()).unwrap_or(0))
        }
        Err(e) => {
            let _ = std::fs::remove_file(&partial);
            Err(e)
        }
    }
}

fn write_zip_into(source_dir: &Path, dest_path: &Path) -> DiagnosticsResult<()> {
    if let Some(parent) = dest_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| DiagnosticsError::ExportFailed {
            reason: format!("cannot create dest dir: {e}"),
        })?;
    }

    let file = std::fs::File::create(dest_path).map_err(|e| DiagnosticsError::ExportFailed {
        reason: format!("cannot create zip file: {e}"),
    })?;

    let mut zip = zip::ZipWriter::new(file);
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .last_modified_time(local_zip_timestamp());

    let mut total_uncompressed = 0u64;

    for (file_name_str, size) in staged_files(source_dir) {
        let file_path = source_dir.join(&file_name_str);

        // Check the budget against the file's LENGTH before reading it: a guard
        // that first pulls the oversized file into memory does not guard
        // against what it names.
        total_uncompressed += size;
        if total_uncompressed > crate::archive::request::MAX_ARCHIVE_SIZE_BYTES {
            return Err(DiagnosticsError::ExportFailed {
                reason: format!(
                    "archive exceeds maximum size of {} bytes",
                    crate::archive::request::MAX_ARCHIVE_SIZE_BYTES
                ),
            });
        }

        let content = std::fs::read(&file_path).map_err(|e| DiagnosticsError::ExportFailed {
            reason: format!("cannot read {}: {e}", file_path.display()),
        })?;

        zip.start_file(file_name_str.as_str(), options)
            .map_err(|e| DiagnosticsError::ExportFailed {
                reason: format!("cannot add {file_name_str} to zip: {e}"),
            })?;
        zip.write_all(&content)
            .map_err(|e| DiagnosticsError::ExportFailed {
                reason: format!("cannot write {file_name_str} to zip: {e}"),
            })?;
    }

    zip.finish().map_err(|e| DiagnosticsError::ExportFailed {
        reason: format!("cannot finalize zip: {e}"),
    })?;

    Ok(())
}

#[cfg(test)]
mod tests;
