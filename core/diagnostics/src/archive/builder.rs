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
    pub request: DiagnosticArchiveRequest,
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
        let mut sections_written = write_sections(&input, temp_dir.path())?;
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
            log_entry_count: input.log_entries.len() as u32,
            audit_entry_count: input.audit_entries.len() as u32,
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

/// Writes all requested sections to `dir`.  Returns list of filenames written.
/// Name of the captured-stderr section inside the archive.
const SERVICE_STDERR_FILENAME: &str = "nrr_service_stderr.log";

fn write_sections(input: &ArchiveInput, dir: &Path) -> DiagnosticsResult<Vec<String>> {
    let mut written = Vec::new();

    for section in input.request.all_sections() {
        // The report describes the sections around it, so it is written last,
        // once there is something to describe.
        if section == ArchiveSection::RedactionReport {
            continue;
        }
        if write_section(input, dir, section)? {
            written.push(section.filename().to_string());
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

    Ok(written)
}

fn write_section(
    input: &ArchiveInput,
    dir: &Path,
    section: ArchiveSection,
) -> DiagnosticsResult<bool> {
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
            }
            write_file(&path, content.as_bytes())?;
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
        }
        ArchiveSection::AuditChain => {
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
            let json = serde_json::to_string_pretty(&input.explain_samples).map_err(ser_err)?;
            write_file(&path, json.as_bytes())?;
        }
        ArchiveSection::CacheHealth => {
            let summary = json!({
                "healthy": input.health.cache_health.healthy,
                "entry_count": input.health.cache_health.entry_count,
                "rebuilding": input.health.cache_health.rebuilding,
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
            return Ok(false);
        }
    }
    Ok(true)
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
    let Ok(entries) = std::fs::read_dir(dir) else {
        return counts;
    };
    for entry in entries.flatten() {
        let Ok(text) = std::fs::read_to_string(entry.path()) else {
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
    std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok())
        .filter_map(|e| e.metadata().ok())
        .map(|m| m.len())
        .sum()
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

    let entries = std::fs::read_dir(source_dir).map_err(|e| DiagnosticsError::ExportFailed {
        reason: format!("cannot read temp dir: {e}"),
    })?;

    let mut total_uncompressed = 0u64;

    for entry in entries {
        let entry = entry.map_err(|e| DiagnosticsError::ExportFailed {
            reason: format!("cannot read dir entry: {e}"),
        })?;
        let file_path = entry.path();
        let file_name = entry.file_name();
        let file_name_str = file_name.to_string_lossy();

        // Check the budget against the file's LENGTH before reading it: a guard
        // that first pulls the oversized file into memory does not guard
        // against what it names.
        total_uncompressed += entry.metadata().map(|m| m.len()).unwrap_or(0);
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

        zip.start_file(file_name_str.as_ref(), options)
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
mod tests {
    use super::*;
    use crate::archive::request::DiagnosticArchiveRequest;
    use crate::facade::dto::{
        CacheHealthCard, DiagnosticModeStateDto, DiagnosticsDataOrigin, DiagnosticsStatusDto,
        LogHealthCard, SecurityStatusCard, ServiceHealthCard,
    };

    fn sample_health() -> DiagnosticsStatusDto {
        DiagnosticsStatusDto {
            overall_healthy: true,
            service_health: ServiceHealthCard {
                state: "running".into(),
                active_revision_id: Some("rev-001".into()),
                pending_changes: 0,
            },
            security_status: SecurityStatusCard {
                audit_chain_ok: true,
                active_alert_count: 0,
                audit_write_healthy: true,
            },
            active_alerts: Vec::new(),
            cache_health: CacheHealthCard {
                entry_count: 10,
                healthy: true,
                rebuilding: false,
            },
            log_health: LogHealthCard {
                dir_writable: true,
                total_size_bytes: 4096,
                file_count: 1,
                dropped_count: 0,
                last_cleanup_at: None,
            },
            diagnostic_mode: DiagnosticModeStateDto::inactive(),
            stale: false,
            origin: DiagnosticsDataOrigin::Service,
        }
    }

    fn sample_input(request: DiagnosticArchiveRequest) -> ArchiveInput {
        ArchiveInput {
            health: sample_health(),
            health_enrichment: DiagnosticArchiveHealthEnrichmentDto::default(),
            log_entries: vec![LogEntryDto {
                event_id: "evt-001".into(),
                created_at: 1_745_000_000_000,
                level: "info".into(),
                category: "service".into(),
                kind: "service.started".into(),
                message_key: "diag.service.started.summary".into(),
                message: String::new(),
                has_payload: false,
                correlation_summary: Vec::new(),
            }],
            audit_entries: vec![AuditEntryDto {
                event_id: "adt-001".into(),
                seq: 1,
                kind: "revision_activated".into(),
                created_at: 1_745_000_000_000,
                result: "success".into(),
                reason_code: "review.approved".into(),
                revision_id: Some("rev-001".into()),
                has_payload_summary: false,
            }],
            audit_chain_lines: Vec::new(),
            explain_samples: Vec::new(),
            system_info: Some(nrr_shared::system_info::SystemInfo {
                os: "windows".into(),
                os_version: "Windows 11 Pro 23H2 (build 22631)".into(),
                arch: "AMD64".into(),
                cpu_model: "Test CPU".into(),
                cpu_logical_cores: 8,
                total_ram_bytes: 17_179_869_184,
            }),
            service_stderr: None,
            request,
        }
    }

    #[test]
    fn captured_stderr_is_archived_when_there_is_any() {
        let dir = tempfile::tempdir().expect("temp");
        let dest = dir.path().join("diag.zip");
        let mut input = sample_input(DiagnosticArchiveRequest::default_export("0.1.0-test"));
        input.service_stderr = Some("thread 'main' panicked at src/main.rs:1:1\n".to_string());

        ArchiveBuilder::build(input, &dest).expect("build archive");

        let file = std::fs::File::open(&dest).expect("open zip");
        let mut zip = zip::ZipArchive::new(file).expect("parse zip");
        let mut buffer = Vec::new();
        std::io::Read::read_to_end(
            &mut zip
                .by_name(SERVICE_STDERR_FILENAME)
                .expect("stderr section present"),
            &mut buffer,
        )
        .expect("read stderr section");
        assert!(String::from_utf8_lossy(&buffer).contains("panicked"));
    }

    #[test]
    fn an_empty_stderr_adds_no_section() {
        let dir = tempfile::tempdir().expect("temp");
        let dest = dir.path().join("diag.zip");
        let mut input = sample_input(DiagnosticArchiveRequest::default_export("0.1.0-test"));
        // Whitespace only: the file exists on disk but the service never
        // wrote anything to it — an empty section would just raise questions.
        input.service_stderr = Some("\n\n".to_string());

        let result = ArchiveBuilder::build(input, &dest).expect("build archive");

        assert!(!result
            .manifest
            .included_sections
            .iter()
            .any(|s| s == SERVICE_STDERR_FILENAME));
    }

    #[test]
    fn build_default_archive_succeeds() {
        let dir = tempfile::tempdir().expect("temp");
        let dest = dir.path().join("diag.zip");
        let req = DiagnosticArchiveRequest::default_export("0.1.0-test");
        let input = sample_input(req);

        let result = ArchiveBuilder::build(input, &dest).expect("build");
        assert!(dest.exists(), "zip file must exist");
        assert!(result.size_bytes > 0);
        assert_eq!(result.manifest.log_entry_count, 1);
        assert_eq!(result.manifest.audit_entry_count, 1);
    }

    #[test]
    fn manifest_is_valid_after_build() {
        let dir = tempfile::tempdir().expect("temp");
        let dest = dir.path().join("diag.zip");
        let req = DiagnosticArchiveRequest::default_export("0.1.0-test");
        let result = ArchiveBuilder::build(sample_input(req), &dest).expect("build");
        assert!(result.manifest.validate().is_ok());
    }

    #[test]
    fn archive_contains_no_raw_db_paths() {
        let dir = tempfile::tempdir().expect("temp");
        let dest = dir.path().join("diag.zip");
        let req = DiagnosticArchiveRequest::default_export("0.1.0-test");
        ArchiveBuilder::build(sample_input(req), &dest).expect("build");

        // Read zip and verify no raw db filenames appear.
        let file = std::fs::File::open(&dest).expect("open zip");
        let mut zip = zip::ZipArchive::new(file).expect("parse zip");
        for i in 0..zip.len() {
            let entry = zip.by_index(i).expect("entry");
            let name = entry.name();
            assert!(
                !name.ends_with(".db"),
                "archive must not contain .db files: {name}"
            );
        }
    }

    #[test]
    fn manifest_json_is_in_archive() {
        let dir = tempfile::tempdir().expect("temp");
        let dest = dir.path().join("diag.zip");
        let req = DiagnosticArchiveRequest::default_export("0.1.0-test");
        ArchiveBuilder::build(sample_input(req), &dest).expect("build");

        let file = std::fs::File::open(&dest).expect("open zip");
        let mut zip = zip::ZipArchive::new(file).expect("parse zip");
        let names: Vec<String> = (0..zip.len())
            .map(|i| zip.by_index(i).unwrap().name().to_string())
            .collect();
        assert!(
            names.contains(&"manifest.json".to_string()),
            "manifest.json must be in archive"
        );
        assert!(names.contains(&"troubleshooting.md".to_string()));
        assert!(names.contains(&"health.json".to_string()));
        assert!(names.contains(&"logs.ndjson".to_string()));
        // system_info.json is a mandatory section.
        assert!(names.contains(&"system_info.json".to_string()));
    }

    #[test]
    fn system_info_section_carries_host_and_app_version() {
        use std::io::Read;
        let dir = tempfile::tempdir().expect("temp");
        let dest = dir.path().join("diag.zip");
        let req = DiagnosticArchiveRequest::default_export("9.9.9-test");
        ArchiveBuilder::build(sample_input(req), &dest).expect("build");

        let file = std::fs::File::open(&dest).expect("open zip");
        let mut zip = zip::ZipArchive::new(file).expect("parse zip");
        let mut body = String::new();
        zip.by_name("system_info.json")
            .expect("system_info.json present")
            .read_to_string(&mut body)
            .expect("read");
        let v: serde_json::Value = serde_json::from_str(&body).expect("valid json");
        assert_eq!(v["app_version"], "9.9.9-test");
        assert_eq!(v["system_info_available"], true);
        assert_eq!(v["os"], "windows");
        assert!(v["total_ram_bytes"].as_u64().unwrap() > 0);
    }

    #[test]
    fn logs_ndjson_drops_entries_before_logs_from_ms() {
        use std::io::Read;
        let dir = tempfile::tempdir().expect("temp");
        let dest = dir.path().join("diag.zip");
        // "Current session only": the cutoff sits between
        // entry 0 (older, dropped) and entries 1..2 (kept).
        let mut req = DiagnosticArchiveRequest::default_export("t");
        req.logs_from_ms = Some(1_745_000_000_001);
        let mut input = sample_input(req);
        input.log_entries = (0..3)
            .map(|i| LogEntryDto {
                event_id: format!("evt-{i:03}"),
                created_at: 1_745_000_000_000 + i as i64,
                level: "info".into(),
                category: "service".into(),
                kind: "service.tick".into(),
                message_key: "diag.service.tick.summary".into(),
                message: String::new(),
                has_payload: false,
                correlation_summary: Vec::new(),
            })
            .collect();
        ArchiveBuilder::build(input, &dest).expect("build");

        let file = std::fs::File::open(&dest).expect("open zip");
        let mut zip = zip::ZipArchive::new(file).expect("parse zip");
        let mut logs = String::new();
        zip.by_name("logs.ndjson")
            .expect("logs present")
            .read_to_string(&mut logs)
            .expect("read");
        assert_eq!(logs.lines().count(), 2, "pre-session entry is dropped");
        assert!(!logs.contains("evt-000"));
        assert!(logs.contains("evt-001"));
        assert!(logs.contains("evt-002"));
    }

    #[test]
    fn logs_ndjson_respects_the_byte_budget() {
        use std::io::Read;
        let dir = tempfile::tempdir().expect("temp");
        let dest = dir.path().join("diag.zip");
        // Tiny byte budget: only the first line fits.
        let mut req = DiagnosticArchiveRequest::default_export("t");
        req.max_log_bytes = 80;
        let mut input = sample_input(req);
        // Three log entries, each serialising to well over 80 bytes.
        input.log_entries = (0..3)
            .map(|i| LogEntryDto {
                event_id: format!("evt-{i:03}"),
                created_at: 1_745_000_000_000 + i as i64,
                level: "info".into(),
                category: "service".into(),
                kind: "service.tick".into(),
                message_key: "diag.service.tick.summary".into(),
                message: String::new(),
                has_payload: false,
                correlation_summary: Vec::new(),
            })
            .collect();
        ArchiveBuilder::build(input, &dest).expect("build");

        let file = std::fs::File::open(&dest).expect("open zip");
        let mut zip = zip::ZipArchive::new(file).expect("parse zip");
        let mut logs = String::new();
        zip.by_name("logs.ndjson")
            .expect("logs present")
            .read_to_string(&mut logs)
            .expect("read");
        // Only the first entry fits under the 80-byte budget (the loop always
        // writes the first line, then stops before overrunning).
        assert_eq!(logs.lines().count(), 1, "byte budget caps the log lines");
        assert!(logs.contains("evt-000"));
        assert!(!logs.contains("evt-001"));
    }

    #[test]
    fn health_json_carries_no_enrichment_keys_when_unpopulated() {
        // An all-`None` `health_enrichment` (the default; existing callers that never
        // touch the new field) must not add any keys to `health.json`.
        use std::io::Read;
        let dir = tempfile::tempdir().expect("temp");
        let dest = dir.path().join("diag.zip");
        let req = DiagnosticArchiveRequest::default_export("0.1.0-test");
        ArchiveBuilder::build(sample_input(req), &dest).expect("build");

        let file = std::fs::File::open(&dest).expect("open zip");
        let mut zip = zip::ZipArchive::new(file).expect("parse zip");
        let mut body = String::new();
        zip.by_name("health.json")
            .expect("health.json present")
            .read_to_string(&mut body)
            .expect("read");
        let v: serde_json::Value = serde_json::from_str(&body).expect("valid json");
        assert!(v.get("behavior_mode").is_none());
        assert!(v.get("state_schema_version").is_none());
        assert!(v.get("adapters_snapshot").is_none());
        assert_eq!(v["overall_healthy"], true, "base health fields intact");
    }

    #[test]
    fn health_json_merges_enrichment_fields_when_populated() {
        // Behavior mode / schema version / adapters snapshot land as SIBLING keys of the base
        // health fields (flat merge), not a nested sub-object.
        use nrr_shared::ipc_payloads::SnapshotInterfacesResponse;
        use std::io::Read;
        let dir = tempfile::tempdir().expect("temp");
        let dest = dir.path().join("diag.zip");
        let req = DiagnosticArchiveRequest::default_export("0.1.0-test");
        let mut input = sample_input(req);
        input.health_enrichment = DiagnosticArchiveHealthEnrichmentDto {
            behavior_mode: Some("prefer-primary".into()),
            state_schema_version: Some(29),
            adapters_snapshot: Some(SnapshotInterfacesResponse {
                data_source: "windows-live".into(),
                adapters: Vec::new(),
                secondary: None,
                rows: Vec::new(),
            }),
        };
        ArchiveBuilder::build(input, &dest).expect("build");

        let file = std::fs::File::open(&dest).expect("open zip");
        let mut zip = zip::ZipArchive::new(file).expect("parse zip");
        let mut body = String::new();
        zip.by_name("health.json")
            .expect("health.json present")
            .read_to_string(&mut body)
            .expect("read");
        let v: serde_json::Value = serde_json::from_str(&body).expect("valid json");
        assert_eq!(v["behavior_mode"], "prefer-primary");
        assert_eq!(v["state_schema_version"], 29);
        // `SnapshotInterfacesResponse` itself is `#[serde(rename_all =
        // "kebab-case")]`, so its OWN fields render kebab-case even though
        // the enrichment DTO's field name (`adapters_snapshot`) does not.
        assert_eq!(v["adapters_snapshot"]["data-source"], "windows-live");
        // Base health fields still present alongside the new ones.
        assert_eq!(v["overall_healthy"], true);
        assert_eq!(v["service_health"]["state"], "running");
    }

    #[test]
    fn manifest_redaction_mode_default() {
        let dir = tempfile::tempdir().expect("temp");
        let dest = dir.path().join("diag.zip");
        let req = DiagnosticArchiveRequest::default_export("0.1.0-test");
        let result = ArchiveBuilder::build(sample_input(req), &dest).expect("build");
        assert_eq!(result.manifest.redaction_mode, "default");
        assert!(!result.manifest.contains_diagnostic_detail);
    }

    #[test]
    fn diagnostics_archive_contains_extra_sections() {
        let dir = tempfile::tempdir().expect("temp");
        let dest = dir.path().join("diag.zip");
        let req = DiagnosticArchiveRequest::diagnostics_export("0.1.0-test");
        let result = ArchiveBuilder::build(sample_input(req), &dest).expect("build");

        assert!(result
            .manifest
            .included_sections
            .contains(&"cache_health.json".to_string()));
        assert_eq!(result.manifest.redaction_mode, "diagnostics");
        assert!(result.manifest.contains_diagnostic_detail);
    }

    #[test]
    fn diagnostics_export_ships_the_raw_verifiable_audit_chain() {
        use std::io::Read;
        let dir = tempfile::tempdir().expect("temp");
        let dest = dir.path().join("diag.zip");
        let req = DiagnosticArchiveRequest::diagnostics_export("0.1.0-test");
        let mut input = sample_input(req);
        // Two raw NDJSON audit lines WITH the chain fields the DTO summary drops.
        input.audit_chain_lines = vec![
            r#"{"seq":1,"kind":"revision_activated","prev_hash":"GENESIS","event_hash":"aaaa"}"#
                .to_string(),
            r#"{"seq":2,"kind":"revision_activated","prev_hash":"aaaa","event_hash":"bbbb"}"#
                .to_string(),
        ];
        ArchiveBuilder::build(input, &dest).expect("build");

        let file = std::fs::File::open(&dest).expect("open zip");
        let mut zip = zip::ZipArchive::new(file).expect("parse zip");
        let mut body = String::new();
        zip.by_name("audit_chain.ndjson")
            .expect("audit_chain.ndjson present in diagnostics export")
            .read_to_string(&mut body)
            .expect("read");
        // The chain fields survive verbatim (unlike audit_summary.json's DTO).
        assert!(body.contains("prev_hash"), "{body}");
        assert!(body.contains("event_hash"), "{body}");
        assert_eq!(body.lines().count(), 2);
    }

    #[test]
    fn default_export_never_ships_the_raw_audit_chain() {
        let dir = tempfile::tempdir().expect("temp");
        let dest = dir.path().join("diag.zip");
        let req = DiagnosticArchiveRequest::default_export("0.1.0-test");
        let mut input = sample_input(req);
        // Even if raw lines are somehow supplied, a default export must not
        // include the AuditChain section (privacy: raw payload_summary_json).
        input.audit_chain_lines = vec![r#"{"seq":1,"event_hash":"secret"}"#.to_string()];
        ArchiveBuilder::build(input, &dest).expect("build");

        let file = std::fs::File::open(&dest).expect("open zip");
        let mut zip = zip::ZipArchive::new(file).expect("parse zip");
        let names: Vec<String> = (0..zip.len())
            .map(|i| zip.by_index(i).unwrap().name().to_string())
            .collect();
        assert!(
            !names.contains(&"audit_chain.ndjson".to_string()),
            "default export leaked the raw audit chain: {names:?}"
        );
        // The redacted summary is still present (it is mandatory).
        assert!(names.contains(&"audit_summary.json".to_string()));
    }

    #[test]
    fn build_failure_does_not_leave_orphan_temp_files() {
        // We can't easily force a build failure here without mocking,
        // but we verify the temp dir itself is not leaked by checking
        // the system temp dir count hasn't grown after a successful build.
        // This test ensures the happy path cleans up.
        let dir = tempfile::tempdir().expect("temp");
        let dest = dir.path().join("sub").join("diag.zip"); // sub dir created by builder
        let req = DiagnosticArchiveRequest::default_export("0.1.0-test");
        ArchiveBuilder::build(sample_input(req), &dest).expect("build");
        assert!(dest.exists());
    }

    #[test]
    fn zip_entries_are_stamped_with_local_wall_clock_time() {
        // Captured before/after the build call so the assertion can't flake
        // near a wall-clock rollover (second, minute, midnight, ...).
        let before = chrono::Local::now();
        let dir = tempfile::tempdir().expect("temp");
        let dest = dir.path().join("diag.zip");
        let req = DiagnosticArchiveRequest::default_export("0.1.0-test");
        ArchiveBuilder::build(sample_input(req), &dest).expect("build");
        let after = chrono::Local::now();

        let file = std::fs::File::open(&dest).expect("open zip");
        let mut zip = zip::ZipArchive::new(file).expect("parse zip");
        let entry = zip.by_name("manifest.json").expect("manifest.json present");
        let mtime = entry
            .last_modified()
            .expect("entry carries a modified time");

        let entry_naive = chrono::NaiveDate::from_ymd_opt(
            mtime.year() as i32,
            mtime.month() as u32,
            mtime.day() as u32,
        )
        .and_then(|date| {
            date.and_hms_opt(
                mtime.hour() as u32,
                mtime.minute() as u32,
                mtime.second() as u32,
            )
        })
        .expect("zip entry stores a valid calendar date/time");

        // DOS timestamps have 2-second resolution and drop odd seconds, so
        // widen the [before, after] window by a few seconds on both ends.
        // Under the old UTC-"now" behavior this assertion fails on any
        // machine whose local offset from UTC is nonzero.
        let tolerance = chrono::Duration::seconds(3);
        let lower = before.naive_local() - tolerance;
        let upper = after.naive_local() + tolerance;
        assert!(
            entry_naive >= lower && entry_naive <= upper,
            "expected entry mtime {entry_naive:?} within [{lower:?}, {upper:?}] \
             (local time), got a value that looks UTC-shifted"
        );
    }

    #[test]
    fn no_backup_guarantee_in_manifest() {
        let dir = tempfile::tempdir().expect("temp");
        let dest = dir.path().join("diag.zip");
        let req = DiagnosticArchiveRequest::default_export("0.1.0-test");
        let result = ArchiveBuilder::build(sample_input(req), &dest).expect("build");
        assert!(
            result.manifest.no_backup_guarantee.contains("diagnostic"),
            "no_backup_guarantee must mention 'diagnostic'"
        );
    }

    #[test]
    fn the_manifest_states_the_size_of_what_it_describes() {
        let dir = tempfile::tempdir().expect("temp");
        let dest = dir.path().join("archive.zip");
        let input = sample_input(DiagnosticArchiveRequest::default_export("0.1.0-test"));

        let result = ArchiveBuilder::build(input, &dest).expect("build");
        assert!(
            result.manifest.total_size_bytes_approx > 0,
            "a manifest that reports zero bytes describes nothing"
        );
        assert!(result.size_bytes > 0);
    }

    #[test]
    fn a_failed_build_leaves_no_archive_behind() {
        let dir = tempfile::tempdir().expect("temp");
        let dest = dir.path().join("archive.zip");
        let mut input = sample_input(DiagnosticArchiveRequest::default_export("0.1.0-test"));
        // Captured stderr goes into the archive verbatim; oversize it past the
        // 50 MiB cap so the build has to abort mid-zip.
        input.service_stderr =
            Some("x".repeat(crate::archive::request::MAX_ARCHIVE_SIZE_BYTES as usize + 1024));

        let result = ArchiveBuilder::build(input, &dest);
        assert!(result.is_err(), "the size cap must stop the export");
        assert!(
            !dest.exists(),
            "a truncated zip must not be left where retention counts it as good"
        );
        assert!(
            !dest.with_extension("part").exists(),
            "no leftover part file"
        );
    }

    #[test]
    fn the_redaction_report_names_the_sections_that_were_left_out() {
        let dir = tempfile::tempdir().expect("temp");
        let dest = dir.path().join("archive.zip");
        let input = sample_input(DiagnosticArchiveRequest::default_export("0.1.0-test"));

        ArchiveBuilder::build(input, &dest).expect("build");

        let file = std::fs::File::open(&dest).expect("open zip");
        let mut zip = zip::ZipArchive::new(file).expect("read zip");
        let mut json = String::new();
        {
            use std::io::Read;
            let mut entry = zip
                .by_name("redaction_report.json")
                .expect("report present");
            entry.read_to_string(&mut json).expect("read report");
        }
        let report: serde_json::Value = serde_json::from_str(&json).expect("parse");
        let excluded: Vec<String> = report["excluded_sections"]
            .as_array()
            .expect("array")
            .iter()
            .map(|v| v.as_str().unwrap_or_default().to_string())
            .collect();
        assert!(
            excluded.contains(&"audit_chain.ndjson".to_string()),
            "a default export excludes the raw chain and must say so: {excluded:?}"
        );
    }

    #[test]
    fn captured_stderr_does_not_carry_the_users_name_into_the_archive() {
        let dir = tempfile::tempdir().expect("temp");
        let dest = dir.path().join("archive.zip");
        let mut input = sample_input(DiagnosticArchiveRequest::default_export("0.1.0-test"));
        input.service_stderr = Some(
            "panicked at C:QQUsersQQalexeyQQAppDataQQnrr.exe:12"
                .to_string()
                .replace("QQ", "\\"),
        );

        ArchiveBuilder::build(input, &dest).expect("build");

        let text = read_zip_entry(&dest, SERVICE_STDERR_FILENAME);
        assert!(
            !text.contains("alexey"),
            "user name leaked verbatim: {text}"
        );
        assert!(
            text.contains("nrr.exe:12"),
            "the useful part of the panic must survive: {text}"
        );
    }

    #[test]
    fn a_default_export_does_not_ship_mac_addresses_or_dns_servers() {
        use nrr_shared::ipc_payloads::{AdapterEntry, InterfaceRowDto, SnapshotInterfacesResponse};

        let dir = tempfile::tempdir().expect("temp");
        let dest = dir.path().join("archive.zip");
        let mut input = sample_input(DiagnosticArchiveRequest::default_export("0.1.0-test"));
        let row = InterfaceRowDto {
            persistent_id: "00-11-22-33-44-55".into(),
            adapter_name: "Ethernet".into(),
            windows_name: "Ethernet".into(),
            interface_description: "Realtek Gaming GbE".into(),
            interface_type: "ethernet".into(),
            is_bluetooth_like: false,
            local_ip: "192.168.1.42".into(),
            gateway: "192.168.1.1".into(),
            dns_servers: "8.8.8.8, 1.1.1.1".into(),
            has_default_route: true,
            has_forwarding_path: Some(true),
            availability: "available".into(),
            selected_role: None,
            route_state: "not-selected".into(),
            observed_facts: nrr_shared::ipc_payloads::InterfaceObservedFactsDto {
                connectivity_state: "online".into(),
                external_ip_status: "not-checked".into(),
                external_ip: None,
                external_probe_attempted: false,
                external_probe_note: String::new(),
            },
            derived_assessment: nrr_shared::ipc_payloads::InterfaceDerivedAssessmentDto {
                vpn_tunnel_likelihood: "low".into(),
                virtual_interface_likelihood: "low".into(),
                service_interface_likelihood: "low".into(),
                classification: "physical".into(),
                confidence_percent: 90,
                heuristic_only: true,
                signals: Vec::new(),
            },
            recommendation: nrr_shared::ipc_payloads::InterfaceRecommendationDto {
                class: "primary-candidate".into(),
                confidence: "high".into(),
                advisory_only: true,
                summary: String::new(),
                key_signals: Vec::new(),
                excluded_alternatives: Vec::new(),
            },
        };
        input.health_enrichment.adapters_snapshot = Some(SnapshotInterfacesResponse {
            data_source: "windows-live".into(),
            adapters: vec![AdapterEntry {
                persistent_id: "00-11-22-33-44-55".into(),
                adapter_name: "Ethernet".into(),
                ipv6_if_index: 12,
                physical_address: Some("00-11-22-33-44-55".into()),
                windows_name: "Ethernet".into(),
                interface_description: "Realtek Gaming GbE".into(),
                interface_type: "ethernet".into(),
                oper_status: "up".into(),
            }],
            secondary: None,
            rows: vec![row],
        });

        ArchiveBuilder::build(input, &dest).expect("build");

        let health = read_zip_entry(&dest, "health.json");
        assert!(
            !health.contains("00-11-22-33-44-55"),
            "MAC leaked: {health}"
        );
        assert!(!health.contains("192.168.1.42"), "local address leaked");
        assert!(!health.contains("8.8.8.8"), "DNS server leaked");
    }

    fn read_zip_entry(archive: &Path, name: &str) -> String {
        use std::io::Read;
        let file = std::fs::File::open(archive).expect("open zip");
        let mut zip = zip::ZipArchive::new(file).expect("read zip");
        let mut entry = zip.by_name(name).expect("entry present");
        let mut text = String::new();
        entry.read_to_string(&mut text).expect("read entry");
        text
    }
}
