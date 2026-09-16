//! The `DiagnosticsFacade` implementation — the surface the IPC handlers call.
//!
//! Every method here is audience-scoped before it reads: the caller cannot name
//! its own audience, so the scoping happens on this side of the boundary.

use super::*;

// ── DiagnosticsFacade impl ───────────────────────────────────────────────────

impl DiagnosticsFacade for ProductionDiagnosticsFacade {
    fn get_status(&self) -> DiagnosticsStatusDto {
        let now_ms = millis_since_epoch();

        // Service health
        let (active_revision_id, pending_changes) = self.read_revision_summary();
        let start_relation = self.start_relative_to_sign_in();
        let service_health = ServiceHealthCard {
            state: "running".to_string(),
            active_revision_id,
            pending_changes,
            start_relative_to_sign_in: start_relation.slug().to_string(),
            start_sign_in_gap_ms: start_relation.millis(),
        };

        // Audit
        let audit_reader = AuditReader::new(self.audit_dir.clone());
        let audit_chain_ok = self.audit_chain_ok(&audit_reader);
        let audit_write_healthy = is_dir_writable(&self.audit_dir);

        let open_alerts = self.alerts_repo.list_open().unwrap_or_default();
        let active_alert_count = open_alerts.len() as u32;
        let active_alerts: Vec<SecurityAlertDto> = open_alerts.iter().map(alert_to_dto).collect();
        let security_status = SecurityStatusCard {
            audit_chain_ok,
            active_alert_count,
            audit_write_healthy,
        };

        // Cache
        let cache_health = self.compute_cache_health();

        // Log health
        let log_health = self.compute_log_health();

        let diagnostic_mode = self
            .diagnostic_session
            .current(now_ms)
            .map(|s| {
                // #21 — a no-expiry ("until restart") session has no countdown.
                let until_restart = s.is_until_restart();
                DiagnosticModeStateDto {
                    active: true,
                    expires_at: if until_restart {
                        None
                    } else {
                        Some(s.expires_at)
                    },
                    remaining_ms: if until_restart {
                        None
                    } else {
                        Some(s.remaining_ms(now_ms))
                    },
                    scope_key: Some(scope_slug(s.scope).to_string()),
                }
            })
            .unwrap_or_else(DiagnosticModeStateDto::inactive);

        let overall_healthy = audit_chain_ok
            && audit_write_healthy
            && cache_health.healthy
            && log_health.dir_writable
            && active_alert_count == 0;

        DiagnosticsStatusDto {
            overall_healthy,
            service_health,
            security_status,
            active_alerts,
            cache_health,
            log_health,
            diagnostic_mode,
            stale: false,
            origin: DiagnosticsDataOrigin::Service,
        }
    }

    fn list_log_entries(
        &self,
        filter: &LogEntryFilter,
        pagination: &PaginationParams,
        audience: &DiagnosticsAudience,
    ) -> DiagnosticsResult<PageResult<LogEntryDto>> {
        let events = self.scan_sorted_log_events_for(filter, audience);
        let items: Vec<LogEntryDto> = events.iter().map(log_event_to_dto).collect();
        Ok(paginate(items, pagination, log_entry_position))
    }

    /// Single-scan override (see the trait default): take the newest
    /// `max_entries` of the ascending scan (its tail) and reverse to
    /// newest-first, without paging the full tree once per wire page.
    fn recent_log_entries(
        &self,
        filter: &LogEntryFilter,
        max_entries: usize,
        audience: &DiagnosticsAudience,
    ) -> DiagnosticsResult<Vec<LogEntryDto>> {
        if max_entries == 0 {
            return Ok(Vec::new());
        }
        let events = self.scan_sorted_log_events_for(filter, audience);
        let start = events.len().saturating_sub(max_entries);
        let mut items: Vec<LogEntryDto> = events[start..].iter().map(log_event_to_dto).collect();
        items.reverse();
        Ok(items)
    }

    fn list_audit_entries(
        &self,
        filter: &AuditEntryFilter,
        pagination: &PaginationParams,
        audience: &DiagnosticsAudience,
    ) -> DiagnosticsResult<PageResult<AuditEntryDto>> {
        let reader = AuditReader::new(self.audit_dir.clone());
        let query_filter = audit_filter_to_query(filter);
        let mut events: Vec<AuditEvent> = reader.scan(&query_filter);
        // Whose events these are is decided here, not by the request. The hash
        // is computed from the caller's own principal with the same function
        // the writer used, so "mine" cannot be spelled as somebody else's.
        if let Some(principal) = audience.principal() {
            let mine = nrr_diagnostics::audit::actor_id_hash(principal);
            events.retain(|event| audit_event_is_visible_to(event, mine.as_deref()));
        }

        events.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.event_id.cmp(&b.event_id))
        });

        let items: Vec<AuditEntryDto> = events.iter().map(audit_event_to_dto).collect();
        Ok(paginate(items, pagination, audit_entry_position))
    }

    fn recent_log_lines_raw(
        &self,
        max_bytes: usize,
        from_ms: Option<i64>,
        audience: &DiagnosticsAudience,
    ) -> DiagnosticsResult<Vec<String>> {
        Ok(
            nrr_diagnostics::logs::reader::LogReader::new(self.logs_dir.clone())
                .recent_raw_lines_for(max_bytes, audience.principal(), from_ms),
        )
    }

    fn recent_log_files_raw(
        &self,
        max_bytes: usize,
        from_ms: Option<i64>,
        audience: &DiagnosticsAudience,
    ) -> DiagnosticsResult<Vec<nrr_diagnostics::logs::reader::RawLogFile>> {
        Ok(
            nrr_diagnostics::logs::reader::LogReader::new(self.logs_dir.clone())
                .recent_raw_files_for(max_bytes, audience.principal(), from_ms),
        )
    }

    fn recent_audit_chain_lines(&self, max_bytes: usize) -> DiagnosticsResult<Vec<String>> {
        // Read the raw NDJSON verbatim (chain fields intact) straight off disk;
        // the reader keeps the newest byte-budgeted suffix. The SYSTEM service
        // has full access to the audit dir, so no ACL gate here — the redaction
        // gate is the caller's (diagnostics-tier export only).
        Ok(AuditReader::new(self.audit_dir.clone()).recent_raw_lines(max_bytes))
    }

    fn list_active_alerts(&self) -> DiagnosticsResult<Vec<SecurityAlertDto>> {
        let alerts = self.alerts_repo.list_open()?;
        Ok(alerts.iter().map(alert_to_dto).collect())
    }

    fn acknowledge_alert(&self, req: &AcknowledgeAlertRequest) -> DiagnosticsResult<()> {
        // Alert ack routes through `MutationKind::SecurityAlertAck`
        // (via the mutation queue, so the audit-before-act invariant
        // and single-writer contract both hold). This direct-call
        // path is deliberately NOT mutating to avoid two parallel
        // write routes diverging. The GUI should never reach this —
        // it routes through `MutationSubmit`. Surfaces a structured
        // error so accidental use shows up in logs.
        if req.alert_id.is_empty() {
            return Err(DiagnosticsError::AuditWriteFailed {
                reason: "alert_id must not be empty".into(),
            });
        }
        Err(DiagnosticsError::AuditWriteFailed {
            reason: "acknowledge_alert must be routed through \
                     MutationKind::SecurityAlertAck (block 16.10)"
                .into(),
        })
    }

    fn set_diagnostic_mode(&self, req: &SetDiagnosticModeRequest) -> DiagnosticsResult<()> {
        let now_ms = millis_since_epoch();
        if !req.enabled {
            self.diagnostic_session.store(None);
            return Ok(());
        }
        let scope = req
            .scope
            .as_deref()
            .map(slug_to_scope)
            .unwrap_or(DiagnosticSessionScope::All);
        // #21 — the "until restart" radio maps to a no-expiry session; the
        // 1h/4h radios pass a bounded duration.
        let session = if req.until_restart {
            DiagnosticSession::until_restart(now_ms, "gui-user", scope, None)
        } else {
            let duration_ms = req
                .duration_ms
                .unwrap_or(DiagnosticSession::DEFAULT_DURATION_MS);
            DiagnosticSession::new(now_ms, duration_ms, "gui-user", scope, None)
        };
        self.diagnostic_session.store(Some(session));
        Ok(())
    }

    fn clear_logs(&self, req: &ClearLogsRequest) -> DiagnosticsResult<ClearLogsResult> {
        let reader = LogReader::new(self.logs_dir.clone());
        let files = reader.list_files();
        let mut files_deleted = 0u32;
        let mut bytes_freed = 0u64;
        for path in files {
            let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            if req.dry_run {
                files_deleted += 1;
                bytes_freed += size;
                continue;
            }
            // Best-effort: a file held open by the writer can't be
            // deleted on Windows. Skip such files silently; the
            // operator can retry after the writer rotates.
            if std::fs::remove_file(&path).is_ok() {
                files_deleted += 1;
                bytes_freed += size;
            }
        }
        // `include_archives` honouring deferred to follow-up — the
        // archives directory is a sibling of `logs/` and uses the
        // same Users:RX ACL; not implemented here to keep the scope
        // tight.
        Ok(ClearLogsResult {
            files_deleted,
            bytes_freed,
            dry_run: req.dry_run,
        })
    }

    fn get_explain(
        &self,
        query: &ExplainQuery,
        level: ExplainDetailLevel,
        caller_sid: &str,
    ) -> DiagnosticsResult<ExplainResponse> {
        // Historical replay would need persisted decision snapshots, and
        // nothing produces them: enforcement is generated from the rule book
        // rather than decided per connection, so there is no per-decision
        // record to store. The branch answers `DecisionNotFound` rather than
        // pretending. The synthetic path runs a real rule-match
        // against the current revision's canonical rule book. Compact
        // view fields (`input`, `route_role`, `reason_key`) get
        // populated; the rest stays empty (no lookup section, no
        // availability section). The reason key set is enumerated in
        // `locales/{en,ru}.json` under `explain.reason.*`.
        match query {
            ExplainQuery::HistoricalDecision { .. } => Ok(ExplainResponse::unavailable(
                query.kind(),
                level,
                ExplainDataAvailability::DecisionNotFound,
            )),
            ExplainQuery::Synthetic { input_sample } => {
                Ok(self.synthetic_explain(input_sample, level, caller_sid))
            }
        }
    }
}
