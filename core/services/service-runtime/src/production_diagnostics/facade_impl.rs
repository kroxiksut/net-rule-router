//! The `DiagnosticsFacade` implementation — the surface the IPC handlers call.
//!
//! Every method here is audience-scoped before it reads: the caller cannot name
//! its own audience, so the scoping happens on this side of the boundary.

use super::*;

// ── DiagnosticsFacade impl ───────────────────────────────────────────────────

impl DiagnosticsFacade for ProductionDiagnosticsFacade {
    fn get_status(&self, audience: &DiagnosticsAudience) -> DiagnosticsStatusDto {
        // Service health
        let (active_revision_id, pending_changes) = self.read_revision_summary(audience);
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

        // An unreadable store is not an empty one: the card says which it was.
        let (active_alerts, alerts_readable) =
            match self.list_alerts(AlertListFilter::Open, audience) {
                Ok(alerts) => (alerts, true),
                Err(e) => {
                    tracing::warn!(
                        target: "nrr::diagnostics",
                        error = %e,
                        "security alerts could not be read for the status snapshot",
                    );
                    (Vec::new(), false)
                }
            };
        let active_alert_count = active_alerts.len() as u32;
        let security_status = SecurityStatusCard {
            audit_chain_ok,
            active_alert_count,
            audit_write_healthy,
            alerts_readable,
        };

        // Cache
        let cache_health = self.compute_cache_health();

        // Log health
        let log_health = self.compute_log_health();

        let overall_healthy = audit_chain_ok
            && audit_write_healthy
            && cache_health.healthy
            && log_health.dir_writable
            && alerts_readable
            && active_alert_count == 0;

        DiagnosticsStatusDto {
            overall_healthy,
            service_health,
            security_status,
            active_alerts,
            cache_health,
            log_health,
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
        // A malformed cursor restarts from the newest entry, as it always has.
        let before = pagination.cursor.as_ref().and_then(PageCursor::parse);
        let page = self.log_page_for(
            filter,
            audience,
            before,
            pagination.effective_page_size() as usize,
        );
        let items: Vec<LogEntryDto> = page.events.iter().map(log_event_to_dto).collect();
        Ok(window_page(items, page.has_more, log_entry_position))
    }

    /// One read of the newest `max_entries` rather than one per wire page.
    fn recent_log_entries(
        &self,
        filter: &LogEntryFilter,
        max_entries: usize,
        audience: &DiagnosticsAudience,
    ) -> DiagnosticsResult<Vec<LogEntryDto>> {
        if max_entries == 0 {
            return Ok(Vec::new());
        }
        let page = self.log_page_for(filter, audience, None, max_entries);
        Ok(page.events.iter().map(log_event_to_dto).collect())
    }

    fn list_audit_entries(
        &self,
        filter: &AuditEntryFilter,
        pagination: &PaginationParams,
        audience: &DiagnosticsAudience,
    ) -> DiagnosticsResult<PageResult<AuditEntryDto>> {
        let reader = AuditReader::new(self.audit_dir.clone());
        let query_filter = audit_filter_to_query(filter);
        let mut events: Vec<AuditEvent> = reader.scan(&query_filter, audience);

        events.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
                .then_with(|| b.event_id.cmp(&a.event_id))
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
                .recent_raw_lines_for(max_bytes, audience, from_ms),
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
                .recent_raw_files_for(max_bytes, audience, from_ms),
        )
    }

    fn recent_audit_chain_lines(
        &self,
        max_bytes: usize,
        audience: &DiagnosticsAudience,
    ) -> DiagnosticsResult<Vec<String>> {
        // The redaction gate is the caller's (diagnostics-tier export only);
        // the audience gate is the reader's.
        Ok(AuditReader::new(self.audit_dir.clone()).recent_raw_lines(max_bytes, audience))
    }

    fn list_alerts(
        &self,
        filter: AlertListFilter,
        audience: &DiagnosticsAudience,
    ) -> DiagnosticsResult<Vec<SecurityAlertDto>> {
        let alerts = match filter {
            AlertListFilter::Open => self.alerts_repo.list_open()?,
            AlertListFilter::In(state) => self.alerts_repo.list_by_state(state)?,
            AlertListFilter::All => {
                let mut all = Vec::new();
                for state in [
                    SecurityAlertState::Active,
                    SecurityAlertState::Acknowledged,
                    SecurityAlertState::Resolved,
                    SecurityAlertState::Superseded,
                ] {
                    all.extend(self.alerts_repo.list_by_state(state)?);
                }
                all
            }
        };
        let owner = |revision_id: &str| self.principal_of_revision(revision_id);
        Ok(
            crate::alert_audience::scope_alerts(alerts, audience, &owner)
                .iter()
                .map(alert_to_dto)
                .collect(),
        )
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
                     MutationKind::SecurityAlertAck"
                .into(),
        })
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
