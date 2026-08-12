//! Production [`PolicyManager`] implementation.
//!
//! `CoordinatorPolicyManager` wraps an `Arc<ActivationCoordinator>` plus
//! the shared `Arc<Mutex<Connection>>` and routes the trait's read-side
//! methods to the coordinator + storage layer.
//!
//! Note on `load_active` / `current_revision`: this returns an empty
//! `ServicePolicyState::NoState` when there is no active pointer. Full LKG
//! fallback flow via `PolicyLoader` is exercised separately; for now the
//! coordinator's `current_active` is consulted directly to keep this
//! production impl independent of the loader's state machine.

use std::sync::{Arc, Mutex};

use rusqlite::Connection;

use crate::activation_coordinator::ActivationCoordinator;
use crate::managers::{PolicyManager, RevisionSummary};
use crate::state::{ActiveRevisionState, ServicePolicyState};
use nrr_storage::policy_settings::ApplyFailurePolicySettingsRepository;
use nrr_storage::revisions::RevisionsRepository;

/// Production `PolicyManager` impl. Forwards trait methods to the
/// coordinator + storage repositories.
pub struct CoordinatorPolicyManager {
    coordinator: Arc<ActivationCoordinator>,
    conn: Arc<Mutex<Connection>>,
    /// Limit for `pending_revisions` query. Recent candidates +
    /// recent terminal entries; the GUI lists are short.
    pending_limit: usize,
}

impl CoordinatorPolicyManager {
    pub fn new(coordinator: Arc<ActivationCoordinator>, conn: Arc<Mutex<Connection>>) -> Self {
        Self {
            coordinator,
            conn,
            pending_limit: 10,
        }
    }

    pub fn with_pending_limit(mut self, limit: usize) -> Self {
        self.pending_limit = limit;
        self
    }
}

fn record_to_summary(rec: nrr_storage::revisions::RevisionRecord) -> RevisionSummary {
    use nrr_domain::rules_revision::RevisionStatus;
    let status_slug: &'static str = match rec.status {
        RevisionStatus::Candidate => "candidate",
        RevisionStatus::Active => "active",
        RevisionStatus::Superseded => "superseded",
        RevisionStatus::RolledBack => "rolled-back",
        RevisionStatus::Rejected => "rejected",
    };
    let source_slug: &'static str = match rec.source {
        nrr_domain::rules_revision::RulesRevisionSource::GuiRulesEdit => "gui-rules-edit",
        nrr_domain::rules_revision::RulesRevisionSource::PresetImport => "preset-import",
        nrr_domain::rules_revision::RulesRevisionSource::RecoveryLkg => "recovery-lkg",
        nrr_domain::rules_revision::RulesRevisionSource::Rollback => "rollback",
    };
    let risk_level_slug: Option<&'static str> = rec.risk_level.map(|level| match level {
        nrr_domain::revision::RiskLevel::Low => "low",
        nrr_domain::revision::RiskLevel::Medium => "medium",
        nrr_domain::revision::RiskLevel::High => "high",
        nrr_domain::revision::RiskLevel::Critical => "critical",
    });
    RevisionSummary {
        revision_id: rec.revision_id,
        status_slug,
        source_slug,
        correlation_id: rec.correlation_id,
        created_at: rec.created_at as u64,
        activated_at: rec.activated_at.map(|v| v as u64),
        superseded_at: rec.superseded_at.map(|v| v as u64),
        risk_level_slug,
        content_hash: rec.content_hash,
    }
}

impl PolicyManager for CoordinatorPolicyManager {
    fn load_active(&self) -> ServicePolicyState {
        match self.coordinator.current_active() {
            Ok(Some(_)) => ServicePolicyState::ActiveReady,
            Ok(None) => ServicePolicyState::NoState,
            Err(_) => ServicePolicyState::RecoveryRequired,
        }
    }

    fn current_revision(&self) -> Option<ActiveRevisionState> {
        let record = self.coordinator.current_active().ok().flatten()?;
        Some(ActiveRevisionState {
            revision_id: record.revision_id,
            // Provenance is currently the source slug; a future revision
            // may surface a richer label.
            provenance: match record.source {
                nrr_domain::rules_revision::RulesRevisionSource::GuiRulesEdit => "gui-rules-edit",
                nrr_domain::rules_revision::RulesRevisionSource::PresetImport => "preset-import",
                nrr_domain::rules_revision::RulesRevisionSource::RecoveryLkg => "recovery-lkg",
                nrr_domain::rules_revision::RulesRevisionSource::Rollback => "rollback",
            }
            .to_string(),
            // Rule count is opaque to the coordinator (rules_json
            // stays in storage). A future revision may parse + count when
            // this field becomes user-visible.
            rule_count: 0,
            // Behavior mode is per-SID live config, not per-revision.
            // Surfaced via SnapshotInitialResponse.route_policy.
            behavior_mode: String::new(),
            content_hash_hex: record.content_hash,
            activated_at_iso: record
                .activated_at
                .map(|secs| chrono_like_format(secs).unwrap_or_else(|| "unknown".to_string()))
                .unwrap_or_default(),
        })
    }

    fn pending_revisions(&self) -> Vec<RevisionSummary> {
        let conn = match self.conn.lock() {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };
        // Query top-N revisions ordered by created_at desc, excluding
        // the active row (the GUI gets active_revision_id separately).
        let limit = self.pending_limit;
        let mut stmt = match conn.prepare(
            "SELECT revision_id, content_hash, rules_json, status, source,
                    correlation_id, created_at, activated_at, superseded_at,
                    superseded_by, rejected_reason, review_summary_json, risk_level
             FROM revisions
             WHERE status != 'active'
             ORDER BY created_at DESC
             LIMIT ?1",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let rows = stmt.query_map([limit as i64], |row| {
            Ok(nrr_storage::revisions::RevisionRecord {
                revision_id: row.get(0)?,
                content_hash: row.get(1)?,
                rules_json: row.get(2)?,
                status: nrr_domain::rules_revision::RevisionStatus::from_slug(
                    &row.get::<_, String>(3)?,
                )
                .unwrap_or(nrr_domain::rules_revision::RevisionStatus::Rejected),
                source: parse_source_slug(&row.get::<_, String>(4)?),
                correlation_id: row.get(5)?,
                created_at: row.get(6)?,
                activated_at: row.get(7)?,
                superseded_at: row.get(8)?,
                superseded_by: row.get(9)?,
                rejected_reason: row.get(10)?,
                review_summary_json: row.get(11)?,
                risk_level: row
                    .get::<_, Option<String>>(12)?
                    .and_then(|s| match s.as_str() {
                        "low" => Some(nrr_domain::revision::RiskLevel::Low),
                        "medium" => Some(nrr_domain::revision::RiskLevel::Medium),
                        "high" => Some(nrr_domain::revision::RiskLevel::High),
                        _ => None,
                    }),
            })
        });
        let rows = match rows {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };
        rows.filter_map(|r| r.ok()).map(record_to_summary).collect()
    }

    fn last_known_good_id(&self) -> Option<String> {
        let conn = self.conn.lock().ok()?;
        let repo = RevisionsRepository::new(&conn);
        let lkg = repo.last_known_good().ok().flatten()?;
        Some(lkg.revision_id)
    }

    fn current_failure_policy_slug(&self) -> &'static str {
        // Read live from settings DB so a policy change made via the
        // ApplyFailurePolicySet IPC handler is reflected on the next
        // snapshot without restart.
        let conn = match self.conn.lock() {
            Ok(c) => c,
            Err(_) => return "all-or-nothing",
        };
        let repo = ApplyFailurePolicySettingsRepository::new(&conn);
        match repo.get_or_default() {
            Ok(rec) => match rec.policy.as_str() {
                "all-or-nothing" => "all-or-nothing",
                "best-effort" => "best-effort",
                "pre-flight-then-all-or-nothing" => "pre-flight-then-all-or-nothing",
                _ => "all-or-nothing",
            },
            Err(_) => "all-or-nothing",
        }
    }
}

fn parse_source_slug(slug: &str) -> nrr_domain::rules_revision::RulesRevisionSource {
    use nrr_domain::rules_revision::RulesRevisionSource;
    match slug {
        "gui-rules-edit" => RulesRevisionSource::GuiRulesEdit,
        "preset-import" => RulesRevisionSource::PresetImport,
        "recovery-lkg" => RulesRevisionSource::RecoveryLkg,
        "rollback" => RulesRevisionSource::Rollback,
        // Defensive default; storage CHECK should keep this unreachable.
        _ => RulesRevisionSource::GuiRulesEdit,
    }
}

/// Tiny ISO-8601 formatter without pulling in `chrono`. Matches the
/// `activated_at_iso` field's existing convention (`YYYY-MM-DDTHH:MM:SSZ`).
fn chrono_like_format(epoch_secs: i64) -> Option<String> {
    if epoch_secs < 0 {
        return None;
    }
    let secs = epoch_secs as u64;
    let total_days = secs / 86_400;
    let time_in_day = secs % 86_400;
    let hh = time_in_day / 3600;
    let mm = (time_in_day % 3600) / 60;
    let ss = time_in_day % 60;
    let (year, month, day) = epoch_days_to_ymd(total_days as i64);
    Some(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hh, mm, ss
    ))
}

/// Converts days-since-1970-01-01 into (year, month, day). Uses the
/// civil-from-days algorithm (Howard Hinnant). Avoids the chrono dep.
fn epoch_days_to_ymd(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_days_to_ymd_known_dates() {
        //  corresponds to days 20_582 since 1970-01-01.
        assert_eq!(epoch_days_to_ymd(20_582), (2026, 5, 9));
        assert_eq!(epoch_days_to_ymd(0), (1970, 1, 1));
        assert_eq!(epoch_days_to_ymd(20_454), (2026, 1, 1));
    }

    #[test]
    fn chrono_like_format_round_trip() {
        // 2026-05-09T00:00:00Z = 1_778_284_800
        let s = chrono_like_format(1_778_284_800).expect("formatter");
        assert!(s.starts_with("2026-05-09T"));
        assert!(s.ends_with("Z"));
    }
}
