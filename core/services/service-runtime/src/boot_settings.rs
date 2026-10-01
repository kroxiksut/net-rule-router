//! The operator's saved runtime settings, read once at boot.
//!
//! Shared by every platform's daemon: a setting the IPC surface accepts and
//! stores but a daemon never reads back is a setting that silently does
//! nothing. A missing row, a failed read or a poisoned lock all resolve to the
//! documented defaults — boot has no one to ask.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use nrr_diagnostics::{AuditRetentionPolicy, LogRetentionPolicy};
use rusqlite::Connection;

use crate::service_stability::{IpcAcceptFailurePolicy, ServiceStabilityConfig};

/// The persisted operational-log and audit retention caps. `None` on lock or
/// read failure.
pub fn read_log_retention_config(
    conn: &Arc<Mutex<Connection>>,
) -> Option<nrr_storage::LogRetentionConfig> {
    let guard = conn.lock().ok()?;
    let repo = nrr_storage::LogRetentionConfigRepository::new(&guard);
    match repo.get_or_default() {
        Ok(cfg) => Some(cfg),
        Err(e) => {
            tracing::warn!(
                target: "nrr::runtime",
                msg_key = "svc-boot-log-retention-read-failed",
                error = %e,
                "log_retention_config read failed; using retention defaults",
            );
            None
        }
    }
}

/// The persisted IPC accept-loop policy. `None` on lock or read failure.
pub fn read_service_stability_config(
    conn: &Arc<Mutex<Connection>>,
) -> Option<ServiceStabilityConfig> {
    use nrr_storage::service_stability_config::{
        IpcAcceptPolicyRecord, ServiceStabilityConfigRepository,
    };

    let guard = conn.lock().ok()?;
    let repo = ServiceStabilityConfigRepository::new(&guard);
    let record = match repo.get_or_default() {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                target: "nrr::runtime",
                msg_key = "svc-boot-stability-config-read-failed",
                error = %e,
                "service_stability_config read failed; using runtime defaults",
            );
            return None;
        }
    };
    // Logged with the numbers so an operator can confirm from the log that a
    // saved change reached the supervisor after a restart.
    let policy = match record.ipc_accept_policy {
        IpcAcceptPolicyRecord::Critical => {
            tracing::info!(
                target: "nrr::stability",
                msg_key = "svc-boot-stability-config-loaded-critical",
                kind = "critical",
                "service_stability_config loaded",
            );
            IpcAcceptFailurePolicy::Critical
        }
        IpcAcceptPolicyRecord::Recoverable {
            max_restarts,
            backoff_base_ms,
            backoff_cap_ms,
        } => {
            tracing::info!(
                target: "nrr::stability",
                msg_key = "svc-boot-stability-config-loaded-recoverable",
                kind = "recoverable",
                max_restarts,
                backoff_base_ms,
                backoff_cap_ms,
                "service_stability_config loaded",
            );
            IpcAcceptFailurePolicy::Recoverable {
                max_restarts,
                backoff_base: Duration::from_millis(u64::from(backoff_base_ms)),
                backoff_cap: Duration::from_millis(u64::from(backoff_cap_ms)),
            }
        }
    };
    Some(ServiceStabilityConfig {
        ipc_accept_policy: policy,
    })
}

/// What the supervisor and the cleanup jobs run on.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct BootSettings {
    pub stability: ServiceStabilityConfig,
    pub log_retention: LogRetentionPolicy,
    pub audit_retention: AuditRetentionPolicy,
}

/// The saved settings, or the defaults where the state database or a row is
/// unavailable.
pub fn read_boot_settings(conn: Option<&Arc<Mutex<Connection>>>) -> BootSettings {
    let (log_retention, audit_retention) = match conn.and_then(read_log_retention_config) {
        Some(cfg) => (
            LogRetentionPolicy {
                max_age_days: cfg.log_max_age_days,
                max_total_size_bytes: cfg.log_max_size_bytes,
                ..LogRetentionPolicy::default()
            },
            AuditRetentionPolicy {
                max_age_days: cfg.audit_max_age_days,
                max_total_size_bytes: cfg.audit_max_size_bytes,
            },
        ),
        None => Default::default(),
    };
    let stability = conn
        .and_then(read_service_stability_config)
        .unwrap_or_else(|| {
            tracing::info!(
                target: "nrr::stability",
                msg_key = "svc-boot-stability-defaults-applied",
                source = "default",
                "service_stability_config defaults applied (no persisted row or settings DB unavailable)",
            );
            ServiceStabilityConfig::default()
        });
    BootSettings {
        stability,
        log_retention,
        audit_retention,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_storage::service_stability_config::{
        IpcAcceptPolicyWrite, ServiceStabilityConfigRepository,
    };
    use nrr_storage::{open_connection, repository::MigrationRunner, SqliteMigrationRunner};

    fn state_db() -> (tempfile::TempDir, Arc<Mutex<Connection>>) {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let conn = open_connection(&dir.path().join("nrr_service_state.db")).expect("open");
        let runner = SqliteMigrationRunner::for_state_db(conn);
        runner.run_pending_migrations().expect("migrate");
        (dir, Arc::new(Mutex::new(runner.into_connection())))
    }

    #[test]
    fn no_database_boots_on_the_defaults() {
        assert_eq!(read_boot_settings(None), BootSettings::default());
    }

    /// Saved values are what the daemon runs on, not the factory ones.
    #[test]
    fn saved_settings_reach_the_runtime() {
        let (_dir, conn) = state_db();
        {
            let guard = conn.lock().expect("lock");
            nrr_storage::LogRetentionConfigRepository::new(&guard)
                .set(
                    &nrr_storage::LogRetentionConfig {
                        log_max_age_days: 3,
                        log_max_size_bytes: 1_048_576,
                        audit_max_age_days: 400,
                        audit_max_size_bytes: 2_097_152,
                        updated_at: 0,
                    },
                    0,
                )
                .expect("save retention");
            let repo = ServiceStabilityConfigRepository::new(&guard);
            let r = repo.get_or_default().expect("read stability");
            repo.set(
                &IpcAcceptPolicyWrite::Critical,
                r.verbose_until_ms,
                r.conn_trace_ndjson,
                r.conn_trace_gui,
                r.rule_scope_service_driven,
                r.routing_stop_policy,
                r.cache_refresh_interval_secs,
                r.enforcement_mode,
                r.secondary_liveness_window_secs,
                r.fake_ip_enabled,
                r.dns_via_secondary,
                r.dns_fast_answers,
                r.fake_ip_udp_relay,
                r.fake_ip_instant_rst,
                r.allow_user_rule_edits,
                None,
                0,
            )
            .expect("save stability");
        }

        let settings = read_boot_settings(Some(&conn));
        assert_eq!(
            settings.stability.ipc_accept_policy,
            IpcAcceptFailurePolicy::Critical
        );
        assert_eq!(settings.log_retention.max_age_days, 3);
        assert_eq!(settings.log_retention.max_total_size_bytes, 1_048_576);
        assert_eq!(settings.audit_retention.max_age_days, 400);
        assert_eq!(settings.audit_retention.max_total_size_bytes, 2_097_152);
        assert_ne!(settings, BootSettings::default());
    }
}
