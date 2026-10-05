//! The operator's saved runtime settings, read once at boot.
//!
//! Shared by every platform's daemon: a setting the IPC surface accepts and
//! stores but a daemon never reads back is a setting that silently does
//! nothing. A missing row, a failed read or a poisoned lock all resolve to the
//! documented defaults — boot has no one to ask.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nrr_diagnostics::{AuditRetentionPolicy, LogRetentionPolicy};
use rusqlite::Connection;

use crate::service_stability::{IpcAcceptFailurePolicy, ServiceStabilityConfig};
use crate::timed_window::{now_ms, TimedSwitch, TimedWindow, WindowKind, WindowSink};

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

/// The file whose presence in the service's data root forces the connection
/// trace into the operational log.
pub const CONN_TRACE_SENTINEL: &str = "conn-trace.enabled";

/// The variable that forces the connection trace into the operational log.
pub const CONN_TRACE_ENV: &str = "NRR_CONN_TRACE";

/// What holds the connection trace in the operational log for the life of the
/// process. The file is the service-friendly knob: a service manager caches
/// its environment, a file needs only a restart.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConnTraceForce {
    Environment,
    File(PathBuf),
}

impl ConnTraceForce {
    /// What the user removes to give control back: the variable's name or the
    /// file's full path on this machine.
    #[must_use]
    pub fn source(&self) -> String {
        match self {
            Self::Environment => CONN_TRACE_ENV.to_owned(),
            Self::File(path) => path.display().to_string(),
        }
    }
}

/// Whether, and by what, the connection trace is forced: the variable, or the
/// sentinel file in `data_root`.
#[must_use]
pub fn conn_trace_forced(data_root: Option<&Path>) -> Option<ConnTraceForce> {
    if std::env::var_os(CONN_TRACE_ENV).is_some() {
        return Some(ConnTraceForce::Environment);
    }
    data_root
        .map(|root| root.join(CONN_TRACE_SENTINEL))
        .filter(|file| file.exists())
        .map(ConnTraceForce::File)
}

/// Writing observed connections to the operational log: a window that closes
/// by itself, like verbose logging, plus the process-wide force.
///
/// The observer reads one flag per batch; the window drives it, so a deadline
/// passing turns the sink off without a restart and costs nothing per
/// connection. A forced trace stays on whatever the window says. The sink is
/// privacy-sensitive, so every failure to read the stored deadline leaves it
/// off.
#[derive(Clone)]
pub struct ConnTraceLogSwitch {
    flag: Arc<AtomicBool>,
    forced_by: Option<ConnTraceForce>,
    window: TimedSwitch,
}

impl ConnTraceLogSwitch {
    /// Resume the stored window, if it is still open.
    #[must_use]
    pub fn at_boot(
        conn: Option<&Arc<Mutex<Connection>>>,
        forced_by: Option<ConnTraceForce>,
    ) -> Self {
        Self::resume(conn.and_then(read_conn_trace_until), now_ms(), forced_by)
    }

    /// Resume `persisted_until_ms` as of `now_ms`: the sink starts open only
    /// while that deadline is ahead, or when forced.
    #[must_use]
    pub fn resume(
        persisted_until_ms: Option<i64>,
        now_ms: i64,
        forced_by: Option<ConnTraceForce>,
    ) -> Self {
        let forced = forced_by.is_some();
        let resumed = TimedWindow::resumed(persisted_until_ms, now_ms);
        let flag = Arc::new(AtomicBool::new(resumed.is_open(now_ms) || forced));
        let sink: WindowSink = {
            let flag = Arc::clone(&flag);
            Arc::new(move |open: bool| flag.store(open || forced, Ordering::Relaxed))
        };
        let window = TimedSwitch::resume(
            WindowKind::ConnTraceLog,
            persisted_until_ms,
            now_ms,
            Some(sink),
        );
        let (mode, until_ms) = resumed.reported(now_ms);
        tracing::info!(
            target: "nrr::stability",
            msg_key = "conn-trace-log-at-boot",
            mode = mode.as_slug(),
            until_ms,
            forced,
            "connection trace log window resumed at boot",
        );
        Self {
            flag,
            forced_by,
            window,
        }
    }

    /// The flag the observer reads on every batch.
    #[must_use]
    pub fn flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.flag)
    }

    /// Whether the sentinel file or the environment holds the sink on.
    #[must_use]
    pub fn forced(&self) -> bool {
        self.forced_by.is_some()
    }

    /// What holds the sink on, if anything.
    #[must_use]
    pub fn forced_by(&self) -> Option<&ConnTraceForce> {
        self.forced_by.as_ref()
    }

    /// The window, for the settings writer to move and report.
    #[must_use]
    pub fn window(&self) -> &TimedSwitch {
        &self.window
    }
}

fn read_conn_trace_until(conn: &Arc<Mutex<Connection>>) -> Option<i64> {
    use nrr_storage::service_stability_config::ServiceStabilityConfigRepository;
    let guard = conn.lock().ok()?;
    ServiceStabilityConfigRepository::new(&guard)
        .get_or_default()
        .ok()
        .and_then(|r| r.conn_trace_ndjson_until_ms)
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
                r.conn_trace_ndjson_until_ms,
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

    fn save_conn_trace_until(conn: &Arc<Mutex<Connection>>, until_ms: Option<i64>) {
        let guard = conn.lock().expect("lock");
        let repo = ServiceStabilityConfigRepository::new(&guard);
        let r = repo.get_or_default().expect("read stability");
        repo.set(
            &IpcAcceptPolicyWrite::Critical,
            r.verbose_until_ms,
            until_ms,
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

    /// Polls instead of sleeping a fixed time: a loaded machine delays the
    /// timer thread, never the verdict.
    fn wait_until(done: impl Fn() -> bool) -> bool {
        let started = std::time::Instant::now();
        while !done() && started.elapsed() < Duration::from_secs(10) {
            std::thread::sleep(Duration::from_millis(10));
        }
        done()
    }

    #[test]
    fn the_conn_trace_log_is_off_by_default() {
        let (_dir, conn) = state_db();
        let switch = ConnTraceLogSwitch::at_boot(Some(&conn), None);
        assert!(!switch.flag().load(Ordering::Relaxed), "opt-in");
        assert_eq!(switch.window().window(), TimedWindow::Off);
        let unreadable = ConnTraceLogSwitch::at_boot(None, None);
        assert!(!unreadable.flag().load(Ordering::Relaxed));
    }

    /// A restart inside a timed window resumes it; one after it does not.
    #[test]
    fn a_restart_resumes_a_future_deadline_and_not_a_past_one() {
        let (_dir, conn) = state_db();
        let ahead = now_ms() + 3_600_000;
        save_conn_trace_until(&conn, Some(ahead));
        let resumed = ConnTraceLogSwitch::at_boot(Some(&conn), None);
        assert!(resumed.flag().load(Ordering::Relaxed));
        assert_eq!(
            resumed.window().window(),
            TimedWindow::Until { deadline_ms: ahead }
        );

        save_conn_trace_until(&conn, Some(1_000));
        let expired = ConnTraceLogSwitch::at_boot(Some(&conn), None);
        assert!(!expired.flag().load(Ordering::Relaxed));
        assert_eq!(expired.window().window(), TimedWindow::Off);
    }

    #[test]
    fn the_conn_trace_window_closes_the_sink_without_a_restart() {
        let switch = ConnTraceLogSwitch::resume(None, now_ms(), None);
        let flag = switch.flag();
        switch.window().set(
            TimedWindow::Until {
                deadline_ms: now_ms() + 150,
            },
            now_ms(),
        );
        assert!(flag.load(Ordering::Relaxed), "the window opens the sink");
        assert!(
            wait_until(|| !flag.load(Ordering::Relaxed)),
            "the deadline must close the sink"
        );
        assert_eq!(switch.window().window(), TimedWindow::Off);

        // A resumed window ends the same way.
        let resumed = ConnTraceLogSwitch::resume(Some(now_ms() + 150), now_ms(), None);
        let flag = resumed.flag();
        assert!(flag.load(Ordering::Relaxed));
        assert!(wait_until(|| !flag.load(Ordering::Relaxed)));
    }

    #[test]
    fn a_forced_conn_trace_survives_a_closed_or_expired_window() {
        let switch =
            ConnTraceLogSwitch::resume(Some(1), now_ms(), Some(ConnTraceForce::Environment));
        assert!(switch.forced());
        assert!(switch.flag().load(Ordering::Relaxed), "an expired window");
        switch.window().set(TimedWindow::UntilRestart, now_ms());
        switch.window().set(TimedWindow::Off, now_ms());
        assert!(switch.flag().load(Ordering::Relaxed), "a closed window");

        switch.window().set(
            TimedWindow::Until {
                deadline_ms: now_ms() + 50,
            },
            now_ms(),
        );
        assert!(wait_until(|| switch.window().window() == TimedWindow::Off));
        assert!(
            switch.flag().load(Ordering::Relaxed),
            "a window that ran out"
        );
    }

    #[test]
    fn the_sentinel_file_forces_the_conn_trace() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        if std::env::var_os("NRR_CONN_TRACE").is_none() {
            assert!(conn_trace_forced(Some(dir.path())).is_none());
            assert!(conn_trace_forced(None).is_none());
        }
        std::fs::write(dir.path().join(CONN_TRACE_SENTINEL), b"").expect("sentinel");
        assert_eq!(
            conn_trace_forced(Some(dir.path())).map(|force| force.source()),
            Some(dir.path().join(CONN_TRACE_SENTINEL).display().to_string()),
            "the user is told the file's full path"
        );
    }
}
