//! Logrotate backstop drop-in for the Linux service's
//! operational NDJSON logs.
//!
//! ## Why a backstop and not the rotation authority
//!
//! The rotation/retention AUTHORITY is the in-app `nrr-diagnostics` retention
//! (age + size caps the operator configures in GUI Settings). That policy is
//! neutral, tested once, and behaves identically on every OS — the product
//! promise "30 days means 30 days" must not change across platforms, which is
//! why we do NOT hand operational retention to logrotate.
//!
//! This logrotate drop-in exists for the ONE thing the in-app retention cannot
//! cover: when the service is stopped or crash-looping, its cleanup task is not
//! running, so nothing trims the logs. `logrotate` is driven by a system
//! cron/systemd-timer INDEPENDENTLY of our process, so it catches runaway
//! growth in that window. Its size ceiling sits well ABOVE the in-app 50 MiB
//! cap, so while the service is healthy the in-app cleanup keeps files under
//! the in-app cap and logrotate never fires.
//!
//! ## Scope discipline
//!
//! The stanza globs only `nrr_service_*.ndjson` under `/var/log/netrulerouter`.
//! The audit trail lives in `/var/lib/netrulerouter/audit` (hash-chained,
//! append-only, security-critical) — it is out of this path entirely and is
//! never matched, so a misconfiguration here can never truncate the audit log.
//!
//! `#[cfg(target_os = "linux")]`: this is a Linux-only install artefact, kept
//! next to `systemd` (which consumes [`config_file`] in its install plan).

#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};

/// System directory for logrotate drop-in configs. `logrotate`'s default
/// `/etc/logrotate.conf` includes everything here.
pub const LOGROTATE_CONFIG_DIR: &str = "/etc/logrotate.d";

/// Our drop-in file name. Matches the systemd unit leaf (`netrulerouter`) so an
/// admin finds both artefacts under the same name.
pub const LOGROTATE_CONFIG_NAME: &str = "netrulerouter";

/// The operational log directory this config governs. MUST mirror
/// `nrr-storage`'s Linux production `logs_dir` (`/var/log/netrulerouter`); the
/// two are a single source of truth for where operational NDJSON lives.
pub const OPERATIONAL_LOG_DIR: &str = "/var/log/netrulerouter";

/// Backstop size ceiling per file. Deliberately far above the in-app 50 MiB
/// operational cap (CLAUDE.md retention default) so logrotate only ever fires
/// when the in-app cleanup is NOT running.
pub const BACKSTOP_SIZE: &str = "200M";

/// Backstop age ceiling in days. Above the in-app 90-day operational default,
/// for the same reason: a healthy service is trimmed by the in-app policy long
/// before this triggers.
pub const BACKSTOP_MAX_AGE_DAYS: u32 = 120;

/// How many rotated (compressed) generations to keep before deletion.
pub const BACKSTOP_ROTATE_KEEP: u32 = 8;

/// Absolute path of the logrotate drop-in file.
pub fn config_file() -> PathBuf {
    Path::new(LOGROTATE_CONFIG_DIR).join(LOGROTATE_CONFIG_NAME)
}

/// Render the logrotate drop-in contents.
///
/// Pure — no filesystem or process side effects. The stanza is intentionally a
/// backstop:
/// - `missingok` / `notifempty` — a healthy machine may have no oversized file.
/// - `nocreate` — the NDJSON writer owns file creation (dated filenames via
///   `next_log_filename`); logrotate must not pre-create an empty active file.
/// - `compress` + `delaycompress` — old generations shrink; the most-recent
///   rotation stays uncompressed one cycle in case it is still being read.
/// - `size` + `maxage` — the actual backstop triggers (both above the in-app
///   caps, see the constants).
/// - `rotate` — cap the number of kept generations.
///
/// Compressed rotations end in `.gz` (not `.ndjson`), so the GUI log reader —
/// which lists `nrr_service_*.ndjson` — simply does not see them; acceptable
/// for a backstop that only fires on trimmed, stale data.
pub fn render_logrotate_config() -> String {
    format!(
        "{dir}/nrr_service_*.ndjson {{\n\
         \x20   missingok\n\
         \x20   notifempty\n\
         \x20   nocreate\n\
         \x20   compress\n\
         \x20   delaycompress\n\
         \x20   maxage {age}\n\
         \x20   size {size}\n\
         \x20   rotate {keep}\n\
         }}\n",
        dir = OPERATIONAL_LOG_DIR,
        age = BACKSTOP_MAX_AGE_DAYS,
        size = BACKSTOP_SIZE,
        keep = BACKSTOP_ROTATE_KEEP,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_file_is_a_dropin_under_logrotate_d() {
        assert_eq!(
            config_file(),
            PathBuf::from("/etc/logrotate.d/netrulerouter")
        );
    }

    #[test]
    fn config_governs_only_operational_logs_under_var_log() {
        let cfg = render_logrotate_config();
        // The glob targets operational NDJSON under /var/log/netrulerouter.
        assert!(
            cfg.contains("/var/log/netrulerouter/nrr_service_*.ndjson {"),
            "{cfg}"
        );
    }

    #[test]
    fn config_never_touches_the_audit_trail() {
        let cfg = render_logrotate_config();
        // The audit trail lives under /var/lib, is hash-chained, and must never
        // be rotated/truncated by logrotate. Prove neither the state dir nor an
        // audit glob leaks into the stanza.
        assert!(!cfg.contains("/var/lib"), "{cfg}");
        assert!(!cfg.contains("nrr_audit"), "{cfg}");
        assert!(!cfg.contains("audit"), "{cfg}");
    }

    #[test]
    fn config_is_a_backstop_above_the_in_app_caps() {
        let cfg = render_logrotate_config();
        // Size ceiling well above the in-app 50 MiB operational cap.
        assert!(cfg.contains("size 200M"), "{cfg}");
        // Age ceiling above the in-app 90-day default.
        assert!(cfg.contains("maxage 120"), "{cfg}");
        // Compress old generations, keep a bounded number.
        assert!(cfg.contains("compress"), "{cfg}");
        assert!(cfg.contains("rotate 8"), "{cfg}");
    }

    #[test]
    fn config_does_not_recreate_the_active_file() {
        // The NDJSON writer creates its own dated files; logrotate must not
        // pre-create an empty active log or it fights the writer's rollover.
        let cfg = render_logrotate_config();
        assert!(cfg.contains("nocreate"), "{cfg}");
        assert!(!cfg.contains("copytruncate"), "{cfg}");
    }
}
