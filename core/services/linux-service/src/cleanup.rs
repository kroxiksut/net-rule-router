//! `cleanup`: give the machine back what this daemon put on it — the DNS
//! redirect, the nftables table, the per-user routing rules and the routes it
//! owns — once the process that
//! would have removed them is gone. `nrr-cli reset-network` and
//! `scripts/reset-network.sh` both run this, so there is one undo, not three.
//!
//! Stops nothing: a live service would put the state straight back, so it is
//! refused instead, and stopping stays the operator's decision.

#![cfg(target_os = "linux")]

use std::fmt::Write as _;
use std::path::PathBuf;
use std::sync::Arc;

use nrr_platform_api::service_control::{ServiceControlPort, ServiceRunState};
use nrr_shared::product_identity::{BinaryRole, PRODUCT_NAME};

/// The console relays this as its own "needs privilege", which is what makes
/// its elevation offer fire. Same code as the Windows `cleanup`.
pub(crate) const EXIT_NEEDS_ROOT: u8 = 3;
/// The service is live. Distinct from a failure so a wrapper can tell "stop it
/// first" from "the undo did not work".
pub(crate) const EXIT_SERVICE_RUNNING: u8 = 4;
const EXIT_FAILED: u8 = 1;

/// The machine, as far as cleanup touches it. Every undo is idempotent: with
/// nothing of ours present it succeeds and changes nothing.
pub(crate) trait CleanupHost {
    /// `Ok(None)` when the unit is not installed.
    fn service_run_state(&self) -> Result<Option<ServiceRunState>, String>;
    fn is_root(&self) -> bool;
    fn restore_dns(&self) -> Result<(), String>;
    /// `Ok(false)` when there is no `nft` to ask, and so no table either.
    fn delete_table(&self) -> Result<bool, String>;
    /// How many per-user routing rules went.
    fn sweep_rules(&self) -> Result<usize, String>;
    /// How many routes went.
    fn sweep_routes(&self) -> Result<usize, String>;
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    ServiceLive(ServiceRunState),
    NeedsRoot,
    Ran(Report),
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Report {
    pub dns: Result<(), String>,
    pub table: Result<bool, String>,
    pub rules: Result<usize, String>,
    pub routes: Result<usize, String>,
    /// Why systemd could not say whether the unit runs, when it could not.
    pub unit_unknown: Option<String>,
}

impl Report {
    fn complete(&self) -> bool {
        self.dns.is_ok() && self.table.is_ok() && self.rules.is_ok() && self.routes.is_ok()
    }
}

pub(crate) fn cleanup(host: &dyn CleanupHost) -> Outcome {
    let unit_unknown = match host.service_run_state() {
        Ok(None | Some(ServiceRunState::Stopped)) => None,
        Ok(Some(live)) => return Outcome::ServiceLive(live),
        // A broken systemd is no reason to leave a machine cut off.
        Err(reason) => Some(reason),
    };
    // Not only for the kernel: the record of what was taken lives in a
    // root-only directory, and an unprivileged run would read "nothing
    // recorded" and report a clean machine.
    if !host.is_root() {
        return Outcome::NeedsRoot;
    }
    // DNS first: a redirect to a listener that is gone breaks every name.
    let dns = host.restore_dns();
    let table = host.delete_table();
    // Rules before routes: without a rule pointing at it a table is inert.
    let rules = host.sweep_rules();
    let routes = host.sweep_routes();
    Outcome::Ran(Report {
        dns,
        table,
        rules,
        routes,
        unit_unknown,
    })
}

pub(crate) fn exit_code(outcome: &Outcome) -> u8 {
    match outcome {
        Outcome::ServiceLive(_) => EXIT_SERVICE_RUNNING,
        Outcome::NeedsRoot => EXIT_NEEDS_ROOT,
        Outcome::Ran(report) if report.complete() => 0,
        Outcome::Ran(_) => EXIT_FAILED,
    }
}

/// What to print: `(stdout, stderr)`.
pub(crate) fn render(outcome: &Outcome) -> (String, String) {
    let mut out = String::new();
    let mut err = String::new();
    match outcome {
        Outcome::ServiceLive(state) => {
            let _ = writeln!(
                err,
                "cleanup: the {PRODUCT_NAME} service is {}; it keeps this state in place \
                 and would put back anything removed now.",
                state.slug()
            );
            let _ = writeln!(
                err,
                "Stop it first (`{} stop`, or `systemctl stop {}`), then run this again.",
                BinaryRole::Console.unix_file_name(),
                nrr_platform_linux::systemd::SYSTEMD_UNIT_NAME
            );
        }
        Outcome::NeedsRoot => {
            let _ = writeln!(
                err,
                "cleanup: must run as root — the network state and the record of what \
                 was changed belong to root."
            );
        }
        Outcome::Ran(report) => {
            if let Some(reason) = &report.unit_unknown {
                let _ = writeln!(
                    err,
                    "cleanup: systemd could not say whether the service runs ({reason}); \
                     going ahead. If it does, it will put this state back."
                );
            }
            let _ = writeln!(out, "{PRODUCT_NAME} network cleanup:");
            match &report.dns {
                Ok(()) => {
                    let _ = writeln!(out, "  DNS redirect:    none left");
                }
                Err(e) => {
                    let _ = writeln!(out, "  DNS redirect:    NOT undone");
                    let _ = writeln!(err, "cleanup: the DNS redirect could not be undone: {e}");
                }
            }
            let table = format!("inet {}", nrr_platform_linux::lower_linux::NRR_TABLE);
            match &report.table {
                Ok(true) => {
                    let _ = writeln!(out, "  packet filters:  none left (nft table {table})");
                }
                Ok(false) => {
                    let _ = writeln!(
                        out,
                        "  packet filters:  nft is not installed; none to remove"
                    );
                }
                Err(e) => {
                    let _ = writeln!(out, "  packet filters:  NOT removed");
                    let _ = writeln!(err, "cleanup: nft table {table} could not be deleted: {e}");
                }
            }
            match &report.rules {
                Ok(n) => {
                    let _ = writeln!(out, "  routing rules:   {n} removed");
                }
                Err(e) => {
                    let _ = writeln!(out, "  routing rules:   NOT removed");
                    let _ = writeln!(
                        err,
                        "cleanup: per-user routing rules could not be removed: {e}"
                    );
                }
            }
            match &report.routes {
                Ok(n) => {
                    let _ = writeln!(out, "  routes removed:  {n}");
                }
                Err(e) => {
                    let _ = writeln!(out, "  routes:          NOT swept");
                    let _ = writeln!(err, "cleanup: route sweep failed: {e}");
                }
            }
            if report.table.is_err() || report.rules.is_err() || report.routes.is_err() {
                let _ = writeln!(
                    err,
                    "A reboot clears the packet filters and routes that are left."
                );
            }
        }
    }
    (out, err)
}

/// The real machine.
pub(crate) struct SystemHost {
    pub data_dir: Option<PathBuf>,
}

impl CleanupHost for SystemHost {
    fn service_run_state(&self) -> Result<Option<ServiceRunState>, String> {
        nrr_platform_linux::service_control::LinuxServiceControl::new()
            .query()
            .map(|report| report.map(|r| r.run_state))
            .map_err(|e| e.to_string())
    }

    fn is_root(&self) -> bool {
        nrr_platform_linux::elevation::running_as_root()
    }

    fn restore_dns(&self) -> Result<(), String> {
        let dir = self
            .data_dir
            .as_deref()
            .ok_or_else(|| "no service data directory is known on this host".to_string())?;
        crate::dns_stack::clear_dns_redirect(dir)
    }

    fn delete_table(&self) -> Result<bool, String> {
        use nrr_platform_linux::nft_apply::NftApplyError;
        match nrr_platform_linux::nft_backend::NftablesEnforcement::default().teardown() {
            Ok(()) => Ok(true),
            Err(NftApplyError::NftUnavailable { .. }) => Ok(false),
            Err(e) => Err(e.to_string()),
        }
    }

    fn sweep_rules(&self) -> Result<usize, String> {
        nrr_platform_linux::policy_routing::sweep_selectors().map_err(|e| e.to_string())
    }

    /// The main table's rows by our signature, and every row of a per-user
    /// table: only we write those.
    fn sweep_routes(&self) -> Result<usize, String> {
        use nrr_platform_api::{RouteEntry, RouteTableRef};
        use nrr_platform_linux::policy_routing::is_our_table;
        nrr_service_runtime::route_reconciler::sweep_owned_routes_with(
            Arc::new(nrr_platform_linux::LinuxApi),
            &|r: &RouteEntry| matches!(r.table, RouteTableRef::Tagged(n) if is_our_table(n)),
        )
        .map_err(|e| e.to_string())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    use nrr_platform_api::dns_redirect::SystemDnsRedirectPort;
    use nrr_platform_api::error::PlatformError;
    use nrr_platform_linux::dns_redirect::{
        clear_every_redirect, CommandReply, DnsCommands, DnsFiles, ResolvConfFileRedirect,
        LOOPBACK_LISTENER_ADDR,
    };

    /// A machine where nothing answers: no resolved link, no NetworkManager,
    /// no resolvconf. Only the files decide what is there.
    #[derive(Clone)]
    struct SilentCommands;

    impl DnsCommands for SilentCommands {
        fn run(&self, _program: &str, _args: &[&str]) -> Result<CommandReply, PlatformError> {
            Ok(CommandReply {
                success: false,
                stdout: String::new(),
                stderr: "not here".to_string(),
            })
        }

        fn run_with_input(
            &self,
            program: &str,
            args: &[&str],
            _input: &str,
        ) -> Result<CommandReply, PlatformError> {
            self.run(program, args)
        }
    }

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "nrr-cleanup-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn scratch_files(root: &std::path::Path) -> DnsFiles {
        let data_dir = root.join("data");
        std::fs::create_dir_all(&data_dir).unwrap();
        DnsFiles {
            resolv_conf: root.join("resolv.conf"),
            data_dir,
            nm_conf_dir: root.join("nm"),
            resolvconf_record_dirs: vec![root.join("resolvconf")],
            resolved_stub: root.join("stub-resolv.conf"),
        }
    }

    /// Records the order of the undo steps; DNS goes through the real undo
    /// over scratch files.
    struct FakeHost {
        state: Result<Option<ServiceRunState>, String>,
        root: bool,
        files: DnsFiles,
        table_present: Cell<bool>,
        rules: Cell<usize>,
        routes: Cell<usize>,
        calls: RefCell<Vec<&'static str>>,
    }

    impl FakeHost {
        fn new(files: DnsFiles) -> Self {
            Self {
                state: Ok(Some(ServiceRunState::Stopped)),
                root: true,
                files,
                table_present: Cell::new(false),
                rules: Cell::new(0),
                routes: Cell::new(0),
                calls: RefCell::new(Vec::new()),
            }
        }
    }

    impl CleanupHost for FakeHost {
        fn service_run_state(&self) -> Result<Option<ServiceRunState>, String> {
            self.state.clone()
        }
        fn is_root(&self) -> bool {
            self.root
        }
        fn restore_dns(&self) -> Result<(), String> {
            self.calls.borrow_mut().push("dns");
            clear_every_redirect(SilentCommands, &self.files).map_err(|e| e.to_string())
        }
        fn delete_table(&self) -> Result<bool, String> {
            self.calls.borrow_mut().push("table");
            self.table_present.set(false);
            Ok(true)
        }
        fn sweep_rules(&self) -> Result<usize, String> {
            self.calls.borrow_mut().push("rules");
            Ok(self.rules.replace(0))
        }
        fn sweep_routes(&self) -> Result<usize, String> {
            self.calls.borrow_mut().push("routes");
            Ok(self.routes.replace(0))
        }
    }

    const SYSTEM_RESOLV_CONF: &str = "nameserver 192.0.2.53\n";

    #[test]
    fn nothing_to_undo_succeeds_and_changes_nothing() {
        let dir = TempDir::new("clean");
        let files = scratch_files(&dir.0);
        std::fs::write(&files.resolv_conf, SYSTEM_RESOLV_CONF).unwrap();
        let host = FakeHost::new(files.clone());

        let outcome = cleanup(&host);

        assert_eq!(exit_code(&outcome), 0);
        assert_eq!(
            std::fs::read_to_string(&files.resolv_conf).unwrap(),
            SYSTEM_RESOLV_CONF
        );
        // Twice is the same as once.
        assert_eq!(exit_code(&cleanup(&host)), 0);
    }

    #[test]
    fn a_recorded_redirect_and_a_table_are_both_undone_dns_first() {
        let dir = TempDir::new("dirty");
        let files = scratch_files(&dir.0);
        std::fs::write(&files.resolv_conf, SYSTEM_RESOLV_CONF).unwrap();
        // A crashed run: the redirect was made by the real mechanism and never
        // restored.
        ResolvConfFileRedirect::new(files.clone())
            .redirect_to(LOOPBACK_LISTENER_ADDR)
            .unwrap();
        assert_ne!(
            std::fs::read_to_string(&files.resolv_conf).unwrap(),
            SYSTEM_RESOLV_CONF
        );
        let host = FakeHost::new(files.clone());
        host.table_present.set(true);
        host.rules.set(3);
        host.routes.set(2);

        let outcome = cleanup(&host);

        assert_eq!(
            *host.calls.borrow(),
            vec!["dns", "table", "rules", "routes"]
        );
        assert_eq!(
            std::fs::read_to_string(&files.resolv_conf).unwrap(),
            SYSTEM_RESOLV_CONF
        );
        assert!(!host.table_present.get());
        let Outcome::Ran(report) = &outcome else {
            panic!("expected a run, got {outcome:?}");
        };
        assert_eq!(report.rules, Ok(3));
        assert_eq!(report.routes, Ok(2));
        assert_eq!(exit_code(&outcome), 0);
    }

    #[test]
    fn a_live_service_is_refused_before_anything_is_touched() {
        for live in [
            ServiceRunState::Running,
            ServiceRunState::StartPending,
            ServiceRunState::StopPending,
            ServiceRunState::Other,
        ] {
            let dir = TempDir::new("live");
            let mut host = FakeHost::new(scratch_files(&dir.0));
            host.state = Ok(Some(live));

            let outcome = cleanup(&host);

            assert_eq!(outcome, Outcome::ServiceLive(live));
            assert_eq!(exit_code(&outcome), EXIT_SERVICE_RUNNING);
            assert!(host.calls.borrow().is_empty());
            let (_, err) = render(&outcome);
            assert!(err.contains("stop"), "names how to stop it: {err}");
        }
    }

    #[test]
    fn a_crashed_or_absent_unit_does_not_block_the_undo() {
        let dir = TempDir::new("absent");
        let mut host = FakeHost::new(scratch_files(&dir.0));
        host.state = Ok(None);
        assert_eq!(exit_code(&cleanup(&host)), 0);
        host.state = Err("no system bus".to_string());
        let outcome = cleanup(&host);
        assert_eq!(exit_code(&outcome), 0);
        assert!(render(&outcome).1.contains("no system bus"));
    }

    #[test]
    fn without_root_nothing_runs_and_the_code_is_the_consoles_privilege_code() {
        let dir = TempDir::new("user");
        let mut host = FakeHost::new(scratch_files(&dir.0));
        host.root = false;

        let outcome = cleanup(&host);

        assert_eq!(outcome, Outcome::NeedsRoot);
        assert_eq!(exit_code(&outcome), 3);
        assert!(host.calls.borrow().is_empty());
    }

    #[test]
    fn one_failed_step_does_not_stop_the_rest_and_fails_the_run() {
        struct TableRefuses(FakeHost);
        impl CleanupHost for TableRefuses {
            fn service_run_state(&self) -> Result<Option<ServiceRunState>, String> {
                self.0.service_run_state()
            }
            fn is_root(&self) -> bool {
                true
            }
            fn restore_dns(&self) -> Result<(), String> {
                self.0.restore_dns()
            }
            fn delete_table(&self) -> Result<bool, String> {
                self.0.calls.borrow_mut().push("table");
                Err("the kernel refused".to_string())
            }
            fn sweep_rules(&self) -> Result<usize, String> {
                self.0.sweep_rules()
            }
            fn sweep_routes(&self) -> Result<usize, String> {
                self.0.sweep_routes()
            }
        }
        let dir = TempDir::new("partial");
        let host = TableRefuses(FakeHost::new(scratch_files(&dir.0)));

        let outcome = cleanup(&host);

        assert_eq!(
            *host.0.calls.borrow(),
            vec!["dns", "table", "rules", "routes"]
        );
        assert_eq!(exit_code(&outcome), EXIT_FAILED);
        assert!(render(&outcome).1.contains("the kernel refused"));
    }

    #[test]
    fn the_codes_stay_clear_of_usage_and_of_each_other() {
        // 2 is the unknown-verb code the recovery script reads as "an older
        // binary without this verb".
        let codes = [0, EXIT_FAILED, EXIT_NEEDS_ROOT, EXIT_SERVICE_RUNNING];
        assert!(!codes.contains(&2));
        let mut sorted = codes.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), codes.len());
    }
}
