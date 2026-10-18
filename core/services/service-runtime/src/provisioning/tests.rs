//! Provisioning: the pure check, the folder, the first-start apply and the
//! verbs' exit codes.

use std::path::Path;
use std::sync::{Arc, Mutex};

use nrr_diagnostics::audit::alert::{
    InMemorySecurityAlertsRepository, SecurityAlertState, SecurityAlertsRepository,
};
use nrr_domain::rules_file::HostPlatform;
use nrr_storage::install_policy::{InstallPolicyRepository, SecondaryUnset};
use nrr_storage::route_bindings::BehaviorMode;
use rusqlite::Connection;

use super::bundle::{read_options, read_settings_export};
use super::folder::stage_bundle_owned_by;
use super::*;
use crate::activation_coordinator::{ActivationCoordinator, ApplyFailurePolicy, IdGenerator};
use crate::per_sid_orchestrator::RulesProvider;

const GOOD_PRIMARY: &[u8] = b"# NetRuleRouter rules\n--- Domains\nprimary.example\n";
const GOOD_SECONDARY: &[u8] = b"--- Domains\nsecondary.example\n";
/// Not UTF-8: the import parser refuses it before reading a line.
const BROKEN: &[u8] = &[0xFF, 0xFE, 0x00, 0x41];

fn state_conn() -> Arc<Mutex<Connection>> {
    use nrr_storage::migration::SqliteMigrationRunner;
    use nrr_storage::repository::MigrationRunner;
    let conn = Connection::open_in_memory().expect("open");
    let runner = SqliteMigrationRunner::for_state_db(conn);
    runner.run_pending_migrations().expect("migrate");
    Arc::new(Mutex::new(runner.into_connection()))
}

fn executor(
    conn: &Arc<Mutex<Connection>>,
    markers: &Path,
) -> crate::production_mutation_executor::ProductionMutationExecutor {
    use crate::active_sid_registry::ActiveSidRegistry;
    use crate::production_coordinator::{
        NoopRulesApplyDispatcher, ProductionApplyMarkerStore, ProductionIdGenerator,
    };
    let coordinator = ActivationCoordinator::new(
        Arc::clone(conn),
        Arc::new(ActiveSidRegistry::new()),
        Arc::new(NoopRulesApplyDispatcher),
        Arc::new(ProductionApplyMarkerStore::new(markers)),
        Arc::new(crate::activation_coordinator::NoopActivationAudit),
        Arc::new(crate::production_settings::SystemClock),
        Arc::new(ProductionIdGenerator::new()) as Arc<dyn IdGenerator>,
        ApplyFailurePolicy::AllOrNothing,
    );
    crate::production_mutation_executor::ProductionMutationExecutor::new(Arc::new(coordinator))
        .with_state_conn(Arc::clone(conn))
}

/// Whoever runs the test owns its temp folder; production demands root.
fn owner_of(dir: &Path) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(dir).expect("meta").uid()
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        0
    }
}

struct Fixture {
    _temp: tempfile::TempDir,
    dir: std::path::PathBuf,
    markers: std::path::PathBuf,
    conn: Arc<Mutex<Connection>>,
    alerts: InMemorySecurityAlertsRepository,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("temp");
        let dir = temp.path().join("provision");
        let markers = temp.path().join("markers");
        std::fs::create_dir_all(&markers).expect("markers");
        Self {
            dir,
            markers,
            _temp: temp,
            conn: state_conn(),
            alerts: InMemorySecurityAlertsRepository::new(),
        }
    }

    fn owner(&self) -> u32 {
        owner_of(self._temp.path())
    }

    fn stage(&self, bundle: &BundleBytes) {
        stage_bundle_owned_by(&self.dir, bundle, self.owner()).expect("stage");
    }

    fn apply(&self) -> ProvisionApplyOutcome {
        let exec = executor(&self.conn, &self.markers);
        let mut applier = ProvisionApplier::new(&exec, &self.conn);
        applier.alerts = Some(&self.alerts);
        applier.owner = self.owner();
        apply_staged(&self.dir, &applier)
    }

    /// Rules per route of the baseline's stored active revision, as written.
    fn rules_of(&self, principal: &str) -> Option<(usize, usize)> {
        let guard = self.conn.lock().expect("conn");
        let record = nrr_storage::revisions::RevisionsRepository::new(&guard)
            .get_active_for(principal)
            .expect("active")?;
        let dto = nrr_shared::rules_json::from_canonical_string(&record.rules_json).expect("dto");
        Some((dto.primary.len(), dto.secondary.len()))
    }

    /// What enforcement reads for `principal`, read-through included.
    fn enforced_for(&self, principal: &str) -> Option<nrr_domain::canonical::CanonicalRuleBook> {
        crate::production_rules_provider::ProductionRulesProvider::new(Arc::clone(&self.conn))
            .active_rules_for(principal)
            .map(|s| s.rule_book)
    }

    fn policy(&self) -> nrr_storage::install_policy::InstallPolicy {
        let guard = self.conn.lock().expect("conn");
        InstallPolicyRepository::new(&guard).get().expect("policy")
    }
}

fn bundle(primary: Option<&[u8]>, secondary: Option<&[u8]>) -> BundleBytes {
    BundleBytes {
        primary: primary.map(<[u8]>::to_vec),
        secondary: secondary.map(<[u8]>::to_vec),
        ..BundleBytes::default()
    }
}

// ── the pure check ───────────────────────────────────────────────────────────

#[test]
fn a_rules_file_passes_and_a_broken_one_names_its_part() {
    let checked = check_bundle(&bundle(Some(GOOD_PRIMARY), None), HostPlatform::compiled())
        .expect("good file");
    assert_eq!(checked.primary.as_ref().map(|s| s.rules().len()), Some(1));
    for (primary, secondary, part) in [
        (Some(BROKEN), None, ProvisionPart::Primary),
        (Some(GOOD_PRIMARY), Some(BROKEN), ProvisionPart::Secondary),
    ] {
        let refusal = check_bundle(&bundle(primary, secondary), HostPlatform::compiled())
            .expect_err("refused");
        assert_eq!(refusal.part, part);
        assert_eq!(
            refusal.part.exit_code(),
            match part {
                ProvisionPart::Primary => exit::PRIMARY_REFUSED,
                _ => exit::SECONDARY_REFUSED,
            }
        );
    }
}

#[test]
fn an_oversized_rules_file_is_refused_before_it_is_parsed() {
    let mut big = b"--- Domains\n".to_vec();
    big.resize(RULES_MAX_BYTES + 1, b'a');
    let refusal =
        check_bundle(&bundle(Some(&big), None), HostPlatform::compiled()).expect_err("too large");
    assert_eq!(refusal.part, ProvisionPart::Primary);
}

#[test]
fn the_settings_reader_takes_the_exporters_own_output_and_ignores_its_adapters() {
    use crate::production_settings_exporter::{ProductionSettingsExporter, SettingsExportSource};
    let conn = state_conn();
    let yaml = ProductionSettingsExporter::new(conn)
        .export_settings(
            "S-1-5-21-1",
            Some("C:\\rules.txt"),
            None,
            "2026-10-17T00:00:00Z",
        )
        .expect("export")
        .yaml_bytes_utf8;
    let facts = read_settings_export(yaml.as_bytes()).expect("read");
    assert_eq!(facts.route_mode, Some(BehaviorMode::PreferPrimary));
}

#[test]
fn the_settings_reader_refuses_what_it_does_not_understand() {
    let ok = "nrr_settings_export:\n  version: 1\n  behavior:\n    nested:\n      x: 1\n    route_mode: \"prefer-secondary-when-available\" # chosen\n";
    assert_eq!(
        read_settings_export(ok.as_bytes())
            .expect("read")
            .route_mode,
        Some(BehaviorMode::PreferSecondaryWhenAvailable)
    );
    for (text, code) in [
        ("version: 1\n", "not-a-settings-export"),
        (
            "nrr_settings_export:\n  version: 2\n",
            "unsupported-version",
        ),
        (
            "nrr_settings_export:\n  behavior:\n    route_mode: x\n",
            "missing-version",
        ),
        (
            "nrr_settings_export:\n  version: 1\n  behavior:\n    route_mode: \"sideways\"\n",
            "unknown-route-mode",
        ),
        ("nrr_settings_export:\n\tversion: 1\n", "tab-indentation"),
        (
            "nrr_settings_export:\n  version: \"1\n",
            "unterminated-string",
        ),
        ("nrr_settings_export:\n  version 1\n", "not-a-key"),
    ] {
        assert_eq!(
            read_settings_export(text.as_bytes()).err().map(|e| e.0),
            Some(code),
            "{text}"
        );
    }
    let deep: String = std::iter::once("nrr_settings_export:\n".to_owned())
        .chain((1..=20).map(|depth| format!("{}k{depth}:\n", " ".repeat(depth))))
        .collect();
    assert_eq!(
        read_settings_export(deep.as_bytes()).err().map(|e| e.0),
        Some("too-deep")
    );
    let big = vec![b'#'; SETTINGS_MAX_BYTES + 1];
    assert_eq!(
        read_settings_export(&big).err().map(|e| e.0),
        Some("file-too-large")
    );
}

#[test]
fn the_options_reader_knows_both_values_and_nothing_else() {
    for (text, want) in [
        ("secondary-unset = block\n", SecondaryUnset::Block),
        (
            "# comment\nsecondary_unset=DIRECT\n",
            SecondaryUnset::Direct,
        ),
    ] {
        assert_eq!(
            read_options(text.as_bytes()).expect(text).secondary_unset,
            Some(want)
        );
    }
    assert_eq!(
        read_options(b"secondary-unset = leak\n").err().map(|e| e.0),
        Some("unknown-secondary-unset")
    );
    assert_eq!(
        read_options(b"adapter = eth0\n").err().map(|e| e.0),
        Some("unknown-option")
    );
}

// ── the first-start apply ────────────────────────────────────────────────────

#[test]
fn provisioning_is_applied_once_into_the_baseline_every_new_user_reads() {
    let fx = Fixture::new();
    fx.stage(&bundle(Some(GOOD_PRIMARY), Some(GOOD_SECONDARY)));

    assert_eq!(
        fx.apply(),
        ProvisionApplyOutcome::Applied {
            rules: true,
            policy: false
        }
    );
    assert_eq!(fx.rules_of(nrr_storage::BASELINE_PRINCIPAL), Some((1, 1)));
    let baseline = fx.enforced_for(nrr_storage::BASELINE_PRINCIPAL);
    assert!(baseline
        .as_ref()
        .is_some_and(|book| !book.primary.rules().is_empty()));
    assert_eq!(
        fx.enforced_for("S-1-5-21-1000-2000-3000-1001"),
        baseline,
        "a user who never edited reads the baseline"
    );
    assert!(fx.dir.join(format!("{PRIMARY_FILE}.applied")).exists());
    assert!(!fx.dir.join(PRIMARY_FILE).exists());

    assert_eq!(fx.apply(), ProvisionApplyOutcome::NothingStaged, "once");
    assert!(fx.alerts.list_open().expect("alerts").is_empty());
}

#[test]
fn a_broken_file_leaves_the_baseline_and_the_policy_and_raises_the_notice() {
    let fx = Fixture::new();
    fx.stage(&bundle(Some(GOOD_PRIMARY), None));
    assert!(matches!(fx.apply(), ProvisionApplyOutcome::Applied { .. }));
    let before = fx.rules_of(nrr_storage::BASELINE_PRINCIPAL);

    let mut broken = bundle(Some(BROKEN), None);
    broken.options = Some(b"secondary-unset = block\n".to_vec());
    fx.stage(&broken);
    let outcome = fx.apply();
    assert!(
        matches!(&outcome, ProvisionApplyOutcome::Refused(r) if r.part == ProvisionPart::Primary),
        "{outcome:?}"
    );
    assert_eq!(fx.rules_of(nrr_storage::BASELINE_PRINCIPAL), before);
    assert_eq!(
        fx.policy().secondary_unset,
        SecondaryUnset::Direct,
        "nothing half-applied"
    );
    let alerts = fx
        .alerts
        .list_by_state(SecurityAlertState::Active)
        .expect("alerts");
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].kind, "provisioning_refused");
    assert!(
        !crate::tamper_bootstrap::is_blocking_alert_kind(&alerts[0].kind),
        "the notice never holds anyone's rule edits"
    );
    assert!(fx.dir.join(format!("{PRIMARY_FILE}.refused")).exists());
    assert_eq!(
        fx.apply(),
        ProvisionApplyOutcome::NothingStaged,
        "not retried"
    );
}

#[test]
fn secondary_unset_is_stored_with_either_value() {
    for want in [SecondaryUnset::Block, SecondaryUnset::Direct] {
        let fx = Fixture::new();
        let options = format!("secondary-unset = {}\n", want.slug());
        fx.stage(&BundleBytes {
            options: Some(options.into_bytes()),
            ..BundleBytes::default()
        });
        assert_eq!(
            fx.apply(),
            ProvisionApplyOutcome::Applied {
                rules: false,
                policy: true
            }
        );
        assert_eq!(fx.policy().secondary_unset, want);
        assert_eq!(
            fx.rules_of(nrr_storage::BASELINE_PRINCIPAL),
            None,
            "no rules asked for"
        );
    }
}

#[test]
fn a_staged_link_is_refused() {
    let fx = Fixture::new();
    fx.stage(&bundle(Some(GOOD_PRIMARY), None));
    let target = fx._temp.path().join("elsewhere.txt");
    std::fs::write(&target, GOOD_PRIMARY).expect("write");
    let link = fx.dir.join(SECONDARY_FILE);
    #[cfg(unix)]
    let made = std::os::unix::fs::symlink(&target, &link).is_ok();
    #[cfg(windows)]
    let made = std::os::windows::fs::symlink_file(&target, &link).is_ok();
    if !made {
        return; // creating links needs a privilege this runner lacks
    }
    assert!(matches!(
        fx.apply(),
        ProvisionApplyOutcome::Refused(r) if r.part == ProvisionPart::Secondary
    ));
}

// ── the verbs ────────────────────────────────────────────────────────────────

fn args(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| (*s).to_owned()).collect()
}

#[test]
fn the_check_verb_exit_codes() {
    let temp = tempfile::tempdir().expect("temp");
    let write = |name: &str, bytes: &[u8]| {
        let path = temp.path().join(name);
        std::fs::write(&path, bytes).expect("write");
        path.to_string_lossy().into_owned()
    };
    let good = write("good.txt", GOOD_PRIMARY);
    let broken = write("broken.txt", BROKEN);
    let settings = write("settings.yaml", b"nrr_settings_export:\n  version: 9\n");
    let missing = temp
        .path()
        .join("absent.txt")
        .to_string_lossy()
        .into_owned();

    let code = |list: &[&str]| cli::run_check(&args(list)).0;
    assert_eq!(code(&[]), exit::USAGE);
    assert_eq!(code(&["--primary"]), exit::USAGE);
    assert_eq!(code(&["--frobnicate", "x"]), exit::USAGE);
    assert_eq!(
        code(&["--primary", "", "--secondary-unset", ""]),
        exit::USAGE
    );
    assert_eq!(code(&["--primary", &good]), exit::OK);
    assert_eq!(
        code(&[&format!("--primary={good}"), "--secondary-unset=block"]),
        exit::OK
    );
    assert_eq!(code(&["--primary", &broken]), exit::PRIMARY_REFUSED);
    assert_eq!(code(&["--primary", &missing]), exit::PRIMARY_REFUSED);
    assert_eq!(
        code(&["--primary", &good, "--secondary", &broken]),
        exit::SECONDARY_REFUSED
    );
    assert_eq!(code(&["--settings", &settings]), exit::SETTINGS_REFUSED);
    assert_eq!(
        code(&["--secondary-unset", "sideways"]),
        exit::OPTION_REFUSED
    );
}

#[test]
fn the_stage_verb_writes_only_what_it_checked() {
    let temp = tempfile::tempdir().expect("temp");
    let good = temp.path().join("good.txt");
    std::fs::write(&good, GOOD_PRIMARY).expect("write");
    let broken = temp.path().join("broken.txt");
    std::fs::write(&broken, BROKEN).expect("write");
    let dir = temp.path().join("provision");
    let good = good.to_string_lossy().into_owned();
    let broken = broken.to_string_lossy().into_owned();

    let (code, _) = cli::run_stage(&args(&["--secondary", &broken]), &dir);
    assert_eq!(code, exit::SECONDARY_REFUSED);
    assert!(!dir.exists(), "a refusal writes nothing");

    // Staging writes root-owned files in production; the test only checks the
    // bytes, because an ordinary user cannot stage under the root rule.
    #[cfg(windows)]
    {
        let (code, _) = cli::run_stage(
            &args(&["--primary", &good, "--secondary-unset", "block"]),
            &dir,
        );
        assert_eq!(code, exit::OK);
        assert_eq!(
            std::fs::read(dir.join(PRIMARY_FILE)).expect("staged"),
            GOOD_PRIMARY
        );
        assert!(std::fs::read_to_string(dir.join(OPTIONS_FILE))
            .expect("options")
            .contains("block"));
    }
    let _ = good;
}
