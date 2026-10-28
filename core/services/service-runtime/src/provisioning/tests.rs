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
            &nrr_shared::ipc_payloads::SettingsExportFullRequest {
                rules_file_path_primary: Some("C:\\rules.txt".to_owned()),
                ..Default::default()
            },
            "2026-10-17T00:00:00Z",
        )
        .expect("export")
        .yaml_bytes_utf8;
    let facts = read_settings_export(yaml.as_bytes()).expect("read");
    assert_eq!(facts.route_mode, Some(BehaviorMode::PreferPrimary));
    assert_eq!(facts.leak_protection, Some(nrr_domain::LeakProtection::Off));
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
    // An export from before the strict mode was retired still installs, and
    // keeps its promise of no leaks.
    let old = "nrr_settings_export:\n  version: 1\n  behavior:\n    route_mode: \"strict-secondary-fail-closed\"\n";
    let facts = read_settings_export(old.as_bytes()).expect("read");
    assert_eq!(
        facts.route_mode,
        Some(BehaviorMode::PreferSecondaryWhenAvailable)
    );
    assert_eq!(
        facts.leak_protection,
        Some(nrr_domain::LeakProtection::Everything)
    );
    for (text, code) in [
        ("version: 1\n", "not-a-settings-export"),
        (
            "nrr_settings_export:\n  version: 3\n",
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
        (
            "nrr_settings_export:\n  version: 1\n  behavior:\n    leak_protection: \"on\"\n",
            "unknown-leak-protection",
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

/// An old export's strict mode reaches the install policy as the additional
/// route with a floor of everything.
#[test]
fn a_strict_export_stores_the_additional_route_and_a_floor_of_everything() {
    let fx = Fixture::new();
    fx.stage(&BundleBytes {
        settings: Some(
            b"nrr_settings_export:\n  version: 1\n  behavior:\n    route_mode: \"strict-secondary-fail-closed\"\n"
                .to_vec(),
        ),
        ..BundleBytes::default()
    });
    assert_eq!(
        fx.apply(),
        ProvisionApplyOutcome::Applied {
            rules: false,
            policy: true
        }
    );
    let policy = fx.policy();
    assert_eq!(
        policy.default_route_mode,
        Some(BehaviorMode::PreferSecondaryWhenAvailable)
    );
    assert_eq!(
        policy.default_leak_protection,
        nrr_domain::LeakProtection::Everything
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

// ── the full settings export carries the rules ───────────────────────────────

const RICH_PRIMARY: &str = "# NetRuleRouter rules file\n\
--- Zones\n\
corp-internal  # internal zone\n\
\n\
--- Domains\n\
updates.example.org    # vendor updates\n\
# old.example.com    # disabled\n\
?accounts.example.com  # main route while it opens there\n\
\n\
--- IP\n\
203.0.113.7\n\
\n\
--- CIDR\n\
10.0.0.0/8  # corporate\n\
\n\
--- Ranges\n\
192.0.2.10-192.0.2.40\n\
\n\
--- Windows\n\
browser.exe  # browser\n\
C:\\Tools\\Sync\\*\n\
# powershell.exe\n\
\n\
--- Linux\n\
other-browser\n\
/opt/tools/*\n";

const RICH_SECONDARY: &str = "--- Domains\n\
*.streaming.example.com  # always through the tunnel\n\
!telemetry.example.net  # never leaves this computer\n";

/// The rules a book applies, without the ids an import assigns afresh.
fn rules_without_ids(
    book: &nrr_domain::canonical::CanonicalRuleBook,
) -> (
    Vec<nrr_domain::canonical::CanonicalRule>,
    Vec<nrr_domain::canonical::CanonicalRule>,
) {
    let strip = |set: &nrr_domain::canonical::CanonicalRuleSet| {
        set.rules()
            .iter()
            .cloned()
            .map(|mut rule| {
                rule.id = nrr_domain::RuleId(String::new());
                rule
            })
            .collect::<Vec<_>>()
    };
    (strip(&book.primary), strip(&book.secondary))
}

fn export_of(conn: &Arc<Mutex<Connection>>, sid: &str) -> String {
    export_with(conn, sid, &Default::default())
}

fn export_with(
    conn: &Arc<Mutex<Connection>>,
    sid: &str,
    client: &nrr_shared::ipc_payloads::SettingsExportFullRequest,
) -> String {
    use crate::production_settings_exporter::{ProductionSettingsExporter, SettingsExportSource};
    ProductionSettingsExporter::new(Arc::clone(conn))
        .export_settings(sid, client, "2026-10-26T00:00:00Z")
        .expect("export")
        .yaml_bytes_utf8
}

/// A section no build of ours applies here: another system's programs.
fn foreign_app_section() -> &'static str {
    if HostPlatform::compiled() == HostPlatform::MacOS {
        "Linux"
    } else {
        "MacOS"
    }
}

/// Another system's programs ride along in the export, verbatim, so a restore
/// from it keeps them; the install takes them as it takes them from a rules
/// file, and none of them is applied here.
#[test]
fn a_full_export_keeps_the_sections_this_system_does_not_apply() {
    let source = Fixture::new();
    source.stage(&bundle(Some(GOOD_PRIMARY), Some(GOOD_SECONDARY)));
    assert!(matches!(
        source.apply(),
        ProvisionApplyOutcome::Applied { rules: true, .. }
    ));
    let user = "S-1-5-21-1000-2000-3000-1001";
    let foreign = foreign_app_section();
    let client = nrr_shared::ipc_payloads::SettingsExportFullRequest {
        passthrough_sections_primary: [(
            foreign.to_owned(),
            "Other Browser  # their browser\n# Old Tool\n".to_owned(),
        )]
        .into(),
        // A section this build applies is the service's own to write: a copy
        // from the caller would turn into applied rules on install.
        passthrough_sections_secondary: [
            ("Domains".to_owned(), "injected.example\n".to_owned()),
            (
                foreign.to_owned(),
                "Tool\n--- Domains\nsmuggled.example\n".to_owned(),
            ),
        ]
        .into(),
        ..Default::default()
    };
    let yaml = export_with(&source.conn, user, &client);
    let facts = read_settings_export(yaml.as_bytes()).expect("read");
    let primary = facts.rules_primary.as_deref().expect("primary rules");
    assert!(
        primary.contains(&format!(
            "--- {foreign}\nOther Browser  # their browser\n# Old Tool\n"
        )),
        "{yaml}"
    );
    assert!(primary.contains("primary.example"), "{yaml}");
    assert!(!yaml.contains("injected.example"), "{yaml}");
    assert!(!yaml.contains("smuggled.example"), "{yaml}");

    let in_force = source.enforced_for(user).expect("rules in force");
    let target = Fixture::new();
    target.stage(&BundleBytes {
        settings: Some(yaml.clone().into_bytes()),
        ..BundleBytes::default()
    });
    assert!(matches!(
        target.apply(),
        ProvisionApplyOutcome::Applied { rules: true, .. }
    ));
    let installed = target
        .enforced_for(nrr_storage::BASELINE_PRINCIPAL)
        .expect("installed rules");
    assert_eq!(
        rules_without_ids(&installed),
        rules_without_ids(&in_force),
        "nothing of another system is applied: {yaml}"
    );
}

/// No rules in force, but the bound file holds another system's programs: the
/// export still carries them.
#[test]
fn foreign_sections_travel_without_rules_in_force() {
    let foreign = foreign_app_section();
    let client = nrr_shared::ipc_payloads::SettingsExportFullRequest {
        passthrough_sections_primary: [(foreign.to_owned(), "Other Browser\n".to_owned())].into(),
        ..Default::default()
    };
    let yaml = export_with(&state_conn(), "S-1-5-21-1", &client);
    let facts = read_settings_export(yaml.as_bytes()).expect("read");
    assert_eq!(
        facts.rules_primary.as_deref(),
        Some(format!("--- {foreign}\nOther Browser\n").as_str()),
        "{yaml}"
    );
    assert_eq!(facts.rules_secondary, None);
}

/// A user's full settings export, handed to an unattended install on another
/// computer, brings that user's rules of both routes with it.
#[test]
fn a_full_export_installs_the_same_rules_it_was_taken_from() {
    let source = Fixture::new();
    source.stage(&bundle(
        Some(RICH_PRIMARY.as_bytes()),
        Some(RICH_SECONDARY.as_bytes()),
    ));
    assert!(matches!(
        source.apply(),
        ProvisionApplyOutcome::Applied { rules: true, .. }
    ));
    // A user who never edited holds the baseline: that is what they export.
    let user = "S-1-5-21-1000-2000-3000-1001";
    let in_force = source.enforced_for(user).expect("rules in force");
    let stored_before = source.rules_of(nrr_storage::BASELINE_PRINCIPAL);
    // The service holds no free comments and no other system's section (the
    // clients keep those in the bound files), so neither travels.
    let yaml = export_of(&source.conn, user);
    assert_eq!(source.rules_of(user), None, "an export writes nothing");
    assert_eq!(
        source.rules_of(nrr_storage::BASELINE_PRINCIPAL),
        stored_before
    );

    let target = Fixture::new();
    target.stage(&BundleBytes {
        settings: Some(yaml.clone().into_bytes()),
        ..BundleBytes::default()
    });
    assert!(
        matches!(
            target.apply(),
            ProvisionApplyOutcome::Applied { rules: true, .. }
        ),
        "{yaml}"
    );
    let installed = target
        .enforced_for(nrr_storage::BASELINE_PRINCIPAL)
        .expect("installed rules");
    assert_eq!(
        rules_without_ids(&installed),
        rules_without_ids(&in_force),
        "{yaml}"
    );
    assert_eq!(
        target.rules_of(nrr_storage::BASELINE_PRINCIPAL),
        stored_before,
        "rules kept aside travel too: {yaml}"
    );
}

/// No rules anywhere is an export with an empty rules section, not a failure.
#[test]
fn a_user_with_no_rules_exports_an_empty_rules_section() {
    let yaml = export_of(&state_conn(), "S-1-5-21-1");
    assert!(
        yaml.contains("  rules:\n    primary: \"\"\n    secondary: \"\"\n"),
        "{yaml}"
    );
    let facts = read_settings_export(yaml.as_bytes()).expect("read");
    assert_eq!(facts.rules_primary, None);
    assert_eq!(facts.rules_secondary, None);
}

/// A route given rules twice is the administrator's choice to make, not one
/// the service makes by dropping either copy.
#[test]
fn a_route_with_a_rules_file_and_rules_in_the_export_is_refused() {
    let settings = "nrr_settings_export:\n  version: 2\n  rules:\n    primary: |\n      --- Domains\n      from-export.example\n";
    let refusal = check_bundle(
        &BundleBytes {
            primary: Some(GOOD_PRIMARY.to_vec()),
            settings: Some(settings.as_bytes().to_vec()),
            ..BundleBytes::default()
        },
        HostPlatform::compiled(),
    )
    .expect_err("twice");
    assert_eq!(
        (refusal.part, refusal.code.as_str()),
        (ProvisionPart::Settings, "rules-given-twice")
    );
    // The other route's file and the export's primary rules sit side by side.
    let checked = check_bundle(
        &BundleBytes {
            secondary: Some(GOOD_SECONDARY.to_vec()),
            settings: Some(settings.as_bytes().to_vec()),
            ..BundleBytes::default()
        },
        HostPlatform::compiled(),
    )
    .expect("one copy per route");
    assert!(checked.primary.is_some() && checked.secondary.is_some());
}

/// The embedded rules are hostile bytes like a rules file: refused rules name
/// the settings file, and a block never grows past the import limit.
#[test]
fn rules_in_a_settings_file_meet_the_rules_file_gates() {
    let broken = "nrr_settings_export:\n  version: 2\n  rules:\n    secondary: |\n      --- Domains\n      bad\u{7}name.example\n";
    let refusal = check_bundle(
        &BundleBytes {
            settings: Some(broken.as_bytes().to_vec()),
            ..BundleBytes::default()
        },
        HostPlatform::compiled(),
    )
    .expect_err("control character");
    assert_eq!(refusal.part, ProvisionPart::Settings, "{refusal}");

    let line = "      a.example\n";
    let mut huge = String::from(
        "nrr_settings_export:\n  version: 2\n  rules:\n    primary: |\n      --- Domains\n",
    );
    // The block counts what is left once its indentation is taken off.
    while huge.len() < 2 * RULES_MAX_BYTES {
        huge.push_str(line);
    }
    assert_eq!(
        read_settings_export(huge.as_bytes()).err().map(|e| e.0),
        Some("rules-too-large")
    );
}

/// Version 1 never carried rules: a version-1 file with them is not ours.
#[test]
fn rules_belong_to_version_2_and_version_1_reads_as_before() {
    let v1_with_rules = "nrr_settings_export:\n  version: 1\n  rules:\n    primary: |\n      --- Domains\n      a.example\n";
    assert_eq!(
        read_settings_export(v1_with_rules.as_bytes())
            .err()
            .map(|e| e.0),
        Some("rules-need-version-2")
    );
    let v2 = "nrr_settings_export:\n  version: 2\n  rules:\n    primary: |\n      --- Domains\n      a.example  # kept\n\n      # disabled.example\n    secondary: \"\"\n  behavior:\n    route_mode: \"prefer-primary\"\n";
    let facts = read_settings_export(v2.as_bytes()).expect("read");
    assert_eq!(
        facts.rules_primary.as_deref(),
        Some("--- Domains\na.example  # kept\n\n# disabled.example\n")
    );
    assert_eq!(facts.rules_secondary, None);
    assert_eq!(facts.route_mode, Some(BehaviorMode::PreferPrimary));
    for (text, code) in [
        (
            "nrr_settings_export:\n  version: 2\n  rules:\n    primary: \"a.example\"\n",
            "rules-not-a-block",
        ),
        (
            "nrr_settings_export:\n  version: 2\n  rules:\n    primary: |\n        --- Domains\n      a.example\n",
            "bad-block-indentation",
        ),
    ] {
        assert_eq!(
            read_settings_export(text.as_bytes()).err().map(|e| e.0),
            Some(code),
            "{text}"
        );
    }
}
