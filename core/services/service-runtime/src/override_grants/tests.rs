use super::*;

use std::sync::OnceLock;

use nrr_diagnostics::DiagnosticsError;
use nrr_domain::canonical::{
    CanonicalAppMatch, CanonicalAppPattern, CanonicalRule, CanonicalRuleBook, CanonicalRuleSet,
    RuleAction,
};
use nrr_domain::protected_places::critical_processes_covered;
use nrr_domain::rules_file::HostPlatform;
use nrr_storage::migration::SqliteMigrationRunner;
use nrr_storage::repository::MigrationRunner;

const KEY: [u8; 32] = [7; 32];

/// Kind and reason of every audit record, in order.
#[derive(Default)]
pub(crate) struct RecordingAudit {
    pub records: Mutex<Vec<(AuditEventKind, &'static str)>>,
}

impl AuditSink for RecordingAudit {
    type Event = AuditEventInput;
    fn append(&self, event: AuditEventInput) -> Result<(), DiagnosticsError> {
        lock(&self.records).push((event.kind, event.reason_code.as_str()));
        Ok(())
    }
}

impl RecordingAudit {
    fn reasons(&self) -> Vec<&'static str> {
        lock(&self.records)
            .iter()
            .map(|(_, reason)| *reason)
            .collect()
    }
}

fn state_conn() -> Arc<Mutex<Connection>> {
    let conn = Connection::open_in_memory().expect("open in-memory");
    let runner = SqliteMigrationRunner::for_state_db(conn);
    runner.run_pending_migrations().expect("migrate");
    Arc::new(Mutex::new(runner.into_connection()))
}

fn opened(
    conn: &Arc<Mutex<Connection>>,
    key: Option<Vec<u8>>,
) -> (Arc<OverrideGrants>, Arc<RecordingAudit>) {
    let audit = Arc::new(RecordingAudit::default());
    let grants = OverrideGrants::open(
        Arc::clone(conn),
        key,
        Some(Arc::clone(&audit) as Arc<AuditTrail>),
        now_ms(),
    );
    (grants, audit)
}

/// The registry every rules read of this test process consults; tests keep
/// apart by principal.
pub(crate) fn installed_for_tests() -> &'static Arc<OverrideGrants> {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        let (grants, _) = opened(&state_conn(), Some(KEY.to_vec()));
        install(grants);
    });
    installed().expect("installed above")
}

/// A site root this platform protects as a folder many programs share.
pub(crate) fn site_root() -> &'static str {
    match HostPlatform::compiled() {
        HostPlatform::Windows => r"C:\inetpub\*",
        HostPlatform::Linux => "/var/www/*",
        HostPlatform::MacOS => "/Library/WebServer/Documents/*",
    }
}

pub(crate) fn site_pattern() -> CanonicalAppPattern {
    nrr_domain::protected_places::canonical_app_value(site_root(), HostPlatform::compiled())
        .expect("a path the pipeline accepts")
}

pub(crate) fn preview_for(owner: &str, needs_administrator: bool) -> Preview {
    Preview {
        owner: owner.to_owned(),
        value: site_pattern().as_str().to_owned(),
        effect: RuleEffect::Deny,
        reason: ProtectionReason::SharedFolder,
        critical: Vec::new(),
        accounts: Vec::new(),
        programs: 2,
        needs_administrator,
    }
}

/// `!<site root> +override` as a stored rule of `owner`'s main-route file.
pub(crate) fn requested_deny_book() -> CanonicalRuleBook {
    CanonicalRuleBook {
        primary: CanonicalRuleSet::from_rules(vec![CanonicalRule {
            id: nrr_domain::RuleId("r-site".into()),
            enabled: true,
            address_match: None,
            app_match: Some(CanonicalAppMatch {
                pattern: site_pattern(),
                include_child_processes: false,
                override_requested: true,
            }),
            comment: String::new(),
            action: RuleAction::Block,
            origin: None,
        }]),
        secondary: CanonicalRuleSet::default(),
    }
}

fn ask(value: &str) -> OverrideAsk<'_> {
    OverrideAsk {
        value,
        effect: RuleEffect::Deny,
        reason: ProtectionReason::SharedFolder,
        critical: &[],
    }
}

/// The acceptance path: not applied without a confirmation, applied with one
/// and listed with its term, not applied once the term ran out.
#[test]
fn a_requested_override_applies_only_while_confirmed() {
    // Where rules by path are not carried out yet they are withheld anyway.
    if !nrr_platform_api::enforcement::EnforcementCapabilities::current().app_path_rules {
        return;
    }
    let owner = "S-1-5-21-override-accept";
    let grants = installed_for_tests();
    let (kept, withheld) = crate::protected_rules::withhold_for(owner, requested_deny_book());
    assert!(
        kept.primary.is_empty(),
        "not applied before it is confirmed"
    );
    assert!(withheld[0].override_pending);

    let before = generation();
    let granted = grants
        .grant(
            &preview_for(owner, false),
            OverrideTerm::OneDay,
            owner,
            now_ms(),
        )
        .expect("granted");
    assert!(generation() > before, "a pass sees the change");
    let (kept, withheld) = crate::protected_rules::withhold_for(owner, requested_deny_book());
    assert_eq!(kept.primary.len(), 1, "applied once confirmed");
    assert!(withheld.is_empty());
    let listed = grants.grants_for(owner);
    assert_eq!(listed.len(), 1);
    let dto = listed[0].dto();
    assert_eq!(dto.route, "block");
    assert_eq!(dto.until_ms, granted.expires_at_ms);
    assert!(dto.until_ms.is_some_and(|until| until > now_ms()));

    // Another user's book is not theirs to lift.
    let (kept, _) =
        crate::protected_rules::withhold_for("S-1-5-21-someone-else", requested_deny_book());
    assert!(kept.primary.is_empty());

    // A day later the protection is back.
    let a_day_on = now_ms() + 24 * 3_600_000 + 1;
    assert!(!grants.honours(owner, &ask(&dto.value), a_day_on));
    assert!(grants.honours(owner, &ask(&dto.value), now_ms()));
    assert!(grants.revoke(owner, &dto.value, RuleEffect::Deny, now_ms()));
    assert!(!honoured(owner, &ask(&dto.value)));
}

/// A term that ran out ends the grant, its row and its mark, and the owner is
/// told which rule the protection holds again.
#[test]
fn an_ended_term_removes_the_grant_and_says_so() {
    let conn = state_conn();
    let (grants, audit) = opened(&conn, Some(KEY.to_vec()));
    let bus = Arc::new(EventBus::new());
    grants.attach_events(Arc::clone(&bus));
    let owner = "S-1-5-21-override-ends";
    let subscription = bus
        .subscribe_as("test".into(), Some(owner.into()), None)
        .subscription_id;
    let grant = grants
        .grant(
            &preview_for(owner, false),
            OverrideTerm::OneHour,
            owner,
            now_ms(),
        )
        .expect("granted");
    // The term ran out a moment ago.
    let ended = Grant {
        expires_at_ms: Some(now_ms() - 1),
        ..grant
    };
    lock(&grants.grants).insert(ended.key(), ended.clone());
    grants.end(&ended.key());
    assert!(grants.grants_for(owner).is_empty());
    let guard = lock(&conn);
    assert!(OverrideGrantsRepository::new(&guard)
        .list()
        .expect("list")
        .is_empty());
    drop(guard);
    assert_eq!(
        audit.reasons(),
        [
            integrity::PROTECTION_OVERRIDE_GRANTED.as_str(),
            integrity::PROTECTION_OVERRIDE_EXPIRED.as_str()
        ]
    );
    let events = bus.peek_pending_for(&subscription, 16);
    let expired: Vec<Vec<String>> = events
        .iter()
        .filter_map(|entry| match &entry.event {
            StatusUpdateEvent::RuleOverridesChanged { expired, .. } => Some(expired.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(expired.last(), Some(&vec![ended.value.clone()]));
}

/// A confirmation survives a restart: the next start reads it back, signed,
/// with its term.
#[test]
fn a_confirmation_outlives_the_service_but_not_its_key() {
    let conn = state_conn();
    let owner = "S-1-5-21-override-restart";
    {
        let (grants, _) = opened(&conn, Some(KEY.to_vec()));
        grants
            .grant(
                &preview_for(owner, false),
                OverrideTerm::OneWeek,
                owner,
                now_ms(),
            )
            .expect("granted");
    }
    let (again, _) = opened(&conn, Some(KEY.to_vec()));
    let back = again.grants_for(owner);
    assert_eq!(back.len(), 1);
    assert!(back[0].expires_at_ms.is_some());
    // Another key reads the row as written by nobody it trusts.
    let (other, audit) = opened(&conn, Some(vec![9; 32]));
    assert!(other.grants_for(owner).is_empty());
    assert!(audit
        .reasons()
        .contains(&integrity::PROTECTION_OVERRIDE_REVOKED.as_str()));
    // Without a key nothing is honoured and nothing granted.
    let (keyless, _) = opened(&conn, None);
    assert!(!keyless.available());
    assert_eq!(
        keyless.grant(
            &preview_for(owner, false),
            OverrideTerm::OneDay,
            owner,
            now_ms()
        ),
        Err(GrantRefused::Unavailable)
    );
}

/// A row put into the database by hand lifts nothing: unsigned or forged, it
/// is removed at the next start and the removal audited.
#[test]
fn a_hand_written_row_creates_no_permission() {
    let conn = state_conn();
    let owner = "S-1-5-21-override-forged";
    {
        let guard = lock(&conn);
        let repo = OverrideGrantsRepository::new(&guard);
        for (value, tag) in [("/a/*", Vec::new()), ("/b/*", vec![1u8; 32])] {
            repo.upsert(&OverrideGrantRow {
                sid: owner.into(),
                rule_value: value.into(),
                effect: "deny".into(),
                reason: "shared-folder".into(),
                critical: String::new(),
                accounts: String::new(),
                programs: 0,
                granted_by: owner.into(),
                granted_at: 1,
                expires_at: None,
                row_hmac: tag,
            })
            .expect("store");
        }
    }
    let (grants, audit) = opened(&conn, Some(KEY.to_vec()));
    assert!(grants.grants_for(owner).is_empty());
    assert_eq!(audit.reasons().len(), 2);
    let guard = lock(&conn);
    assert!(OverrideGrantsRepository::new(&guard)
        .list()
        .expect("list")
        .is_empty());
}

/// The emergency reset, with the service stopped, takes every confirmation;
/// the next start audits each and honours none.
#[test]
fn the_emergency_reset_revokes_every_confirmation() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("state.db");
    let conn = {
        let conn = nrr_storage::migration::open_connection(&path).expect("open");
        let runner = SqliteMigrationRunner::for_state_db(conn);
        runner.run_pending_migrations().expect("migrate");
        Arc::new(Mutex::new(runner.into_connection()))
    };
    let owner = "S-1-5-21-override-reset";
    {
        let (grants, _) = opened(&conn, Some(KEY.to_vec()));
        grants
            .grant(
                &preview_for(owner, false),
                OverrideTerm::UntilRevoked,
                owner,
                now_ms(),
            )
            .expect("granted");
    }
    assert_eq!(revoke_all_offline(&path), Ok(1));
    let (after, audit) = opened(&conn, Some(KEY.to_vec()));
    assert!(after.grants_for(owner).is_empty());
    assert_eq!(
        audit.reasons(),
        [integrity::PROTECTION_OVERRIDE_REVOKED.as_str()]
    );
    // Nothing left to revoke, and a machine without a database is fine.
    assert_eq!(revoke_all_offline(&path), Ok(0));
    assert_eq!(revoke_all_offline(&dir.path().join("absent.db")), Ok(0));
}

/// A new critical program under a confirmed rule asks for a new confirmation.
#[test]
fn a_new_critical_program_lapses_the_confirmation() {
    let conn = state_conn();
    let (grants, _) = opened(&conn, Some(KEY.to_vec()));
    let owner = "S-1-5-21-override-critical";
    grants
        .grant(
            &preview_for(owner, false),
            OverrideTerm::OneDay,
            owner,
            now_ms(),
        )
        .expect("granted");
    let value = site_pattern().as_str().to_owned();
    assert!(grants.honours(owner, &ask(&value), now_ms()));
    let critical = critical_processes_covered(
        nrr_domain::protected_places::AppTarget::Name("svchost.exe"),
        &[] as &[&str],
        HostPlatform::Windows,
    );
    let wider = OverrideAsk {
        critical: &critical,
        ..ask(&value)
    };
    assert!(!grants.honours(owner, &wider, now_ms()));
}

/// A preview is good once, for its owner, for its time.
#[test]
fn a_preview_token_is_its_owners_and_runs_out() {
    let conn = state_conn();
    let (grants, _) = opened(&conn, Some(KEY.to_vec()));
    let now = now_ms();
    let token = grants.issue(preview_for("S-1-5-21-a", true), now);
    assert_eq!(
        grants.preview(&token, now).map(|p| p.owner),
        Ok("S-1-5-21-a".to_owned())
    );
    assert_eq!(grants.preview(&token, now + TOKEN_TTL_MS), Err(true));
    assert_eq!(grants.preview("ovr-unknown", now), Err(false));
    grants.spend(&token);
    assert_eq!(grants.preview(&token, now), Err(false));
    // Previewing the same rule again replaces the older token.
    let first = grants.issue(preview_for("S-1-5-21-a", true), now);
    let second = grants.issue(preview_for("S-1-5-21-a", true), now);
    assert_eq!(grants.preview(&first, now), Err(false));
    assert!(grants.preview(&second, now).is_ok());
}

/// One user previewing in a loop pushes out only their own tokens.
#[test]
fn previews_in_a_loop_do_not_push_out_another_users_token() {
    let conn = state_conn();
    let (grants, _) = opened(&conn, Some(KEY.to_vec()));
    let now = now_ms();
    let bobs = grants.issue(preview_for("S-1-5-21-b", false), now);
    let mut alices = Vec::new();
    for i in 0..(MAX_TOKENS * 2) {
        let mut preview = preview_for("S-1-5-21-a", false);
        preview.value = format!("{}-{i}", preview.value);
        alices.push(grants.issue(preview, now));
    }
    assert!(
        grants.preview(&bobs, now).is_ok(),
        "the other user's token stays"
    );
    let alive = alices
        .iter()
        .filter(|t| grants.preview(t, now).is_ok())
        .count();
    assert_eq!(alive, MAX_TOKENS_PER_PRINCIPAL);
    assert!(
        grants.preview(alices.last().expect("issued"), now).is_ok(),
        "the newest of the looping user's stays"
    );
}

/// A full reset of a user's data takes their confirmations with it.
#[test]
fn a_full_reset_forgets_the_users_confirmations() {
    let conn = state_conn();
    let (grants, audit) = opened(&conn, Some(KEY.to_vec()));
    let owner = "S-1-5-21-override-purge";
    grants
        .grant(
            &preview_for(owner, false),
            OverrideTerm::OneDay,
            owner,
            now_ms(),
        )
        .expect("granted");
    grants.forget(owner);
    assert!(grants.grants_for(owner).is_empty());
    assert_eq!(
        audit.reasons().last(),
        Some(&integrity::PROTECTION_OVERRIDE_REVOKED.as_str())
    );
}

/// A crash loop takes back every user's confirmations, each audited with its
/// cause; a series that has not reached the threshold takes none.
#[test]
fn a_crash_loop_withdraws_every_confirmation_and_audits_each() {
    use crate::crash_series::{withdraw_on_crash_loop, THRESHOLD};
    let conn = state_conn();
    let (grants, audit) = opened(&conn, Some(KEY.to_vec()));
    let (alice, bob) = ("S-1-5-21-loop-a", "S-1-5-21-loop-b");
    for owner in [alice, bob] {
        grants
            .grant(
                &preview_for(owner, false),
                OverrideTerm::UntilRevoked,
                owner,
                now_ms(),
            )
            .expect("granted");
    }
    let granted_records = audit.reasons().len();
    let dir = tempfile::tempdir().expect("tempdir");
    let t0 = now_ms();
    // The first start has nothing before it; each later one follows an
    // unclean stop, so the loop completes on start number THRESHOLD + 1.
    for start in 0..THRESHOLD {
        assert_eq!(
            withdraw_on_crash_loop(dir.path(), &grants, t0 + start as i64),
            0,
            "start {start}"
        );
        assert_eq!(grants.grants_for(alice).len(), 1);
    }
    assert_eq!(
        withdraw_on_crash_loop(dir.path(), &grants, t0 + THRESHOLD as i64),
        2
    );
    assert!(grants.grants_for(alice).is_empty() && grants.grants_for(bob).is_empty());
    let revoked = audit.reasons().len() - granted_records;
    assert_eq!(revoked, 2, "one record per confirmation");
    let kinds = lock(&audit.records);
    assert!(kinds[granted_records..]
        .iter()
        .all(|(kind, _)| *kind == AuditEventKind::ProtectionOverrideRevoked));
    // The rows are gone too: the next start honours none.
    drop(kinds);
    let (after, _) = opened(&conn, Some(KEY.to_vec()));
    assert!(after.grants_for(alice).is_empty());
}

/// A clean stop ends the series: the starts after it begin a new count.
#[test]
fn a_clean_stop_keeps_the_confirmations_through_later_restarts() {
    use crate::crash_series::{end_run, withdraw_on_crash_loop, THRESHOLD};
    let conn = state_conn();
    let (grants, _) = opened(&conn, Some(KEY.to_vec()));
    let owner = "S-1-5-21-loop-clean";
    grants
        .grant(
            &preview_for(owner, false),
            OverrideTerm::UntilRevoked,
            owner,
            now_ms(),
        )
        .expect("granted");
    let dir = tempfile::tempdir().expect("tempdir");
    let t0 = now_ms();
    for round in 0..3 * THRESHOLD as i64 {
        assert_eq!(withdraw_on_crash_loop(dir.path(), &grants, t0 + round), 0);
        if round % 2 == 1 {
            end_run(dir.path());
        }
    }
    assert_eq!(grants.grants_for(owner).len(), 1);
}

/// Every cause the audit can carry has words in the window and the TUI.
#[test]
fn every_cause_written_is_one_the_clients_word() {
    let written = [
        Ending::Revoked.cause(),
        Ending::Expired.cause(),
        Ending::FullReset.cause(),
        Ending::CrashLoop.cause(),
        Ending::ServicesChanged.cause(),
        CAUSE_EMERGENCY_RESET,
        "unsigned",
        "tampered",
    ];
    for cause in written {
        assert!(
            nrr_shared::diagnostics_dto::AUDIT_CAUSES.contains(&cause),
            "{cause} missing from AUDIT_CAUSES"
        );
    }
}
