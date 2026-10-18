use super::*;
use nrr_domain::rules_revision::RevisionStatus;
use nrr_shared::rules_json::AddressMatchDto;
use nrr_storage::repository::MigrationRunner;
use nrr_storage::revisions::RevisionRecord;
use nrr_storage::SqliteMigrationRunner;

fn domain(value: &str) -> RuleDto {
    RuleDto {
        id: String::new(),
        enabled: true,
        address_match: Some(AddressMatchDto::ExactFqdn {
            value: value.into(),
        }),
        app_match: None,
        comment: String::new(),
        action: RuleAction::Route,
        origin: None,
    }
}

fn with(mut rule: RuleDto, f: impl FnOnce(&mut RuleDto)) -> RuleDto {
    f(&mut rule);
    rule
}

fn book(primary: Vec<RuleDto>, secondary: Vec<RuleDto>) -> CanonicalRulesJsonV1 {
    let number = |rules: Vec<RuleDto>, from: usize| -> Vec<RuleDto> {
        rules
            .into_iter()
            .enumerate()
            .map(|(i, mut r)| {
                r.id = format!("r-{:04}", from + i + 1);
                r
            })
            .collect()
    };
    let secondary_from = primary.len();
    CanonicalRulesJsonV1 {
        schema_version: 1,
        primary: number(primary, 0),
        secondary: number(secondary, secondary_from),
    }
}

fn step(at: i64, book: CanonicalRulesJsonV1) -> ChainStep {
    ChainStep {
        at,
        replaces: false,
        book,
    }
}

fn chain(base: CanonicalRulesJsonV1, steps: Vec<ChainStep>) -> Chain {
    Chain {
        base,
        steps,
        history_starts_at: None,
        truncated: false,
    }
}

fn summary(resp: &RulesRecentChangesResponse) -> Vec<(RecentRuleChangeKind, i64, String)> {
    resp.changes
        .iter()
        .map(|c| {
            let value = c
                .rule
                .as_ref()
                .map_or_else(|| format!("{} rules", c.count), |r| r.match_value.clone());
            (c.kind, c.at, value)
        })
        .collect()
}

#[test]
fn added_changed_and_deleted_rules_are_told_apart() {
    // Ids are positional: removing the first rule renumbers every later one.
    let base = book(
        vec![domain("gone.example"), domain("moved.example")],
        vec![domain("kept.example")],
    );
    let steps = vec![
        step(
            100,
            book(vec![domain("moved.example")], vec![domain("kept.example")]),
        ),
        step(
            200,
            book(
                vec![domain("new.example")],
                vec![domain("kept.example"), domain("moved.example")],
            ),
        ),
    ];
    let resp = changes_of(&chain(base, steps), None);
    assert_eq!(
        summary(&resp),
        vec![
            (RecentRuleChangeKind::Added, 200, "new.example".to_owned()),
            (
                RecentRuleChangeKind::Changed,
                200,
                "moved.example".to_owned()
            ),
            (
                RecentRuleChangeKind::Deleted,
                100,
                "gone.example".to_owned()
            ),
        ]
    );
    let moved = &resp.changes[1];
    assert_eq!(
        moved.rule.as_ref().map(|r| r.target_route.as_str()),
        Some("secondary")
    );
    assert_eq!(
        moved.previous,
        Some(RecentRulePreviousDto {
            target_route: "primary".into(),
            enabled: true,
            verify: false,
        })
    );
    // An id names nothing across revisions.
    assert!(resp
        .changes
        .iter()
        .all(|c| c.rule.as_ref().is_some_and(|r| r.id.is_empty())));
    assert_eq!(resp.history_starts_at, None);
    assert!(!resp.truncated);
}

#[test]
fn switching_a_rule_off_or_blocking_it_is_a_change_but_a_note_is_not() {
    let base = book(
        vec![domain("off.example"), domain("note.example")],
        vec![domain("block.example")],
    );
    let after = book(
        vec![
            with(domain("off.example"), |r| r.enabled = false),
            with(domain("note.example"), |r| r.comment = "edited".into()),
        ],
        vec![with(domain("block.example"), |r| {
            r.action = RuleAction::Block
        })],
    );
    let resp = changes_of(&chain(base, vec![step(50, after)]), None);
    assert_eq!(
        summary(&resp),
        vec![
            (
                RecentRuleChangeKind::Changed,
                50,
                "block.example".to_owned()
            ),
            (RecentRuleChangeKind::Changed, 50, "off.example".to_owned()),
        ]
    );
    let blocked = &resp.changes[0];
    assert_eq!(
        blocked.rule.as_ref().map(|r| r.target_route.as_str()),
        Some("block")
    );
    let off = &resp.changes[1];
    assert_eq!(off.rule.as_ref().map(|r| r.enabled), Some(false));
    assert_eq!(off.previous.as_ref().map(|p| p.enabled), Some(true));
}

#[test]
fn a_change_undone_within_the_period_leaves_nothing_to_tell() {
    let base = book(vec![domain("a.example")], Vec::new());
    let steps = vec![
        step(10, book(Vec::new(), vec![domain("a.example")])),
        step(20, book(vec![domain("a.example")], Vec::new())),
    ];
    assert!(changes_of(&chain(base, steps), None).changes.is_empty());
}

#[test]
fn a_rule_added_and_then_deleted_is_offered_back_as_it_was() {
    let base = book(Vec::new(), Vec::new());
    let steps = vec![
        step(
            10,
            book(
                Vec::new(),
                vec![with(domain("brief.example"), |r| r.comment = "mine".into())],
            ),
        ),
        step(20, book(Vec::new(), Vec::new())),
    ];
    let resp = changes_of(&chain(base, steps), None);
    assert_eq!(
        summary(&resp),
        vec![(
            RecentRuleChangeKind::Deleted,
            20,
            "brief.example".to_owned()
        )]
    );
    let rule = resp.changes[0].rule.as_ref().expect("the rule as it was");
    assert_eq!(rule.target_route, "secondary");
    assert_eq!(rule.comment.as_deref(), Some("mine"));
    assert!(!resp.changes[0].exists_now);
}

#[test]
fn a_deleted_rule_that_is_in_force_again_says_so() {
    let base = book(vec![domain("again.example")], Vec::new());
    let chain = chain(base, vec![step(5, book(Vec::new(), Vec::new()))]);
    let now = book(Vec::new(), vec![domain("again.example")]);
    let resp = changes_of(&chain, Some(&now));
    assert_eq!(resp.changes.len(), 1);
    assert!(resp.changes[0].exists_now);
}

#[test]
fn a_replaced_set_is_one_event_and_later_edits_are_told_after_it() {
    let base = book(vec![domain("before.example")], Vec::new());
    let mut imported = step(
        100,
        book(
            vec![domain("one.example"), domain("two.example")],
            vec![domain("three.example")],
        ),
    );
    imported.replaces = true;
    let steps = vec![
        step(
            50,
            book(
                vec![domain("before.example"), domain("early.example")],
                Vec::new(),
            ),
        ),
        imported,
        step(
            150,
            book(
                vec![
                    domain("one.example"),
                    domain("two.example"),
                    domain("later.example"),
                ],
                vec![domain("three.example")],
            ),
        ),
    ];
    let resp = changes_of(&chain(base, steps), None);
    assert_eq!(
        summary(&resp),
        vec![
            (RecentRuleChangeKind::Added, 150, "later.example".to_owned()),
            (RecentRuleChangeKind::Replaced, 100, "3 rules".to_owned()),
        ]
    );
    let members: Vec<&str> = resp.changes[1]
        .members
        .iter()
        .map(|r| r.match_value.as_str())
        .collect();
    assert_eq!(members, ["one.example", "three.example", "two.example"]);
}

#[test]
fn the_answer_is_bounded() {
    let many: Vec<RuleDto> = (0..MAX_RECENT_RULE_CHANGES + 7)
        .map(|i| domain(&format!("h{i}.example")))
        .collect();
    let resp = changes_of(
        &chain(
            book(Vec::new(), Vec::new()),
            vec![step(1, book(many, Vec::new()))],
        ),
        None,
    );
    assert_eq!(resp.changes.len(), MAX_RECENT_RULE_CHANGES);
    assert!(resp.truncated);

    let huge = "x".repeat(RECENT_RULE_CHANGES_TEXT_BUDGET);
    let resp = changes_of(
        &chain(
            book(Vec::new(), Vec::new()),
            vec![step(
                1,
                book(
                    vec![with(domain("big.example"), |r| r.comment = huge)],
                    Vec::new(),
                ),
            )],
        ),
        None,
    );
    assert!(resp.changes.is_empty());
    assert!(resp.truncated);
}

#[test]
fn the_same_value_on_another_rule_type_is_another_rule() {
    let zone = RuleDto {
        address_match: Some(AddressMatchDto::Zone {
            name: "example".into(),
        }),
        ..domain("")
    };
    let base = book(vec![domain("example")], Vec::new());
    let resp = changes_of(
        &chain(
            base,
            vec![step(9, book(vec![domain("example"), zone], Vec::new()))],
        ),
        None,
    );
    assert_eq!(
        summary(&resp),
        vec![(RecentRuleChangeKind::Added, 9, "example".to_owned())]
    );
    assert_eq!(
        resp.changes[0].rule.as_ref().map(|r| r.rule_type.as_str()),
        Some("zone")
    );
}

// ── Against stored revisions ─────────────────────────────────────────────────

const USER: &str = "S-1-5-21-1-2-3-1001";

fn state_db() -> Mutex<Connection> {
    let conn = Connection::open_in_memory().expect("in-memory state DB");
    let runner = SqliteMigrationRunner::for_state_db(conn);
    runner.run_pending_migrations().expect("state migrations");
    Mutex::new(runner.into_connection())
}

/// Stores `rules` as `principal`'s revision in force from `at`.
fn apply(
    conn: &Mutex<Connection>,
    principal: &str,
    id: &str,
    rules: &CanonicalRulesJsonV1,
    source: RulesRevisionSource,
    at: i64,
) {
    let guard = conn.lock().expect("lock");
    let repo = RevisionsRepository::new(&guard);
    let previous = repo
        .get_active_for(principal)
        .expect("active")
        .map(|r| r.revision_id);
    let record = RevisionRecord {
        revision_id: id.into(),
        content_hash: format!("hash-{id}"),
        rules_json: nrr_shared::rules_json::to_canonical_string(rules).expect("encode"),
        status: RevisionStatus::Candidate,
        source,
        correlation_id: "test".into(),
        created_at: at,
        activated_at: None,
        superseded_at: None,
        superseded_by: None,
        rejected_reason: None,
        review_summary_json: None,
        risk_level: None,
    };
    repo.insert_candidate_for(principal, &record)
        .expect("insert");
    repo.mark_apply_succeeded_for(principal, id, previous.as_deref(), at)
        .expect("activate");
}

#[test]
fn stored_revisions_tell_all_three_kinds_of_change() {
    let conn = state_db();
    let edit = RulesRevisionSource::GuiRulesEdit;
    apply(
        &conn,
        USER,
        "rev-1",
        &book(
            vec![domain("gone.example"), domain("moved.example")],
            Vec::new(),
        ),
        edit,
        1_000,
    );
    apply(
        &conn,
        USER,
        "rev-2",
        &book(vec![domain("added.example")], vec![domain("moved.example")]),
        edit,
        2_000,
    );
    // Another user's history stays theirs.
    apply(
        &conn,
        "S-1-5-21-1-2-3-1002",
        "rev-other",
        &book(vec![domain("theirs.example")], Vec::new()),
        edit,
        2_500,
    );
    let resp = read_for(&conn, USER, 1_500, 3_000).expect("read");
    assert_eq!(
        summary(&resp),
        vec![
            (
                RecentRuleChangeKind::Added,
                2_000,
                "added.example".to_owned()
            ),
            (
                RecentRuleChangeKind::Changed,
                2_000,
                "moved.example".to_owned()
            ),
            (
                RecentRuleChangeKind::Deleted,
                2_000,
                "gone.example".to_owned()
            ),
        ]
    );
    assert_eq!(resp.history_starts_at, None);
}

#[test]
fn a_stored_import_is_one_event() {
    let conn = state_db();
    apply(
        &conn,
        USER,
        "rev-1",
        &book(vec![domain("old.example")], Vec::new()),
        RulesRevisionSource::GuiRulesEdit,
        1_000,
    );
    apply(
        &conn,
        USER,
        "rev-2",
        &book(vec![domain("a.example"), domain("b.example")], Vec::new()),
        RulesRevisionSource::PresetImport,
        2_000,
    );
    let resp = read_for(&conn, USER, 1_500, 3_000).expect("read");
    assert_eq!(
        summary(&resp),
        vec![(RecentRuleChangeKind::Replaced, 2_000, "2 rules".to_owned())]
    );
}

#[test]
fn the_first_own_revision_is_told_against_the_baseline_it_was_made_from() {
    let conn = state_db();
    let baseline = book(vec![domain("shared.example")], Vec::new());
    apply(
        &conn,
        BASELINE_PRINCIPAL,
        "rev-base",
        &baseline,
        RulesRevisionSource::GuiRulesEdit,
        500,
    );
    apply(
        &conn,
        USER,
        "rev-1",
        &book(
            vec![domain("shared.example"), domain("mine.example")],
            Vec::new(),
        ),
        RulesRevisionSource::GuiRulesEdit,
        2_000,
    );
    // The administrator's later edit of the baseline is not the user's.
    apply(
        &conn,
        BASELINE_PRINCIPAL,
        "rev-base-2",
        &book(
            vec![domain("shared.example"), domain("admin.example")],
            Vec::new(),
        ),
        RulesRevisionSource::GuiRulesEdit,
        2_500,
    );
    let resp = read_for(&conn, USER, 1_000, 3_000).expect("read");
    assert_eq!(
        summary(&resp),
        vec![(
            RecentRuleChangeKind::Added,
            2_000,
            "mine.example".to_owned()
        )]
    );
    assert_eq!(resp.history_starts_at, None);
}

#[test]
fn a_history_shorter_than_the_period_says_where_it_starts() {
    let conn = state_db();
    // A first own revision that re-entered history: what it was made from is
    // not known, so the telling starts at it.
    apply(
        &conn,
        USER,
        "rev-1",
        &book(vec![domain("a.example")], Vec::new()),
        RulesRevisionSource::Rollback,
        2_000,
    );
    apply(
        &conn,
        USER,
        "rev-2",
        &book(vec![domain("a.example"), domain("b.example")], Vec::new()),
        RulesRevisionSource::GuiRulesEdit,
        2_600,
    );
    let resp = read_for(&conn, USER, 1_000, 3_000).expect("read");
    assert_eq!(resp.history_starts_at, Some(2_000));
    assert_eq!(
        summary(&resp),
        vec![(RecentRuleChangeKind::Added, 2_600, "b.example".to_owned())]
    );
}

#[test]
fn a_user_with_no_own_revisions_has_nothing_to_tell() {
    let conn = state_db();
    apply(
        &conn,
        BASELINE_PRINCIPAL,
        "rev-base",
        &book(vec![domain("shared.example")], Vec::new()),
        RulesRevisionSource::GuiRulesEdit,
        2_000,
    );
    let resp = read_for(&conn, USER, 1_000, 3_000).expect("read");
    assert_eq!(resp, RulesRecentChangesResponse::default());
}
