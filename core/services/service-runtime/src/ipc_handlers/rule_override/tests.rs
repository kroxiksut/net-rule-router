use super::*;

use nrr_domain::canonical::CanonicalRuleBook;
use nrr_platform_api::conn_observe::live::{LiveConnection, MockLiveConnectionSource};
use nrr_shared::ipc::{IpcClientProfile, IpcOperationName};
use nrr_storage::migration::SqliteMigrationRunner;
use nrr_storage::repository::MigrationRunner;

use crate::ipc::{IpcOperationClass, IPC_PROTOCOL_VERSION};
use crate::override_grants::tests::{requested_deny_book, site_pattern, site_root};

const ALICE: &str = "S-1-5-21-1-2-3-1001";
const BOB: &str = "S-1-5-21-1-2-3-1002";
const KEY: [u8; 32] = [3; 32];

fn ctx(sid: &str, elevated: bool) -> IpcRequestContext {
    IpcRequestContext {
        client_profile: IpcClientProfile::GuiInteractive,
        caller_is_elevated: elevated,
        caller_principal: nrr_domain::user_principal::UserPrincipal::from_windows_sid(sid).ok(),
        caller_pid: None,
    }
}

fn req(op: IpcOperationName, payload: serde_json::Value) -> IpcRequestEnvelope {
    IpcRequestEnvelope {
        protocol_version: IPC_PROTOCOL_VERSION,
        request_id: "r-ovr".into(),
        correlation_id: None,
        operation: op,
        operation_class: IpcOperationClass::UserScopedConfiguration,
        confirmation_token: None,
        payload,
    }
}

fn state_with_book(owner: &str, book: CanonicalRuleBook) -> Arc<Mutex<Connection>> {
    let conn = Connection::open_in_memory().expect("open in-memory");
    let runner = SqliteMigrationRunner::for_state_db(conn);
    runner.run_pending_migrations().expect("migrate");
    let conn = runner.into_connection();
    let content = nrr_domain::rules_revision::RulesRevisionContent {
        unrecognized: Default::default(),
        inactive: Default::default(),
        rule_book: book,
        format_version: nrr_domain::rules_revision::RULES_REVISION_FORMAT_VERSION,
    };
    let dto = nrr_domain::rules_json_codec::encode(&content);
    let json = nrr_shared::rules_json::to_canonical_string(&dto).expect("json");
    conn.execute(
        "INSERT INTO revisions (
            principal, revision_id, content_hash, rules_json, status, source,
            correlation_id, created_at, activated_at
         ) VALUES (?1, 'rev-1', 'hash-1', ?2, 'active', 'gui-rules-edit', 'c-1', 1, 1)",
        rusqlite::params![owner, json],
    )
    .expect("insert");
    Arc::new(Mutex::new(conn))
}

/// A program running from the site root under a service account.
fn served_from_site() -> LiveConnection {
    let image = match HostPlatform::compiled() {
        HostPlatform::Windows => r"C:\inetpub\app\w3wp.exe",
        HostPlatform::Linux => "/var/www/app/php-fpm",
        HostPlatform::MacOS => "/Library/WebServer/Documents/app/httpd",
    };
    LiveConnection {
        process_path: image.into(),
        remote: std::net::Ipv4Addr::new(203, 0, 113, 9),
        owner: Some("S-1-5-18".into()),
    }
}

fn deps(conn: Arc<Mutex<Connection>>, live: Vec<LiveConnection>) -> Arc<RuleOverrideDeps> {
    let source = MockLiveConnectionSource::default();
    source.set(live);
    Arc::new(RuleOverrideDeps {
        grants: OverrideGrants::open(Arc::clone(&conn), Some(KEY.to_vec()), None, now_ms()),
        conn,
        folders: None,
        live: Some(Arc::new(source)),
        unix_sys_uid_max: crate::ipc_handlers::DEFAULT_UNIX_SYS_UID_MAX,
    })
}

fn preview(deps: &Arc<RuleOverrideDeps>, sid: &str) -> RuleOverridePreviewResponse {
    let value = RuleOverridePreviewHandler::new(Arc::clone(deps))
        .handle(
            &req(
                IpcOperationName::RulesOverridePreview,
                serde_json::json!({
                    "value": format!("{} +override", site_root()),
                    "route": "block",
                }),
            ),
            &ctx(sid, false),
        )
        .expect("previewed");
    serde_json::from_value(value).expect("preview payload")
}

fn grant_request(token: &str, typed: &str) -> IpcRequestEnvelope {
    req(
        IpcOperationName::RulesOverrideGrant,
        serde_json::json!({ "token": token, "typed-value": typed, "term": "one-week" }),
    )
}

/// The rule must be saved with its request first: a hand edit of nothing, or
/// a rule without `+override`, is not offered.
#[test]
fn only_a_saved_request_is_offered() {
    let empty = deps(
        state_with_book(ALICE, CanonicalRuleBook::default()),
        Vec::new(),
    );
    let answer = preview(&empty, ALICE);
    assert_eq!(answer.status, RULE_OVERRIDE_NOT_REQUESTED);
    assert!(answer.token.is_empty());
    let book = deps(state_with_book(ALICE, requested_deny_book()), Vec::new());
    assert_eq!(
        preview(&book, BOB).status,
        RULE_OVERRIDE_NOT_REQUESTED,
        "not Bob's rule"
    );
}

#[test]
fn a_confirmation_needs_the_rule_typed_and_spends_its_token() {
    let deps = deps(state_with_book(ALICE, requested_deny_book()), Vec::new());
    let shown = preview(&deps, ALICE);
    assert_eq!(shown.status, RULE_OVERRIDE_READY);
    assert_eq!(shown.reason, "shared-folder");
    assert_eq!(shown.value, site_pattern().as_str());
    assert!(!shown.needs_administrator);
    assert_eq!(shown.token_ttl_ms, TOKEN_TTL_MS);

    let handler = RuleOverrideGrantHandler::new(Arc::clone(&deps));
    let wrong = handler
        .precheck(
            &grant_request(&shown.token, "/somewhere/else/*"),
            &ctx(ALICE, false),
        )
        .err()
        .expect("refused");
    assert_eq!(wrong.code, IpcErrorCode::PreconditionFailed);
    // Bob holds no such preview, whatever he types.
    let foreign = handler
        .precheck(&grant_request(&shown.token, site_root()), &ctx(BOB, false))
        .err()
        .expect("refused");
    assert_eq!(foreign.code, IpcErrorCode::ConfirmationUnknown);

    let granted = handler
        .handle(
            &grant_request(&shown.token, site_root()),
            &ctx(ALICE, false),
        )
        .expect("granted");
    let granted: RuleOverrideGrantResponse = serde_json::from_value(granted).expect("payload");
    assert_eq!(granted.granted.route, "block");
    assert!(granted.granted.until_ms.is_some());
    let spent = handler
        .precheck(
            &grant_request(&shown.token, site_root()),
            &ctx(ALICE, false),
        )
        .err()
        .expect("spent");
    assert_eq!(spent.code, IpcErrorCode::ConfirmationUnknown);

    let again = preview(&deps, ALICE);
    assert_eq!(again.status, RULE_OVERRIDE_GRANTED);
    assert!(again.granted.is_some());

    let revoked = RuleOverrideRevokeHandler::new(Arc::clone(&deps))
        .handle(
            &req(
                IpcOperationName::RulesOverrideRevoke,
                serde_json::json!({ "value": site_root(), "route": "block" }),
            ),
            &ctx(ALICE, false),
        )
        .expect("revoked");
    let revoked: RuleOverrideRevokeResponse = serde_json::from_value(revoked).expect("payload");
    assert!(revoked.revoked);
    assert_eq!(preview(&deps, ALICE).status, RULE_OVERRIDE_READY);
}

/// What a service account runs from takes an administrator; the refusal is
/// the one the router lifts through polkit and the window through its broker,
/// and the elevated answer still grants for the rule's owner.
#[test]
fn a_rule_that_reaches_a_service_account_needs_an_administrator() {
    let deps = deps(
        state_with_book(ALICE, requested_deny_book()),
        vec![served_from_site()],
    );
    let shown = preview(&deps, ALICE);
    assert!(shown.needs_administrator);
    assert_eq!(shown.service_accounts, ["S-1-5-18"]);
    assert!(shown.breaks.contains(&"other-programs".to_owned()));

    let handler = RuleOverrideGrantHandler::new(Arc::clone(&deps));
    let refused = handler
        .precheck(
            &grant_request(&shown.token, site_root()),
            &ctx(ALICE, false),
        )
        .err()
        .expect("needs an administrator");
    assert_eq!(refused.code, IpcErrorCode::Forbidden);
    assert!(nrr_shared::ipc_transport::is_needs_administrator(
        &refused.message
    ));
    // Not spent by the refusal: the elevated retry finds it.
    let by_admin = handler
        .handle(&grant_request(&shown.token, site_root()), &ctx(BOB, true))
        .expect("granted by an administrator");
    let by_admin: RuleOverrideGrantResponse = serde_json::from_value(by_admin).expect("payload");
    assert_eq!(by_admin.granted.value, site_pattern().as_str());
    assert!(deps
        .grants
        .grant_for(ALICE, site_pattern().as_str(), RuleEffect::Deny)
        .is_some());
    assert!(deps
        .grants
        .grant_for(BOB, site_pattern().as_str(), RuleEffect::Deny)
        .is_none());
}

#[test]
fn hostile_requests_are_refused_before_anything_is_read() {
    let deps = deps(state_with_book(ALICE, requested_deny_book()), Vec::new());
    let preview_handler = RuleOverridePreviewHandler::new(Arc::clone(&deps));
    for payload in [
        serde_json::json!({
            "value": "x".repeat(RULE_OVERRIDE_MAX_VALUE_BYTES + 1),
            "route": "block",
        }),
        serde_json::json!({ "value": site_root(), "route": "primary" }),
        serde_json::json!({ "value": "*", "route": "block" }),
        serde_json::json!({ "value": 5 }),
    ] {
        let err = preview_handler
            .handle(
                &req(IpcOperationName::RulesOverridePreview, payload),
                &ctx(ALICE, false),
            )
            .expect_err("refused");
        assert_eq!(err.code, IpcErrorCode::MalformedRequest);
    }
    let grant = RuleOverrideGrantHandler::new(Arc::clone(&deps));
    let long = grant
        .precheck(
            &grant_request(&"t".repeat(200), site_root()),
            &ctx(ALICE, false),
        )
        .err()
        .expect("refused");
    assert_eq!(long.code, IpcErrorCode::MalformedRequest);
    let unknown = grant
        .precheck(
            &grant_request("ovr-unknown", site_root()),
            &ctx(ALICE, false),
        )
        .err()
        .expect("refused");
    assert_eq!(unknown.code, IpcErrorCode::ConfirmationUnknown);
}
