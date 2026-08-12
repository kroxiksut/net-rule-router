//! `block-notices.mutes.{list,set,remove,clear}` and
//! `block-notices.route-to-secondary` handlers.
//!
//! Mutes are personal, so every op here is scoped to the CALLER's own
//! principal and none requires elevation — silencing your own notices, or
//! routing a host YOU were blocked on, must never meet a UAC prompt. Same
//! stance as the companion-domain suggestion ops in `auto_rules_handlers`.
//!
//! A mute write must reach the live [`BlockNoticeCenter`] ledger before it can
//! do anything: without the `reload_mutes` call after every set/remove/clear,
//! the mute only takes effect after the next service restart.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use nrr_domain::block_notice::{Mute, MuteScope};
use nrr_shared::ipc_payloads::{
    BlockNoticeMuteDto, BlockNoticeMuteScopeDto, BlockNoticeMutesClearResponse,
    BlockNoticeMutesListResponse, BlockNoticeMutesRemoveRequest, BlockNoticeMutesRemoveResponse,
    BlockNoticeMutesSetRequest, BlockNoticeMutesSetResponse, BlockNoticeRouteToSecondaryRequest,
    BlockNoticeRouteToSecondaryResponse,
};
use nrr_shared::{AutoRuleReason, RouteRole};

use crate::auto_rules::{AuthoredMatchKind, AuthoredRule, AutoRuleAuthor};
use crate::block_notice_center::BlockNoticeCenter;
use crate::block_notice_mute_store::BlockNoticeMuteStore;
use crate::ipc::{
    HandlerOutcome, IpcError, IpcErrorCode, IpcHandler, IpcRequestContext, IpcRequestEnvelope,
};

/// Resolves the principal a request acts for. Mutes and rules are both
/// per-principal, so an unattributed caller cannot be served — guessing here
/// would show one user another user's mutes or write into their rules.
fn principal(ctx: &IpcRequestContext) -> Result<&str, IpcError> {
    let sid = ctx.caller_stored();
    if sid.is_empty() {
        return Err(IpcError {
            code: IpcErrorCode::Unauthorized,
            message: "this request carries no user identity, so it cannot be scoped to a user"
                .to_string(),
            diagnostics_id: None,
        });
    }
    Ok(sid)
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn malformed(context: &str, err: impl std::fmt::Display) -> IpcError {
    IpcError {
        code: IpcErrorCode::MalformedRequest,
        message: format!("{context}: {err}"),
        diagnostics_id: None,
    }
}

fn serialize(context: &str, value: impl serde::Serialize) -> HandlerOutcome {
    serde_json::to_value(value).map_err(|e| IpcError {
        code: IpcErrorCode::Internal,
        message: format!("{context} serialisation failed: {e}"),
        diagnostics_id: None,
    })
}

fn scope_from_dto(dto: BlockNoticeMuteScopeDto) -> Result<MuteScope, IpcError> {
    match dto {
        BlockNoticeMuteScopeDto::Host { host } if !host.trim().is_empty() => {
            Ok(MuteScope::Host(host))
        }
        BlockNoticeMuteScopeDto::Host { .. } => Err(IpcError {
            code: IpcErrorCode::MalformedRequest,
            message: "a host mute needs a non-empty host name".to_string(),
            diagnostics_id: None,
        }),
        BlockNoticeMuteScopeDto::App { app } if !app.trim().is_empty() => Ok(MuteScope::App(app)),
        BlockNoticeMuteScopeDto::App { .. } => Err(IpcError {
            code: IpcErrorCode::MalformedRequest,
            message: "an app mute needs a non-empty image name".to_string(),
            diagnostics_id: None,
        }),
        BlockNoticeMuteScopeDto::Reason { reason } => {
            nrr_domain::block_notice::BlockReason::from_slug(reason.trim())
                .map(MuteScope::Reason)
                .ok_or_else(|| IpcError {
                    code: IpcErrorCode::MalformedRequest,
                    message: format!("unknown block reason {reason:?}"),
                    diagnostics_id: None,
                })
        }
        BlockNoticeMuteScopeDto::All => Ok(MuteScope::All),
    }
}

fn dto_from_scope(scope: &MuteScope) -> BlockNoticeMuteScopeDto {
    match scope {
        MuteScope::Host(host) => BlockNoticeMuteScopeDto::Host { host: host.clone() },
        MuteScope::App(app) => BlockNoticeMuteScopeDto::App { app: app.clone() },
        MuteScope::Reason(reason) => BlockNoticeMuteScopeDto::Reason {
            reason: reason.slug().to_string(),
        },
        MuteScope::All => BlockNoticeMuteScopeDto::All,
    }
}

fn dto_from_mute(mute: &Mute) -> BlockNoticeMuteDto {
    BlockNoticeMuteDto {
        scope: dto_from_scope(&mute.scope),
        until_unix_ms: mute.until_ms,
    }
}

fn active_mutes(store: &dyn BlockNoticeMuteStore, sid: &str) -> Vec<BlockNoticeMuteDto> {
    store
        .list_active(sid, now_ms())
        .iter()
        .map(dto_from_mute)
        .collect()
}

// ── list ─────────────────────────────────────────────────────────────────────

pub struct BlockNoticeMutesListHandler {
    store: Arc<dyn BlockNoticeMuteStore>,
}

impl BlockNoticeMutesListHandler {
    pub fn new(store: Arc<dyn BlockNoticeMuteStore>) -> Self {
        Self { store }
    }
}

impl IpcHandler for BlockNoticeMutesListHandler {
    fn handle(&self, _request: &IpcRequestEnvelope, ctx: &IpcRequestContext) -> HandlerOutcome {
        let sid = principal(ctx)?;
        serialize(
            "block-notices.mutes.list",
            BlockNoticeMutesListResponse {
                mutes: active_mutes(self.store.as_ref(), sid),
            },
        )
    }
}

// ── set ──────────────────────────────────────────────────────────────────────

pub struct BlockNoticeMutesSetHandler {
    store: Arc<dyn BlockNoticeMuteStore>,
    center: Arc<BlockNoticeCenter>,
}

impl BlockNoticeMutesSetHandler {
    pub fn new(store: Arc<dyn BlockNoticeMuteStore>, center: Arc<BlockNoticeCenter>) -> Self {
        Self { store, center }
    }
}

impl IpcHandler for BlockNoticeMutesSetHandler {
    fn handle(&self, request: &IpcRequestEnvelope, ctx: &IpcRequestContext) -> HandlerOutcome {
        let sid = principal(ctx)?;
        let parsed: BlockNoticeMutesSetRequest = serde_json::from_value(request.payload.clone())
            .map_err(|e| malformed("block-notices.mutes.set payload invalid", e))?;
        let scope = scope_from_dto(parsed.scope)?;
        let mute = Mute {
            scope,
            until_ms: parsed.until_unix_ms,
        };
        self.store.upsert(sid, &mute, now_ms());
        self.center.reload_mutes(sid);
        serialize(
            "block-notices.mutes.set",
            BlockNoticeMutesSetResponse {
                mutes: active_mutes(self.store.as_ref(), sid),
            },
        )
    }
}

// ── remove ───────────────────────────────────────────────────────────────────

pub struct BlockNoticeMutesRemoveHandler {
    store: Arc<dyn BlockNoticeMuteStore>,
    center: Arc<BlockNoticeCenter>,
}

impl BlockNoticeMutesRemoveHandler {
    pub fn new(store: Arc<dyn BlockNoticeMuteStore>, center: Arc<BlockNoticeCenter>) -> Self {
        Self { store, center }
    }
}

impl IpcHandler for BlockNoticeMutesRemoveHandler {
    fn handle(&self, request: &IpcRequestEnvelope, ctx: &IpcRequestContext) -> HandlerOutcome {
        let sid = principal(ctx)?;
        let parsed: BlockNoticeMutesRemoveRequest = serde_json::from_value(request.payload.clone())
            .map_err(|e| malformed("block-notices.mutes.remove payload invalid", e))?;
        let scope = scope_from_dto(parsed.scope)?;
        // A scope that was never muted is a no-op, not an error — the caller
        // only ever asks for their own mute to go away.
        let removed = self.store.remove(sid, &scope);
        self.center.reload_mutes(sid);
        serialize(
            "block-notices.mutes.remove",
            BlockNoticeMutesRemoveResponse {
                removed,
                mutes: active_mutes(self.store.as_ref(), sid),
            },
        )
    }
}

// ── clear ────────────────────────────────────────────────────────────────────

pub struct BlockNoticeMutesClearHandler {
    store: Arc<dyn BlockNoticeMuteStore>,
    center: Arc<BlockNoticeCenter>,
}

impl BlockNoticeMutesClearHandler {
    pub fn new(store: Arc<dyn BlockNoticeMuteStore>, center: Arc<BlockNoticeCenter>) -> Self {
        Self { store, center }
    }
}

impl IpcHandler for BlockNoticeMutesClearHandler {
    fn handle(&self, _request: &IpcRequestEnvelope, ctx: &IpcRequestContext) -> HandlerOutcome {
        let sid = principal(ctx)?;
        self.store.clear(sid);
        self.center.reload_mutes(sid);
        serialize(
            "block-notices.mutes.clear",
            BlockNoticeMutesClearResponse {
                mutes: active_mutes(self.store.as_ref(), sid),
            },
        )
    }
}

// ── route-to-secondary ──────────────────────────────────────────────────────

pub struct BlockNoticeRouteToSecondaryHandler {
    author: Arc<dyn AutoRuleAuthor>,
    center: Option<Arc<BlockNoticeCenter>>,
}

impl BlockNoticeRouteToSecondaryHandler {
    pub fn new(author: Arc<dyn AutoRuleAuthor>) -> Self {
        Self {
            author,
            center: None,
        }
    }

    /// Close the notice's episode once the rule is written. Without this the
    /// notice outlives the answer the user just gave it.
    #[must_use]
    pub fn with_center(mut self, center: Arc<BlockNoticeCenter>) -> Self {
        self.center = Some(center);
        self
    }
}

impl IpcHandler for BlockNoticeRouteToSecondaryHandler {
    fn handle(&self, request: &IpcRequestEnvelope, ctx: &IpcRequestContext) -> HandlerOutcome {
        let sid = principal(ctx)?;
        let parsed: BlockNoticeRouteToSecondaryRequest =
            serde_json::from_value(request.payload.clone())
                .map_err(|e| malformed("block-notices.route-to-secondary payload invalid", e))?;
        let destination = parsed.destination.trim().trim_end_matches('.').to_string();
        if destination.is_empty() {
            return Err(IpcError {
                code: IpcErrorCode::MalformedRequest,
                message: "destination must not be empty".to_string(),
                diagnostics_id: None,
            });
        }
        // A raw address has no hostname a suffix rule can match — the notice
        // falls back to the address only when the host was never learned, and
        // there is nothing to route by in that case.
        if destination.parse::<IpAddr>().is_ok() {
            return Err(IpcError {
                code: IpcErrorCode::PreconditionFailed,
                message: "this destination has no known hostname to route by".to_string(),
                diagnostics_id: None,
            });
        }

        let rule_value = destination.clone();
        let rule = AuthoredRule {
            route: RouteRole::Secondary,
            match_kind: AuthoredMatchKind::SuffixDomain,
            value: destination.clone(),
            anchor: destination,
        };
        let now = SystemTime::now();
        let correlation = format!("block-notice-route-{}", now_ms());
        match self.author.author(
            sid,
            &AutoRuleReason::BlockNoticeRouted,
            &[rule],
            now,
            &correlation,
        ) {
            Ok(count) => {
                if let Some(center) = self.center.as_ref() {
                    center.resolve_destination(sid, &rule_value);
                }
                serialize(
                    "block-notices.route-to-secondary",
                    BlockNoticeRouteToSecondaryResponse {
                        authored: count > 0,
                    },
                )
            }
            // Same posture as `AutoRuleCandidatesAcceptHandler`: pass the
            // executor's own code through so the user sees why the write was
            // refused (rule cap, tamper gate) rather than a generic failure.
            Err(e) => Err(IpcError {
                code: IpcErrorCode::PreconditionFailed,
                message: format!("{}: {}", e.code, e.message),
                diagnostics_id: None,
            }),
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::auto_rules::AuthorError;
    use crate::block_notice_mute_store::InMemoryBlockNoticeMuteStore;
    use crate::ipc::{IpcOperationClass, IPC_PROTOCOL_VERSION};
    use nrr_shared::ipc::{IpcClientProfile, IpcOperationName};
    use std::sync::Mutex;

    fn ctx(sid: Option<&str>) -> IpcRequestContext {
        IpcRequestContext {
            client_profile: IpcClientProfile::TrayLightweight,
            caller_is_elevated: false,
            caller_principal: sid
                .and_then(|s| nrr_domain::user_principal::UserPrincipal::from_windows_sid(s).ok()),
        }
    }

    fn req(op: IpcOperationName, payload: serde_json::Value) -> IpcRequestEnvelope {
        IpcRequestEnvelope {
            protocol_version: IPC_PROTOCOL_VERSION,
            request_id: "r-bn".into(),
            correlation_id: None,
            operation: op,
            operation_class: IpcOperationClass::ReadSnapshot,
            confirmation_token: None,
            payload,
        }
    }

    fn wired() -> (Arc<dyn BlockNoticeMuteStore>, Arc<BlockNoticeCenter>) {
        let store: Arc<dyn BlockNoticeMuteStore> = Arc::new(InMemoryBlockNoticeMuteStore::new());
        let center = Arc::new(BlockNoticeCenter::new());
        (store, center)
    }

    #[test]
    fn listing_for_a_caller_with_nothing_muted_returns_an_empty_set() {
        let (store, _center) = wired();
        let h = BlockNoticeMutesListHandler::new(store);
        let value = h
            .handle(
                &req(
                    IpcOperationName::BlockNoticeMutesList,
                    serde_json::Value::Null,
                ),
                &ctx(Some("S-A")),
            )
            .expect("list");
        let parsed: BlockNoticeMutesListResponse = serde_json::from_value(value).expect("decode");
        assert!(parsed.mutes.is_empty());
    }

    #[test]
    fn an_unattributed_caller_is_refused_rather_than_served_someone_elses_mutes() {
        let (store, _center) = wired();
        let h = BlockNoticeMutesListHandler::new(store);
        let err = h
            .handle(
                &req(
                    IpcOperationName::BlockNoticeMutesList,
                    serde_json::Value::Null,
                ),
                &ctx(None),
            )
            .expect_err("no identity");
        assert_eq!(err.code, IpcErrorCode::Unauthorized);
    }

    #[test]
    fn setting_a_mute_takes_effect_on_the_live_ledger_without_a_restart() {
        // Prove the write reaches the LIVE ledger, not only the store: a mute
        // set through the handler must silence the very next matching
        // episode, with no service restart in between.
        let store = Arc::new(InMemoryBlockNoticeMuteStore::new());
        let bus = Arc::new(crate::ipc_handlers::event_bus::EventBus::new());
        // The loader is the SAME production shape: it reads through the SAME
        // store the handler writes to, so a mute set via IPC is visible the
        // moment `reload_mutes` asks for it — no restart needed.
        let loader_store = Arc::clone(&store);
        let center = Arc::new(
            BlockNoticeCenter::new()
                .with_event_bus(Arc::clone(&bus))
                .with_mute_loader(Arc::new(move |sid: &str| loader_store.list_active(sid, 0))),
        );
        let store: Arc<dyn BlockNoticeMuteStore> = store;
        let sub = bus.subscribe("test-client".to_string(), None);

        let notice = |host: &str| nrr_domain::block_notice::BlockAttempt {
            host: Some(host.to_string()),
            dest: "203.0.113.7".to_string(),
            app: Some("chrome.exe".to_string()),
            reason: nrr_domain::block_notice::BlockReason::NotCoveredByRules,
        };
        // A block from an unrelated host creates S-A's ledger — proving the
        // mute set below reaches an ALREADY-LIVE ledger, not just a fresh one
        // seeded at creation time.
        center.record("S-A", &notice("other.example"));
        let pending = bus.peek_pending_for(&sub.subscription_id, 10);
        assert_eq!(pending.len(), 1);
        bus.advance_cursor(&sub.subscription_id, pending[0].event_id);

        let set = BlockNoticeMutesSetHandler::new(Arc::clone(&store), Arc::clone(&center));
        let value = set
            .handle(
                &req(
                    IpcOperationName::BlockNoticeMutesSet,
                    serde_json::json!({
                        "scope": { "kind": "host", "host": "cdn.example" },
                    }),
                ),
                &ctx(Some("S-A")),
            )
            .expect("set");
        let parsed: BlockNoticeMutesSetResponse = serde_json::from_value(value).expect("decode");
        assert_eq!(parsed.mutes.len(), 1);
        assert_eq!(
            parsed.mutes[0].scope,
            BlockNoticeMuteScopeDto::Host {
                host: "cdn.example".into()
            }
        );

        center.record("S-A", &notice("cdn.example"));
        assert!(
            bus.peek_pending_for(&sub.subscription_id, 10).is_empty(),
            "the mute set through the handler must silence this episode immediately"
        );
    }

    #[test]
    fn a_host_mute_needs_a_non_empty_host_name() {
        let (store, center) = wired();
        let set = BlockNoticeMutesSetHandler::new(store, center);
        let err = set
            .handle(
                &req(
                    IpcOperationName::BlockNoticeMutesSet,
                    serde_json::json!({ "scope": { "kind": "host", "host": "" } }),
                ),
                &ctx(Some("S-A")),
            )
            .expect_err("empty host");
        assert_eq!(err.code, IpcErrorCode::MalformedRequest);
    }

    #[test]
    fn removing_a_mute_that_was_never_set_does_not_fail_the_call() {
        let (store, center) = wired();
        let remove = BlockNoticeMutesRemoveHandler::new(store, center);
        let value = remove
            .handle(
                &req(
                    IpcOperationName::BlockNoticeMutesRemove,
                    serde_json::json!({ "scope": { "kind": "host", "host": "cdn.example" } }),
                ),
                &ctx(Some("S-A")),
            )
            .expect("remove is a no-op, not an error");
        let parsed: BlockNoticeMutesRemoveResponse = serde_json::from_value(value).expect("decode");
        assert!(!parsed.removed);
        assert!(parsed.mutes.is_empty());
    }

    #[test]
    fn a_second_sid_neither_sees_nor_can_remove_the_first_sids_mute() {
        let (store, center) = wired();
        BlockNoticeMutesSetHandler::new(Arc::clone(&store), Arc::clone(&center))
            .handle(
                &req(
                    IpcOperationName::BlockNoticeMutesSet,
                    serde_json::json!({ "scope": { "kind": "all" } }),
                ),
                &ctx(Some("S-A")),
            )
            .expect("set for S-A");

        let listed = BlockNoticeMutesListHandler::new(Arc::clone(&store))
            .handle(
                &req(
                    IpcOperationName::BlockNoticeMutesList,
                    serde_json::Value::Null,
                ),
                &ctx(Some("S-B")),
            )
            .expect("list for S-B");
        let parsed: BlockNoticeMutesListResponse = serde_json::from_value(listed).expect("decode");
        assert!(parsed.mutes.is_empty(), "S-B must not see S-A's mute");

        let removed = BlockNoticeMutesRemoveHandler::new(store, center)
            .handle(
                &req(
                    IpcOperationName::BlockNoticeMutesRemove,
                    serde_json::json!({ "scope": { "kind": "all" } }),
                ),
                &ctx(Some("S-B")),
            )
            .expect("remove for S-B");
        let parsed: BlockNoticeMutesRemoveResponse =
            serde_json::from_value(removed).expect("decode");
        assert!(!parsed.removed, "S-B must not be able to remove S-A's mute");
    }

    #[test]
    fn clearing_drops_every_mute_for_the_caller_only() {
        let (store, center) = wired();
        for scope in [
            serde_json::json!({ "kind": "host", "host": "a.example" }),
            serde_json::json!({ "kind": "app", "app": "chrome.exe" }),
        ] {
            BlockNoticeMutesSetHandler::new(Arc::clone(&store), Arc::clone(&center))
                .handle(
                    &req(
                        IpcOperationName::BlockNoticeMutesSet,
                        serde_json::json!({ "scope": scope }),
                    ),
                    &ctx(Some("S-A")),
                )
                .expect("set");
        }
        BlockNoticeMutesSetHandler::new(Arc::clone(&store), Arc::clone(&center))
            .handle(
                &req(
                    IpcOperationName::BlockNoticeMutesSet,
                    serde_json::json!({ "scope": { "kind": "all" } }),
                ),
                &ctx(Some("S-B")),
            )
            .expect("set for S-B");

        let value = BlockNoticeMutesClearHandler::new(Arc::clone(&store), Arc::clone(&center))
            .handle(
                &req(
                    IpcOperationName::BlockNoticeMutesClear,
                    serde_json::Value::Null,
                ),
                &ctx(Some("S-A")),
            )
            .expect("clear");
        let parsed: BlockNoticeMutesClearResponse = serde_json::from_value(value).expect("decode");
        assert!(parsed.mutes.is_empty());

        let other = BlockNoticeMutesListHandler::new(store)
            .handle(
                &req(
                    IpcOperationName::BlockNoticeMutesList,
                    serde_json::Value::Null,
                ),
                &ctx(Some("S-B")),
            )
            .expect("list S-B");
        let parsed: BlockNoticeMutesListResponse = serde_json::from_value(other).expect("decode");
        assert_eq!(parsed.mutes.len(), 1, "clearing S-A must not touch S-B");
    }

    // ── route-to-secondary ───────────────────────────────────────────────────

    struct RecordingAuthor {
        calls: Mutex<Vec<(String, AutoRuleReason, Vec<AuthoredRule>)>>,
        result: Result<u32, AuthorError>,
    }

    impl RecordingAuthor {
        fn ok(count: u32) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                result: Ok(count),
            }
        }

        fn failing(code: &str, message: &str) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                result: Err(AuthorError {
                    code: code.to_string(),
                    message: message.to_string(),
                }),
            }
        }
    }

    impl AutoRuleAuthor for RecordingAuthor {
        fn author(
            &self,
            principal: &str,
            reason: &AutoRuleReason,
            rules: &[AuthoredRule],
            _now: SystemTime,
            _correlation_id: &str,
        ) -> Result<u32, AuthorError> {
            self.calls.lock().unwrap_or_else(|p| p.into_inner()).push((
                principal.to_string(),
                reason.clone(),
                rules.to_vec(),
            ));
            self.result.clone()
        }
    }

    #[test]
    fn routing_a_blocked_host_authors_a_suffix_rule_on_the_secondary_route() {
        let author = Arc::new(RecordingAuthor::ok(1));
        let h =
            BlockNoticeRouteToSecondaryHandler::new(Arc::clone(&author) as Arc<dyn AutoRuleAuthor>);
        let value = h
            .handle(
                &req(
                    IpcOperationName::BlockNoticeRouteToSecondary,
                    serde_json::json!({ "destination": "cdn.example" }),
                ),
                &ctx(Some("S-A")),
            )
            .expect("route");
        let parsed: BlockNoticeRouteToSecondaryResponse =
            serde_json::from_value(value).expect("decode");
        assert!(parsed.authored);

        let calls = author.calls.lock().unwrap_or_else(|p| p.into_inner());
        assert_eq!(calls.len(), 1);
        let (principal, reason, rules) = &calls[0];
        assert_eq!(principal, "S-A");
        assert_eq!(reason, &AutoRuleReason::BlockNoticeRouted);
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].route, RouteRole::Secondary);
        assert_eq!(rules[0].match_kind, AuthoredMatchKind::SuffixDomain);
        assert_eq!(rules[0].value, "cdn.example");
    }

    #[test]
    fn routing_the_host_closes_the_notice_that_asked_about_it() {
        // The complaint this fixes: the rule is added from the tray and the
        // notice keeps standing.
        let bus = Arc::new(crate::ipc_handlers::event_bus::EventBus::new());
        let sub = bus.subscribe("test-client".to_string(), None);
        let center = Arc::new(BlockNoticeCenter::new().with_event_bus(Arc::clone(&bus)));
        let attempt = nrr_domain::block_notice::BlockAttempt {
            host: Some("cdn.example".to_string()),
            dest: "203.0.113.7".to_string(),
            app: Some("chrome.exe".to_string()),
            reason: nrr_domain::block_notice::BlockReason::NotCoveredByRules,
        };
        center.record("S-A", &attempt);
        assert_eq!(bus.peek_pending_for(&sub.subscription_id, 10).len(), 1);

        let author = Arc::new(RecordingAuthor::ok(1));
        let h =
            BlockNoticeRouteToSecondaryHandler::new(Arc::clone(&author) as Arc<dyn AutoRuleAuthor>)
                .with_center(Arc::clone(&center));
        h.handle(
            &req(
                IpcOperationName::BlockNoticeRouteToSecondary,
                serde_json::json!({ "destination": "cdn.example" }),
            ),
            &ctx(Some("S-A")),
        )
        .expect("route");

        // The episode is gone, so the very next block is news again rather than
        // a silent retry of a notice the user already answered.
        center.record("S-A", &attempt);
        assert_eq!(
            bus.peek_pending_for(&sub.subscription_id, 10).len(),
            2,
            "the episode was closed, so a later block speaks again"
        );
    }

    #[test]
    fn a_raw_address_destination_is_refused_rather_than_authored_as_a_suffix() {
        let author = Arc::new(RecordingAuthor::ok(1));
        let h = BlockNoticeRouteToSecondaryHandler::new(author as Arc<dyn AutoRuleAuthor>);
        let err = h
            .handle(
                &req(
                    IpcOperationName::BlockNoticeRouteToSecondary,
                    serde_json::json!({ "destination": "203.0.113.7" }),
                ),
                &ctx(Some("S-A")),
            )
            .expect_err("no hostname");
        assert_eq!(err.code, IpcErrorCode::PreconditionFailed);
    }

    #[test]
    fn a_refused_write_passes_the_authors_code_through() {
        let author = Arc::new(RecordingAuthor::failing(
            "rule-cap-exceeded",
            "too many rules",
        ));
        let h = BlockNoticeRouteToSecondaryHandler::new(author as Arc<dyn AutoRuleAuthor>);
        let err = h
            .handle(
                &req(
                    IpcOperationName::BlockNoticeRouteToSecondary,
                    serde_json::json!({ "destination": "cdn.example" }),
                ),
                &ctx(Some("S-A")),
            )
            .expect_err("refused");
        assert_eq!(err.code, IpcErrorCode::PreconditionFailed);
        assert!(err.message.contains("rule-cap-exceeded"));
    }
}
