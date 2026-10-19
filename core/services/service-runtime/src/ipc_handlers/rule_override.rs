//! `rules.override.{preview,grant,revoke}` — confirming one of the caller's
//! rules the protection of system programs and folders refuses (`+override`).
//!
//! The preview reads what the rule would take and hands out a token naming
//! the caller as its owner; the grant spends it. A grant that reaches past the
//! caller needs an administrator: on Linux the router asks polkit and runs the
//! request again with rights, on Windows the window's elevation broker relays
//! it. The relay may carry another identity, which is why the owner rides the
//! token rather than the connection.

use std::sync::{Arc, Mutex, PoisonError};

use nrr_domain::canonical::CanonicalAppPattern;
use nrr_domain::protected_places::{
    canonical_app_value, override_coverage, protection_verdict, AppTarget, ProgramOwner,
    ProtectionVerdict, RuleEffect, RunningProgram,
};
use nrr_domain::rules_file::HostPlatform;
use nrr_domain::RouteRole;
use nrr_platform_api::app_folders::{path_programs_once, ProgramFolders};
use nrr_platform_api::conn_observe::live::{LiveConnection, LiveConnectionSource};
use nrr_shared::ipc_payloads::{
    OverrideTerm, RuleOverrideGrantRequest, RuleOverrideGrantResponse, RuleOverridePreviewRequest,
    RuleOverridePreviewResponse, RuleOverrideRevokeRequest, RuleOverrideRevokeResponse,
    RULE_OVERRIDE_GRANTED, RULE_OVERRIDE_MAX_VALUE_BYTES, RULE_OVERRIDE_NOT_ALLOWED,
    RULE_OVERRIDE_NOT_PROTECTED, RULE_OVERRIDE_NOT_REQUESTED, RULE_OVERRIDE_READY,
    RULE_OVERRIDE_UNAVAILABLE,
};
use rusqlite::Connection;

use crate::ipc::{
    CheckedIpcHandler, HandlerOutcome, IpcError, IpcErrorCode, IpcHandler, IpcRequestContext,
    IpcRequestEnvelope, Prechecked,
};
use crate::override_grants::{
    route_slug, Grant, GrantRefused, OverrideGrants, Preview, TOKEN_TTL_MS,
};
use crate::timed_window::now_ms;

const OP_PREVIEW: &str = "rules.override.preview";
const OP_GRANT: &str = "rules.override.grant";
const OP_REVOKE: &str = "rules.override.revoke";

/// Connections read for one preview, at most.
const MAX_RUNNING_READ: usize = 4096;
/// Token bytes accepted; a real one is far shorter.
const MAX_TOKEN_BYTES: usize = 128;

/// What the three operations read: the confirmations, the caller's rules, and
/// what the machine has where the rule points.
pub struct RuleOverrideDeps {
    pub grants: Arc<OverrideGrants>,
    pub conn: Arc<Mutex<Connection>>,
    /// The folder a rule by path names; `None` where the platform lists none.
    pub folders: Option<Arc<dyn ProgramFolders>>,
    /// The programs running with a connection, and their accounts.
    pub live: Option<Arc<dyn LiveConnectionSource>>,
    /// The highest system uid, where accounts are uids.
    pub unix_sys_uid_max: u32,
}

fn error(code: IpcErrorCode, message: String) -> IpcError {
    IpcError {
        code,
        message,
        diagnostics_id: None,
    }
}

fn principal<'a>(op: &str, ctx: &'a IpcRequestContext) -> Result<&'a str, IpcError> {
    let sid = ctx.caller_stored();
    if sid.is_empty() {
        return Err(error(
            IpcErrorCode::Unauthorized,
            format!("{op}: this request carries no user identity"),
        ));
    }
    Ok(sid)
}

fn decode<T: serde::de::DeserializeOwned>(
    op: &str,
    request: &IpcRequestEnvelope,
) -> Result<T, IpcError> {
    serde_json::from_value(request.payload.clone()).map_err(|e| {
        error(
            IpcErrorCode::MalformedRequest,
            format!("{op} payload invalid: {e}"),
        )
    })
}

fn reply(op: &str, value: impl serde::Serialize) -> HandlerOutcome {
    serde_json::to_value(value).map_err(|e| {
        error(
            IpcErrorCode::Internal,
            format!("{op} serialisation failed: {e}"),
        )
    })
}

/// The effect a route slug names, when a confirmation can be about it.
fn guarded_effect(op: &str, route: &str) -> Result<RuleEffect, IpcError> {
    match RuleEffect::from_route_slug(route) {
        Some(effect) if effect.guarded() => Ok(effect),
        _ => Err(error(
            IpcErrorCode::MalformedRequest,
            format!("{op}: route must be `secondary` or `block`"),
        )),
    }
}

/// The canonical pattern of an application value as the table holds it.
fn canonical_pattern(op: &str, value: &str) -> Result<CanonicalAppPattern, IpcError> {
    if value.len() > RULE_OVERRIDE_MAX_VALUE_BYTES {
        return Err(error(
            IpcErrorCode::MalformedRequest,
            format!("{op}: value longer than {RULE_OVERRIDE_MAX_VALUE_BYTES} bytes"),
        ));
    }
    canonical_app_value(value, HostPlatform::compiled()).ok_or_else(|| {
        error(
            IpcErrorCode::MalformedRequest,
            format!("{op}: not an application value"),
        )
    })
}

/// Whether `principal`'s rules in force hold `pattern` doing `effect` with
/// `+override`. `None`: no such rule at all.
fn stored_request(
    conn: &Mutex<Connection>,
    principal: &str,
    pattern: &CanonicalAppPattern,
    effect: RuleEffect,
) -> Option<bool> {
    let dto = {
        let guard = conn.lock().unwrap_or_else(PoisonError::into_inner);
        crate::production_rules_provider::stored_book_in_force_for(&guard, principal)?
    };
    let book = nrr_domain::rules_json_codec::decode(dto, HostPlatform::compiled())
        .ok()?
        .rule_book;
    let mut found = None;
    for (set, role) in [
        (&book.primary, RouteRole::Primary),
        (&book.secondary, RouteRole::Secondary),
    ] {
        for rule in set.rules() {
            let Some(app) = rule.app_match.as_ref() else {
                continue;
            };
            if app.pattern.as_str() != pattern.as_str()
                || RuleEffect::of(rule.action, role) != effect
            {
                continue;
            }
            if app.override_requested {
                return Some(true);
            }
            found = Some(false);
        }
    }
    found
}

/// `connections` as the programs behind them, with whose they are relative to
/// `owner`; at most [`MAX_RUNNING_READ`] connections are looked at.
fn running_programs(
    connections: &[LiveConnection],
    owner: &str,
    unix_sys_uid_max: u32,
) -> Vec<(String, String, ProgramOwner)> {
    let mut out: Vec<(String, String, ProgramOwner)> = connections
        .iter()
        .take(MAX_RUNNING_READ)
        .filter_map(|connection| {
            let account = connection.owner.as_deref()?;
            let kind = if account == owner {
                ProgramOwner::Caller
            } else if crate::ipc_handlers::diagnostics_handlers::is_service_account(
                account,
                unix_sys_uid_max,
            ) {
                ProgramOwner::ServiceAccount
            } else {
                ProgramOwner::OtherUser
            };
            Some((connection.process_path.clone(), account.to_owned(), kind))
        })
        .collect();
    out.sort_unstable_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
    out.dedup_by(|a, b| a.0 == b.0 && a.1 == b.1);
    out
}

/// Reads the machine once and answers, per confirmation, which service
/// accounts run what its rule takes now. `None` for a grant whose rule cannot
/// be read back; it stays as it was.
pub fn service_accounts_reader(
    deps: &RuleOverrideDeps,
) -> impl FnMut(&Grant) -> Option<Vec<String>> + '_ {
    let connections = deps
        .live
        .as_ref()
        .map(|live| live.established())
        .unwrap_or_default();
    move |grant| {
        let pattern = canonical_app_value(&grant.value, HostPlatform::compiled())?;
        let (listing, over_cap) = match (&pattern, deps.folders.as_ref()) {
            (CanonicalAppPattern::Path(path), Some(folders)) => {
                let found = path_programs_once(folders.as_ref(), path, &grant.sid);
                let listing = found
                    .programs
                    .iter()
                    .map(|p| p.to_string_lossy().into_owned())
                    .collect();
                (listing, found.over_cap)
            }
            _ => (Vec::new(), false),
        };
        let running = running_programs(&connections, &grant.sid, deps.unix_sys_uid_max);
        let programs: Vec<RunningProgram<'_>> = running
            .iter()
            .map(|(image, account, kind)| RunningProgram {
                image,
                account,
                owner: *kind,
            })
            .collect();
        let coverage = override_coverage(
            &pattern,
            grant.reason,
            &listing,
            over_cap,
            &programs,
            crate::protected_rules::places().platform(),
        );
        Some(coverage.service_accounts)
    }
}

// ── Preview ───────────────────────────────────────────────────────────────────

pub struct RuleOverridePreviewHandler {
    deps: Arc<RuleOverrideDeps>,
}

impl RuleOverridePreviewHandler {
    pub fn new(deps: Arc<RuleOverrideDeps>) -> Self {
        Self { deps }
    }

    /// The programs running now, with whose they are.
    fn running(&self, owner: &str) -> Vec<(String, String, ProgramOwner)> {
        let Some(live) = self.deps.live.as_ref() else {
            return Vec::new();
        };
        running_programs(&live.established(), owner, self.deps.unix_sys_uid_max)
    }

    fn preview(
        &self,
        request: &RuleOverridePreviewRequest,
        owner: &str,
    ) -> Result<RuleOverridePreviewResponse, IpcError> {
        let effect = guarded_effect(OP_PREVIEW, &request.route)?;
        let pattern = canonical_pattern(OP_PREVIEW, &request.value)?;
        let value = pattern.as_str().to_owned();
        let mut out = RuleOverridePreviewResponse {
            status: RULE_OVERRIDE_NOT_REQUESTED.to_owned(),
            value: value.clone(),
            route: route_slug(effect).to_owned(),
            ..RuleOverridePreviewResponse::default()
        };
        let places = crate::protected_rules::places();
        let target = AppTarget::of_pattern(&pattern);
        let reason = match protection_verdict(target, effect, places) {
            ProtectionVerdict::Refused(reason) => reason,
            ProtectionVerdict::Warn(_) | ProtectionVerdict::Allowed => {
                out.status = RULE_OVERRIDE_NOT_PROTECTED.to_owned();
                return Ok(out);
            }
        };
        out.reason = reason.slug().to_owned();
        if !reason.overridable() {
            out.status = RULE_OVERRIDE_NOT_ALLOWED.to_owned();
            return Ok(out);
        }
        if stored_request(&self.deps.conn, owner, &pattern, effect) != Some(true) {
            return Ok(out);
        }
        // The place the disk reveals: a link into somewhere protected for
        // another reason is not what the rule names, and no confirmation of
        // the name covers it.
        let (listing, over_cap) = match (&pattern, self.deps.folders.as_ref()) {
            (CanonicalAppPattern::Path(path), Some(folders)) => {
                let found = path_programs_once(folders.as_ref(), path, owner);
                if let Some(real) = found.place.as_ref() {
                    if let ProtectionVerdict::Refused(real_reason) =
                        protection_verdict(AppTarget::of_path(real), effect, places)
                    {
                        if real_reason != reason {
                            out.status = RULE_OVERRIDE_NOT_ALLOWED.to_owned();
                            out.reason = real_reason.slug().to_owned();
                            return Ok(out);
                        }
                    }
                }
                let listing: Vec<String> = found
                    .programs
                    .iter()
                    .map(|p| p.to_string_lossy().into_owned())
                    .collect();
                (listing, found.over_cap)
            }
            _ => (Vec::new(), false),
        };
        let running = self.running(owner);
        let programs: Vec<RunningProgram<'_>> = running
            .iter()
            .map(|(image, account, kind)| RunningProgram {
                image,
                account,
                owner: *kind,
            })
            .collect();
        let coverage = override_coverage(
            &pattern,
            reason,
            &listing,
            over_cap,
            &programs,
            places.platform(),
        );
        out.programs = u32::try_from(coverage.programs).unwrap_or(u32::MAX);
        out.programs_over_cap = coverage.programs_over_cap;
        out.critical_processes = coverage.critical.clone();
        out.service_accounts = coverage.service_accounts.clone();
        out.other_users = u32::try_from(coverage.other_users).unwrap_or(u32::MAX);
        out.breaks = coverage
            .consequences
            .iter()
            .map(|c| c.slug().to_owned())
            .collect();
        out.needs_administrator = coverage.touches_machine;
        if !self.deps.grants.available() {
            out.status = RULE_OVERRIDE_UNAVAILABLE.to_owned();
            return Ok(out);
        }
        out.granted = self
            .deps
            .grants
            .grant_for(owner, &value, effect)
            .map(|grant| grant.dto());
        out.status = if out.granted.is_some() {
            RULE_OVERRIDE_GRANTED
        } else {
            RULE_OVERRIDE_READY
        }
        .to_owned();
        let now = now_ms();
        out.token = self.deps.grants.issue(
            Preview {
                owner: owner.to_owned(),
                value,
                effect,
                reason,
                critical: coverage.critical,
                accounts: coverage.service_accounts,
                programs: out.programs,
                needs_administrator: coverage.touches_machine,
            },
            now,
        );
        out.token_ttl_ms = TOKEN_TTL_MS;
        Ok(out)
    }
}

impl IpcHandler for RuleOverridePreviewHandler {
    fn handle(&self, request: &IpcRequestEnvelope, ctx: &IpcRequestContext) -> HandlerOutcome {
        let req: RuleOverridePreviewRequest = decode(OP_PREVIEW, request)?;
        let owner = principal(OP_PREVIEW, ctx)?;
        reply(OP_PREVIEW, self.preview(&req, owner)?)
    }
}

// ── Grant ─────────────────────────────────────────────────────────────────────

pub struct RuleOverrideGrantHandler {
    deps: Arc<RuleOverrideDeps>,
}

impl RuleOverrideGrantHandler {
    pub fn new(deps: Arc<RuleOverrideDeps>) -> Self {
        Self { deps }
    }
}

/// A grant that passed its checks.
pub struct CheckedGrant {
    token: String,
    preview: Preview,
    term: OverrideTerm,
    by: String,
}

impl CheckedIpcHandler for RuleOverrideGrantHandler {
    type Checked = CheckedGrant;

    fn precheck(
        &self,
        request: &IpcRequestEnvelope,
        ctx: &IpcRequestContext,
    ) -> Result<CheckedGrant, IpcError> {
        let req: RuleOverrideGrantRequest = decode(OP_GRANT, request)?;
        let caller = principal(OP_GRANT, ctx)?;
        if req.token.len() > MAX_TOKEN_BYTES {
            return Err(error(
                IpcErrorCode::MalformedRequest,
                format!("{OP_GRANT}: token longer than {MAX_TOKEN_BYTES} bytes"),
            ));
        }
        let preview = match self.deps.grants.preview(&req.token, now_ms()) {
            Ok(preview) => preview,
            Err(true) => {
                return Err(error(
                    IpcErrorCode::ConfirmationExpired,
                    format!("{OP_GRANT}: the preview ran out; open the confirmation again"),
                ))
            }
            Err(false) => {
                return Err(error(
                    IpcErrorCode::ConfirmationUnknown,
                    format!("{OP_GRANT}: no such preview"),
                ))
            }
        };
        // Someone else's preview reads as none, unless an administrator
        // answers for its owner.
        if preview.owner != caller && !ctx.caller_is_elevated {
            return Err(error(
                IpcErrorCode::ConfirmationUnknown,
                format!("{OP_GRANT}: no such preview"),
            ));
        }
        let typed = canonical_pattern(OP_GRANT, &req.typed_value).map_err(|_| {
            error(
                IpcErrorCode::PreconditionFailed,
                format!("{OP_GRANT}: the value typed does not name the rule"),
            )
        })?;
        if typed.as_str() != preview.value {
            return Err(error(
                IpcErrorCode::PreconditionFailed,
                format!("{OP_GRANT}: the value typed does not name the rule"),
            ));
        }
        if !self.deps.grants.available() {
            return Err(error(
                IpcErrorCode::ServiceDegraded,
                format!("{OP_GRANT}: confirmations cannot be kept this start"),
            ));
        }
        if preview.needs_administrator && !ctx.caller_is_elevated {
            return Err(IpcError::needs_administrator(
                "confirming a rule that reaches the system or other accounts",
            ));
        }
        Ok(CheckedGrant {
            token: req.token,
            preview,
            term: req.term,
            by: caller.to_owned(),
        })
    }

    fn execute(
        &self,
        checked: Prechecked<CheckedGrant>,
        _request: &IpcRequestEnvelope,
        _ctx: &IpcRequestContext,
    ) -> HandlerOutcome {
        let CheckedGrant {
            token,
            preview,
            term,
            by,
        } = checked.into_inner();
        match self.deps.grants.grant(&preview, term, &by, now_ms()) {
            Ok(grant) => {
                self.deps.grants.spend(&token);
                reply(
                    OP_GRANT,
                    RuleOverrideGrantResponse {
                        granted: grant.dto(),
                    },
                )
            }
            Err(GrantRefused::Unavailable) => Err(error(
                IpcErrorCode::ServiceDegraded,
                format!("{OP_GRANT}: confirmations cannot be kept this start"),
            )),
            Err(GrantRefused::TooMany) => Err(error(
                IpcErrorCode::PreconditionFailed,
                format!(
                    "{OP_GRANT}: at most {} confirmations at once",
                    crate::override_grants::MAX_GRANTS_PER_PRINCIPAL
                ),
            )),
            Err(GrantRefused::Storage(e)) => Err(error(
                IpcErrorCode::Internal,
                format!("{OP_GRANT}: the confirmation could not be kept: {e}"),
            )),
        }
    }
}

// ── Revoke ────────────────────────────────────────────────────────────────────

pub struct RuleOverrideRevokeHandler {
    deps: Arc<RuleOverrideDeps>,
}

impl RuleOverrideRevokeHandler {
    pub fn new(deps: Arc<RuleOverrideDeps>) -> Self {
        Self { deps }
    }
}

/// A revocation that passed its checks.
pub struct CheckedRevoke {
    owner: String,
    value: String,
    effect: RuleEffect,
}

impl CheckedIpcHandler for RuleOverrideRevokeHandler {
    type Checked = CheckedRevoke;

    fn precheck(
        &self,
        request: &IpcRequestEnvelope,
        ctx: &IpcRequestContext,
    ) -> Result<CheckedRevoke, IpcError> {
        let req: RuleOverrideRevokeRequest = decode(OP_REVOKE, request)?;
        let owner = principal(OP_REVOKE, ctx)?;
        let effect = guarded_effect(OP_REVOKE, &req.route)?;
        let pattern = canonical_pattern(OP_REVOKE, &req.value)?;
        Ok(CheckedRevoke {
            owner: owner.to_owned(),
            value: pattern.as_str().to_owned(),
            effect,
        })
    }

    fn execute(
        &self,
        checked: Prechecked<CheckedRevoke>,
        _request: &IpcRequestEnvelope,
        _ctx: &IpcRequestContext,
    ) -> HandlerOutcome {
        let CheckedRevoke {
            owner,
            value,
            effect,
        } = checked.into_inner();
        let revoked = self.deps.grants.revoke(&owner, &value, effect, now_ms());
        reply(OP_REVOKE, RuleOverrideRevokeResponse { revoked })
    }
}

#[cfg(test)]
mod tests;
