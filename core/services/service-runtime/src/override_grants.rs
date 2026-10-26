//! Confirmed overrides of the protection of system programs and folders.
//!
//! A rule written with `+override` asks to apply although the protection
//! refuses it. Its owner confirms it in the window or the terminal, for a
//! term. The confirmation lives here and in the state database, signed with
//! the revision key, never in the rules file: no edit of the file creates one,
//! and a row the service did not sign lifts nothing. Without the key this
//! start honours no confirmation and takes none.
//!
//! Every grant, revocation and end is audited. A timed grant ends through a
//! [`TimedSwitch`]; enforcement reads the deadline as well, so a timer that
//! did not start cannot keep a grant alive past its term.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError, Weak};

use nrr_diagnostics::audit::kind::AuditEventKind;
use nrr_diagnostics::audit::writer::AuditEventInput;
use nrr_diagnostics::reason::{integrity, ReasonCode};
use nrr_diagnostics::{ActorKind, AuditEventResult, AuditSink};
use nrr_domain::protected_places::{
    confirmation_still_covers, OverrideAsk, ProtectionReason, RuleEffect,
};
use nrr_shared::ipc_payloads::{OverrideTerm, RuleOverrideDto, StatusUpdateEvent};
use nrr_storage::override_grants::{OverrideGrantRow, OverrideGrantsRepository};
use nrr_storage::revision_hmac::{compute_grant_hmac, verify_grant, HmacVerification};
use rusqlite::Connection;

use crate::boot_integrity::AuditTrail;
use crate::ipc_handlers::event_bus::EventBus;
use crate::timed_window::{now_ms, TimedSwitch, WindowKind, WindowSink};

/// Confirmations one user may hold at once.
pub const MAX_GRANTS_PER_PRINCIPAL: usize = 64;
/// How long a preview's token stays good.
pub const TOKEN_TTL_MS: i64 = 10 * 60 * 1000;
/// Previews one user may keep waiting; their own oldest goes.
const MAX_TOKENS_PER_PRINCIPAL: usize = 8;
/// Previews waiting across users; the oldest of whoever holds most goes.
const MAX_TOKENS: usize = 64;
/// Characters of a rule value an audit record keeps.
const AUDIT_VALUE_CHARS: usize = 96;

/// What the reset leaves behind as the cause of its revocations.
pub const CAUSE_EMERGENCY_RESET: &str = "emergency-reset";
/// The cause of a withdrawal after the service stopped unexpectedly in a row.
pub const CAUSE_CRASH_LOOP: &str = "crash-loop";
/// The cause of a lapse because the service accounts a rule takes changed.
pub const CAUSE_SERVICES_CHANGED: &str = "services-changed";

/// Moves whenever what the confirmations allow changes; an enforcement pass
/// and the rules provider's decode count it among their inputs.
static GENERATION: AtomicU64 = AtomicU64::new(0);

static INSTALLED: OnceLock<Arc<OverrideGrants>> = OnceLock::new();

fn bump() {
    GENERATION.fetch_add(1, Ordering::AcqRel);
}

/// See [`GENERATION`].
#[must_use]
pub fn generation() -> u64 {
    GENERATION.load(Ordering::Acquire)
}

/// [`generation`] with the number of confirmations whose term has run out
/// folded in: what an enforcement pass counts among its inputs.
#[must_use]
pub fn pass_generation() -> u64 {
    pass_generation_at(generation(), installed().map(Arc::as_ref), now_ms())
}

/// [`pass_generation`] at `now_ms`: a term running out moves it with no timer.
fn pass_generation_at(generation: u64, grants: Option<&OverrideGrants>, now_ms: i64) -> u64 {
    let due = grants.map_or(0, |grants| grants.due_count(now_ms));
    generation.wrapping_mul(1_000_003).wrapping_add(due as u64)
}

/// Makes `grants` the service's. Only the first call counts.
pub fn install(grants: Arc<OverrideGrants>) {
    if INSTALLED.set(grants).is_ok() {
        bump();
    }
}

/// The service's confirmations; `None` before [`install`] and in tools, where
/// nothing is confirmed.
#[must_use]
pub fn installed() -> Option<&'static Arc<OverrideGrants>> {
    INSTALLED.get()
}

/// Whether `principal` confirmed `ask` and the confirmation still holds.
#[must_use]
pub fn honoured(principal: &str, ask: &OverrideAsk<'_>) -> bool {
    installed().is_some_and(|grants| grants.honours(principal, ask, now_ms()))
}

/// The earliest end of `principal`'s timed confirmations: a decode made
/// before it is stale from then on.
#[must_use]
pub fn earliest_end_for(principal: &str) -> Option<i64> {
    installed().and_then(|grants| grants.earliest_end(principal))
}

/// After a full reset erased `principal`'s data: forget their confirmations.
pub fn forget_principal(principal: &str) {
    if let Some(grants) = installed() {
        grants.forget(principal);
    }
}

/// What a rules table route slug a confirmation is for.
#[must_use]
pub const fn route_slug(effect: RuleEffect) -> &'static str {
    match effect {
        RuleEffect::Deny => "block",
        RuleEffect::SecondaryRoute => "secondary",
        RuleEffect::PrimaryRoute => "primary",
    }
}

const fn stored_effect(effect: RuleEffect) -> &'static str {
    match effect {
        RuleEffect::Deny => "deny",
        RuleEffect::SecondaryRoute | RuleEffect::PrimaryRoute => "secondary",
    }
}

fn effect_of_stored(slug: &str) -> Option<RuleEffect> {
    match slug {
        "deny" => Some(RuleEffect::Deny),
        "secondary" => Some(RuleEffect::SecondaryRoute),
        _ => None,
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct GrantKey {
    sid: String,
    value: String,
    effect: RuleEffect,
}

/// One confirmation in force.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    pub sid: String,
    /// The rule's application pattern, canonical spelling.
    pub value: String,
    pub effect: RuleEffect,
    pub reason: ProtectionReason,
    /// Critical processes it covered when confirmed, sorted.
    pub critical: Vec<String>,
    /// Service accounts seen running what it covers when confirmed, sorted.
    pub accounts: Vec<String>,
    pub programs: u32,
    pub granted_by: String,
    pub granted_at_ms: i64,
    /// `None`: until revoked.
    pub expires_at_ms: Option<i64>,
}

impl Grant {
    fn key(&self) -> GrantKey {
        GrantKey {
            sid: self.sid.clone(),
            value: self.value.clone(),
            effect: self.effect,
        }
    }

    fn order_key(&self) -> (&str, &'static str) {
        (&self.value, route_slug(self.effect))
    }

    fn live_at(&self, now_ms: i64) -> bool {
        self.expires_at_ms.is_none_or(|end| now_ms < end)
    }

    /// The row as stored, signed with `key`.
    fn signed_row(&self, key: &[u8]) -> OverrideGrantRow {
        let mut row = OverrideGrantRow {
            sid: self.sid.clone(),
            rule_value: self.value.clone(),
            effect: stored_effect(self.effect).to_owned(),
            reason: self.reason.slug().to_owned(),
            critical: self.critical.join("\n"),
            accounts: self.accounts.join("\n"),
            programs: i64::from(self.programs),
            granted_by: self.granted_by.clone(),
            granted_at: self.granted_at_ms,
            expires_at: self.expires_at_ms,
            row_hmac: Vec::new(),
        };
        row.row_hmac = compute_grant_hmac(&row.signed_fields(), key).to_vec();
        row
    }

    /// A stored row, when it verifies under `key` and reads as a grant.
    fn from_row(row: &OverrideGrantRow, key: &[u8]) -> Result<Self, &'static str> {
        match verify_grant(&row.signed_fields(), &row.row_hmac, key) {
            HmacVerification::Verified => {}
            HmacVerification::Unsigned => return Err("unsigned"),
            HmacVerification::Tampered => return Err("tampered"),
        }
        let effect = effect_of_stored(&row.effect).ok_or("malformed")?;
        let reason = ProtectionReason::from_slug(&row.reason)
            .filter(|reason| reason.overridable())
            .ok_or("malformed")?;
        let list = |text: &str| -> Vec<String> {
            text.split('\n')
                .filter(|item| !item.is_empty())
                .map(str::to_owned)
                .collect()
        };
        Ok(Self {
            sid: row.sid.clone(),
            value: row.rule_value.clone(),
            effect,
            reason,
            critical: list(&row.critical),
            accounts: list(&row.accounts),
            programs: u32::try_from(row.programs).unwrap_or(u32::MAX),
            granted_by: row.granted_by.clone(),
            granted_at_ms: row.granted_at,
            expires_at_ms: row.expires_at,
        })
    }

    /// As the rules list marks the rule.
    #[must_use]
    pub fn dto(&self) -> RuleOverrideDto {
        RuleOverrideDto {
            value: self.value.clone(),
            route: route_slug(self.effect).to_owned(),
            reason: self.reason.slug().to_owned(),
            until_ms: self.expires_at_ms,
            granted_at_ms: self.granted_at_ms,
        }
    }
}

/// A preview waiting for its confirmation: what the person was shown.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Preview {
    /// Whose rule it is. An elevated relay may run under another identity;
    /// the grant is still the owner's.
    pub owner: String,
    pub value: String,
    pub effect: RuleEffect,
    pub reason: ProtectionReason,
    pub critical: Vec<String>,
    pub accounts: Vec<String>,
    pub programs: u32,
    pub needs_administrator: bool,
}

struct Waiting {
    preview: Preview,
    issued_ms: i64,
    seq: u64,
}

/// Why a grant was not stored.
#[derive(Debug, PartialEq, Eq)]
pub enum GrantRefused {
    /// No signing key this start: nothing could be trusted later.
    Unavailable,
    /// The owner already holds [`MAX_GRANTS_PER_PRINCIPAL`].
    TooMany,
    /// The audit or the database refused; nothing changed.
    Storage(String),
}

/// How a confirmation ended, for the audit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ending {
    /// Its owner, or an administrator, took it back.
    Revoked,
    /// Its term ran out.
    Expired,
    /// A full reset of the owner's data.
    FullReset,
    /// The service stopped unexpectedly several times in a row.
    CrashLoop,
    /// A service account the rule takes was not covered by the confirmation.
    ServicesChanged,
}

impl Ending {
    const fn cause(self) -> &'static str {
        match self {
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::FullReset => "full-reset",
            Self::CrashLoop => CAUSE_CRASH_LOOP,
            Self::ServicesChanged => CAUSE_SERVICES_CHANGED,
        }
    }
}

/// The service's confirmations: in memory, mirrored to the signed rows.
pub struct OverrideGrants {
    conn: Arc<Mutex<Connection>>,
    key: Option<Vec<u8>>,
    audit: Option<Arc<AuditTrail>>,
    events: OnceLock<Arc<EventBus>>,
    grants: Mutex<HashMap<GrantKey, Grant>>,
    timers: Mutex<HashMap<GrantKey, TimedSwitch>>,
    tokens: Mutex<HashMap<String, Waiting>>,
    token_seq: AtomicU64,
    /// Users whose withdrawal no client has heard yet, with the cause.
    unheard: Mutex<HashMap<String, &'static str>>,
    this: Weak<Self>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// `owner`'s oldest waiting preview.
fn oldest_of(tokens: &HashMap<String, Waiting>, owner: &str) -> Option<String> {
    tokens
        .iter()
        .filter(|(_, waiting)| waiting.preview.owner == owner)
        .min_by_key(|(_, waiting)| waiting.seq)
        .map(|(token, _)| token.clone())
}

impl OverrideGrants {
    /// Reads the stored confirmations and the revocations a reset left. A
    /// row that does not verify is dropped and audited; one past its term is
    /// ended. Without `key` none is honoured. Call before any rules read.
    #[must_use]
    pub fn open(
        conn: Arc<Mutex<Connection>>,
        key: Option<Vec<u8>>,
        audit: Option<Arc<AuditTrail>>,
        now_ms: i64,
    ) -> Arc<Self> {
        let key = key.filter(|k| nrr_storage::revision_hmac::is_usable_signing_key(k));
        let this = Arc::new_cyclic(|weak| Self {
            conn,
            key,
            audit,
            events: OnceLock::new(),
            grants: Mutex::new(HashMap::new()),
            timers: Mutex::new(HashMap::new()),
            tokens: Mutex::new(HashMap::new()),
            token_seq: AtomicU64::new(0),
            unheard: Mutex::new(HashMap::new()),
            this: weak.clone(),
        });
        this.load(now_ms);
        this
    }

    /// Where a change of a user's confirmations is told.
    pub fn attach_events(&self, bus: Arc<EventBus>) {
        let _ = self.events.set(bus);
    }

    /// Whether this start can keep confirmations at all.
    #[must_use]
    pub fn available(&self) -> bool {
        self.key.is_some()
    }

    fn load(&self, now_ms: i64) {
        let (pending, rows) = {
            let guard = lock(&self.conn);
            let repo = OverrideGrantsRepository::new(&guard);
            let pending = repo.take_pending_revocations().unwrap_or_else(|e| {
                tracing::warn!(
                    target: "nrr::override",
                    msg_key = "protection-override-read-failed",
                    error = %e,
                    "confirmed overrides could not be read; none is honoured",
                );
                Vec::new()
            });
            let rows = repo.list().unwrap_or_default();
            (pending, rows)
        };
        for note in &pending {
            self.audit_end_note(
                &note.sid,
                &note.rule_value,
                &note.effect,
                &note.cause,
                note.revoked_at,
            );
        }
        let Some(key) = self.key.as_deref() else {
            if !rows.is_empty() {
                tracing::warn!(
                    target: "nrr::override",
                    msg_key = "protection-override-no-key",
                    count = rows.len(),
                    "confirmed overrides are not honoured this start: the signing key is unavailable",
                );
            }
            return;
        };
        let mut loaded = Vec::new();
        for row in rows {
            match Grant::from_row(&row, key) {
                Ok(grant) if grant.live_at(now_ms) => loaded.push(grant),
                Ok(grant) => {
                    self.delete_row(&grant);
                    self.audit_end(&grant, Ending::Expired, now_ms);
                }
                Err(why) => {
                    // Taking an untrusted row away only tightens.
                    let guard = lock(&self.conn);
                    let _ = OverrideGrantsRepository::new(&guard).delete(
                        &row.sid,
                        &row.rule_value,
                        &row.effect,
                    );
                    drop(guard);
                    tracing::warn!(
                        target: "nrr::override",
                        msg_key = "protection-override-row-rejected",
                        sid = %row.sid,
                        why,
                        "a stored override did not verify and was removed; the protection holds its rule",
                    );
                    self.audit_end_note(&row.sid, &row.rule_value, &row.effect, why, now_ms);
                }
            }
        }
        {
            let mut grants = lock(&self.grants);
            for grant in &loaded {
                grants.insert(grant.key(), grant.clone());
            }
        }
        for grant in &loaded {
            self.arm(grant, now_ms);
        }
        bump();
    }

    fn honours(&self, principal: &str, ask: &OverrideAsk<'_>, now_ms: i64) -> bool {
        let key = GrantKey {
            sid: principal.to_owned(),
            value: ask.value.to_owned(),
            effect: ask.effect,
        };
        lock(&self.grants).get(&key).is_some_and(|grant| {
            grant.reason == ask.reason
                && grant.live_at(now_ms)
                && confirmation_still_covers(&grant.critical, ask.critical)
        })
    }

    fn due_count(&self, now_ms: i64) -> usize {
        lock(&self.grants)
            .values()
            .filter(|grant| !grant.live_at(now_ms))
            .count()
    }

    fn earliest_end(&self, principal: &str) -> Option<i64> {
        lock(&self.grants)
            .values()
            .filter(|grant| grant.sid == principal)
            .filter_map(|grant| grant.expires_at_ms)
            .min()
    }

    /// `principal`'s confirmations in force, sorted by value.
    #[must_use]
    pub fn grants_for(&self, principal: &str) -> Vec<Grant> {
        let now = now_ms();
        let mut out: Vec<Grant> = lock(&self.grants)
            .values()
            .filter(|grant| grant.sid == principal && grant.live_at(now))
            .cloned()
            .collect();
        out.sort_by(|a, b| a.order_key().cmp(&b.order_key()));
        out
    }

    /// The confirmation `principal` holds for `value` and `effect`.
    #[must_use]
    pub fn grant_for(&self, principal: &str, value: &str, effect: RuleEffect) -> Option<Grant> {
        let key = GrantKey {
            sid: principal.to_owned(),
            value: value.to_owned(),
            effect,
        };
        lock(&self.grants)
            .get(&key)
            .filter(|grant| grant.live_at(now_ms()))
            .cloned()
    }

    // ── Previews ─────────────────────────────────────────────────────────────

    /// Keep `preview` for its confirmation; the token names it.
    #[must_use]
    pub fn issue(&self, preview: Preview, now_ms: i64) -> String {
        let seq = self.token_seq.fetch_add(1, Ordering::Relaxed);
        let token = format!("ovr-{seq:x}-{}", random_suffix());
        let mut tokens = lock(&self.tokens);
        tokens.retain(|_, waiting| now_ms - waiting.issued_ms < TOKEN_TTL_MS);
        // A person previews again before confirming: the older one goes.
        tokens.retain(|_, waiting| {
            !(waiting.preview.owner == preview.owner
                && waiting.preview.value == preview.value
                && waiting.preview.effect == preview.effect)
        });
        // One user previewing in a loop must not push out another's token
        // between their preview and confirmation.
        while tokens
            .values()
            .filter(|waiting| waiting.preview.owner == preview.owner)
            .count()
            >= MAX_TOKENS_PER_PRINCIPAL
        {
            let Some(oldest) = oldest_of(&tokens, &preview.owner) else {
                break;
            };
            tokens.remove(&oldest);
        }
        while tokens.len() >= MAX_TOKENS {
            let mut held: HashMap<&str, usize> = HashMap::new();
            for waiting in tokens.values() {
                *held.entry(waiting.preview.owner.as_str()).or_default() += 1;
            }
            let Some(busiest) = held
                .into_iter()
                .max_by_key(|(_, count)| *count)
                .map(|(owner, _)| owner.to_owned())
            else {
                break;
            };
            let Some(oldest) = oldest_of(&tokens, &busiest) else {
                break;
            };
            tokens.remove(&oldest);
        }
        tokens.insert(
            token.clone(),
            Waiting {
                preview,
                issued_ms: now_ms,
                seq,
            },
        );
        token
    }

    /// The preview `token` names, when it is still good. `Err(true)`: it was
    /// issued and ran out; `Err(false)`: never issued, or spent.
    pub fn preview(&self, token: &str, now_ms: i64) -> Result<Preview, bool> {
        let tokens = lock(&self.tokens);
        match tokens.get(token) {
            Some(waiting) if now_ms - waiting.issued_ms < TOKEN_TTL_MS => {
                Ok(waiting.preview.clone())
            }
            Some(_) => Err(true),
            None => Err(false),
        }
    }

    /// Spend `token`: a confirmation is given once.
    pub fn spend(&self, token: &str) {
        lock(&self.tokens).remove(token);
    }

    // ── Changes ──────────────────────────────────────────────────────────────

    /// Confirm `preview` for `term`, on behalf of `by`. Audited first: a
    /// confirmation that cannot be accounted for is not given.
    pub fn grant(
        &self,
        preview: &Preview,
        term: OverrideTerm,
        by: &str,
        now_ms: i64,
    ) -> Result<Grant, GrantRefused> {
        let Some(key) = self.key.as_deref() else {
            return Err(GrantRefused::Unavailable);
        };
        let grant = Grant {
            sid: preview.owner.clone(),
            value: preview.value.clone(),
            effect: preview.effect,
            reason: preview.reason,
            critical: preview.critical.clone(),
            accounts: preview.accounts.clone(),
            programs: preview.programs,
            granted_by: by.to_owned(),
            granted_at_ms: now_ms,
            expires_at_ms: term.window_ms().map(|len| now_ms.saturating_add(len)),
        };
        {
            let grants = lock(&self.grants);
            let held = grants
                .values()
                .filter(|g| g.sid == grant.sid && g.key() != grant.key())
                .count();
            if held >= MAX_GRANTS_PER_PRINCIPAL {
                return Err(GrantRefused::TooMany);
            }
        }
        self.audit_grant(&grant, term)
            .map_err(GrantRefused::Storage)?;
        {
            let guard = lock(&self.conn);
            OverrideGrantsRepository::new(&guard)
                .upsert(&grant.signed_row(key))
                .map_err(|e| GrantRefused::Storage(e.to_string()))?;
        }
        let previous_timer = {
            lock(&self.grants).insert(grant.key(), grant.clone());
            lock(&self.timers).remove(&grant.key())
        };
        disarm(previous_timer, now_ms);
        self.arm(&grant, now_ms);
        bump();
        tracing::warn!(
            target: "nrr::override",
            msg_key = "protection-override-granted",
            sid = %grant.sid,
            rule = %grant.value,
            reason = %grant.reason,
            term = term.slug(),
            "a rule the protection of system programs refuses was confirmed and applies for its term",
        );
        self.tell(&grant.sid, Vec::new(), "");
        Ok(grant)
    }

    /// Take back `principal`'s confirmation for `value` and `effect`; `false`
    /// when there was none.
    pub fn revoke(&self, principal: &str, value: &str, effect: RuleEffect, now_ms: i64) -> bool {
        let key = GrantKey {
            sid: principal.to_owned(),
            value: value.to_owned(),
            effect,
        };
        match self.take(&key, true) {
            Some(grant) => {
                self.delete_row(&grant);
                self.audit_end(&grant, Ending::Revoked, now_ms);
                self.tell(principal, Vec::new(), "");
                true
            }
            None => false,
        }
    }

    /// The term of the grant `key` ran out.
    fn end(&self, key: &GrantKey) {
        let now = now_ms();
        let due = lock(&self.grants)
            .get(key)
            .is_some_and(|grant| !grant.live_at(now));
        if !due {
            return;
        }
        // From the timer's own thread, which holds its switch: stopping it
        // here would wait on itself, and it stops on its own.
        let Some(grant) = self.take(key, false) else {
            return;
        };
        self.delete_row(&grant);
        self.audit_end(&grant, Ending::Expired, now);
        tracing::info!(
            target: "nrr::override",
            msg_key = "protection-override-expired",
            sid = %grant.sid,
            rule = %grant.value,
            "a confirmed override reached the end of its term; the protection holds its rule again",
        );
        self.tell(&grant.sid, vec![grant.value.clone()], "");
    }

    /// `principal`'s rows are already gone with the rest of their data.
    fn forget(&self, principal: &str) {
        let keys: Vec<GrantKey> = lock(&self.grants)
            .keys()
            .filter(|key| key.sid == principal)
            .cloned()
            .collect();
        if keys.is_empty() {
            return;
        }
        let now = now_ms();
        for key in keys {
            if let Some(grant) = self.take(&key, true) {
                self.audit_end(&grant, Ending::FullReset, now);
            }
        }
        self.tell(principal, Vec::new(), "");
    }

    /// Remove `key` from memory and its timer from the map, stopping it when
    /// `stop_timer`.
    fn take(&self, key: &GrantKey, stop_timer: bool) -> Option<Grant> {
        let grant = lock(&self.grants).remove(key);
        let timer = lock(&self.timers).remove(key);
        if stop_timer {
            disarm(timer, now_ms());
        }
        if grant.is_some() {
            bump();
        }
        grant
    }

    fn delete_row(&self, grant: &Grant) {
        let guard = lock(&self.conn);
        if let Err(e) = OverrideGrantsRepository::new(&guard).delete(
            &grant.sid,
            &grant.value,
            stored_effect(grant.effect),
        ) {
            tracing::warn!(
                target: "nrr::override",
                msg_key = "protection-override-delete-failed",
                error = %e,
                "an ended override could not be removed from the database; it is not honoured",
            );
        }
    }

    /// A timer for a timed grant. Taken back early, the timer is stopped and
    /// its sink finds nothing left to end.
    fn arm(&self, grant: &Grant, now_ms: i64) {
        let Some(deadline) = grant.expires_at_ms else {
            return;
        };
        let weak = self.this.clone();
        let key = grant.key();
        let sink_key = key.clone();
        let sink: WindowSink = Arc::new(move |open: bool| {
            if open {
                return;
            }
            if let Some(this) = weak.upgrade() {
                this.end(&sink_key);
            }
        });
        let switch = TimedSwitch::resume(
            WindowKind::ProtectionOverride,
            Some(deadline),
            now_ms,
            Some(sink),
        );
        lock(&self.timers).insert(key, switch);
    }

    fn tell(&self, principal: &str, expired: Vec<String>, cause: &str) {
        if let Some(bus) = self.events.get() {
            bus.publish_for(
                principal,
                StatusUpdateEvent::RuleOverridesChanged {
                    sid: principal.to_owned(),
                    expired,
                    cause: cause.to_owned(),
                },
            );
        }
    }

    /// Take back every confirmation of every user, each audited with `ending`'s
    /// cause. A crash-loop withdrawal is told once a client of the user is
    /// there to hear it ([`Self::deliver_unheard`]); returns how many went.
    pub fn revoke_all(&self, ending: Ending, now_ms: i64) -> usize {
        let keys: Vec<GrantKey> = lock(&self.grants).keys().cloned().collect();
        let mut owners: Vec<String> = Vec::new();
        for key in keys {
            let Some(grant) = self.take(&key, true) else {
                continue;
            };
            self.delete_row(&grant);
            self.audit_end(&grant, ending, now_ms);
            if !owners.contains(&grant.sid) {
                owners.push(grant.sid);
            }
        }
        let count = owners.len();
        for sid in owners {
            if ending == Ending::CrashLoop {
                lock(&self.unheard).insert(sid, CAUSE_CRASH_LOOP);
            } else {
                self.tell(&sid, Vec::new(), ending.cause());
            }
        }
        count
    }

    /// Tell the users a withdrawal left unheard, as soon as one of their
    /// clients is subscribed: the push right after a start has no listener.
    pub fn deliver_unheard(&self) {
        let Some(bus) = self.events.get() else {
            return;
        };
        let mut unheard = lock(&self.unheard);
        if unheard.is_empty() {
            return;
        }
        unheard.retain(|sid, cause| {
            if !bus.has_subscriber_for(sid) {
                return true;
            }
            bus.publish_for(
                sid.as_str(),
                StatusUpdateEvent::RuleOverridesChanged {
                    sid: sid.clone(),
                    expired: Vec::new(),
                    cause: (*cause).to_owned(),
                },
            );
            false
        });
    }

    /// Re-check the service accounts each confirmation covers. `accounts_now`
    /// names the accounts running what a grant's rule takes now (`None`: could
    /// not be told, the grant stays). A grant whose rule now takes an account it
    /// did not list goes back to waiting for a confirmation. Returns how many.
    pub fn recheck_accounts(
        &self,
        accounts_now: &mut dyn FnMut(&Grant) -> Option<Vec<String>>,
        now_ms: i64,
    ) -> usize {
        let held: Vec<Grant> = lock(&self.grants)
            .values()
            .filter(|grant| grant.live_at(now_ms))
            .cloned()
            .collect();
        let mut lapsed: HashMap<String, Vec<String>> = HashMap::new();
        for grant in held {
            let Some(now) = accounts_now(&grant) else {
                continue;
            };
            if confirmation_still_covers(&grant.accounts, &now) {
                continue;
            }
            let Some(taken) = self.take(&grant.key(), true) else {
                continue;
            };
            self.delete_row(&taken);
            self.audit_end(&taken, Ending::ServicesChanged, now_ms);
            tracing::warn!(
                target: "nrr::override",
                msg_key = "protection-override-services-changed",
                sid = %taken.sid,
                rule = %taken.value,
                "a service account now runs what a confirmed rule takes; the rule waits for a new confirmation",
            );
            lapsed.entry(taken.sid).or_default().push(taken.value);
        }
        let count = lapsed.values().map(Vec::len).sum();
        for (sid, values) in lapsed {
            self.tell(&sid, values, CAUSE_SERVICES_CHANGED);
        }
        count
    }

    // ── Audit ────────────────────────────────────────────────────────────────

    fn audit_grant(&self, grant: &Grant, term: OverrideTerm) -> Result<(), String> {
        let Some(audit) = self.audit.as_ref() else {
            return Ok(());
        };
        let summary = serde_json::json!({
            "rule": audit_value(&grant.value),
            "route": route_slug(grant.effect),
            "reason": grant.reason.slug(),
            "term": term.slug(),
            "until": grant.expires_at_ms,
            "programs": grant.programs,
            "critical": grant.critical.len(),
            "accounts": grant.accounts.len(),
            "by-owner": grant.granted_by == grant.sid,
        });
        AuditSink::append(
            &**audit,
            input(
                AuditEventKind::ProtectionOverrideGranted,
                integrity::PROTECTION_OVERRIDE_GRANTED,
                ActorKind::User,
                &grant.granted_by,
                grant.granted_at_ms,
                &summary,
            ),
        )
        .map_err(|e| e.to_string())
    }

    fn audit_end(&self, grant: &Grant, ending: Ending, at_ms: i64) {
        let reason = if ending == Ending::Expired {
            integrity::PROTECTION_OVERRIDE_EXPIRED
        } else {
            integrity::PROTECTION_OVERRIDE_REVOKED
        };
        let actor = if ending == Ending::Revoked {
            ActorKind::User
        } else {
            ActorKind::Service
        };
        let summary = serde_json::json!({
            "rule": audit_value(&grant.value),
            "route": route_slug(grant.effect),
            "reason": grant.reason.slug(),
            "cause": ending.cause(),
        });
        self.append(reason, actor, &grant.sid, at_ms, &summary);
    }

    /// An end known only from a row: a reset's note, or a row that did not
    /// verify.
    fn audit_end_note(&self, sid: &str, value: &str, effect: &str, cause: &str, at_ms: i64) {
        let summary = serde_json::json!({
            "rule": audit_value(value),
            "route": effect_of_stored(effect).map_or("unknown", route_slug),
            "cause": cause,
        });
        self.append(
            integrity::PROTECTION_OVERRIDE_REVOKED,
            ActorKind::Service,
            sid,
            at_ms,
            &summary,
        );
    }

    fn append(
        &self,
        reason: ReasonCode,
        actor: ActorKind,
        sid: &str,
        at_ms: i64,
        summary: &serde_json::Value,
    ) {
        let Some(audit) = self.audit.as_ref() else {
            return;
        };
        let record = input(
            AuditEventKind::ProtectionOverrideRevoked,
            reason,
            actor,
            sid,
            at_ms,
            summary,
        );
        if let Err(e) = AuditSink::append(&**audit, record) {
            tracing::error!(
                target: "nrr::override",
                msg_key = "protection-override-audit-failed",
                error = %e,
                "the end of a confirmed override could not be audited; it ended all the same",
            );
        }
    }
}

fn input(
    kind: AuditEventKind,
    reason: ReasonCode,
    actor: ActorKind,
    sid: &str,
    at_ms: i64,
    summary: &serde_json::Value,
) -> AuditEventInput {
    AuditEventInput {
        event_id: crate::production_ipc_audit::next_audit_event_id(),
        kind,
        created_at: at_ms,
        actor_kind: actor,
        actor_id_hash: nrr_diagnostics::audit::actor_id_hash(sid),
        revision_id: None,
        risk_level: Some(
            if kind == AuditEventKind::ProtectionOverrideGranted {
                "high"
            } else {
                "low"
            }
            .to_owned(),
        ),
        result: AuditEventResult::Success,
        reason_code: reason,
        payload_summary_json: Some(summary.to_string()),
    }
}

/// The value an audit record keeps: enough to tell the rule, never a long path.
fn audit_value(value: &str) -> String {
    value.chars().take(AUDIT_VALUE_CHARS).collect()
}

/// Stop a timer taken out of the map. Its sink then finds no grant to end.
fn disarm(timer: Option<TimedSwitch>, now_ms: i64) {
    if let Some(timer) = timer {
        timer.set(crate::timed_window::TimedWindow::Off, now_ms);
    }
}

fn random_suffix() -> String {
    let mut bytes = [0u8; 16];
    match getrandom::fill(&mut bytes) {
        Ok(()) => bytes.iter().map(|b| format!("{b:02x}")).collect(),
        // Spent once, bound to its owner and short-lived: a guessable token
        // still confirms nothing its owner was not shown.
        Err(_) => format!("{:032x}", u128::try_from(now_ms()).unwrap_or(0)),
    }
}

/// The emergency network reset, run while the service is stopped: every
/// confirmation goes, each leaving a note the next start audits. The reset
/// holds no key and needs none: it only takes away. `Ok(0)` when there is no
/// database or no table yet.
pub fn revoke_all_offline(state_db_path: &std::path::Path) -> Result<usize, String> {
    if !state_db_path.exists() {
        return Ok(0);
    }
    let conn =
        nrr_storage::migration::open_connection(state_db_path).map_err(|e| format!("{e:?}"))?;
    let table_present: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'override_grants'",
            [],
            |r| r.get::<_, i64>(0),
        )
        .map(|n| n > 0)
        .map_err(|e| e.to_string())?;
    if !table_present {
        return Ok(0);
    }
    OverrideGrantsRepository::new(&conn)
        .revoke_all_pending_audit(now_ms(), CAUSE_EMERGENCY_RESET)
        .map_err(|e| e.to_string())
}

#[cfg(test)]
pub(crate) mod tests;
