//! Companion-domain discovery: the service side.
//!
//! # The problem this solves
//!
//! A user routes `example.com` over the additional link. The page loads, but its
//! images and video come from CDN hostnames no rule mentions, so those requests
//! go direct and fail. Today the user has to notice, guess the CDN's name, and
//! type a rule. This module makes the service notice instead.
//!
//! # Shape
//!
//! - **Learning** is [`nrr_domain::companion_affinity`] — pure, deterministic,
//!   bounded. This module owns one ledger per user principal and feeds it from
//!   the DNS-observation batch that already runs at 1 Hz. An observation whose
//!   hostname matches an active rule opens/extends that rule host's window; every
//!   other observation may become a companion of the windows currently open.
//! - **Proposing** happens on a slow tick, never per observation: the ledger
//!   computes proposals lazily and the answer only changes on the scale of a
//!   browsing session, so recomputing per observation would burn CPU to produce
//!   the same list.
//! - **Deciding** is the user's, through `auto_rules_mode`: `off` collects
//!   nothing, `suggest` (the default) parks findings for the tray to offer, and
//!   `auto` authors them straight into the user's own rules.
//!
//! # Cost
//!
//! Nothing here sits on the data path. The per-observation cost is one hash
//! lookup and, for a genuinely new hostname, one string allocation — the same
//! order as the rule match the consumer already performs. The mutex is taken
//! once per BATCH, not once per observation, so a busy second does not turn into
//! a thousand lock acquisitions.
//!
//! # Known limitation
//!
//! Observations are attributed to the single routing-active SID, because that is
//! all the DNS path can currently tell us: on Windows the system resolver issues
//! the query, so the observation carries no requesting process and therefore no
//! user. Everything below is keyed by SID regardless — ledgers, pending sets,
//! refusals, authoring — so when a per-user observation feed arrives it replaces
//! one argument at the call site and nothing else.

pub mod authoring;
pub mod store;

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant, SystemTime};

use nrr_domain::canonical::{CanonicalAddressMatch, CanonicalRuleBook};
use nrr_domain::companion_affinity::{
    CandidateExclusions, CoActivityKind, CompanionAffinityConfig, CompanionAffinityLedger,
    CompanionEvidenceSnapshot, CompanionProposal, CompanionSignal, PrimaryBehavior,
    PrimaryHealthEvent,
};
use nrr_shared::ipc_payloads::{
    AutoRuleCandidateDto, AutoRuleConsumerDto, AutoRuleDismissedEntryDto, StatusUpdateEvent,
    AUTO_RULE_MATCH_KIND_EXACT, AUTO_RULE_MATCH_KIND_SUFFIX, AUTO_RULE_PRIMARY_BEHAVIOR_CUT,
    AUTO_RULE_PRIMARY_BEHAVIOR_RESPONDS, AUTO_RULE_PRIMARY_BEHAVIOR_STALLS,
    AUTO_RULE_SIGNAL_BRAND_RELATED, AUTO_RULE_SIGNAL_CO_ACTIVITY, AUTO_RULE_SIGNAL_DELIVERY_NAME,
    AUTO_RULE_SIGNAL_ISP_BLOCK_PAGE,
};
use nrr_shared::{AutoRuleReason, RouteRole};
use nrr_storage::auto_rule_dismissals::AutoRuleDismissal;
use nrr_storage::auto_rule_pending::AutoRulePendingRecord;
use nrr_storage::auto_rules::AutoRulesMode;
use sha2::{Digest, Sha256};

use crate::dns_observation_consumer::rule_set_matches;
use crate::ipc_handlers::event_bus::EventBus;
use crate::per_sid_orchestrator::RulesProvider;

pub use authoring::{
    AuthorError, AuthoredMatchKind, AuthoredRule, AutoRuleAuthor, ProductionAutoRuleAuthor,
};
pub use store::{
    DismissalStore, EvidenceStore, InMemoryDismissalStore, InMemoryEvidenceStore,
    InMemoryPendingStore, PendingSuggestionStore, SqliteDismissalStore, SqliteEvidenceStore,
    SqlitePendingStore,
};

// ── Tunables ─────────────────────────────────────────────────────────────────

/// How long a SID's companion-discovery settings are trusted before re-reading.
///
/// They live in the state DB and the observation feed consults them once per
/// batch — at 1 Hz that would be a database read every second forever, to answer
/// a question whose answer changes about once a year. Ten seconds is short
/// enough that flipping a setting in the GUI feels immediate and long enough
/// that the steady-state cost rounds to zero.
const MODE_MEMO_TTL: Duration = Duration::from_secs(10);

/// How long an accepted suggestion keeps suppressing itself. Only has to
/// outlast the activation that creates the rule; past that the rule book is the
/// authority, so deleting the rule makes the host offerable again.
const AUTHORED_SUPPRESSION: Duration = Duration::from_secs(300);

/// Minimum gap between two `AutoRuleCandidatesChanged` pushes for one SID.
///
/// The tray opens a window on each event. Publishing on every tick that found
/// one more candidate would turn a helpful notice into a stream of popups, so
/// unannounced suggestions are announced at most this often. What arrives
/// inside the gap is not lost — the next tick still sees it as unannounced.
///
/// The FIRST announcement for a principal skips this entirely (there is nothing
/// to space it from), which is what makes a suggestion appear during the visit
/// that produced it. The gap only paces what follows.
const PUBLISH_MIN_INTERVAL: Duration = Duration::from_secs(20);

/// How often accumulated evidence is written to disk.
///
/// The cost of the gap is what a hard kill loses; the cost of writing more
/// often is one JSON serialisation and one row update per principal. A minute
/// leaves at most a minute of browsing unsaved, which is far below the window
/// granularity the evidence is counted in.
const EVIDENCE_SAVE_INTERVAL: Duration = Duration::from_secs(60);

/// Maximum suggestions held for one principal at a time.
///
/// A browsing session can produce far more than a person will ever review — one
/// acceptance run reached 102 — and an offer nobody can get through is the same
/// as no offer. At the cap the weakest are dropped: the strongest evidence is
/// what deserves the user's attention.
const MAX_PENDING_PER_PRINCIPAL: usize = 50;

/// How long an unanswered suggestion survives without fresh evidence (24 h) —
/// the same horizon the learner keeps evidence for, so the two cannot disagree
/// about what is still current.
const PENDING_TTL_MS: i64 = 86_400_000;

/// Maximum principals tracked concurrently.
///
/// Free is single-active-user, so in practice this is one. The cap exists so a
/// machine with fast-user-switching cannot accumulate ledgers without bound; on
/// overflow the principal with the least accumulated evidence is dropped, since
/// it is the one whose loss costs the least and which re-learns fastest.
const MAX_TRACKED_PRINCIPALS: usize = 8;

// ── Ports ────────────────────────────────────────────────────────────────────

/// Reads a principal's `auto_rules_mode`. A closure over the per-SID policy
/// source at the composition root, so this module never learns what a
/// `secondary_block_policy` row is.
pub type AutoRulesModeFn = Arc<dyn Fn(&str) -> AutoRulesMode + Send + Sync>;

/// Reads a principal's `auto_rules_eager_delivery_names` opt-in — same per-SID
/// source and same reason for being a closure as [`AutoRulesModeFn`]. Unwired
/// means "not opted in", which is also the stored default.
pub type AutoRulesEagerDeliveryFn = Arc<dyn Fn(&str) -> bool + Send + Sync>;

/// What one principal configured for companion discovery, read together and
/// memoised together because they are one row and are consulted on the same
/// paths.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PrincipalSettings {
    mode: AutoRulesMode,
    eager_delivery_names: bool,
}

/// One principal's ledger plus the setting it was constructed with.
///
/// The ledger takes its configuration once and keeps it for life, so a user who
/// flips the setting gets a new ledger rather than a reconfigured one; the pair
/// lives together so the two can never disagree.
struct SidLedger {
    eager_delivery_names: bool,
    ledger: CompanionAffinityLedger,
}

impl SidLedger {
    fn config(eager_delivery_names: bool) -> CompanionAffinityConfig {
        CompanionAffinityConfig {
            propose_delivery_names_without_co_activity: eager_delivery_names,
            ..CompanionAffinityConfig::default()
        }
    }

    fn new(eager_delivery_names: bool) -> Self {
        Self {
            eager_delivery_names,
            ledger: CompanionAffinityLedger::new(Self::config(eager_delivery_names)),
        }
    }

    /// A ledger holding evidence saved before the last restart. The config
    /// comes from the CURRENT setting, never from the snapshot.
    fn restored(eager_delivery_names: bool, snapshot: CompanionEvidenceSnapshot) -> Self {
        Self {
            eager_delivery_names,
            ledger: CompanionAffinityLedger::restored(Self::config(eager_delivery_names), snapshot),
        }
    }
}

// ── Pending candidates ───────────────────────────────────────────────────────

/// One suggestion waiting for an answer.
#[derive(Clone, Debug, PartialEq)]
struct PendingCandidate {
    dto: AutoRuleCandidateDto,
    route: RouteRole,
    match_kind: AuthoredMatchKind,
}

impl PendingCandidate {
    fn authored_rule(&self) -> AuthoredRule {
        AuthoredRule {
            route: self.route,
            match_kind: self.match_kind,
            value: self.dto.proposed_match.clone(),
            anchor: self.dto.anchor.clone(),
        }
    }

    /// Reconstructs a candidate from its persisted DTO. `None` when the DTO
    /// carries a route or match-kind slug this build does not recognise — a
    /// row from a newer build, or a hand-edited database — in which case the
    /// row is dropped rather than guessed at.
    fn from_dto(dto: AutoRuleCandidateDto) -> Option<Self> {
        let route = [RouteRole::Primary, RouteRole::Secondary]
            .into_iter()
            .find(|r| r.slug() == dto.route)?;
        let match_kind = match dto.match_kind.as_str() {
            AUTO_RULE_MATCH_KIND_EXACT => AuthoredMatchKind::ExactHost,
            AUTO_RULE_MATCH_KIND_SUFFIX => AuthoredMatchKind::SuffixDomain,
            _ => return None,
        };
        Some(Self {
            dto,
            route,
            match_kind,
        })
    }

    /// The refusal record, carrying the offer itself so undoing the refusal can
    /// hand it straight back. A DTO that will not serialize is stored empty
    /// rather than dropping the refusal: suppressing the host is the part the
    /// user asked for, restoring it verbatim is the convenience.
    fn dismissal(&self) -> AutoRuleDismissal {
        AutoRuleDismissal {
            candidate_id: self.dto.id.clone(),
            anchor: self.dto.anchor.clone(),
            proposed_match: self.dto.proposed_match.clone(),
            dto_json: serde_json::to_string(&self.dto).unwrap_or_default(),
        }
    }
}

/// Per-principal announcement bookkeeping — the debounce state.
#[derive(Clone, Debug, Default)]
struct PublishState {
    /// Ids already announced — identity, not a count. Accepting a suggestion
    /// lowers the pending total, so "more than last time" silences every later
    /// arrival that stays under the session's high-water mark.
    announced: HashSet<String>,
    announced_at: Option<SystemTime>,
}

/// What one proposal tick did, for logging and tests.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TickSummary {
    /// Suggestions newly parked for review (`suggest` mode).
    pub parked: u32,
    /// Rules authored without asking (`auto` mode).
    pub authored: u32,
    /// Total pending for this principal after the tick.
    pub pending: usize,
    /// An `AutoRuleCandidatesChanged` push was emitted.
    pub published: bool,
}

/// Result of accepting or dismissing a set of suggestions.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ActionSummary {
    pub applied: u32,
    pub unknown: u32,
    pub pending: usize,
}

// ── Exclusions ───────────────────────────────────────────────────────────────

/// Applies the product's three exclusion rules to a proposal, reading the
/// principal's live rule book.
struct RuleBookExclusions<'a> {
    book: &'a CanonicalRuleBook,
}

impl CandidateExclusions for RuleBookExclusions<'_> {
    /// A hostname that is itself the subject of a rule.
    ///
    /// Deliberately wider than "there is an ExactFqdn rule for it": a
    /// `SuffixDomain` rule's own apex is not *matched* by that rule (subdomain
    /// semantics exclude the apex), so without checking the rule's VALUE too, a
    /// suffix suggestion the user just accepted would be offered again forever.
    fn is_rule_host(&self, hostname: &str) -> bool {
        [&self.book.primary, &self.book.secondary]
            .into_iter()
            .flat_map(|set| set.rules().iter())
            .filter(|r| r.enabled)
            .any(|r| match &r.address_match {
                Some(CanonicalAddressMatch::ExactFqdn(v))
                | Some(CanonicalAddressMatch::SuffixDomain(v))
                | Some(CanonicalAddressMatch::Zone(v)) => v == hostname,
                _ => false,
            })
    }

    fn is_matched_by_existing_rule(&self, hostname: &str) -> bool {
        rule_set_matches(hostname, &self.book.primary)
            || rule_set_matches(hostname, &self.book.secondary)
    }

    fn is_platform_infrastructure(&self, hostname: &str) -> bool {
        crate::fake_ip::self_heal::is_platform_infrastructure(hostname)
    }
}

// ── Observation batch ────────────────────────────────────────────────────────

/// Exclusive access to one principal's ledger for the duration of one
/// observation batch.
///
/// Holding the guard across the batch is the point: the lock is acquired once
/// per drain instead of once per observation, so a second with a thousand
/// resolutions costs one acquisition.
pub struct LedgerBatch<'a> {
    ledgers: MutexGuard<'a, HashMap<String, SidLedger>>,
    sid: &'a str,
}

impl LedgerBatch<'_> {
    /// Records one observation. Allocation-light by construction: the only
    /// allocation is the hostname copy the ledger makes the first time it sees a
    /// name, and the ledger's own caps bound how many of those can exist.
    pub fn observe(&mut self, at_ms: u64, hostname: &str, kind: CoActivityKind) {
        if let Some(entry) = self.ledgers.get_mut(self.sid) {
            entry.ledger.observe(at_ms, hostname, kind);
        }
    }

    /// Records a primary-route outcome. Carries no timestamp on purpose: an
    /// outcome is not a sighting, so it must neither open a window nor postpone
    /// TTL eviction, and a caller supplying one would imply otherwise.
    pub fn note_primary_health(&mut self, hostname: &str, event: PrimaryHealthEvent) {
        self.observe(0, hostname, CoActivityKind::PrimaryHealth(event));
    }
}

// ── Engine ───────────────────────────────────────────────────────────────────

/// Owns the per-principal ledgers, the pending suggestions, and the decision of
/// what to do with a finding.
pub struct AutoRulesEngine {
    ledgers: Mutex<HashMap<String, SidLedger>>,
    pending: Mutex<HashMap<String, Vec<PendingCandidate>>>,
    /// Refusals, read once per principal per session and then kept here.
    dismissed: Mutex<HashMap<String, HashSet<String>>>,
    /// Ids authored recently, with the moment they were. The rule itself is the
    /// durable record; this only covers the window until the activation lands.
    /// Entries expire ([`AUTHORED_SUPPRESSION`]) so that a rule the user later
    /// deletes stops silencing its own host.
    authored: Mutex<HashMap<String, HashMap<String, Instant>>>,
    publish_state: Mutex<HashMap<String, PublishState>>,
    settings_memo: Mutex<HashMap<String, (PrincipalSettings, Instant)>>,
    mode_for: AutoRulesModeFn,
    /// `None` means the composition root wired no source, so nobody is opted in.
    eager_delivery_for: Option<AutoRulesEagerDeliveryFn>,
    rules: Arc<dyn RulesProvider>,
    dismissals: Arc<dyn DismissalStore>,
    /// Durable mirror of `pending`. Written through on every change so a
    /// restart resumes with the same offer set instead of an empty one.
    pending_store: Arc<dyn PendingSuggestionStore>,
    /// Set once, possibly AFTER construction: the observation consumer is built
    /// long before the mutation executor exists at the composition root, and the
    /// engine must be the same `Arc` in both places. A write-once cell keeps the
    /// read side lock-free on the accept path.
    author: OnceLock<Arc<dyn AutoRuleAuthor>>,
    events: Option<Arc<EventBus>>,
    /// Gate for [`Self::note_isp_blocked_host`]. Off by default. `Arc` so
    /// production can share it live with the settings writer; tests get a private one.
    isp_block_candidates_enabled: Arc<AtomicBool>,
    /// Durable mirror of the ledgers. A proposal needs two windows, and a
    /// restart used to reset the count to zero — a machine that restarts a few
    /// times a day therefore never reached the second one. `None` (no state DB)
    /// keeps the old session-scoped behaviour.
    evidence_store: Option<Arc<dyn EvidenceStore>>,
    /// When each principal's evidence was last written, so the save rides the
    /// proposal tick without writing on every one of them.
    evidence_saved_at: Mutex<HashMap<String, Instant>>,
}

impl AutoRulesEngine {
    /// `now` seeds the TTL check that filters restored suggestions — taken
    /// explicitly, like every other time-sensitive call on this engine,
    /// rather than read from the clock internally, so a test can control it.
    pub fn new(
        rules: Arc<dyn RulesProvider>,
        mode_for: AutoRulesModeFn,
        dismissals: Arc<dyn DismissalStore>,
        pending_store: Arc<dyn PendingSuggestionStore>,
        now: SystemTime,
    ) -> Self {
        let now_ms = unix_ms(now);
        Self {
            ledgers: Mutex::new(HashMap::new()),
            pending: Mutex::new(hydrate_pending(pending_store.as_ref(), now_ms)),
            dismissed: Mutex::new(HashMap::new()),
            authored: Mutex::new(HashMap::new()),
            publish_state: Mutex::new(HashMap::new()),
            settings_memo: Mutex::new(HashMap::new()),
            mode_for,
            eager_delivery_for: None,
            rules,
            dismissals,
            pending_store,
            author: OnceLock::new(),
            events: None,
            isp_block_candidates_enabled: Arc::new(AtomicBool::new(false)),
            evidence_store: None,
            evidence_saved_at: Mutex::new(HashMap::new()),
        }
    }

    /// Is a ledger already live for `sid`? Read on its own so the evidence load
    /// can happen off the ledger lock.
    fn ledgers_contains(&self, sid: &str) -> bool {
        self.ledgers
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .contains_key(sid)
    }

    /// Writes `sid`'s accumulated evidence, at most once per
    /// [`EVIDENCE_SAVE_INTERVAL`]. The snapshot is taken under the ledger lock
    /// and the write happens after it is released — the observation feed is
    /// never held open across a disk write.
    fn persist_evidence(&self, sid: &str, now: SystemTime) {
        let Some(store) = self.evidence_store.as_ref() else {
            return;
        };
        {
            let mut saved = self
                .evidence_saved_at
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            let at = Instant::now();
            match saved.get(sid) {
                Some(last) if at.duration_since(*last) < EVIDENCE_SAVE_INTERVAL => return,
                _ => saved.insert(sid.to_string(), at),
            };
        }
        let snapshot = {
            let ledgers = self.ledgers.lock().unwrap_or_else(|p| p.into_inner());
            ledgers.get(sid).map(|l| l.ledger.snapshot())
        };
        if let Some(snapshot) = snapshot {
            store.save(sid, &snapshot, unix_ms(now));
        }
    }

    /// Attach the durable evidence store. Without it the learner still works,
    /// it just starts from nothing after every restart — which on a laptop is
    /// the difference between suggestions appearing and never appearing.
    #[must_use]
    pub fn with_evidence_store(mut self, store: Arc<dyn EvidenceStore>) -> Self {
        self.evidence_store = Some(store);
        self
    }

    /// Attach the rule author. Without it `auto` mode collects and parks like
    /// `suggest`, and `accept` reports `authoring-unavailable` rather than
    /// silently dropping the user's answer.
    #[must_use]
    pub fn with_author(self, author: Arc<dyn AutoRuleAuthor>) -> Self {
        self.attach_author(author);
        self
    }

    /// Attach the author after construction. Returns `false` when one was
    /// already attached, which the caller may ignore — the first wins, and a
    /// second attach means the composition root wired the same engine twice.
    pub fn attach_author(&self, author: Arc<dyn AutoRuleAuthor>) -> bool {
        self.author.set(author).is_ok()
    }

    /// Attach the per-SID source of the eager delivery-name opt-in. Without it
    /// every principal keeps the conservative default, which is what an
    /// un-opted-in user gets anyway.
    #[must_use]
    pub fn with_eager_delivery_names(mut self, source: AutoRulesEagerDeliveryFn) -> Self {
        self.eager_delivery_for = Some(source);
        self
    }

    /// Attach the push channel so the tray learns about new suggestions without
    /// polling. Without it the suggestions still accumulate and the GUI can
    /// still list them on demand.
    #[must_use]
    pub fn with_event_bus(mut self, events: Arc<EventBus>) -> Self {
        self.events = Some(events);
        self
    }

    /// Arms [`Self::note_isp_blocked_host`]. Stores into this engine's own flag,
    /// so parallel test fixtures never leak state to each other.
    #[must_use]
    pub fn with_isp_block_candidates(self, enabled: bool) -> Self {
        self.isp_block_candidates_enabled
            .store(enabled, Ordering::Relaxed);
        self
    }

    /// Replace the gate with an externally-owned flag, so a settings writer
    /// can flip it live via the same `Arc`, no restart.
    #[must_use]
    pub fn with_isp_block_candidates_flag(mut self, flag: Arc<AtomicBool>) -> Self {
        self.isp_block_candidates_enabled = flag;
        self
    }

    // ── Observation feed ─────────────────────────────────────────────────────

    /// Opens an observation batch for `sid`, or returns `None` when this
    /// principal collects nothing (`auto_rules_mode = off`) — the caller then
    /// does no work at all, which is what "off" has to mean.
    pub fn begin_batch<'a>(&'a self, sid: &'a str) -> Option<LedgerBatch<'a>> {
        let settings = self.settings(sid);
        if settings.mode == AutoRulesMode::Off {
            return None;
        }
        let eager = settings.eager_delivery_names;
        // Read BEFORE the ledger lock: the store touches SQLite, and holding
        // the observation feed shut for a disk read would stall every caller.
        let saved = match self.evidence_store.as_ref() {
            Some(store) if !self.ledgers_contains(sid) => store.load(sid),
            _ => None,
        };
        let mut ledgers = self.ledgers.lock().unwrap_or_else(|p| p.into_inner());
        match ledgers.get(sid) {
            Some(existing) if existing.eager_delivery_names == eager => {}
            // Setting changed under a live ledger. It cannot be reconfigured in
            // place, so it is replaced; the evidence lost re-accumulates over the
            // next few page loads, which is the same cost as a service restart.
            Some(_) => {
                ledgers.insert(sid.to_string(), SidLedger::new(eager));
            }
            None => {
                evict_if_over_cap(&mut ledgers, sid);
                ledgers.insert(
                    sid.to_string(),
                    match saved {
                        Some(snapshot) if !snapshot.is_empty() => {
                            tracing::info!(
                                target: "nrr::auto-rules",
                                candidates = snapshot.candidates.len(),
                                anchors = snapshot.anchors.len(),
                                "restored companion evidence saved before the last restart",
                            );
                            SidLedger::restored(eager, snapshot)
                        }
                        _ => SidLedger::new(eager),
                    },
                );
            }
        }
        Some(LedgerBatch { ledgers, sid })
    }

    /// A flow to `hostname` just opened — treat it as activity, exactly like a
    /// DNS resolution of the same name.
    ///
    /// Why this exists: a window only opens when the learner is TOLD the site is
    /// in use, and until now the only source of that was a DNS observation. A
    /// browser answering from its own cache, or resolving over DoH, produces no
    /// observation at all — so the anchor stayed shut while the user sat on the
    /// page, and every companion loading beside it attached to nothing. A
    /// connection is the one signal that cannot be cached away: it is the thing
    /// the user is actually doing.
    ///
    /// Called from the relay's poll thread, so it does exactly what the DNS path
    /// does and nothing more: one classification against the rule book, one
    /// ledger write.
    ///
    /// Takes a wall-clock instant, not a duration: the ledger compares this
    /// against windows opened by the DNS path and against the proposal tick,
    /// both of which are wall-clock. A monotonic "millis since this observer
    /// started" reads as 1970 next to them, so every window it opened was
    /// invisible to the other source and every candidate it reported landed
    /// outside all of them.
    pub fn note_flow(&self, sid: &str, hostname: &str, at: SystemTime) {
        if hostname.is_empty() {
            return;
        }
        let at_ms = unix_ms(at).max(0) as u64;
        let Some(snapshot) = self.rules.active_rules_for(sid) else {
            return;
        };
        let kind = Self::classify(
            rule_set_matches(hostname, &snapshot.rule_book.primary),
            rule_set_matches(hostname, &snapshot.rule_book.secondary),
        );
        let Some(mut batch) = self.begin_batch(sid) else {
            return;
        };
        batch.observe(at_ms, hostname, kind);
    }

    /// Traffic to `hostname` was seen leaving over the wrong link while a
    /// routed site was open — the half-broken page, observed directly.
    ///
    /// Reported as [`CoActivityKind::CandidateInUse`], which lets a
    /// delivery-named host qualify from the visit that needed it instead of
    /// waiting for a second one. A host that turns out to be a rule host, or
    /// that arrives outside every anchor window, is dropped by the ledger — the
    /// caller does not have to know the rules to report a fact.
    ///
    /// Wall-clock instant, for the reason spelled out on [`Self::note_flow`].
    pub fn note_candidate_in_use(&self, sid: &str, hostname: &str, at: SystemTime) {
        if hostname.is_empty() {
            return;
        }
        let Some(mut batch) = self.begin_batch(sid) else {
            return;
        };
        batch.observe(
            unix_ms(at).max(0) as u64,
            hostname,
            CoActivityKind::CandidateInUse,
        );
    }

    /// Reports how a host behaved on the primary route. Only hosts the ledger
    /// already tracks are affected — an outcome is evidence about a candidate,
    /// never a reason to start tracking one, so a busy machine does not turn
    /// every stalled connection into a suggestion.
    pub fn note_primary_health(&self, sid: &str, hostname: &str, event: PrimaryHealthEvent) {
        if hostname.is_empty() {
            return;
        }
        let Some(mut batch) = self.begin_batch(sid) else {
            return;
        };
        batch.note_primary_health(hostname, event);
    }

    /// A host an ISP notice page named as blocked — parked like a companion
    /// suggestion (no anchor, so the host signs its own offer). Gated like
    /// `count_cuts`: observing never stops, only parking does.
    pub fn note_isp_blocked_host(&self, sid: &str, hostname: &str, now: SystemTime) -> bool {
        if !self.isp_block_candidates_enabled.load(Ordering::Relaxed) {
            return false;
        }
        let host = hostname.trim().trim_end_matches('.').to_ascii_lowercase();
        if host.is_empty() || self.mode(sid) == AutoRulesMode::Off {
            return false;
        }
        let Some(snapshot) = self.rules.active_rules_for(sid) else {
            return false;
        };
        let exclusions = RuleBookExclusions {
            book: &snapshot.rule_book,
        };
        // Already covered, or a rule would change nothing (same reasoning
        // `tick` applies to companion proposals).
        if exclusions.is_rule_host(&host)
            || exclusions.is_matched_by_existing_rule(&host)
            || snapshot.behavior_mode.default_route_role() == RouteRole::Secondary
        {
            return false;
        }
        let now_ms = unix_ms(now);
        let id = candidate_id(sid, AUTO_RULE_MATCH_KIND_SUFFIX, &host);
        if self.suppressed_ids(sid).contains(&id) {
            return false;
        }
        let candidate = PendingCandidate {
            dto: AutoRuleCandidateDto {
                id,
                anchor: host.clone(),
                proposed_match: host,
                match_kind: AUTO_RULE_MATCH_KIND_SUFFIX.to_string(),
                route: RouteRole::Secondary.slug().to_string(),
                affinity: 0.0,
                observations: 1,
                first_seen_unix_ms: now_ms,
                last_seen_unix_ms: now_ms,
                signal: AUTO_RULE_SIGNAL_ISP_BLOCK_PAGE.to_string(),
                consumers: Vec::new(),
                consumers_changed_unix_ms: 0,
                primary_behavior: String::new(),
            },
            route: RouteRole::Secondary,
            match_kind: AuthoredMatchKind::SuffixDomain,
        };
        self.park(sid, vec![candidate], now_ms);
        if matches!(self.mode(sid), AutoRulesMode::Suggest) {
            self.announce_pending(sid, now);
        }
        true
    }

    /// Classifies one observed hostname for the ledger: a hostname covered by an
    /// active rule anchors its own route, everything else is a candidate.
    ///
    /// Takes the match results the caller already computed — the DNS consumer
    /// tests both rule sets to decide whether to cache the resolution, so
    /// learning rides along at zero additional matching cost.
    pub fn classify(in_primary: bool, in_secondary: bool) -> CoActivityKind {
        if in_secondary {
            CoActivityKind::Anchor {
                route: RouteRole::Secondary,
            }
        } else if in_primary {
            CoActivityKind::Anchor {
                route: RouteRole::Primary,
            }
        } else {
            CoActivityKind::Candidate
        }
    }

    // ── Proposal tick ────────────────────────────────────────────────────────

    /// Recomputes `sid`'s suggestions and acts on them per the principal's mode.
    ///
    /// Runs on a slow timer. Never call this per observation: the ledger's
    /// answer is stable over a browsing session, so the extra work would produce
    /// the identical list.
    pub fn tick(&self, sid: &str, now: SystemTime) -> TickSummary {
        let mut summary = TickSummary::default();
        let mode = self.mode(sid);
        if mode == AutoRulesMode::Off {
            self.forget(sid);
            return summary;
        }
        // Save what has been learned so far. Rides this tick rather than a
        // timer of its own — the ledger is only worth writing when it has had
        // time to change, and this is the tick that already runs on that scale.
        self.persist_evidence(sid, now);
        let Some(snapshot) = self.rules.active_rules_for(sid) else {
            return summary;
        };
        let now_ms = unix_ms(now);
        self.expire_pending(sid, now_ms);

        // Compute proposals with the ledger lock held and NOTHING else: the
        // exclusions read the rule book (already in hand) and the authoring path
        // below must never run while the observation feed is blocked.
        let exclusions = RuleBookExclusions {
            book: &snapshot.rule_book,
        };
        let proposals: Vec<CompanionProposal> = {
            let ledgers = self.ledgers.lock().unwrap_or_else(|p| p.into_inner());
            ledgers
                .get(sid)
                .map(|l| l.ledger.proposals(now_ms.max(0) as u64, &exclusions))
                .unwrap_or_default()
        };
        if proposals.is_empty() {
            summary.pending = self.pending_count(sid);
            return summary;
        }

        // A suggestion naming the route unmatched traffic already takes changes
        // nothing: the host is uncovered (the exclusions guarantee it), so it
        // goes there anyway. Dropping these is not a matter of taste — offering
        // them asks the user to approve a rule with no effect.
        let default_role = snapshot.behavior_mode.default_route_role();
        let suppressed = self.suppressed_ids(sid);
        let mut inert = 0_usize;
        // One address, one offer. A CDN host pulled by two routed sites yields
        // two proposals with the same id (the id names the address, not the
        // pairing), so the strongest evidence wins and the user is asked once.
        // Held alongside the offer: whose activity actually pulled the address.
        // Not part of the DTO — it decides which anchor SIGNS the offer, and the
        // user is shown the site, not the arithmetic.
        let mut strongest: HashMap<String, (f64, PendingCandidate)> = HashMap::new();
        // Every site pulling each address, winner and losers alike — the losers
        // become `consumers` on the winning DTO instead of being discarded, so
        // the user sees who else needs the host. This is gathered for EVERY
        // proposal, including one an inert or suppressed anchor made: a site on
        // the default route gets no offer of its own (adding it changes
        // nothing) but the user must still see that its traffic rides along.
        let mut consumers: HashMap<String, Vec<(f64, AutoRuleConsumerDto)>> = HashMap::new();
        // Names of a few dropped ones. A bare count answers "how many" but not
        // "was my site among them", which is the question asked of every quiet
        // run; the cap keeps a busy tick from writing a page of hostnames.
        let mut inert_names: Vec<String> = Vec::new();
        for proposal in proposals.iter() {
            // The kind is part of the id only because it used to vary; it is
            // now fixed, and keeping it keeps ids stable across the change.
            let id = candidate_id(sid, AUTO_RULE_MATCH_KIND_SUFFIX, proposal.proposed.value());
            consumers.entry(id.clone()).or_default().push((
                proposal.nearest_share,
                AutoRuleConsumerDto {
                    hostname: proposal.anchor_hostname.clone(),
                    route: proposal.route.slug().to_string(),
                },
            ));
            if proposal.route == default_role {
                inert += 1;
                if inert_names.len() < 8 {
                    inert_names.push(format!(
                        "{} ({})",
                        proposal.proposed.value(),
                        proposal.anchor_hostname
                    ));
                }
                continue;
            }
            if suppressed.contains(&id) {
                continue;
            }
            let candidate = to_candidate(proposal, id.clone());
            let pulled = proposal.nearest_share;
            match strongest.get(&id) {
                Some((held_pulled, held))
                    if !explains_better(pulled, &candidate.dto, *held_pulled, &held.dto) => {}
                _ => {
                    strongest.insert(id, (pulled, candidate));
                }
            }
        }
        let mut fresh: Vec<PendingCandidate> = strongest
            .into_values()
            .map(|(_, mut candidate)| {
                let entries = consumers.remove(&candidate.dto.id).unwrap_or_default();
                candidate.dto.consumers = merge_consumers(&candidate.dto.anchor, entries);
                candidate
            })
            .collect();
        fresh.sort_by(|a, b| a.dto.id.cmp(&b.dto.id));
        if inert > 0 {
            tracing::debug!(
                target: "nrr::auto-rules",
                sid = %sid,
                dropped = inert,
                default_route = %default_role.slug(),
                sample = %inert_names.join(", "),
                "dropped companion suggestions that would not change where the traffic goes",
            );
        }
        if fresh.is_empty() {
            summary.pending = self.pending_count(sid);
            if matches!(mode, AutoRulesMode::Suggest) {
                summary.published = self.announce_pending(sid, now);
            }
            return summary;
        }

        match mode {
            AutoRulesMode::Off => unreachable_off(),
            AutoRulesMode::Auto => {
                summary.authored = self.author_now(sid, &fresh, now);
                summary.pending = self.pending_count(sid);
                if summary.authored > 0 {
                    // Informational: the tray drops an event whose pending count
                    // yields no unseen candidates, so this cannot prompt. It
                    // exists so a GUI that wants to show "rules were added for
                    // you" has a signal to hang that on.
                    summary.published =
                        self.publish(sid, summary.pending as u64, &fresh, true, now);
                }
            }
            AutoRulesMode::Suggest => {
                let (added, total) = self.park(sid, fresh.clone(), now_ms);
                summary.parked = added;
                summary.pending = total;
                if added > 0 {
                    // WHAT was found, not just how many. "5 candidates" cannot
                    // be checked against "the site I just opened offered
                    // nothing"; a list of names can.
                    tracing::info!(
                        target: "nrr::auto-rules",
                        sid = %sid,
                        offered = %preview(&fresh),
                        "parked new suggestions",
                    );
                }
                summary.published = self.announce_pending(sid, now);
            }
        }
        summary
    }

    /// Announce everything still on offer for `sid` when any of it has not been
    /// announced yet.
    ///
    /// Runs on EVERY `suggest` tick, not only on the tick that parked something:
    /// an arrival that lands inside the quiet gap would otherwise wait for the
    /// next arrival to be mentioned, and there may not be one.
    fn announce_pending(&self, sid: &str, now: SystemTime) -> bool {
        let offered = self.pending_snapshot(sid);
        if offered.is_empty() {
            return false;
        }
        // The count stays whole — the list the user opens holds every offer.
        let pending = offered.len() as u64;
        // A host that already answers over the main route earns no popup: the
        // offer reads "move this into the tunnel", and it plainly works without
        // one. It keeps its place in the list, and a later stall re-opens the
        // question on its own, because the verdict is recomputed every tick.
        let (worth_a_popup, settled): (Vec<PendingCandidate>, Vec<PendingCandidate>) = offered
            .into_iter()
            .partition(|c| c.dto.primary_behavior != AUTO_RULE_PRIMARY_BEHAVIOR_RESPONDS);
        if !settled.is_empty() {
            tracing::debug!(
                target: "nrr::auto-rules",
                sid = %sid,
                held_back = settled.len(),
                sample = %preview(&settled),
                "suggestions kept out of the tray — the host already answers on the main route",
            );
        }
        if worth_a_popup.is_empty() {
            return false;
        }
        self.publish(sid, pending, &worth_a_popup, false, now)
    }

    fn pending_snapshot(&self, sid: &str) -> Vec<PendingCandidate> {
        self.pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(sid)
            .cloned()
            .unwrap_or_default()
    }

    // ── IPC surface ──────────────────────────────────────────────────────────

    /// `autorules.candidates.list` — the suggestions waiting for `sid`.
    pub fn candidates(&self, sid: &str) -> Vec<AutoRuleCandidateDto> {
        self.pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(sid)
            .map(|v| v.iter().map(|c| c.dto.clone()).collect())
            .unwrap_or_default()
    }

    /// Does any parked suggestion for the ADDITIONAL route already cover
    /// `hostname`?
    ///
    /// Read by the DNS answer path, which must not steer such a host onto the
    /// primary link as if it were unrelated collateral — see
    /// [`crate::dns_resolver::CompanionCandidateLookup`]. Every principal is
    /// consulted: the answer path is one per service, and Free has a single
    /// routing-active user, so "any user suspects this host" is the useful
    /// question and the map holds a handful of entries.
    pub fn covers_pending_secondary_host(&self, hostname: &str) -> bool {
        let host = hostname.trim().trim_end_matches('.').to_ascii_lowercase();
        if host.is_empty() {
            return false;
        }
        self.pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .values()
            .flatten()
            .filter(|c| c.dto.route == RouteRole::Secondary.slug())
            .any(|c| {
                let m = c.dto.proposed_match.trim_matches('.').to_ascii_lowercase();
                if m.is_empty() {
                    return false;
                }
                // Subdomains count for BOTH kinds, because that is what
                // accepting writes: `CanonicalRuleSet::with_subdomain_rules`
                // expands every exact rule into a suffix one, so an exact
                // suggestion for `cdninstagram.com` would cover
                // `static.cdninstagram.com` the moment it is accepted.
                // Reading it narrower here let the collateral rescue yank that
                // subdomain onto the primary while its parent was on offer.
                host == m || host.ends_with(&format!(".{m}"))
            })
    }

    /// `autorules.candidates.accept` — author the named suggestions into `sid`'s
    /// own rules with reason `user-confirmed`.
    ///
    /// Ids the pending set no longer holds are counted as `unknown` rather than
    /// failing the call: the set is in-memory and may have been recomputed
    /// between the list and the answer, and refusing the whole batch over one
    /// stale id would lose the user's decision about the others.
    pub fn accept(
        &self,
        sid: &str,
        ids: &[String],
        now: SystemTime,
    ) -> Result<ActionSummary, AuthorError> {
        let (selected, unknown) = self.take_selected(sid, ids, unix_ms(now));
        if selected.is_empty() {
            return Ok(ActionSummary {
                applied: 0,
                unknown,
                pending: self.pending_count(sid),
            });
        }
        let author = self.author.get().ok_or_else(|| {
            // Put the suggestions back — the user's answer was not applied, so
            // the offer must survive for them to answer it again.
            self.park(sid, selected.clone(), unix_ms(now));
            AuthorError {
                code: "authoring-unavailable".to_string(),
                message: "this service build cannot write rules".to_string(),
            }
        })?;
        let rules: Vec<AuthoredRule> = selected
            .iter()
            .map(PendingCandidate::authored_rule)
            .collect();
        let correlation = format!("auto-rules-accept-{}", unix_ms(now));
        match author.author(
            sid,
            &AutoRuleReason::UserConfirmed,
            &rules,
            now,
            &correlation,
        ) {
            Ok(_) => {
                self.remember_authored(sid, &selected);
                tracing::info!(
                    target: "nrr::auto-rules",
                    sid = %sid,
                    accepted = selected.len(),
                    anchor = %top_anchor(&selected),
                    "user accepted suggested addresses — added to their own rules",
                );
                Ok(ActionSummary {
                    applied: selected.len() as u32,
                    unknown,
                    pending: self.pending_count(sid),
                })
            }
            Err(e) => {
                // A refused write (rule cap, unacknowledged security alert, a
                // policy error) leaves the offer standing so the user can retry
                // once they have dealt with the cause.
                self.park(sid, selected, unix_ms(now));
                tracing::warn!(
                    target: "nrr::auto-rules",
                    sid = %sid,
                    code = %e.code,
                    "could not add the accepted addresses: {}",
                    e.message,
                );
                Err(e)
            }
        }
    }

    /// `autorules.candidates.dismiss` — refuse the named suggestions and
    /// remember the refusal across restarts.
    pub fn dismiss(&self, sid: &str, ids: &[String], now: SystemTime) -> ActionSummary {
        let (selected, unknown) = self.take_selected(sid, ids, unix_ms(now));
        if selected.is_empty() {
            return ActionSummary {
                applied: 0,
                unknown,
                pending: self.pending_count(sid),
            };
        }
        let records: Vec<AutoRuleDismissal> =
            selected.iter().map(PendingCandidate::dismissal).collect();
        self.dismissals.record(sid, &records, unix_ms(now));
        {
            let mut guard = self.dismissed.lock().unwrap_or_else(|p| p.into_inner());
            let entry = guard.entry(sid.to_string()).or_default();
            for c in &selected {
                entry.insert(c.dto.id.clone());
            }
        }
        tracing::info!(
            target: "nrr::auto-rules",
            sid = %sid,
            dismissed = selected.len(),
            anchor = %top_anchor(&selected),
            "user declined suggested addresses — they will not be offered again",
        );
        ActionSummary {
            applied: selected.len() as u32,
            unknown,
            pending: self.pending_count(sid),
        }
    }

    /// `autorules.dismissed.list` — refusals `sid` has recorded, most recent
    /// first, for a "review your declined suggestions" surface.
    pub fn list_dismissed(&self, sid: &str) -> Vec<AutoRuleDismissedEntryDto> {
        self.dismissals
            .list(sid)
            .into_iter()
            .map(|r| AutoRuleDismissedEntryDto {
                candidate_id: r.candidate_id,
                anchor: r.anchor,
                proposed_match: r.proposed_match,
                dismissed_at_unix_ms: r.dismissed_at,
            })
            .collect()
    }

    /// `autorules.dismissed.restore` — undoes refusals and puts the offers back
    /// on the list.
    ///
    /// Restoring used to lift the suppression and nothing else, leaving the
    /// host to re-earn its place from fresh observations. In practice the
    /// evidence had usually aged out of the ledger, so the row the user just
    /// asked for simply never came back. The refusal record now carries the
    /// offer itself, so it returns immediately; a refusal written before that
    /// column existed still only lifts the suppression.
    pub fn restore_dismissed(&self, sid: &str, ids: &[String], now: SystemTime) -> ActionSummary {
        let stored: HashMap<String, String> = self
            .dismissals
            .list(sid)
            .into_iter()
            .map(|r| (r.candidate_id, r.dto_json))
            .collect();
        let mut restored = 0_u32;
        let mut unknown = 0_u32;
        let mut back: Vec<PendingCandidate> = Vec::new();
        for id in ids {
            if !self.dismissals.forget(sid, id) {
                unknown += 1;
                continue;
            }
            restored += 1;
            if let Some(candidate) = stored
                .get(id)
                .filter(|json| !json.is_empty())
                .and_then(|json| serde_json::from_str::<AutoRuleCandidateDto>(json).ok())
                .and_then(PendingCandidate::from_dto)
            {
                back.push(candidate);
            }
        }
        {
            let mut guard = self.dismissed.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(entry) = guard.get_mut(sid) {
                for id in ids {
                    entry.remove(id);
                }
            }
        }
        // After the suppression is lifted, never before: `park` drops anything
        // still on the refused list.
        let re_offered = if back.is_empty() {
            0
        } else {
            self.park(sid, back, unix_ms(now)).0
        };
        if restored > 0 {
            tracing::info!(
                target: "nrr::auto-rules",
                sid = %sid,
                restored,
                re_offered,
                "user restored declined addresses — back on the list",
            );
        }
        ActionSummary {
            applied: restored,
            unknown,
            pending: self.pending_count(sid),
        }
    }

    /// `autorules.candidates.forget` — erases every trace of these suggestions
    /// for `sid`: the pending offer, the durable refusal, and the quiet period
    /// that follows authoring.
    ///
    /// Distinct from [`Self::restore_dismissed`], which lifts a refusal but
    /// leaves the rest of the service's memory of the answer intact. This is
    /// the "ask me again from scratch" answer, so the host returns the moment
    /// the observation feed earns it a second time.
    pub fn forget_candidates(&self, sid: &str, ids: &[String], now: SystemTime) -> ActionSummary {
        let wanted: HashSet<&str> = ids.iter().map(String::as_str).collect();
        let (dropped, remaining) = {
            let mut guard = self.pending.lock().unwrap_or_else(|p| p.into_inner());
            let entry = guard.entry(sid.to_string()).or_default();
            let before = entry.len();
            entry.retain(|c| !wanted.contains(c.dto.id.as_str()));
            let snapshot = entry.clone();
            (before - entry.len(), snapshot)
        };
        self.persist_pending(sid, &remaining, unix_ms(now));

        let mut forgotten = dropped as u32;
        for id in ids {
            if self.dismissals.forget(sid, id) {
                forgotten += 1;
            }
        }
        {
            let mut guard = self.dismissed.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(entry) = guard.get_mut(sid) {
                entry.retain(|id| !wanted.contains(id.as_str()));
            }
        }
        {
            let mut guard = self.authored.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(entry) = guard.get_mut(sid) {
                entry.retain(|id, _| !wanted.contains(id.as_str()));
            }
        }
        if forgotten > 0 {
            tracing::info!(
                target: "nrr::auto-rules",
                sid = %sid,
                forgotten,
                "user erased suggestions — they may be offered again from scratch",
            );
        }
        ActionSummary {
            applied: forgotten,
            unknown: (ids.len() as u32).saturating_sub(forgotten),
            pending: self.pending_count(sid),
        }
    }

    // ── Internals ────────────────────────────────────────────────────────────

    /// `sid`'s companion-discovery settings, memoised for [`MODE_MEMO_TTL`].
    fn settings(&self, sid: &str) -> PrincipalSettings {
        let mut memo = self.settings_memo.lock().unwrap_or_else(|p| p.into_inner());
        if let Some((settings, at)) = memo.get(sid) {
            if at.elapsed() < MODE_MEMO_TTL {
                return *settings;
            }
        }
        let settings = PrincipalSettings {
            mode: (self.mode_for)(sid),
            eager_delivery_names: self
                .eager_delivery_for
                .as_ref()
                .is_some_and(|read| read(sid)),
        };
        memo.insert(sid.to_string(), (settings, Instant::now()));
        settings
    }

    fn mode(&self, sid: &str) -> AutoRulesMode {
        self.settings(sid).mode
    }

    /// Forces the next settings read to hit the source. Production refreshes on
    /// the [`MODE_MEMO_TTL`] timer; a test cannot wait for it.
    #[cfg(test)]
    fn expire_settings_memo(&self) {
        self.settings_memo
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clear();
    }

    /// Ages every authored-suppression entry past its window. A test cannot wait
    /// out [`AUTHORED_SUPPRESSION`].
    #[cfg(test)]
    fn expire_authored_suppression(&self) {
        let stale = Instant::now() - AUTHORED_SUPPRESSION - Duration::from_secs(1);
        for entry in self
            .authored
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .values_mut()
        {
            for at in entry.values_mut() {
                *at = stale;
            }
        }
    }

    /// Drops every trace of a principal that turned collection off.
    fn forget(&self, sid: &str) {
        self.ledgers
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(sid);
        self.pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(sid);
        self.pending_store.clear(sid);
        if let Some(store) = self.evidence_store.as_ref() {
            store.clear(sid);
        }
        self.evidence_saved_at
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(sid);
    }

    fn pending_count(&self, sid: &str) -> usize {
        self.pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(sid)
            .map_or(0, Vec::len)
    }

    /// Ids that must not be offered: refused earlier (durable) or authored this
    /// session (the rule exists; the exclusions will catch it on the next read,
    /// this closes the race until then).
    fn suppressed_ids(&self, sid: &str) -> HashSet<String> {
        let mut out = {
            let mut guard = self.dismissed.lock().unwrap_or_else(|p| p.into_inner());
            guard
                .entry(sid.to_string())
                .or_insert_with(|| self.dismissals.load(sid))
                .clone()
        };
        let mut guard = self.authored.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(authored) = guard.get_mut(sid) {
            authored.retain(|_, at| at.elapsed() < AUTHORED_SUPPRESSION);
            out.extend(authored.keys().cloned());
        }
        out
    }

    fn remember_authored(&self, sid: &str, candidates: &[PendingCandidate]) {
        let mut guard = self.authored.lock().unwrap_or_else(|p| p.into_inner());
        let entry = guard.entry(sid.to_string()).or_default();
        let now = Instant::now();
        for c in candidates {
            entry.insert(c.dto.id.clone(), now);
        }
    }

    /// Merges `fresh` into the pending set, returning `(newly added, total)`.
    ///
    /// Strongest first, so a consumer showing only the top of the list shows the
    /// most defensible offers.
    fn park(&self, sid: &str, fresh: Vec<PendingCandidate>, now_ms: i64) -> (u32, usize) {
        let mut guard = self.pending.lock().unwrap_or_else(|p| p.into_inner());
        let entry = guard.entry(sid.to_string()).or_default();
        let mut added = 0_u32;
        for mut candidate in fresh {
            match entry.iter_mut().find(|c| c.dto.id == candidate.dto.id) {
                // Refresh the evidence on an offer already standing — the user
                // sees current numbers whenever they get round to answering.
                // The "new basis" clock only advances when a consumer this
                // offer didn't have before shows up; unchanged evidence keeps
                // its date, which is what lets the tray sort by what's new.
                Some(existing) => {
                    let known: HashSet<&str> = existing
                        .dto
                        .consumers
                        .iter()
                        .map(|c| c.hostname.as_str())
                        .collect();
                    let gained_consumer = candidate
                        .dto
                        .consumers
                        .iter()
                        .any(|c| !known.contains(c.hostname.as_str()));
                    candidate.dto.consumers_changed_unix_ms = if gained_consumer {
                        now_ms
                    } else {
                        existing.dto.consumers_changed_unix_ms
                    };
                    *existing = candidate;
                }
                None => {
                    // A `0` sentinel means this offer was never parked before
                    // (fresh out of `to_candidate`); a nonzero value means it is
                    // being restored after a failed accept/author, and its own
                    // "first appeared" date must survive the round trip.
                    if candidate.dto.consumers_changed_unix_ms == 0 {
                        candidate.dto.consumers_changed_unix_ms = now_ms;
                    }
                    entry.push(candidate);
                    added = added.saturating_add(1);
                }
            }
        }
        sort_and_cap(entry, sid);
        added = added.min(entry.len() as u32);
        let total = entry.len();
        let snapshot = entry.clone();
        drop(guard);
        self.persist_pending(sid, &snapshot, now_ms);
        (added, total)
    }

    /// Writes `sid`'s pending set through to the durable store, so the table
    /// mirrors memory after every change. An empty set clears the row instead
    /// of writing nothing, so a cleared-out queue does not leave a stale row.
    fn persist_pending(&self, sid: &str, candidates: &[PendingCandidate], now_ms: i64) {
        if candidates.is_empty() {
            self.pending_store.clear(sid);
            return;
        }
        let records: Vec<AutoRulePendingRecord> = candidates
            .iter()
            .filter_map(|c| match serde_json::to_string(&c.dto) {
                Ok(dto_json) => Some(AutoRulePendingRecord {
                    candidate_id: c.dto.id.clone(),
                    route: c.dto.route.clone(),
                    match_kind: c.dto.match_kind.clone(),
                    dto_json,
                    parked_at: now_ms,
                }),
                Err(e) => {
                    tracing::warn!(
                        target: "nrr::auto-rules",
                        sid = %sid,
                        error = %e,
                        "could not serialize a pending suggestion — it will not survive a restart",
                    );
                    None
                }
            })
            .collect();
        self.pending_store.replace(sid, &records);
    }

    /// Forgets offers whose evidence has gone stale. An unanswered suggestion is
    /// not a debt: if the site still needs the address, the next visit re-earns
    /// it, and if it does not, the offer was noise.
    fn expire_pending(&self, sid: &str, now_ms: i64) {
        let mut guard = self.pending.lock().unwrap_or_else(|p| p.into_inner());
        let Some(entry) = guard.get_mut(sid) else {
            return;
        };
        let before = entry.len();
        entry.retain(|c| now_ms.saturating_sub(c.dto.last_seen_unix_ms) <= PENDING_TTL_MS);
        let expired = before - entry.len();
        let snapshot = (expired > 0).then(|| entry.clone());
        drop(guard);
        if expired > 0 {
            tracing::debug!(
                target: "nrr::auto-rules",
                sid = %sid,
                expired,
                "dropped suggestions nobody answered and nothing refreshed",
            );
        }
        if let Some(snapshot) = snapshot {
            self.persist_pending(sid, &snapshot, now_ms);
        }
    }

    /// Removes the named candidates from the pending set, returning them
    /// alongside the count of ids that were not there.
    fn take_selected(
        &self,
        sid: &str,
        ids: &[String],
        now_ms: i64,
    ) -> (Vec<PendingCandidate>, u32) {
        let wanted: HashSet<&str> = ids.iter().map(String::as_str).collect();
        let mut guard = self.pending.lock().unwrap_or_else(|p| p.into_inner());
        let Some(entry) = guard.get_mut(sid) else {
            return (Vec::new(), ids.len() as u32);
        };
        let mut selected = Vec::new();
        entry.retain(|c| {
            if wanted.contains(c.dto.id.as_str()) {
                selected.push(c.clone());
                false
            } else {
                true
            }
        });
        let unknown = (ids.len().saturating_sub(selected.len())) as u32;
        let snapshot = (!selected.is_empty()).then(|| entry.clone());
        drop(guard);
        if let Some(snapshot) = snapshot {
            self.persist_pending(sid, &snapshot, now_ms);
        }
        (selected, unknown)
    }

    /// `auto` mode: write the rules without asking. Returns how many landed.
    fn author_now(&self, sid: &str, fresh: &[PendingCandidate], now: SystemTime) -> u32 {
        let Some(author) = self.author.get() else {
            // No author wired: park rather than discard the finding, so wiring
            // authoring later does not start from zero. Nothing was authored.
            self.park(sid, fresh.to_vec(), unix_ms(now));
            return 0;
        };
        let rules: Vec<AuthoredRule> = fresh.iter().map(PendingCandidate::authored_rule).collect();
        let correlation = format!("auto-rules-auto-{}", unix_ms(now));
        match author.author(
            sid,
            &AutoRuleReason::SiteCompanion,
            &rules,
            now,
            &correlation,
        ) {
            Ok(count) => {
                self.remember_authored(sid, fresh);
                if count > 0 {
                    tracing::info!(
                        target: "nrr::auto-rules",
                        sid = %sid,
                        added = count,
                        anchor = %top_anchor(fresh),
                        "added addresses a routed site needs to the user's own rules (auto mode)",
                    );
                }
                count
            }
            Err(e) => {
                tracing::warn!(
                    target: "nrr::auto-rules",
                    sid = %sid,
                    code = %e.code,
                    anchor = %top_anchor(fresh),
                    "could not add discovered addresses automatically: {}",
                    e.message,
                );
                0
            }
        }
    }

    /// Emits `AutoRuleCandidatesChanged` unless the debounce says otherwise.
    /// `force` bypasses the growth check for the informational `auto`-mode
    /// event, which reports work already done rather than an offer.
    fn publish(
        &self,
        sid: &str,
        pending: u64,
        offered: &[PendingCandidate],
        force: bool,
        now: SystemTime,
    ) -> bool {
        let Some(bus) = self.events.as_ref() else {
            return false;
        };
        let mut states = self.publish_state.lock().unwrap_or_else(|p| p.into_inner());
        let state = states.entry(sid.to_string()).or_default();
        let unseen: Vec<&PendingCandidate> = offered
            .iter()
            .filter(|c| !state.announced.contains(&c.dto.id))
            .collect();
        if !force && unseen.is_empty() {
            return false;
        }
        // A clock that went backwards reads as "ready" rather than muting the
        // tray until wall time catches up.
        let quiet_enough = state.announced_at.is_none_or(|at| {
            now.duration_since(at)
                .map_or(true, |since| since >= PUBLISH_MIN_INTERVAL)
        });
        if !quiet_enough {
            return false;
        }
        // Name the site whose suggestions the user has not seen yet.
        let anchor_source: Vec<PendingCandidate> = if unseen.is_empty() {
            offered.to_vec()
        } else {
            unseen.into_iter().cloned().collect()
        };
        // Forget ids no longer on offer (accepted, dismissed, evicted) so the
        // set tracks the live offer instead of growing all session.
        let live: HashSet<&str> = offered.iter().map(|c| c.dto.id.as_str()).collect();
        state.announced.retain(|id| live.contains(id.as_str()));
        state
            .announced
            .extend(offered.iter().map(|c| c.dto.id.clone()));
        state.announced_at = Some(now);
        drop(states);
        bus.publish(StatusUpdateEvent::AutoRuleCandidatesChanged {
            sid: sid.to_string(),
            pending_count: pending,
            top_anchor: top_anchor(&anchor_source),
        });
        true
    }
}

/// `value (anchor)` for the first few suggestions — enough to recognise them in
/// a log without printing a browsing session.
fn preview(candidates: &[PendingCandidate]) -> String {
    const SHOWN: usize = 5;
    let mut out = candidates
        .iter()
        .take(SHOWN)
        // The tier rides along: when an offer names the wrong site, WHICH tier
        // accepted the pairing is the whole diagnosis, and it is not otherwise
        // recoverable from the logs.
        .map(|c| {
            format!(
                "{} ({}, {})",
                c.dto.proposed_match, c.dto.anchor, c.dto.signal
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    if candidates.len() > SHOWN {
        out.push_str(&format!(" +{} more", candidates.len() - SHOWN));
    }
    out
}

/// The anchor most of `candidates` belong to — the site the prompt names. Ties
/// break on hostname so the same set always names the same site.
fn top_anchor(candidates: &[PendingCandidate]) -> String {
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for c in candidates {
        *counts.entry(c.dto.anchor.as_str()).or_insert(0) += 1;
    }
    counts
        .into_iter()
        .max_by(|(name_a, a), (name_b, b)| a.cmp(b).then_with(|| name_b.cmp(name_a)))
        .map(|(name, _)| name.to_string())
        .unwrap_or_default()
}

/// Projects a proposal into its wire shape plus the fields authoring needs.
/// `id` is computed once by the caller (it is also the consumer-map key), so
/// this never re-hashes it.
///
/// Every offer is written as a suffix, whatever shape the engine proposed:
/// `*.x` covers the apex and everything under it, so the rule means the same
/// thing whether or not "cover subdomains" is on. An exact rule would silently
/// narrow the moment that setting is turned off.
fn to_candidate(proposal: &CompanionProposal, id: String) -> PendingCandidate {
    PendingCandidate {
        dto: AutoRuleCandidateDto {
            id,
            anchor: proposal.anchor_hostname.clone(),
            proposed_match: proposal.proposed.value().to_string(),
            match_kind: AUTO_RULE_MATCH_KIND_SUFFIX.to_string(),
            route: proposal.route.slug().to_string(),
            affinity: proposal.affinity,
            observations: proposal.distinct_windows,
            first_seen_unix_ms: proposal.first_seen_ms as i64,
            last_seen_unix_ms: proposal.last_seen_ms as i64,
            signal: signal_slug(proposal.signal).to_string(),
            // Filled in by the caller once every proposal for this address has
            // been seen; a sentinel of `0` marks "not parked before" for `park`.
            consumers: Vec::new(),
            consumers_changed_unix_ms: 0,
            primary_behavior: primary_behavior_slug(proposal.primary_behavior).to_string(),
        },
        route: proposal.route,
        match_kind: AuthoredMatchKind::SuffixDomain,
    }
}

/// Orders one candidate's consumers: `winner` (the anchor that signs the
/// offer) first, the rest by descending `nearest_share`. Duplicate hostnames
/// collapse to their strongest entry.
fn merge_consumers(
    winner: &str,
    mut entries: Vec<(f64, AutoRuleConsumerDto)>,
) -> Vec<AutoRuleConsumerDto> {
    entries.sort_by(|(a_share, a), (b_share, b)| {
        b_share
            .total_cmp(a_share)
            .then_with(|| a.hostname.cmp(&b.hostname))
    });
    let mut seen: HashSet<String> = HashSet::with_capacity(entries.len());
    let mut winner_entry = None;
    let mut rest = Vec::with_capacity(entries.len());
    for (_, consumer) in entries {
        if !seen.insert(consumer.hostname.clone()) {
            continue;
        }
        if winner_entry.is_none() && consumer.hostname == winner {
            winner_entry = Some(consumer);
        } else {
            rest.push(consumer);
        }
    }
    let mut out = Vec::with_capacity(rest.len() + 1);
    out.push(winner_entry.unwrap_or_else(|| AutoRuleConsumerDto {
        hostname: winner.to_string(),
        route: String::new(),
    }));
    out.extend(rest);
    out
}

/// Wire slug for the tier that accepted a proposal — the "why" the prompt shows
/// next to the offer.
fn signal_slug(signal: CompanionSignal) -> &'static str {
    match signal {
        CompanionSignal::BrandRelated => AUTO_RULE_SIGNAL_BRAND_RELATED,
        CompanionSignal::DeliveryName => AUTO_RULE_SIGNAL_DELIVERY_NAME,
        CompanionSignal::CoActivity => AUTO_RULE_SIGNAL_CO_ACTIVITY,
    }
}

/// Wire slug for the primary-route verdict. `Unknown` maps to the empty string:
/// "nothing conclusive" is the absence of a verdict, not one of its values.
fn primary_behavior_slug(behavior: PrimaryBehavior) -> &'static str {
    match behavior {
        PrimaryBehavior::Responds => AUTO_RULE_PRIMARY_BEHAVIOR_RESPONDS,
        PrimaryBehavior::Stalls => AUTO_RULE_PRIMARY_BEHAVIOR_STALLS,
        PrimaryBehavior::Cut => AUTO_RULE_PRIMARY_BEHAVIOR_CUT,
        PrimaryBehavior::Unknown => "",
    }
}

/// Which of two offers for the same address should sign it.
///
/// Whichever anchor was actually active when the address was fetched wins,
/// ahead of every other measure: a rule host that chatters in the background
/// has a window open next to everything the user browses and ties on affinity
/// with the site that genuinely pulled the host. Naming the wrong site is not
/// cosmetic — the user judges the offer by the site it claims to belong to.
fn explains_better(
    pulled: f64,
    candidate: &AutoRuleCandidateDto,
    held_pulled: f64,
    held: &AutoRuleCandidateDto,
) -> bool {
    match pulled.partial_cmp(&held_pulled) {
        Some(std::cmp::Ordering::Greater) => true,
        Some(std::cmp::Ordering::Less) => false,
        _ => outranks(candidate, held),
    }
}

/// Which of two offers for the same address carries the better evidence.
fn outranks(candidate: &AutoRuleCandidateDto, held: &AutoRuleCandidateDto) -> bool {
    (
        candidate.affinity,
        candidate.observations,
        // Only for determinism when the evidence ties.
        std::cmp::Reverse(held.anchor.as_str()),
    )
        .partial_cmp(&(
            held.affinity,
            held.observations,
            std::cmp::Reverse(candidate.anchor.as_str()),
        ))
        .is_some_and(std::cmp::Ordering::is_gt)
}

/// Stable candidate id.
///
/// Derived, never counted: an incrementing number would renumber every
/// suggestion whenever the ledger recomputed or the service restarted, which
/// would break both the tray's already-offered set and the persisted refusals.
/// The SID is part of the input so one user's refusal cannot suppress another's
/// suggestion for the same host. The anchor is deliberately NOT: the id names
/// the address being proposed, so the same address discovered next to a second
/// site is the same offer, and refusing it refuses it everywhere.
fn candidate_id(sid: &str, match_kind: &str, value: &str) -> String {
    let mut hasher = Sha256::new();
    for part in [sid, match_kind, value] {
        hasher.update(part.as_bytes());
        hasher.update([0]);
    }
    let digest = hasher.finalize();
    let mut out = String::with_capacity(16);
    out.push_str("arc-");
    for byte in digest.iter().take(6) {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Sorts strongest-evidence-first and truncates to
/// [`MAX_PENDING_PER_PRINCIPAL`], logging what it drops. Shared by `park`
/// (merging fresh evidence in) and startup hydration (a durable set that
/// might have grown past a since-lowered cap while the service was down).
fn sort_and_cap(entry: &mut Vec<PendingCandidate>, sid: &str) {
    entry.sort_by(|a, b| {
        b.dto
            .affinity
            .total_cmp(&a.dto.affinity)
            .then_with(|| b.dto.observations.cmp(&a.dto.observations))
            .then_with(|| a.dto.anchor.cmp(&b.dto.anchor))
            .then_with(|| a.dto.proposed_match.cmp(&b.dto.proposed_match))
    });
    if entry.len() > MAX_PENDING_PER_PRINCIPAL {
        let dropped = entry.len() - MAX_PENDING_PER_PRINCIPAL;
        entry.truncate(MAX_PENDING_PER_PRINCIPAL);
        // Never silently: a suggestion the user never got a chance to see is
        // exactly the kind of thing that looks like a bug from outside.
        tracing::info!(
            target: "nrr::auto-rules",
            sid = %sid,
            dropped,
            kept = MAX_PENDING_PER_PRINCIPAL,
            "pending suggestions are at the cap — dropped the weakest",
        );
    }
}

/// Restores durably-parked suggestions at construction, so a restart resumes
/// with the same offer set instead of an empty one. TTL-expired rows are
/// dropped rather than restored — an offer nobody answered across a long
/// outage is exactly what [`PENDING_TTL_MS`] already forgets on a live tick.
/// A row that fails to decode (DTO shape changed, unrecognised route or
/// match-kind slug) is skipped rather than failing the whole restore.
fn hydrate_pending(
    store: &dyn PendingSuggestionStore,
    now_ms: i64,
) -> HashMap<String, Vec<PendingCandidate>> {
    let mut out = HashMap::new();
    for (sid, records) in store.load_all() {
        let mut list: Vec<PendingCandidate> = records
            .into_iter()
            .filter_map(|r| {
                let dto: AutoRuleCandidateDto = serde_json::from_str(&r.dto_json).ok()?;
                if now_ms.saturating_sub(dto.last_seen_unix_ms) > PENDING_TTL_MS {
                    return None;
                }
                // Offers are written as suffixes now. An exact row predates
                // that and would sit beside its own suffix twin, since the
                // kind is part of the id. Dropping it costs nothing: a live
                // candidate is re-proposed on the next tick in the new shape.
                if dto.match_kind == AUTO_RULE_MATCH_KIND_EXACT {
                    return None;
                }
                PendingCandidate::from_dto(dto)
            })
            .collect();
        if list.is_empty() {
            continue;
        }
        sort_and_cap(&mut list, &sid);
        out.insert(sid, list);
    }
    out
}

/// Drops the least-invested principal when the tracking cap is reached.
fn evict_if_over_cap(ledgers: &mut HashMap<String, SidLedger>, incoming: &str) {
    if ledgers.len() < MAX_TRACKED_PRINCIPALS {
        return;
    }
    let victim = ledgers
        .iter()
        .filter(|(sid, _)| sid.as_str() != incoming)
        .min_by(|(sid_a, a), (sid_b, b)| {
            a.ledger
                .candidate_count()
                .cmp(&b.ledger.candidate_count())
                .then_with(|| sid_a.cmp(sid_b))
        })
        .map(|(sid, _)| sid.clone());
    if let Some(sid) = victim {
        ledgers.remove(&sid);
    }
}

fn unix_ms(now: SystemTime) -> i64 {
    now.duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// The `Off` arm is filtered out before the match; this keeps that fact readable
/// without a panic path.
fn unreachable_off() {}

/// Process-wide ISP block-page rule-candidates flag — mirrors
/// `dns_egress::global_dns_via_secondary`, same rationale.
pub fn global_isp_block_candidates_enabled() -> Arc<AtomicBool> {
    static FLAG: OnceLock<Arc<AtomicBool>> = OnceLock::new();
    Arc::clone(FLAG.get_or_init(|| Arc::new(AtomicBool::new(false))))
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests;
