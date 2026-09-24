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
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant, SystemTime};

use crate::navigation_registry::HostCounts;
use nrr_domain::canonical::{CanonicalAddressMatch, CanonicalRuleBook};
use nrr_domain::companion_affinity::{
    registrable_domain, CandidateExclusions, CoActivityKind, CompanionAffinityConfig,
    CompanionAffinityLedger, CompanionEvidenceSnapshot, CompanionProposal, CompanionSignal,
    PrimaryBehavior, PrimaryHealthEvent,
};
use nrr_shared::ipc_payloads::is_self_signed_signal;
use nrr_shared::ipc_payloads::{
    AutoRuleCandidateDto, AutoRuleConsumerDto, AutoRuleDismissedEntryDto, StatusUpdateEvent,
    AUTO_RULE_MATCH_KIND_EXACT, AUTO_RULE_MATCH_KIND_SUFFIX, AUTO_RULE_PRIMARY_BEHAVIOR_RESPONDS,
    AUTO_RULE_PRIMARY_BEHAVIOR_STALLS, AUTO_RULE_SIGNAL_BRAND_RELATED,
    AUTO_RULE_SIGNAL_CO_ACTIVITY, AUTO_RULE_SIGNAL_DELIVERY_NAME,
    AUTO_RULE_SIGNAL_MAIN_LINK_BLOCKED, AUTO_RULE_SIGNAL_PLACEHOLDER_ANSWER,
};
use nrr_shared::{AutoRuleReason, RouteRole};
use nrr_storage::auto_rule_dismissals::AutoRuleDismissal;
use nrr_storage::auto_rule_pending::AutoRulePendingRecord;
use nrr_storage::auto_rules::AutoRulesMode;
use sha2::{Digest, Sha256};

use crate::dns_observation_consumer::{rule_set_match_origin, rule_set_matches};
use crate::ipc_handlers::event_bus::EventBus;
use crate::per_sid_orchestrator::{ActiveRulesSnapshot, RulesProvider};

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

/// The same, for an offer a host signed about ITSELF (4 h).
///
/// Its evidence is that connections were failing a moment ago, and that is a
/// statement about the network right now: a provider's block lifts, a route
/// changes, an outage ends. A companion offer says "these two belong together",
/// which stays true across a day; this one goes stale with the weather, and an
/// offer nobody can act on any more is noise in the inbox.
const SELF_SIGNED_PENDING_TTL_MS: i64 = 4 * 60 * 60 * 1_000;

/// One "neither link reaches it" notice per host per day: it names somebody
/// else's outage, and repeating it would teach the user to ignore the list.
const UNREACHABLE_NOTICE_GAP_MS: i64 = 24 * 60 * 60 * 1_000;
/// Bound on the hosts remembered for that; past it the notice stays quiet.
const UNREACHABLE_NOTICE_CAP: usize = 256;

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

/// Reads the sites a principal marked as answering the MAIN link with a
/// refusal. Their companions must never be quietened by "it answers on the main
/// route" — answering is exactly what a refusal does. A closure over the state
/// DB at the composition root.
pub type RefusingAnchorsFn = Arc<dyn Fn(&str) -> Vec<String> + Send + Sync>;

/// Reads whether this principal's automatic main-link pass is switched on — i.e.
/// whether an answer about a third-party host can still arrive. A closure over
/// the state DB at the composition root. `None` (tests, degraded boot) behaves
/// as "no pass is coming", which keeps the pre-existing behaviour of asking
/// immediately.
pub type MainLinkPassEnabledFn = Arc<dyn Fn(&str) -> bool + Send + Sync>;

/// Reads whether a principal's additional route resolves to a usable adapter
/// right now. A closure over the route coordinator at the composition root, so
/// this module never learns what an adapter binding is.
pub type SecondaryReadyFn = Arc<dyn Fn(&str) -> bool + Send + Sync>;

/// How a host currently fares on the main link, asked by name.
///
/// The companion ledger only keeps this verdict for hosts it already tracks as
/// candidates, so an offer a host made about ITSELF has no way to learn that
/// the main link started working. A closure over the observation registry at
/// the composition root answers it for any name. `None` behaves as
/// [`PrimaryBehavior::Unknown`], which is what a self-signed offer carried
/// before this existed.
pub type PrimaryBehaviorFn = Arc<dyn Fn(&str) -> PrimaryBehavior + Send + Sync>;

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
            // The service watches connections, so a resolution before the
            // window that nothing followed is a prefetch, not a companion.
            lookback_requires_traffic: true,
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
            nrr_shared::ipc_payloads::AUTO_RULE_MATCH_KIND_APPLICATION => {
                AuthoredMatchKind::Application
            }
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

/// Is `hostname` already the subject of, or matched by, a rule in `snapshot`?
/// `None` (no active revision to read) answers `false`: an unreadable rule book
/// must not silently withdraw offers.
fn covered_by_rules(snapshot: Option<&ActiveRulesSnapshot>, hostname: &str) -> bool {
    let Some(snapshot) = snapshot else {
        return false;
    };
    let exclusions = RuleBookExclusions {
        book: &snapshot.rule_book,
    };
    exclusions.is_rule_host(hostname) || exclusions.is_matched_by_existing_rule(hostname)
}

/// Is this an offer about a whole program rather than a name?
fn is_app_offer(dto: &AutoRuleCandidateDto) -> bool {
    dto.match_kind == nrr_shared::ipc_payloads::AUTO_RULE_MATCH_KIND_APPLICATION
}

/// Is the offer already done by the rules — its name matched, or its program
/// already named by an application rule?
fn offer_covered(snapshot: Option<&ActiveRulesSnapshot>, dto: &AutoRuleCandidateDto) -> bool {
    if is_app_offer(dto) {
        return snapshot.is_some_and(|s| app_covered(&s.rule_book, &dto.proposed_match));
    }
    covered_by_rules(snapshot, &dto.proposed_match)
}

/// Does a rule already name `program` as its application? Only a rule scoped to
/// the program alone counts: one that also names addresses carries just those.
fn app_covered(book: &CanonicalRuleBook, program: &str) -> bool {
    book.primary
        .rules()
        .iter()
        .chain(book.secondary.rules())
        .any(|r| {
            r.enabled
                && r.address_match.is_none()
                && r.app_match.as_ref().is_some_and(|m| {
                    nrr_platform_api::app_path_resolver::glob_match(m.pattern.as_str(), program)
                })
        })
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
/// Companions the last tick decided not to offer, because the site pulling
/// them already travels the route they would be sent to.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct QuietNote {
    pub inert: u64,
    /// A few of the dropped names, capped where they are collected.
    pub sample: Vec<String>,
}

/// Whether this tick's dropped-companion set says anything the log does not
/// already carry.
///
/// The tick fires every ten seconds; a set that has not moved writes the same
/// names again for as long as the site is open. Both halves count: the COUNT
/// alone would hide one companion being swapped for another, and the SAMPLE
/// alone would hide the count growing past what the sample shows.
fn quiet_note_is_news(previous: Option<&QuietNote>, current: &QuietNote) -> bool {
    previous != Some(current)
}

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
    unreachable_told: Mutex<HashMap<(String, String), i64>>,
    /// Why the last tick had nothing to offer: how many companions were
    /// dropped as inert and a few of their names. Read by the suggestions
    /// screen, which otherwise shows an empty list and no reason for it —
    /// "why does it say nothing about this site" was asked of every quiet run.
    quiet_note: Mutex<HashMap<String, QuietNote>>,
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
    /// Is this principal's additional route usable right now? `None` (tests,
    /// degraded boot) means "assume yes", which is the behaviour that existed
    /// before the gate. See the check in [`Self::announce_pending`].
    secondary_ready: Option<SecondaryReadyFn>,
    /// Sites the user says refuse main-link addresses (see
    /// [`RefusingAnchorsFn`]). `None` behaves as "none marked".
    refusing_anchors: Option<RefusingAnchorsFn>,
    /// Is an answer about the main link still coming (see
    /// [`MainLinkPassEnabledFn`])? `None` behaves as "no", so nothing is held.
    main_link_pass_enabled: Option<MainLinkPassEnabledFn>,
    /// Current main-link verdict for a host by name (see [`PrimaryBehaviorFn`]).
    primary_behavior_of: Option<PrimaryBehaviorFn>,
    /// Durable mirror of the ledgers. A proposal needs two windows, and a
    /// restart used to reset the count to zero — a machine that restarts a few
    /// times a day therefore never reached the second one. `None` (no state DB)
    /// keeps the old session-scoped behaviour.
    evidence_store: Option<Arc<dyn EvidenceStore>>,
    /// When each principal's evidence was last written, so the save rides the
    /// proposal tick without writing on every one of them.
    evidence_saved_at: Mutex<HashMap<String, Instant>>,
}

mod inbox;
mod intake;
mod ledger;
mod tick;
mod wiring;

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
            observations: Some(proposal.distinct_windows),
            first_seen_unix_ms: proposal.first_seen_ms as i64,
            last_seen_unix_ms: proposal.last_seen_ms as i64,
            signal: signal_slug(proposal.signal).to_string(),
            // Filled in by the caller once every proposal for this address has
            // been seen; a sentinel of `0` marks "not parked before" for `park`.
            consumers: Vec::new(),
            consumers_changed_unix_ms: 0,
            primary_behavior: primary_behavior_slug(proposal.primary_behavior).to_string(),
            // Stamped when the list is served: the mark is the user's, lives in
            // the state DB, and can change without the evidence changing.
            anchor_refuses_main_link: false,
            observed_members: proposal.observed_members.clone(),
            served_by_main_link: false,
            third_party: None,
            secondary_reach: None,
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
/// Is this candidate answered by the main link already?
///
/// "It answers" is not proof the address is unwanted: a site can complete the
/// connection and serve a refusal — ChatGPT answers main-link addresses with
/// "this address is not served" — so a name of the ANCHOR'S OWN brand still
/// opens the question. A name of someone else's brand does not: a shared CDN,
/// an advertising or telemetry endpoint that loads nearby works without the
/// tunnel, and both offering it and routing traffic for it are noise.
///
/// One declaration, because two callers must agree: the tray decides whether to
/// ask, and the answer path decides whether to keep the host on the main link.
/// A candidate that is not worth asking about must not silently re-route
/// traffic either.
/// Is this candidate still waiting for the main link's answer?
///
/// [`settled_by_the_main_link`] one step earlier. A third party on the delivery
/// or co-activity tier is only worth a question once we know the main link
/// cannot serve it — and until the pass has run, `primary_behavior` is empty,
/// which reads exactly like "unreachable". That is how a shared CDN reached the
/// offer list: not because anything measured it as broken, but because nothing
/// measured it at all.
///
/// Held only while an answer can still arrive. With the automatic pass switched
/// off there is nothing to wait for, and holding the question forever would
/// retire the feature behind the user's back.
fn awaiting_the_main_link(dto: &AutoRuleCandidateDto, pass_can_answer: bool) -> bool {
    if !pass_can_answer || !dto.primary_behavior.is_empty() {
        return false;
    }
    // A self-signed offer is never held WAITING for the pass: its addresses
    // come only from a short-lived memory of names seen resolving, which may
    // already have forgotten them, and holding would silence the offer for
    // good. What settles it is an answer that actually arrives.
    if is_self_signed_signal(&dto.signal) {
        return false;
    }
    if !matches!(
        dto.signal.as_str(),
        AUTO_RULE_SIGNAL_CO_ACTIVITY | AUTO_RULE_SIGNAL_DELIVERY_NAME
    ) {
        return false;
    }
    !shares_registrable_domain(&dto.anchor, &dto.proposed_match)
}

/// A host that answers the main link has settled its OWN offer.
///
/// Kept apart from [`settled_by_the_main_link`] because the reasoning differs.
/// For a companion, "it answers" only settles a name of another brand — the
/// routed site's own delivery name can complete a connection and serve a
/// refusal. A self-signed offer has no anchor to be a companion of: its entire
/// claim is "the main link will not carry me", and one main-link answer
/// contradicts it outright.
fn settled_self_signed(dto: &AutoRuleCandidateDto) -> bool {
    is_self_signed_signal(&dto.signal)
        && dto.primary_behavior == AUTO_RULE_PRIMARY_BEHAVIOR_RESPONDS
}

fn settled_by_the_main_link(dto: &AutoRuleCandidateDto) -> bool {
    if dto.primary_behavior != AUTO_RULE_PRIMARY_BEHAVIOR_RESPONDS {
        return false;
    }
    if is_self_signed_signal(&dto.signal) {
        return true;
    }
    if !matches!(
        dto.signal.as_str(),
        AUTO_RULE_SIGNAL_CO_ACTIVITY | AUTO_RULE_SIGNAL_DELIVERY_NAME
    ) {
        return false;
    }
    !shares_registrable_domain(&dto.anchor, &dto.proposed_match)
}

/// Same registrable domain on both sides — the candidate is the anchor's own
/// name rather than a third party's.
fn shares_registrable_domain(anchor: &str, proposed: &str) -> bool {
    let anchor = anchor.trim().trim_end_matches('.');
    let proposed = proposed
        .trim()
        .trim_start_matches('.')
        .trim_end_matches('.');
    match (registrable_domain(anchor), registrable_domain(proposed)) {
        (Some(left), Some(right)) => left.eq_ignore_ascii_case(right),
        _ => false,
    }
}

fn primary_behavior_slug(behavior: PrimaryBehavior) -> &'static str {
    match behavior {
        PrimaryBehavior::Responds => AUTO_RULE_PRIMARY_BEHAVIOR_RESPONDS,
        PrimaryBehavior::Stalls => AUTO_RULE_PRIMARY_BEHAVIOR_STALLS,
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
        // A self-signed offer counts no visits; ranking it as the one visit it
        // used to claim keeps the order exactly what it was before the count
        // became optional.
        candidate.observations.unwrap_or(1),
        // Only for determinism when the evidence ties.
        std::cmp::Reverse(held.anchor.as_str()),
    )
        .partial_cmp(&(
            held.affinity,
            held.observations.unwrap_or(1),
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
            .then_with(|| {
                b.dto
                    .observations
                    .unwrap_or(1)
                    .cmp(&a.dto.observations.unwrap_or(1))
            })
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
///
/// An offer a host made about ITSELF is not restored at all. The two kinds
/// rest on different ground: a companion offer stands on accumulated
/// evidence, and that evidence is restored alongside it, while a
/// self-signed one asserts what the network is doing RIGHT NOW — and
/// nothing behind it survives a restart. The stall registry starts empty,
/// no answer has been screened yet, so the restored row would state as
/// current a condition nobody has checked since. A host that still fails
/// re-earns its offer on the next connection; one that has been fixed
/// meanwhile never asks again.
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
                if is_self_signed_signal(&dto.signal) {
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

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests;
