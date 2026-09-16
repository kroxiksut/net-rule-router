//! Companion affinity engine — pure, deterministic, no I/O.
//!
//! # Problem
//!
//! A user routes a site (a *rule host*) through a specific route, but the
//! site's media/CDN hostnames are not covered by any rule, so those requests
//! take the default route and the page half-breaks. This engine learns which
//! hostnames are *companions* of which rule host, so the application can
//! propose adding them to the same route.
//!
//! # Why the engine reads hostnames
//!
//! Temporal co-activity alone is structurally insufficient. Browser tabs are
//! opened side by side, so a site the user happens to have open at the same
//! moment produces byte-identical timing evidence to a genuine CDN of the site
//! in front of them — no threshold can separate them, because there is nothing
//! left to separate. Replaying a real browsing trace confirms it: every purely
//! temporal variant either proposes nothing at all or proposes several unrelated
//! hosts for each correct one.
//!
//! The engine therefore also looks at the *shape of the name*: whether the
//! candidate carries the anchor's brand token, and whether it looks like a
//! delivery endpoint. Those are the two properties that survive simultaneous
//! tabs. This trades the old "hostnames are opaque strings" property away
//! deliberately; purity, determinism and the absence of I/O are unaffected —
//! the added tests are string inspections of the caller's own input.
//!
//! Precision beats recall here: an accepted proposal enlarges the rule book,
//! and the rule book is on the traffic path. A candidate the engine is unsure
//! about is dropped, never proposed "just in case".
//!
//! # Design contract (mirrors `decision_engine`)
//!
//! - **Pure and deterministic**: identical event streams produce identical
//!   proposal lists, byte for byte. No clock reads, no randomness, no I/O —
//!   time always arrives as a caller-supplied millisecond parameter.
//! - **Never on the data path**: the caller feeds ALREADY-COLLECTED
//!   observations (e.g. on an existing timer tick). [`CompanionAffinityLedger::observe`]
//!   is cheap — bounded by the anchor cap, O(1) with respect to traffic volume —
//!   and proposals are computed lazily only when
//!   [`CompanionAffinityLedger::proposals`] is called.
//! - **Bounded memory**: state is O(configured caps), never O(traffic).
//!   Tracked anchors and candidates are capped with least-recently-seen
//!   eviction; per-candidate anchor statistics are swept when an anchor is
//!   evicted, so the pair table is bounded by `max_candidates * max_anchors`.
//! - **One ledger per user principal**: rule books are per-SID, so companion
//!   evidence must be too. The caller partitions — it creates one ledger per
//!   SID and feeds each ledger only that principal's observations. The engine
//!   itself has no notion of users.
//!
//! # Algorithm
//!
//! An *anchor* observation (a hostname that is a rule host) opens a window of
//! [`CompanionAffinityConfig::window_ms`]. Further anchor observations extend
//! the window while it is open, but a window force-closes once
//! [`CompanionAffinityConfig::max_window_ms`] has elapsed since it opened —
//! continuous browsing of one site therefore yields a stream of windows rather
//! than one never-closing window, which is what makes a companion proposable
//! during a single visit. A *candidate* observed while one or more anchor
//! windows are open records a co-occurrence with each open anchor, counted per
//! DISTINCT window (a page load firing 50 requests counts once), and each
//! counted co-occurrence also increments the candidate's total
//! window-participation count across all anchors.
//!
//! Two ratios summarize a (candidate, anchor) pair:
//!
//! - `affinity = distinct_windows_with(anchor) / total_windows` — the share of
//!   the candidate's window participations that belong to this anchor. Near 1.0
//!   means the candidate was never seen outside this anchor's windows.
//! - `nearest_share = nearest_hits / total_hits` — the share of the candidate's
//!   observations for which this anchor was the *most recently active* of the
//!   open windows. Unlike `affinity` it is not diluted by a window that merely
//!   happened to be open in another tab, which is what makes it usable at all
//!   when several sites are open at once.
//!
//! A pair is proposed when ANY of three tiers accepts it
//! ([`CompanionSignal`], strongest first):
//!
//! 1. **Brand relation** — the candidate carries the anchor's brand token or
//!    vice versa (`web.chatapp.example` and `static.chatapp.test`, `ab.example` and
//!    `login.ab.test`, `tiktok.com` and `tiktokv.com`). Shared branding is a
//!    statement of ownership, so a single co-occurrence is enough and no
//!    temporal threshold applies.
//! 2. **Delivery name** — the name matches a delivery-endpoint mask
//!    ([`DELIVERY_NAME_MASKS`]) or an explicit shard label
//!    (`rr5---sn-…`), AND the anchor dominates the candidate's attributions
//!    (`nearest_share`) across at least two distinct windows. The name alone is
//!    far too weak — advertising and telemetry CDNs match the same masks — so
//!    here the temporal evidence does the discriminating.
//! 3. **Co-activity** — the original purely temporal rule, unchanged: a high
//!    `affinity` over at least
//!    [`CompanionAffinityConfig::min_distinct_windows`] windows. At the default
//!    threshold this tier is close to inert by design; it is the conservative
//!    fallback, not the workhorse.
//!
//! Tiers 2 and 3 are additionally held to **sub-resource, not neighbour in
//! time**: both rest on the assumption that the anchor is the page doing the
//! fetching, and the ledger checks it. The most recent page-shaped hostname is
//! remembered, and an attributed observation made while a DIFFERENT site's page
//! was loading counts against the pair; once most of them do, the pair is not
//! proposed. Without this, a rule host left open in one tab collects the CDN of
//! whatever the user visited next. Brand relation is exempt — a shared name
//! states ownership whatever was on screen.
//!
//! Qualifying subdomains of one registrable domain generalize into a single
//! suffix proposal (see [`registrable_domain`]): immediately for a brand or
//! delivery name, and from two distinct subdomains for co-activity alone.
//!
//! # Input expectations
//!
//! The caller must feed normalized hostnames (lowercase, ASCII/IDNA form, no
//! trailing dot) — the same normalization the decision pipeline applies. The
//! engine never normalizes, so `Foo.example` and `foo.example` would be
//! distinct keys, and the name-shape tests above are ASCII-literal.

use std::collections::{BTreeMap, HashMap, VecDeque};

use nrr_shared::RouteRole;

// ── Tunable defaults ──────────────────────────────────────────────────────────

/// Default anchor window idle extension, in milliseconds.
///
/// Rationale: companion fetches of a page load (media, CDN segments) start
/// within a few seconds of the anchor's own DNS activity. 15 s absorbs slow
/// pages and lazy media without merging unrelated browsing into the window.
pub const DEFAULT_WINDOW_MS: u64 = 15_000;

/// How far BACK an opening window reaches for companions already seen, in
/// milliseconds.
///
/// Rationale: a browser routinely opens the CDN connection before the one to
/// the page itself — `static.cdninsta.test` a second ahead of
/// `www.insta.example` is the ordinary case, not a rarity. A window that only
/// looks forward throws that sighting away at the door and the CDN is never
/// proposed, while the same site visited in the other order proposes fine. Ten
/// seconds covers the spread of one page load without reaching into whatever
/// the user was doing before it.
pub const DEFAULT_RETRO_WINDOW_MS: u64 = 10_000;

/// Cap on companions parked while no window is open. A page load fires dozens
/// of requests, and only the newest handful can still be inside a look-back by
/// the time a window opens.
const MAX_UNATTRIBUTED: usize = 64;

/// Default hard cap on a single anchor window's duration, in milliseconds.
///
/// Rationale: with idle extension alone, continuous browsing of one site
/// (e.g. watching a video, clicking through a gallery) would keep extending a
/// single window forever and the minimum distinct-window requirement could
/// never be met without the user manually leaving and reloading the site.
/// Force-closing a window after 60 s guarantees that roughly 90 s of
/// continuous activity produces at least two windows, so a dedicated CDN
/// becomes proposable during the user's first normal visit.
pub const DEFAULT_MAX_WINDOW_MS: u64 = 60_000;

/// Default minimum affinity for a proposal.
///
/// Rationale: a dedicated companion (CDN serving exactly one site) trends to
/// 1.0; shared infrastructure appearing with several anchors dilutes quickly
/// (two anchors at equal rates gives 0.5). 0.8 admits a little noise from
/// overlapping windows while still rejecting anything genuinely shared.
pub const DEFAULT_MIN_AFFINITY: f64 = 0.8;

/// Default minimum affinity for a BRAND-related proposal.
///
/// Rationale: a shared name states ownership, not need — an operator's
/// advertising, telemetry and platform-asset domains carry the brand exactly as
/// plainly as the host a page cannot render without. What separates them is
/// company: a site's own hosts ride along with that site, the operator's
/// everything-hosts ride along with every site and dilute to affinities in the
/// thousandths. Measured on the trace study, genuine brand companions sit at
/// 0.11-0.5; the floor is set below that band and two orders of magnitude above
/// the ubiquitous ones. Much lower than [`DEFAULT_MIN_AFFINITY`] on purpose:
/// the shared name is real evidence, so this tier asks for less of the temporal
/// kind than the purely co-activity one.
pub const DEFAULT_BRAND_MIN_AFFINITY: f64 = 0.1;

/// Default minimum number of distinct co-occurrence windows for a proposal.
///
/// Rationale: never propose from a single page load — one window proves
/// nothing about a stable relationship. Two independent windows is the
/// smallest repeatable signal.
pub const DEFAULT_MIN_DISTINCT_WINDOWS: u32 = 2;

/// Default minimum `nearest_share` for a delivery-named candidate.
///
/// Rationale: a delivery name is a weak signal on its own — advertising and
/// telemetry endpoints are named exactly like site CDNs. Requiring the anchor
/// to own the majority of the candidate's observations is what separates them.
/// Measured on a real browsing trace, 0.6 is the point where the tier stops
/// admitting background traffic while still catching site CDNs of a site the
/// user is actively reading.
pub const DEFAULT_DELIVERY_MIN_NEAREST_SHARE: f64 = 0.6;

/// Default minimum distinct windows for a delivery-named candidate.
///
/// Rationale: same reason as [`DEFAULT_MIN_DISTINCT_WINDOWS`] — one page load
/// is not a relationship. Dropping this to 1 was measured to cost most of the
/// tier's precision.
pub const DEFAULT_DELIVERY_MIN_DISTINCT_WINDOWS: u32 = 2;

/// Whether delivery-named candidates skip the co-activity gate by default.
///
/// Off: the gate is the only thing keeping advertising and telemetry CDNs out
/// of the rule book, and every accepted proposal enlarges a structure that sits
/// on the traffic path. Turning it on is a user decision, taken with the
/// consequences spelled out.
pub const DEFAULT_PROPOSE_DELIVERY_NAMES_WITHOUT_CO_ACTIVITY: bool = false;

/// Whether a delivery name with exactly one owner that failed on the main route
/// is proposed on the first visit.
///
/// On: the two-window rule was written for evidence that keeps arriving, and a
/// blocked address produces none — it cannot be "seen in use", because being
/// blocked is why the user is looking for it. What this tier demands instead is
/// undivided ownership plus a failure the user can see: advertising and
/// telemetry endpoints load fine on the main route, so they never qualify.
pub const DEFAULT_PROPOSE_DELIVERY_NAMES_WITH_SINGLE_OWNER: bool = true;

/// Default cap on tracked anchors (rule hosts observed recently).
///
/// Rationale: only rule hosts become anchors, and the set of *recently
/// visited* rule hosts is small; 64 covers heavy rule books while keeping the
/// per-candidate pair table and the per-event open-window scan strictly
/// bounded.
pub const DEFAULT_MAX_ANCHORS: usize = 64;

/// Default cap on tracked candidates.
///
/// Rationale: candidates only accumulate while an anchor window is open, so
/// the live set is browsing-session-sized, not internet-sized. 512 comfortably
/// covers many concurrent sites; overflow evicts the least recently seen.
pub const DEFAULT_MAX_CANDIDATES: usize = 512;

/// Default cap on proposals emitted per anchor.
///
/// Rationale: proposals surface in the GUI as suggestions; more than a
/// screenful per rule host is noise. The strongest 16 by affinity are kept.
pub const DEFAULT_MAX_PROPOSALS_PER_ANCHOR: usize = 16;

/// Default freshness horizon for proposal evidence, in milliseconds (24 h).
///
/// Rationale: proposals should reflect the user's recent browsing; CDN
/// assignments rotate and stale co-activity loses value. Candidates not seen
/// within this horizon (relative to the `now_ms` passed to `proposals`) are
/// skipped. Evidence counts are kept — the candidate revives if seen again.
pub const DEFAULT_EVIDENCE_TTL_MS: u64 = 86_400_000;

/// How close two anchors' last sightings must be before neither can claim sole
/// ownership of an observation, in milliseconds.
///
/// "Most recently active" is decided by when a rule host was last *resolved*,
/// and that is driven by its DNS TTL, not by the user: a site with a 30-second
/// TTL re-resolves all through a visit while a site with a multi-hour TTL is
/// seen once and then goes quiet. A margin this size separates "the user just
/// opened it" from TTL chatter; inside it, every tied anchor takes the credit
/// so the true owner shows up among the consumers instead of losing a coin
/// flip it never entered.
pub const DEFAULT_ATTRIBUTION_TIE_MS: u64 = 2_000;

/// Distinct proper subdomains of one registrable domain required before
/// co-activity evidence alone generalizes into a single suffix proposal. One
/// subdomain that merely loaded alongside the anchor proves nothing about its
/// siblings; two independent ones strongly suggest the whole domain serves it.
///
/// Brand-related and delivery names bypass this: their name is itself the
/// evidence, so one is enough.
const SUFFIX_MIN_DISTINCT_SUBDOMAINS: usize = 2;

// ── Configuration ─────────────────────────────────────────────────────────────

/// Tunable parameters for a [`CompanionAffinityLedger`].
///
/// All fields have documented defaults (see the `DEFAULT_*` constants). The
/// engine does not validate combinations; callers own sane values. Caps of 0
/// disable tracking of the corresponding kind without panicking.
#[derive(Clone, Copy, Debug)]
pub struct CompanionAffinityConfig {
    /// Idle extension of an anchor window (see [`DEFAULT_WINDOW_MS`]).
    pub window_ms: u64,
    /// Hard cap on a single window's duration (see [`DEFAULT_MAX_WINDOW_MS`]).
    pub max_window_ms: u64,
    /// How far back an opening window reaches for already-seen companions
    /// (see [`DEFAULT_RETRO_WINDOW_MS`]). Zero disables the look-back.
    pub retro_window_ms: u64,
    /// Minimum affinity for a proposal (see [`DEFAULT_MIN_AFFINITY`]).
    pub min_affinity: f64,
    /// Minimum affinity for a brand-related proposal
    /// (see [`DEFAULT_BRAND_MIN_AFFINITY`]).
    pub brand_min_affinity: f64,
    /// Minimum distinct co-occurrence windows (see [`DEFAULT_MIN_DISTINCT_WINDOWS`]).
    pub min_distinct_windows: u32,
    /// Minimum `nearest_share` for a delivery-named candidate
    /// (see [`DEFAULT_DELIVERY_MIN_NEAREST_SHARE`]).
    pub delivery_min_nearest_share: f64,
    /// Minimum distinct windows for a delivery-named candidate
    /// (see [`DEFAULT_DELIVERY_MIN_DISTINCT_WINDOWS`]).
    pub delivery_min_distinct_windows: u32,
    /// Propose a delivery-named candidate on its first co-occurrence, skipping
    /// both delivery gates above (see
    /// [`DEFAULT_PROPOSE_DELIVERY_NAMES_WITHOUT_CO_ACTIVITY`]). Affects only
    /// that tier: brand relation is already ungated, and the conservative
    /// co-activity tier keeps its thresholds.
    pub propose_delivery_names_without_co_activity: bool,
    /// Propose a delivery-named candidate that has exactly one owner and has
    /// never been seen with anyone else, without waiting for a second visit
    /// (see [`DEFAULT_PROPOSE_DELIVERY_NAMES_WITH_SINGLE_OWNER`]).
    pub propose_delivery_names_with_single_owner: bool,
    /// Cap on tracked anchors (see [`DEFAULT_MAX_ANCHORS`]).
    pub max_anchors: usize,
    /// Cap on tracked candidates (see [`DEFAULT_MAX_CANDIDATES`]).
    pub max_candidates: usize,
    /// Cap on proposals per anchor (see [`DEFAULT_MAX_PROPOSALS_PER_ANCHOR`]).
    pub max_proposals_per_anchor: usize,
    /// Evidence freshness horizon (see [`DEFAULT_EVIDENCE_TTL_MS`]).
    pub evidence_ttl_ms: u64,
    /// Window inside which anchors count as equally active
    /// (see [`DEFAULT_ATTRIBUTION_TIE_MS`]).
    pub attribution_tie_ms: u64,
}

impl Default for CompanionAffinityConfig {
    fn default() -> Self {
        Self {
            window_ms: DEFAULT_WINDOW_MS,
            max_window_ms: DEFAULT_MAX_WINDOW_MS,
            retro_window_ms: DEFAULT_RETRO_WINDOW_MS,
            min_affinity: DEFAULT_MIN_AFFINITY,
            brand_min_affinity: DEFAULT_BRAND_MIN_AFFINITY,
            min_distinct_windows: DEFAULT_MIN_DISTINCT_WINDOWS,
            delivery_min_nearest_share: DEFAULT_DELIVERY_MIN_NEAREST_SHARE,
            delivery_min_distinct_windows: DEFAULT_DELIVERY_MIN_DISTINCT_WINDOWS,
            propose_delivery_names_without_co_activity:
                DEFAULT_PROPOSE_DELIVERY_NAMES_WITHOUT_CO_ACTIVITY,
            propose_delivery_names_with_single_owner:
                DEFAULT_PROPOSE_DELIVERY_NAMES_WITH_SINGLE_OWNER,
            max_anchors: DEFAULT_MAX_ANCHORS,
            max_candidates: DEFAULT_MAX_CANDIDATES,
            max_proposals_per_anchor: DEFAULT_MAX_PROPOSALS_PER_ANCHOR,
            evidence_ttl_ms: DEFAULT_EVIDENCE_TTL_MS,
            attribution_tie_ms: DEFAULT_ATTRIBUTION_TIE_MS,
        }
    }
}

/// How many stalled connections make a host count as failing on the primary
/// route. A stall is a connection, never a resent segment: one loss burst
/// resends several segments on a healthy link.
const PRIMARY_STALL_CONFIRMATIONS: u32 = 3;

/// One observation of a candidate's fate on the primary route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrimaryHealthEvent {
    /// The stack had to send a segment again — the peer was not acknowledging.
    Stalled,
    /// A connection was torn down in order, so it carried traffic.
    Completed,
}

/// What the accumulated evidence says about reaching a companion over the
/// primary route. Deliberately three-valued and biased to [`Self::Unknown`]:
/// the user is told how a host behaves only when the evidence points one way.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PrimaryBehavior {
    /// Nothing observed, or evidence pointing both ways.
    #[default]
    Unknown,
    /// Connections completed and none failed — it works without the tunnel.
    Responds,
    /// Connections stalled repeatedly and none completed.
    Stalls,
}

impl PrimaryBehavior {
    /// Verdict for a set of hosts summarized as one offer (a suffix proposal):
    /// a single failing member makes the offer failing, and only unanimity the
    /// other way makes it working.
    ///
    /// `pub` because the stall registry answers the same question for a name
    /// and everything under it, and a second spelling of "one failing member
    /// makes the offer failing" is how the two come to disagree.
    #[must_use]
    pub fn merge(self, other: Self) -> Self {
        match (self, other) {
            (Self::Stalls, _) | (_, Self::Stalls) => Self::Stalls,
            (Self::Responds, Self::Responds) => Self::Responds,
            (Self::Responds, Self::Unknown) | (Self::Unknown, Self::Responds) => Self::Responds,
            (Self::Unknown, Self::Unknown) => Self::Unknown,
        }
    }
}

// ── Event model ───────────────────────────────────────────────────────────────

/// Where a candidate sighting came from.
///
/// The look-back raises sightings parked before their anchor's window opened,
/// and it runs WHILE that window is opening — before the page that opened it
/// has been recorded. The two cases therefore differ in what context is
/// knowable at the moment of attribution, and only the live one can honestly be
/// judged against the page on screen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sighting {
    Live,
    ReplayedIntoWindow,
}

/// Classification of one observed hostname activity event.
///
/// The caller decides the kind: a hostname that is a rule host in the active
/// rule book is an [`CoActivityKind::Anchor`] carrying that rule's route;
/// everything else is a [`CoActivityKind::Candidate`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoActivityKind {
    /// The hostname is a rule host; its activity opens/extends an anchor window.
    Anchor {
        /// The route the anchor's rule assigns — carried into proposals.
        route: RouteRole,
    },
    /// The hostname is not covered by any rule; it may become a companion.
    Candidate,
    /// Evidence about how a candidate behaved on the primary route. Never
    /// creates or revives a candidate — it says something about a host already
    /// under consideration, and must not itself be a reason to consider one.
    PrimaryHealth(PrimaryHealthEvent),
    /// Same, but the caller SAW traffic to it — a connection was opened, not
    /// merely a name resolved.
    ///
    /// This is the strongest thing that can be said about a candidate short of
    /// asking the user. A resolution may be speculative (prefetch, a page that
    /// never loaded); a connection is the site actually reaching for the host,
    /// and it is observable even when the name never crossed our DNS path.
    CandidateInUse,
}

// ── Exclusions ────────────────────────────────────────────────────────────────

/// Caller-supplied exclusion checks applied at proposal time.
///
/// The engine stays pure: it never inspects the rule book or any deny list
/// itself. The caller injects the three checks the product requires. Each
/// receives an exact hostname, and for suffix generalization also the proposed
/// registrable-domain apex (callers that cannot evaluate a suffix precisely
/// should answer conservatively — excluding an apex falls back to exact-host
/// proposals for its members).
///
/// The platform-infrastructure check corresponds to the service layer's
/// existing infrastructure gate; the service passes it in rather than this
/// crate depending on it.
pub trait CandidateExclusions {
    /// The hostname is itself a rule host — never proposed as a companion.
    fn is_rule_host(&self, hostname: &str) -> bool;
    /// The hostname is already matched by an existing rule — nothing to add.
    fn is_matched_by_existing_rule(&self, hostname: &str) -> bool;
    /// The hostname is shared platform infrastructure — proposing it would
    /// drag unrelated traffic onto the anchor's route.
    fn is_platform_infrastructure(&self, hostname: &str) -> bool;

    /// Combined check; `true` suppresses the hostname from proposals.
    fn excludes(&self, hostname: &str) -> bool {
        self.is_rule_host(hostname)
            || self.is_matched_by_existing_rule(hostname)
            || self.is_platform_infrastructure(hostname)
    }
}

/// Does shared infrastructure still earn a proposal?
///
/// Normally it does not: a host that belongs to everybody would drag
/// unrelated traffic onto one site's route. But the product cannot tell an
/// advertising endpoint from a delivery one, and it must not try — deciding
/// which hosts a person is allowed to reach is a different product, and the
/// sites would work around it anyway.
///
/// So the exception is not about what the host IS, it is about what was
/// MEASURED: connections to it keep failing on the main link. Then it is no
/// longer "an ad server", it is a host the user's site needs and cannot
/// reach — exactly the case the suggestion exists for.
#[must_use]
pub fn infrastructure_earns_a_proposal(behavior: PrimaryBehavior) -> bool {
    behavior == PrimaryBehavior::Stalls
}

/// No-op exclusions — nothing is suppressed. Useful for tests and previews.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoExclusions;

impl CandidateExclusions for NoExclusions {
    fn is_rule_host(&self, _hostname: &str) -> bool {
        false
    }
    fn is_matched_by_existing_rule(&self, _hostname: &str) -> bool {
        false
    }
    fn is_platform_infrastructure(&self, _hostname: &str) -> bool {
        false
    }
}

// ── Output model ──────────────────────────────────────────────────────────────

/// The match shape a companion proposal suggests adding to the rule book.
#[derive(Clone, Debug, PartialEq)]
pub enum ProposedCompanionMatch {
    /// Add the exact hostname.
    ExactHost(String),
    /// Add a subdomain-wildcard rule for this registrable domain — emitted
    /// when two or more distinct subdomains of the domain qualified. It also
    /// covers the domain itself, so no separate `ExactHost` proposal for the
    /// apex accompanies it.
    SuffixDomain(String),
}

impl ProposedCompanionMatch {
    /// The proposed hostname or domain, regardless of shape.
    pub fn value(&self) -> &str {
        match self {
            Self::ExactHost(s) | Self::SuffixDomain(s) => s.as_str(),
        }
    }
}

/// Which tier accepted a proposal — the evidence the user is being shown.
///
/// Ordered strongest first; proposals sort on it, so the per-anchor cap keeps
/// the best-supported suggestions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CompanionSignal {
    /// The candidate and the anchor share a brand token.
    BrandRelated,
    /// The name looks like a delivery endpoint and the anchor dominates the
    /// candidate's observations.
    DeliveryName,
    /// Neither name test applied; the candidate passed the co-activity
    /// thresholds alone.
    CoActivity,
}

/// One companion proposal: "this hostname/domain appears to belong to that
/// rule host — consider routing it the same way".
///
/// For suffix proposals the numeric fields summarize the strongest member
/// subdomain (maximum affinity and window count) and the union of the members'
/// observation span (earliest first-seen, latest last-seen).
#[derive(Clone, Debug, PartialEq)]
pub struct CompanionProposal {
    /// The rule host this companion co-occurred with.
    pub anchor_hostname: String,
    /// The suggested match to add.
    pub proposed: ProposedCompanionMatch,
    /// The route of the anchor's rule, as last observed.
    pub route: RouteRole,
    /// Which tier accepted this proposal. For a suffix proposal it is the
    /// strongest signal among the members.
    pub signal: CompanionSignal,
    /// `distinct_windows / total windows the candidate appeared in` — 1.0
    /// means the candidate was never seen outside this anchor's windows.
    /// Reported for every proposal as evidence; only the
    /// [`CompanionSignal::CoActivity`] tier gates on it.
    pub affinity: f64,
    /// Share of the candidate's observations for which this anchor was the
    /// most recently active one. Answers a different question than `affinity`:
    /// not "was the anchor's window open" but "was this anchor what fetched
    /// it". A rule host that chatters in the background keeps a window open
    /// next to everything the user browses and scores 1.0 on affinity for hosts
    /// it never pulled; this separates it from the site that did.
    pub nearest_share: f64,
    /// Number of distinct anchor windows the candidate co-occurred in.
    pub distinct_windows: u32,
    /// First observation of the candidate, caller-supplied milliseconds.
    pub first_seen_ms: u64,
    /// Most recent observation of the candidate, caller-supplied milliseconds.
    pub last_seen_ms: u64,
    /// What the host does when reached over the primary route. The offer is
    /// "move this into the tunnel", so "it already works without one" is the
    /// single most useful thing the user can be told about it.
    pub primary_behavior: PrimaryBehavior,
    /// For a suffix proposal, the hostnames the evidence actually covers,
    /// ascending. A suffix rule reaches every name under the apex, most of
    /// which were never seen — showing what WAS seen is the difference between
    /// confirming an offer and confirming a guess. Empty for an exact host,
    /// which covers itself and nothing else.
    pub observed_members: Vec<String>,
}

mod name_shapes;
pub use name_shapes::*;
// ── Internal state ────────────────────────────────────────────────────────────

/// Live state of one tracked anchor (rule host).
#[derive(Clone, Debug)]
struct AnchorState {
    /// Stable id for this tracking span; per-candidate pair stats key on it.
    /// A re-tracked anchor after eviction gets a fresh id.
    id: u32,
    /// Route of the anchor's rule, as last observed.
    route: RouteRole,
    /// Identity of the currently open (or most recent) window.
    window_id: u64,
    /// Timestamp the current window opened — anchors the hard duration cap.
    window_start_ms: u64,
    /// Timestamp the current window closes, already clamped to
    /// `window_start_ms + max_window_ms`.
    window_end_ms: u64,
    /// Most recent observation — the LRU eviction key.
    last_seen_ms: u64,
}

/// Per-(candidate, anchor) co-occurrence statistics.
#[derive(Clone, Debug)]
struct PairStats {
    anchor_id: u32,
    /// Number of distinct windows of this anchor the candidate appeared in.
    distinct_windows: u32,
    /// Last window already counted — dedupes repeat hits inside one window.
    last_window_id: u64,
    /// Observations attributed to this anchor because its window was the most
    /// recently active one. Counted per observation, NOT per window: a busy
    /// companion of the site in the foreground should outweigh a site sitting
    /// idle in another tab, and window counts cannot express that.
    nearest_hits: u32,
    /// The subset of `nearest_hits` won with no rival anchor active in the same
    /// breath — the only ones that say anything about ownership on their own.
    uncontested_hits: u32,
    /// The subset of `nearest_hits` that happened while a DIFFERENT site's page
    /// was the one loading. Each is evidence that this anchor was a neighbour in
    /// time, not the parent of the fetch.
    foreign_parent_hits: u32,
}

// ── Persistable snapshot ─────────────────────────────────────────────────────
//
// Evidence accumulates over days of ordinary browsing, and a service restart
// used to throw all of it away — on a laptop that restarts several times a day
// the second window a proposal needs was never reached, so nothing was ever
// offered. The ledger therefore hands its state out as plain data and takes it
// back; the domain stays free of serde and SQLite, and the caller decides where
// it lives.

/// One tracked anchor, as data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorSnapshot {
    pub hostname: String,
    pub id: u32,
    pub route: RouteRole,
    pub window_id: u64,
    pub window_start_ms: u64,
    pub window_end_ms: u64,
    pub last_seen_ms: u64,
}

/// One (candidate, anchor) pair's counters, as data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairSnapshot {
    pub anchor_id: u32,
    pub distinct_windows: u32,
    pub last_window_id: u64,
    pub nearest_hits: u32,
    pub uncontested_hits: u32,
    pub foreign_parent_hits: u32,
}

/// One tracked candidate, as data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CandidateSnapshot {
    pub hostname: String,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    pub total_windows: u32,
    pub total_hits: u32,
    pub seen_in_use: bool,
    pub primary_stalls: u32,
    pub primary_completions: u32,
    pub pairs: Vec<PairSnapshot>,
}

/// Everything one ledger has learned. Config is deliberately absent: it belongs
/// to the build and the user's settings, never to the saved evidence.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CompanionEvidenceSnapshot {
    pub anchors: Vec<AnchorSnapshot>,
    pub candidates: Vec<CandidateSnapshot>,
    pub next_anchor_id: u32,
    pub next_window_id: u64,
}

impl CompanionEvidenceSnapshot {
    /// Nothing learned yet — restoring this is the same as starting fresh.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.anchors.is_empty() && self.candidates.is_empty()
    }
}

/// Live state of one tracked candidate hostname.
#[derive(Clone, Debug)]
struct CandidateState {
    first_seen_ms: u64,
    /// Most recent observation — the LRU eviction key and TTL anchor.
    last_seen_ms: u64,
    /// Total distinct (anchor, window) participations across ALL anchors —
    /// the affinity denominator. Deliberately NOT decremented when an anchor
    /// is evicted: totals are historical, so post-eviction affinity can only
    /// be underestimated, which keeps the engine from over-proposing.
    total_windows: u32,
    /// Every observation of the candidate that fell inside some anchor window —
    /// the `nearest_share` denominator. Like `total_windows` it is historical
    /// and survives anchor eviction, so the share can only be underestimated.
    total_hits: u32,
    /// Traffic to this candidate was actually observed, not just a name
    /// resolution. Sticky: one connection settles the question for good.
    seen_in_use: bool,
    /// Fate of this candidate's connections on the primary route.
    primary_stalls: u32,
    primary_completions: u32,
    /// One entry per live anchor the candidate co-occurred with; swept on
    /// anchor eviction, so its length is bounded by the anchor cap.
    pairs: Vec<PairStats>,
}

impl CandidateState {
    /// Verdict from the accumulated primary-route outcomes. Evidence pointing
    /// both ways yields [`PrimaryBehavior::Unknown`] rather than a guess.
    fn primary_behavior(&self) -> PrimaryBehavior {
        primary_behavior_from(self.primary_completions, self.primary_stalls)
    }
}

/// How a host behaves on the primary route, from raw outcome counts.
///
/// Public and free-standing because this ledger is not the only reader of the
/// signal: the observer reports how EVERY named destination fares on the main
/// link, while this ledger keeps only the hosts that are companion candidates.
/// A second consumer restating these thresholds would be a second definition of
/// "stalling", and two definitions of one fact is how the mechanisms in this
/// codebase have drifted apart before.
#[must_use]
pub fn primary_behavior_from(completions: u32, stalls: u32) -> PrimaryBehavior {
    match (completions, stalls) {
        (c, 0) if c > 0 => PrimaryBehavior::Responds,
        (0, s) if s >= PRIMARY_STALL_CONFIRMATIONS => PrimaryBehavior::Stalls,
        _ => PrimaryBehavior::Unknown,
    }
}

// ── Ledger ────────────────────────────────────────────────────────────────────

/// Co-activity ledger for one user principal.
///
/// See the module documentation for the full contract. Feed events through
/// [`Self::observe`]; harvest suggestions through [`Self::proposals`].
#[derive(Debug)]
pub struct CompanionAffinityLedger {
    config: CompanionAffinityConfig,
    anchors: HashMap<String, AnchorState>,
    candidates: HashMap<String, CandidateState>,
    next_anchor_id: u32,
    next_window_id: u64,
    /// The page-shaped hostname seen most recently, and when. Answers "whose
    /// page is loading right now" — deliberately not persisted, because a
    /// restart genuinely does not know what page the user is on.
    last_document: Option<(String, u64)>,
    /// Companions seen while no window was open, newest last: `(hostname,
    /// at_ms, in_use)`. An opening window replays the ones that fall inside its
    /// look-back and the rest age out. Not persisted — a restart has no page
    /// load in flight to attribute them to.
    unattributed: VecDeque<(String, u64, bool)>,
}

mod ledger;

// ── test_support ──────────────────────────────────────────────────────────────

/// Fixture helpers for exercising the ledger in tests.
///
/// Always compiled (not `#[cfg(test)]`) so integration tests in `tests/` and
/// downstream crates' tests can reuse them — the same convention as
/// `decision_engine_input::test_support`.
pub mod test_support {
    use std::collections::BTreeSet;

    use nrr_shared::RouteRole;

    use super::{CandidateExclusions, CoActivityKind, CompanionAffinityLedger};

    /// Set-backed [`CandidateExclusions`] for tests and previews.
    #[derive(Clone, Debug, Default)]
    pub struct StaticExclusions {
        pub rule_hosts: BTreeSet<String>,
        pub matched_by_existing_rule: BTreeSet<String>,
        pub platform_infrastructure: BTreeSet<String>,
    }

    impl CandidateExclusions for StaticExclusions {
        fn is_rule_host(&self, hostname: &str) -> bool {
            self.rule_hosts.contains(hostname)
        }
        fn is_matched_by_existing_rule(&self, hostname: &str) -> bool {
            self.matched_by_existing_rule.contains(hostname)
        }
        fn is_platform_infrastructure(&self, hostname: &str) -> bool {
            self.platform_infrastructure.contains(hostname)
        }
    }

    /// Simulates one page load: the anchor fires at `at_ms`, each candidate
    /// follows 1 ms apart (well inside the default window).
    pub fn page_load(
        ledger: &mut CompanionAffinityLedger,
        at_ms: u64,
        anchor: &str,
        route: RouteRole,
        candidates: &[&str],
    ) {
        ledger.observe(at_ms, anchor, CoActivityKind::Anchor { route });
        for (i, candidate) in candidates.iter().enumerate() {
            ledger.observe(at_ms + 1 + i as u64, candidate, CoActivityKind::Candidate);
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests;
