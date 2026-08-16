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
//!    vice versa (`web.whatsapp.com` and `static.whatsapp.net`, `vk.ru` and
//!    `login.vk.com`, `tiktok.com` and `tiktokv.com`). Shared branding is a
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

use std::collections::{BTreeMap, HashMap};

use nrr_shared::RouteRole;

// ── Tunable defaults ──────────────────────────────────────────────────────────

/// Default anchor window idle extension, in milliseconds.
///
/// Rationale: companion fetches of a page load (media, CDN segments) start
/// within a few seconds of the anchor's own DNS activity. 15 s absorbs slow
/// pages and lazy media without merging unrelated browsing into the window.
pub const DEFAULT_WINDOW_MS: u64 = 15_000;

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
    /// Minimum affinity for a proposal (see [`DEFAULT_MIN_AFFINITY`]).
    pub min_affinity: f64,
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
    /// Let [`PrimaryHealthEvent::Cut`] count towards the primary-route verdict
    /// (see [`DEFAULT_COUNT_CUTS`]). Off by default: an early teardown has
    /// innocent causes too, so the evidence is collected but only speaks when
    /// the user opts in.
    pub count_cuts: bool,
}

impl Default for CompanionAffinityConfig {
    fn default() -> Self {
        Self {
            window_ms: DEFAULT_WINDOW_MS,
            max_window_ms: DEFAULT_MAX_WINDOW_MS,
            min_affinity: DEFAULT_MIN_AFFINITY,
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
            count_cuts: DEFAULT_COUNT_CUTS,
        }
    }
}

/// How many stalls must pile up before a host counts as failing on the primary
/// route. A single resend happens on healthy links; the offer only says
/// "this one does not work without the tunnel" when the stack gave up repeatedly.
const PRIMARY_STALL_CONFIRMATIONS: u32 = 3;

/// How many early teardowns make the same statement. Lower than the stall
/// threshold because the signal is sharper: a link that drops packets resends
/// them, while a connection killed right after the handshake was killed by
/// someone — but a single one still happens for ordinary reasons.
const PRIMARY_CUT_CONFIRMATIONS: u32 = 2;

/// Whether early teardowns count towards the verdict by default.
const DEFAULT_COUNT_CUTS: bool = false;

/// One observation of a candidate's fate on the primary route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrimaryHealthEvent {
    /// The stack had to send a segment again — the peer was not acknowledging.
    Stalled,
    /// The connection died right after being established, having carried
    /// nothing: something answered the handshake and then tore it down.
    Cut,
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
    /// Connections were killed right after the handshake and none completed.
    /// Distinct from [`Self::Stalls`] on purpose: a stalled host may simply be
    /// unreachable, while a cut one was answered by something that refused it.
    Cut,
}

impl PrimaryBehavior {
    /// Verdict for a set of hosts summarized as one offer (a suffix proposal):
    /// a single failing member makes the offer failing, and only unanimity the
    /// other way makes it working. Between the two failure modes the more
    /// specific one wins — being refused says more than being unreachable.
    fn merge(self, other: Self) -> Self {
        match (self, other) {
            (Self::Cut, _) | (_, Self::Cut) => Self::Cut,
            (Self::Stalls, _) | (_, Self::Stalls) => Self::Stalls,
            (Self::Responds, Self::Responds) => Self::Responds,
            (Self::Responds, Self::Unknown) | (Self::Unknown, Self::Responds) => Self::Responds,
            (Self::Unknown, Self::Unknown) => Self::Unknown,
        }
    }
}

// ── Event model ───────────────────────────────────────────────────────────────

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
}

// ── Registrable-domain heuristic ──────────────────────────────────────────────

/// Common multi-part public suffixes recognized by [`registrable_domain`].
///
/// This is a deliberately short, static HEURISTIC table of frequent two-label
/// public suffixes — it is NOT the Public Suffix List and does not try to be.
/// A miss only makes suffix generalization slightly less aggressive (the
/// engine falls back to exact-host proposals), never incorrect routing.
const MULTI_PART_PUBLIC_SUFFIXES: &[&str] = &[
    "ac.uk", "co.uk", "gov.uk", "org.uk", "co.jp", "ne.jp", "or.jp", "com.br", "com.au", "net.au",
    "org.au", "com.tr", "com.cn", "net.cn", "org.cn", "com.ua", "co.in", "co.kr", "co.za",
    "com.ar", "com.hk", "com.mx", "com.sg", "com.tw",
];

/// Extracts the registrable domain of a hostname using a documented heuristic:
/// the last two labels, or the last three when the last two form a known
/// multi-part public suffix (see [`MULTI_PART_PUBLIC_SUFFIXES`]).
///
/// Returns `None` when no registrable domain can be extracted: single-label
/// hosts (`localhost`, intranet flat names) and hostnames that consist of a
/// bare multi-part suffix (`co.uk`). The suffix-table comparison is
/// ASCII-case-insensitive; the returned slice borrows from the input
/// unchanged.
///
/// This is a heuristic, not a Public Suffix List implementation — see the
/// table's documentation for the failure mode (strictly less generalization).
/// Whether generalizing to `*.apex` would also swallow the anchor itself.
///
/// One site under a corporate umbrella says nothing about the umbrella:
/// `aistudio.google.com` is evidence about itself, not about every host under
/// `google.com`. Generalizing there is only earned when the anchor IS the
/// apex (`vk.com` may speak for `*.vk.com`). A companion apex the anchor does
/// not live under — a CDN, say — is unaffected and still generalizes on its
/// own evidence.
/// A suffix rule on `suffix` would route the anchor itself — the site whose
/// companions we are proposing. `*.x` covers `x`, so equality counts.
fn covers_the_anchor(anchor: &str, suffix: &str) -> bool {
    anchor.eq_ignore_ascii_case(suffix) || is_under_suffix(anchor, suffix)
}

fn suffix_would_swallow_the_anchor(anchor: &str, apex: &str) -> bool {
    !anchor.eq_ignore_ascii_case(apex)
        && registrable_domain(anchor).is_some_and(|d| d.eq_ignore_ascii_case(apex))
}

/// `host` sits strictly below `suffix` (`ev-h.disk.example` under
/// `disk.example`), matching the label boundary rather than the raw bytes.
fn is_under_suffix(host: &str, suffix: &str) -> bool {
    host.len() > suffix.len()
        && host.as_bytes()[host.len() - suffix.len() - 1] == b'.'
        && host[host.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
}

/// The deepest suffix that `min_members` of `hostnames` share, deeper than
/// `apex` and accepted by `accept`.
///
/// Used when the registrable domain is out of reach: a dozen fourth-level names
/// of one service is not a review list anybody reads, and the level they share
/// (`disk.example` under `example.md`) names that service exactly. Deeper is
/// narrower, so this can only propose LESS than the apex proposal it stands in
/// for. Deeper wins, then alphabetical, so the choice is deterministic.
fn deepest_shared_suffix<'a>(
    hostnames: &[&'a str],
    apex: &str,
    min_members: usize,
    accept: impl Fn(&str) -> bool,
) -> Option<&'a str> {
    let apex_labels = apex.split('.').count();
    let mut members: BTreeMap<&'a str, usize> = BTreeMap::new();
    for host in hostnames {
        let mut candidate: &'a str = host;
        while let Some((_, parent)) = candidate.split_once('.') {
            candidate = parent;
            if candidate.split('.').count() <= apex_labels {
                break;
            }
            *members.entry(candidate).or_insert(0) += 1;
        }
    }
    members
        .into_iter()
        .filter(|&(suffix, count)| count >= min_members && accept(suffix))
        .max_by(|(a, _), (b, _)| {
            a.split('.')
                .count()
                .cmp(&b.split('.').count())
                .then_with(|| b.cmp(a))
        })
        .map(|(suffix, _)| suffix)
}

pub fn registrable_domain(hostname: &str) -> Option<&str> {
    let mut dots = hostname.rmatch_indices('.').map(|(i, _)| i);
    // Index of the dot preceding the last label; `None` => single label.
    dots.next()?;
    let second_dot = dots.next();
    let last_two = second_dot.map_or(hostname, |i| &hostname[i + 1..]);
    let is_multi_part = MULTI_PART_PUBLIC_SUFFIXES
        .iter()
        .any(|s| s.eq_ignore_ascii_case(last_two));
    if !is_multi_part {
        return Some(last_two);
    }
    // The last two labels are a public suffix: the registrable domain is the
    // last THREE labels — absent a third label there is nothing registrable.
    let second_dot = second_dot?;
    if let Some(third_dot) = dots.next() {
        return Some(&hostname[third_dot + 1..]);
    }
    // Exactly three labels: the whole hostname is the registrable domain,
    // unless a leading dot makes the first label empty (malformed input).
    if second_dot == 0 {
        return None;
    }
    Some(hostname)
}

// ── Name-shape signals ────────────────────────────────────────────────────────

/// Shortest brand token accepted for a substring relation.
///
/// Below this, containment is coincidence rather than branding: three-letter
/// tokens (`vk`, `ok`, `mts`) appear inside unrelated words constantly.
const MIN_BRAND_TOKEN_LEN: usize = 4;

/// Substrings that mark a hostname as a delivery endpoint rather than a site.
///
/// Deliberately a short, human-auditable list of the words operators actually
/// put in delivery hostnames. It is a WEAK signal on purpose — advertising and
/// telemetry endpoints match it just as well — which is why the tier using it
/// also demands temporal evidence.
pub const DELIVERY_NAME_MASKS: &[&str] = &[
    "cdn", "static", "cache", "edge", "media", "img", "video", "stream", "assets", "content",
];

/// The first label of the registrable domain — the token that carries the
/// brand (`static.whatsapp.net` -> `whatsapp`, `login.vk.com` -> `vk`).
fn brand_token(hostname: &str) -> &str {
    registrable_domain(hostname)
        .unwrap_or(hostname)
        .split('.')
        .next()
        .unwrap_or(hostname)
}

/// The candidate carries the anchor's brand, or the anchor carries the
/// candidate's: `web.whatsapp.com` and `static.whatsapp.net`, `vk.ru` and
/// `login.vk.com`, `tiktok.com` and `tiktokv.com`, `dzen.ru` and
/// `static.dzeninfra.ru`.
///
/// Containment (not equality) is what catches the last two shapes: operators
/// register adjacent brands rather than reusing the exact one. Every label of
/// the hostname is searched, so a brand appearing in a deeper label still counts.
fn is_brand_related(anchor: &str, candidate: &str) -> bool {
    let (anchor_brand, candidate_brand) = (brand_token(anchor), brand_token(candidate));
    if anchor_brand == candidate_brand {
        return true;
    }
    carries_brand(candidate, anchor_brand) || carries_brand(anchor, candidate_brand)
}

/// Whether `name` carries `brand` as a label, a label's prefix, or a label's
/// suffix — the shapes branding actually takes (`dzeninfra`, `tiktokv`,
/// `cdninstagram`).
///
/// Anchored on purpose. A brand found anywhere INSIDE a label is a collision,
/// not a relation: `istu` sits in the middle of `aistudio`, and reading that as
/// kinship proposed a university's domain as a companion of Google's AI studio.
///
/// Only the REGISTRABLE domain is searched. A brand sitting in a subdomain of
/// somebody else's apex names the customer, not the owner: `mozilla.map.fastly.net`
/// is a Fastly machine, and treating it as kin proposed moving all of
/// `mozilla.org` onto the additional link. Ownership shapes survive, because
/// they put the brand in the registrable domain itself (`dzeninfra.ru`,
/// `githubusercontent.com`).
fn carries_brand(name: &str, brand: &str) -> bool {
    brand.len() >= MIN_BRAND_TOKEN_LEN
        && registrable_domain(name)
            .unwrap_or(name)
            .split(['.', '-'])
            .any(|label| label.starts_with(brand) || label.ends_with(brand))
}

/// An explicit shard marker: `rr5---sn-ajaig5-5a.googlevideo.com` and friends.
///
/// Only this literal, unmistakable form is recognized. A structural rule for
/// short alphanumeric labels (`s07.`, `p13.`) was measured and rejected: it
/// matches ordinary infrastructure such as software-update endpoints and floods
/// the review list with traffic that belongs on no site's route.
fn is_sharded_delivery_label(hostname: &str) -> bool {
    let first_label = hostname.split('.').next().unwrap_or("");
    let Some((prefix, _)) = first_label.split_once("---sn-") else {
        return false;
    };
    !prefix.is_empty()
        && prefix.chars().all(|c| c.is_ascii_alphanumeric())
        && prefix.chars().any(|c| c.is_ascii_digit())
}

/// The hostname spells out an IPv4 address, so it names one machine rather
/// than a service: `a23-45-67-89.deploy.static.akamaitechnologies.com`,
/// `ec2-18-97-36-79.compute-1.amazonaws.com`, `140.206.0.34.bc.googleusercontent.com`.
///
/// These reach the ledger through the reverse-lookup learner, which exists to
/// name companions the DNS path never sees (browser cache, DoH). What it can
/// name, though, is the machine that answers at an address — never the service
/// the application asked for. Treating one as a companion proposes its shared
/// infrastructure apex for the tunnel, which is a rule over somebody else's
/// traffic.
fn names_one_machine(hostname: &str) -> bool {
    // The leading octet often wears a prefix (`a23-`, `ec2-`), so a token is
    // read as its trailing digits. Demanding that three of the four be bare
    // numbers keeps ordinary names such as `a1-b2-c3-d4` out.
    let octet_of = |token: &str| -> Option<bool> {
        let digits = token.trim_start_matches(|c: char| c.is_ascii_alphabetic());
        let prefix = &token[..token.len() - digits.len()];
        (!digits.is_empty()
            && digits.len() <= 3
            && digits.bytes().all(|b| b.is_ascii_digit())
            && digits.parse::<u16>().is_ok_and(|n| n <= 255))
        .then_some(prefix.is_empty())
    };
    let mut run = 0_u8;
    let mut bare = 0_u8;
    for token in hostname.split(['.', '-']) {
        match octet_of(token) {
            Some(is_bare) => {
                run += 1;
                bare += u8::from(is_bare);
                if run >= 4 && bare >= 3 {
                    return true;
                }
            }
            None => {
                run = 0;
                bare = 0;
            }
        }
    }
    false
}

/// The hostname looks like a delivery endpoint (see [`DELIVERY_NAME_MASKS`]).
fn is_delivery_named(hostname: &str) -> bool {
    DELIVERY_NAME_MASKS.iter().any(|m| hostname.contains(m)) || is_sharded_delivery_label(hostname)
}

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
    pub primary_cuts: u32,
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
    primary_cuts: u32,
    primary_completions: u32,
    /// One entry per live anchor the candidate co-occurred with; swept on
    /// anchor eviction, so its length is bounded by the anchor cap.
    pairs: Vec<PairStats>,
}

impl CandidateState {
    /// Verdict from the accumulated primary-route outcomes. Evidence pointing
    /// both ways yields [`PrimaryBehavior::Unknown`] rather than a guess.
    /// Cuts are weighed only when the caller counts them; unweighed, they leave
    /// the verdict exactly as it would have been without the signal at all.
    fn primary_behavior(&self, count_cuts: bool) -> PrimaryBehavior {
        let cuts = if count_cuts { self.primary_cuts } else { 0 };
        match (self.primary_completions, self.primary_stalls, cuts) {
            (c, 0, 0) if c > 0 => PrimaryBehavior::Responds,
            (0, _, k) if k >= PRIMARY_CUT_CONFIRMATIONS => PrimaryBehavior::Cut,
            (0, s, _) if s >= PRIMARY_STALL_CONFIRMATIONS => PrimaryBehavior::Stalls,
            _ => PrimaryBehavior::Unknown,
        }
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
}

impl CompanionAffinityLedger {
    /// Creates a ledger with the given configuration.
    pub fn new(config: CompanionAffinityConfig) -> Self {
        Self {
            config,
            anchors: HashMap::new(),
            candidates: HashMap::new(),
            next_anchor_id: 0,
            next_window_id: 0,
        }
    }

    /// Creates a ledger with the documented default configuration.
    pub fn with_defaults() -> Self {
        Self::new(CompanionAffinityConfig::default())
    }

    /// Everything learned so far, as plain data the caller can persist.
    #[must_use]
    pub fn snapshot(&self) -> CompanionEvidenceSnapshot {
        let mut anchors: Vec<AnchorSnapshot> = self
            .anchors
            .iter()
            .map(|(hostname, state)| AnchorSnapshot {
                hostname: hostname.clone(),
                id: state.id,
                route: state.route,
                window_id: state.window_id,
                window_start_ms: state.window_start_ms,
                window_end_ms: state.window_end_ms,
                last_seen_ms: state.last_seen_ms,
            })
            .collect();
        // Deterministic order so a saved snapshot compares byte-for-byte with
        // itself and a diff of two saves reads.
        anchors.sort_by(|a, b| a.hostname.cmp(&b.hostname));
        let mut candidates: Vec<CandidateSnapshot> = self
            .candidates
            .iter()
            .map(|(hostname, state)| CandidateSnapshot {
                hostname: hostname.clone(),
                first_seen_ms: state.first_seen_ms,
                last_seen_ms: state.last_seen_ms,
                total_windows: state.total_windows,
                total_hits: state.total_hits,
                seen_in_use: state.seen_in_use,
                primary_stalls: state.primary_stalls,
                primary_cuts: state.primary_cuts,
                primary_completions: state.primary_completions,
                pairs: state
                    .pairs
                    .iter()
                    .map(|p| PairSnapshot {
                        anchor_id: p.anchor_id,
                        distinct_windows: p.distinct_windows,
                        last_window_id: p.last_window_id,
                        nearest_hits: p.nearest_hits,
                        uncontested_hits: p.uncontested_hits,
                    })
                    .collect(),
            })
            .collect();
        candidates.sort_by(|a, b| a.hostname.cmp(&b.hostname));
        CompanionEvidenceSnapshot {
            anchors,
            candidates,
            next_anchor_id: self.next_anchor_id,
            next_window_id: self.next_window_id,
        }
    }

    /// A ledger holding previously saved evidence. `config` comes from this
    /// build and the user's current settings, never from the snapshot — a
    /// threshold the user changed must apply to evidence gathered before it.
    /// Over-cap input is truncated to the configured caps (least recently seen
    /// dropped first), so a snapshot written by a build with roomier caps
    /// cannot push this one past its own bounds.
    #[must_use]
    pub fn restored(config: CompanionAffinityConfig, snapshot: CompanionEvidenceSnapshot) -> Self {
        let mut ledger = Self::new(config);
        let mut anchors = snapshot.anchors;
        anchors.sort_by(|a, b| b.last_seen_ms.cmp(&a.last_seen_ms));
        anchors.truncate(ledger.config.max_anchors);
        let mut candidates = snapshot.candidates;
        candidates.sort_by(|a, b| b.last_seen_ms.cmp(&a.last_seen_ms));
        candidates.truncate(ledger.config.max_candidates);

        let live_ids: std::collections::HashSet<u32> = anchors.iter().map(|a| a.id).collect();
        for a in anchors {
            ledger.anchors.insert(
                a.hostname,
                AnchorState {
                    id: a.id,
                    route: a.route,
                    window_id: a.window_id,
                    window_start_ms: a.window_start_ms,
                    window_end_ms: a.window_end_ms,
                    last_seen_ms: a.last_seen_ms,
                },
            );
        }
        for c in candidates {
            ledger.candidates.insert(
                c.hostname,
                CandidateState {
                    first_seen_ms: c.first_seen_ms,
                    last_seen_ms: c.last_seen_ms,
                    total_windows: c.total_windows,
                    total_hits: c.total_hits,
                    seen_in_use: c.seen_in_use,
                    primary_stalls: c.primary_stalls,
                    primary_cuts: c.primary_cuts,
                    primary_completions: c.primary_completions,
                    // Pairs of anchors that did not survive the truncation are
                    // dropped exactly as an eviction would have dropped them;
                    // the historical totals stay, so affinity is only ever
                    // underestimated.
                    pairs: c
                        .pairs
                        .into_iter()
                        .filter(|p| live_ids.contains(&p.anchor_id))
                        .map(|p| PairStats {
                            anchor_id: p.anchor_id,
                            distinct_windows: p.distinct_windows,
                            last_window_id: p.last_window_id,
                            nearest_hits: p.nearest_hits,
                            uncontested_hits: p.uncontested_hits,
                        })
                        .collect(),
                },
            );
        }
        // Ids must never be reissued: a restored anchor keeps its id, so the
        // next one has to start past every id in the snapshot.
        ledger.next_anchor_id = snapshot
            .next_anchor_id
            .max(ledger.anchors.values().map(|a| a.id + 1).max().unwrap_or(0));
        ledger.next_window_id = snapshot.next_window_id.max(
            ledger
                .anchors
                .values()
                .map(|a| a.window_id + 1)
                .max()
                .unwrap_or(0),
        );
        ledger
    }

    /// Number of currently tracked anchors (diagnostics/tests).
    pub fn anchor_count(&self) -> usize {
        self.anchors.len()
    }

    /// Number of currently tracked candidates (diagnostics/tests).
    pub fn candidate_count(&self) -> usize {
        self.candidates.len()
    }

    /// `true` when the hostname is currently tracked as a candidate.
    pub fn is_tracking_candidate(&self, hostname: &str) -> bool {
        self.candidates.contains_key(hostname)
    }

    /// Records one observation. Cheap and never panics: bounded by the anchor
    /// cap per call, allocation only when a new hostname enters the tracked
    /// set. `at_ms` is caller-supplied monotonic-ish milliseconds; an
    /// out-of-order timestamp is tolerated (windows never shrink, `last_seen`
    /// never moves backwards).
    pub fn observe(&mut self, at_ms: u64, hostname: &str, kind: CoActivityKind) {
        match kind {
            CoActivityKind::Anchor { route } => self.observe_anchor(at_ms, hostname, route),
            CoActivityKind::Candidate => self.observe_candidate(at_ms, hostname, false),
            CoActivityKind::CandidateInUse => self.observe_candidate(at_ms, hostname, true),
            CoActivityKind::PrimaryHealth(event) => self.note_primary_health(hostname, event),
        }
    }

    /// Counts one primary-route outcome against an already-tracked candidate.
    /// Untracked hostnames are ignored outright — health is not a reason to
    /// start tracking, and `last_seen_ms` deliberately does not move: a resend
    /// is not a fresh sighting and must not postpone TTL eviction.
    fn note_primary_health(&mut self, hostname: &str, event: PrimaryHealthEvent) {
        let Some(candidate) = self.candidates.get_mut(hostname) else {
            return;
        };
        match event {
            PrimaryHealthEvent::Stalled => {
                candidate.primary_stalls = candidate.primary_stalls.saturating_add(1);
            }
            PrimaryHealthEvent::Cut => {
                candidate.primary_cuts = candidate.primary_cuts.saturating_add(1);
            }
            PrimaryHealthEvent::Completed => {
                candidate.primary_completions = candidate.primary_completions.saturating_add(1);
            }
        }
    }

    fn observe_anchor(&mut self, at_ms: u64, hostname: &str, route: RouteRole) {
        if self.config.max_anchors == 0 {
            return;
        }
        // A hostname promoted to rule host stops being a candidate; its
        // accumulated candidate evidence is discarded.
        self.candidates.remove(hostname);

        let window_ms = self.config.window_ms.min(self.config.max_window_ms);
        if let Some(anchor) = self.anchors.get_mut(hostname) {
            anchor.route = route;
            anchor.last_seen_ms = anchor.last_seen_ms.max(at_ms);
            if at_ms <= anchor.window_end_ms {
                // Same window: extend the idle deadline, but never past the
                // hard cap measured from the window's opening.
                let hard_cap = anchor
                    .window_start_ms
                    .saturating_add(self.config.max_window_ms);
                anchor.window_end_ms = anchor
                    .window_end_ms
                    .max(at_ms.saturating_add(window_ms))
                    .min(hard_cap);
            } else {
                // Previous window closed (idle gap or hard cap): open a new one.
                anchor.window_id = self.next_window_id;
                self.next_window_id += 1;
                anchor.window_start_ms = at_ms;
                anchor.window_end_ms = at_ms.saturating_add(window_ms);
            }
            return;
        }

        if self.anchors.len() >= self.config.max_anchors {
            self.evict_least_recent_anchor();
        }
        let id = self.next_anchor_id;
        self.next_anchor_id += 1;
        let window_id = self.next_window_id;
        self.next_window_id += 1;
        self.anchors.insert(
            hostname.to_string(),
            AnchorState {
                id,
                route,
                window_id,
                window_start_ms: at_ms,
                window_end_ms: at_ms.saturating_add(window_ms),
                last_seen_ms: at_ms,
            },
        );
    }

    fn observe_candidate(&mut self, at_ms: u64, hostname: &str, in_use: bool) {
        if self.config.max_candidates == 0 {
            return;
        }
        // An anchor is never its own companion; the caller normally marks
        // rule hosts as anchors, this is a cheap defensive backstop.
        if self.anchors.contains_key(hostname) {
            return;
        }
        // Dropped at the door rather than at proposal time: a per-machine name
        // is evidence of nothing, and letting a CDN's node names in would
        // evict real candidates from the tracked set.
        if names_one_machine(hostname) {
            return;
        }
        // A candidate seen outside every anchor window carries no signal;
        // not tracking it keeps memory tied to co-activity, not to traffic.
        if !self
            .anchors
            .values()
            .any(|a| at_ms <= a.window_end_ms && at_ms >= a.window_start_ms)
        {
            return;
        }

        if !self.candidates.contains_key(hostname) {
            if self.candidates.len() >= self.config.max_candidates {
                self.evict_least_recent_candidate();
            }
            self.candidates.insert(
                hostname.to_string(),
                CandidateState {
                    first_seen_ms: at_ms,
                    last_seen_ms: at_ms,
                    total_windows: 0,
                    total_hits: 0,
                    seen_in_use: false,
                    primary_stalls: 0,
                    primary_cuts: 0,
                    primary_completions: 0,
                    pairs: Vec::new(),
                },
            );
        }

        // The anchor that was active most recently owns this observation;
        // hostname order breaks ties so the attribution is deterministic.
        let nearest = self
            .anchors
            .iter()
            .filter(|(_, a)| at_ms <= a.window_end_ms && at_ms >= a.window_start_ms)
            .max_by(|(name_a, a), (name_b, b)| {
                a.last_seen_ms
                    .cmp(&b.last_seen_ms)
                    .then_with(|| name_a.cmp(name_b))
            })
            .map(|(_, a)| a);
        let nearest_anchor_id = nearest.map(|a| a.id);
        // Whether that lead is worth anything. A rival sighted within the tie
        // margin means the winner was picked by DNS timing, not by the user.
        let uncontested = nearest.is_some_and(|winner| {
            !self.anchors.values().any(|a| {
                a.id != winner.id
                    && at_ms <= a.window_end_ms
                    && at_ms >= a.window_start_ms
                    && a.last_seen_ms
                        .saturating_add(self.config.attribution_tie_ms)
                        >= winner.last_seen_ms
            })
        });

        // Split borrow: anchors read-only, one candidate mutated.
        let anchors = &self.anchors;
        let Some(candidate) = self.candidates.get_mut(hostname) else {
            return;
        };
        candidate.last_seen_ms = candidate.last_seen_ms.max(at_ms);
        candidate.total_hits = candidate.total_hits.saturating_add(1);
        candidate.seen_in_use |= in_use;
        for anchor in anchors
            .values()
            .filter(|a| at_ms <= a.window_end_ms && at_ms >= a.window_start_ms)
        {
            let is_nearest = nearest_anchor_id == Some(anchor.id);
            match candidate
                .pairs
                .iter_mut()
                .find(|p| p.anchor_id == anchor.id)
            {
                Some(pair) => {
                    if is_nearest {
                        pair.nearest_hits = pair.nearest_hits.saturating_add(1);
                        if uncontested {
                            pair.uncontested_hits = pair.uncontested_hits.saturating_add(1);
                        }
                    }
                    // Count each window at most once regardless of hit volume.
                    if pair.last_window_id != anchor.window_id {
                        pair.last_window_id = anchor.window_id;
                        pair.distinct_windows = pair.distinct_windows.saturating_add(1);
                        candidate.total_windows = candidate.total_windows.saturating_add(1);
                    }
                }
                None => {
                    candidate.pairs.push(PairStats {
                        anchor_id: anchor.id,
                        distinct_windows: 1,
                        last_window_id: anchor.window_id,
                        nearest_hits: u32::from(is_nearest),
                        uncontested_hits: u32::from(is_nearest && uncontested),
                    });
                    candidate.total_windows = candidate.total_windows.saturating_add(1);
                }
            }
        }
    }

    /// Evicts the least recently seen anchor (ties broken by hostname order
    /// for determinism) and sweeps its pair statistics out of every candidate.
    /// The sweep keeps candidate memory bounded by the LIVE anchor set;
    /// candidate `total_windows` deliberately keeps the historical
    /// contribution (see [`CandidateState::total_windows`]). Never panics —
    /// on an empty map it is a no-op.
    fn evict_least_recent_anchor(&mut self) {
        let victim = self
            .anchors
            .iter()
            .min_by(|(name_a, a), (name_b, b)| {
                a.last_seen_ms
                    .cmp(&b.last_seen_ms)
                    .then_with(|| name_a.cmp(name_b))
            })
            .map(|(name, state)| (name.clone(), state.id));
        if let Some((name, evicted_id)) = victim {
            self.anchors.remove(&name);
            for candidate in self.candidates.values_mut() {
                candidate.pairs.retain(|p| p.anchor_id != evicted_id);
            }
        }
    }

    /// Evicts the least recently seen candidate (ties broken by hostname
    /// order for determinism). Never panics — on an empty map it is a no-op.
    fn evict_least_recent_candidate(&mut self) {
        let victim = self
            .candidates
            .iter()
            .min_by(|(name_a, a), (name_b, b)| {
                a.last_seen_ms
                    .cmp(&b.last_seen_ms)
                    .then_with(|| name_a.cmp(name_b))
            })
            .map(|(name, _)| name.clone());
        if let Some(name) = victim {
            self.candidates.remove(&name);
        }
    }

    /// Decides whether one (candidate, anchor) pair is worth proposing, and on
    /// which grounds. Tiers are tried strongest first; `None` means the pair
    /// stays unproposed — the deliberate default, since a wrong proposal grows
    /// the rule book that every packet is matched against.
    fn qualify(
        &self,
        anchor_hostname: &str,
        candidate_hostname: &str,
        pair: &PairStats,
        candidate: &CandidateState,
        affinity: f64,
    ) -> Option<CompanionSignal> {
        if is_brand_related(anchor_hostname, candidate_hostname) {
            return Some(CompanionSignal::BrandRelated);
        }
        if is_delivery_named(candidate_hostname) {
            let nearest_share =
                f64::from(pair.nearest_hits) / f64::from(candidate.total_hits.max(1));
            let dominated = pair.distinct_windows >= self.config.delivery_min_distinct_windows
                && nearest_share >= self.config.delivery_min_nearest_share;
            // Observed traffic stands in for the second visit. The second visit
            // was only ever a proxy for "this is real, not a speculative
            // resolution" — a connection answers that directly, and answers it
            // during the visit that needed the address rather than the one
            // after. The name still has to look like a delivery endpoint AND
            // this anchor still has to own the observation.
            //
            // Ownership here must be uncontested: this tier publishes on a
            // single sighting, so a lead of a tenth of a second over another
            // open site would be enough to sign the offer with the wrong name,
            // with no later evidence to correct it.
            let proven_by_use = candidate.seen_in_use
                && pair.uncontested_hits > 0
                && nearest_share >= self.config.delivery_min_nearest_share;
            // The blocked case: the address never carried traffic BECAUSE it
            // was blocked, so `seen_in_use` can never arrive and the tier above
            // is unreachable for exactly the names the user is missing. Two
            // things stand in for it, and both are required. Ownership has to be
            // undivided — one anchor, every observation attributed to it, never
            // a rival open in the same breath — and the name has to have
            // actually FAILED on the main route. Advertising and telemetry
            // endpoints work fine there, so they never reach this tier; the
            // half-loaded page the user is looking at does, during the visit
            // that broke rather than the one after.
            let single_obvious_owner = self.config.propose_delivery_names_with_single_owner
                && candidate.pairs.len() == 1
                && pair.uncontested_hits > 0
                && pair.nearest_hits == candidate.total_hits
                && matches!(
                    candidate.primary_behavior(self.config.count_cuts),
                    PrimaryBehavior::Stalls | PrimaryBehavior::Cut
                );
            if self.config.propose_delivery_names_without_co_activity
                || dominated
                || proven_by_use
                || single_obvious_owner
            {
                return Some(CompanionSignal::DeliveryName);
            }
        }
        if pair.distinct_windows >= self.config.min_distinct_windows
            && affinity >= self.config.min_affinity
        {
            return Some(CompanionSignal::CoActivity);
        }
        None
    }

    /// Computes companion proposals from the evidence accumulated so far.
    ///
    /// `now_ms` bounds evidence freshness: candidates last seen more than
    /// [`CompanionAffinityConfig::evidence_ttl_ms`] before `now_ms` are
    /// skipped (their counts are retained and revive on the next sighting).
    ///
    /// A pair is emitted when any of the three tiers accepts it (see the module
    /// documentation and [`CompanionSignal`]).
    ///
    /// Pure read — the ledger is not mutated. Output ordering is fully
    /// deterministic: anchor hostname ascending, then signal (strongest first),
    /// then affinity descending, then proposed value ascending; at most
    /// [`CompanionAffinityConfig::max_proposals_per_anchor`] per anchor, so the
    /// cap drops the weakest evidence first.
    ///
    /// Exclusion checks receive every candidate hostname and every
    /// suffix-proposal apex; an excluded apex falls back to exact-host
    /// proposals for its non-excluded members.
    pub fn proposals<E>(&self, now_ms: u64, exclusions: &E) -> Vec<CompanionProposal>
    where
        E: CandidateExclusions + ?Sized,
    {
        struct Member<'a> {
            hostname: &'a str,
            signal: CompanionSignal,
            affinity: f64,
            nearest_share: f64,
            distinct_windows: u32,
            first_seen_ms: u64,
            last_seen_ms: u64,
            primary_behavior: PrimaryBehavior,
        }

        let mut anchors_by_id: HashMap<u32, (&str, RouteRole)> =
            HashMap::with_capacity(self.anchors.len());
        for (name, state) in &self.anchors {
            anchors_by_id.insert(state.id, (name.as_str(), state.route));
        }

        // anchor hostname -> registrable-domain group -> qualifying members.
        // BTreeMaps make iteration (and thus output) order deterministic.
        let mut grouped: BTreeMap<&str, BTreeMap<&str, Vec<Member<'_>>>> = BTreeMap::new();
        let mut routes: HashMap<&str, RouteRole> = HashMap::new();

        for (host, candidate) in &self.candidates {
            if now_ms.saturating_sub(candidate.last_seen_ms) > self.config.evidence_ttl_ms {
                continue;
            }
            if candidate.total_windows == 0 || exclusions.excludes(host) {
                continue;
            }
            for pair in &candidate.pairs {
                let Some(&(anchor_name, route)) = anchors_by_id.get(&pair.anchor_id) else {
                    continue;
                };
                let affinity =
                    f64::from(pair.distinct_windows) / f64::from(candidate.total_windows);
                let Some(signal) = self.qualify(anchor_name, host, pair, candidate, affinity)
                else {
                    continue;
                };
                let group_key = registrable_domain(host).unwrap_or(host.as_str());
                routes.insert(anchor_name, route);
                grouped
                    .entry(anchor_name)
                    .or_default()
                    .entry(group_key)
                    .or_default()
                    .push(Member {
                        hostname: host.as_str(),
                        signal,
                        affinity,
                        nearest_share: f64::from(pair.nearest_hits)
                            / f64::from(candidate.total_hits.max(1)),
                        distinct_windows: pair.distinct_windows,
                        first_seen_ms: candidate.first_seen_ms,
                        last_seen_ms: candidate.last_seen_ms,
                        primary_behavior: candidate.primary_behavior(self.config.count_cuts),
                    });
            }
        }

        let mut out: Vec<CompanionProposal> = Vec::new();
        for (anchor_name, groups) in &grouped {
            let Some(&route) = routes.get(anchor_name) else {
                continue;
            };
            let mut per_anchor: Vec<CompanionProposal> = Vec::new();
            for (apex, members) in groups {
                let exact = |m: &Member<'_>| CompanionProposal {
                    anchor_hostname: (*anchor_name).to_string(),
                    proposed: ProposedCompanionMatch::ExactHost(m.hostname.to_string()),
                    route,
                    signal: m.signal,
                    affinity: m.affinity,
                    nearest_share: m.nearest_share,
                    distinct_windows: m.distinct_windows,
                    first_seen_ms: m.first_seen_ms,
                    last_seen_ms: m.last_seen_ms,
                    primary_behavior: m.primary_behavior,
                };
                // Only true subdomains justify generalizing to `*.apex` — the
                // apex alone is not evidence that a whole suffix belongs on the
                // route. (It IS covered by the resulting rule, which is why no
                // separate exact proposal is emitted for it below when the
                // suffix proposal fires.)
                let subdomains: Vec<&Member<'_>> =
                    members.iter().filter(|m| m.hostname != *apex).collect();
                // A name that carries the anchor's brand or is a delivery name
                // is evidence about the domain, not just about itself:
                // `static.cdninstagram.com` says the whole CDN serves the site.
                // Co-activity alone says nothing of the kind — a host that
                // merely loaded at the same time must not drag its siblings
                // onto the route.
                //
                // The evidence has to hold for the APEX, though, not just for
                // the one subdomain that was seen. `cdn.auth0.com` is a delivery
                // name under a service's own domain: generalizing it moved all
                // of `auth0.com` — sign-in included — onto the additional link
                // on the strength of one asset host. A dedicated delivery apex
                // (`cdninstagram.com`, `googlevideo.com`, `ytimg.com`) carries
                // the mask itself, and that is the shape worth generalizing.
                let generalizes_alone = subdomains.iter().any(|m| match m.signal {
                    CompanionSignal::BrandRelated => is_brand_related(anchor_name, apex),
                    CompanionSignal::DeliveryName => is_delivery_named(apex),
                    CompanionSignal::CoActivity => false,
                });
                let suffix_proposed = !subdomains.is_empty()
                    && (generalizes_alone || subdomains.len() >= SUFFIX_MIN_DISTINCT_SUBDOMAINS)
                    && !suffix_would_swallow_the_anchor(anchor_name, apex)
                    && !exclusions.excludes(apex);
                // Summarize with the strongest member's evidence and the union
                // of the members' observation span.
                let summarize = |members: &[&Member<'_>], value: String| CompanionProposal {
                    anchor_hostname: (*anchor_name).to_string(),
                    proposed: ProposedCompanionMatch::SuffixDomain(value),
                    route,
                    signal: members
                        .iter()
                        .map(|m| m.signal)
                        .min()
                        .unwrap_or(CompanionSignal::CoActivity),
                    affinity: members.iter().fold(0.0_f64, |acc, m| acc.max(m.affinity)),
                    nearest_share: members
                        .iter()
                        .fold(0.0_f64, |acc, m| acc.max(m.nearest_share)),
                    distinct_windows: members
                        .iter()
                        .map(|m| m.distinct_windows)
                        .max()
                        .unwrap_or(0),
                    first_seen_ms: members.iter().map(|m| m.first_seen_ms).min().unwrap_or(0),
                    last_seen_ms: members.iter().map(|m| m.last_seen_ms).max().unwrap_or(0),
                    primary_behavior: members.iter().fold(PrimaryBehavior::Unknown, |acc, m| {
                        acc.merge(m.primary_behavior)
                    }),
                };
                if suffix_proposed {
                    per_anchor.push(summarize(&subdomains, (*apex).to_string()));
                } else {
                    // The apex is out of reach — it would swallow the anchor, or
                    // a rule already covers it. Falling straight to one proposal
                    // per host hands the user ten fourth-level names of a single
                    // service to answer one by one; the level those names share
                    // is the service, and one `*.that` says the same thing.
                    // Repeated, because one group can hold several such families.
                    let mut remaining: Vec<&Member<'_>> = subdomains;
                    loop {
                        let hostnames: Vec<&str> = remaining.iter().map(|m| m.hostname).collect();
                        let Some(shared) = deepest_shared_suffix(
                            &hostnames,
                            apex,
                            SUFFIX_MIN_DISTINCT_SUBDOMAINS,
                            |suffix| {
                                !covers_the_anchor(anchor_name, suffix)
                                    && !exclusions.excludes(suffix)
                            },
                        ) else {
                            break;
                        };
                        let shared = shared.to_string();
                        let (covered, rest): (Vec<_>, Vec<_>) =
                            remaining.into_iter().partition(|m| {
                                m.hostname == shared || is_under_suffix(m.hostname, &shared)
                            });
                        per_anchor.push(summarize(&covered, shared));
                        remaining = rest;
                    }
                    per_anchor.extend(remaining.iter().map(|m| exact(m)));
                }
                // `*.apex` already covers the apex; a second exact proposal for
                // it would be a redundant entry in the user's review list.
                if !suffix_proposed {
                    per_anchor.extend(members.iter().filter(|m| m.hostname == *apex).map(exact));
                }
            }
            per_anchor.sort_by(|a, b| {
                a.signal
                    .cmp(&b.signal)
                    .then_with(|| b.affinity.total_cmp(&a.affinity))
                    .then_with(|| a.proposed.value().cmp(b.proposed.value()))
            });
            per_anchor.truncate(self.config.max_proposals_per_anchor);
            out.extend(per_anchor);
        }

        // `grouped` already iterates anchors in ascending order; re-sorting
        // makes the contract explicit and independent of the loop above.
        out.sort_by(|a, b| {
            a.anchor_hostname
                .cmp(&b.anchor_hostname)
                .then_with(|| a.signal.cmp(&b.signal))
                .then_with(|| b.affinity.total_cmp(&a.affinity))
                .then_with(|| a.proposed.value().cmp(b.proposed.value()))
        });
        out
    }
}

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
mod tests {
    use super::test_support::{page_load, StaticExclusions};
    use super::*;

    const SECONDARY: RouteRole = RouteRole::Secondary;
    const PRIMARY: RouteRole = RouteRole::Primary;

    fn defaults() -> CompanionAffinityLedger {
        CompanionAffinityLedger::with_defaults()
    }

    /// Two page loads far enough apart to land in distinct windows.
    fn two_visits(ledger: &mut CompanionAffinityLedger, anchor: &str, candidates: &[&str]) {
        page_load(ledger, 0, anchor, SECONDARY, candidates);
        page_load(ledger, 100_000, anchor, SECONDARY, candidates);
    }

    // ── Core proposal flow ───────────────────────────────────────────────────

    #[test]
    fn dedicated_cdn_across_two_page_loads_is_proposed() {
        let mut ledger = defaults();
        two_visits(&mut ledger, "site.example", &["cdn.example"]);

        let proposals = ledger.proposals(150_000, &NoExclusions);
        assert_eq!(proposals.len(), 1);
        let p = &proposals[0];
        assert_eq!(p.anchor_hostname, "site.example");
        assert_eq!(
            p.proposed,
            ProposedCompanionMatch::ExactHost("cdn.example".to_string())
        );
        assert_eq!(p.route, SECONDARY);
        assert_eq!(p.distinct_windows, 2);
        assert!((p.affinity - 1.0).abs() < f64::EPSILON);
        assert_eq!(p.first_seen_ms, 1);
        assert_eq!(p.last_seen_ms, 100_001);
    }

    // ── Primary-route behaviour ──────────────────────────────────────────────

    fn health(
        ledger: &mut CompanionAffinityLedger,
        host: &str,
        event: PrimaryHealthEvent,
        times: u32,
    ) {
        for _ in 0..times {
            ledger.observe(0, host, CoActivityKind::PrimaryHealth(event));
        }
    }

    #[test]
    fn a_host_whose_connections_completed_is_reported_as_working_without_the_tunnel() {
        let mut ledger = defaults();
        two_visits(&mut ledger, "site.example", &["cdn.example"]);
        health(&mut ledger, "cdn.example", PrimaryHealthEvent::Completed, 1);

        let proposals = ledger.proposals(150_000, &NoExclusions);
        assert_eq!(proposals[0].primary_behavior, PrimaryBehavior::Responds);
    }

    #[test]
    fn one_stall_is_not_enough_to_call_a_host_broken() {
        let mut ledger = defaults();
        two_visits(&mut ledger, "site.example", &["cdn.example"]);
        health(&mut ledger, "cdn.example", PrimaryHealthEvent::Stalled, 1);

        let proposals = ledger.proposals(150_000, &NoExclusions);
        assert_eq!(proposals[0].primary_behavior, PrimaryBehavior::Unknown);
    }

    #[test]
    fn repeated_stalls_with_nothing_completing_report_the_host_as_stalling() {
        let mut ledger = defaults();
        two_visits(&mut ledger, "site.example", &["cdn.example"]);
        health(
            &mut ledger,
            "cdn.example",
            PrimaryHealthEvent::Stalled,
            PRIMARY_STALL_CONFIRMATIONS,
        );

        let proposals = ledger.proposals(150_000, &NoExclusions);
        assert_eq!(proposals[0].primary_behavior, PrimaryBehavior::Stalls);
    }

    #[test]
    fn evidence_pointing_both_ways_yields_no_verdict() {
        let mut ledger = defaults();
        two_visits(&mut ledger, "site.example", &["cdn.example"]);
        health(
            &mut ledger,
            "cdn.example",
            PrimaryHealthEvent::Stalled,
            PRIMARY_STALL_CONFIRMATIONS,
        );
        health(&mut ledger, "cdn.example", PrimaryHealthEvent::Completed, 1);

        let proposals = ledger.proposals(150_000, &NoExclusions);
        assert_eq!(proposals[0].primary_behavior, PrimaryBehavior::Unknown);
    }

    fn counting_cuts() -> CompanionAffinityLedger {
        CompanionAffinityLedger::new(CompanionAffinityConfig {
            count_cuts: true,
            ..CompanionAffinityConfig::default()
        })
    }

    #[test]
    fn cuts_say_nothing_until_the_user_counts_them() {
        let mut ledger = defaults();
        two_visits(&mut ledger, "site.example", &["cdn.example"]);
        health(&mut ledger, "cdn.example", PrimaryHealthEvent::Cut, 10);

        let proposals = ledger.proposals(150_000, &NoExclusions);
        assert_eq!(proposals[0].primary_behavior, PrimaryBehavior::Unknown);
    }

    #[test]
    fn one_cut_is_not_enough_to_call_a_host_refused() {
        let mut ledger = counting_cuts();
        two_visits(&mut ledger, "site.example", &["cdn.example"]);
        health(&mut ledger, "cdn.example", PrimaryHealthEvent::Cut, 1);

        let proposals = ledger.proposals(150_000, &NoExclusions);
        assert_eq!(proposals[0].primary_behavior, PrimaryBehavior::Unknown);
    }

    #[test]
    fn repeated_cuts_with_nothing_completing_report_the_host_as_refused() {
        let mut ledger = counting_cuts();
        two_visits(&mut ledger, "site.example", &["cdn.example"]);
        health(
            &mut ledger,
            "cdn.example",
            PrimaryHealthEvent::Cut,
            PRIMARY_CUT_CONFIRMATIONS,
        );

        let proposals = ledger.proposals(150_000, &NoExclusions);
        assert_eq!(proposals[0].primary_behavior, PrimaryBehavior::Cut);
    }

    #[test]
    fn a_cut_host_that_also_completes_yields_no_verdict() {
        let mut ledger = counting_cuts();
        two_visits(&mut ledger, "site.example", &["cdn.example"]);
        health(
            &mut ledger,
            "cdn.example",
            PrimaryHealthEvent::Cut,
            PRIMARY_CUT_CONFIRMATIONS,
        );
        health(&mut ledger, "cdn.example", PrimaryHealthEvent::Completed, 1);

        let proposals = ledger.proposals(150_000, &NoExclusions);
        assert_eq!(proposals[0].primary_behavior, PrimaryBehavior::Unknown);
    }

    #[test]
    fn being_refused_outranks_being_unreachable_in_the_same_host() {
        let mut ledger = counting_cuts();
        two_visits(&mut ledger, "site.example", &["cdn.example"]);
        health(
            &mut ledger,
            "cdn.example",
            PrimaryHealthEvent::Stalled,
            PRIMARY_STALL_CONFIRMATIONS,
        );
        health(
            &mut ledger,
            "cdn.example",
            PrimaryHealthEvent::Cut,
            PRIMARY_CUT_CONFIRMATIONS,
        );

        let proposals = ledger.proposals(150_000, &NoExclusions);
        assert_eq!(proposals[0].primary_behavior, PrimaryBehavior::Cut);
    }

    #[test]
    fn a_summary_takes_the_most_specific_failure_of_its_members() {
        assert_eq!(
            PrimaryBehavior::Stalls.merge(PrimaryBehavior::Cut),
            PrimaryBehavior::Cut
        );
        assert_eq!(
            PrimaryBehavior::Responds.merge(PrimaryBehavior::Cut),
            PrimaryBehavior::Cut
        );
        assert_eq!(
            PrimaryBehavior::Cut.merge(PrimaryBehavior::Unknown),
            PrimaryBehavior::Cut
        );
    }

    #[test]
    fn an_untracked_host_is_not_created_by_a_health_report() {
        let mut ledger = defaults();
        health(
            &mut ledger,
            "stranger.example",
            PrimaryHealthEvent::Stalled,
            5,
        );

        assert_eq!(ledger.candidate_count(), 0);
        assert!(!ledger.is_tracking_candidate("stranger.example"));
    }

    #[test]
    fn single_page_load_is_never_proposed() {
        let mut ledger = defaults();
        page_load(&mut ledger, 0, "site.example", SECONDARY, &["cdn.example"]);

        assert!(ledger.proposals(10_000, &NoExclusions).is_empty());
    }

    #[test]
    fn repeat_hits_inside_one_window_count_as_one_window() {
        let mut ledger = defaults();
        page_load(&mut ledger, 0, "site.example", SECONDARY, &[]);
        // A page load fires the same candidate many times in one window.
        for i in 0..50 {
            ledger.observe(100 + i, "cdn.example", CoActivityKind::Candidate);
        }
        page_load(
            &mut ledger,
            100_000,
            "site.example",
            SECONDARY,
            &["cdn.example"],
        );

        let proposals = ledger.proposals(150_000, &NoExclusions);
        assert_eq!(proposals.len(), 1);
        // 50 hits in window 1 + 1 hit in window 2 => exactly 2 distinct windows.
        assert_eq!(proposals[0].distinct_windows, 2);
        assert!((proposals[0].affinity - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn ubiquitous_candidate_falls_below_affinity_threshold() {
        let mut ledger = defaults();
        // Dedicated companion: only ever seen with anchor a.
        two_visits(&mut ledger, "a.example", &["only-a.cdn", "metrics.shared"]);
        // The shared host also shows up under two other anchors.
        page_load(
            &mut ledger,
            200_000,
            "b.example",
            SECONDARY,
            &["metrics.shared"],
        );
        page_load(
            &mut ledger,
            300_000,
            "c.example",
            SECONDARY,
            &["metrics.shared"],
        );

        let proposals = ledger.proposals(400_000, &NoExclusions);
        // metrics.shared: 2 windows with a / 4 total = 0.5 < 0.8 => suppressed.
        assert!(proposals
            .iter()
            .all(|p| p.proposed.value() != "metrics.shared"));
        // The dedicated companion still qualifies (2/2 = 1.0).
        assert!(proposals
            .iter()
            .any(|p| p.anchor_hostname == "a.example" && p.proposed.value() == "only-a.cdn"));
    }

    #[test]
    fn candidate_outside_any_window_is_not_tracked() {
        let mut ledger = defaults();
        page_load(&mut ledger, 0, "site.example", SECONDARY, &[]);
        // Long after the window (and its hard cap) closed.
        ledger.observe(500_000, "stray.example", CoActivityKind::Candidate);

        assert!(!ledger.is_tracking_candidate("stray.example"));
        assert_eq!(ledger.candidate_count(), 0);
    }

    // ── Tier 1: brand relation ───────────────────────────────────────────────

    #[test]
    fn a_brand_related_companion_is_proposed_from_the_very_first_window() {
        // A brand-related subdomain generalizes to its domain; a candidate that
        // IS the domain has no subdomain to generalize from and stays exact.
        for (anchor, candidate, expected) in [
            ("web.whatsapp.com", "crashlogs.whatsapp.net", "whatsapp.net"),
            ("vk.ru", "login.vk.com", "vk.com"),
            ("tiktok.com", "tiktokv.com", "tiktokv.com"),
        ] {
            let mut ledger = defaults();
            page_load(&mut ledger, 0, anchor, SECONDARY, &[candidate]);

            let proposals = ledger.proposals(10_000, &NoExclusions);
            assert_eq!(proposals.len(), 1, "{candidate} should be proposed");
            assert_eq!(proposals[0].proposed.value(), expected);
            assert_eq!(proposals[0].signal, CompanionSignal::BrandRelated);
            // Shared branding needs no temporal support at all.
            assert_eq!(proposals[0].distinct_windows, 1);
        }
    }

    #[test]
    fn a_brand_buried_inside_a_longer_word_is_not_a_relation() {
        // `istu` sits in the middle of `aistudio`. Reading that as kinship
        // proposed a university's domain as a companion of Google's AI studio.
        let mut ledger = defaults();
        page_load(
            &mut ledger,
            0,
            "aistudio.google.com",
            SECONDARY,
            &["istu.edu"],
        );

        assert!(ledger.proposals(10_000, &NoExclusions).is_empty());
    }

    #[test]
    fn a_brand_at_a_label_edge_is_still_a_relation() {
        // The shapes operators actually register: prefix, suffix, dashed label.
        for (anchor, candidate) in [
            ("dzen.ru", "static.dzeninfra.ru"),
            ("instagram.com", "static.cdninstagram.com"),
            ("example.com", "assets.example-cdn.net"),
        ] {
            let mut ledger = defaults();
            page_load(&mut ledger, 0, anchor, SECONDARY, &[candidate]);

            let proposals = ledger.proposals(10_000, &NoExclusions);
            assert_eq!(proposals.len(), 1, "{candidate} should be proposed");
            assert_eq!(proposals[0].signal, CompanionSignal::BrandRelated);
        }
    }

    #[test]
    fn a_bystander_whose_window_merely_overlapped_does_not_claim_the_host() {
        let mut ledger = defaults();
        for visit in [0_u64, 100_000] {
            // A chatty rule host speaks first and keeps its window open next to
            // whatever the user browses afterwards.
            ledger.observe(
                visit,
                "hub.example",
                CoActivityKind::Anchor { route: SECONDARY },
            );
            page_load(
                &mut ledger,
                visit + 10,
                "site.example",
                SECONDARY,
                &["cdn.example"],
            );
        }

        let proposals = ledger.proposals(200_000, &NoExclusions);
        // Only the site that fetched it proposes: sharing every window halves
        // each anchor's affinity, and the bystander has no other evidence —
        // it was never what the address was fetched for.
        assert_eq!(proposals.len(), 1);
        assert_eq!(proposals[0].anchor_hostname, "site.example");
        assert_eq!(proposals[0].nearest_share, 1.0);
    }

    #[test]
    fn an_unrelated_name_is_not_mistaken_for_a_brand_relation() {
        let mut ledger = defaults();
        // Single visit, so only the ungated brand tier could fire.
        page_load(
            &mut ledger,
            0,
            "web.whatsapp.com",
            SECONDARY,
            &["telemetry.othervendor.net"],
        );

        assert!(ledger.proposals(10_000, &NoExclusions).is_empty());
    }

    #[test]
    fn a_brand_sitting_in_someone_elses_subdomain_is_not_a_relation() {
        // From a live run: a Fastly machine named after its customer offered to
        // move all of mozilla.org onto the additional link.
        let mut ledger = defaults();
        page_load(
            &mut ledger,
            0,
            "mozilla.map.fastly.net",
            SECONDARY,
            &["mozilla.org"],
        );

        assert!(
            ledger.proposals(10_000, &NoExclusions).is_empty(),
            "the brand names Fastly's customer, not Fastly's kin"
        );
    }

    #[test]
    fn a_brand_in_the_registrable_domain_is_still_a_relation() {
        // The shape the rule must keep: the brand is in the apex itself.
        let mut ledger = defaults();
        page_load(
            &mut ledger,
            0,
            "user-images.githubusercontent.com",
            SECONDARY,
            &["github.com"],
        );

        let proposals = ledger.proposals(10_000, &NoExclusions);
        assert_eq!(proposals.len(), 1);
        assert_eq!(proposals[0].signal, CompanionSignal::BrandRelated);
    }

    // ── Tier 2: delivery names ───────────────────────────────────────────────

    #[test]
    fn a_delivery_named_companion_needs_a_second_window() {
        let mut ledger = defaults();
        page_load(
            &mut ledger,
            0,
            "site.test",
            SECONDARY,
            &["img.edgefarm.net"],
        );
        assert!(ledger.proposals(10_000, &NoExclusions).is_empty());

        page_load(
            &mut ledger,
            100_000,
            "site.test",
            SECONDARY,
            &["img.edgefarm.net"],
        );
        let proposals = ledger.proposals(150_000, &NoExclusions);
        assert_eq!(proposals.len(), 1);
        assert_eq!(proposals[0].proposed.value(), "edgefarm.net");
        assert_eq!(proposals[0].signal, CompanionSignal::DeliveryName);
    }

    #[test]
    fn observed_traffic_stands_in_for_the_second_visit() {
        // The user's report: opened the site once, nothing was offered. The
        // second visit was only ever a proxy for "this is real" — a connection
        // says it outright, during the visit that needed the address.
        let mut ledger = defaults();
        let anchor = CoActivityKind::Anchor { route: SECONDARY };
        ledger.observe(0, "site.test", anchor);
        ledger.observe(1_000, "img.edgefarm.net", CoActivityKind::CandidateInUse);

        let proposals = ledger.proposals(10_000, &NoExclusions);
        assert_eq!(proposals.len(), 1, "one visit was enough");
        assert_eq!(proposals[0].proposed.value(), "edgefarm.net");
        assert_eq!(proposals[0].signal, CompanionSignal::DeliveryName);
    }

    #[test]
    fn observed_traffic_does_not_promote_a_host_this_site_does_not_own() {
        // Two sites open, the delivery host belongs to neither in particular
        // (nearest_share 0.5). Seeing traffic to it does not make it this
        // anchor's companion — the ownership gate still has to pass.
        let mut ledger = defaults();
        let anchor = CoActivityKind::Anchor { route: SECONDARY };
        ledger.observe(0, "other.test", anchor);
        ledger.observe(1_000, "site.test", anchor);
        ledger.observe(2_000, "img.edgefarm.net", CoActivityKind::CandidateInUse);
        ledger.observe(3_000, "other.test", anchor);
        ledger.observe(4_000, "img.edgefarm.net", CoActivityKind::Candidate);

        assert!(ledger.proposals(10_000, &NoExclusions).is_empty());
    }

    #[test]
    fn a_delivery_named_companion_goes_to_the_site_that_owns_its_observations() {
        let mut ledger = defaults();
        let anchor = CoActivityKind::Anchor { route: SECONDARY };
        // Both sites are open; "near.test" is always the one just active, so
        // every observation of the delivery host is attributed to it.
        for start in [0_u64, 100_000] {
            ledger.observe(start, "far.test", anchor);
            ledger.observe(start + 1_000, "near.test", anchor);
            ledger.observe(start + 2_000, "img.edgefarm.net", CoActivityKind::Candidate);
        }

        let proposals = ledger.proposals(150_000, &NoExclusions);
        assert_eq!(proposals.len(), 1);
        assert_eq!(proposals[0].anchor_hostname, "near.test");
        assert_eq!(proposals[0].signal, CompanionSignal::DeliveryName);
        // "far.test" saw it in just as many windows, but never owned it.
        assert!((proposals[0].affinity - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn one_sighting_publishes_only_when_no_other_site_was_active_alongside() {
        // Field case: the user opened one site, a second one re-resolved 0.8 s
        // later purely because its TTL expired, and that lead was enough to
        // sign the CDN of the first site with the second one's name. One
        // sighting cannot carry an offer when two sites are in play.
        let mut contested = defaults();
        let anchor = CoActivityKind::Anchor { route: SECONDARY };
        contested.observe(0, "opened-by-the-user.test", anchor);
        contested.observe(800, "chatty-ttl.test", anchor);
        contested.observe(1_000, "img.edgefarm.net", CoActivityKind::CandidateInUse);
        assert!(contested.proposals(10_000, &NoExclusions).is_empty());

        // The same sighting with the rival long quiet still publishes at once —
        // that shortcut is what makes a half-broken page fixable on the spot.
        let mut clear = defaults();
        clear.observe(0, "chatty-ttl.test", anchor);
        clear.observe(30_000, "opened-by-the-user.test", anchor);
        clear.observe(31_000, "img.edgefarm.net", CoActivityKind::CandidateInUse);
        let proposals = clear.proposals(40_000, &NoExclusions);
        assert_eq!(proposals.len(), 1);
        assert_eq!(proposals[0].anchor_hostname, "opened-by-the-user.test");
    }

    #[test]
    fn a_contested_sighting_still_counts_once_the_evidence_repeats() {
        // Refusing the one-sighting shortcut must not silence the offer for
        // good: the ordinary two-window path is untouched.
        let mut ledger = defaults();
        let anchor = CoActivityKind::Anchor { route: SECONDARY };
        for start in [0_u64, 100_000] {
            ledger.observe(start, "opened-by-the-user.test", anchor);
            ledger.observe(start + 800, "chatty-ttl.test", anchor);
            ledger.observe(
                start + 1_000,
                "img.edgefarm.net",
                CoActivityKind::CandidateInUse,
            );
        }
        assert!(!ledger.proposals(150_000, &NoExclusions).is_empty());
    }

    #[test]
    fn a_family_of_fourth_level_names_collapses_to_the_level_they_share() {
        // The user's report: ten fourth-level names of one service, each its own
        // row to answer. The registrable domain is unreachable here — the anchor
        // lives under it — but `disk.example.md` names the service exactly.
        let mut ledger = defaults();
        let anchor = CoActivityKind::Anchor { route: SECONDARY };
        for start in [0_u64, 100_000] {
            ledger.observe(start, "mail.example.md", anchor);
            for (i, host) in [
                "a.disk.example.md",
                "b.disk.example.md",
                "c.disk.example.md",
            ]
            .iter()
            .enumerate()
            {
                ledger.observe(start + 1 + i as u64, host, CoActivityKind::Candidate);
            }
        }

        let proposals = ledger.proposals(150_000, &NoExclusions);
        let values: Vec<&str> = proposals.iter().map(|p| p.proposed.value()).collect();
        assert_eq!(values, vec!["disk.example.md"], "one row, not three");
        assert!(matches!(
            proposals[0].proposed,
            ProposedCompanionMatch::SuffixDomain(_)
        ));
    }

    #[test]
    fn the_shared_level_never_swallows_the_site_it_was_found_next_to() {
        // Same shape, except the anchor sits INSIDE the level the companions
        // share. Collapsing there would write a rule over the anchor itself, so
        // the individual names stand.
        let mut ledger = defaults();
        let anchor = CoActivityKind::Anchor { route: SECONDARY };
        for start in [0_u64, 100_000] {
            ledger.observe(start, "disk.example.md", anchor);
            for (i, host) in ["a.disk.example.md", "b.disk.example.md"]
                .iter()
                .enumerate()
            {
                ledger.observe(start + 1 + i as u64, host, CoActivityKind::Candidate);
            }
        }

        let values: Vec<String> = ledger
            .proposals(150_000, &NoExclusions)
            .into_iter()
            .map(|p| p.proposed.value().to_string())
            .collect();
        assert_eq!(values, vec!["a.disk.example.md", "b.disk.example.md"]);
    }

    #[test]
    fn two_families_under_one_domain_collapse_separately() {
        let mut ledger = defaults();
        let anchor = CoActivityKind::Anchor { route: SECONDARY };
        for start in [0_u64, 100_000] {
            ledger.observe(start, "mail.example.md", anchor);
            for (i, host) in [
                "a.disk.example.md",
                "b.disk.example.md",
                "a.upd.example.md",
                "b.upd.example.md",
            ]
            .iter()
            .enumerate()
            {
                ledger.observe(start + 1 + i as u64, host, CoActivityKind::Candidate);
            }
        }

        let mut values: Vec<String> = ledger
            .proposals(150_000, &NoExclusions)
            .into_iter()
            .map(|p| p.proposed.value().to_string())
            .collect();
        values.sort();
        assert_eq!(values, vec!["disk.example.md", "upd.example.md"]);
    }

    #[test]
    fn one_lonely_fourth_level_name_is_not_a_family() {
        // Two hosts is the same bar the apex generalization uses; one host says
        // nothing about its siblings.
        let mut ledger = defaults();
        let anchor = CoActivityKind::Anchor { route: SECONDARY };
        for start in [0_u64, 100_000] {
            ledger.observe(start, "mail.example.md", anchor);
            ledger.observe(start + 1, "only.disk.example.md", CoActivityKind::Candidate);
        }

        let values: Vec<String> = ledger
            .proposals(150_000, &NoExclusions)
            .into_iter()
            .map(|p| p.proposed.value().to_string())
            .collect();
        assert_eq!(values, vec!["only.disk.example.md"]);
    }

    #[test]
    fn a_hostname_that_spells_out_an_address_is_not_a_companion() {
        let mut ledger = defaults();
        let anchor = CoActivityKind::Anchor { route: SECONDARY };
        ledger.observe(0, "site.test", anchor);
        // Reverse lookup named the machine behind a shared CDN address. Its
        // apex serves the whole internet, so proposing it routes strangers.
        ledger.observe(
            1_000,
            "a23-213-41-17.deploy.static.akamaitechnologies.com",
            CoActivityKind::CandidateInUse,
        );

        assert!(ledger.proposals(10_000, &NoExclusions).is_empty());
        assert_eq!(
            ledger.candidate_count(),
            0,
            "never tracked in the first place"
        );
    }

    #[test]
    fn machine_names_are_told_apart_from_service_names() {
        // Every shape here was observed in the wild, reaching the ledger
        // through the reverse-lookup learner.
        for machine in [
            "a23-213-41-17.deploy.static.akamaitechnologies.com",
            "ec2-18-97-36-79.compute-1.amazonaws.com",
            "ec2-3-233-36-186.compute-1.amazonaws.com",
            "140.206.0.34.bc.googleusercontent.com",
            "server-13-32-45-67.fra6.r.example.net",
        ] {
            assert!(names_one_machine(machine), "{machine}");
        }
        for service in [
            "static.cdninstagram.com",
            "xx-fbcdn-shv-02-fra3.fbcdn.net",
            "rr5---sn-2o25g5-55.googlevideo.com",
            "ei.phncdn.com",
            // Four groups, but 2026 is no octet.
            "build-2026-01-02-03.example.com",
        ] {
            assert!(!names_one_machine(service), "{service}");
        }
    }

    #[test]
    fn only_the_explicit_shard_form_counts_as_a_delivery_name() {
        assert!(is_delivery_named("rr5---sn-ajaig5-5a.googlevideo.com"));
        assert!(is_delivery_named("static.whatsapp.net"));
        assert!(is_delivery_named("i.ytimg.com"));
        // A short alphanumeric label is NOT a shard marker: ordinary update and
        // telemetry infrastructure is named that way, and admitting it was
        // measured to bury the real companions in noise.
        assert!(!is_delivery_named("s07.upd3.kaspersky.com"));
        assert!(!is_delivery_named("p13.upd3.kaspersky.com"));
        assert!(!is_delivery_named("api.example.com"));
    }

    #[test]
    fn a_delivery_name_under_a_services_own_domain_stays_exact() {
        // From a live run: one asset host offered to move the whole service —
        // sign-in included — onto the additional link.
        let mut ledger = defaults();
        for at in [0_u64, 100_000] {
            page_load(&mut ledger, at, "site.test", SECONDARY, &["cdn.auth0.com"]);
        }

        let proposals = ledger.proposals(150_000, &NoExclusions);
        assert_eq!(proposals.len(), 1);
        assert_eq!(
            proposals[0].proposed.value(),
            "cdn.auth0.com",
            "an asset host under a service's own apex is evidence about itself only"
        );
    }

    #[test]
    fn a_shard_shaped_name_is_proposed_but_a_numbered_label_is_not() {
        let mut ledger = defaults();
        let anchor = CoActivityKind::Anchor { route: SECONDARY };
        // Two sites open, "site.test" always the most recent one. Affinity is
        // 0.5 for both candidates, so only the delivery tier can propose.
        for start in [0_u64, 100_000] {
            ledger.observe(start, "other.test", anchor);
            ledger.observe(start + 1_000, "site.test", anchor);
            for (i, host) in [
                "rr5---sn-ajaig5-5a.googlevideo.com",
                "s07.upd3.kaspersky.com",
            ]
            .iter()
            .enumerate()
            {
                ledger.observe(start + 2_000 + i as u64, host, CoActivityKind::Candidate);
            }
        }

        let proposals = ledger.proposals(150_000, &NoExclusions);
        let values: Vec<&str> = proposals.iter().map(|p| p.proposed.value()).collect();
        assert_eq!(values, vec!["googlevideo.com"]);
        assert_eq!(proposals[0].anchor_hostname, "site.test");
    }

    // ── Evidence that survives a restart ─────────────────────────────────────

    #[test]
    fn a_restored_ledger_proposes_on_the_visit_that_would_have_been_the_second() {
        // The restart is the whole point: one visit before it, one after, and
        // the pair adds up exactly as two visits in one session would.
        let mut before = defaults();
        page_load(&mut before, 0, "site.example", SECONDARY, &["cdn.example"]);
        assert!(before.proposals(10_000, &NoExclusions).is_empty());

        let mut after = CompanionAffinityLedger::restored(
            CompanionAffinityConfig::default(),
            before.snapshot(),
        );
        page_load(
            &mut after,
            100_000,
            "site.example",
            SECONDARY,
            &["cdn.example"],
        );

        let proposals = after.proposals(150_000, &NoExclusions);
        assert_eq!(proposals.len(), 1, "the window before the restart counted");
        assert_eq!(proposals[0].anchor_hostname, "site.example");
    }

    #[test]
    fn a_snapshot_round_trips_unchanged() {
        let mut ledger = defaults();
        two_visits(
            &mut ledger,
            "site.example",
            &["cdn.example", "helper.other"],
        );
        health(&mut ledger, "cdn.example", PrimaryHealthEvent::Stalled, 2);
        let snapshot = ledger.snapshot();

        let restored =
            CompanionAffinityLedger::restored(CompanionAffinityConfig::default(), snapshot.clone());
        assert_eq!(restored.snapshot(), snapshot);
        assert_eq!(
            restored.proposals(150_000, &NoExclusions),
            ledger.proposals(150_000, &NoExclusions),
            "restored evidence must produce the same offers"
        );
    }

    #[test]
    fn restoring_never_reissues_an_anchor_id() {
        let mut ledger = defaults();
        page_load(&mut ledger, 0, "a.test", SECONDARY, &["cdn.example"]);
        let snapshot = ledger.snapshot();
        let highest = snapshot.anchors.iter().map(|a| a.id).max().expect("anchor");

        let mut restored =
            CompanionAffinityLedger::restored(CompanionAffinityConfig::default(), snapshot);
        page_load(&mut restored, 100_000, "b.test", SECONDARY, &[]);
        let ids: Vec<u32> = restored.snapshot().anchors.iter().map(|a| a.id).collect();
        assert!(
            ids.iter().filter(|id| **id == highest).count() == 1,
            "a fresh anchor must not take an id that is already in use: {ids:?}"
        );
    }

    #[test]
    fn restoring_more_than_the_caps_allow_truncates_to_the_freshest() {
        let config = CompanionAffinityConfig {
            max_anchors: 1,
            max_candidates: 1,
            ..CompanionAffinityConfig::default()
        };
        let mut roomy = defaults();
        page_load(&mut roomy, 0, "old.test", SECONDARY, &["old-cdn.example"]);
        page_load(
            &mut roomy,
            50_000,
            "new.test",
            SECONDARY,
            &["new-cdn.example"],
        );

        let tight = CompanionAffinityLedger::restored(config, roomy.snapshot());
        assert_eq!(tight.anchor_count(), 1);
        assert_eq!(tight.candidate_count(), 1);
        let kept = tight.snapshot();
        assert_eq!(kept.anchors[0].hostname, "new.test");
        assert_eq!(kept.candidates[0].hostname, "new-cdn.example");
        assert!(
            kept.candidates[0]
                .pairs
                .iter()
                .all(|p| p.anchor_id == kept.anchors[0].id),
            "pairs of dropped anchors must not survive them"
        );
    }

    #[test]
    fn a_delivery_name_with_one_owner_that_failed_on_the_main_route_needs_no_second_visit() {
        // The 0811 case: images of the site the user is reading do not load,
        // the visit is short, the service restarts before a second one. One
        // anchor, nobody else, and the address failing on the main route is
        // everything the offer needs.
        let mut ledger = defaults();
        page_load(
            &mut ledger,
            0,
            "site.test",
            SECONDARY,
            &["img.edgefarm.net"],
        );
        assert!(
            ledger.proposals(10_000, &NoExclusions).is_empty(),
            "no failure observed yet — nothing to offer"
        );
        health(
            &mut ledger,
            "img.edgefarm.net",
            PrimaryHealthEvent::Stalled,
            PRIMARY_STALL_CONFIRMATIONS,
        );

        let proposals = ledger.proposals(10_000, &NoExclusions);
        assert_eq!(proposals.len(), 1, "one visit is enough now");
        assert_eq!(proposals[0].signal, CompanionSignal::DeliveryName);
        assert_eq!(proposals[0].anchor_hostname, "site.test");
    }

    #[test]
    fn a_failing_delivery_name_shared_with_a_second_site_still_waits() {
        // Ownership has to be undivided: a name two open sites both asked for
        // says nothing about which of them it belongs to, however badly it
        // behaves.
        let mut ledger = defaults();
        page_load(&mut ledger, 0, "a.test", SECONDARY, &["img.edgefarm.net"]);
        page_load(
            &mut ledger,
            1_000,
            "b.test",
            SECONDARY,
            &["img.edgefarm.net"],
        );
        health(
            &mut ledger,
            "img.edgefarm.net",
            PrimaryHealthEvent::Stalled,
            PRIMARY_STALL_CONFIRMATIONS,
        );

        assert!(ledger.proposals(10_000, &NoExclusions).is_empty());
    }

    #[test]
    fn the_delivery_bypass_option_proposes_on_first_sight_and_touches_nothing_else() {
        let feed = |ledger: &mut CompanionAffinityLedger| {
            page_load(
                ledger,
                0,
                "site.test",
                SECONDARY,
                &["assets.edgefarm.net", "helper.other"],
            );
        };

        let mut gated = defaults();
        feed(&mut gated);
        assert!(
            gated.proposals(10_000, &NoExclusions).is_empty(),
            "the gate is on by default"
        );

        let mut ungated = CompanionAffinityLedger::new(CompanionAffinityConfig {
            propose_delivery_names_without_co_activity: true,
            ..CompanionAffinityConfig::default()
        });
        feed(&mut ungated);
        let proposals = ungated.proposals(10_000, &NoExclusions);
        // Only the delivery-shaped name is released; the plain one still has to
        // earn its proposal through the co-activity tier.
        let values: Vec<&str> = proposals.iter().map(|p| p.proposed.value()).collect();
        assert_eq!(values, vec!["edgefarm.net"]);
        assert_eq!(proposals[0].signal, CompanionSignal::DeliveryName);
    }

    // ── Tier 3: co-activity only ─────────────────────────────────────────────

    #[test]
    fn a_plain_named_companion_still_needs_the_strict_affinity_threshold() {
        let mut ledger = defaults();
        // Neither brand-related nor delivery-shaped: only the conservative tier
        // applies, and two anchors sharing the host put it at 0.5.
        for (at, anchor) in [(0_u64, "a.test"), (100_000, "b.test")] {
            page_load(&mut ledger, at, anchor, SECONDARY, &["helper.other"]);
            page_load(
                &mut ledger,
                at + 30_000,
                anchor,
                SECONDARY,
                &["helper.other"],
            );
        }
        assert!(ledger.proposals(200_000, &NoExclusions).is_empty());

        // Further visits to one site alone lift it to the threshold (8/10).
        for at in [200_000, 300_000, 400_000, 500_000, 600_000, 700_000] {
            page_load(&mut ledger, at, "a.test", SECONDARY, &["helper.other"]);
        }
        let proposals = ledger.proposals(550_000, &NoExclusions);
        assert_eq!(proposals.len(), 1);
        assert_eq!(proposals[0].anchor_hostname, "a.test");
        assert_eq!(proposals[0].signal, CompanionSignal::CoActivity);
    }

    // ── Window mechanics ─────────────────────────────────────────────────────

    #[test]
    fn anchor_activity_extends_a_window_instead_of_opening_a_new_one() {
        let mut ledger = defaults();
        let anchor = CoActivityKind::Anchor { route: SECONDARY };
        // Anchor keeps firing every 10 s: same window while under the hard cap.
        ledger.observe(0, "site.example", anchor);
        ledger.observe(10_000, "site.example", anchor);
        ledger.observe(20_000, "site.example", anchor);
        // Candidate hits at both ends of the extended window: one window only.
        ledger.observe(1_000, "cdn.example", CoActivityKind::Candidate);
        ledger.observe(30_000, "cdn.example", CoActivityKind::Candidate);

        // Only one distinct window so far => below the minimum, no proposal.
        assert!(ledger.proposals(40_000, &NoExclusions).is_empty());

        // A later visit opens a second window and unlocks the proposal.
        page_load(
            &mut ledger,
            200_000,
            "site.example",
            SECONDARY,
            &["cdn.example"],
        );
        let proposals = ledger.proposals(250_000, &NoExclusions);
        assert_eq!(proposals.len(), 1);
        assert_eq!(proposals[0].distinct_windows, 2);
    }

    #[test]
    fn continuous_browsing_of_one_site_proposes_within_a_single_visit() {
        // Product rule: the proposal must appear during the user's first
        // normal visit (open the site, click into a video) — it must NOT
        // require the user to leave and reload the site by hand. The hard
        // window cap guarantees continuous activity still closes windows.
        let mut ledger = defaults();
        let anchor = CoActivityKind::Anchor { route: SECONDARY };
        // ~2.5 minutes of continuous activity with NO idle gap: anchor and
        // candidate keep firing every 5 s.
        let mut t: u64 = 0;
        while t <= 150_000 {
            ledger.observe(t, "site.example", anchor);
            ledger.observe(t + 1_000, "cdn.example", CoActivityKind::Candidate);
            t += 5_000;
        }

        let proposals = ledger.proposals(150_000, &NoExclusions);
        assert_eq!(proposals.len(), 1);
        let p = &proposals[0];
        assert_eq!(p.proposed.value(), "cdn.example");
        assert!(
            p.distinct_windows >= 2,
            "hard window cap must split continuous browsing into windows, got {}",
            p.distinct_windows
        );
        assert!((p.affinity - 1.0).abs() < f64::EPSILON);
    }

    // ── Suffix generalization ────────────────────────────────────────────────

    #[test]
    fn two_distinct_subdomains_generalize_to_a_suffix_proposal() {
        let mut ledger = defaults();
        two_visits(
            &mut ledger,
            "site.example",
            &["di.cdn-relay.example", "ev-h.cdn-relay.example"],
        );

        let proposals = ledger.proposals(150_000, &NoExclusions);
        assert_eq!(proposals.len(), 1);
        assert_eq!(
            proposals[0].proposed,
            ProposedCompanionMatch::SuffixDomain("cdn-relay.example".to_string())
        );
        assert_eq!(proposals[0].distinct_windows, 2);
        assert_eq!(proposals[0].first_seen_ms, 1);
        assert_eq!(proposals[0].last_seen_ms, 100_002);
    }

    #[test]
    fn a_single_co_active_subdomain_stays_an_exact_host_proposal() {
        let mut ledger = defaults();
        // Neither branded after the anchor nor delivery-named: it only ever
        // loaded at the same time, which says nothing about its siblings.
        two_visits(&mut ledger, "site.example", &["one.partner.test"]);

        let proposals = ledger.proposals(150_000, &NoExclusions);
        assert_eq!(proposals.len(), 1);
        assert_eq!(
            proposals[0].proposed,
            ProposedCompanionMatch::ExactHost("one.partner.test".to_string())
        );
    }

    #[test]
    fn one_delivery_named_subdomain_is_enough_to_generalize() {
        let mut ledger = defaults();
        // The user's case: seeing `static.cdninstagram.com` should offer the
        // whole CDN, not one host of it that the next page load replaces.
        two_visits(&mut ledger, "site.example", &["di.cdn-relay.example"]);

        let proposals = ledger.proposals(150_000, &NoExclusions);
        assert_eq!(proposals.len(), 1);
        assert_eq!(
            proposals[0].proposed,
            ProposedCompanionMatch::SuffixDomain("cdn-relay.example".to_string())
        );
    }

    #[test]
    fn the_apex_itself_does_not_count_toward_suffix_generalization() {
        let mut ledger = defaults();
        // Apex + one co-active subdomain is not enough evidence to generalize
        // to `*.apex` — one observed subdomain stays one observed subdomain, so
        // both remain exact proposals.
        two_visits(
            &mut ledger,
            "site.example",
            &["partner.test", "one.partner.test"],
        );

        let proposals = ledger.proposals(150_000, &NoExclusions);
        let values: Vec<&str> = proposals.iter().map(|p| p.proposed.value()).collect();
        assert_eq!(values, vec!["one.partner.test", "partner.test"]);
        assert!(proposals
            .iter()
            .all(|p| matches!(p.proposed, ProposedCompanionMatch::ExactHost(_))));
    }

    #[test]
    fn a_suffix_proposal_absorbs_the_apex_instead_of_duplicating_it() {
        let mut ledger = defaults();
        // Apex + two subdomains: the suffix proposal fires and, since it now
        // covers the apex too, the apex must NOT also appear as an exact
        // proposal — that would be a redundant row in the review list.
        two_visits(
            &mut ledger,
            "site.example",
            &[
                "cdn-relay.example",
                "di.cdn-relay.example",
                "ev-h.cdn-relay.example",
            ],
        );

        let proposals = ledger.proposals(150_000, &NoExclusions);
        assert_eq!(
            proposals
                .iter()
                .map(|p| p.proposed.clone())
                .collect::<Vec<_>>(),
            vec![ProposedCompanionMatch::SuffixDomain(
                "cdn-relay.example".to_string()
            )]
        );
    }

    #[test]
    fn a_suffix_covering_the_anchor_itself_is_never_proposed() {
        let mut ledger = defaults();
        // The anchor lives under the apex, so `*.google.com` would put the
        // whole corporation on the route on the strength of one site. The
        // companions stay as exact proposals instead.
        two_visits(
            &mut ledger,
            "aistudio.google.com",
            &[
                "google.com",
                "accounts.google.com",
                "content.googleapis.com",
            ],
        );

        let proposals = ledger.proposals(150_000, &NoExclusions);
        assert!(
            !proposals.iter().any(|p| matches!(
                &p.proposed,
                ProposedCompanionMatch::SuffixDomain(d) if d == "google.com")),
            "the anchor's own umbrella was proposed: {:?}",
            proposals
                .iter()
                .map(|p| p.proposed.clone())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn an_apex_the_anchor_does_not_live_under_still_generalizes() {
        let mut ledger = defaults();
        // The guard above is about the anchor's OWN umbrella. A third-party
        // delivery domain is unaffected: two subdomains still earn `*.apex`.
        two_visits(
            &mut ledger,
            "aistudio.google.com",
            &["static.cdnexample.net", "media.cdnexample.net"],
        );

        let proposals = ledger.proposals(150_000, &NoExclusions);
        assert!(
            proposals.iter().any(|p| matches!(
                &p.proposed,
                ProposedCompanionMatch::SuffixDomain(d) if d == "cdnexample.net")),
            "a third-party apex stopped generalizing: {:?}",
            proposals
                .iter()
                .map(|p| p.proposed.clone())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_brand_related_sibling_under_the_anchors_own_apex_stays_exact() {
        let mut ledger = defaults();
        // `rt.site.com` shares a brand with `www.site.com` only because they
        // share a domain — the same trivial equality that would fire for any
        // sibling of `aistudio.google.com`. It must earn only itself, not
        // `*.site.com`, on one window's evidence — this is the shape behind
        // any two same-domain subdomains reached via trivial brand equality
        // in the companion-affinity trace study.
        page_load(&mut ledger, 0, "www.site.com", SECONDARY, &["rt.site.com"]);

        let proposals = ledger.proposals(10_000, &NoExclusions);
        assert_eq!(proposals.len(), 1);
        assert_eq!(proposals[0].signal, CompanionSignal::BrandRelated);
        assert_eq!(
            proposals[0].proposed,
            ProposedCompanionMatch::ExactHost("rt.site.com".to_string())
        );
    }

    #[test]
    fn a_delivery_looking_sibling_under_the_anchors_own_apex_stays_exact() {
        let mut ledger = defaults();
        // `static.site.com` looks like a CDN host, but sharing the anchor's
        // own registrable domain means brand equality (the trivial "same
        // domain" branch of `is_brand_related`) always wins the tier race
        // before the delivery-name check runs — so this can never reach
        // `CompanionSignal::DeliveryName` in the first place, and the same
        // swallow guard applies regardless of which tier accepted it.
        two_visits(&mut ledger, "www.site.com", &["static.site.com"]);

        let proposals = ledger.proposals(150_000, &NoExclusions);
        assert_eq!(proposals.len(), 1);
        assert_eq!(proposals[0].signal, CompanionSignal::BrandRelated);
        assert_eq!(
            proposals[0].proposed,
            ProposedCompanionMatch::ExactHost("static.site.com".to_string())
        );
    }

    #[test]
    fn excluded_suffix_apex_falls_back_to_exact_host_proposals() {
        let mut ledger = defaults();
        two_visits(
            &mut ledger,
            "site.example",
            &["di.cdn-relay.example", "ev-h.cdn-relay.example"],
        );

        let mut exclusions = StaticExclusions::default();
        exclusions
            .matched_by_existing_rule
            .insert("cdn-relay.example".to_string());
        let proposals = ledger.proposals(150_000, &exclusions);
        let values: Vec<&str> = proposals.iter().map(|p| p.proposed.value()).collect();
        assert_eq!(
            values,
            vec!["di.cdn-relay.example", "ev-h.cdn-relay.example"]
        );
    }

    // ── Registrable-domain heuristic ─────────────────────────────────────────

    #[test]
    fn registrable_domain_heuristic_cases() {
        // Plain two-label host: itself.
        assert_eq!(registrable_domain("example.com"), Some("example.com"));
        // Deep subdomain: last two labels.
        assert_eq!(
            registrable_domain("ev-h.cdn-relay.example"),
            Some("cdn-relay.example")
        );
        // Multi-part public suffix: last three labels.
        assert_eq!(
            registrable_domain("a.b.example.co.uk"),
            Some("example.co.uk")
        );
        assert_eq!(registrable_domain("www.foo.com.br"), Some("foo.com.br"));
        assert_eq!(registrable_domain("foo.com.br"), Some("foo.com.br"));
        // Bare multi-part suffix: nothing registrable.
        assert_eq!(registrable_domain("co.uk"), None);
        // Single label: nothing registrable.
        assert_eq!(registrable_domain("localhost"), None);
        // Case-insensitive suffix table match.
        assert_eq!(registrable_domain("www.foo.CO.UK"), Some("foo.CO.UK"));
    }

    // ── Bounds and eviction ──────────────────────────────────────────────────

    #[test]
    fn exceeding_the_candidate_cap_evicts_the_least_recently_seen() {
        let mut ledger = CompanionAffinityLedger::new(CompanionAffinityConfig {
            max_candidates: 2,
            ..CompanionAffinityConfig::default()
        });
        page_load(&mut ledger, 0, "site.example", SECONDARY, &[]);
        ledger.observe(1_000, "old.cdn", CoActivityKind::Candidate);
        ledger.observe(2_000, "mid.cdn", CoActivityKind::Candidate);
        ledger.observe(3_000, "new.cdn", CoActivityKind::Candidate);

        assert_eq!(ledger.candidate_count(), 2);
        assert!(!ledger.is_tracking_candidate("old.cdn"));
        assert!(ledger.is_tracking_candidate("mid.cdn"));
        assert!(ledger.is_tracking_candidate("new.cdn"));
    }

    #[test]
    fn exceeding_the_anchor_cap_evicts_and_sweeps_pair_statistics() {
        let mut ledger = CompanionAffinityLedger::new(CompanionAffinityConfig {
            max_anchors: 2,
            ..CompanionAffinityConfig::default()
        });
        // The candidate earns a qualifying score with the oldest anchor.
        page_load(&mut ledger, 0, "a.example", SECONDARY, &["shared.cdn"]);
        page_load(
            &mut ledger,
            100_000,
            "a.example",
            SECONDARY,
            &["shared.cdn"],
        );
        page_load(&mut ledger, 200_000, "b.example", SECONDARY, &[]);
        // Third anchor exceeds the cap: a.example (least recent) is evicted.
        page_load(&mut ledger, 300_000, "c.example", SECONDARY, &[]);

        assert_eq!(ledger.anchor_count(), 2);
        // The swept pair can no longer produce a proposal for the evicted anchor.
        let proposals = ledger.proposals(350_000, &NoExclusions);
        assert!(proposals.iter().all(|p| p.anchor_hostname != "a.example"));
    }

    #[test]
    fn zero_caps_disable_tracking_without_panicking() {
        let mut ledger = CompanionAffinityLedger::new(CompanionAffinityConfig {
            max_anchors: 0,
            max_candidates: 0,
            ..CompanionAffinityConfig::default()
        });
        page_load(&mut ledger, 0, "site.example", SECONDARY, &["cdn.example"]);

        assert_eq!(ledger.anchor_count(), 0);
        assert_eq!(ledger.candidate_count(), 0);
        assert!(ledger.proposals(10_000, &NoExclusions).is_empty());
    }

    #[test]
    fn proposals_per_anchor_are_capped() {
        let mut ledger = CompanionAffinityLedger::new(CompanionAffinityConfig {
            max_proposals_per_anchor: 2,
            ..CompanionAffinityConfig::default()
        });
        // Three qualifying candidates with equal affinity: the cap keeps the
        // first two in deterministic (name ascending) order.
        two_visits(&mut ledger, "site.example", &["a.one", "b.two", "c.three"]);

        let proposals = ledger.proposals(150_000, &NoExclusions);
        let values: Vec<&str> = proposals.iter().map(|p| p.proposed.value()).collect();
        assert_eq!(values, vec!["a.one", "b.two"]);
    }

    // ── Determinism and ordering ─────────────────────────────────────────────

    #[test]
    fn identical_event_streams_produce_identical_proposals() {
        let feed = |ledger: &mut CompanionAffinityLedger| {
            two_visits(ledger, "b.site", &["video.bcdn.net", "img.bcdn.net"]);
            page_load(ledger, 200_000, "a.site", PRIMARY, &["solo.cdn"]);
            page_load(
                ledger,
                300_000,
                "a.site",
                PRIMARY,
                &["solo.cdn", "late.cdn"],
            );
            page_load(ledger, 400_000, "a.site", PRIMARY, &["late.cdn"]);
        };
        let mut first = defaults();
        let mut second = defaults();
        feed(&mut first);
        feed(&mut second);

        let a = first.proposals(450_000, &NoExclusions);
        let b = second.proposals(450_000, &NoExclusions);
        assert_eq!(a, b);
        assert!(!a.is_empty());
    }

    #[test]
    fn proposals_are_ordered_by_anchor_then_affinity_then_name() {
        let mut ledger = defaults();
        // Anchor "b.site" gets two equal-affinity companions (tie broken by name).
        two_visits(&mut ledger, "b.site", &["m.host", "n.host"]);
        // Anchor "a.site": "pure.cdn" reaches affinity 1.0 (4/4); "mixed.cdn"
        // is diluted by one extra window under "b.site" (4/5 = 0.8, exactly at
        // the threshold) but its name sorts before "pure.cdn" — affinity must
        // win over name. Every candidate here qualifies through the same tier,
        // so the signal key does not participate.
        for t in [200_000, 300_000, 400_000, 500_000] {
            page_load(
                &mut ledger,
                t,
                "a.site",
                PRIMARY,
                &["pure.cdn", "mixed.cdn"],
            );
        }
        page_load(&mut ledger, 600_000, "b.site", SECONDARY, &["mixed.cdn"]);

        let proposals = ledger.proposals(650_000, &NoExclusions);
        let shape: Vec<(&str, &str)> = proposals
            .iter()
            .map(|p| (p.anchor_hostname.as_str(), p.proposed.value()))
            .collect();
        assert_eq!(
            shape,
            vec![
                ("a.site", "pure.cdn"),
                ("a.site", "mixed.cdn"),
                ("b.site", "m.host"),
                ("b.site", "n.host"),
            ]
        );
        assert!(proposals[0].affinity > proposals[1].affinity);
    }

    #[test]
    fn a_stronger_signal_outranks_a_higher_affinity() {
        let mut ledger = defaults();
        page_load(
            &mut ledger,
            0,
            "web.whatsapp.com",
            SECONDARY,
            &["helper.other", "crashlogs.whatsapp.net"],
        );
        page_load(
            &mut ledger,
            100_000,
            "web.whatsapp.com",
            SECONDARY,
            &["helper.other"],
        );
        // Dilutes the brand-related host down to affinity 0.5.
        page_load(
            &mut ledger,
            200_000,
            "b.test",
            SECONDARY,
            &["crashlogs.whatsapp.net"],
        );

        let proposals = ledger.proposals(250_000, &NoExclusions);
        let shape: Vec<(&str, CompanionSignal)> = proposals
            .iter()
            .map(|p| (p.proposed.value(), p.signal))
            .collect();
        assert_eq!(
            shape,
            vec![
                ("whatsapp.net", CompanionSignal::BrandRelated),
                ("helper.other", CompanionSignal::CoActivity),
            ]
        );
        assert!(proposals[0].affinity < proposals[1].affinity);
    }

    // ── Exclusions ───────────────────────────────────────────────────────────

    #[test]
    fn each_exclusion_predicate_suppresses_a_proposal() {
        let build = || {
            let mut ledger = defaults();
            two_visits(&mut ledger, "site.example", &["cdn.example"]);
            ledger
        };
        let cases: [fn(&mut StaticExclusions); 3] = [
            |e| {
                e.rule_hosts.insert("cdn.example".to_string());
            },
            |e| {
                e.matched_by_existing_rule.insert("cdn.example".to_string());
            },
            |e| {
                e.platform_infrastructure.insert("cdn.example".to_string());
            },
        ];
        for case in cases {
            let ledger = build();
            let mut exclusions = StaticExclusions::default();
            case(&mut exclusions);
            assert!(ledger.proposals(150_000, &exclusions).is_empty());
        }
        // Sanity: without exclusions the same evidence does propose.
        assert_eq!(build().proposals(150_000, &NoExclusions).len(), 1);
    }

    #[test]
    fn a_hostname_promoted_to_anchor_stops_being_a_candidate() {
        let mut ledger = defaults();
        two_visits(&mut ledger, "site.example", &["cdn.example"]);
        // The user adds a rule for the companion; the caller now reports it
        // as an anchor. Its candidate evidence must disappear.
        ledger.observe(
            200_000,
            "cdn.example",
            CoActivityKind::Anchor { route: SECONDARY },
        );

        assert!(!ledger.is_tracking_candidate("cdn.example"));
        assert!(ledger.proposals(250_000, &NoExclusions).is_empty());
    }

    #[test]
    fn an_active_anchor_is_never_recorded_as_a_candidate() {
        let mut ledger = defaults();
        page_load(&mut ledger, 0, "site.example", SECONDARY, &[]);
        // Defensive backstop: a mislabeled event for a live anchor is ignored.
        ledger.observe(1_000, "site.example", CoActivityKind::Candidate);

        assert!(!ledger.is_tracking_candidate("site.example"));
    }

    // ── Evidence freshness ───────────────────────────────────────────────────

    #[test]
    fn stale_evidence_is_skipped_and_revives_on_a_new_sighting() {
        let mut ledger = defaults();
        two_visits(&mut ledger, "site.example", &["cdn.example"]);
        let last_seen = 100_001;

        // At the horizon edge the proposal is still visible.
        let at_edge = last_seen + DEFAULT_EVIDENCE_TTL_MS;
        assert_eq!(ledger.proposals(at_edge, &NoExclusions).len(), 1);
        // One millisecond past the horizon it is skipped.
        assert!(ledger.proposals(at_edge + 1, &NoExclusions).is_empty());

        // A fresh sighting revives the accumulated evidence.
        page_load(
            &mut ledger,
            at_edge + 10_000,
            "site.example",
            SECONDARY,
            &["cdn.example"],
        );
        let revived = ledger.proposals(at_edge + 20_000, &NoExclusions);
        assert_eq!(revived.len(), 1);
        assert_eq!(revived[0].distinct_windows, 3);
    }
}
