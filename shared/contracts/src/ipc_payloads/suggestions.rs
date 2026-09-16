use super::*;

// ── Probing a suggestion against the main link ───────────────────────────────

/// `autorules.candidates.probe` — check the named suggestions, or every pending
/// one when `ids` is empty.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct AutoRuleCandidatesProbeRequest {
    #[serde(default)]
    pub ids: Vec<String>,
    /// Rule hosts to examine instead of pending suggestions.
    ///
    /// The same question asked of an address already in the rule set: does the
    /// main link reach it? A user looking at their rules wants to know which
    /// ones still earn their place, and the mechanism is identical — only the
    /// source of the host list differs. Empty (the default) keeps the original
    /// behaviour, so an older GUI is unaffected.
    #[serde(default)]
    pub rule_hostnames: Vec<String>,
}

/// The pass is accepted, not awaited: verdicts land through
/// `AutoRuleCandidatesChanged` once the probing thread finishes, so a slow link
/// cannot hold the GUI's request open.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct AutoRuleCandidatesProbeResponse {
    /// How many hosts the pass will examine after limits and the repeat window
    /// were applied. Zero means everything was already answered recently — the
    /// GUI says so instead of showing a spinner that resolves to nothing.
    pub accepted: u32,
    /// Hosts left out because the pass hit the caller's target limit.
    #[serde(default)]
    pub over_limit: u32,
}

// ── Sites that refuse main-link addresses ────────────────────────────────────

/// `autorules.refusing-anchor.set` — mark or unmark one site.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RefusingAnchorSetRequest {
    pub hostname: String,
    pub refusing: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RefusingAnchorSetResponse {
    /// Every site the caller has marked, after the write.
    #[serde(default)]
    pub refusing: Vec<String>,
}

// ── Local networks under the kill-switch ─────────────────────────────────────

/// Where a local network in the list came from, so the GUI can explain itself:
/// the main link's own subnet, the host side of a hypervisor adapter, or a
/// network the user named because nothing on the machine reveals it.
pub const LOCAL_NETWORK_KIND_MAIN_LINK: &str = "main-link";
pub const LOCAL_NETWORK_KIND_VIRTUAL_MACHINE: &str = "virtual-machine";
pub const LOCAL_NETWORK_KIND_MANUAL: &str = "manual";

/// One local network the kill-switch may leave reachable.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct LocalNetworkDto {
    /// Canonical `a.b.c.d/len`.
    pub cidr: String,
    /// One of the `LOCAL_NETWORK_KIND_*` slugs.
    pub kind: String,
    /// Adapter this network belongs to, by the name the interfaces list shows.
    /// Empty for a network the user named themselves.
    #[serde(default)]
    pub adapter: String,
    /// Whether it is exempt right now — the automatic answer, with the user's
    /// own decision already applied.
    pub allowed: bool,
    /// `true` when the state above comes from a stored decision rather than the
    /// automatic answer, so the GUI can offer "back to automatic".
    #[serde(default)]
    pub decided_by_user: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct LocalNetworksGetRequest {}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct LocalNetworksGetResponse {
    /// Discovered networks first (main link, then hypervisor segments), then
    /// the user's own entries; each group ordered by network.
    #[serde(default)]
    pub networks: Vec<LocalNetworkDto>,
}

/// One decision to store. `allowed` is what the user wants; `cidr` may name a
/// network the service never discovered.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct LocalNetworkDecisionDto {
    pub cidr: String,
    pub allowed: bool,
}

/// `settings.local-networks.set` — decisions to record, and decisions to
/// forget (the network returns to the automatic answer).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct LocalNetworksSetRequest {
    #[serde(default)]
    pub decisions: Vec<LocalNetworkDecisionDto>,
    #[serde(default)]
    pub forget: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct LocalNetworksSetResponse {
    /// The list as it stands after the write — same shape as the read, so the
    /// GUI never has to guess what the service made of its request.
    #[serde(default)]
    pub networks: Vec<LocalNetworkDto>,
    /// Entries the service refused, with the reason slug (`malformed-cidr`,
    /// `not-private`). Refusing one entry never fails the whole write.
    #[serde(default)]
    pub rejected: Vec<LocalNetworkRejectionDto>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct LocalNetworkRejectionDto {
    pub cidr: String,
    pub reason: String,
}

// ── Companion-domain suggestions ─────────────────────────────────────────────

/// Slug for [`AutoRuleCandidateDto::match_kind`] when the suggestion is one
/// exact hostname.
pub const AUTO_RULE_MATCH_KIND_EXACT: &str = "exact";

/// Slug for [`AutoRuleCandidateDto::match_kind`] when the suggestion covers a
/// whole domain's subdomains.
pub const AUTO_RULE_MATCH_KIND_SUFFIX: &str = "suffix";

/// [`AutoRuleCandidateDto::match_kind`]: the offer is a whole program — the
/// rule names the application, not an address.
pub const AUTO_RULE_MATCH_KIND_APPLICATION: &str = "application";

/// [`AutoRuleCandidateDto::signal`]: the host and the routed site share a brand
/// name, so the relation is visible in the name itself.
pub const AUTO_RULE_SIGNAL_BRAND_RELATED: &str = "brand-related";

/// [`AutoRuleCandidateDto::signal`]: the host is named like a delivery endpoint
/// (a CDN node) and the routed site dominates its traffic. This is the class the
/// `auto-rules-eager-delivery-names` toggle releases early, so the GUI's warning
/// about that toggle and this badge must name the same thing.
pub const AUTO_RULE_SIGNAL_DELIVERY_NAME: &str = "delivery-name";

/// [`AutoRuleCandidateDto::signal`]: neither name test applied — the host earned
/// the suggestion purely by appearing alongside the routed site.
pub const AUTO_RULE_SIGNAL_CO_ACTIVITY: &str = "co-activity";

/// Every [`AutoRuleCandidateDto::signal`] slug, for GUI allow-lists. Pinned
/// 1:1 with `CompanionSignal`; the signals a host raises about itself stay
/// outside it — see [`AUTO_RULE_SELF_SIGNED_SIGNALS`].
pub const AUTO_RULE_SIGNAL_SLUGS: &[&str] = &[
    AUTO_RULE_SIGNAL_BRAND_RELATED,
    AUTO_RULE_SIGNAL_DELIVERY_NAME,
    AUTO_RULE_SIGNAL_CO_ACTIVITY,
];

/// [`AutoRuleCandidateDto::signal`]: the main link answered this host with
/// addresses nothing can live at — a placeholder standing in for the real
/// answer. Unlike the companion signals this one is about the host itself, not
/// about the company it keeps, so it stays out of
/// [`AUTO_RULE_SIGNAL_SLUGS`].
pub const AUTO_RULE_SIGNAL_PLACEHOLDER_ANSWER: &str = "placeholder-answer";

/// [`AutoRuleCandidateDto::signal`]: connections to this host kept failing on
/// the main link while nothing about it ever completed there. Measured, not
/// inferred from an address — the one honest way to say "the main link will not
/// carry this site". Also outside [`AUTO_RULE_SIGNAL_SLUGS`].
pub const AUTO_RULE_SIGNAL_MAIN_LINK_BLOCKED: &str = "main-link-blocked";

/// [`AutoRuleCandidateDto::signal`]: a program none of whose connections
/// completed on the main link while it stalled on several unnamed addresses.
/// The offer is about the program itself.
pub const AUTO_RULE_SIGNAL_APP_MAIN_LINK_BLOCKED: &str = "app-main-link-blocked";

/// The signals where the host makes the offer about ITSELF: `anchor` is the
/// host, there is no companion arithmetic, and the question is only whether the
/// main link carries it. The GUI reads this to know it must not say "a site
/// needs this address", and the engine reads it to know the main-link verdict
/// settles the offer outright.
pub const AUTO_RULE_SELF_SIGNED_SIGNALS: &[&str] = &[
    AUTO_RULE_SIGNAL_PLACEHOLDER_ANSWER,
    AUTO_RULE_SIGNAL_MAIN_LINK_BLOCKED,
    AUTO_RULE_SIGNAL_APP_MAIN_LINK_BLOCKED,
];

/// `true` when `signal` is one of [`AUTO_RULE_SELF_SIGNED_SIGNALS`].
#[must_use]
pub fn is_self_signed_signal(signal: &str) -> bool {
    AUTO_RULE_SELF_SIGNED_SIGNALS.contains(&signal)
}

/// [`AutoRuleCandidateDto::primary_behavior`]: connections to the host went
/// through on the main route — it already works without the tunnel.
pub const AUTO_RULE_PRIMARY_BEHAVIOR_RESPONDS: &str = "responds";

/// [`AutoRuleCandidateDto::primary_behavior`]: connections to the host kept
/// stalling on the main route.
pub const AUTO_RULE_PRIMARY_BEHAVIOR_STALLS: &str = "stalls";

/// Every [`AutoRuleCandidateDto::primary_behavior`] slug, for GUI allow-lists.
/// The absent/empty value — "nothing conclusive was observed" — is deliberately
/// NOT a slug: it is the default, not a verdict.
pub const AUTO_RULE_PRIMARY_BEHAVIOR_SLUGS: &[&str] = &[
    AUTO_RULE_PRIMARY_BEHAVIOR_RESPONDS,
    AUTO_RULE_PRIMARY_BEHAVIOR_STALLS,
];

/// One site relying on a companion host — an element of
/// [`AutoRuleCandidateDto::consumers`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct AutoRuleConsumerDto {
    /// The routed hostname that pulled this host.
    pub hostname: String,
    /// Route slug the consumer's own rule lives on ([`crate::RouteRole::slug`]).
    pub route: String,
}

/// One pending suggestion: a host a routed site turned out to need, which the
/// caller's rules do not cover.
///
/// `id` is derived from the SID plus the anchor plus the proposed match, so it
/// is stable across service restarts and across proposal recomputations — the
/// tray keeps a set of already-offered ids and must not see a suggestion renamed
/// out from under it, and a persisted refusal must still match after a restart.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct AutoRuleCandidateDto {
    /// Stable id; the unit `accept` / `dismiss` act on.
    pub id: String,
    /// The routed host this candidate kept appearing alongside — the site the
    /// prompt names to the user.
    pub anchor: String,
    /// The hostname or domain the rule would match.
    pub proposed_match: String,
    /// [`AUTO_RULE_MATCH_KIND_EXACT`], [`AUTO_RULE_MATCH_KIND_SUFFIX`] or
    /// [`AUTO_RULE_MATCH_KIND_APPLICATION`].
    pub match_kind: String,
    /// Route slug the rule would be added to ([`crate::RouteRole::slug`]) —
    /// always the anchor's own route.
    pub route: String,
    /// How exclusively this host belongs to the anchor, `0.0..=1.0`. Near 1.0
    /// means it was never seen anywhere else.
    pub affinity: f64,
    /// Distinct visits the pair was observed in.
    ///
    /// `None` for an offer a host signed about ITSELF: there is no pair and
    /// there were no visits, and the count of 1 it used to carry read as
    /// "seen once" about a host whose evidence is three failed connections.
    /// The signal, not a visit count, is what such an offer knows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observations: Option<u32>,
    /// First and most recent sighting, UTC Unix milliseconds.
    pub first_seen_unix_ms: i64,
    pub last_seen_unix_ms: i64,
    /// Why this host was suggested — one of [`AUTO_RULE_SIGNAL_SLUGS`]. The
    /// user is being asked to add something to their own rules, so the answer to
    /// "how do you know?" travels with the offer rather than being inferred from
    /// the numbers.
    ///
    /// Additive on the wire: absent (and omitted when empty) for peers that
    /// predate it, so existing messages keep their exact byte shape.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub signal: String,
    /// Every site currently relying on this host, strongest evidence first —
    /// element 0 is always `anchor`. A host needed by two routed sites is one
    /// offer, not two, but the user still gets to see who else it affects,
    /// including a site on the OTHER route whose own proposal is inert (its
    /// route already gets the host by default).
    ///
    /// Additive on the wire: empty (and omitted) for peers that predate it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub consumers: Vec<AutoRuleConsumerDto>,
    /// Unix ms when a hostname not already in `consumers` last joined it.
    /// Unchanged by a recomputation that finds the same consumers — this is
    /// "when did the evidence grow", not "when was this last seen".
    ///
    /// Additive on the wire: `0` for peers that predate it.
    #[serde(default)]
    pub consumers_changed_unix_ms: i64,
    /// How the host behaves when reached over the main route — one of
    /// [`AUTO_RULE_PRIMARY_BEHAVIOR_SLUGS`], or empty when nothing conclusive
    /// was observed. The offer is "move this into the tunnel", so "it already
    /// works without one" is what most changes the answer.
    ///
    /// Additive on the wire: absent (and omitted when empty) for peers that
    /// predate it.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub primary_behavior: String,
    /// Whether the user marked this candidate's anchor as answering the main
    /// link with a refusal. Defaulted so an older service reads as "not
    /// marked"; the GUI uses it to explain why a reachable address is still
    /// worth adding.
    #[serde(default)]
    pub anchor_refuses_main_link: bool,
    /// The hostnames the evidence actually covers, ascending. Every offer is
    /// written as a suffix, so it reaches names that were never seen; this is
    /// what WAS seen, so the user confirms an offer rather than a guess.
    ///
    /// Additive on the wire: empty (and omitted) for peers that predate it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub observed_members: Vec<String>,
    /// A third party the main route already serves. The tray notice has always
    /// withheld these; the inbox showed them like any other offer, so the same
    /// host read as "your site needs this" in one surface and as "nothing to do
    /// here" in the other.
    ///
    /// Decided by the service, not re-derived by the GUI: the judgement folds
    /// the measured main-route behaviour with "is this the site's own name",
    /// and two copies of that rule would drift.
    ///
    /// Additive on the wire: `false` for peers that predate it.
    #[serde(default)]
    pub served_by_main_link: bool,
    /// The offer is a name that does NOT belong to the site that pulled it —
    /// an analytics, tag or delivery host rather than the site's own. The user
    /// asked to see the difference; it changes how much the offer is worth,
    /// not whether it is shown.
    ///
    /// `None` when the question was never posed: an offer a host makes about
    /// ITSELF has no site that pulled it, so "whose name is this" has no
    /// answer to give. A `bool` there could only answer "the site's own",
    /// which is what an ad host was being called.
    ///
    /// Additive on the wire: absent for peers that predate it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub third_party: Option<bool>,
    /// Did the ADDITIONAL route reach this host when it was checked?
    ///
    /// The offer is "move this into the tunnel", and that is worth nothing if
    /// the tunnel cannot carry it either — an outage upstream of both links
    /// looks exactly like a host worth routing. `None` means nobody has
    /// checked; only a measured `false` says the move would not help.
    ///
    /// Additive on the wire: absent for peers that predate it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secondary_reach: Option<bool>,
}

/// `autorules.candidates.list` request — no parameters; the caller's own SID
/// scopes the read. Present as a type so the op has the same
/// request/response pairing as every other operation.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct AutoRuleCandidatesListRequest {}

/// `autorules.candidates.list` response.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct AutoRuleCandidatesListResponse {
    pub candidates: Vec<AutoRuleCandidateDto>,
    /// Companions the last pass declined to offer because the site pulling them
    /// already travels the route they would be sent to. Lets the screen explain
    /// an empty list instead of looking broken.
    #[serde(default)]
    pub inert_dropped: u64,
    /// A few of those names, for a concrete "your site was among them".
    #[serde(default)]
    pub inert_sample: Vec<String>,
}

/// Request shared by `autorules.candidates.accept` and
/// `autorules.candidates.dismiss`: the ids the user answered for. Ids the
/// service no longer holds are ignored rather than rejected — the pending set
/// is in-memory and may have been re-derived between the list and the answer.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct AutoRuleCandidatesActionRequest {
    #[serde(default)]
    pub ids: Vec<String>,
}

/// Response shared by `autorules.candidates.accept` and
/// `autorules.candidates.dismiss`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct AutoRuleCandidatesActionResponse {
    /// How many of the requested ids were actually acted on.
    pub applied: u32,
    /// How many ids were not found in the caller's pending set.
    pub unknown: u32,
    /// Pending suggestions left for this caller after the action.
    pub pending: u64,
}

/// One suggestion the caller previously declined, as reviewed and possibly
/// restored on `autorules.dismissed.list`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct AutoRuleDismissedEntryDto {
    /// Same stable id `autorules.candidates.dismiss` accepted; also what
    /// `autorules.dismissed.restore` acts on.
    pub candidate_id: String,
    /// The routed host the suggestion was made alongside.
    pub anchor: String,
    /// The hostname or domain that was declined.
    pub proposed_match: String,
    /// When the refusal was recorded, or last re-affirmed.
    pub dismissed_at_unix_ms: i64,
}

/// `autorules.dismissed.list` request — no parameters; the caller's own SID
/// scopes the read.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct AutoRuleDismissedListRequest {}

/// `autorules.dismissed.list` response.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct AutoRuleDismissedListResponse {
    /// Most recently declined first — the order a review surface wants.
    pub dismissed: Vec<AutoRuleDismissedEntryDto>,
}

/// `autorules.dismissed.restore` request: candidate ids to un-decline. Ids the
/// caller never declined (or already restored) are ignored rather than
/// rejected — same tolerance as the accept/dismiss request.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct AutoRuleDismissedRestoreRequest {
    #[serde(default)]
    pub ids: Vec<String>,
}

/// `autorules.dismissed.restore` response. Restoring only lifts the
/// suppression — it does not resurrect the original offer — so, unlike
/// [`AutoRuleCandidatesActionResponse`], there is no `pending` count to report.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct AutoRuleDismissedRestoreResponse {
    /// How many of the requested ids were actually restored.
    pub restored: u32,
    /// How many ids were not found in the caller's declined set.
    pub unknown: u32,
}

// ── Block-notice mutes ───────────────────────────────────────────────────────

/// Wire form of `nrr_domain::block_notice::MuteScope`. A tagged enum rather
/// than a bare struct because `all` carries no name to check against —
/// mirrors the shape of [`crate::RuleOrigin`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "kebab-case"
)]
pub enum BlockNoticeMuteScopeDto {
    /// One destination, by the name shown to the user.
    Host { host: String },
    /// Every block from one application, by image name.
    App { app: String },
    /// Every block that happened for one reason, by `BlockReason` slug.
    Reason { reason: String },
    /// Block notices as a whole.
    All,
}

/// One active mute, as listed or just written.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct BlockNoticeMuteDto {
    pub scope: BlockNoticeMuteScopeDto,
    /// Wall-clock Unix ms after which the mute lapses; absent means
    /// indefinitely.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until_unix_ms: Option<u64>,
}

/// One notice from the caller's backlog — a block that happened while no
/// surface was subscribed to show it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct BlockNoticeJournalEntryDto {
    /// Backlog id; the largest one shown goes back in the ack.
    pub id: i64,
    /// Wall-clock Unix ms the notice was raised at.
    pub raised_at_unix_ms: i64,
    pub destination: String,
    /// Empty when the owning process could not be determined.
    pub app: String,
    /// `BlockReason` slug, same vocabulary the live push event uses.
    pub reason: String,
    pub attempts: u64,
}

/// `block-notices.journal.list` request — no parameters; the caller's own SID
/// scopes the read.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct BlockNoticeJournalListRequest {}

/// `block-notices.journal.list` response — oldest first, the order the
/// notices would have arrived in.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct BlockNoticeJournalListResponse {
    pub entries: Vec<BlockNoticeJournalEntryDto>,
}

/// `block-notices.journal.ack` request — everything up to and including
/// `through-id` has been shown.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct BlockNoticeJournalAckRequest {
    pub through_id: i64,
}

/// `block-notices.journal.ack` response.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct BlockNoticeJournalAckResponse {
    /// Backlog entries dropped by this call.
    pub acknowledged: u64,
}

/// `block-notices.mutes.list` request — no parameters; the caller's own SID
/// scopes the read.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct BlockNoticeMutesListRequest {}

/// `block-notices.mutes.list` response.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct BlockNoticeMutesListResponse {
    pub mutes: Vec<BlockNoticeMuteDto>,
}

/// `block-notices.mutes.set` request — add or refresh one mute for the
/// caller. An absent expiry means "until removed".
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct BlockNoticeMutesSetRequest {
    pub scope: BlockNoticeMuteScopeDto,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until_unix_ms: Option<u64>,
}

/// `block-notices.mutes.set` response — the caller's active mutes after the
/// write, so the tray can refresh in one round trip.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct BlockNoticeMutesSetResponse {
    pub mutes: Vec<BlockNoticeMuteDto>,
}

/// `block-notices.mutes.remove` request — undo one mute. A scope that was
/// never muted is a no-op, not an error.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct BlockNoticeMutesRemoveRequest {
    pub scope: BlockNoticeMuteScopeDto,
}

/// `block-notices.mutes.remove` response.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct BlockNoticeMutesRemoveResponse {
    /// Whether a mute actually existed at that scope.
    pub removed: bool,
    pub mutes: Vec<BlockNoticeMuteDto>,
}

/// `block-notices.mutes.clear` request — no parameters; drops every mute the
/// caller has set.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct BlockNoticeMutesClearRequest {}

/// `block-notices.mutes.clear` response.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct BlockNoticeMutesClearResponse {
    pub mutes: Vec<BlockNoticeMuteDto>,
}

// ── Block-notice-driven routing ──────────────────────────────────────────────

/// `block-notices.route-to-secondary` request — turn one blocked destination
/// into a rule that routes it over the additional link. `destination` is the
/// notice's own `destination` field (a hostname; an address with no known
/// hostname cannot be routed by a suffix rule and is refused).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct BlockNoticeRouteToSecondaryRequest {
    pub destination: String,
}

/// `block-notices.route-to-secondary` response.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct BlockNoticeRouteToSecondaryResponse {
    /// `false` when an equivalent rule already covered the host — the
    /// destination is routed either way, nothing new was written.
    pub authored: bool,
}

// ── Full-reset auxiliary-state purge ─────────────────────────────────────────

/// `principal-data.purge` request — no parameters; scopes to the caller's
/// own principal, same shape as `block-notices.mutes.clear`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct PrincipalDataPurgeRequest {
    /// Also drop the rules the SERVICE holds for this caller — revision
    /// history, the active pointer, unconsumed mutation tokens. Only a full
    /// reset asks for it; every other caller leaves the rules alone.
    #[serde(default)]
    pub include_rules_history: bool,
    /// Purge EVERY principal, not just the caller. Machine-wide, so the
    /// service refuses it without elevation. Absent = the caller alone, which
    /// is what every pre-existing peer meant.
    #[serde(default)]
    pub all_principals: bool,
}

/// `principal-data.count` request — no parameters.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct PrincipalDataCountRequest {}

/// `principal-data.count` response. A COUNT, never a list of identities: full
/// reset needs to know whether other OS users have rules here, not who they
/// are.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct PrincipalDataCountResponse {
    /// Principals other than the caller that the service holds rules for.
    pub other_principals: u32,
}

/// `principal-data.purge` response.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct PrincipalDataPurgeResponse {
    /// Total rows deleted across every purged table.
    pub rows_deleted: u64,
    /// How many of the purged tables actually held a row for this caller.
    pub tables_touched: u32,
    /// Rows deleted from the service's own rule storage; zero unless the
    /// request asked for it.
    #[serde(default)]
    pub rules_rows_deleted: u64,
    /// How many principals were purged. 1 for the ordinary caller-scoped
    /// reset; more only when `all-principals` was asked for and granted.
    #[serde(default)]
    pub principals_purged: u32,
}
