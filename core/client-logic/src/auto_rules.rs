//! Suggested addresses: the service's pending offers and the user's earlier
//! refusals merged into one list grouped by registrable domain, as the GUI's
//! suggestions screen shows them (`groupAutoRuleRows` and its filters).
//!
//! A rule of "domain + *.domain" acts on the whole group, so the answers key
//! on the group's id lists, never on a single host the user cannot see.

use std::collections::HashMap;

use nrr_shared::ipc_payloads::{
    is_self_signed_signal, AutoRuleCandidateDto, AutoRuleConsumerDto, AutoRuleDismissedEntryDto,
    AUTO_RULE_MATCH_KIND_APPLICATION, AUTO_RULE_PRIMARY_BEHAVIOR_RESPONDS,
    AUTO_RULE_PRIMARY_BEHAVIOR_STALLS, AUTO_RULE_SIGNAL_APP_MAIN_LINK_BLOCKED,
    AUTO_RULE_SIGNAL_APP_OWN_RESOLVER,
};

use crate::js;
use crate::public_suffix::{is_dotted_quad, MULTI_LABEL_SUFFIXES};

/// The registrable domain (eTLD+1) of a hostname, the key suggestions group
/// on (`registrableDomain`). An IPv4 address or a name of two labels or fewer
/// is its own group.
pub fn registrable_domain(hostname: &str) -> String {
    let lower = hostname.to_lowercase();
    let host = lower.strip_suffix('.').unwrap_or(&lower);
    if host.is_empty() || is_dotted_quad(host) {
        return host.to_owned();
    }
    let labels: Vec<&str> = host.split('.').collect();
    let n = labels.len();
    if n <= 2 {
        return host.to_owned();
    }
    let last_two = format!("{}.{}", labels[n - 2], labels[n - 1]);
    if MULTI_LABEL_SUFFIXES.contains(&last_two.as_str()) {
        return format!("{}.{last_two}", labels[n - 3]);
    }
    last_two
}

/// Whether the list shows an offer without being asked to show more
/// (`autoRuleShownByDefault`). The service decides; every surface reads its
/// one mark so none offers a row another hides.
pub fn shown_by_default(candidate: &AutoRuleCandidateDto) -> bool {
    !candidate.served_by_main_link
}

/// The offers a surface may show unasked (`autoRuleRowsShownByDefault`).
pub fn rows_shown_by_default(rows: &[AutoRuleCandidateDto]) -> Vec<&AutoRuleCandidateDto> {
    rows.iter().filter(|row| shown_by_default(row)).collect()
}

/// Does an `auto-rule-candidates-changed` push raise a notice
/// (`autoRuleNoticeDue`)? Only one that announces offers, and never over an
/// empty inbox: a push that only moves the count updates the badges.
pub fn notice_due(announces: bool, pending_count: u64) -> bool {
    announces && pending_count > 0
}

/// Is this an offer the host or program made about itself
/// (`autoRuleIsSelfSigned`)? A slug this build does not know still reads as
/// one when the row names itself as its own anchor.
pub fn is_self_signed_row(row: &AutoRuleCandidateDto) -> bool {
    is_self_signed_signal(&row.signal)
        || (!row.anchor.is_empty() && row.anchor == row.proposed_match)
}

/// What one notice over a set of offers is about, which picks its heading
/// (`autoRuleNoticeKind`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoticeKind {
    /// Addresses a routed site needs.
    Companions,
    /// Sites the main route will not carry.
    SitesBlocked,
    /// Programs the main route will not carry.
    ProgramsBlocked,
    /// Programs that look names up on their own, out of reach of site rules.
    ProgramsOwnResolver,
    /// Programs and sites that fail on the main route.
    MixedBlocked,
    /// Offers with different reasons; each row says its own.
    Assorted,
}

impl NoticeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Companions => "companions",
            Self::SitesBlocked => "sites-blocked",
            Self::ProgramsBlocked => "programs-blocked",
            Self::ProgramsOwnResolver => "programs-own-resolver",
            Self::MixedBlocked => "mixed-blocked",
            Self::Assorted => "assorted",
        }
    }
}

/// The heading a notice over `rows` takes: a claim true of every row, or one
/// that claims nothing when the rows disagree.
pub fn notice_kind(rows: &[AutoRuleCandidateDto]) -> NoticeKind {
    if rows.is_empty() {
        return NoticeKind::Companions;
    }
    let count = |signal: &str| rows.iter().filter(|r| r.signal == signal).count();
    let own = count(AUTO_RULE_SIGNAL_APP_OWN_RESOLVER);
    if own > 0 {
        return if own == rows.len() {
            NoticeKind::ProgramsOwnResolver
        } else {
            NoticeKind::Assorted
        };
    }
    let blocked = count(AUTO_RULE_SIGNAL_APP_MAIN_LINK_BLOCKED);
    if blocked > 0 {
        return if blocked == rows.len() {
            NoticeKind::ProgramsBlocked
        } else {
            NoticeKind::MixedBlocked
        };
    }
    if rows.iter().all(is_self_signed_row) {
        NoticeKind::SitesBlocked
    } else {
        NoticeKind::Companions
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostStatus {
    /// Waiting for an answer.
    Pending,
    /// Answered "don't suggest again".
    Dismissed,
}

impl HostStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Dismissed => "dismissed",
        }
    }
}

/// One offered name inside a group.
#[derive(Clone, Debug, PartialEq)]
pub struct SuggestionHost {
    pub id: String,
    pub status: HostStatus,
    /// The name the rule would match.
    pub match_value: String,
    pub match_kind: String,
    pub anchor: String,
    pub route: String,
    pub consumers: Vec<AutoRuleConsumerDto>,
    pub affinity: f64,
    pub observations: u32,
    pub signal: String,
    /// `responds`, `stalls`, or empty when nothing conclusive was seen.
    pub primary_behavior: String,
    pub anchor_refuses_main_link: bool,
    pub served_by_main_link: bool,
    /// `None` when the question was not posed (an offer a host made about itself).
    pub third_party: Option<bool>,
    pub observed_members: Vec<String>,
    pub timestamp_ms: i64,
    /// The site this offer and its anchor share across zones; empty when none.
    pub any_zone_site: String,
    /// Why the offer is less certain (`AUTO_RULE_LESS_CERTAIN_SLUGS`); empty
    /// when it rests on full evidence, and always for an answered row.
    pub less_certain: String,
}

impl SuggestionHost {
    fn shown_by_default(&self) -> bool {
        !self.served_by_main_link
    }
}

/// Every offer under one registrable domain, or one application.
#[derive(Clone, Debug, PartialEq)]
pub struct SuggestionGroup {
    pub domain: String,
    /// A program: its name is the group, it has no registrable domain.
    pub is_app: bool,
    pub hosts: Vec<SuggestionHost>,
    pub pending_ids: Vec<String>,
    pub dismissed_ids: Vec<String>,
    /// Every site relying on the group, one entry per hostname.
    pub consumers: Vec<AutoRuleConsumerDto>,
    /// The newest evidence or answer, Unix ms; 0 when none is known.
    pub latest_ms: i64,
}

/// The sites relying on a row; a peer without `consumers` names the anchor
/// alone (`autoRuleRowConsumers`).
fn row_consumers(
    consumers: &[AutoRuleConsumerDto],
    anchor: &str,
    route: &str,
) -> Vec<AutoRuleConsumerDto> {
    if !consumers.is_empty() {
        return consumers.to_vec();
    }
    if anchor.is_empty() {
        return Vec::new();
    }
    vec![AutoRuleConsumerDto {
        hostname: anchor.to_owned(),
        route: route.to_owned(),
    }]
}

/// Merges the two lists into domain groups, pending rows first, each group in
/// the order its first row arrived (`groupAutoRuleRows`).
pub fn group_rows(
    candidates: &[AutoRuleCandidateDto],
    dismissed: &[AutoRuleDismissedEntryDto],
) -> Vec<SuggestionGroup> {
    let mut groups: Vec<SuggestionGroup> = Vec::new();
    let mut index: HashMap<String, usize> = HashMap::new();
    let pending = candidates.iter().map(|row| SuggestionHost {
        id: row.id.clone(),
        status: HostStatus::Pending,
        match_value: row.proposed_match.clone(),
        match_kind: row.match_kind.clone(),
        anchor: row.anchor.clone(),
        route: row.route.clone(),
        consumers: row_consumers(&row.consumers, &row.anchor, &row.route),
        affinity: row.affinity,
        observations: row.observations.unwrap_or(0),
        signal: row.signal.clone(),
        primary_behavior: row.primary_behavior.clone(),
        anchor_refuses_main_link: row.anchor_refuses_main_link,
        served_by_main_link: !shown_by_default(row),
        third_party: row.third_party,
        observed_members: row.observed_members.clone(),
        timestamp_ms: if row.consumers_changed_unix_ms != 0 {
            row.consumers_changed_unix_ms
        } else {
            row.first_seen_unix_ms
        },
        any_zone_site: row.any_zone_site.clone(),
        less_certain: row.less_certain.clone(),
    });
    let answered = dismissed.iter().map(|row| SuggestionHost {
        id: row.candidate_id.clone(),
        status: HostStatus::Dismissed,
        match_value: row.proposed_match.clone(),
        match_kind: String::new(),
        anchor: row.anchor.clone(),
        route: String::new(),
        consumers: row_consumers(&[], &row.anchor, ""),
        affinity: 0.0,
        observations: 0,
        signal: String::new(),
        primary_behavior: String::new(),
        anchor_refuses_main_link: false,
        served_by_main_link: false,
        third_party: None,
        observed_members: Vec::new(),
        timestamp_ms: row.dismissed_at_unix_ms,
        any_zone_site: String::new(),
        less_certain: String::new(),
    });
    for host in pending.chain(answered) {
        if host.match_value.is_empty() {
            continue;
        }
        let is_app = host.match_kind == AUTO_RULE_MATCH_KIND_APPLICATION;
        let domain = if is_app {
            host.match_value.clone()
        } else {
            registrable_domain(&host.match_value)
        };
        let at = match index.get(&domain) {
            Some(&at) => at,
            None => {
                index.insert(domain.clone(), groups.len());
                groups.push(SuggestionGroup {
                    domain,
                    is_app,
                    hosts: Vec::new(),
                    pending_ids: Vec::new(),
                    dismissed_ids: Vec::new(),
                    consumers: Vec::new(),
                    latest_ms: 0,
                });
                groups.len() - 1
            }
        };
        let group = &mut groups[at];
        match host.status {
            HostStatus::Pending => group.pending_ids.push(host.id.clone()),
            HostStatus::Dismissed => group.dismissed_ids.push(host.id.clone()),
        }
        group.latest_ms = group.latest_ms.max(host.timestamp_ms);
        // A later mention of a site replaces the earlier one in its place.
        for consumer in host.consumers.iter().filter(|c| !c.hostname.is_empty()) {
            match group
                .consumers
                .iter()
                .position(|c| c.hostname == consumer.hostname)
            {
                Some(known) => group.consumers[known] = consumer.clone(),
                None => group.consumers.push(consumer.clone()),
            }
        }
        group.hosts.push(host);
    }
    groups
}

/// The site a group's pending offers can be taken as, in every zone; empty
/// when none of them names one (`autoRuleGroupAnyZoneSite`).
pub fn any_zone_site(group: &SuggestionGroup) -> &str {
    group
        .hosts
        .iter()
        .filter(|h| h.status == HostStatus::Pending)
        .map(|h| h.any_zone_site.as_str())
        .find(|site| !site.is_empty())
        .unwrap_or("")
}

/// Pending hosts a group lists after the filters (`countShownPendingAutoRuleHosts`).
pub fn count_shown_pending_hosts(group: &SuggestionGroup) -> usize {
    group
        .hosts
        .iter()
        .filter(|h| h.status == HostStatus::Pending)
        .count()
}

/// Without `show_dismissed`, only groups with something pending, and only
/// their pending hosts (`filterAutoRuleGroupsByStatus`): answered addresses
/// are history, not work.
pub fn filter_by_status(groups: &[SuggestionGroup], show_dismissed: bool) -> Vec<SuggestionGroup> {
    if show_dismissed {
        return groups.to_vec();
    }
    groups
        .iter()
        .filter(|g| !g.pending_ids.is_empty())
        .map(|g| SuggestionGroup {
            hosts: g
                .hosts
                .iter()
                .filter(|h| h.status == HostStatus::Pending)
                .cloned()
                .collect(),
            dismissed_ids: Vec::new(),
            ..g.clone()
        })
        .collect()
}

/// How many answered hosts the groups hold (`countDismissedAutoRuleHosts`).
pub fn count_dismissed_hosts(groups: &[SuggestionGroup]) -> usize {
    groups.iter().map(|g| g.dismissed_ids.len()).sum()
}

/// Without `show_served`, the hosts the main route already serves leave the
/// list and the id lists shrink with them, so a group's answer never reaches
/// a host the user cannot see (`filterAutoRuleGroupsServedByMainLink`).
pub fn filter_served_by_main_link(
    groups: &[SuggestionGroup],
    show_served: bool,
) -> Vec<SuggestionGroup> {
    if show_served {
        return groups.to_vec();
    }
    groups
        .iter()
        .filter_map(|g| {
            let hosts: Vec<SuggestionHost> = g
                .hosts
                .iter()
                .filter(|h| h.shown_by_default())
                .cloned()
                .collect();
            if hosts.is_empty() {
                return None;
            }
            let ids = |status: HostStatus| -> Vec<String> {
                hosts
                    .iter()
                    .filter(|h| h.status == status)
                    .map(|h| h.id.clone())
                    .collect()
            };
            Some(SuggestionGroup {
                pending_ids: ids(HostStatus::Pending),
                dismissed_ids: ids(HostStatus::Dismissed),
                hosts,
                ..g.clone()
            })
        })
        .collect()
}

/// How many hosts the filter above hides (`countAutoRuleHostsServedByMainLink`).
pub fn count_served_by_main_link(groups: &[SuggestionGroup]) -> usize {
    groups
        .iter()
        .flat_map(|g| &g.hosts)
        .filter(|h| !h.shown_by_default())
        .count()
}

/// Groups a site named exactly `consumer` relies on; an empty name keeps all
/// (`filterAutoRuleGroups`).
pub fn filter_by_consumer(groups: &[SuggestionGroup], consumer: &str) -> Vec<SuggestionGroup> {
    if consumer.is_empty() {
        return groups.to_vec();
    }
    groups
        .iter()
        .filter(|g| g.consumers.iter().any(|c| c.hostname == consumer))
        .cloned()
        .collect()
}

/// Groups whose domain, a host, or a site relying on them contains `query`,
/// ignoring case; an empty query keeps all (`searchAutoRuleGroups`).
pub fn search(groups: &[SuggestionGroup], query: &str) -> Vec<SuggestionGroup> {
    let q = js::trim(query).to_lowercase();
    if q.is_empty() {
        return groups.to_vec();
    }
    let hit = |text: &str| text.to_lowercase().contains(&q);
    groups
        .iter()
        .filter(|g| {
            hit(&g.domain)
                || g.hosts.iter().any(|h| hit(&h.match_value))
                || g.consumers.iter().any(|c| hit(&c.hostname))
        })
        .cloned()
        .collect()
}

/// The list's orders (`sortAutoRuleGroups`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SortMode {
    /// What the main route cannot reach first: what the user is here to fix.
    #[default]
    MainRoute,
    Newest,
    Consumers,
    Name,
}

impl SortMode {
    pub const ALL: [Self; 4] = [Self::MainRoute, Self::Newest, Self::Consumers, Self::Name];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MainRoute => "main-route",
            Self::Newest => "newest",
            Self::Consumers => "consumers",
            Self::Name => "name",
        }
    }

    /// An unknown slug sorts newest first, as the JS default branch does.
    pub fn from_slug(slug: &str) -> Self {
        Self::ALL
            .into_iter()
            .find(|m| m.as_str() == slug)
            .unwrap_or(Self::Newest)
    }

    pub fn next(self) -> Self {
        let at = Self::ALL.iter().position(|m| *m == self).unwrap_or(0);
        Self::ALL[(at + 1) % Self::ALL.len()]
    }
}

/// 0: an address stalls on the main route; 1: something is unchecked; 2: the
/// main route reaches all of them (`autoRuleGroupMainRouteRank`). Order only:
/// "reaches" does not mean "not needed".
pub fn main_route_rank(group: &SuggestionGroup) -> u8 {
    let mut rank = 2;
    for host in &group.hosts {
        if host.primary_behavior == AUTO_RULE_PRIMARY_BEHAVIOR_STALLS {
            return 0;
        }
        if host.primary_behavior != AUTO_RULE_PRIMARY_BEHAVIOR_RESPONDS {
            rank = 1;
        }
    }
    rank
}

/// Stable, as `Array.prototype.sort` is; names compare by code unit.
pub fn sort_groups(groups: &[SuggestionGroup], mode: SortMode) -> Vec<SuggestionGroup> {
    let mut out = groups.to_vec();
    out.sort_by(|a, b| {
        let newest = || b.latest_ms.cmp(&a.latest_ms);
        let name = || a.domain.cmp(&b.domain);
        match mode {
            SortMode::MainRoute => main_route_rank(a)
                .cmp(&main_route_rank(b))
                .then_with(newest)
                .then_with(name),
            SortMode::Name => name(),
            SortMode::Consumers => b.consumers.len().cmp(&a.consumers.len()).then_with(name),
            SortMode::Newest => newest().then_with(name),
        }
    });
    out
}
