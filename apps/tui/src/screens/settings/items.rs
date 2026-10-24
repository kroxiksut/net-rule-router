//! What each section lists: the settings, their values, and which change each
//! one stands for. Built from the state on every frame, so nothing is shown
//! that the state does not hold; words stay keys until the view resolves them.

use nrr_client_logic::notice_mutes::MUTABLE_NOTICE_KINDS;
use nrr_client_logic::routing_settings::{self, RoutingContext};
use nrr_client_logic::units::format_storage_bytes;
use nrr_client_logic::{route_policy, stability};
use nrr_platform_api::service_control::{ServiceRunState, ServiceStartMode};
use nrr_shared::display_text::display_text;
use nrr_shared::ipc_payloads::{BlockNoticeMuteDto, BlockNoticeMuteScopeDto, TrafficRowDto};
use serde_json::{Map, Value};

use super::text as t;
use super::{failure_text, Category, Failure, Loadable, MuteScope, RollbackOffer, ServiceInfo};
use crate::i18n::{Key, Texts};
use crate::link::admin_command;
use crate::state::AppState;
use crate::view::StateTone;

/// Text that is resolved only when drawn, in the language of the moment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Words {
    Key(Key),
    Fill(Key, Vec<(&'static str, String)>),
    /// A key whose placeholders are themselves words.
    Nested(Key, Vec<(&'static str, Words)>),
    /// A key named by a service slug, with the slug as its fallback.
    Dynamic(String),
    Raw(String),
    /// `{error}` in the key filled with the failure's words.
    Failed(Key, Failure),
    Join(Vec<Words>),
}

impl Words {
    pub fn resolve(&self, texts: &Texts) -> String {
        match self {
            Self::Key(key) => texts.get(*key),
            Self::Fill(key, values) => texts.fill(*key, values),
            Self::Nested(key, values) => {
                let resolved: Vec<(&str, String)> = values
                    .iter()
                    .map(|(name, words)| (*name, words.resolve(texts)))
                    .collect();
                texts.fill(*key, &resolved)
            }
            Self::Dynamic(id) => {
                let fallback = id.rsplit('.').next().unwrap_or(id);
                texts.dynamic(id, fallback)
            }
            Self::Raw(text) => text.clone(),
            Self::Failed(key, failure) => {
                texts.fill(*key, &[("error", failure_text(failure, texts))])
            }
            Self::Join(parts) => parts.iter().map(|p| p.resolve(texts)).collect(),
        }
    }
}

fn raw(text: impl Into<String>) -> Words {
    Words::Raw(text.into())
}

/// One option of a choice, by the slug a change sends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opt {
    pub slug: &'static str,
    pub label: Words,
}

fn opt(slug: &'static str, label: Key) -> Opt {
    Opt {
        slug,
        label: Words::Key(label),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    Heading,
    Info,
    /// The label is a state word, put into `template` at `{state}`; its
    /// colour only repeats what it says.
    State(StateTone, Key),
    Toggle(bool),
    Choice {
        options: Vec<Opt>,
        current: Option<usize>,
    },
    Number {
        value: Option<i64>,
        min: i64,
        max: i64,
    },
    Text(String),
    Action {
        confirm: bool,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogField {
    LogsAge,
    LogsSize,
    AuditAge,
    AuditSize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RevisionField {
    SupersededDays,
    SupersededCount,
    RejectedDays,
    RolledbackDays,
    RolledbackCount,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpcField {
    MaxRestarts,
    BackoffBaseMs,
    BackoffCapSecs,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrafficField {
    Enabled,
    Loopback,
    Virtual,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrefField {
    Plain,
    NoColor,
    Ascii,
}

/// Which change a row stands for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ItemId {
    None,
    /// A whole notice kind, or `block-notices` for every block notice.
    HideKind(&'static str),
    RemoveMute(usize),
    ClearMutes,
    MuteScope,
    MuteTarget,
    MuteForever,
    MuteAmount,
    MuteUnit,
    MuteAdd,
    /// A route-policy field written through the full-replacement update.
    Policy(&'static str),
    Protocol(i32),
    ShortToggle,
    ShortSuffix,
    /// One entry of the machine-wide home-network suffix list.
    LocalSuffixRemove(usize),
    /// One suffix the main link offered.
    LocalSuffixAccept(usize),
    LocalSuffixNew,
    LocalSuffixAdd,
    /// A listed local network, answered by toggling.
    LocalNetwork(usize),
    /// A network the user added, removed.
    LocalNetworkForget(usize),
    LocalNetworkNew,
    LocalNetworkAdd,
    /// The control channel's failure policy, by its `kind`.
    IpcPolicy,
    IpcNumber(IpcField),
    /// The address cache refresh, in minutes on screen.
    CacheRefresh,
    /// Shows or hides the shared addresses leak protection leaves open.
    SharedExemptionsDetails,
    /// Opens or closes the machine-wide DoH/DoT resolver list.
    DohManage,
    DohResolver(usize),
    DohResolverRemove(usize),
    DohNewTarget,
    DohNewComment,
    DohAdd,
    ProbeReset,
    /// A field of the service-stability row.
    Stability(&'static str),
    RuleLock,
    StopPersist,
    /// Applying the rules at all (the GUI's "Apply rules").
    RulesPause,
    RulesPauseTerm,
    /// A one-shot log-window request (`verbose-logging-change`, …).
    LogWindow(&'static str),
    FailurePolicy,
    ServiceStart,
    ServiceStop,
    ServiceRestart,
    ExportPath,
    ExportRun,
    /// Who wins when the bound files and the service differ on a rule.
    MergePolicy,
    SafeDisableReason,
    SafeDisableTerm,
    SafeDisableRun,
    RollbackLookup,
    RollbackRun,
    LogRetention(LogField),
    ClearLogs,
    Revisions(RevisionField),
    PinLkg,
    RevisionsReset,
    Traffic(TrafficField),
    TrafficRetention,
    TrafficReset,
    /// The answer to the history question: the same connection or not.
    TrafficMerge(bool),
    TrafficExportPath,
    TrafficExportUnit,
    TrafficExport,
    /// The caller's own connection history.
    HistoryEnabled,
    HistoryRetention,
    HistoryClear,
    Pref(PrefField),
    Reset(super::reset::ResetRow),
    Provider(super::providers::ProviderRow),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Item {
    pub id: ItemId,
    pub label: Words,
    pub kind: Kind,
    /// What the row says instead of its raw value ("Hidden until …").
    pub shown: Option<Words>,
    /// The explanation, shown under the row that has the cursor.
    pub note: Option<Words>,
}

impl Item {
    fn new(id: ItemId, label: Words, kind: Kind) -> Self {
        Self {
            id,
            label,
            kind,
            shown: None,
            note: None,
        }
    }

    fn note(mut self, note: Key) -> Self {
        self.note = Some(Words::Key(note));
        self
    }

    fn shown(mut self, shown: Words) -> Self {
        self.shown = Some(shown);
        self
    }

    pub fn selectable(&self) -> bool {
        !matches!(self.kind, Kind::Heading | Kind::Info | Kind::State(..))
    }

    /// The value as the row shows it after its label.
    pub fn value(&self) -> Option<Words> {
        if let Some(shown) = &self.shown {
            return Some(shown.clone());
        }
        match &self.kind {
            Kind::Toggle(on) => Some(Words::Key(if *on { t::ON } else { t::OFF })),
            Kind::Choice { options, current } => current
                .and_then(|i| options.get(i))
                .map(|o| o.label.clone()),
            Kind::Number { value, .. } => value.map(|v| raw(v.to_string())),
            Kind::Text(text) if text.is_empty() => Some(Words::Key(t::NOT_SET)),
            Kind::Text(text) => Some(raw(text.clone())),
            _ => None,
        }
    }
}

fn heading(key: Key) -> Item {
    Item::new(ItemId::None, Words::Key(key), Kind::Heading)
}

fn info(words: Words) -> Item {
    Item::new(ItemId::None, words, Kind::Info)
}

fn toggle(id: ItemId, label: Key, on: bool) -> Item {
    Item::new(id, Words::Key(label), Kind::Toggle(on))
}

fn choice(id: ItemId, label: Key, options: Vec<Opt>, current_slug: &str) -> Item {
    let current = options.iter().position(|o| o.slug == current_slug);
    Item::new(id, Words::Key(label), Kind::Choice { options, current })
}

fn number(id: ItemId, label: Words, value: Option<i64>, min: i64, max: i64) -> Item {
    Item::new(id, label, Kind::Number { value, min, max })
}

fn action(id: ItemId, label: Key, confirm: bool) -> Item {
    Item::new(id, Words::Key(label), Kind::Action { confirm })
}

/// What stands in for data not read yet, or not readable.
fn pending<T>(app: &AppState, data: &Loadable<T>) -> Item {
    match data {
        Loadable::Failed(failure) => info(Words::Failed(t::LOAD_FAILED, failure.clone())),
        _ if !app.link.is_connected() => info(Words::Key(t::NO_DATA)),
        _ => info(Words::Key(t::LOADING)),
    }
}

pub fn items(app: &AppState, category: Category) -> Vec<Item> {
    match category {
        Category::Notifications => notifications(app),
        Category::Routing => routing(app),
        Category::FailurePolicy => failure_policy(app),
        Category::Service => service(app),
        Category::Presets => presets(app),
        Category::Logs => logs(app),
        Category::Traffic => traffic(app),
        Category::Updates => about(app),
        Category::Terminal => terminal(app),
    }
}

// ── Notifications ────────────────────────────────────────────────────────────

/// The options of a "hide this kind" chooser, `show` first.
pub fn hide_options() -> Vec<Opt> {
    vec![
        opt("show", t::HIDE_SHOW),
        opt("1d", t::FOR_A_DAY),
        opt("7d", t::FOR_7_DAYS),
        opt("30d", t::FOR_30_DAYS),
        opt("forever", t::FOREVER),
    ]
}

/// The scope that hides `kind`: every block notice, or one notice kind.
pub fn kind_scope(kind: &str) -> BlockNoticeMuteScopeDto {
    if kind == BLOCK_NOTICES {
        BlockNoticeMuteScopeDto::All
    } else {
        BlockNoticeMuteScopeDto::Notice {
            notice: kind.to_owned(),
        }
    }
}

/// The table's row for block notices as a class.
pub const BLOCK_NOTICES: &str = "block-notices";

pub fn kind_mute<'a>(
    mutes: &'a [BlockNoticeMuteDto],
    kind: &str,
) -> Option<&'a BlockNoticeMuteDto> {
    let scope = kind_scope(kind);
    mutes.iter().find(|m| m.scope == scope)
}

/// One host, app or reason: what the kinds table does not show.
pub fn fine_mutes(mutes: &[BlockNoticeMuteDto]) -> Vec<&BlockNoticeMuteDto> {
    mutes
        .iter()
        .filter(|m| {
            matches!(
                m.scope,
                BlockNoticeMuteScopeDto::Host { .. }
                    | BlockNoticeMuteScopeDto::App { .. }
                    | BlockNoticeMuteScopeDto::Reason { .. }
            )
        })
        .collect()
}

fn until_ms(mute: &BlockNoticeMuteDto) -> Option<i64> {
    mute.until_unix_ms
        .and_then(|u| i64::try_from(u).ok())
        .filter(|u| *u > 0)
}

fn scope_words(scope: &BlockNoticeMuteScopeDto) -> Words {
    match scope {
        BlockNoticeMuteScopeDto::Host { host } => {
            let name = display_text(host).into_owned();
            Words::Fill(t::MUTE_HOST, vec![("name", name)])
        }
        BlockNoticeMuteScopeDto::App { app } => {
            let name = display_text(app).into_owned();
            Words::Fill(t::MUTE_APP, vec![("name", name)])
        }
        // The reason's own words are a key named after the slug.
        BlockNoticeMuteScopeDto::Reason { reason } => Words::Nested(
            t::MUTE_REASON,
            vec![("name", Words::Dynamic(format!("block-reason.{reason}")))],
        ),
        BlockNoticeMuteScopeDto::All | BlockNoticeMuteScopeDto::Notice { .. } => {
            Words::Key(t::MUTE_ALL)
        }
    }
}

fn notifications(app: &AppState) -> Vec<Item> {
    let s = &app.settings;
    let clock = s.clock;
    let mut v = vec![
        heading(t::HIDDEN_HEADING),
        info(Words::Key(t::HIDDEN_DESCRIPTION)),
    ];
    let mutes = match &s.data.mutes {
        Loadable::Ready(mutes) => Some(mutes.as_slice()),
        other => {
            v.push(pending(app, other));
            None
        }
    };
    if let Some(mutes) = mutes {
        let block_row = s
            .supports
            .block_notices
            .then_some((BLOCK_NOTICES, Words::Key(t::MUTE_ALL)));
        let kinds = block_row
            .into_iter()
            .chain(MUTABLE_NOTICE_KINDS.iter().map(|k| {
                (
                    k.slug,
                    Words::Key(Key {
                        id: k.title_key,
                        en: k.title_en,
                    }),
                )
            }));
        for (kind, title) in kinds {
            let state = match kind_mute(mutes, kind) {
                None => Words::Key(t::HIDDEN_SHOWN),
                Some(mute) => match until_ms(mute) {
                    None => Words::Key(t::HIDDEN_FOREVER),
                    Some(until) => {
                        Words::Fill(t::HIDDEN_UNTIL, vec![("timestamp", clock.format(until))])
                    }
                },
            };
            v.push(
                Item::new(
                    ItemId::HideKind(kind),
                    title,
                    Kind::Choice {
                        options: hide_options(),
                        current: None,
                    },
                )
                .shown(state),
            );
        }
    }

    v.push(heading(t::BLOCK_GROUP));
    if !s.supports.block_notices {
        v.push(info(Words::Key(t::UNSUPPORTED)));
        return v;
    }
    v.push(heading(t::MUTES_HEADING));
    if let Some(mutes) = mutes {
        let fine = fine_mutes(mutes);
        if fine.is_empty() {
            v.push(info(Words::Key(t::MUTES_EMPTY)));
        }
        for (index, mute) in fine.iter().enumerate() {
            let until = match until_ms(mute) {
                None => Words::Key(t::FOREVER),
                Some(until) => Words::Fill(t::MUTE_UNTIL, vec![("timestamp", clock.format(until))]),
            };
            let label = Words::Join(vec![
                Words::Key(t::DELETE),
                raw(": "),
                scope_words(&mute.scope),
                raw(" — "),
                until,
            ]);
            v.push(Item::new(
                ItemId::RemoveMute(index),
                label,
                Kind::Action { confirm: false },
            ));
        }
        if !fine.is_empty() {
            v.push(action(ItemId::ClearMutes, t::CLEAR, true));
        }
    }

    let form = &s.mute_form;
    v.push(heading(t::ADD_HEADING));
    v.push(info(Words::Key(t::ADD_DESCRIPTION)));
    v.push(choice(
        ItemId::MuteScope,
        t::SCOPE_LABEL,
        vec![
            opt("all", t::SCOPE_ALL),
            opt("host", t::SCOPE_HOST),
            opt("app", t::SCOPE_APP),
        ],
        form.scope.slug(),
    ));
    match form.scope {
        MuteScope::All => {}
        MuteScope::Host | MuteScope::App => {
            let label = if form.scope == MuteScope::Host {
                t::HOST_FIELD
            } else {
                t::APP_FIELD
            };
            v.push(Item::new(
                ItemId::MuteTarget,
                Words::Key(label),
                Kind::Text(form.target.clone()),
            ));
        }
    }
    v.push(toggle(ItemId::MuteForever, t::FOREVER, form.forever));
    if !form.forever {
        v.push(number(
            ItemId::MuteAmount,
            Words::Key(t::DURATION),
            Some(form.amount),
            1,
            999,
        ));
        v.push(choice(
            ItemId::MuteUnit,
            t::UNIT,
            vec![
                opt("minutes", t::MINUTES),
                opt("hours", t::HOURS),
                opt("days", t::DAYS),
            ],
            form.unit.slug(),
        ));
    }
    v.push(action(ItemId::MuteAdd, t::ADD, false));
    v
}

/// The machine-wide list of home and local network suffixes: every entry with
/// the rule hosts it would cover, the main link's offers, and a row to add.
/// A change needs an administrator; the service says so when it refuses.
fn local_suffixes(app: &AppState) -> Vec<Item> {
    let mut v = vec![
        heading(t::SUFFIX_TITLE),
        info(Words::Key(t::SUFFIX_DESCRIPTION)),
    ];
    let list = match &app.settings.data.local_suffixes {
        Loadable::Ready(list) => list,
        other => {
            v.push(pending(app, other));
            return v;
        }
    };
    if list.suffixes.is_empty() {
        v.push(info(Words::Key(t::SUFFIX_EMPTY)));
    }
    for (index, entry) in list.suffixes.iter().enumerate() {
        let mut label = vec![raw(entry.suffix.clone())];
        if !entry.covers_rule_hosts.is_empty() {
            label.push(raw("  "));
            label.push(Words::Fill(
                t::SUFFIX_COVERS,
                vec![("hosts", entry.covers_rule_hosts.join(", "))],
            ));
        }
        v.push(Item::new(
            ItemId::LocalSuffixRemove(index),
            Words::Join(label),
            Kind::Action { confirm: true },
        ));
    }
    for (index, offer) in list.offered.iter().enumerate() {
        v.push(Item::new(
            ItemId::LocalSuffixAccept(index),
            Words::Fill(
                t::SUFFIX_OFFERED,
                vec![
                    ("suffix", offer.suffix.clone()),
                    ("link", offer.link.clone()),
                ],
            ),
            Kind::Action { confirm: false },
        ));
    }
    v.push(Item::new(
        ItemId::LocalSuffixNew,
        Words::Key(t::SUFFIX_FIELD),
        Kind::Text(app.settings.local_suffix_new.clone()),
    ));
    v.push(action(ItemId::LocalSuffixAdd, t::ADD, false));
    v
}

/// The shared list the DoH/DoT block cuts, opened on demand as in the window:
/// a row per entry to stop blocking it or remove it, and fields to add one.
fn doh_resolvers(app: &AppState) -> Vec<Item> {
    let s = &app.settings;
    let mut v = vec![action(
        ItemId::DohManage,
        if s.doh_open {
            t::DOH_HIDE
        } else {
            t::DOH_MANAGE
        },
        false,
    )];
    if !s.doh_open {
        return v;
    }
    v.push(info(Words::Key(t::DOH_DESCRIPTION)));
    v.push(info(Words::Key(t::DOH_REQUIRES_ADMIN)));
    let list = match &s.data.doh_resolvers {
        Loadable::Ready(list) => list,
        other => {
            v.push(pending(app, other));
            return v;
        }
    };
    if list.resolvers.is_empty() {
        v.push(info(Words::Key(t::DOH_EMPTY)));
    }
    for (index, entry) in list.resolvers.iter().enumerate() {
        let kind = if entry.target_kind == "ip" {
            t::DOH_KIND_IP
        } else {
            t::DOH_KIND_HOST
        };
        let target = display_text(&entry.target).into_owned();
        let mut label = vec![raw(target.clone()), raw("  "), Words::Key(kind)];
        if !entry.comment.is_empty() {
            label.push(raw(format!("  {}", display_text(&entry.comment))));
        }
        v.push(Item::new(
            ItemId::DohResolver(index),
            Words::Join(label),
            Kind::Toggle(entry.enabled),
        ));
        v.push(Item::new(
            ItemId::DohResolverRemove(index),
            Words::Join(vec![Words::Key(t::DELETE), raw(" "), raw(target)]),
            Kind::Action { confirm: true },
        ));
    }
    v.push(Item::new(
        ItemId::DohNewTarget,
        Words::Key(t::DOH_ADD_TARGET),
        Kind::Text(s.doh_new_target.clone()),
    ));
    v.push(Item::new(
        ItemId::DohNewComment,
        Words::Key(t::DOH_ADD_COMMENT),
        Kind::Text(s.doh_new_comment.clone()),
    ));
    v.push(action(ItemId::DohAdd, t::ADD, false));
    v
}

/// The local networks leak protection may leave reachable, as the window lists
/// them: an answer per row, a reason where no answer opens one.
fn local_networks(app: &AppState) -> Vec<Item> {
    let mut v = Vec::new();
    let list = match &app.settings.data.local_networks {
        Loadable::Ready(list) => list,
        other => {
            v.push(pending(app, other));
            return v;
        }
    };
    if list.networks.is_empty() {
        v.push(info(Words::Key(t::LOCAL_EMPTY)));
    }
    for (index, network) in list.networks.iter().enumerate() {
        let adapter = display_text(&network.adapter).into_owned();
        let origin = match network.kind.as_str() {
            "manual" => Words::Key(t::LOCAL_KIND_MANUAL),
            "main-link" => Words::Fill(t::LOCAL_KIND_MAIN, vec![("name", adapter)]),
            _ => Words::Fill(t::LOCAL_KIND_VM, vec![("name", adapter)]),
        };
        let mut label = vec![raw(network.cidr.clone()), raw("  "), origin];
        let reason = match network.reason.as_str() {
            "too-wide" => Some(t::LOCAL_TOO_WIDE),
            "contains-rule-address" => Some(t::LOCAL_NAMES_RULE),
            _ => None,
        };
        if let Some(reason) = reason {
            label.push(raw(" — "));
            label.push(Words::Key(reason));
            v.push(info(Words::Join(label)));
            continue;
        }
        if !network.decided_by_user {
            label.push(raw("  "));
            label.push(Words::Key(t::LOCAL_UNDECIDED));
        }
        v.push(Item::new(
            ItemId::LocalNetwork(index),
            Words::Join(label),
            Kind::Toggle(network.allowed),
        ));
        if network.kind == "manual" {
            v.push(Item::new(
                ItemId::LocalNetworkForget(index),
                Words::Join(vec![
                    Words::Key(t::DELETE),
                    raw(" "),
                    raw(network.cidr.clone()),
                ]),
                Kind::Action { confirm: true },
            ));
        }
    }
    v.push(Item::new(
        ItemId::LocalNetworkNew,
        Words::Key(t::LOCAL_FIELD),
        Kind::Text(app.settings.local_network_new.clone()),
    ));
    v.push(action(ItemId::LocalNetworkAdd, t::ADD, false));
    v
}

// ── Routing behaviour ────────────────────────────────────────────────────────

/// The leak-protection protocol boxes, in the GUI's order.
pub const PROTOCOLS: [(i32, Key); 6] = [
    (1, t::PROTOCOL_TCP),
    (2, t::PROTOCOL_UDP),
    (4, t::PROTOCOL_ICMP),
    (8, t::PROTOCOL_IGMP),
    (16, t::PROTOCOL_GRE),
    (32, t::PROTOCOL_ESP),
];

/// The leak-protection level as the policy's default route offers it.
pub fn leak_protection(policy: &Map<String, Value>) -> &'static str {
    route_policy::coerce_leak_protection(
        &policy_text(policy, "mode"),
        &policy_text(policy, route_policy::LEAK_PROTECTION_KEY),
    )
}

/// The levels `mode` offers, as choice options.
pub fn leak_protection_options(mode: &str) -> Vec<Opt> {
    route_policy::leak_protection_choices(mode)
        .into_iter()
        .map(|level| opt(level, leak_protection_label(level)))
        .collect()
}

pub fn leak_protection_label(level: &str) -> Key {
    match level {
        "sites" => t::LEAK_SITES,
        "everything" => t::LEAK_EVERYTHING,
        _ => t::LEAK_OFF,
    }
}

fn leak_protection_note(level: &str) -> Key {
    match level {
        "sites" => t::LEAK_SITES_NOTE,
        "everything" => t::LEAK_EVERYTHING_NOTE,
        _ => t::LEAK_OFF_NOTE,
    }
}

pub fn policy_bool(policy: &Map<String, Value>, key: &str) -> bool {
    route_policy::effective(policy, key) == Some(Value::Bool(true))
}

pub fn policy_text(policy: &Map<String, Value>, key: &str) -> String {
    route_policy::effective(policy, key)
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

pub fn policy_int(policy: &Map<String, Value>, key: &str) -> Option<i64> {
    route_policy::effective(policy, key).and_then(|v| v.as_i64())
}

pub fn stability_bool(config: &Map<String, Value>, key: &str) -> bool {
    stability::effective(config, key) == Some(Value::Bool(true))
}

pub fn stability_text(config: &Map<String, Value>, key: &str) -> String {
    stability::effective(config, key)
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

/// The administrator's rules lock: an absent value is "users may edit".
pub fn rule_edits_allowed(config: &Map<String, Value>) -> bool {
    config.get("allow-user-rule-edits") != Some(&Value::Bool(false))
}

fn policy_toggle(policy: &Map<String, Value>, key: &'static str, label: Key) -> Item {
    toggle(ItemId::Policy(key), label, policy_bool(policy, key))
}

fn stability_toggle(config: &Map<String, Value>, key: &'static str, label: Key) -> Item {
    toggle(ItemId::Stability(key), label, stability_bool(config, key))
}

/// The GUI's "Safe rollback": ask what would be restored, and only then offer it.
fn rollback_rows(app: &AppState) -> Vec<Item> {
    let mut rows = vec![
        heading(t::ROLLBACK_TITLE),
        action(ItemId::RollbackLookup, t::ROLLBACK_LOOKUP, false),
    ];
    match &app.settings.rollback {
        RollbackOffer::Unasked => {}
        RollbackOffer::Nothing => rows.push(info(Words::Key(t::ROLLBACK_NONE))),
        RollbackOffer::Ready { target, .. } => {
            let at = target.activated_at.unwrap_or(0).saturating_mul(1000);
            rows.push(info(Words::Fill(
                t::ROLLBACK_READY,
                vec![
                    ("time", app.settings.clock.format(at)),
                    ("count", target.rule_count.to_string()),
                ],
            )));
            rows.push(action(ItemId::RollbackRun, t::ROLLBACK_RUN, true));
        }
    }
    rows
}

fn routing(app: &AppState) -> Vec<Item> {
    let s = &app.settings;
    let policy = match &s.data.policy {
        Loadable::Ready(policy) => policy,
        other => return vec![pending(app, other)],
    };
    let stability_row = match &s.data.stability {
        Loadable::Ready(config) => Ok(config),
        other => Err(other),
    };
    let paused = app.routing_state() == crate::state::RoutingState::Paused;
    let mut v = vec![
        heading(t::RULES_PAUSE_TITLE),
        toggle(ItemId::RulesPause, t::RULES_PAUSE_TITLE, !paused),
        info(Words::Key(t::RULES_PAUSE_HINT)),
    ];
    if !paused {
        v.push(choice(
            ItemId::RulesPauseTerm,
            t::SAFE_DISABLE_TERM,
            safe_disable_term_options(),
            s.pause_term,
        ));
    }
    v.extend(rollback_rows(app));
    let mode = policy_text(policy, "mode");
    v.extend([
        heading(t::DEFAULT_ROUTE),
        choice(
            ItemId::Policy("mode"),
            t::DEFAULT_ROUTE,
            vec![
                opt("prefer-primary", t::MODE_PREFER_PRIMARY),
                opt("prefer-secondary-when-available", t::MODE_PREFER_SECONDARY),
            ],
            &mode,
        )
        .note(t::DEFAULT_ROUTE_NOTE),
        policy_toggle(policy, "include-subdomains", t::SUBDOMAINS).note(t::SUBDOMAINS_NOTE),
        policy_toggle(policy, "app-rules-take-all-addresses", t::APP_TAKEOVER)
            .note(t::APP_TAKEOVER_NOTE),
        heading(t::LEAK_TITLE),
    ]);
    let level = leak_protection(policy);
    if s.supports.kill_switch {
        v.push(
            choice(
                ItemId::Policy(route_policy::LEAK_PROTECTION_KEY),
                t::LEAK_TITLE,
                leak_protection_options(&mode),
                level,
            )
            .note(leak_protection_note(level)),
        );
    } else {
        v.push(info(Words::Key(t::UNSUPPORTED)));
    }
    v.extend(routing_refinements(app, policy, stability_row, level));

    v.push(heading(t::DOH_TITLE));
    v.push(policy_toggle(policy, "doh-lockdown-auto", t::DOH_AUTO).note(t::DOH_AUTO_NOTE));
    if policy_bool(policy, "doh-lockdown-auto") {
        // What the service decided, read back rather than guessed.
        v.push(info(Words::Key(
            if policy_bool(policy, "doh-lockdown-effective") {
                t::DOH_AUTO_ON
            } else {
                t::DOH_AUTO_OFF
            },
        )));
    } else {
        v.push(policy_toggle(policy, "doh-lockdown-enabled", t::DOH_ENABLE));
        if policy_bool(policy, "doh-lockdown-enabled") {
            v.push(choice(
                ItemId::Policy("doh-lockdown-scope"),
                t::DOH_SCOPE,
                vec![
                    opt("leak-protection-only", t::DOH_LEAK_ONLY),
                    opt("always", t::DOH_ALWAYS),
                ],
                &policy_text(policy, "doh-lockdown-scope"),
            ));
        }
    }
    v.extend(doh_resolvers(app));
    v.push(
        policy_toggle(policy, "browser-history-auto-seed", t::AUTO_SEED).note(t::AUTO_SEED_NOTE),
    );
    v.extend(local_suffixes(app));
    v.push(heading(t::HOSTS_TITLE));
    v.push(policy_toggle(
        policy,
        "resolve-hosts-bypass",
        t::HOSTS_BYPASS,
    ));
    // Read only: the program never edits it, the user may.
    if !s.hosts_file_path.is_empty() {
        v.push(info(Words::Join(vec![
            Words::Key(t::HOSTS_FILE),
            raw(": "),
            raw(s.hosts_file_path.clone()),
        ])));
        v.push(info(Words::Key(t::HOSTS_FILE_NOTE)));
    }
    let offered = offered_routing_settings(app, stability_row.ok(), level);
    if offered.contains(&routing_settings::LOCAL_NETWORKS) {
        v.push(heading(t::LOCAL_TITLE));
        v.push(policy_toggle(
            policy,
            "local-networks-auto-accept",
            t::LOCAL_AUTO,
        ));
        v.extend(local_networks(app));
    }
    if s.supports.forwarded_traffic_guard {
        let answer = policy_text(policy, "forwarded-outage");
        v.push(heading(t::FWD_TITLE));
        let row = choice(
            ItemId::Policy("forwarded-outage"),
            t::FWD_CHOICE,
            vec![
                opt("as-computer", t::FWD_AS_COMPUTER),
                opt("unprotected", t::FWD_UNPROTECTED),
            ],
            &answer,
        )
        .note(t::FWD_NOTE);
        v.push(if answer.is_empty() {
            row.shown(Words::Key(t::FWD_UNANSWERED))
        } else {
            row
        });
    }
    v.extend(provider_rows(policy, &s.providers));
    v.extend(gateway_rows(app));
    v.push(
        policy_toggle(policy, "external-address-auto-check", t::EXTERNAL_CHECK)
            .note(t::EXTERNAL_CHECK_NOTE),
    );
    v.push(heading(t::SHORT_TITLE));
    v.push(
        toggle(
            ItemId::ShortToggle,
            t::SHORT_ENABLE,
            policy_bool(policy, "short-name-completion"),
        )
        .note(t::SHORT_NOTE),
    );
    v.push(Item::new(
        ItemId::ShortSuffix,
        Words::Key(t::SHORT_FIELD),
        Kind::Text(policy_text(policy, "short-name-suffix")),
    ));
    v.push(heading(t::AUTO_TITLE));
    v.push(policy_toggle(policy, "primary-probe-auto", t::PROBE_AUTO));
    for (key, label, min, max) in PROBE_LIMITS {
        v.push(number(
            ItemId::Policy(key),
            Words::Key(label),
            policy_int(policy, key),
            min,
            max,
        ));
    }
    v.push(action(ItemId::ProbeReset, t::PROBE_RESET, false));
    let auto_mode = policy_text(policy, "auto-rules-mode");
    v.push(choice(
        ItemId::Policy("auto-rules-mode"),
        t::AUTO_MODE,
        vec![
            opt("off", t::AUTO_OFF),
            opt("suggest", t::AUTO_SUGGEST),
            opt("auto", t::AUTO_AUTO),
        ],
        &auto_mode,
    ));
    if auto_mode != "off" {
        v.push(policy_toggle(
            policy,
            "auto-rules-eager-delivery-names",
            t::AUTO_EAGER,
        ));
    }
    if s.supports.service_stability_config {
        v.push(heading(t::SYSTEM_TITLE));
        match stability_row {
            Ok(config) => {
                v.push(
                    toggle(ItemId::RuleLock, t::RULE_LOCK, rule_edits_allowed(config))
                        .note(t::RULE_LOCK_NOTE),
                );
                v.push(stability_toggle(
                    config,
                    "rule-scope-service-driven",
                    t::SERVICE_DRIVEN,
                ));
                v.push(toggle(
                    ItemId::StopPersist,
                    t::STOP_PERSIST,
                    stability_text(config, "routing-stop-policy") == "persist",
                ));
            }
            Err(other) => v.push(pending(app, other)),
        }
    }
    v
}

/// Whether an additional connection is bound, as the snapshot names it.
fn secondary_bound(app: &AppState) -> bool {
    app.snapshot
        .as_ref()
        .and_then(|snapshot| snapshot.route_policy.as_ref())
        .is_some_and(|policy| policy.secondary.is_some())
}

/// The routing settings the window offers for these readings, in its order.
pub fn offered_routing_settings(
    app: &AppState,
    stability_row: Option<&Map<String, Value>>,
    level: &str,
) -> Vec<&'static str> {
    let supports = app.settings.supports_map();
    let mode = stability_row.map(|c| stability_text(c, "enforcement-mode"));
    routing_settings::offered(&RoutingContext {
        supports: Some(&supports),
        enforcement_mode: mode.as_deref().unwrap_or(""),
        leak_protection: level,
        secondary_bound: secondary_bound(app),
        fake_ip_enabled: stability_row.is_some_and(|c| stability_bool(c, "fake-ip-enabled")),
    })
}

/// The leak-protection refinements under the level, then the routing ones,
/// exactly the rows `routing_settings::offered` names.
fn routing_refinements(
    app: &AppState,
    policy: &Map<String, Value>,
    stability_row: Result<&Map<String, Value>, &Loadable<Map<String, Value>>>,
    level: &str,
) -> Vec<Item> {
    let config = stability_row.ok();
    let mut v = Vec::new();
    let mut titled = false;
    let mut waiting = false;
    for row in offered_routing_settings(app, config, level) {
        // Listed further down, with the networks themselves.
        if row == routing_settings::LOCAL_NETWORKS {
            continue;
        }
        let leak_row = matches!(
            row,
            route_policy::KILL_SWITCH_PROTOCOLS_KEY | routing_settings::ALLOW_DNS_OVER_PRIMARY
        );
        if !leak_row && !titled {
            titled = true;
            v.push(heading(t::ROUTING_METHOD));
        }
        let item = match row {
            route_policy::KILL_SWITCH_PROTOCOLS_KEY => {
                v.push(heading(t::PROTOCOLS));
                let mask = policy_int(policy, row).unwrap_or(0);
                v.extend(PROTOCOLS.into_iter().map(|(bit, label)| {
                    toggle(ItemId::Protocol(bit), label, mask & i64::from(bit) != 0)
                }));
                continue;
            }
            routing_settings::ALLOW_DNS_OVER_PRIMARY => {
                policy_toggle(policy, row, t::ALLOW_DNS).note(t::ALLOW_DNS_NOTE)
            }
            routing_settings::SHARED_IP_POLICY => choice(
                ItemId::Policy(row),
                t::SHARED_IP,
                vec![
                    opt("majority-of-ip", t::SHARED_MAJORITY_IP),
                    opt("majority-of-rules", t::SHARED_MAJORITY_RULES),
                    opt("any-rule-domain", t::SHARED_ANY),
                ],
                &policy_text(policy, row),
            )
            .note(t::SHARED_IP_NOTE),
            routing_settings::STRICT_SHARED_IPS => {
                v.push(policy_toggle(policy, row, t::SHARED_STRICT).note(t::SHARED_STRICT_NOTE));
                if !policy_bool(policy, row) {
                    v.extend(shared_exemptions(app));
                }
                continue;
            }
            routing_settings::STABILITY_UNAVAILABLE => info(Words::Key(t::UNSUPPORTED)),
            _ => {
                // Every other row is a field of the stability row.
                let Some(config) = config else {
                    if !waiting {
                        waiting = true;
                        if let Err(other) = stability_row {
                            v.push(pending(app, other));
                        }
                    }
                    continue;
                };
                match stability_item(config, row) {
                    Some(item) => item,
                    None => continue,
                }
            }
        };
        v.push(item);
    }
    v
}

/// The shared addresses leak protection left open in its smart mode, as
/// the window says it: the count, then the addresses on demand.
fn shared_exemptions(app: &AppState) -> Vec<Item> {
    let Some(snapshot) = app.snapshot.as_ref().filter(|_| app.link.is_connected()) else {
        return Vec::new();
    };
    let count = snapshot.kill_switch_shared_ip_exemptions;
    if count == 0 {
        return Vec::new();
    }
    let open = app.settings.shared_exemptions_open;
    let mut v = vec![
        info(Words::Join(vec![
            Words::Key(t::SHARED_SMART_WARNING),
            raw(count.to_string()),
        ])),
        action(
            ItemId::SharedExemptionsDetails,
            if open {
                t::HIDE_DETAILS
            } else {
                t::SHOW_DETAILS
            },
            false,
        ),
    ];
    if !open {
        return v;
    }
    let addresses = &snapshot.kill_switch_shared_ip_exemption_addresses;
    if addresses.is_empty() {
        v.push(info(Words::Key(t::SHARED_SMART_UNAVAILABLE)));
        return v;
    }
    v.push(info(Words::Key(t::SHARED_SMART_LIST)));
    v.extend(
        addresses
            .iter()
            .map(|address| info(raw(format!("  {}", display_text(address))))),
    );
    v
}

/// The window's control-channel and cache rows of the stability config.
fn service_stability(config: &Map<String, Value>) -> Vec<Item> {
    let policy = config.get("ipc-accept-policy").and_then(Value::as_object);
    let critical = policy.and_then(|p| p.get("kind")).and_then(Value::as_str) == Some("critical");
    let int = |key: &str| policy.and_then(|p| p.get(key)).and_then(Value::as_i64);
    let mut v = vec![
        heading(t::STABILITY_TITLE),
        info(Words::Key(t::STABILITY_HELP)),
        stability_toggle(config, "conn-trace-gui", t::TRACE_GUI).note(t::TRACE_GUI_NOTE),
        choice(
            ItemId::IpcPolicy,
            t::IPC_POLICY,
            vec![
                opt("recoverable", t::IPC_RECOVERABLE),
                opt("critical", t::IPC_CRITICAL),
            ],
            if critical { "critical" } else { "recoverable" },
        )
        .note(if critical {
            t::IPC_CRITICAL_NOTE
        } else {
            t::IPC_RECOVERABLE_NOTE
        }),
    ];
    if !critical {
        v.push(number(
            ItemId::IpcNumber(IpcField::MaxRestarts),
            Words::Key(t::IPC_MAX_RESTARTS),
            int("max-restarts"),
            1,
            100,
        ));
        v.push(number(
            ItemId::IpcNumber(IpcField::BackoffBaseMs),
            Words::Key(t::IPC_BACKOFF_BASE),
            int("backoff-base-ms"),
            50,
            5000,
        ));
        v.push(number(
            ItemId::IpcNumber(IpcField::BackoffCapSecs),
            Words::Key(t::IPC_BACKOFF_CAP),
            int("backoff-cap-ms").map(|ms| (ms + 999) / 1000),
            1,
            60,
        ));
    }
    let minutes = config
        .get("cache-refresh-interval-secs")
        .and_then(Value::as_i64)
        .map(|secs| (secs / 60).clamp(1, 1440));
    v.push(heading(t::CACHE_REFRESH_TITLE));
    v.push(
        number(
            ItemId::CacheRefresh,
            Words::Join(vec![
                Words::Key(t::CACHE_REFRESH),
                raw(", "),
                Words::Key(t::CACHE_REFRESH_UNIT),
            ]),
            minutes,
            1,
            1440,
        )
        .note(t::CACHE_REFRESH_NOTE),
    );
    v
}

fn stability_item(config: &Map<String, Value>, row: &'static str) -> Option<Item> {
    Some(match row {
        routing_settings::ENFORCEMENT_MODE => {
            let mode = stability_text(config, row);
            // The legacy mode is a GUI opt-in; held, it is named, not offered.
            let item = choice(
                ItemId::Stability(row),
                t::ENFORCEMENT,
                vec![opt("resolver", t::ENFORCEMENT_RESOLVER)],
                &mode,
            )
            .note(t::ENFORCEMENT_NOTE);
            if mode == "reactive" {
                item.shown(Words::Key(t::ENFORCEMENT_REACTIVE))
            } else {
                item
            }
        }
        routing_settings::DNS_VIA_SECONDARY => {
            stability_toggle(config, row, t::DNS_VIA_SECONDARY).note(t::DNS_VIA_SECONDARY_NOTE)
        }
        routing_settings::DNS_FAST_ANSWERS => {
            stability_toggle(config, row, t::DNS_FAST).note(t::DNS_FAST_NOTE)
        }
        routing_settings::FAKE_IP_ENABLED => stability_toggle(config, row, t::FAKE_IP),
        // Named and explained, as the GUI does, rather than offered.
        routing_settings::FAKE_IP_UNAVAILABLE => info(Words::Join(vec![
            Words::Key(t::FAKE_IP),
            raw(": "),
            Words::Key(t::UNSUPPORTED),
        ])),
        routing_settings::FAKE_IP_UDP_RELAY => stability_toggle(config, row, t::FAKE_IP_UDP),
        routing_settings::FAKE_IP_INSTANT_RST => stability_toggle(config, row, t::FAKE_IP_RST),
        routing_settings::LIVENESS_WINDOW => {
            let secs = stability::effective(config, row).and_then(|v| v.as_i64());
            let mut item = number(
                ItemId::Stability(row),
                Words::Key(t::LIVENESS),
                secs,
                0,
                3600,
            );
            item.note = Some(Words::Join(vec![
                Words::Key(t::LIVENESS_NOTE),
                raw(" "),
                Words::Key(t::LIVENESS_RANGE),
            ]));
            item.shown = Some(match secs {
                Some(0) | None => Words::Key(t::LIVENESS_DISABLED),
                Some(n) => Words::Join(vec![raw(format!("{n} ")), Words::Key(t::SECONDS)]),
            });
            item
        }
        _ => return None,
    })
}

/// The main-route check limits: key, label and the GUI's bounds.
pub const PROBE_LIMITS: [(&str, Key, i64, i64); 3] = [
    ("primary-probe-timeout-ms", t::PROBE_TIMEOUT, 300, 5000),
    ("primary-probe-max-targets", t::PROBE_TARGETS, 1, 32),
    ("primary-probe-repeat-secs", t::PROBE_REPEAT, 30, 86400),
];

// ── Apply failure policy ─────────────────────────────────────────────────────

/// The service's closed list of terms, in the order the GUI offers them.
pub fn safe_disable_term_options() -> Vec<Opt> {
    vec![
        opt("fifteen-minutes", t::SAFE_DISABLE_TERM_15M),
        opt("one-hour", t::SAFE_DISABLE_TERM_1H),
        opt("four-hours", t::SAFE_DISABLE_TERM_4H),
        opt("until-restart", t::SAFE_DISABLE_TERM_RESTART),
        opt("until-resumed", t::SAFE_DISABLE_TERM_RESUMED),
    ]
}

pub fn failure_policy_options() -> Vec<Opt> {
    vec![
        opt("best-effort", t::POLICY_BEST_EFFORT),
        opt("all-or-nothing", t::POLICY_ALL),
        opt("pre-flight-then-all-or-nothing", t::POLICY_PREFLIGHT),
    ]
}

fn failure_policy(app: &AppState) -> Vec<Item> {
    let mut v = vec![info(Words::Key(t::POLICY_DESCRIPTION))];
    match &app.settings.data.failure_policy {
        Loadable::Ready(slug) => {
            let note = match slug.as_str() {
                "all-or-nothing" => t::POLICY_ALL_NOTE,
                "pre-flight-then-all-or-nothing" => t::POLICY_PREFLIGHT_NOTE,
                _ => t::POLICY_BEST_EFFORT_NOTE,
            };
            v.push(
                choice(
                    ItemId::FailurePolicy,
                    t::FAILURE_POLICY,
                    failure_policy_options(),
                    slug,
                )
                .note(note),
            );
        }
        other => v.push(pending(app, other)),
    }
    v.push(info(Words::Key(t::POLICY_ELEVATION)));
    v
}

// ── Service management ───────────────────────────────────────────────────────

pub fn run_state_word(state: ServiceRunState) -> (Key, StateTone) {
    match state {
        ServiceRunState::Running => (t::RUN_RUNNING, StateTone::Good),
        ServiceRunState::Stopped => (t::RUN_STOPPED, StateTone::Bad),
        ServiceRunState::StartPending => (t::RUN_STARTING, StateTone::Caution),
        ServiceRunState::StopPending => (t::RUN_STOPPING, StateTone::Caution),
        ServiceRunState::Other => (t::RUN_UNKNOWN, StateTone::Caution),
    }
}

fn state_line(word: Key, tone: StateTone) -> Item {
    Item::new(
        ItemId::None,
        Words::Key(word),
        Kind::State(tone, t::SERVICE_STATE),
    )
}

fn service(app: &AppState) -> Vec<Item> {
    let mut v = vec![info(Words::Key(t::SERVICE_NOTE))];
    match &app.settings.data.service {
        Loadable::Ready(ServiceInfo::NoManager) => v.push(info(Words::Key(t::SERVICE_NO_MANAGER))),
        Loadable::Ready(ServiceInfo::NotInstalled) => {
            v.push(state_line(t::RUN_NOT_INSTALLED, StateTone::Bad));
            v.push(info(Words::Fill(
                crate::keys::FIX_INSTALL,
                vec![("command", admin_command("install"))],
            )));
        }
        Loadable::Ready(ServiceInfo::Registered(report)) => {
            let (word, tone) = run_state_word(report.run_state);
            v.push(state_line(word, tone));
            if let Some(mode) = report.start_mode {
                let mode = match mode {
                    ServiceStartMode::WithWindows => t::MODE_WITH_SYSTEM,
                    ServiceStartMode::OnAppLaunch => t::MODE_ON_LAUNCH,
                };
                v.push(info(Words::Nested(
                    t::SERVICE_START_MODE,
                    vec![("mode", Words::Key(mode))],
                )));
            }
            match report.run_state {
                ServiceRunState::Stopped => {
                    v.push(action(ItemId::ServiceStart, t::SERVICE_START, false))
                }
                ServiceRunState::Running => {
                    v.push(action(ItemId::ServiceStop, t::SERVICE_STOP, true));
                    v.push(action(ItemId::ServiceRestart, t::SERVICE_RESTART, true));
                }
                _ => {}
            }
            v.push(info(Words::Fill(
                t::SERVICE_FIX_UNINSTALL,
                vec![("command", admin_command("uninstall"))],
            )));
            v.push(info(Words::Fill(
                t::SERVICE_FIX_REINSTALL,
                vec![("command", admin_command("reinstall"))],
            )));
            if let Some(mode) = report.start_mode {
                let other = match mode {
                    ServiceStartMode::WithWindows => "--start-mode=on-demand",
                    ServiceStartMode::OnAppLaunch => "--start-mode=auto",
                };
                v.push(info(Words::Fill(
                    t::SERVICE_FIX_MODE,
                    vec![
                        ("uninstall", admin_command("uninstall")),
                        ("install", admin_command(&format!("install {other}"))),
                    ],
                )));
            }
            if report.run_state == ServiceRunState::Running {
                v.push(info(Words::Key(t::SAFE_DISABLE_NOTE)));
                v.push(Item::new(
                    ItemId::SafeDisableReason,
                    Words::Key(t::SAFE_DISABLE_REASON),
                    Kind::Text(app.settings.safe_disable_reason.clone()),
                ));
                v.push(choice(
                    ItemId::SafeDisableTerm,
                    t::SAFE_DISABLE_TERM,
                    safe_disable_term_options(),
                    app.settings.safe_disable_term,
                ));
                v.push(action(ItemId::SafeDisableRun, t::SAFE_DISABLE_RUN, true));
            }
            // The GUI's "restore network": a live service would put the state
            // straight back, so it is stopped first, and ended if it hangs.
            let (hint, verb) = if report.run_state == ServiceRunState::Stopped {
                (crate::keys::FIX_RESTORE_NETWORK, "reset-network --confirm")
            } else {
                (
                    crate::keys::FIX_STOP_AND_RESTORE_NETWORK,
                    "reset-network --confirm --stop-service",
                )
            };
            v.push(info(Words::Fill(
                hint,
                vec![("command", admin_command(verb))],
            )));
        }
        Loadable::Failed(failure) => v.push(info(Words::Failed(
            t::SERVICE_QUERY_FAILED,
            failure.clone(),
        ))),
        Loadable::NotLoaded | Loadable::Loading => v.push(info(Words::Key(t::LOADING))),
    }
    v
}

// ── Presets and settings ─────────────────────────────────────────────────────

fn presets(app: &AppState) -> Vec<Item> {
    let mut v = vec![
        info(Words::Key(t::EXPORT_DESCRIPTION)),
        Item::new(
            ItemId::ExportPath,
            Words::Key(t::EXPORT_PATH),
            Kind::Text(app.settings.export_path.clone()),
        ),
        action(ItemId::ExportRun, t::EXPORT_RUN, false),
        info(Words::Key(t::RULES_NOTE)),
        choice(
            ItemId::MergePolicy,
            t::MERGE_POLICY,
            vec![
                opt("union", t::MERGE_POLICY_UNION),
                opt("file-wins", t::MERGE_POLICY_FILE_WINS),
                opt("service-wins", t::MERGE_POLICY_SERVICE_WINS),
            ],
            app.settings.merge_policy.slug(),
        )
        .note(t::MERGE_POLICY_NOTE),
    ];
    v.extend(reset_rows(app));
    v
}

/// The programs kept working over the main link, the scan's finds each
/// ticked when confirmed, and the form to add one by path.
fn provider_rows(
    policy: &Map<String, Value>,
    state: &super::providers::ProvidersState,
) -> Vec<Item> {
    use super::providers as p;
    let typed = state.new.as_str();
    let apps = p::apps_of(policy);
    let mut v = vec![heading(p::TITLE), info(Words::Key(p::NOTE))];
    if apps.is_empty() {
        v.push(info(Words::Key(p::EMPTY)));
    }
    for (index, app) in apps.iter().enumerate() {
        v.push(Item::new(
            ItemId::Provider(p::ProviderRow::Remove(index)),
            Words::Fill(
                p::REMOVE,
                vec![
                    ("name", p::name_of(app)),
                    ("path", display_text(&app.exe_path).into_owned()),
                ],
            ),
            Kind::Action { confirm: true },
        ));
    }
    v.push(action(
        ItemId::Provider(p::ProviderRow::Scan),
        match (state.scanning, state.found.is_some()) {
            (true, _) => p::SCANNING,
            (false, true) => p::SCAN_AGAIN,
            (false, false) => p::SCAN,
        },
        false,
    ));
    if let Some(found) = &state.found {
        if found.is_empty() {
            v.push(info(Words::Key(p::FOUND_NONE)));
        } else {
            v.push(info(Words::Key(p::FOUND_HINT)));
        }
        for (index, row) in found.iter().enumerate() {
            v.push(
                if nrr_client_logic::vpn_client_trust::picker_tickable(row) {
                    Item::new(
                        ItemId::Provider(p::ProviderRow::Found(index)),
                        p::found_label(row),
                        Kind::Toggle(p::is_confirmed(policy, row)),
                    )
                } else {
                    info(p::found_label(row))
                },
            );
        }
    }
    v.push(Item::new(
        ItemId::Provider(p::ProviderRow::New),
        Words::Key(p::NEW),
        Kind::Text(typed.to_owned()),
    ));
    v.push(action(ItemId::Provider(p::ProviderRow::Add), t::ADD, false));
    v
}

/// The other VPNs' servers the user let through, each with its remove row.
/// Added only by answering the question, so nothing shows until one is.
fn gateway_rows(app: &AppState) -> Vec<Item> {
    use super::providers as p;
    let confirmed = &app.vpn_gateway_trust.confirmed;
    if confirmed.is_empty() {
        return Vec::new();
    }
    let mut v = vec![
        heading(p::GATEWAYS_TITLE),
        info(Words::Key(p::GATEWAYS_NOTE)),
    ];
    for (index, gateway) in confirmed.iter().enumerate() {
        v.push(Item::new(
            ItemId::Provider(p::ProviderRow::RemoveGateway(index)),
            Words::Join(vec![
                Words::Fill(
                    p::GATEWAY_REMOVE,
                    vec![("address", display_text(&gateway.address).into_owned())],
                ),
                raw(" ("),
                p::gateway_program(gateway),
                raw(")"),
            ]),
            Kind::Action { confirm: true },
        ));
    }
    v
}

/// The full reset, with the choice of whose data when others have rules too.
fn reset_rows(app: &AppState) -> Vec<Item> {
    use super::reset as r;
    let state = &app.settings.reset;
    let mut v = vec![heading(r::TITLE), info(Words::Key(r::BODY))];
    if let Loadable::Ready(count) = &state.others {
        if *count > 0 {
            v.push(info(Words::Fill(
                r::OTHERS,
                vec![("count", count.to_string())],
            )));
            v.push(choice(
                ItemId::Reset(r::ResetRow::Scope),
                r::SCOPE,
                vec![opt("mine", r::MINE), opt("everyone", r::EVERYONE)],
                if state.everyone { "everyone" } else { "mine" },
            ));
        }
    }
    v.push(action(ItemId::Reset(r::ResetRow::Run), r::RUN, true));
    v
}

// ── Logs and storage ─────────────────────────────────────────────────────────

const MIB: u64 = 1024 * 1024;

/// A size budget shown in whole megabytes, at least one.
pub fn megabytes(bytes: u64) -> i64 {
    i64::try_from(((bytes + MIB / 2) / MIB).max(1)).unwrap_or(i64::MAX)
}

/// The words for a log window (`verbose-logging-mode` and its deadline).
fn window_words(
    config: &Map<String, Value>,
    prefix: &str,
    labels: [Key; 2],
    clock: super::Clock,
) -> Words {
    let mode = stability_text(config, &format!("{prefix}-mode"));
    match mode.as_str() {
        "until-restart" => Words::Key(labels[1]),
        "timed" => {
            let until = stability::effective(config, &format!("{prefix}-until-ms"))
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            Words::Fill(t::WINDOW_UNTIL, vec![("timestamp", clock.format(until))])
        }
        _ => Words::Key(labels[0]),
    }
}

fn window_options(labels: [Key; 4]) -> Vec<Opt> {
    stability::LOG_WINDOW_CHANGES
        .into_iter()
        .zip(labels)
        .map(|(slug, label)| opt(slug, label))
        .collect()
}

fn logs(app: &AppState) -> Vec<Item> {
    let s = &app.settings;
    let mut v = vec![heading(t::RETENTION_TITLE)];
    match &s.data.log_retention {
        Loadable::Ready(r) => {
            let days = |label: Key| {
                Words::Join(vec![Words::Key(label), raw(", "), Words::Key(t::DAYS_UNIT)])
            };
            let mb = |label: Key| {
                Words::Join(vec![Words::Key(label), raw(", "), Words::Key(t::MB_UNIT)])
            };
            v.push(number(
                ItemId::LogRetention(LogField::LogsAge),
                days(t::LOGS_AGE),
                Some(i64::from(r.log_max_age_days)),
                1,
                3650,
            ));
            v.push(number(
                ItemId::LogRetention(LogField::LogsSize),
                mb(t::LOGS_SIZE),
                Some(megabytes(r.log_max_size_bytes)),
                1,
                1024,
            ));
            v.push(number(
                ItemId::LogRetention(LogField::AuditAge),
                days(t::AUDIT_AGE),
                Some(i64::from(r.audit_max_age_days)),
                1,
                3650,
            ));
            v.push(number(
                ItemId::LogRetention(LogField::AuditSize),
                mb(t::AUDIT_SIZE),
                Some(megabytes(r.audit_max_size_bytes)),
                1,
                1024,
            ));
        }
        other => v.push(pending(app, other)),
    }
    if s.supports.verbose_logging || s.supports.conn_trace_log {
        match &s.data.stability {
            Loadable::Ready(config) => {
                if s.supports.verbose_logging {
                    v.push(
                        Item::new(
                            ItemId::LogWindow("verbose-logging-change"),
                            Words::Key(t::VERBOSE),
                            Kind::Choice {
                                options: window_options([
                                    t::VERBOSE_OFF,
                                    t::VERBOSE_HOUR,
                                    t::VERBOSE_FOUR,
                                    t::VERBOSE_RESTART,
                                ]),
                                current: None,
                            },
                        )
                        .shown(window_words(
                            config,
                            "verbose-logging",
                            [t::VERBOSE_OFF, t::VERBOSE_RESTART],
                            s.clock,
                        )),
                    );
                }
                if s.supports.conn_trace_log {
                    v.push(
                        Item::new(
                            ItemId::LogWindow("conn-trace-ndjson-change"),
                            Words::Key(t::TRACE_LOG),
                            Kind::Choice {
                                options: window_options([
                                    t::TRACE_OFF,
                                    t::TRACE_HOUR,
                                    t::TRACE_FOUR,
                                    t::TRACE_RESTART,
                                ]),
                                current: None,
                            },
                        )
                        .shown(window_words(
                            config,
                            "conn-trace-ndjson",
                            [t::TRACE_OFF, t::TRACE_RESTART],
                            s.clock,
                        )),
                    );
                }
            }
            other => v.push(pending(app, other)),
        }
    }
    if let Loadable::Ready(config) = &s.data.stability {
        v.extend(service_stability(config));
    }
    v.push(action(ItemId::ClearLogs, t::CLEAR_LOGS, true));

    v.push(heading(t::HISTORY_TITLE));
    v.push(info(Words::Key(t::HISTORY_NOTE)));
    match &s.data.conn_history {
        Loadable::Ready(h) => {
            if !h.available {
                v.push(info(Words::Key(t::HISTORY_UNAVAILABLE)));
            }
            v.push(toggle(ItemId::HistoryEnabled, t::HISTORY_KEEP, h.enabled));
            v.push(number(
                ItemId::HistoryRetention,
                Words::Join(vec![
                    Words::Key(t::HISTORY_DAYS),
                    raw(", "),
                    Words::Key(t::DAYS_UNIT),
                ]),
                Some(i64::from(h.retention_days)),
                1,
                i64::from(h.max_retention_days.max(1)),
            ));
            if h.available {
                v.push(action(ItemId::HistoryClear, t::HISTORY_CLEAR, true));
            }
        }
        other => v.push(pending(app, other)),
    }

    v.push(heading(t::STORAGE_TITLE));
    match &s.data.storage {
        Loadable::Ready(usage) => {
            let line = |label: Key, bytes: u64| {
                info(Words::Join(vec![
                    Words::Key(label),
                    raw(format!(": {}", format_storage_bytes(bytes))),
                ]))
            };
            if let Some(bytes) = usage.state_db_bytes {
                v.push(line(t::STORAGE_STATE, bytes));
            }
            if let Some(bytes) = usage.cache_db_bytes {
                v.push(line(t::STORAGE_CACHE, bytes));
            }
            v.push(line(t::STORAGE_LOGS, usage.operational_logs_bytes));
            v.push(line(t::STORAGE_AUDIT, usage.audit_logs_bytes));
            v.push(line(t::STORAGE_TOTAL, usage.total_bytes));
        }
        other => v.push(pending(app, other)),
    }

    v.push(heading(t::REVISIONS_TITLE));
    v.push(info(Words::Key(t::REVISIONS_NOTE)));
    match &s.data.retention {
        Loadable::Ready(r) => {
            for (field, label, note, value, min, max) in [
                (
                    RevisionField::SupersededDays,
                    t::SUPERSEDED_DAYS,
                    t::SUPERSEDED_DAYS_NOTE,
                    r.superseded_days,
                    7,
                    365,
                ),
                (
                    RevisionField::SupersededCount,
                    t::SUPERSEDED_COUNT,
                    t::SUPERSEDED_COUNT_NOTE,
                    r.superseded_count_cap,
                    20,
                    1000,
                ),
                (
                    RevisionField::RejectedDays,
                    t::REJECTED_DAYS,
                    t::REJECTED_DAYS_NOTE,
                    r.rejected_days,
                    1,
                    90,
                ),
                (
                    RevisionField::RolledbackDays,
                    t::ROLLEDBACK_DAYS,
                    t::ROLLEDBACK_DAYS_NOTE,
                    r.rolledback_days,
                    1,
                    90,
                ),
                (
                    RevisionField::RolledbackCount,
                    t::ROLLEDBACK_COUNT,
                    t::ROLLEDBACK_COUNT_NOTE,
                    r.rolledback_count_cap,
                    5,
                    100,
                ),
            ] {
                v.push(
                    number(
                        ItemId::Revisions(field),
                        Words::Key(label),
                        Some(i64::from(value)),
                        min,
                        max,
                    )
                    .note(note),
                );
            }
            v.push(toggle(ItemId::PinLkg, t::PIN_LKG, r.pin_lkg).note(t::PIN_LKG_NOTE));
            v.push(action(ItemId::RevisionsReset, t::REVISIONS_RESET, false));
            v.push(info(
                match r.last_cleanup_at.and_then(|at| i64::try_from(at).ok()) {
                    Some(secs) => Words::Fill(
                        t::LAST_CLEANUP,
                        vec![("timestamp", s.clock.format(secs.saturating_mul(1000)))],
                    ),
                    None => Words::Key(t::LAST_CLEANUP_NEVER),
                },
            ));
        }
        other => v.push(pending(app, other)),
    }
    v
}

// ── Traffic statistics ───────────────────────────────────────────────────────

fn totals(rows: &[TrafficRowDto]) -> (u64, u64) {
    rows.iter().fold((0, 0), |(i, o), r| {
        (i.saturating_add(r.in_bytes), o.saturating_add(r.out_bytes))
    })
}

fn traffic(app: &AppState) -> Vec<Item> {
    let mut v = vec![info(Words::Key(t::TRAFFIC_NOTE))];
    let stats = match &app.settings.data.traffic {
        Loadable::Ready(stats) => stats,
        other => {
            v.push(pending(app, other));
            return v;
        }
    };
    let periods = [
        (t::TRAFFIC_TODAY, &stats.today),
        (t::TRAFFIC_SESSION, &stats.session),
        (t::TRAFFIC_ALL_TIME, &stats.all_time),
    ];
    if periods.iter().all(|(_, rows)| rows.is_empty()) {
        v.push(info(Words::Key(t::TRAFFIC_NO_DATA)));
    }
    if let Some(question) = &stats.history_merge {
        v.push(info(Words::Fill(
            t::TRAFFIC_MERGE_QUESTION,
            vec![
                ("old", display_text(&question.old_name).into_owned()),
                ("new", display_text(&question.new_name).into_owned()),
            ],
        )));
        v.push(info(Words::Key(t::TRAFFIC_MERGE_HINT)));
        v.push(action(
            ItemId::TrafficMerge(true),
            t::TRAFFIC_MERGE_SAME,
            false,
        ));
        v.push(action(
            ItemId::TrafficMerge(false),
            t::TRAFFIC_MERGE_DIFFERENT,
            false,
        ));
    }
    for (period, rows) in periods.iter().filter(|(_, rows)| !rows.is_empty()) {
        let (received, sent) = totals(rows);
        v.push(info(Words::Join(vec![
            Words::Key(*period),
            raw(": "),
            bytes_words(received, sent),
        ])));
        v.extend(traffic_rows(rows));
    }
    let settings = &stats.settings;
    v.push(toggle(
        ItemId::Traffic(TrafficField::Enabled),
        t::TRAFFIC_ENABLED,
        settings.enabled,
    ));
    v.push(toggle(
        ItemId::Traffic(TrafficField::Loopback),
        t::TRAFFIC_LOOPBACK,
        settings.count_loopback,
    ));
    v.push(toggle(
        ItemId::Traffic(TrafficField::Virtual),
        t::TRAFFIC_VIRTUAL,
        settings.count_virtual,
    ));
    v.push(number(
        ItemId::TrafficRetention,
        Words::Key(t::TRAFFIC_RETENTION),
        Some(i64::from(settings.retention_days)),
        7,
        3650,
    ));
    v.push(Item::new(
        ItemId::TrafficExportPath,
        Words::Key(t::EXPORT_PATH),
        Kind::Text(app.settings.traffic_export_path.clone()),
    ));
    v.push(choice(
        ItemId::TrafficExportUnit,
        t::TRAFFIC_EXPORT_UNIT,
        traffic_export_units(),
        app.settings.traffic_export_unit,
    ));
    v.push(action(ItemId::TrafficExport, t::TRAFFIC_EXPORT, false));
    v.push(action(ItemId::TrafficReset, t::TRAFFIC_RESET, true));
    v
}

/// The units the exported byte columns may use, as the window offers them.
pub fn traffic_export_units() -> Vec<Opt> {
    vec![
        opt("bytes", t::UNIT_BYTES),
        opt("kb", t::UNIT_KB),
        opt("mb", t::UNIT_MB),
        opt("gb", t::UNIT_GB),
    ]
}

fn bytes_words(received: u64, sent: u64) -> Words {
    Words::Join(vec![
        Words::Key(t::TRAFFIC_RECEIVED),
        raw(format!(" {}, ", format_storage_bytes(received))),
        Words::Key(t::TRAFFIC_SENT),
        raw(format!(" {}", format_storage_bytes(sent))),
    ])
}

/// A period's rows by route, in the window's order: the additional adapter
/// first, then the main one, then the opt-in local and virtual counts.
fn traffic_rows(rows: &[TrafficRowDto]) -> Vec<Item> {
    const ORDER: [(&str, Key); 4] = [
        ("secondary", t::TRAFFIC_THROUGH_SECONDARY),
        ("primary", t::TRAFFIC_THROUGH_PRIMARY),
        ("loopback", t::TRAFFIC_ROLE_LOOPBACK),
        ("virtual", t::TRAFFIC_ROLE_VIRTUAL),
    ];
    ORDER
        .iter()
        .flat_map(|(role, title)| {
            rows.iter()
                .filter(move |row| row.role == *role)
                .map(move |row| {
                    info(Words::Join(vec![
                        raw("  "),
                        Words::Key(*title),
                        raw(format!(" — {}: ", display_text(&row.display_name))),
                        bytes_words(row.in_bytes, row.out_bytes),
                    ]))
                })
        })
        .collect()
}

// ── Updates and the terminal itself ──────────────────────────────────────────

/// What the window's About shows, and the third-party list with each
/// component's integrity verdict; no list where nothing is shipped.
fn about(app: &AppState) -> Vec<Item> {
    let shell = nrr_shared::gui_shell_v1().about;
    let fact =
        |label: Key, value: Words| info(Words::Join(vec![Words::Key(label), raw(": "), value]));
    let mut v = vec![
        fact(t::VERSION, raw(env!("CARGO_PKG_VERSION"))),
        fact(t::LICENSE, raw(env!("CARGO_PKG_LICENSE"))),
        fact(t::AUTHOR, Words::Key(t::AUTHOR_NAME)),
        fact(t::AUTHOR_EMAIL, raw(shell.author_email)),
        fact(t::PROJECT, raw(shell.project_url)),
        fact(t::BUILD_CHANNEL, raw(shell.build_channel)),
        info(Words::Key(t::UPDATES_NOTE)),
    ];
    match &app.settings.data.third_party {
        Loadable::Ready(list) if list.components.is_empty() => {}
        Loadable::Ready(list) => {
            v.push(heading(t::THIRD_PARTY));
            for component in &list.components {
                v.extend(third_party_rows(component));
            }
        }
        other => {
            v.push(heading(t::THIRD_PARTY));
            v.push(pending(app, other));
        }
    }
    v
}

fn third_party_rows(component: &nrr_shared::third_party::ThirdPartyComponentStatus) -> Vec<Item> {
    use nrr_shared::third_party::IntegrityVerdict;
    let (verdict, note) = match component.verdict {
        IntegrityVerdict::Genuine => (t::VERDICT_GENUINE, None),
        IntegrityVerdict::Untrusted => (t::VERDICT_UNTRUSTED, Some(t::VERDICT_UNTRUSTED_NOTE)),
        IntegrityVerdict::Missing => (t::VERDICT_MISSING, Some(t::VERDICT_MISSING_NOTE)),
        IntegrityVerdict::NotApplicable => (t::VERDICT_NOT_APPLICABLE, None),
    };
    let mut rows = vec![info(Words::Join(vec![
        raw(format!(
            "{} {} ({}) — ",
            display_text(&component.display_name),
            display_text(&component.version),
            display_text(&component.license_name),
        )),
        Words::Key(verdict),
    ]))];
    if let Some(note) = note {
        rows.push(info(Words::Key(note)));
    }
    rows
}

fn terminal(app: &AppState) -> Vec<Item> {
    let prefs = app.settings.prefs;
    vec![
        toggle(ItemId::Pref(PrefField::Plain), t::PREF_PLAIN, prefs.plain),
        toggle(
            ItemId::Pref(PrefField::NoColor),
            t::PREF_NO_COLOR,
            prefs.no_color,
        ),
        toggle(ItemId::Pref(PrefField::Ascii), t::PREF_ASCII, prefs.ascii),
        info(Words::Key(t::PREF_NOTE)),
    ]
}

#[cfg(test)]
pub fn scope_label(scope: &BlockNoticeMuteScopeDto, texts: &Texts) -> String {
    scope_words(scope).resolve(texts)
}
