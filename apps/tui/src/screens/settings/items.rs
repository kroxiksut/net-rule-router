//! What each section lists: the settings, their values, and which change each
//! one stands for. Built from the state on every frame, so nothing is shown
//! that the state does not hold; words stay keys until the view resolves them.

use nrr_client_logic::notice_mutes::MUTABLE_NOTICE_KINDS;
use nrr_client_logic::units::format_storage_bytes;
use nrr_client_logic::{route_policy, stability};
use nrr_platform_api::service_control::{ServiceRunState, ServiceStartMode};
use nrr_shared::ipc_payloads::{BlockNoticeMuteDto, BlockNoticeMuteScopeDto, TrafficRowDto};
use serde_json::{Map, Value};

use super::text as t;
use super::{failure_text, Category, Failure, Loadable, MuteScope, ServiceInfo};
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
    FillWords(Key, Vec<(&'static str, Words)>),
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
            Self::FillWords(key, values) => {
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
    ProbeReset,
    /// A field of the service-stability row.
    Stability(&'static str),
    RuleLock,
    StopPersist,
    /// A one-shot log-window request (`verbose-logging-change`, …).
    LogWindow(&'static str),
    FailurePolicy,
    ServiceStart,
    ServiceStop,
    ServiceRestart,
    ExportPath,
    ExportRun,
    LogRetention(LogField),
    ClearLogs,
    Revisions(RevisionField),
    PinLkg,
    Traffic(TrafficField),
    TrafficRetention,
    TrafficReset,
    Pref(PrefField),
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
        Category::Updates => updates(),
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

pub fn kind_mute<'a>(mutes: &'a [BlockNoticeMuteDto], kind: &str) -> Option<&'a BlockNoticeMuteDto> {
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
            Words::Fill(t::MUTE_HOST, vec![("name", host.clone())])
        }
        BlockNoticeMuteScopeDto::App { app } => {
            Words::Fill(t::MUTE_APP, vec![("name", app.clone())])
        }
        // The reason's own words are a key named after the slug.
        BlockNoticeMuteScopeDto::Reason { reason } => Words::FillWords(
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
    let mut v = vec![heading(t::HIDDEN_HEADING), info(Words::Key(t::HIDDEN_DESCRIPTION))];
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
        let kinds = block_row.into_iter().chain(MUTABLE_NOTICE_KINDS.iter().map(|k| {
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
                    Some(until) => Words::Fill(
                        t::HIDDEN_UNTIL,
                        vec![("timestamp", clock.format(until))],
                    ),
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
    let mut v = vec![
        heading(t::DEFAULT_ROUTE),
        choice(
            ItemId::Policy("mode"),
            t::DEFAULT_ROUTE,
            vec![
                opt("prefer-primary", t::MODE_PREFER_PRIMARY),
                opt("prefer-secondary-when-available", t::MODE_PREFER_SECONDARY),
                opt("strict-secondary-fail-closed", t::MODE_STRICT_SECONDARY),
            ],
            &policy_text(policy, "mode"),
        )
        .note(t::DEFAULT_ROUTE_NOTE),
        policy_toggle(policy, "include-subdomains", t::SUBDOMAINS).note(t::SUBDOMAINS_NOTE),
        heading(t::LEAK_TITLE),
    ];
    if !s.supports.kill_switch {
        v.push(info(Words::Key(t::UNSUPPORTED)));
    } else {
        v.push(policy_toggle(policy, "kill-switch-enabled", t::LEAK_ENABLE).note(t::LEAK_ENABLE_NOTE));
        let enabled = policy_bool(policy, "kill-switch-enabled");
        let fail_closed = policy_bool(policy, "kill-switch-fail-closed");
        if enabled {
            v.push(
                choice(
                    ItemId::Policy("kill-switch-fail-closed"),
                    t::FAILURE_MODE,
                    vec![opt("fail-closed", t::FAIL_CLOSED), opt("fail-open", t::FAIL_OPEN)],
                    if fail_closed { "fail-closed" } else { "fail-open" },
                )
                .note(if fail_closed {
                    t::FAIL_CLOSED_NOTE
                } else {
                    t::FAIL_OPEN_NOTE
                }),
            );
            if fail_closed {
                v.push(heading(t::PROTOCOLS));
                let mask = policy_int(policy, route_policy::KILL_SWITCH_PROTOCOLS_KEY).unwrap_or(0);
                for (bit, label) in PROTOCOLS {
                    v.push(toggle(ItemId::Protocol(bit), label, mask & i64::from(bit) != 0));
                }
                v.push(policy_toggle(policy, "kill-switch-block-all", t::BLOCK_ALL).note(t::BLOCK_ALL_NOTE));
                if policy_bool(policy, "kill-switch-block-all") {
                    v.push(
                        policy_toggle(policy, "allow-dns-over-primary", t::ALLOW_DNS)
                            .note(t::ALLOW_DNS_NOTE),
                    );
                }
                v.push(
                    policy_toggle(policy, "kill-switch-strict-shared-ips", t::SHARED_STRICT)
                        .note(t::SHARED_STRICT_NOTE),
                );
            }
            v.push(
                choice(
                    ItemId::Policy("shared-ip-policy"),
                    t::SHARED_IP,
                    vec![
                        opt("majority-of-ip", t::SHARED_MAJORITY_IP),
                        opt("majority-of-rules", t::SHARED_MAJORITY_RULES),
                        opt("any-rule-domain", t::SHARED_ANY),
                    ],
                    &policy_text(policy, "shared-ip-policy"),
                )
                .note(t::SHARED_IP_NOTE),
            );
            if s.supports.service_stability_config {
                match stability_row {
                    Ok(config) => {
                        let resolver = stability_text(config, "enforcement-mode") == "resolver";
                        if resolver {
                            v.push(
                                stability_toggle(config, "dns-via-secondary", t::DNS_VIA_SECONDARY)
                                    .note(t::DNS_VIA_SECONDARY_NOTE),
                            );
                        }
                        v.push(stability_toggle(config, "dns-fast-answers", t::DNS_FAST));
                        if resolver {
                            v.push(stability_toggle(config, "fake-ip-enabled", t::FAKE_IP));
                        }
                        v.push(stability_toggle(config, "fake-ip-udp-relay", t::FAKE_IP_UDP));
                        v.push(stability_toggle(config, "fake-ip-instant-rst", t::FAKE_IP_RST));
                        if fail_closed {
                            let key = "secondary-liveness-window-secs";
                            let secs = stability::effective(config, key).and_then(|v| v.as_i64());
                            let mut item = number(
                                ItemId::Stability(key),
                                Words::Key(t::LIVENESS),
                                secs,
                                0,
                                3600,
                            )
                            .note(t::LIVENESS_RANGE);
                            item.shown = Some(match secs {
                                Some(0) | None => Words::Key(t::LIVENESS_DISABLED),
                                Some(n) => Words::Join(vec![
                                    raw(format!("{n} ")),
                                    Words::Key(t::SECONDS),
                                ]),
                            });
                            v.push(item);
                        }
                    }
                    Err(other) => v.push(pending(app, other)),
                }
            }
        }
    }

    v.push(heading(t::DOH_TITLE));
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
    v.push(heading(t::HOSTS_TITLE));
    v.push(policy_toggle(policy, "resolve-hosts-bypass", t::HOSTS_BYPASS));
    if s.supports.local_network_exceptions {
        v.push(heading(t::LOCAL_TITLE));
        v.push(policy_toggle(policy, "local-networks-auto-accept", t::LOCAL_AUTO));
    }
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
        v.push(policy_toggle(policy, "auto-rules-eager-delivery-names", t::AUTO_EAGER));
    }
    if s.supports.service_stability_config {
        v.push(heading(t::SYSTEM_TITLE));
        match stability_row {
            Ok(config) => {
                v.push(toggle(ItemId::RuleLock, t::RULE_LOCK, rule_edits_allowed(config)));
                v.push(stability_toggle(config, "rule-scope-service-driven", t::SERVICE_DRIVEN));
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

/// The main-route check limits: key, label and the GUI's bounds.
pub const PROBE_LIMITS: [(&str, Key, i64, i64); 3] = [
    ("primary-probe-timeout-ms", t::PROBE_TIMEOUT, 300, 5000),
    ("primary-probe-max-targets", t::PROBE_TARGETS, 1, 32),
    ("primary-probe-repeat-secs", t::PROBE_REPEAT, 30, 86400),
];

// ── Apply failure policy ─────────────────────────────────────────────────────

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
    Item::new(ItemId::None, Words::Key(word), Kind::State(tone, t::SERVICE_STATE))
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
                v.push(info(Words::FillWords(
                    t::SERVICE_START_MODE,
                    vec![("mode", Words::Key(mode))],
                )));
            }
            match report.run_state {
                ServiceRunState::Stopped => v.push(action(ItemId::ServiceStart, t::SERVICE_START, false)),
                ServiceRunState::Running => {
                    v.push(action(ItemId::ServiceStop, t::SERVICE_STOP, true));
                    v.push(action(ItemId::ServiceRestart, t::SERVICE_RESTART, true));
                }
                _ => {}
            }
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
    vec![
        info(Words::Key(t::EXPORT_DESCRIPTION)),
        Item::new(
            ItemId::ExportPath,
            Words::Key(t::EXPORT_PATH),
            Kind::Text(app.settings.export_path.clone()),
        ),
        action(ItemId::ExportRun, t::EXPORT_RUN, false),
        info(Words::Key(t::RULES_NOTE)),
    ]
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
            let days = |label: Key| Words::Join(vec![Words::Key(label), raw(", "), Words::Key(t::DAYS_UNIT)]);
            let mb = |label: Key| Words::Join(vec![Words::Key(label), raw(", "), Words::Key(t::MB_UNIT)]);
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
    v.push(action(ItemId::ClearLogs, t::CLEAR_LOGS, true));

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
            for (field, label, value, min, max) in [
                (RevisionField::SupersededDays, t::SUPERSEDED_DAYS, r.superseded_days, 7, 365),
                (RevisionField::SupersededCount, t::SUPERSEDED_COUNT, r.superseded_count_cap, 20, 1000),
                (RevisionField::RejectedDays, t::REJECTED_DAYS, r.rejected_days, 1, 90),
                (RevisionField::RolledbackDays, t::ROLLEDBACK_DAYS, r.rolledback_days, 1, 90),
                (RevisionField::RolledbackCount, t::ROLLEDBACK_COUNT, r.rolledback_count_cap, 5, 100),
            ] {
                v.push(number(
                    ItemId::Revisions(field),
                    Words::Key(label),
                    Some(i64::from(value)),
                    min,
                    max,
                ));
            }
            v.push(toggle(ItemId::PinLkg, t::PIN_LKG, r.pin_lkg).note(t::PIN_LKG_NOTE));
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
    for (period, rows) in periods.iter().filter(|(_, rows)| !rows.is_empty()) {
        let (received, sent) = totals(rows);
        v.push(info(Words::Join(vec![
            Words::Key(*period),
            raw(": "),
            Words::Key(t::TRAFFIC_RECEIVED),
            raw(format!(" {}, ", format_storage_bytes(received))),
            Words::Key(t::TRAFFIC_SENT),
            raw(format!(" {}", format_storage_bytes(sent))),
        ])));
    }
    let settings = &stats.settings;
    v.push(toggle(ItemId::Traffic(TrafficField::Enabled), t::TRAFFIC_ENABLED, settings.enabled));
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
    v.push(action(ItemId::TrafficReset, t::TRAFFIC_RESET, true));
    v
}

// ── Updates and the terminal itself ──────────────────────────────────────────

fn updates() -> Vec<Item> {
    vec![
        info(Words::Join(vec![
            Words::Key(t::VERSION),
            raw(format!(": {}", env!("CARGO_PKG_VERSION"))),
        ])),
        info(Words::Key(t::UPDATES_NOTE)),
    ]
}

fn terminal(app: &AppState) -> Vec<Item> {
    let prefs = app.settings.prefs;
    vec![
        toggle(ItemId::Pref(PrefField::Plain), t::PREF_PLAIN, prefs.plain),
        toggle(ItemId::Pref(PrefField::NoColor), t::PREF_NO_COLOR, prefs.no_color),
        toggle(ItemId::Pref(PrefField::Ascii), t::PREF_ASCII, prefs.ascii),
        info(Words::Key(t::PREF_NOTE)),
    ]
}

/// Every row the cursor stops on, in order.
pub fn selectable(items: &[Item]) -> Vec<&Item> {
    items.iter().filter(|i| i.selectable()).collect()
}

#[cfg(test)]
pub fn scope_label(scope: &BlockNoticeMuteScopeDto, texts: &Texts) -> String {
    scope_words(scope).resolve(texts)
}
