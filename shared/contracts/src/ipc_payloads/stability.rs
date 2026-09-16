use super::*;

// ── ServiceStabilityConfig ────────────────────────────────────────────────

/// Wire shape for `nrr_service_runtime::service_stability::ServiceStabilityConfig`.
/// Carries the IPC accept-failure policy as a tagged enum payload plus
/// the verbose-logging toggle.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ServiceStabilityConfigDto {
    pub ipc_accept_policy: IpcAcceptFailurePolicyDto,
    /// When `true` the supervisor installs
    /// `EnvFilter::new("nrr=debug,info")` instead of the canonical
    /// `"nrr=info,info"`, so operational NDJSON captures `tracing::debug!`
    /// events. `#[serde(default)]` keeps the field additive — older
    /// GUI builds that omit it deserialise as `false`, matching the
    /// previous server behaviour.
    #[serde(default)]
    pub verbose_logging: bool,
    /// When `true` the opt-in connection-egress
    /// trace writes each observed connection to the operational NDJSON.
    /// `#[serde(default)]` keeps it additive (older GUIs deserialise `false`).
    #[serde(default)]
    pub conn_trace_ndjson: bool,
    /// When `true` the Diagnostics connection-trace panel may show what was
    /// observed. Independent of `conn_trace_ndjson` — it gates the VIEW, never
    /// the observation app routing and the learners depend on. Defaults to
    /// `true`: an absent field must not blank a panel that costs nothing on
    /// disk (the privacy-sensitive half is the NDJSON sink).
    #[serde(default = "default_true")]
    pub conn_trace_gui: bool,
    /// Routing scope. `true` (default) = service-driven
    /// (the service enforces continuously while it runs, even with no GUI/tray
    /// connected); `false` = app-driven (enforced only while a tray is
    /// connected). The wire default is `true` so an older GUI that omits the
    /// field cannot silently flip an installed service-driven policy to
    /// app-driven on a round-trip Save.
    #[serde(default = "rule_scope_default")]
    pub rule_scope_service_driven: bool,
    /// Persist-on-stop — what happens to NRR routing/filters when the service
    /// stops. `"teardown"` (default) removes NRR `/32` routes and strips every
    /// WFP filter so the box returns to its pre-NRR channel; `"persist"` keeps
    /// the `/32` routes but STILL strips every block/fail-closed/kill-switch
    /// filter (an orphaned block with no service to lift it is a lockout).
    /// Stored as a slug (mirrors the storage column). The serde default is the
    /// teardown slug so an older GUI that omits the field can never silently
    /// flip an installed policy to `persist` on a round-trip Save.
    #[serde(default = "routing_stop_policy_default")]
    pub routing_stop_policy: String,
    /// User-configurable FQDN cache refresh cadence
    /// (seconds): how often a routed site's IPs are re-resolved. The service
    /// clamps this to `nrr_domain::decision_lookup::CACHE_REFRESH_{MIN,MAX}_SECS`
    /// (60 s..24 h) on both write and read — the GUI limit is a convenience, the
    /// backend is authoritative. `#[serde(default)]` keeps it additive (older
    /// GUIs deserialise the 5-minute default).
    #[serde(default = "cache_refresh_interval_default")]
    pub cache_refresh_interval_secs: u32,
    /// Machine-wide traffic-enforcement mechanism
    /// slug. `"resolver"` (default) selects the local DNS resolver;
    /// `"reactive"` selects the legacy reactive kill-switch. Global service
    /// setting (NOT per-SID). Stored as a slug (mirrors
    /// `nrr_domain::enforcement_mode::EnforcementMode::as_slug`). The serde
    /// default tracks the domain default: an omitted field must mean "the
    /// product default", never "the other mode".
    #[serde(default = "enforcement_mode_default")]
    pub enforcement_mode: String,
    /// Secondary-tunnel liveness window (SECONDS): how long the
    /// tunnel next-hop must be continuously unreachable (active ICMP probe) before
    /// the kill-switch fail-closes. `0` (the default) DISABLES the probe — it never
    /// fail-closes (safe default). The service clamps any non-zero value to
    /// `5..=3600` on both write and read (the GUI limit is a convenience, the
    /// backend is authoritative). `#[serde(default)]` keeps it additive — older
    /// GUIs that omit the field deserialise `0` (disabled). Wire key
    /// `"secondary-liveness-window-secs"` (kebab-case). Global service setting (NOT
    /// per-SID).
    #[serde(default = "secondary_liveness_window_default")]
    pub secondary_liveness_window_secs: u32,
    /// Machine-wide fake-IP toggle: when `true` AND
    /// `enforcement_mode == "resolver"`, routed (scope) hosts are answered
    /// with virtual addresses and relayed through the local TUN adapter, so a
    /// routed site never shares a real address with a direct one. Off by
    /// default (opt-in; on Windows it loads the bundled Wintun driver).
    /// `#[serde(default)]` keeps the field additive — an older GUI that omits
    /// it can never silently switch the feature ON, and the full-row Set from
    /// an older build turns it OFF (safe direction). Wire key
    /// `"fake-ip-enabled"`. Global service setting (NOT per-SID).
    #[serde(default)]
    pub fake_ip_enabled: bool,
    /// DNS-over-the-secondary-link toggle: when `true` AND the
    /// secondary adapter is up with a usable IPv4 source, the service's own
    /// upstream DNS queries (Mode-B resolver, raw forward, seeder/refresh)
    /// egress source-bound through the secondary link to well-known public
    /// resolvers, instead of the primary link's provider resolver. Benefit:
    /// name answers can no longer be spoofed or stubbed by the primary
    /// provider. Falls back to the primary path whenever the secondary is
    /// down/unresolved (availability over purity). Off by default (opt-in).
    /// `#[serde(default)]` keeps the field additive — an older GUI's full-row
    /// Set turns it OFF (safe direction). Wire key `"dns-via-secondary"`.
    /// Global service setting (NOT per-SID).
    #[serde(default)]
    pub dns_via_secondary: bool,
    /// Fast DNS answers: when `true` (the default), the Mode-B
    /// resolver answers a routed-host query immediately whenever every
    /// answered address is already known to the routable cache, and only
    /// holds the answer for the route-install deadline when the answer
    /// introduces addresses the cache has never seen (first contact).
    /// Benefit: pages stop stalling on name resolution while enforcement
    /// converges in the background. The wire default is `true` so an older
    /// GUI that omits the field cannot silently re-enable the measured
    /// "hold every answer" stall on a round-trip Save. Wire key
    /// `"dns-fast-answers"`. Global service setting (NOT per-SID).
    #[serde(default = "dns_fast_answers_default")]
    pub dns_fast_answers: bool,
    /// Fake-IP UDP relay: when `true`, the fake-IP pool permit
    /// admits UDP (QUIC/HTTP-3) into the pool instead of hard-blocking it, so
    /// QUIC rides the relay's TUN stack the same way TCP already does.
    /// Meaningful only alongside `fake_ip_enabled`. Off by default —
    /// `#[serde(default)]` keeps the field additive, and an older GUI's
    /// full-row Set turns it OFF (safe direction: QUIC keeps falling back to
    /// TCP rather than silently starting to ride an unreviewed relay path).
    /// Wire key `"fake-ip-udp-relay"`. Global service setting (NOT per-SID).
    #[serde(default)]
    pub fake_ip_udp_relay: bool,
    /// Fake-IP instant reset: when `true` (the default), a relay
    /// dial that fails because the source-address policy refused it (most
    /// commonly: the secondary adapter is unresolved during a VPN reconnect)
    /// resets the client immediately — today's behaviour. When `false`, that
    /// ONE refusal class is held and retried for a bounded window (~10 s)
    /// instead of resetting the client outright; a genuine network error
    /// still fails fast either way. The wire default is `true` so an older
    /// GUI that omits the field, or a full-row Set from a pre-this-feature
    /// build, can never silently switch an installed service onto the
    /// held-dial path. Wire key `"fake-ip-instant-rst"`. Global service
    /// setting (NOT per-SID).
    #[serde(default = "fake_ip_instant_rst_default")]
    pub fake_ip_instant_rst: bool,
    /// Administrative rules lock: `Some(true)` lets every user maintain their
    /// own rule set (the product default); `Some(false)` freezes rule
    /// authoring for non-elevated callers — they keep reading the
    /// administrator's baseline while the service refuses their own edits, so
    /// a modified client cannot talk its way past the GUI.
    ///
    /// Modelled as an `Option` rather than a plain `bool` with a serde default,
    /// unlike every other field here, and that is the point: `None` means
    /// "leave the stored value alone". The full-row Set has no sparse shape, so
    /// a plain default would force a choice between a stale client silently
    /// LIFTING an administrator's lock (`true`) and a stale client silently
    /// IMPOSING one nobody asked for (`false`). Neither is acceptable for a
    /// setting whose only job is to be hard to remove, so the wire carries the
    /// three-state answer instead. A Get always answers `Some`.
    ///
    /// Wire key `"allow-user-rule-edits"`. Machine-wide (NOT per-SID) and
    /// writable only by an elevated caller; reading is open to everyone so a
    /// client can render the rules section read-only with an explanation.
    #[serde(default)]
    pub allow_user_rule_edits: Option<bool>,
}

/// Wire default for `ServiceStabilityConfigDto::dns_fast_answers`: `true`.
/// See the field doc — answering immediately is the safe/default posture.
fn dns_fast_answers_default() -> bool {
    true
}

/// Wire default for `ServiceStabilityConfigDto::fake_ip_instant_rst`: `true`.
/// See the field doc — instant reset is today's behaviour and the safe
/// default posture.
fn fake_ip_instant_rst_default() -> bool {
    true
}

/// Wire default for `ServiceStabilityConfigDto::secondary_liveness_window_secs`:
/// `0` (DISABLED — the liveness probe never fail-closes). See the field doc.
fn secondary_liveness_window_default() -> u32 {
    0
}

/// Wire default for `ServiceStabilityConfigDto::enforcement_mode`: the resolver
/// slug. Mirrors `nrr_domain::enforcement_mode::EnforcementMode::default`
/// (kept as a literal here to avoid a contracts→domain dependency), and the
/// mirroring is the point: when this literal and the domain default disagreed,
/// an omitted field meant "quietly fall back to the other mode" instead of
/// "use the default", which is how a wiped service DB ended up enforcing in a
/// mode the user never chose.
pub fn enforcement_mode_default() -> String {
    ENFORCEMENT_MODE_DEFAULT.to_string()
}

/// The enforcement mode a service with no stored choice runs in. Public so the
/// preference mirror and the QML shell can DERIVE it instead of retyping the
/// slug — three hand-written copies had already drifted into two different
/// answers, and the odd one out silently put users in a mode the code itself
/// calls an unsupported historical fallback.
pub const ENFORCEMENT_MODE_DEFAULT: &str = "resolver";

/// Wire default for `ServiceStabilityConfigDto::cache_refresh_interval_secs`:
/// 5 minutes. Mirrors `nrr_domain::decision_lookup::CACHE_REFRESH_DEFAULT_SECS`
/// (kept as a literal here to avoid a contracts→domain dependency).
fn cache_refresh_interval_default() -> u32 {
    300
}

/// Wire default for `ServiceStabilityConfigDto::rule_scope_service_driven`:
/// service-driven (`true`). See the field doc for the rationale.
fn rule_scope_default() -> bool {
    true
}

/// Wire default for `ServiceStabilityConfigDto::routing_stop_policy`: the
/// teardown slug. See the field doc — teardown must be the default at every
/// layer so a stop can never silently leave routing/blocks in place.
fn routing_stop_policy_default() -> String {
    "teardown".to_string()
}

impl Default for ServiceStabilityConfigDto {
    fn default() -> Self {
        Self {
            ipc_accept_policy: IpcAcceptFailurePolicyDto::default(),
            verbose_logging: false,
            conn_trace_ndjson: false,
            conn_trace_gui: true,
            // Preserve the historical Rust-side default (`false`) for this
            // field; the wire/serde default is `true` via `rule_scope_default`.
            rule_scope_service_driven: false,
            routing_stop_policy: routing_stop_policy_default(),
            cache_refresh_interval_secs: cache_refresh_interval_default(),
            enforcement_mode: enforcement_mode_default(),
            secondary_liveness_window_secs: secondary_liveness_window_default(),
            fake_ip_enabled: false,
            dns_via_secondary: false,
            dns_fast_answers: dns_fast_answers_default(),
            fake_ip_udp_relay: false,
            fake_ip_instant_rst: fake_ip_instant_rst_default(),
            // `None` = "no opinion": a default-constructed DTO is what a
            // degraded read falls back to, and it must never be mistaken for
            // an administrator's decision in either direction.
            allow_user_rule_edits: None,
        }
    }
}

/// Wire shape for `nrr_service_runtime::service_stability::IpcAcceptFailurePolicy`.
/// Tagged enum so the wire stays self-describing for future variants.
///
/// `rename_all` propagates to variant tags (`Recoverable` → `recoverable`);
/// `rename_all_fields` propagates to fields INSIDE struct variants
/// (`max_restarts` → `max-restarts`). Both are required for kebab-case
/// consistency with the rest of the wire schema.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "kebab-case"
)]
pub enum IpcAcceptFailurePolicyDto {
    Recoverable {
        max_restarts: u32,
        /// Initial back-off (ms).
        backoff_base_ms: u32,
        /// Cap on exponential back-off (ms).
        backoff_cap_ms: u32,
    },
    Critical,
}

impl Default for IpcAcceptFailurePolicyDto {
    fn default() -> Self {
        // Matches `IpcAcceptFailurePolicy::default()` semantics —
        // canonical constants kept in service-runtime to avoid an
        // import cycle.
        Self::Recoverable {
            max_restarts: 20,
            backoff_base_ms: 100,
            backoff_cap_ms: 5_000,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct ServiceStabilityConfigGetRequest {}

pub type ServiceStabilityConfigGetResponse = ServiceStabilityConfigDto;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ServiceStabilityConfigSetRequest {
    pub config: ServiceStabilityConfigDto,
    /// Free-form writer attribution
    /// (`"user:enforcement-mode"`, `"user:verbose-toggle"`,
    /// `"offline-pending-apply"`, …), logged by the Set handler. Purely
    /// diagnostic: without it, a stability write of unknown provenance can
    /// clobber a user toggle and the NDJSON has no way to say WHICH GUI code
    /// path wrote it. Optional so older clients stay valid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
}

/// Set echoes the persisted config so the GUI can confirm the write
/// took effect (e.g. defaults were applied to omitted fields).
pub type ServiceStabilityConfigSetResponse = ServiceStabilityConfigDto;

/// Wire request for `ThirdPartyComponentsList`. No
/// parameters — the service reports on every third-party binary this build
/// ships. Kept as a struct (not `()`) so fields can be added compatibly.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ThirdPartyComponentsListRequest {}

/// Attribution + live integrity of the shipped third-party
/// binaries. **An empty list is the normal answer on Linux and macOS**, which
/// ship none: the GUI hides the whole surface rather than rendering an empty
/// block, so "no components" and "component missing" never look alike.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ThirdPartyComponentsListResponse {
    pub components: Vec<ThirdPartyComponentStatus>,
}
