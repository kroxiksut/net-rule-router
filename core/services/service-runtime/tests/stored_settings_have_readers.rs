//! Every stored setting has a reader on every OS, or the client hides it there.
//!
//! A setting the service accepts, stores and echoes back but never acts on is
//! the quietest defect a settings surface can have: the user sees the choice
//! saved and nothing changes. The same holds the other way: a control hidden
//! on an OS whose daemon does carry the setting out.
//!
//! The field lists come from the types themselves (an exhaustive destructuring
//! below, so a new field does not compile until it is classified here). For
//! each field and each OS the table names one of:
//!   * the consumer — a chain of (file, needle) links ending in code that only
//!     that OS's service builds, so a shared reader counts only where that OS
//!     wires it;
//!   * the capability that is `false` on that OS, which the GUI gates on;
//!   * a known gap, with the symptoms that make it one. A gap that closes fails
//!     the test as surely as a new one, so the list can only shrink.
//!
//! The same holds for the capability flags: a flag claims a mechanism, and a
//! flag that disagrees with what the daemon wires is the other half of the
//! same defect. The QML stability defaults table is pinned to the wire DTO by
//! `apps/desktop/gui/tests/stability_wire_contract.rs`, not here.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use nrr_shared::platform_profile::PlatformProfile;
use nrr_storage::autostart_state::AutostartStateRecord;
use nrr_storage::doh_lockdown::DohResolverEntry;
use nrr_storage::install_policy::InstallPolicy;
use nrr_storage::log_retention_config::LogRetentionConfig;
use nrr_storage::pause_state::RoutingPauseRecord;
use nrr_storage::policy_settings::ApplyFailurePolicyRecord;
use nrr_storage::retention_settings::RetentionSettings;
use nrr_storage::route_bindings::RoutePolicyRecord;
use nrr_storage::service_stability_config::ServiceStabilityConfigRecord;
use nrr_storage::traffic_stats_settings::TrafficStatsSettings;
use serde_json::Value;

/// The field names of a struct, held exhaustive by a pattern without `..`.
macro_rules! fields_of {
    ($ty:ident { $($field:ident),* $(,)? }) => {{
        let _exhaustive = |value: $ty| {
            let $ty { $($field: _),* } = value;
        };
        vec![$(stringify!($field)),*]
    }};
}

fn stored_fields() -> Vec<(&'static str, Vec<&'static str>)> {
    vec![
        (
            "ServiceStabilityConfigRecord",
            fields_of!(ServiceStabilityConfigRecord {
                ipc_accept_policy,
                set_by_sid,
                updated_at,
                verbose_until_ms,
                conn_trace_ndjson_until_ms,
                conn_trace_gui,
                rule_scope_service_driven,
                routing_stop_policy,
                cache_refresh_interval_secs,
                enforcement_mode,
                secondary_liveness_window_secs,
                fake_ip_enabled,
                dns_via_secondary,
                dns_fast_answers,
                fake_ip_udp_relay,
                fake_ip_instant_rst,
                allow_user_rule_edits,
            }),
        ),
        (
            "ApplyFailurePolicyRecord",
            fields_of!(ApplyFailurePolicyRecord {
                policy,
                set_by_sid,
                set_at,
            }),
        ),
        (
            "RetentionSettings",
            fields_of!(RetentionSettings {
                superseded_days,
                superseded_count_cap,
                rejected_days,
                rolledback_days,
                rolledback_count_cap,
                pin_lkg,
                last_cleanup_at,
                updated_at,
            }),
        ),
        (
            "LogRetentionConfig",
            fields_of!(LogRetentionConfig {
                log_max_age_days,
                log_max_size_bytes,
                audit_max_age_days,
                audit_max_size_bytes,
                updated_at,
            }),
        ),
        (
            "TrafficStatsSettings",
            fields_of!(TrafficStatsSettings {
                enabled,
                count_loopback,
                count_virtual,
                retention_days,
                updated_at,
            }),
        ),
        (
            "AutostartStateRecord",
            fields_of!(AutostartStateRecord {
                enabled,
                last_known_state,
                updated_at,
            }),
        ),
        (
            "DohResolverEntry",
            fields_of!(DohResolverEntry {
                target,
                comment,
                enabled,
            }),
        ),
        (
            "RoutePolicyRecord",
            fields_of!(RoutePolicyRecord {
                primary,
                secondary,
                mode,
                leak_protection,
                kill_switch_protocols,
                allow_dns_over_primary,
                primary_probe_auto,
                primary_probe_timeout_ms,
                primary_probe_max_targets,
                primary_probe_repeat_secs,
                local_networks_auto_accept,
                zone_priority_over_ip,
                short_name_completion,
                short_name_suffix,
                app_rules_take_all_addresses,
                forwarded_outage,
                external_address_auto_check,
                include_subdomains,
                shared_ip_policy,
                resolve_hosts_bypass,
                doh_lockdown_enabled,
                doh_lockdown_scope,
                doh_lockdown_auto,
                browser_history_auto_seed,
                kill_switch_strict_shared_ips,
                auto_rules_mode,
                auto_rules_eager_delivery_names,
                binding_source,
            }),
        ),
        (
            "InstallPolicy",
            fields_of!(InstallPolicy {
                secondary_unset,
                default_route_mode,
                default_leak_protection,
            }),
        ),
        (
            "RoutingPauseRecord",
            fields_of!(RoutingPauseRecord {
                sid,
                paused,
                paused_at,
                pause_reason,
                updated_at,
                end,
            }),
        ),
    ]
}

// ── Evidence vocabulary ──────────────────────────────────────────────────────

/// A repo-relative file (or directory, for absence checks) and the code it
/// must, or must not, contain.
type Link = (&'static str, &'static str);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Os {
    Windows,
    Linux,
}

impl Os {
    const ALL: [Os; 2] = [Os::Windows, Os::Linux];

    /// Code only this OS's service builds.
    fn own_roots(self) -> &'static [&'static str] {
        match self {
            Os::Windows => &[
                "core/services/windows-service/src",
                "core/platform/windows/src",
            ],
            Os::Linux => &["core/services/linux-service/src", "core/platform/linux/src"],
        }
    }

    fn profile(self) -> PlatformProfile {
        match self {
            Os::Windows => PlatformProfile::windows(),
            Os::Linux => PlatformProfile::linux(),
        }
    }
}

enum Cell {
    /// The service reads it on this OS.
    Read(Vec<Link>),
    /// Hidden on this OS by a `supports` key that is `false` there.
    Unsupported(&'static str),
    /// Stored and offered, yet nothing on this OS acts on it.
    #[allow(dead_code)] // no such setting today; the next one lands here
    Gap {
        reason: &'static str,
        present: Vec<Link>,
        absent: Vec<Link>,
    },
}

struct Setting {
    store: &'static str,
    field: &'static str,
    windows: Cell,
    linux: Cell,
}

impl Setting {
    fn cell(&self, os: Os) -> &Cell {
        match os {
            Os::Windows => &self.windows,
            Os::Linux => &self.linux,
        }
    }
}

// ── Wiring anchors ───────────────────────────────────────────────────────────

const WIN_RUNTIME: Link = (
    "core/services/windows-service/src/runtime_deps/build.rs",
    "boot_settings::read_boot_settings(",
);
const LNX_RUNTIME: Link = (
    "core/services/linux-service/src/runtime_deps.rs",
    "boot_settings::read_boot_settings(",
);
const WIN_PLAN: Link = (
    "core/services/windows-service/src/runtime_deps/per_sid_apply.rs",
    "nrr_service_runtime::per_sid_orchestrator::KillSwitchResolver",
);
const WIN_COORDINATOR: Link = (
    "core/services/windows-service/src/runtime_deps/per_sid_apply.rs",
    "SecondaryRouteCoordinator::new(",
);
const LNX_PLAN: Link = (
    "core/services/linux-service/src/runtime_deps.rs",
    "ProductionPrincipalPlanSource::new(",
);
const WIN_POLICY_SOURCE: Link = (
    "core/services/windows-service/src/runtime_deps/per_sid_apply.rs",
    "ProductionRoutePolicySource::new(",
);
const LNX_POLICY_SOURCE: Link = (
    "core/services/linux-service/src/runtime_deps.rs",
    "ProductionRoutePolicySource::new(",
);
const WIN_STABILITY_PROVIDER: Link = (
    "core/services/windows-service/src/runtime_deps/ipc_surface.rs",
    ".with_service_stability(",
);
const LNX_STABILITY_PROVIDER: Link = (
    "core/services/linux-service/src/ipc_deps.rs",
    "deps.with_service_stability(",
);
const WIN_DNS_STACK: Link = (
    "core/services/windows-service/src/runtime_deps/dns_stack.rs",
    "nrr_service_runtime::dns_stack::build_dns_resolver_factory(",
);
const LNX_DNS_STACK: Link = (
    "core/services/linux-service/src/dns_stack.rs",
    "nrr_service_runtime::dns_stack::build_dns_resolver_factory(",
);
const WIN_RULES_PROVIDER: Link = (
    "core/services/windows-service/src/runtime_deps/per_sid_apply.rs",
    "ProductionRulesProvider::new(",
);
const LNX_RULES_PROVIDER: Link = (
    "core/services/linux-service/src/runtime_deps.rs",
    "ProductionRulesProvider::new(",
);
const WIN_STATE_DB_FOR_TASKS: Link = (
    "core/services/windows-service/src/runtime_deps/build.rs",
    "state_db_conn: settings_conn",
);
const LNX_STATE_DB_FOR_TASKS: Link = (
    "core/services/linux-service/src/runtime_deps.rs",
    "state_db_conn: state_conn.clone()",
);
const WIN_TRAFFIC_TICK: Link = (
    "core/services/windows-service/src/runtime_deps/build.rs",
    "let traffic_tick = match",
);
const LNX_TRAFFIC_TICK: Link = (
    "core/services/linux-service/src/runtime_deps.rs",
    "traffic_tick: traffic_tick(",
);
const WIN_AUTOSTART: Link = (
    "core/services/windows-service/src/runtime_deps/ipc_surface.rs",
    "ProductionAutostart::new(",
);
const LNX_AUTOSTART: Link = (
    "core/services/linux-service/src/ipc_deps.rs",
    "ProductionAutostart::new(",
);
const MISC_HANDLERS: &str = "core/services/service-runtime/src/production_handlers_misc.rs";
const WIN_IPC_SURFACE: &str = "core/services/windows-service/src/runtime_deps/ipc_surface.rs";
const LNX_IPC_DEPS: &str = "core/services/linux-service/src/ipc_deps.rs";
const WIN_STORAGE_READS: &str = "core/services/windows-service/src/runtime_deps/storage_reads.rs";
const WIN_PER_SID_APPLY: &str = "core/services/windows-service/src/runtime_deps/per_sid_apply.rs";
const LNX_RUNTIME_DEPS: &str = "core/services/linux-service/src/runtime_deps.rs";
const LNX_DNS_STACK_FILE: &str = "core/services/linux-service/src/dns_stack.rs";
const WIN_PLAN_FILE: &str = "core/services/service-runtime/src/per_sid_orchestrator/plan.rs";
const LNX_PLAN_FILE: &str = "core/services/service-runtime/src/production_principal_plan.rs";
const EXTERNAL_ADDRESS: &str = "core/services/service-runtime/src/secondary_external_address.rs";
const CONN_TRACE_HANDLER: &str =
    "core/services/service-runtime/src/ipc_handlers/diagnostics_handlers/conn_trace.rs";

// ── The table ────────────────────────────────────────────────────────────────

const STABILITY_HIDDEN_ON_LINUX: &str = "serviceStabilityConfig";

fn settings() -> Vec<Setting> {
    use Cell::*;
    vec![
        // ── ServiceStabilityConfigRecord (machine-wide) ──
        Setting {
            store: "ServiceStabilityConfigRecord",
            field: "ipc_accept_policy",
            windows: Read(vec![
                (
                    "core/services/service-runtime/src/boot_settings.rs",
                    "match record.ipc_accept_policy",
                ),
                WIN_RUNTIME,
            ]),
            linux: Read(vec![
                (
                    "core/services/service-runtime/src/boot_settings.rs",
                    "match record.ipc_accept_policy",
                ),
                LNX_RUNTIME,
            ]),
        },
        Setting {
            store: "ServiceStabilityConfigRecord",
            field: "verbose_until_ms",
            windows: Read(vec![
                (
                    "core/services/service-runtime/src/verbose_logging.rs",
                    "probe_verbose_until(&conn)",
                ),
                (
                    "core/services/windows-service/src/main.rs",
                    "verbose_logging::verbose_at_boot(",
                ),
            ]),
            linux: Read(vec![
                (
                    "core/services/service-runtime/src/verbose_logging.rs",
                    "probe_verbose_until(&conn)",
                ),
                (
                    "core/services/linux-service/src/run.rs",
                    "verbose_logging::verbose_at_boot(",
                ),
            ]),
        },
        Setting {
            store: "ServiceStabilityConfigRecord",
            field: "conn_trace_ndjson_until_ms",
            windows: Read(vec![
                (
                    "core/services/service-runtime/src/boot_settings.rs",
                    "r.conn_trace_ndjson_until_ms",
                ),
                (
                    "core/services/windows-service/src/runtime_deps/ipc_surface.rs",
                    "ConnTraceLogSwitch::at_boot(",
                ),
            ]),
            linux: Read(vec![
                (
                    "core/services/service-runtime/src/boot_settings.rs",
                    "r.conn_trace_ndjson_until_ms",
                ),
                (
                    "core/services/linux-service/src/runtime_deps.rs",
                    "ConnTraceLogSwitch::at_boot(",
                ),
            ]),
        },
        Setting {
            store: "ServiceStabilityConfigRecord",
            field: "conn_trace_gui",
            windows: Read(vec![
                (CONN_TRACE_HANDLER, "s.get().conn_trace_gui"),
                (
                    "core/services/service-runtime/src/ipc_handlers/registration.rs",
                    "handler.with_gui_stream_gate(settings)",
                ),
                WIN_STABILITY_PROVIDER,
            ]),
            linux: Read(vec![
                (CONN_TRACE_HANDLER, "s.get().conn_trace_gui"),
                (
                    "core/services/service-runtime/src/ipc_handlers/registration.rs",
                    "handler.with_gui_stream_gate(settings)",
                ),
                LNX_STABILITY_PROVIDER,
            ]),
        },
        Setting {
            store: "ServiceStabilityConfigRecord",
            field: "rule_scope_service_driven",
            windows: Read(vec![(WIN_PER_SID_APPLY, "r.rule_scope_service_driven")]),
            linux: Unsupported(STABILITY_HIDDEN_ON_LINUX),
        },
        Setting {
            store: "ServiceStabilityConfigRecord",
            field: "routing_stop_policy",
            windows: Read(vec![(WIN_STORAGE_READS, "r.routing_stop_policy")]),
            linux: Unsupported(STABILITY_HIDDEN_ON_LINUX),
        },
        Setting {
            store: "ServiceStabilityConfigRecord",
            field: "cache_refresh_interval_secs",
            windows: Read(vec![(
                "core/services/windows-service/src/runtime_deps/build.rs",
                "r.cache_refresh_interval_secs",
            )]),
            linux: Unsupported(STABILITY_HIDDEN_ON_LINUX),
        },
        Setting {
            store: "ServiceStabilityConfigRecord",
            field: "enforcement_mode",
            windows: Read(vec![
                (
                    "core/services/service-runtime/src/dns_stack.rs",
                    "record.enforcement_mode",
                ),
                (
                    "core/services/windows-service/src/runtime_deps/build.rs",
                    "dns_stack::persisted_enforcement_mode(",
                ),
            ]),
            linux: Read(vec![
                (
                    "core/services/service-runtime/src/dns_stack.rs",
                    "record.enforcement_mode",
                ),
                (
                    "core/services/linux-service/src/runtime_deps.rs",
                    "dns_stack::persisted_enforcement_mode(",
                ),
            ]),
        },
        Setting {
            store: "ServiceStabilityConfigRecord",
            field: "secondary_liveness_window_secs",
            windows: Read(vec![(
                "core/services/windows-service/src/runtime_deps/build.rs",
                "rec.secondary_liveness_window_secs",
            )]),
            linux: Read(vec![(
                LNX_RUNTIME_DEPS,
                "config.secondary_liveness_window_secs",
            )]),
        },
        Setting {
            store: "ServiceStabilityConfigRecord",
            field: "fake_ip_enabled",
            windows: Read(vec![(WIN_STORAGE_READS, "record.fake_ip_enabled")]),
            linux: Unsupported("fakeIp"),
        },
        Setting {
            store: "ServiceStabilityConfigRecord",
            field: "dns_via_secondary",
            windows: Read(vec![(WIN_STORAGE_READS, "record.dns_via_secondary")]),
            linux: Unsupported(STABILITY_HIDDEN_ON_LINUX),
        },
        Setting {
            store: "ServiceStabilityConfigRecord",
            field: "dns_fast_answers",
            windows: Read(vec![(WIN_STORAGE_READS, "record.dns_fast_answers")]),
            linux: Unsupported(STABILITY_HIDDEN_ON_LINUX),
        },
        Setting {
            store: "ServiceStabilityConfigRecord",
            field: "fake_ip_udp_relay",
            windows: Read(vec![(WIN_STORAGE_READS, "record.fake_ip_udp_relay")]),
            linux: Unsupported("fakeIp"),
        },
        Setting {
            store: "ServiceStabilityConfigRecord",
            field: "fake_ip_instant_rst",
            windows: Read(vec![(WIN_STORAGE_READS, "record.fake_ip_instant_rst")]),
            linux: Unsupported("fakeIp"),
        },
        Setting {
            store: "ServiceStabilityConfigRecord",
            field: "allow_user_rule_edits",
            windows: Read(vec![
                (
                    "core/services/service-runtime/src/ipc_handlers/providers.rs",
                    "allow_user_rule_edits.unwrap_or(true)",
                ),
                (
                    "core/services/service-runtime/src/ipc_handlers/mutation_submit.rs",
                    "rule_edits_allowed_for(self.stability",
                ),
                WIN_STABILITY_PROVIDER,
            ]),
            linux: Read(vec![
                (
                    "core/services/service-runtime/src/ipc_handlers/providers.rs",
                    "allow_user_rule_edits.unwrap_or(true)",
                ),
                (
                    "core/services/service-runtime/src/ipc_handlers/mutation_submit.rs",
                    "rule_edits_allowed_for(self.stability",
                ),
                LNX_STABILITY_PROVIDER,
            ]),
        },
        // ── ApplyFailurePolicyRecord (machine-wide) ──
        Setting {
            store: "ApplyFailurePolicyRecord",
            field: "policy",
            windows: Read(vec![
                (
                    WIN_PER_SID_APPLY,
                    "ApplyFailurePolicySettingsRepository::new(&guard)",
                ),
                (
                    "core/services/windows-service/src/runtime_deps/storage_integrity.rs",
                    "ApplyFailurePolicy::from_slug(&slug)",
                ),
            ]),
            linux: Read(vec![
                (
                    LNX_IPC_DEPS,
                    "ApplyFailurePolicySettingsRepository::new(&guard)",
                ),
                (LNX_IPC_DEPS, "ApplyFailurePolicy::from_slug(&slug)"),
            ]),
        },
        // ── RetentionSettings (machine-wide, rule revisions) ──
        retention("superseded_days", "settings.superseded_days"),
        retention("superseded_count_cap", "settings.superseded_count_cap"),
        retention("rejected_days", "settings.rejected_days"),
        retention("rolledback_days", "settings.rolledback_days"),
        retention("rolledback_count_cap", "settings.rolledback_count_cap"),
        retention("pin_lkg", "settings.pin_lkg"),
        // ── LogRetentionConfig (machine-wide) ──
        log_retention("log_max_age_days", "cfg.log_max_age_days"),
        log_retention("log_max_size_bytes", "cfg.log_max_size_bytes"),
        log_retention("audit_max_age_days", "cfg.audit_max_age_days"),
        log_retention("audit_max_size_bytes", "cfg.audit_max_size_bytes"),
        // ── TrafficStatsSettings (machine-wide) ──
        traffic("enabled", "cfg.enabled"),
        traffic("count_loopback", "cfg.count_loopback"),
        traffic("count_virtual", "cfg.count_virtual"),
        traffic("retention_days", "cfg.retention_days"),
        // ── AutostartStateRecord ──
        Setting {
            store: "AutostartStateRecord",
            field: "enabled",
            windows: Read(vec![
                (
                    "core/services/service-runtime/src/production_settings.rs",
                    "enabled: rec.enabled",
                ),
                WIN_AUTOSTART,
            ]),
            linux: Read(vec![
                (
                    "core/services/service-runtime/src/production_settings.rs",
                    "enabled: rec.enabled",
                ),
                LNX_AUTOSTART,
            ]),
        },
        // ── DohResolverEntry (shared baseline list) ──
        Setting {
            store: "DohResolverEntry",
            field: "target",
            windows: Read(vec![
                (
                    "core/services/service-runtime/src/production_handlers_misc.rs",
                    "match entry.target",
                ),
                WIN_POLICY_SOURCE,
            ]),
            linux: Read(vec![
                (
                    "core/services/service-runtime/src/production_handlers_misc.rs",
                    "match entry.target",
                ),
                LNX_POLICY_SOURCE,
            ]),
        },
        Setting {
            store: "DohResolverEntry",
            field: "enabled",
            windows: Read(vec![
                (
                    "core/services/service-runtime/src/production_handlers_misc.rs",
                    ".filter(|e| e.enabled)",
                ),
                WIN_POLICY_SOURCE,
            ]),
            linux: Read(vec![
                (
                    "core/services/service-runtime/src/production_handlers_misc.rs",
                    ".filter(|e| e.enabled)",
                ),
                LNX_POLICY_SOURCE,
            ]),
        },
        // ── RoutePolicyRecord (per user) ──
        Setting {
            store: "RoutePolicyRecord",
            field: "primary",
            windows: Read(vec![
                (
                    "core/services/service-runtime/src/route_coordinator/resolve.rs",
                    "r.primary.map(|t| t.interface_index)",
                ),
                WIN_COORDINATOR,
            ]),
            linux: Read(vec![(LNX_PLAN_FILE, "policy.primary.as_ref()"), LNX_PLAN]),
        },
        Setting {
            store: "RoutePolicyRecord",
            field: "secondary",
            windows: Read(vec![
                (
                    "core/services/service-runtime/src/route_coordinator/resolve.rs",
                    "self.resolve(sid).secondary",
                ),
                WIN_COORDINATOR,
            ]),
            linux: Read(vec![(LNX_PLAN_FILE, "policy.secondary.as_ref()"), LNX_PLAN]),
        },
        Setting {
            store: "RoutePolicyRecord",
            field: "mode",
            windows: Read(vec![
                (
                    "core/services/service-runtime/src/per_sid_orchestrator/compute.rs",
                    "match policy.mode",
                ),
                WIN_PLAN,
            ]),
            linux: Read(vec![(LNX_PLAN_FILE, "behavior_mode_for_codegen"), LNX_PLAN]),
        },
        plan_read("leak_protection", "policy.leak_protection"),
        plan_read("kill_switch_protocols", "policy.kill_switch_protocols"),
        plan_read("allow_dns_over_primary", "policy.allow_dns_over_primary"),
        plan_read("zone_priority_over_ip", "policy.zone_priority_over_ip"),
        plan_read(
            "app_rules_take_all_addresses",
            "policy.app_rules_take_all_addresses",
        ),
        plan_read("shared_ip_policy", "policy.shared_ip_policy"),
        plan_read("doh_lockdown_enabled", "policy.doh_lockdown_enabled"),
        plan_read("doh_lockdown_scope", "policy.doh_lockdown_scope"),
        plan_read("doh_lockdown_auto", "policy.doh_lockdown_auto"),
        plan_read(
            "kill_switch_strict_shared_ips",
            "policy.kill_switch_strict_shared_ips",
        ),
        Setting {
            store: "RoutePolicyRecord",
            field: "primary_probe_auto",
            windows: Read(vec![(WIN_PER_SID_APPLY, "record.primary_probe_auto")]),
            linux: Read(vec![(LNX_RUNTIME_DEPS, "record.primary_probe_auto")]),
        },
        Setting {
            store: "RoutePolicyRecord",
            field: "primary_probe_timeout_ms",
            windows: Read(vec![(WIN_IPC_SURFACE, "record.primary_probe_timeout_ms")]),
            linux: Read(vec![(LNX_IPC_DEPS, "record.primary_probe_timeout_ms")]),
        },
        Setting {
            store: "RoutePolicyRecord",
            field: "primary_probe_max_targets",
            windows: Read(vec![(WIN_IPC_SURFACE, "record.primary_probe_max_targets")]),
            linux: Read(vec![(LNX_IPC_DEPS, "record.primary_probe_max_targets")]),
        },
        Setting {
            store: "RoutePolicyRecord",
            field: "primary_probe_repeat_secs",
            windows: Read(vec![(WIN_IPC_SURFACE, "record.primary_probe_repeat_secs")]),
            linux: Read(vec![(LNX_IPC_DEPS, "record.primary_probe_repeat_secs")]),
        },
        Setting {
            store: "RoutePolicyRecord",
            field: "local_networks_auto_accept",
            windows: Read(vec![
                (
                    "core/services/service-runtime/src/production_local_networks.rs",
                    "policy.local_networks_auto_accept",
                ),
                (
                    "core/services/windows-service/src/runtime_deps/ipc_surface.rs",
                    "ProductionLocalNetworks::new(",
                ),
            ]),
            linux: Read(vec![
                (
                    "core/services/service-runtime/src/local_network_source.rs",
                    "policy.local_networks_auto_accept",
                ),
                (
                    "core/services/linux-service/src/ipc_deps.rs",
                    "ProductionLocalNetworks::new(",
                ),
            ]),
        },
        Setting {
            store: "RoutePolicyRecord",
            field: "forwarded_outage",
            windows: Read(vec![
                (
                    "core/services/service-runtime/src/production_handlers_misc.rs",
                    "guard_forwarded_traffic: record.forwarded_outage",
                ),
                (
                    WIN_PLAN_FILE,
                    "guard_forwarded: policy.guard_forwarded_traffic",
                ),
                WIN_PLAN,
            ]),
            linux: Read(vec![
                (LNX_PLAN_FILE, "if policy.guard_forwarded_traffic"),
                LNX_PLAN,
            ]),
        },
        Setting {
            store: "RoutePolicyRecord",
            field: "external_address_auto_check",
            windows: Read(vec![
                (EXTERNAL_ADDRESS, "record.external_address_auto_check"),
                (
                    "core/services/windows-service/src/runtime_deps/build.rs",
                    "secondary_external_address::stored_opt_in(",
                ),
            ]),
            linux: Read(vec![
                (EXTERNAL_ADDRESS, "record.external_address_auto_check"),
                (LNX_RUNTIME_DEPS, "opted_in: stored_opt_in("),
            ]),
        },
        Setting {
            store: "RoutePolicyRecord",
            field: "short_name_completion",
            windows: Read(vec![
                (
                    "core/services/service-runtime/src/short_name_suffixes.rs",
                    "policy.short_name_completion",
                ),
                (
                    "core/services/service-runtime/src/dns_stack.rs",
                    "listener.with_short_name_suffix(",
                ),
                WIN_DNS_STACK,
            ]),
            linux: Read(vec![
                (
                    "core/services/service-runtime/src/short_name_suffixes.rs",
                    "policy.short_name_completion",
                ),
                (
                    "core/services/service-runtime/src/dns_stack.rs",
                    "listener.with_short_name_suffix(",
                ),
                LNX_DNS_STACK,
            ]),
        },
        Setting {
            store: "RoutePolicyRecord",
            field: "short_name_suffix",
            windows: Read(vec![
                (
                    "core/services/service-runtime/src/short_name_suffixes.rs",
                    "policy.short_name_suffix.clone()",
                ),
                (
                    "core/services/service-runtime/src/dns_stack.rs",
                    "listener.with_short_name_suffix(",
                ),
                WIN_DNS_STACK,
            ]),
            linux: Read(vec![
                (
                    "core/services/service-runtime/src/short_name_suffixes.rs",
                    "policy.short_name_suffix.clone()",
                ),
                (
                    "core/services/service-runtime/src/dns_stack.rs",
                    "listener.with_short_name_suffix(",
                ),
                LNX_DNS_STACK,
            ]),
        },
        Setting {
            store: "RoutePolicyRecord",
            field: "include_subdomains",
            windows: Read(vec![
                (
                    "core/services/service-runtime/src/production_rules_provider.rs",
                    "Self::reads_include_subdomains(&guard, principal)",
                ),
                WIN_RULES_PROVIDER,
            ]),
            linux: Read(vec![
                (
                    "core/services/service-runtime/src/production_rules_provider.rs",
                    "Self::reads_include_subdomains(&guard, principal)",
                ),
                LNX_RULES_PROVIDER,
            ]),
        },
        Setting {
            store: "RoutePolicyRecord",
            field: "resolve_hosts_bypass",
            windows: Read(vec![
                (
                    "core/services/service-runtime/src/hosts_bypass.rs",
                    "record.resolve_hosts_bypass",
                ),
                (
                    "core/services/windows-service/src/runtime_deps/dns_stack.rs",
                    "stored_bypass_wanted_by_any(",
                ),
            ]),
            linux: Read(vec![
                (
                    "core/services/service-runtime/src/hosts_bypass.rs",
                    "record.resolve_hosts_bypass",
                ),
                (LNX_RUNTIME_DEPS, "stored_bypass_wanted_by_any("),
                (LNX_DNS_STACK_FILE, "HostsBypassDnsResolver::new("),
            ]),
        },
        Setting {
            store: "RoutePolicyRecord",
            field: "browser_history_auto_seed",
            windows: Read(vec![(WIN_IPC_SURFACE, "r.browser_history_auto_seed")]),
            linux: Read(vec![(LNX_IPC_DEPS, "record.browser_history_auto_seed")]),
        },
        Setting {
            store: "RoutePolicyRecord",
            field: "auto_rules_mode",
            windows: Read(vec![(WIN_PER_SID_APPLY, "record.auto_rules_mode")]),
            linux: Read(vec![(LNX_RUNTIME_DEPS, "record.auto_rules_mode")]),
        },
        Setting {
            store: "RoutePolicyRecord",
            field: "auto_rules_eager_delivery_names",
            windows: Read(vec![(
                WIN_PER_SID_APPLY,
                "record.auto_rules_eager_delivery_names",
            )]),
            linux: Read(vec![(
                LNX_RUNTIME_DEPS,
                "record.auto_rules_eager_delivery_names",
            )]),
        },
        // ── RoutingPauseRecord (per user) ──
        Setting {
            store: "RoutingPauseRecord",
            field: "paused",
            windows: Read(vec![(
                WIN_PER_SID_APPLY,
                "nrr_storage::pause_state::RoutingPauseStateRepository::new(&g)",
            )]),
            // The pass leaves a paused user out, and the pause dispatcher is
            // that pass.
            linux: Read(vec![
                (LNX_RUNTIME_DEPS, "RoutingPauseStateRepository::new(&guard)"),
                (LNX_IPC_DEPS, "CyclePauseDispatcher"),
                (
                    "core/services/service-runtime/src/principal_enforcement.rs",
                    "with_paused_principals",
                ),
            ]),
        },
        // A timed pause is lifted by the term tick both platforms spawn.
        Setting {
            store: "RoutingPauseRecord",
            field: "end",
            windows: Read(vec![
                (
                    "core/services/service-runtime/src/routing_pause.rs",
                    "list_ended(now_ms, at_start)",
                ),
                (
                    "core/services/windows-service/src/runtime_deps/build.rs",
                    "RoutingPauseTerms::new",
                ),
            ]),
            linux: Read(vec![
                (
                    "core/services/service-runtime/src/routing_pause.rs",
                    "list_ended(now_ms, at_start)",
                ),
                (
                    "core/services/linux-service/src/ipc_deps.rs",
                    "RoutingPauseTerms::new",
                ),
            ]),
        },
        // ── InstallPolicy (machine-wide, written at the first start) ──
        Setting {
            store: "InstallPolicy",
            field: "secondary_unset",
            windows: Read(vec![
                (MISC_HANDLERS, "fn secondary_unset_blocks("),
                WIN_POLICY_SOURCE,
            ]),
            linux: Read(vec![
                (MISC_HANDLERS, "fn secondary_unset_blocks("),
                LNX_POLICY_SOURCE,
            ]),
        },
        Setting {
            store: "InstallPolicy",
            field: "default_route_mode",
            windows: Read(vec![
                (MISC_HANDLERS, "fn apply_install_default_mode("),
                (WIN_IPC_SURFACE, "ProductionRoutePolicyWriter::new("),
            ]),
            linux: Read(vec![
                (MISC_HANDLERS, "fn apply_install_default_mode("),
                (LNX_IPC_DEPS, "ProductionRoutePolicyWriter::new("),
            ]),
        },
        Setting {
            store: "InstallPolicy",
            field: "default_leak_protection",
            windows: Read(vec![
                (MISC_HANDLERS, "fn apply_install_default_mode("),
                (WIN_IPC_SURFACE, "ProductionRoutePolicyWriter::new("),
            ]),
            linux: Read(vec![
                (MISC_HANDLERS, "fn apply_install_default_mode("),
                (LNX_IPC_DEPS, "ProductionRoutePolicyWriter::new("),
            ]),
        },
    ]
}

fn retention(field: &'static str, needle: &'static str) -> Setting {
    // The prune task the supervisor spawns whenever it holds the state DB.
    let chain = |anchor: Link| {
        vec![
            ("core/storage/src/revisions/retention.rs", needle),
            (
                "core/services/service-runtime/src/service_tasks/maintenance.rs",
                "prune_by_retention(&settings",
            ),
            (
                "core/services/service-runtime/src/supervised_runtime.rs",
                "build_revisions_retention_task(Arc::clone(conn))",
            ),
            anchor,
        ]
    };
    Setting {
        store: "RetentionSettings",
        field,
        windows: Cell::Read(chain(WIN_STATE_DB_FOR_TASKS)),
        linux: Cell::Read(chain(LNX_STATE_DB_FOR_TASKS)),
    }
}

fn log_retention(field: &'static str, needle: &'static str) -> Setting {
    let chain = |anchor: Link| {
        vec![
            ("core/services/service-runtime/src/boot_settings.rs", needle),
            anchor,
        ]
    };
    Setting {
        store: "LogRetentionConfig",
        field,
        windows: Cell::Read(chain(WIN_RUNTIME)),
        linux: Cell::Read(chain(LNX_RUNTIME)),
    }
}

fn traffic(field: &'static str, needle: &'static str) -> Setting {
    let chain = |anchor: Link| {
        vec![
            (
                "core/services/service-runtime/src/service_tasks/routing.rs",
                needle,
            ),
            (
                "core/services/service-runtime/src/supervised_runtime.rs",
                "deps.traffic_tick.clone()",
            ),
            anchor,
        ]
    };
    Setting {
        store: "TrafficStatsSettings",
        field,
        windows: Cell::Read(chain(WIN_TRAFFIC_TICK)),
        linux: Cell::Read(chain(LNX_TRAFFIC_TICK)),
    }
}

/// A per-user field both planners read as `policy.<field>`.
fn plan_read(field: &'static str, needle: &'static str) -> Setting {
    Setting {
        store: "RoutePolicyRecord",
        field,
        windows: Cell::Read(vec![(WIN_PLAN_FILE, needle), WIN_PLAN]),
        linux: Cell::Read(vec![(LNX_PLAN_FILE, needle), LNX_PLAN]),
    }
}

/// Fields that record who, when or what for display; no OS acts on them.
const BOOKKEEPING: &[(&str, &str)] = &[
    ("ServiceStabilityConfigRecord", "set_by_sid"),
    ("ServiceStabilityConfigRecord", "updated_at"),
    ("ApplyFailurePolicyRecord", "set_by_sid"),
    ("ApplyFailurePolicyRecord", "set_at"),
    ("RetentionSettings", "last_cleanup_at"),
    ("RetentionSettings", "updated_at"),
    ("LogRetentionConfig", "updated_at"),
    ("TrafficStatsSettings", "updated_at"),
    // The OS state observed at the last write, reported next to the intent.
    ("AutostartStateRecord", "last_known_state"),
    ("AutostartStateRecord", "updated_at"),
    ("DohResolverEntry", "comment"),
    // How the binding was made (by the user or healed), shown, not enforced.
    ("RoutePolicyRecord", "binding_source"),
    // The row's key and the "since / why" of a pause, shown to the user.
    ("RoutingPauseRecord", "sid"),
    ("RoutingPauseRecord", "paused_at"),
    ("RoutingPauseRecord", "pause_reason"),
    ("RoutingPauseRecord", "updated_at"),
];

// ── Capability flags ─────────────────────────────────────────────────────────

enum Cap {
    /// The flag is `true` and this is the mechanism behind it.
    Backed(Vec<Link>),
    /// The flag is `false` and nothing claims otherwise.
    NotOffered,
}

struct Capability {
    key: &'static str,
    windows: Cap,
    linux: Cap,
}

fn capabilities() -> Vec<Capability> {
    use Cap::*;
    vec![
        Capability {
            key: "killSwitch",
            windows: Backed(vec![WIN_PLAN]),
            linux: Backed(vec![(LNX_PLAN_FILE, "fn fail_closed_flows("), LNX_PLAN]),
        },
        Capability {
            key: "appRouting",
            windows: Backed(vec![
                (
                    "core/services/windows-service/src/runtime_deps/build.rs",
                    "app_observation_lookup::global_app_observations()",
                ),
                (
                    "core/platform/windows/src/win32_ffi/wfp_filter.rs",
                    "fieldKey: FWPM_CONDITION_ALE_APP_ID",
                ),
            ]),
            linux: Backed(vec![(
                LNX_RUNTIME_DEPS,
                "conn_observe::ProcfsConnectionObserver::new()",
            )]),
        },
        Capability {
            key: "dnsObserve",
            windows: Backed(vec![(
                "core/services/windows-service/src/runtime_deps/build.rs",
                "nrr_platform_windows::dns_observe::DnsObservationSource",
            )]),
            linux: Backed(vec![(
                "core/services/linux-service/src/run.rs",
                "policy_stack.as_ref().and_then(build_dns_observation)",
            )]),
        },
        Capability {
            key: "dnsResolver",
            windows: Backed(vec![WIN_DNS_STACK]),
            linux: Backed(vec![LNX_DNS_STACK]),
        },
        Capability {
            key: "fakeIp",
            windows: Backed(vec![(
                "core/services/windows-service/src/runtime_deps/build.rs",
                "nrr_service_runtime::fake_ip::",
            )]),
            linux: NotOffered,
        },
        Capability {
            key: "hostsPin",
            windows: Backed(vec![(
                "core/services/windows-service/src/runtime_deps/dns_stack.rs",
                "dns_resolver_ports::HostsBypassDnsResolver::new(",
            )]),
            linux: Backed(vec![(LNX_DNS_STACK_FILE, "HostsBypassDnsResolver::new(")]),
        },
        Capability {
            key: "backgroundService",
            windows: Backed(vec![(
                "core/services/windows-service/src/scm.rs",
                "define_windows_service!(ffi_service_main",
            )]),
            linux: Backed(vec![(
                "core/services/linux-service/src/run.rs",
                "NotifyState::Ready",
            )]),
        },
        Capability {
            key: "autostart",
            windows: Backed(vec![WIN_AUTOSTART]),
            linux: Backed(vec![LNX_AUTOSTART]),
        },
        Capability {
            key: "serviceStabilityConfig",
            windows: Backed(vec![(
                WIN_STORAGE_READS,
                "ServiceStabilityConfigRepository::new(&guard)",
            )]),
            linux: NotOffered,
        },
        Capability {
            key: "verboseLogging",
            windows: Backed(vec![(
                "core/services/windows-service/src/main.rs",
                "verbose_logging::verbose_at_boot(",
            )]),
            linux: Backed(vec![(
                "core/services/linux-service/src/run.rs",
                "verbose_logging::verbose_at_boot(",
            )]),
        },
        Capability {
            key: "localNetworkExceptions",
            windows: Backed(vec![(
                "core/services/windows-service/src/runtime_deps/ipc_surface.rs",
                "ProductionLocalNetworks::new(",
            )]),
            linux: Backed(vec![(
                "core/services/linux-service/src/ipc_deps.rs",
                "ProductionLocalNetworks::new(",
            )]),
        },
        Capability {
            key: "forwardedTrafficGuard",
            windows: Backed(vec![
                (WIN_PLAN_FILE, "filters.extend(shares.forwarded)"),
                WIN_PLAN,
            ]),
            linux: Backed(vec![
                (
                    LNX_PLAN_FILE,
                    "plan_forwarded_flows_with_foreign(stored, &guard, &foreign)",
                ),
                LNX_PLAN,
            ]),
        },
        Capability {
            key: "blockNotices",
            windows: Backed(vec![(
                WIN_PER_SID_APPLY,
                "block_notice_center::BlockNoticeCenter::new()",
            )]),
            linux: Backed(vec![(
                LNX_RUNTIME_DEPS,
                "block_notice_center::BlockNoticeCenter::new()",
            )]),
        },
        Capability {
            key: "auditChainRestart",
            windows: Backed(vec![(
                "core/services/windows-service/src/runtime_deps/ipc_surface.rs",
                ".with_chain_restart_key(",
            )]),
            linux: Backed(vec![(
                "core/services/linux-service/src/ipc_deps.rs",
                ".with_chain_restart_key(",
            )]),
        },
        Capability {
            key: "connTraceLog",
            windows: Backed(vec![(
                "core/services/windows-service/src/runtime_deps/ipc_surface.rs",
                "ConnTraceLogSwitch::at_boot(",
            )]),
            linux: Backed(vec![(LNX_RUNTIME_DEPS, "ConnTraceLogSwitch::at_boot(")]),
        },
        Capability {
            key: "serviceStartOnAppLaunch",
            windows: Backed(vec![(
                "core/platform/windows/src/service_control.rs",
                "ServiceStartMode::OnAppLaunch => ServiceStartType::OnDemand",
            )]),
            linux: NotOffered,
        },
        Capability {
            key: "perUserRouting",
            windows: NotOffered,
            linux: Backed(vec![(
                "core/platform/linux/src/policy_routing.rs",
                "&[Some((uid, uid))]",
            )]),
        },
        Capability {
            key: "perAppBlockLeakproof",
            windows: Backed(vec![(
                "core/platform/windows/src/win32_ffi/wfp_filter.rs",
                "fieldKey: FWPM_CONDITION_ALE_APP_ID",
            )]),
            linux: NotOffered,
        },
        Capability {
            key: "appPathRules",
            windows: Backed(vec![(
                "core/platform/windows/src/app_path_resolver/windows_impl.rs",
                "self.folders.programs(path, owner)",
            )]),
            linux: Backed(vec![(
                "core/platform/linux/src/app_path_resolver.rs",
                "self.folders.programs(path, owner)",
            )]),
        },
        Capability {
            key: "appPathScripts",
            windows: Backed(vec![
                (
                    "core/services/windows-service/src/runtime_deps/conn_trace.rs",
                    ".with_script_launches(",
                ),
                (
                    "core/platform/windows/src/process_launch.rs",
                    "impl ProcessLaunchReader for WindowsProcessLaunches",
                ),
            ]),
            linux: Backed(vec![
                (
                    "core/services/linux-service/src/runtime_deps/drop_observation.rs",
                    "ScriptLaunches::new(Arc::new(LinuxProcessLaunches))",
                ),
                (
                    "core/platform/linux/src/process_launch.rs",
                    "impl ProcessLaunchReader for LinuxProcessLaunches",
                ),
            ]),
        },
        Capability {
            key: "perUserAllProtocolScoping",
            windows: NotOffered,
            linux: Backed(vec![("core/platform/linux/src/nft_ir.rs", "meta skuid")]),
        },
    ]
}

// ── Source scanning ──────────────────────────────────────────────────────────

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

/// Production code of a file: `//` comments dropped, and everything from an
/// inline `#[cfg(test)] mod … {` on (always the last item in this tree).
fn production_code(body: &str) -> String {
    let lines: Vec<&str> = body.lines().collect();
    let mut kept = String::new();
    for (idx, line) in lines.iter().enumerate() {
        if line.trim() == "#[cfg(test)]" {
            let next = lines[idx + 1..]
                .iter()
                .map(|l| l.trim())
                .find(|l| !l.is_empty() && !l.starts_with("#["))
                .unwrap_or("");
            let inline_mod = ["pub(crate) mod ", "pub mod ", "mod "]
                .iter()
                .find_map(|p| next.strip_prefix(p))
                .is_some_and(|rest| rest.trim_end().ends_with('{'));
            if inline_mod {
                break;
            }
        }
        kept.push_str(line.split("//").next().unwrap_or(""));
        kept.push('\n');
    }
    kept
}

fn is_ident(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// `needle` in `code`, not as the prefix of a longer identifier.
fn contains_code(code: &str, needle: &str) -> bool {
    let ends_in_ident = needle.chars().last().is_some_and(is_ident);
    code.match_indices(needle).any(|(at, _)| {
        !ends_in_ident
            || !code[at + needle.len()..]
                .chars()
                .next()
                .is_some_and(is_ident)
    })
}

fn is_test_file(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    name == "tests.rs"
        || name.ends_with("_tests.rs")
        || path
            .components()
            .any(|c| c.as_os_str() == "tests" || c.as_os_str() == "test_support")
}

fn rust_files(root: &Path, acc: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(root).unwrap_or_else(|e| panic!("read_dir {root:?}: {e}"));
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_files(&path, acc);
        } else if path.extension().and_then(|s| s.to_str()) == Some("rs") && !is_test_file(&path) {
            acc.push(path);
        }
    }
}

/// Whether the production code under `target` (a file or a directory)
/// contains `needle`.
fn found(target: &str, needle: &str) -> bool {
    let path = repo_root().join(target);
    assert!(
        path.exists(),
        "`{target}` does not exist; the table names a moved file"
    );
    let files = if path.is_dir() {
        let mut acc = Vec::new();
        rust_files(&path, &mut acc);
        acc
    } else {
        vec![path]
    };
    files.iter().any(|file| {
        let body = fs::read_to_string(file).unwrap_or_else(|e| panic!("read {file:?}: {e}"));
        contains_code(&production_code(&body), needle)
    })
}

fn is_own(os: Os, file: &str) -> bool {
    os.own_roots().iter().any(|root| file.starts_with(root))
}

fn other(os: Os) -> Os {
    match os {
        Os::Windows => Os::Linux,
        Os::Linux => Os::Windows,
    }
}

/// Problems with a consumer chain for `os`, as messages.
fn check_chain(os: Os, what: &str, chain: &[Link], problems: &mut Vec<String>) {
    if !chain.iter().any(|(file, _)| is_own(os, file)) {
        problems.push(format!(
            "{what} ({os:?}): no link sits in {os:?}'s own crates, so nothing shows that \
             {os:?} builds this reader"
        ));
    }
    for (file, needle) in chain {
        if is_own(other(os), file) {
            problems.push(format!(
                "{what} ({os:?}): `{file}` belongs to {:?}",
                other(os)
            ));
        }
        if !found(file, needle) {
            problems.push(format!(
                "{what} ({os:?}): `{needle}` is gone from `{file}` — the reader moved or \
                 was removed; name the new consumer or record the gap"
            ));
        }
    }
}

fn supports(os: Os) -> serde_json::Map<String, Value> {
    match serde_json::to_value(os.profile().supports) {
        Ok(Value::Object(map)) => map,
        other => panic!("PlatformSupports must serialise to an object, got {other:?}"),
    }
}

fn flag(os: Os, key: &str) -> bool {
    supports(os)
        .get(key)
        .and_then(Value::as_bool)
        .unwrap_or_else(|| panic!("`supports.{key}` is not a boolean flag of PlatformSupports"))
}

/// Whether some QML file gates on `supports("<key>")`.
fn qml_gates_on(key: &str) -> bool {
    let needle = format!("supports(\"{key}\")");
    let mut files = Vec::new();
    collect_qml(&repo_root().join("apps/desktop/qml"), &mut files);
    files.iter().any(|f| {
        fs::read_to_string(f)
            .map(|body| body.contains(&needle))
            .unwrap_or(false)
    })
}

fn collect_qml(root: &Path, acc: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(root).unwrap_or_else(|e| panic!("read_dir {root:?}: {e}"));
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_qml(&path, acc);
        } else if path.extension().and_then(|s| s.to_str()) == Some("qml") {
            acc.push(path);
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[test]
fn every_stored_field_is_classified_exactly_once() {
    let table = settings();
    let mut classified: Vec<(&str, &str)> = table.iter().map(|s| (s.store, s.field)).collect();
    classified.extend(BOOKKEEPING.iter().copied());
    let unique: BTreeSet<(&str, &str)> = classified.iter().copied().collect();
    assert_eq!(
        unique.len(),
        classified.len(),
        "a field is classified twice (settings table and/or BOOKKEEPING)"
    );

    let mut declared = BTreeSet::new();
    for (store, fields) in stored_fields() {
        for field in fields {
            declared.insert((store, field));
        }
    }
    let unclassified: Vec<_> = declared.difference(&unique).collect();
    let unknown: Vec<_> = unique.difference(&declared).collect();
    assert!(
        unclassified.is_empty(),
        "stored fields with no reader named on either OS: {unclassified:?} — add each to \
         settings() with its consumer per OS, the capability that hides it, or a gap"
    );
    assert!(
        unknown.is_empty(),
        "the table names fields the stores do not have: {unknown:?}"
    );
}

#[test]
fn every_stored_setting_is_read_hidden_or_a_listed_gap_on_every_os() {
    let mut problems = Vec::new();
    for setting in settings() {
        let what = format!("{}.{}", setting.store, setting.field);
        for os in Os::ALL {
            match setting.cell(os) {
                Cell::Read(chain) => {
                    check_chain(os, &what, chain, &mut problems);
                }
                Cell::Unsupported(key) => {
                    if flag(os, key) {
                        problems.push(format!(
                            "{what} ({os:?}): said to be hidden by `supports.{key}`, but the \
                             flag is true there — name the reader instead"
                        ));
                    }
                    if !qml_gates_on(key) {
                        problems.push(format!(
                            "{what} ({os:?}): no QML gates on `supports(\"{key}\")`, so \
                             nothing hides the setting"
                        ));
                    }
                }
                Cell::Gap {
                    reason,
                    present,
                    absent,
                } => {
                    for (file, needle) in present {
                        if !found(file, needle) {
                            problems.push(format!(
                                "{what} ({os:?}) is listed as a gap ({reason}), but its \
                                 symptom `{needle}` left `{file}`: if the gap is closed, \
                                 replace the entry with the reader"
                            ));
                        }
                    }
                    for (target, needle) in absent {
                        if found(target, needle) {
                            problems.push(format!(
                                "{what} ({os:?}) is listed as a gap ({reason}), but \
                                 `{target}` now has `{needle}`: if the gap is closed, \
                                 replace the entry with the reader"
                            ));
                        }
                    }
                }
            }
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

#[test]
fn every_capability_flag_matches_what_the_service_wires() {
    let table = capabilities();
    let declared: BTreeSet<String> = supports(Os::Windows).keys().cloned().collect();
    let listed: BTreeSet<String> = table.iter().map(|c| c.key.to_string()).collect();
    assert_eq!(
        listed.len(),
        table.len(),
        "a capability is listed twice in capabilities()"
    );
    assert_eq!(
        declared, listed,
        "capabilities() must list every PlatformSupports flag exactly once"
    );

    let mut problems = Vec::new();
    for cap in &table {
        for os in Os::ALL {
            let state = match os {
                Os::Windows => &cap.windows,
                Os::Linux => &cap.linux,
            };
            let on = flag(os, cap.key);
            let what = format!("supports.{}", cap.key);
            match state {
                Cap::Backed(chain) => {
                    if !on {
                        problems.push(format!(
                            "{what} ({os:?}) is false, but the table names its mechanism — \
                             record why it is hidden"
                        ));
                    }
                    check_chain(os, &what, chain, &mut problems);
                }
                Cap::NotOffered => {
                    if on {
                        problems.push(format!(
                            "{what} ({os:?}) is true with no mechanism named — name it"
                        ));
                    }
                }
            }
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// The scanner itself: a needle that is only a prefix of a longer name, or
/// only in a comment or a test module, does not count.
#[test]
fn the_scanner_reads_production_code_only() {
    let body = "fn f() { policy.mode_selector }\n\
                // policy.mode in a comment\n\
                #[cfg(test)]\n\
                mod tests {\n    fn g() { policy.mode }\n}\n";
    let code = production_code(body);
    assert!(!contains_code(&code, "policy.mode"));
    assert!(contains_code(&code, "policy.mode_selector"));
    assert!(contains_code("x.f(", "x.f("));
}
