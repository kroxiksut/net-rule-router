//! Custom `tracing-subscriber` layer that routes `tracing` events to the
//! operational NDJSON log writer.
//!
//! # Design
//!
//! [`NdjsonTracingLayer`] implements `tracing_subscriber::Layer`.  It converts
//! each `tracing::Event` into a [`LogEvent`] and forwards it to a shared
//! [`LogWriter`] (via `Arc`).
//!
//! # Field mapping
//!
//! | `tracing` concept        | `LogEvent` field   |
//! |--------------------------|--------------------|
//! | `event.metadata().level` | `level`            |
//! | `event.metadata().target`| determines `category` |
//! | `event.metadata().name`  | `kind`             |
//! | custom field `message`   | `payload`          |
//!
//! `target` is mapped to `EventCategory` by prefix:
//! - `nrr::service`   → `Service`
//! - `nrr::decision`  → `Decision`
//! - `nrr::cache`     → `Cache`
//! - `nrr::apply`     → `Apply`
//! - `nrr::integrity` → `Integrity`
//! - `nrr::security`  → `Security`
//! - `nrr::*` (other) → `Service` (fallback for our crates)
//! - non-`nrr::*`     → dropped (third-party crates do not pollute NDJSON)
//!
//! # Localization
//!
//! The layer does NOT translate message text into locale keys — it is the
//! developer-facing tracing system.  User-visible event descriptions are
//! derived from `reason_code` fields, not from `tracing` message strings.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tracing::field::{Field, Visit};
use tracing::span;
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::layer::Context;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::reload;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::Layer;
use tracing_subscriber::Registry;

use crate::event::{rfc3339_local_millis, LogEvent, LOG_EVENT_SCHEMA_VERSION};
use crate::logs::privacy;
use crate::logs::writer::LogWriter;
use crate::sink::DiagnosticsSink;
use crate::taxonomy::{EventCategory, EventCorrelation, EventLevel, PrivacyClass};

// ── Level mapping ─────────────────────────────────────────────────────────────

fn tracing_to_level(level: &tracing::Level) -> EventLevel {
    match *level {
        tracing::Level::TRACE => EventLevel::Trace,
        tracing::Level::DEBUG => EventLevel::Debug,
        tracing::Level::INFO => EventLevel::Info,
        tracing::Level::WARN => EventLevel::Warn,
        tracing::Level::ERROR => EventLevel::Error,
    }
}

// ── Target → Category mapping ─────────────────────────────────────────────────

/// Maps a `tracing` target to an [`EventCategory`].
///
/// Returns `None` for targets that do not start with `nrr::` — those are
/// third-party crate spans/events (rusqlite, mio, hyper, …) and must not
/// appear in the operational NDJSON log. The caller is expected to early-return
/// on `None` before any allocation.
fn target_to_category(target: &str) -> Option<EventCategory> {
    let area = target.strip_prefix("nrr::")?;
    // `-` and `_` are both in use for the same areas (`fake-ip` / `fake_ip`,
    // `dns-resolver` / `dns_resolver`); one spelling here, normalised on the
    // way in.
    let normalized = area.replace('_', "-");
    Some(category_of_area(&normalized))
}

/// Maps a target's area (everything after `nrr::`) to its category.
///
/// The table is the point. Before it, eight prefixes were listed and 56 areas
/// existed, so nearly everything fell through to `Service` — which made the
/// category filter in the Logs section useless and the per-category rate limit
/// unreachable. Adding an area here changes how it is FILTERED, never whether
/// it is written: Default mode silences no category (see `DEFAULT_MODE_SILENCED`).
fn category_of_area(area: &str) -> EventCategory {
    // Nested areas are classified by their full path where the leaf matters.
    match area {
        "mutation::preset" | "mutation::preview" => return EventCategory::Import,
        "mutation::execute" => return EventCategory::Apply,
        _ => {}
    }
    let head = area.split("::").next().unwrap_or(area);
    match head {
        // The decision path and everything that observes traffic to feed it.
        "decision"
        | "dns"
        | "dns-observe"
        | "dns-redirect"
        | "dns-resolver"
        | "doh"
        | "fcrdns"
        | "fake-ip"
        | "conn-observe"
        | "conn-trace"
        | "app-routing"
        | "app-resolver"
        | "app-path-resolver"
        | "persistent-app-resolver"
        | "app-observations"
        | "auto-rules"
        | "browser-history"
        | "vpn-learn"
        | "block-notice" => EventCategory::Decision,

        // Putting policy onto the machine, and taking it off again.
        "enforcement" | "enforcement-plan" | "killswitch" | "killswitch-codegen" | "routes"
        | "route-codegen" | "route-coordinator" | "wfp" | "wfp-codegen" | "wfp-ledger" | "nft"
        | "nftlink" | "activation" | "rules-provider" | "rule-seed" | "apply" => {
            EventCategory::Apply
        }

        "cache" => EventCategory::Cache,

        // State that must be trustworthy, and what happens when it is not.
        "tamper" | "state" | "recovery" | "integrity" => EventCategory::Integrity,

        "authorization" | "keystore" | "audit" | "security" => EventCategory::Security,

        "diagnostics" | "retention" | "traffic" => EventCategory::Diagnostics,

        // Pausing routing is something a person did, not something the service
        // decided.
        "routing-pause" => EventCategory::UserAction,

        // Lifecycle, transport, and the machine's own inventory.
        _ => EventCategory::Service,
    }
}

// ── Field visitor ─────────────────────────────────────────────────────────────

/// The field a per-principal call site already carries. Lifting it to a column
/// of its own is what lets a read be scoped to the caller without asking every
/// call site to change.
const OWNER_FIELD: &str = "sid";

/// Collects fields from a `tracing::Event` for inclusion in the log payload.
struct EventFieldVisitor {
    fields: serde_json::Map<String, serde_json::Value>,
}

impl EventFieldVisitor {
    fn new() -> Self {
        Self {
            fields: serde_json::Map::new(),
        }
    }

    /// Whose line this is, read from the event's own `sid` field. The value
    /// stays in the payload too: it is already shown in the log view, and the
    /// column exists to be filtered on, not to hide anything.
    fn owner(&self) -> Option<String> {
        match self.fields.get(OWNER_FIELD) {
            Some(serde_json::Value::String(s)) if !s.is_empty() => Some(s.clone()),
            _ => None,
        }
    }

    fn into_payload(self) -> Option<serde_json::Value> {
        if self.fields.is_empty() {
            None
        } else {
            Some(serde_json::Value::Object(self.fields))
        }
    }
}

impl Visit for EventFieldVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.fields.insert(
            field.name().to_string(),
            serde_json::Value::String(value.to_string()),
        );
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.fields
            .insert(field.name().to_string(), serde_json::Value::Bool(value));
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.fields
            .insert(field.name().to_string(), serde_json::json!(value));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.fields
            .insert(field.name().to_string(), serde_json::json!(value));
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        self.fields
            .insert(field.name().to_string(), serde_json::json!(value));
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.fields.insert(
            field.name().to_string(),
            serde_json::Value::String(format!("{value:?}")),
        );
    }
}

// ── NdjsonTracingLayer ────────────────────────────────────────────────────────

/// A `tracing-subscriber` layer that emits NDJSON operational log events.
///
/// Install once at service startup:
/// ```ignore
/// use tracing_subscriber::prelude::*;
///
/// let writer = Arc::new(LogWriter::open(config));
/// let layer = NdjsonTracingLayer::new(Arc::clone(&writer));
/// tracing_subscriber::registry()
///     .with(layer)
///     .init();
/// ```
pub struct NdjsonTracingLayer {
    writer: Arc<LogWriter>,
}

impl NdjsonTracingLayer {
    pub fn new(writer: Arc<LogWriter>) -> Self {
        Self { writer }
    }
}

/// A unique id for one operational log event.
///
/// It used to be `evt-tracing-<call site>`, which is a CONSTANT per line of
/// code: every event from the same statement shared an id. The log page cursor
/// is the pair `(created_at, event_id)` and skips everything at or before it,
/// so whenever a page boundary landed inside a run of identical pairs the rest
/// of that run was dropped and never shown — 180 lost lines out of 7927 when
/// replayed against a real log.
///
/// Deliberately not a v4 UUID: this runs on every log write, and process start
/// + pid + a counter is unique for the same purpose without touching an RNG.
fn next_event_id() -> String {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    static PREFIX: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    let prefix = PREFIX.get_or_init(|| {
        let start_ms = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        format!("{start_ms:x}-{:x}", std::process::id())
    });
    format!("evt-{prefix}-{:x}", SEQ.fetch_add(1, Ordering::Relaxed))
}

impl<S> Layer<S> for NdjsonTracingLayer
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        let meta = event.metadata();
        // Drop events from third-party crates before doing any work.
        let Some(category) = target_to_category(meta.target()) else {
            return;
        };
        let level = tracing_to_level(meta.level());

        // Collect fields.
        let mut visitor = EventFieldVisitor::new();
        event.record(&mut visitor);
        let owner = visitor.owner();
        let mut payload = visitor.into_payload();

        // What this event actually discloses, read off the names of the fields
        // it carries. Every event used to be stamped `PublicSummary` no matter
        // what was in it, which is why the writer's privacy gate could not fire
        // once in any mode — and why production logs held thousands of process
        // paths and remote addresses in a directory local users can read.
        //
        // Fields the current mode may not disclose lose their VALUE; the event
        // itself is written either way. Dropping it would take the timeline
        // with it, and the timeline is the reason the log exists.
        //
        // The stamped class must describe the payload AFTER redaction, or the
        // writer's own privacy gate throws the event away and the redaction was
        // pointless — that is how 50 924 kill-switch drops in one 90-minute
        // window left no line naming a single one of them (`log_drop_once`
        // carries `process`, which is `Sensitive`).
        let mut privacy_class = privacy::classify(payload.as_ref());
        let ceiling = self.writer.filter().mode().max_privacy();
        // `SecretNeverLog` is not redactable down to anything: it is dropped,
        // by the writer, in every mode.
        if privacy_class > ceiling && privacy_class != PrivacyClass::SecretNeverLog {
            if let Some(payload) = payload.as_mut() {
                privacy::redact_above(payload, ceiling);
            }
            privacy_class = ceiling;
        }

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);

        // `kind` is the target's leaf (`nrr::conn-trace` → `conn-trace`), not
        // tracing's event name. That name is the CALL SITE — `event
        // core\services\…:1223` — and the Logs section falls back to `kind`
        // when no locale key resolves, so the user was shown a source path
        // where a message belongs. The leaf is also what the section's "kind"
        // filter is useful against.
        let kind = meta
            .target()
            .strip_prefix("nrr::")
            .unwrap_or(meta.target())
            .replace("::", ".");
        let message_key = format!("tracing.{}.{kind}", meta.target());

        let log_event = LogEvent {
            schema_version: LOG_EVENT_SCHEMA_VERSION,
            event_id: next_event_id(),
            created_at: now_ms,
            created_at_iso: rfc3339_local_millis(now_ms),
            level,
            category,
            kind,
            correlation: EventCorrelation::default(),
            privacy_class,
            message_key,
            payload,
            principal: owner,
        };

        self.writer.emit(log_event);
    }

    fn on_new_span(&self, _attrs: &span::Attributes<'_>, _id: &span::Id, _ctx: Context<'_, S>) {
        // Spans are not written to operational logs by default.
    }

    fn on_close(&self, _id: span::Id, _ctx: Context<'_, S>) {
        // No-op.
    }
}

// ── Install helper ────────────────────────────────────────────────────────────

/// Outcome of [`install_ndjson_tracing`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TracingInstallOutcome {
    /// The global subscriber was successfully registered with our layer.
    Installed,
    /// A global subscriber was already registered (e.g. by another process
    /// component or by an earlier call). The previous registration is left
    /// intact; this call was a no-op.
    AlreadyInstalled,
}

/// Default `EnvFilter` directive applied when `NRR_LOG` is unset or unparseable.
///
/// Allows our crates at `info` and above to reach the layer; third-party
/// crates pass through this gate but are then dropped by the layer's own
/// `nrr::*` target prefilter (see [`target_to_category`]).
pub const DEFAULT_TRACING_FILTER: &str = "nrr=info,info";

/// Verbose variant of [`DEFAULT_TRACING_FILTER`]. When
/// the GUI toggle "Verbose service logging" is on (persisted in
/// `service_stability_config.verbose_logging`), the installer picks
/// this directive instead so `tracing::debug!` events in `nrr_*` crates
/// reach the operational NDJSON. `NRR_LOG` env var still wins over
/// both — dev override remains intact.
pub const VERBOSE_TRACING_FILTER: &str = "nrr=debug,info";

/// Live handle to swap the process's tracing
/// `EnvFilter` directive between [`DEFAULT_TRACING_FILTER`] and
/// [`VERBOSE_TRACING_FILTER`] WITHOUT restarting the service.
///
/// Returned by every `install_ndjson_tracing_*` function alongside
/// [`TracingInstallOutcome`]. Wraps a `tracing_subscriber::reload::Handle`,
/// which is internally reference-counted — cloning is cheap and every clone
/// controls the same live filter. `Send + Sync` so it can be stored in an
/// `Arc` and threaded into settings-write paths (see
/// `nrr-service-runtime::verbosity_control::VerbosityControl`, which this
/// type implements).
#[derive(Clone)]
pub struct TracingVerbosityHandle {
    handle: reload::Handle<EnvFilter, Registry>,
    /// The same writer the installed [`NdjsonTracingLayer`] emits into.
    /// Verbosity is gated TWICE on the way to disk: the tracing
    /// `EnvFilter` decides which events reach the layer at all, and the
    /// writer's own [`LogFilter`](crate::logs::filter::LogFilter) applies
    /// its [`LoggingMode`](crate::logs::filter::LoggingMode) level gate
    /// before serialising. A verbose toggle must flip BOTH — reloading
    /// only the `EnvFilter` lets `debug!` events through the subscriber
    /// just to have the writer's `Default` mode (`Info+`) drop every one
    /// of them on the floor.
    writer: Arc<LogWriter>,
}

impl TracingVerbosityHandle {
    /// Swaps the live filter to [`VERBOSE_TRACING_FILTER`] (when
    /// `verbose == true`) or [`DEFAULT_TRACING_FILTER`] otherwise — the
    /// exact same two constants the boot-time installers pick between, so
    /// boot and live-apply can never diverge. The writer's `LoggingMode`
    /// is switched in the same call (`Diagnostic` when verbose, `Default`
    /// otherwise) for the same reason — see the `writer` field doc.
    ///
    /// Privacy note: switching the writer to `Diagnostic` mode widens the
    /// level gate to `Debug+`, lifts the category allowlist, AND raises the
    /// ceiling the tracing layer redacts against — hostnames and addresses
    /// appear with their values, process paths stay redacted (that needs
    /// `DeveloperTrace`). In `Default` mode both are written as
    /// `<redacted>`; the events themselves are never dropped for privacy.
    ///
    /// Best-effort: a reload failure (e.g. the global subscriber was
    /// somehow replaced after install) is logged via `tracing::warn!` and
    /// swallowed. Logging verbosity is diagnostic sugar, never a routing
    /// dependency — it must never fail a settings write.
    ///
    /// Note: unlike the boot-time installers, this does not re-consult
    /// `NRR_LOG`. There is no bool-typed wire representation of an
    /// arbitrary filter string, so a live toggle always applies one of the
    /// two canonical directives; an `NRR_LOG` override in effect at process
    /// start is superseded by the first live toggle after boot.
    pub fn set_verbose(&self, verbose: bool) {
        self.writer.filter().set_mode(logging_mode_for(verbose));
        let filter = EnvFilter::new(if verbose {
            VERBOSE_TRACING_FILTER
        } else {
            DEFAULT_TRACING_FILTER
        });
        if let Err(err) = self.handle.reload(filter) {
            tracing::warn!(
                target: "nrr::stability",
                error = %err,
                "live tracing verbosity reload failed; filter unchanged",
            );
        }
    }
}

/// The writer-side [`LoggingMode`] the verbose toggle maps to. One
/// function shared by the boot-time installers and the live
/// [`TracingVerbosityHandle::set_verbose`] path so the two can never
/// disagree on what "verbose" means for the on-disk gate.
fn logging_mode_for(verbose: bool) -> crate::logs::filter::LoggingMode {
    if verbose {
        crate::logs::filter::LoggingMode::Diagnostic
    } else {
        crate::logs::filter::LoggingMode::Default
    }
}

/// Installs [`NdjsonTracingLayer`] as part of the global `tracing` subscriber.
///
/// The subscriber stack is:
///
/// 1. `EnvFilter` from the `NRR_LOG` env var (falls back to
///    [`DEFAULT_TRACING_FILTER`]), wrapped in a `reload::Layer` so it can be
///    swapped live later.
/// 2. [`NdjsonTracingLayer`] wrapping the supplied `Arc<LogWriter>`.
///
/// Uses `try_init()` so a second call (or an existing global subscriber)
/// does not panic — returns [`TracingInstallOutcome::AlreadyInstalled`].
///
/// Intended to be called exactly once during service startup, after
/// `bootstrap()` has produced the operational `LogWriter`. The returned
/// [`TracingVerbosityHandle`] lets the caller flip verbosity later without a
/// restart; a fresh handle is still returned on `AlreadyInstalled`, but it
/// only controls the live filter when this call was the one that actually
/// won `try_init()`.
pub fn install_ndjson_tracing(
    writer: Arc<LogWriter>,
) -> (TracingInstallOutcome, TracingVerbosityHandle) {
    install_ndjson_tracing_with_verbose(writer, false)
}

/// Installer that honours the GUI verbose-logging
/// toggle. When `verbose == true` and the operator has NOT set
/// `NRR_LOG`, the directive falls back to [`VERBOSE_TRACING_FILTER`]
/// (`nrr=debug,info`) instead of [`DEFAULT_TRACING_FILTER`]. `NRR_LOG`
/// always wins at boot so dev override remains intact.
///
/// Also returns a [`TracingVerbosityHandle`] so the
/// caller can apply a later GUI toggle live (see that type's docs).
pub fn install_ndjson_tracing_with_verbose(
    writer: Arc<LogWriter>,
    verbose: bool,
) -> (TracingInstallOutcome, TracingVerbosityHandle) {
    let env_filter = EnvFilter::try_from_env("NRR_LOG").unwrap_or_else(|_| {
        EnvFilter::new(if verbose {
            VERBOSE_TRACING_FILTER
        } else {
            DEFAULT_TRACING_FILTER
        })
    });
    // Align the writer's own on-disk level gate with the boot-time verbose
    // flag — the EnvFilter alone is not enough (see the
    // `TracingVerbosityHandle::writer` field doc).
    writer.filter().set_mode(logging_mode_for(verbose));
    let (filter_layer, reload_handle) = reload::Layer::new(env_filter);
    let layer = NdjsonTracingLayer::new(Arc::clone(&writer));
    let result = tracing_subscriber::registry()
        .with(filter_layer)
        .with(layer)
        .try_init();
    let outcome = match result {
        Ok(()) => TracingInstallOutcome::Installed,
        Err(_) => TracingInstallOutcome::AlreadyInstalled,
    };
    (
        outcome,
        TracingVerbosityHandle {
            handle: reload_handle,
            writer,
        },
    )
}

/// Console-mode variant: registers BOTH the NDJSON layer (operational
/// log on disk) and a `tracing_subscriber::fmt` stderr layer so every
/// `tracing::*` event surfaces in the dev console alongside the existing
/// `eprintln!` markers. Intended exclusively for `run_console` — SCM
/// service mode should keep using [`install_ndjson_tracing`] so stdout
/// stays quiet.
///
/// The env filter is shared between layers: a stricter `NRR_LOG=…`
/// directive trims both the console output and the on-disk log.
pub fn install_ndjson_tracing_with_console(
    writer: Arc<LogWriter>,
) -> (TracingInstallOutcome, TracingVerbosityHandle) {
    install_ndjson_tracing_with_console_and_verbose(writer, false)
}

/// Console-mode variant that honours the GUI
/// verbose-logging toggle, mirroring [`install_ndjson_tracing_with_verbose`].
/// Also returns a live [`TracingVerbosityHandle`].
pub fn install_ndjson_tracing_with_console_and_verbose(
    writer: Arc<LogWriter>,
    verbose: bool,
) -> (TracingInstallOutcome, TracingVerbosityHandle) {
    let env_filter = EnvFilter::try_from_env("NRR_LOG").unwrap_or_else(|_| {
        EnvFilter::new(if verbose {
            VERBOSE_TRACING_FILTER
        } else {
            DEFAULT_TRACING_FILTER
        })
    });
    // Same writer-mode alignment as `install_ndjson_tracing_with_verbose`.
    writer.filter().set_mode(logging_mode_for(verbose));
    let (filter_layer, reload_handle) = reload::Layer::new(env_filter);
    let ndjson = NdjsonTracingLayer::new(Arc::clone(&writer));
    let console = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stderr)
        .with_target(true)
        .with_ansi(false);
    let result = tracing_subscriber::registry()
        .with(filter_layer)
        .with(ndjson)
        .with(console)
        .try_init();
    let outcome = match result {
        Ok(()) => TracingInstallOutcome::Installed,
        Err(_) => TracingInstallOutcome::AlreadyInstalled,
    };
    (
        outcome,
        TracingVerbosityHandle {
            handle: reload_handle,
            writer,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logs::filter::LoggingMode;
    use crate::logs::writer::LogWriterConfig;

    #[test]
    fn tracing_level_mapping() {
        assert_eq!(tracing_to_level(&tracing::Level::TRACE), EventLevel::Trace);
        assert_eq!(tracing_to_level(&tracing::Level::DEBUG), EventLevel::Debug);
        assert_eq!(tracing_to_level(&tracing::Level::INFO), EventLevel::Info);
        assert_eq!(tracing_to_level(&tracing::Level::WARN), EventLevel::Warn);
        assert_eq!(tracing_to_level(&tracing::Level::ERROR), EventLevel::Error);
    }

    #[test]
    fn every_live_target_area_lands_where_it_belongs() {
        // Sampled from the areas that actually appear in `target:` today. The
        // point of the table is that these stop falling through to `Service`.
        for (target, expected) in [
            ("nrr::decision::engine", EventCategory::Decision),
            ("nrr::dns-resolver", EventCategory::Decision),
            ("nrr::dns_resolver", EventCategory::Decision),
            ("nrr::fake_ip", EventCategory::Decision),
            ("nrr::conn-trace", EventCategory::Decision),
            ("nrr::enforcement-plan", EventCategory::Apply),
            ("nrr::killswitch", EventCategory::Apply),
            ("nrr::wfp-ledger", EventCategory::Apply),
            ("nrr::nft", EventCategory::Apply),
            ("nrr::mutation::execute", EventCategory::Apply),
            ("nrr::mutation::preset", EventCategory::Import),
            ("nrr::cache::store", EventCategory::Cache),
            ("nrr::tamper", EventCategory::Integrity),
            ("nrr::keystore", EventCategory::Security),
            ("nrr::retention", EventCategory::Diagnostics),
            ("nrr::routing-pause", EventCategory::UserAction),
            ("nrr::boot", EventCategory::Service),
            ("nrr::ipc::dispatch", EventCategory::Service),
        ] {
            assert_eq!(
                target_to_category(target),
                Some(expected),
                "target {target} is misfiled"
            );
        }
    }

    #[test]
    fn non_nrr_target_is_dropped() {
        // Third-party crates must not pollute the operational NDJSON.
        assert_eq!(target_to_category("rusqlite"), None);
        assert_eq!(target_to_category("rusqlite::statement"), None);
        assert_eq!(target_to_category("mio::poll"), None);
        assert_eq!(target_to_category("hyper::client"), None);
        assert_eq!(target_to_category("unknown::crate"), None);
        assert_eq!(target_to_category(""), None);
        // Substring "nrr::" mid-string must not match the prefix.
        assert_eq!(target_to_category("foo_nrr::bar"), None);
    }

    #[test]
    fn ndjson_layer_drops_non_nrr_target_events() {
        let dir = tempfile::tempdir().expect("temp");
        let writer = Arc::new(LogWriter::open(LogWriterConfig::new(dir.path())));
        let layer = NdjsonTracingLayer::new(Arc::clone(&writer));

        use tracing_subscriber::prelude::*;
        let subscriber = tracing_subscriber::registry().with(layer);

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(target: "rusqlite", "noisy_third_party");
            tracing::info!(target: "mio::poll", "internal_event");
        });

        // No file created — third-party events were dropped before any I/O.
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn ndjson_layer_emits_info_event_to_writer() {
        let dir = tempfile::tempdir().expect("temp");
        let config = LogWriterConfig::new(dir.path());
        let writer = Arc::new(LogWriter::open(config));
        let layer = NdjsonTracingLayer::new(Arc::clone(&writer));

        // Build a minimal subscriber with just this layer and use it locally.
        use tracing_subscriber::prelude::*;
        let subscriber = tracing_subscriber::registry().with(layer);

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(target: "nrr::service", key = "value", "test_event");
        });

        let files: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(files.len(), 1, "one log file created");
    }

    /// Scoping a read to the caller only works if the line says whose it is.
    /// The per-principal call sites already carry `sid`; this is where it
    /// becomes a column the reader can filter on.
    #[test]
    fn a_per_principal_event_records_whose_line_it_is() {
        let dir = tempfile::tempdir().expect("temp");
        let writer = Arc::new(LogWriter::open(LogWriterConfig::new(dir.path())));
        let layer = NdjsonTracingLayer::new(Arc::clone(&writer));

        use tracing_subscriber::prelude::*;
        let subscriber = tracing_subscriber::registry().with(layer);

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(target: "nrr::service", sid = "S-1-5-21-7", "per_user_event");
            tracing::info!(target: "nrr::service", "machine_event");
        });

        let file = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .next()
            .expect("one log file");
        let text = std::fs::read_to_string(file.path()).expect("read log");
        let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
        assert_eq!(lines.len(), 2, "both events written: {text}");

        let owned: serde_json::Value = serde_json::from_str(lines[0]).expect("json");
        assert_eq!(owned["principal"], serde_json::json!("S-1-5-21-7"));
        let machine: serde_json::Value = serde_json::from_str(lines[1]).expect("json");
        assert!(
            machine.get("principal").is_none(),
            "a line with no sid belongs to the machine, not to a person: {machine}"
        );
    }

    /// A field the mode may not disclose costs the VALUE, never the line.
    /// The negative control alone (the value is gone) passes just as well when
    /// the whole event was thrown away — which is exactly what happened: the
    /// layer redacted the payload but stamped the pre-redaction class, and the
    /// writer's own privacy gate then dropped the event. Every kill-switch drop
    /// line carries `process`, so a 90-minute outage left nothing to read.
    #[test]
    fn an_over_ceiling_field_is_redacted_and_the_event_is_still_written() {
        for (mode, host_is_readable) in [
            (LoggingMode::Default, false),
            (LoggingMode::Diagnostic, true),
        ] {
            let dir = tempfile::tempdir().expect("temp");
            let writer = Arc::new(LogWriter::open(LogWriterConfig::new(dir.path())));
            writer.filter().set_mode(mode);
            let layer = NdjsonTracingLayer::new(Arc::clone(&writer));

            use tracing_subscriber::prelude::*;
            let subscriber = tracing_subscriber::registry().with(layer);

            tracing::subscriber::with_default(subscriber, || {
                tracing::info!(
                    target: "nrr::conn-trace",
                    process = "C:\\app\\vpn.exe",
                    host = "example.test",
                    count = 3,
                    "observed BLOCKED connection",
                );
            });

            let file = std::fs::read_dir(dir.path())
                .unwrap()
                .filter_map(|e| e.ok())
                .next()
                .unwrap_or_else(|| panic!("{mode:?}: the event must reach a file"));
            let text = std::fs::read_to_string(file.path()).expect("read log");
            let line = text
                .lines()
                .find(|l| !l.trim().is_empty())
                .unwrap_or_else(|| {
                    panic!("{mode:?}: redaction must not take the line with it: {text}")
                });
            let event: serde_json::Value = serde_json::from_str(line).expect("json");

            assert_eq!(
                event["payload"]["process"],
                serde_json::json!(crate::logs::privacy::REDACTED),
                "{mode:?}: a process path is Sensitive in both modes",
            );
            assert_eq!(
                event["payload"]["count"],
                serde_json::json!(3),
                "{mode:?}: a public field keeps its value",
            );
            let host = &event["payload"]["host"];
            if host_is_readable {
                assert_eq!(host, &serde_json::json!("example.test"));
            } else {
                assert_eq!(host, &serde_json::json!(crate::logs::privacy::REDACTED));
            }
        }
    }

    #[test]
    fn ndjson_layer_debug_filtered_in_default_mode() {
        let dir = tempfile::tempdir().expect("temp");
        let writer = Arc::new(LogWriter::open(LogWriterConfig::new(dir.path())));
        let layer = NdjsonTracingLayer::new(Arc::clone(&writer));

        use tracing_subscriber::prelude::*;
        let subscriber = tracing_subscriber::registry().with(layer);

        tracing::subscriber::with_default(subscriber, || {
            tracing::debug!(target: "nrr::service", "debug_event");
        });

        // Default mode filters Debug — no file created.
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn verbose_filter_directive_differs_from_default() {
        // Sanity check that the two named directives
        // are distinct strings and parse cleanly. Runtime-flow
        // verification (debug events actually reaching the writer
        // when verbose is on) is a manual / integration step: the
        // `with_default` + per-layer EnvFilter combo in
        // tracing-subscriber 0.3 has known limitations under unit
        // tests, and the production install path is exercised by
        // booting the service.
        assert_ne!(VERBOSE_TRACING_FILTER, DEFAULT_TRACING_FILTER);
        let _ = EnvFilter::new(VERBOSE_TRACING_FILTER);
        let _ = EnvFilter::new(DEFAULT_TRACING_FILTER);
    }

    /// Proves [`TracingVerbosityHandle::set_verbose`]
    /// actually swaps the live filter and never panics, including on
    /// rapid repeated toggles (the exact shape of a fast Save-Save in the
    /// GUI). Builds the exact same `reload::Layer<EnvFilter, Registry>`
    /// stack the install helpers use.
    ///
    /// Deliberately asserts on the reloaded [`EnvFilter`]'s own `Display`
    /// output (via `reload::Handle::with_current`) rather than on whether a
    /// `tracing::debug!` event actually reaches the writer: `tracing-core`'s
    /// callsite-interest cache and "global max level" hint are process-wide
    /// state shared by every test in this binary (see the sibling
    /// `verbose_filter_directive_differs_from_default` test's doc comment),
    /// so an event-emission assertion here would be racy under parallel
    /// `cargo test` execution — a `with_default`-scoped dispatcher's actual
    /// enable/disable decision for a level change can be starved by an
    /// unrelated test's dispatcher that touched the same global ratchet
    /// first. Reading the live value straight out of the `RwLock` the
    /// `Handle` and `Layer` share has none of that cross-test coupling and
    /// still proves the exact behaviour `set_verbose` promises: the SSOT
    /// [`DEFAULT_TRACING_FILTER`] / [`VERBOSE_TRACING_FILTER`] constants are
    /// the ones actually stored after each call.
    #[test]
    fn verbosity_handle_reload_swaps_filter_without_panicking() {
        let dir = tempfile::tempdir().expect("temp");
        let writer = Arc::new(LogWriter::open(LogWriterConfig::new(dir.path())));
        let (filter_layer, reload_handle) =
            reload::Layer::new(EnvFilter::new(DEFAULT_TRACING_FILTER));
        let handle = TracingVerbosityHandle {
            handle: reload_handle,
            writer: Arc::clone(&writer),
        };
        // Keep `filter_layer` alive for the whole test: `Handle::reload`
        // upgrades a `Weak` back to the shared `Arc<RwLock<EnvFilter>>` and
        // errors out once the last strong ref (owned by the `Layer`) is
        // dropped — exactly the "subscriber gone" case the doc comment on
        // `set_verbose` covers.
        let _keep_alive = &filter_layer;

        assert_eq!(
            current_filter_string(&handle),
            DEFAULT_TRACING_FILTER,
            "must start on the default directive"
        );

        handle.set_verbose(true);
        assert_eq!(
            current_filter_string(&handle),
            VERBOSE_TRACING_FILTER,
            "set_verbose(true) must swap in VERBOSE_TRACING_FILTER"
        );
        assert_eq!(
            writer.filter().mode(),
            crate::logs::filter::LoggingMode::Diagnostic,
            "set_verbose(true) must also lift the writer's on-disk level gate \
             — the EnvFilter alone still leaves every debug event dropped by \
             the writer's Default mode"
        );

        handle.set_verbose(false);
        assert_eq!(
            current_filter_string(&handle),
            DEFAULT_TRACING_FILTER,
            "set_verbose(false) must swap back to DEFAULT_TRACING_FILTER"
        );
        assert_eq!(
            writer.filter().mode(),
            crate::logs::filter::LoggingMode::Default,
            "set_verbose(false) must restore the writer's Default mode"
        );

        // Rapid repeated toggles must never panic.
        handle.set_verbose(true);
        handle.set_verbose(true);
        handle.set_verbose(false);
        handle.set_verbose(false);
        assert_eq!(current_filter_string(&handle), DEFAULT_TRACING_FILTER);
        assert_eq!(
            writer.filter().mode(),
            crate::logs::filter::LoggingMode::Default
        );
    }

    /// End-to-end proof of the double-gate fix: with verbose ON via the
    /// installer's boot path, a `debug!` event must actually land on disk.
    /// Uses a locally scoped subscriber (not the global one) so the test
    /// stays independent of `try_init` winner state; the writer-mode gate
    /// it exercises is exactly the one production shares.
    #[test]
    fn verbose_boot_writer_mode_lets_debug_reach_disk() {
        let dir = tempfile::tempdir().expect("temp");
        let writer = Arc::new(LogWriter::open(LogWriterConfig::new(dir.path())));
        writer.filter().set_mode(logging_mode_for(true));
        let layer = NdjsonTracingLayer::new(Arc::clone(&writer));

        use tracing_subscriber::prelude::*;
        let subscriber = tracing_subscriber::registry().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            tracing::debug!(target: "nrr::service", "verbose_debug_event");
        });

        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            1,
            "verbose writer mode must persist the debug event"
        );
    }

    /// Reads the live `EnvFilter`'s directive string back out through the
    /// shared `reload::Handle`, for assertions in
    /// [`verbosity_handle_reload_swaps_filter_without_panicking`].
    fn current_filter_string(handle: &TracingVerbosityHandle) -> String {
        handle
            .handle
            .with_current(ToString::to_string)
            .expect("reload handle's Layer must still be alive in this test")
    }

    #[test]
    fn events_from_one_call_site_do_not_share_an_id() {
        use crate::logs::writer::LogWriter;
        use tracing::subscriber::with_default;
        use tracing_subscriber::layer::SubscriberExt;

        let dir = tempfile::tempdir().expect("temp");
        let writer = Arc::new(LogWriter::open(LogWriterConfig::new(dir.path())));
        let subscriber =
            tracing_subscriber::registry().with(NdjsonTracingLayer::new(Arc::clone(&writer)));
        with_default(subscriber, || {
            for _ in 0..3 {
                tracing::info!(target: "nrr::test", "same call site");
            }
        });
        drop(writer);

        let ids: Vec<String> = std::fs::read_dir(dir.path())
            .expect("read dir")
            .filter_map(|e| e.ok())
            .filter_map(|e| std::fs::read_to_string(e.path()).ok())
            .flat_map(|text| {
                text.lines()
                    .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
                    .filter_map(|v| v["event_id"].as_str().map(str::to_string))
                    .collect::<Vec<_>>()
            })
            .collect();

        assert_eq!(ids.len(), 3, "all three events must be written: {ids:?}");
        let unique: std::collections::HashSet<_> = ids.iter().collect();
        assert_eq!(unique.len(), 3, "ids from one call site collided: {ids:?}");
    }

    #[test]
    fn a_log_kind_never_carries_a_source_path() {
        use crate::logs::writer::LogWriter;
        use tracing::subscriber::with_default;
        use tracing_subscriber::layer::SubscriberExt;

        let dir = tempfile::tempdir().expect("temp");
        let writer = Arc::new(LogWriter::open(LogWriterConfig::new(dir.path())));
        let subscriber =
            tracing_subscriber::registry().with(NdjsonTracingLayer::new(Arc::clone(&writer)));
        with_default(subscriber, || {
            tracing::info!(target: "nrr::conn-trace", "flow observed");
        });
        drop(writer);

        let kinds: Vec<String> = std::fs::read_dir(dir.path())
            .expect("read dir")
            .filter_map(|e| e.ok())
            .filter_map(|e| std::fs::read_to_string(e.path()).ok())
            .flat_map(|text| {
                text.lines()
                    .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
                    .filter_map(|v| v["kind"].as_str().map(str::to_string))
                    .collect::<Vec<_>>()
            })
            .collect();

        // The Logs section shows `kind` when no locale key resolves, which is
        // always the case for a tracing event.
        assert_eq!(kinds, ["conn-trace"]);
    }
}
