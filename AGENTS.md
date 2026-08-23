# AGENTS.md

This file provides guidance to Codex (Codex.ai/code) when working with code in this repository.

## Project Overview

NetRuleRouter is a **Windows-first** network policy and traffic routing manager. It controls traffic routing across existing network interfaces (e.g., primary + VPN, Wi-Fi + Ethernet). It is **not** a VPN client, anonymity tool, censorship bypass tool, or proxy manager.

## Build Commands

```powershell
# Bootstrap prerequisites and .env
powershell -ExecutionPolicy Bypass -File .\scripts\bootstrap.ps1

# Build all desktop/runtime pieces
cargo build -p nrr-launcher -p nrr-qt-host

# Or build via script
powershell -ExecutionPolicy Bypass -File .\scripts\build.ps1 -Profile dev

# Run executables
.\target\debug\NetRuleRouter.exe
.\target\debug\NetRuleRouterTray.exe

# Or via script
.\scripts\run.ps1 -Component gui
.\scripts\run.ps1 -Component tray
.\scripts\run.ps1 -Component service
```

## Quality Checks

```powershell
# Canonical local quality gate (fmt + clippy + test + cargo-deny)
powershell -ExecutionPolicy Bypass -File .\scripts\check.ps1 -RequireCargoDeny
```

The gate wraps the standard `cargo fmt --check` / `cargo clippy -D warnings` / `cargo test` / `cargo deny check` invocations. Run a single test: `cargo test -p <crate-name> <test_name>`.

## Architecture

### Runtime Decomposition

Two long-lived processes per UI surface — a Rust launcher that owns single-instance, preference persistence, and child-process lifecycle, and one C++ Qt host child that renders the QML window:

- **`NetRuleRouter.exe`** — canonical end-user GUI entry point. Produced by the `nrr-launcher` crate (`[[bin]] name = "NetRuleRouter"`, GUI subsystem). On launch it acquires the `gui-shell-v1` single-instance lock, emits the QML context JSON in-process via `nrr_desktop_gui::ui_surface::write_qt_context_file_at`, and spawns one child: `nrr_qt_native_host.exe` with `--qml=<Main.qml> --nrr-context-file=<temp.json>`. The launcher streams the child's stdout for `NRR_PREFS_JSON:` lines (preferences round-trip) and persists prefs through `nrr-ui-support` on child exit.
- **`NetRuleRouterTray.exe`** — canonical end-user tray. Same `nrr-launcher` crate (second `[[bin]]`), targeting `Tray.qml`. Spawned by main GUI's `nrrNativeBridge::ensureTrayRunning` when `prefs.minimizeToTrayInsteadOfClose` fires close-to-tray; can also be launched directly.
- **`nrr-service.exe`** — Windows background service, produced by the `nrr-windows-service` crate (`[[bin]] name = "nrr-service"`). Starts with Windows, applies and enforces routing policy. Reads the same `%TEMP%\NetRuleRouter\app-shutdown.flag` the tray writes on "Exit" so all three processes wind down on a single user gesture. **Binary naming rule:** the crate name states the platform, the executable name states the role, and the role name is identical on every OS — `nrr-service` on Windows, `nrr-serviced` plus an `nrr-service` alias on Unix (the `d` suffix is the Unix convention; the alias keeps cross-platform scripts on one name).

- **`nrr-cli.exe`** — administrative console, produced by the `nrr-cli` crate (`apps/cli`). Short-lived, not a long-running process. Free surface is deliberately narrow: service lifecycle (`install`/`uninstall`/`start`/`stop`/`restart`/`status`) plus — once wired — diagnostics and network recovery. It never mutates policy, emits no machine-readable output, takes no config file, and never elevates itself (access-denied prints the exact command to repeat and exits 3). Its verb table in `apps/cli/src/verbs.rs` is the single declaration from which help is rendered; tests there reject policy verbs and automation flags by name. Three more settled rules: **output is English only** (an admin interface, never localized); **`status` describes the service** — installed / running / version / start mode — and never the policy, because "N rules applied" immediately raises "whose", which is per-SID and therefore not Free console territory; and the **service binary's own verbs** (`console`, `run`, `set-start-auto`, `query-start-mode`, `update`, SCM mode) stay internal — the broker, GUI and systemd invoke them, they are not publicly documented and may change freely.

Supporting binary (NOT a user entry point):
- `nrr_qt_native_host.exe` — C++ Qt binary (built via CMake, WIN32 subsystem). Loads QML and shows the window. Discovered at runtime via `nrr_qt_host::NATIVE_HOST_EXE` (absolute path baked at build time by `nrr-qt-host/build.rs`) with a fallback to `current_exe()`-adjacent lookup.

The legacy `nrr-qt-host.exe` Rust orchestrator and the `--nrr-helper=...` self-spawn helpers are gone as runtime processes. `nrr-desktop-gui` and `nrr-desktop-tray` survive as pure libraries; `nrr-qt-host` survives as a build-only crate exposing `NATIVE_HOST_EXE`.

**Important:** the block-2-era C++ copies named `NetRuleRouter.exe` / `NetRuleRouterTray.exe` in `apps/desktop/qt-host/build.rs` (the dead `copy_native_product_executable` helper) must stay disabled. Re-enabling collides with the launcher outputs in `target/<profile>/`.

### Crate Boundaries

```
apps/cli/           — nrr-cli: administrative console binary. Depends on
                      platform-api + contracts + ipc-client (plus the Windows
                      platform crate under cfg(windows)); holds no OS-specific
                      logic — `platform.rs` is the single cfg, and it only picks
                      an implementation of the service-control port. The IPC
                      client is what lets `diag export` ask the SERVICE for the
                      archive instead of assembling a second one; the console is
                      held to reading by `IpcClientProfile::AdminConsole`, which
                      the service enforces — not by discipline in this crate.
apps/desktop/       — desktop runtime shells and Qt/QML UI assets
  launcher/         — Rust user-facing entry-point crate (nrr-launcher).
                      Produces NetRuleRouter.exe and NetRuleRouterTray.exe
                      from two [[bin]] entries; embeds the app icon.
  qt-host/          — build-only crate. `build.rs` drives the CMake build
                      of the C++ Qt host (`nrr_qt_native_host.exe`); the
                      lib re-exports its absolute path as `NATIVE_HOST_EXE`.
  gui/              — lib-only crate. QML context emitter + launch-request
                      parser + prefs round-trip helpers consumed by launcher.
  tray/             — lib-only crate. Tray context emitter + supporting types.
  qml/              — QML presentation assets (decomposed into sections/ + sections/settings/)

core/               — all product/domain logic (must not depend on Qt)
  domain/           — pure domain primitives
  application/      — transport-agnostic backend facade
  platform/api/     — nrr-platform-api: neutral port traits + value types every
                      OS backend implements (incl. `service_control` — register /
                      remove / start / stop / query the background service, and
                      `paths` — the ONE declaration of the production state/log
                      roots, leaf taken from `product_identity`)
  platform/windows/ — Windows-specific platform adapters (incl. the SCM
                      implementation of `ServiceControlPort`)
  ui-support/       — UI-runtime-only modules (theme, first_run, ui_preferences, tray)
  mock-backend/     — preview/mock snapshots
  storage/          — nrr-storage: SQLite FQDN/IP cache + service-state persistence
  diagnostics/      — nrr-diagnostics: audit, logs, retention, archives
  ipc-client/       — nrr-ipc-client: NamedPipeIpcClient + wire codec SSOT
  services/service-runtime/ — nrr-service-runtime: orchestration layer.
                              Manager traits + ActivationCoordinator + IPC handlers
                              + ServiceSupervisor + ActiveSidRegistry. Hard deny-list
                              on UI/preview/binary crates enforced by
                              `tests/dependency_boundary.rs`.
  services/windows-service/ — nrr-windows-service: thin SCM/console entrypoint.
                              MUST NOT grow new orchestration logic — that goes
                              in service-runtime.

shared/contracts/   — nrr-shared crate: GUI/tray/service contracts + IPC types +
                      wire-protocol payload SSOT (ipc_payloads.rs) +
                      product-identity SSOT (product_identity.rs)
```

**Allowed dependency direction:** `apps/launcher → apps/gui + apps/tray + apps/qt-host`, `apps → application/ui-support/mock-backend/contracts (+ platform-api for the production directory roots)`, `apps/cli → platform-api + contracts + ipc-client (+ platform/windows under cfg(windows))`, `services/windows-service → services/service-runtime + application`, `services/service-runtime → application/domain/storage/diagnostics/platform/contracts`, `platform → domain/contracts`, `domain → contracts`, `storage → domain + platform-api`, `ipc-client → shared` (with dev-dep on service-runtime for contract tests). `apps/qt-host` is build-only.

**Forbidden:** `services/service-runtime` and `services/windows-service` must not import `ui-support`, `mock-backend`, `windows-gui`, `windows-tray`, `launcher`, or `qt-host` — enforced at `cargo test` time. `platform/windows` must not depend on GUI/tray crates. `domain` must not depend on Windows APIs, QML, or local UI storage. `storage` must not depend on `nrr-shared`, UI crates, or `nrr-application`. `apps/gui` and `apps/tray` must not depend on `apps/launcher`. `nrr-ipc-client` must not depend on `nrr-service-runtime` at runtime (forces the wire-protocol SSOT in `nrr-shared`).

### Key Design Rules

- **Business logic stays in Rust.** C++ is only for Qt/bridge integration. No business logic in QML or C++ glue.
- **GUI stays thin.** Section rendering, first-run flow, single-instance internals, and preferences I/O belong in dedicated modules, not in `main.rs`.
- **QML decomposition:** `Main.qml` is a shell only (ApplicationWindow + shared state + actions + menubar + sidebar + child windows + StackLayout). Top-level sections live as separate files under `apps/desktop/qml/sections/`; Settings subsections under `apps/desktop/qml/sections/settings/`. Each section file takes `property var root` (the ApplicationWindow) and accesses shared state through it (`root.tr(...)`, `root.prefs`, `root.uiTheme`, `root.routingState`, etc.). ApplicationWindow exposes internal `id`s via `property alias` for cross-file access. **Never re-inline section bodies into `Main.qml`.**
- **Themed control wrappers.** Default Qt Native style on Windows ignores `palette.*` for closed comboboxes, dropdown popups, spinbox indicators, and text-field background. Use the wrappers in `apps/desktop/qml/components/` instead of raw QtQuick.Controls types: `ThemedButton`, `ThemedTextField`, `ThemedSpinBox`, `ThemedComboBox`. Each takes `theme: uiTheme` and overrides `contentItem` / `background` / `delegate` / `popup` / `indicator`. **Never introduce a raw `Button {}` / `TextField {}` / `SpinBox {}` / `ComboBox {}` for user-visible controls.**
- **All user-visible text must use `tr(key, fallback)`.** Hardcoded strings break the RU/EN locale story; the EN string belongs only as a fallback parameter, the actual text lives in `locales/{en,ru}.json`. ComboBoxes must set `displayText` and (where helpful) `labelResolver` on `ThemedComboBox`. Diagnostics/log messages from Rust are the only exception.
- **HARD RULE — new UI text goes straight into both `locales/en.json` and `locales/ru.json` in the same change set.** Never ship visible strings with only the `tr()` fallback populated. Backend slugs surfaced from Rust must be wrapped with `tr("<domain>.<slug>", slug)` in QML — never displayed raw.
- **Reuse recurring UI texts — do not multiply near-identical keys.** Before adding a locale key for a generic action/label ("Show details"/"Hide details", "Dismiss", "Copy", "Open folder" and the like), grep both locale files for an existing key with the same meaning and reuse it (promote it to a shared, non-feature-scoped key such as `settings.routing.show-more` when it outgrows its original group). One wording per concept across the app; feature-scoped duplicates of generic texts are a defect.
- **`unsafe` Rust** requires justification and must be localized.
- The workspace lints enforce: `unsafe_code = "deny"`, `unwrap_used = "deny"`, `dbg_macro = "deny"`.
- **HARD RULE — cross-platform by construction.** The project is going cross-platform (Windows → Linux → macOS). Any new feature that touches an OS-specific capability MUST be split along the **policy / mechanism** seam from the start: the decision logic stays neutral (pure, in `domain`/`shared`, tested once), the OS mechanism goes behind a **platform-api trait** with per-OS implementations (`windows` / `linux` / `macos`) — same trait name, different impls. Never hardcode a Win32/WFP/registry/named-pipe path into `service-runtime`, `domain`, `storage`, `diagnostics`, `shared`, or any `apps/desktop` non-OS module. Consult the **platform split map** (`TASKS_RU.md § Блок 19 → «Карта разделения платформенных портов»`) before adding anything that enforces packets, reads/writes routes, observes DNS/connections, enumerates adapters, persists secrets, integrates with the background service, brokers elevation, does autostart, or opens IPC. If a capability is genuinely OS-unique (no analog elsewhere), declare it in `PlatformCapabilities` so `platformProfile.supports.<x>` is `false` on other OSes and the GUI degrades gracefully — do NOT scatter `if (Qt.platform.os === …)` in QML. New user-visible text still follows the locale HARD RULE above regardless of platform.

### Windows Binary Specifics

- **GUI subsystem.** `nrr-launcher` sets `windows_subsystem = "windows"`; the C++ Qt host is built `WIN32`. No process in the runtime chain allocates a console. When launched from a console, `println!`/`eprintln!` still write to the parent because stdio handles inherit.
- **Embedded icon.** `nrr-launcher` has `build.rs` using `embed-resource = "2"` that compiles `resources/app.rc` into the PE resource section of *both* `NetRuleRouter.exe` and `NetRuleRouterTray.exe`. The `.rc` file references `../../../../assets/icons/app/app.ico` — same ICO the C++ Qt host's CMake build embeds via `generated_app.rc`. Single source of truth.
- **QML path resolution (C++ Qt host order):** `--qml=<absolute>` arg → `NRR_QML_MAIN`/`NRR_QML_TRAY` env → `findUpwardFile` from binary location → CMake-baked absolute paths (`NRR_QML_MAIN_DEFAULT` etc. as `target_compile_definitions`). The CMake fallback enables redirected `[build] target-dir`. Consequence: binary is not portable between machines without shipping the QML/locale tree.
- **DWM dark title bar.** The native title bar ignores Qt palette / QML theme. The C++ Qt host links `dwmapi.lib` and exposes `Q_INVOKABLE NrrNativeBridge::setMainWindowDarkTitleBar(bool)` and `setWindowDarkTitleBar(QObject*, bool)` which call `DwmSetWindowAttribute(hwnd, 20, ...)` (with attribute 19 fallback for Win10 1809–1909). Cold-start: host registers main `QWindow` in the bridge **before** `window->show()`. Theme switches re-apply via `SetWindowPos(SWP_FRAMECHANGED)`. Same flow used for child windows on each `onVisibleChanged: visible == true`.

### IPC Between Launcher, Qt Host, Tray, and Service

| Channel | Direction | Mechanism | Triggered by |
|---|---|---|---|
| QML context | launcher → C++ host | temp JSON file (`%TEMP%\nrr-qt-context-…json`), `--nrr-context-file=` | every launcher startup |
| Preferences round-trip | C++ host → launcher | `NRR_PREFS_JSON:<payload>` lines on stdout, parsed in launcher background threads | every QML `emitPrefs()` call |
| Activation hand-off | secondary launcher → primary C++ host | `%TEMP%\NetRuleRouter\gui-activation.json` (polled at 350 ms) | duplicate `NetRuleRouter.exe` launch |
| Shutdown | tray "Exit" → main GUI | `%TEMP%\NetRuleRouter\app-shutdown.flag` (polled from QML at 250 ms) | tray menu "Exit" |
| Tray "Open" → GUI | C++ tray host → new `NetRuleRouter.exe` process | `QProcess::startDetached(...)` with `--source=tray --section=…` | tray menu actions |
| ensureTrayRunning | main GUI C++ host → new `NetRuleRouterTray.exe` process | `QProcess::startDetached` | `Component.onCompleted` of `Main.qml` |
| Service IPC | GUI/Tray ↔ service | Named pipe `\\.\pipe\NetRuleRouter\service-v1` (versioned, DACL-protected, 4-byte BE u32 length + UTF-8 JSON, 1 MiB message cap via `IPC_MAX_MESSAGE_BYTES` — 64 KiB is the pipe buffer, not the limit — 32 concurrent) | every `NamedPipeIpcClient::call` |

### Shared Contracts (`nrr-shared`)

`shared/contracts/src/lib.rs` is the normative layer for GUI/tray/service communication:
- GUI information architecture and navigation model
- `MainWindowShellContract`, `FirstRunContract`, `RulesContract`, `InterfacesRoutesContract`
- IPC types (`ipc.rs`, `ipc_transport.rs`, `ipc_flow.rs`, `ipc_dto.rs`)
- **Wire-protocol payload SSOT** (`ipc_payloads.rs`) — typed request/response structs for every `IpcOperationName`, used by both `nrr-service-runtime` handlers and the `nrr-ipc-client` facade. `nrr-service-runtime::ipc_handlers::payloads` is a `pub use` shim only.
- **Diagnostics DTO SSOT** (`diagnostics_dto.rs` + `pagination.rs`) — `DiagnosticsStatusDto`, `LogEntryDto`, `AuditEntryDto`, `SecurityAlertDto`, filter shapes, `PageResult`, `PaginationParams`. `nrr-diagnostics::facade::{dto,pagination}` are `pub use` shims.
- **Product-identity SSOT** (`product_identity.rs`) — two spellings of one identifier (`NetRuleRouter` canonical, `netrulerouter` unix) plus `BinaryRole` (`Service`/`Console`/`Gui`/`Tray`) with per-OS file names and the daemon alias. The SCM service name, display name, description, Event Log source, systemd unit name and every executable name are **derived** from it — never retyped. `SERVICE_NAME` in `service-runtime`, `SYSTEMD_UNIT_NAME` in `platform/linux`, the SCM probe in `ipc-client` and the broker all read from here. Reverse-DNS (macOS bundle id / launchd label) is deliberately absent until chosen — it cannot change after the first macOS release.
- `AdaptersSnapshot` with stable adapter identity (`AdapterName` + `ifindex+mac` fallback)
- Summary formatting in `summary.rs`

Contract tests live in `shared/contracts/tests/` split by domain.

### Rule Evaluation Priority (baseline; Zone ↔ Exact IP order is user-configurable)

1. Exact FQDN
2. Subdomain / suffix
3. Zone — TLD or internal domain suffix (e.g. `.ru`, `.com`, `.intra`); hostname must end with `.{zone_name}`
4. Exact IP — default priority vs Zone (configurable via `zone_priority_over_ip`)
5. Application
6. Default route

Default: Exact IP wins (more specific overrides zone). IP subnet zones are Pro-only; Free supports domain-suffix zones only.

### Rule Engine (`nrr-domain`)

The sole public entrypoint is `decide_route(DecisionRequest) -> DecisionOutcome` in `core/domain/src/decision_engine.rs`. Design invariants:
- **Pure and deterministic**: identical inputs → identical outputs and identical ordered traces.
- **No I/O**: never DNS, SQLite, OS route apply. All data injected via `DecisionRequest`.
- **`DecisionId` is caller-provided**: service layer generates UUID v4 per invocation; engine never creates random values.
- **App-filter is AND**: a rule with both `address_match` and `app_match` requires both to match.
- Input normalization and fixture helpers live in `decision_engine_input.rs`. `test_support` is always compiled (not `#[cfg(test)]`).

### Storage Layer (`nrr-storage`)

Synchronous SQLite persistence for two databases:

| File | Kind | On corruption |
|------|------|---------------|
| `nrr_fqdn_ip_cache.db` | Rebuildable | Delete + rebuild |
| `nrr_service_state.db` | Service-critical | LKG fallback |

Design invariants:
- **Sync-only** blocking `rusqlite`. No async primitives in the crate. Async callers wrap with `spawn_blocking`.
- **Single connection per database** (one `RefCell<Connection>` per store; no pool).
- **WAL mandatory**: `PRAGMA journal_mode = WAL` verified on open; `busy_timeout = 5000 ms`.
- **Checksum validation**: migration runner validates stored FNV-1a checksums against computed values on every startup — mismatch → `MigrationFailed`.
- **Privacy tiers**: `DiagnosticRedactionLevel` (Compact / Standard / Diagnostics) gates explain detail. Raw hostnames/IPs never appear in `Compact`.

Current schema: **v7** (16.9.3). See block 16.9 memory entries for the full table inventory (`revisions`, `active_revision_pointer`, `mutation_tokens`, `retention_settings`, `apply_failure_policy_settings`, `routing_pause_state`, `autostart_state`, plus 16.8.1's `user_route_bindings`/`secondary_block_policy`/`active_sid_sessions`/`migration_state`).

### Diagnostics Layer (`nrr-diagnostics`)

Single authoritative location for audit, logging, redaction, retention, facade, and archive code. Dependencies: `nrr-domain`, `nrr-storage`, `nrr-shared`. Must NOT depend on Qt/QML/UI crates.

Storage files:

| File | Kind | Notes |
|------|------|-------|
| `nrr_audit_YYYYMMDD-N.ndjson` | Append-only NDJSON | Security audit trail; never deleted by user cleanup |
| `nrr_service_YYYYMMDD-N.ndjson` | Operational logs NDJSON | Rotated; user can clear |

Key design decisions:
- `DiagnosticRedactionLevel` lives in `nrr-storage`; `nrr-diagnostics` uses it via dependency.
- `tracing` + `tracing-subscriber`; custom NDJSON layer in `src/logs/tracing_layer.rs`. Production install via `install_ndjson_tracing` is called in `nrr-windows-service` (NOT inside `bootstrap()` — keeps lib clean for unit tests). Default `EnvFilter` is `nrr=info,info`; override via env `NRR_LOG`. Target prefilter drops non-`nrr::*` events with no allocation. **Service-only invariant**: GUI and tray do NOT write operational NDJSON (consistent with the 16.5 ACL `Users:RX` on `logs/`).
- Audit hash chain: `event_hash = SHA-256(prev_hash || canonical_payload_json)`. `AuditWriter::open()` reads the last hash from the tail of the most recent file to continue across service restarts.
- Retention defaults: operational logs 90 days / 50 MB; audit NDJSON 365 days / 50 MB. Configurable via Settings → «Диагностика и логи».
- `ExplainQuery` has two variants: `HistoricalDecision { decision_id }` and `Synthetic { input_sample }`.
- `SecretNeverLog<T>` deliberately does NOT implement `serde::Serialize` — compile error on accidental inclusion in any output.
- Archive format: `.zip` with `manifest.json` + `health.json` + `logs.ndjson` + `audit_summary.json` + `troubleshooting.md` + optional sections.

### Localization

- All end-user text must use key-based locale resources — no hardcoded strings (except developer-facing diagnostics/logs).
- Locale files: `locales/{en,ru}.json`, schema v1 at `configs/localization/locale.schema.v1.json`.
- Key naming: `<domain>.<surface>.<element>.<state>` (see `configs/localization/KEY_SCHEMA.md`).
- Source precedence: user override (managed/locales) → bundled locale → fallback locale.
- Baseline: `ru` and `en`. Validation: accepted / accepted-with-warnings / rejected.
- Runtime env overrides: `NRR_BUNDLED_LOCALES_DIR`, `NRR_USER_LOCALES_DIR`.

### Accessibility

Required baseline, not optional:
- Accessible names, roles, states on every interactive control
- Keyboard-first navigation with visible focus
- Text scaling without clipped layouts
- System-font selection in Settings
- Dedicated `high-contrast` theme (in addition to `light/dark/system`)
- Tooltips enabled by default but never the sole source of accessible meaning

### Persistence

- UI preferences: `APPDATA`/`LOCALAPPDATA` (QSettings/Windows Registry with managed local fallback).
- Persisted fields: theme, language, accessibility settings, last opened section, route labels, role confirmation flags. *(Policy-affecting fields — selected primary/secondary, behavior mode — are migrating from `UiPreferences` to per-SID service storage.)*
- Active config: one at a time (Free tier). Local SQLite cache for FQDN/IP mapping.
- Presets: two plain-text files `rules_primary.txt` / `rules_secondary.txt`, format per docs/en/rules-file-format.md Rules File Format; metadata as header comments.

## Free vs Pro Configuration Model

**Free version — manual single-config model:**
- Exactly one active rule configuration **per OS user**, plus a shared admin-managed **baseline** every user falls back to; no multi-profile manager, no scenario library. A user's daily edits are **non-elevated** and land under their own SID (per-principal store); editing the shared baseline requires elevation. A new/un-diverged user transparently sees the baseline via provider read-through (no copy until first edit). "Reset to baseline" discards the user's own divergence.
- User manually switches adapters and edits the rules file when changing routing
- No saving/loading multiple named configurations
- `route_primary_label` / `route_secondary_label` are user display names — UI preference only
- `show_bluetooth_adapters` is a UI display toggle (default off) — UI preference only

**Free export/import:**
- **Rules export/import**: two plain-text files (`rules_primary.txt` / `rules_secondary.txt`) — rules only, no adapter bindings. Pro-only sections in imports are preserved but not applied (Pro badge in GUI).
- **Full settings export**: adapter bindings + rules + behavior mode — Pro migration path. Excludes UI preferences (theme/font/language are device-specific).

**Pro version (future):** multiple saved profiles, scenario libraries, 2+N adapters, complex per-site/per-app routing across 3+ routes, automated switching, richer rule types (CIDR, ports, protocols). Imports Full Free exports as a starting point.

## Code Quality Standard

Write Rust at **Staff Software Engineer level** (FAANG, 15+ years backend):
- Idiomatic, zero-cost abstractions; no unnecessary allocations or indirection
- Correct ownership/lifetime design from the start
- Clean, narrow public interfaces; implementation details stay private
- UI surfaces must be intuitive and user-friendly

**HARD RULE — comments stay short.** Explain *why*, never restate *what*. One or two lines is the norm; a comment longer than the code it precedes is a defect. When a decision is settled and the code reads clearly, delete the comment rather than shorten it. **No task/block/phase/ticket references and no dates in comments** (`Block 16.QoL+ (2026-06-05)`, `After 13.R-GUI`, `NRR-143`) — tracking lives in `TASKS_RU.md`, rationale lives in `notes/`, neither ships in source. No history narration ("previously X, now Y"). Whenever you edit a file for any reason, compress over-detailed comments you pass through, keeping their substance.

## Naming Conventions

- Rust crates: `nrr-` prefix
- Rust: `snake_case` for modules/functions/files, `PascalCase` for types/traits, `UPPER_SNAKE_CASE` for constants
- PowerShell scripts: action-named (`bootstrap.ps1`, `build.ps1`, `run.ps1`, `check.ps1`)
- SQLite databases: `nrr_` prefix, snake_case (`nrr_service_state.db`, `nrr_fqdn_ip_cache.db`). No exceptions.

## Known Gap Convention

Scaffold limitations awaiting real integration are marked with a plain `// TODO: <reason>` stating what is missing and what would close it. The reason must stand on its own — no block, phase, or ticket number, which the comment-hygiene gate in `scripts/check.ps1` rejects. Track the work item itself in `TASKS_RU.md`; the comment marks the site, the task list owns the schedule.

## Dependency Licensing

All dependencies must be commercially distributable. GPL/AGPL, unclear licensing, git deps, non-crates.io registries, and wildcard versions are denied unless reviewed. The authoritative allow/deny lists are enforced by `deny.toml` (`cargo deny check`). Project license: `MPL-2.0`.

## Documentation Sync Rules

Several documents exist in English + Russian pairs. When editing one, update the other in the same change set. **Order: English first, then Russian.**
- `README.md` ↔ `README_RU.md`
- `ARCHITECTURE.md` ↔ `ARCHITECTURE_RU.md`

`TASKS_RU.md` is maintained **exclusively in Russian** — no English content. AI-facing files default to English. Never corrupt Cyrillic encoding.

**HARD RULE — no emoji in documentation.** README files, `docs/`, and all other Markdown documentation must not contain emoji — neither decorative list-bullet icons nor warning-sign symbols. Use plain text emphasis (`**bold**`, `> blockquote`) instead. Applies to every agent writing docs in this repository.

**HARD RULE — public docs describe BENEFITS, not mechanism (IP discipline).** The source code is fully public (open on GitHub), so this is a documentation-style rule, not code secrecy. Public-facing documentation — `README.md`, `README_RU.md`, and `docs/` (user AND technical docs) — must describe **what the product does for the user** (outcomes, guarantees, when to use a feature), never **how a proprietary mechanism works internally**. All implementation/mechanism detail belongs in the **gitignored** `notes/` (book notes) and `*_RU` design docs / `TASKS_RU.md`, never in public docs.
- **Litmus test:** a sentence that answers "HOW do we do it" (algorithm, heuristic, thresholds, internal data flow) → gitignored notes only. A sentence that answers "WHAT does the user get" → public docs OK.
- **Do NOT write public (README/docs/) documentation about these mechanisms** — their detail stays in `notes/`/`*_RU`/`TASKS_RU` (mention only the user-facing benefit in public if at all):
  1. **FCrDNS learn-from-drops** — PTR + forward-confirm rule-host learning from blocked connections, anti-spoofing, P2P-suppression.
  2. **Shared-IP census + smart kill-switch** — the "don't pin an IP shared with a direct host" exemption criterion, thresholds, caps.
  3. **fake-IP applied to shared-IP collateral** — the specific scope model (which app-groups get fake-IP; P2P/crypto excluded). (Generic fake-IP concept is prior art; our application + scope is what stays private.)
  4. **Fail-closed state machine specifics** — arming/disarming logic, mode A↔B race handling, edge flushes.
  5. **Per-SID baseline read-through** — non-elevated user divergence over an admin baseline (internal model).
  6. **Any concrete heuristics / thresholds / caps** (census threshold, `.ru` zone cap logic, stable-IP-subset selection, etc.).
- **Everything else may have BOTH user and technical public documentation** — rule types, Fail-Closed as a benefit, per-user + admin baseline at concept level, cross-platform, localization, accessibility, browser-history seeding, the "policy over existing interfaces, not a VPN" positioning, the app-group route-assignment feature (as a user benefit).
- Also avoid leaking mechanism in other public channels: GitHub Issues, blog, Telegram announcements, screenshots exposing internal slugs (`collateral-*`, `fcrdns`, `census`).

## Book Notes (notes/)

Write architectural decision notes proactively into the gitignored local `notes/` folder after any non-trivial decision with a real trade-off — don't wait to be asked. Full workflow (when to write, Russian file naming, required sections, tag set) lives in the `book-notes` skill (`.Codex/skills/book-notes/SKILL.md`).

## Lessons Learned

`LESSONS_LEARNED.md` (English-only) holds 22 recipes for the most common pitfalls: QML binding tracking (use `root.uiRevision >= 0 ? expr : ""` ternary, NOT comma-expression `(root.uiRevision, expr)`), ScrollView responsive layout, DWM dark titlebar timing, `Themed*` wrappers, `ShortcutMenuItem` + Fusion style, IPC between launcher / Qt host / tray / service, `embed-resource` icon embedding, rule engine purity, NDJSON audit hash chain. Read it before touching QML or IPC.

## Block 16 — status

Block 16 closes the GUI ↔ Service real integration. Current status, decisions log, closed sub-blocks, and load-bearing fixes live in `TASKS_RU.md` (primary) and the auto-memory index (`~/.Codex/projects/.../memory/MEMORY.md`). Read MEMORY.md's "Tray ↔ App ↔ Service — load-bearing fixes" and "Cross-cutting block-16 references" sections before touching IPC, push events, the QML bridge, or the apply pipeline.

**Acceptance criteria:** all `TODO(block-16)` markers in code must disappear by end of block. `grep -rn 'TODO(block-16)' apps/ core/ shared/` to triage.

## Implementation Task List

`TASKS_RU.md` is the primary implementation task list (Russian). It tracks all work items grouped by block, using `[ ]` / `[x]` checkboxes. Before starting any implementation, check the current block status here. This file should stay aligned with `README_RU.md`, `ARCHITECTURE_RU.md`, `SECURITY_RU.md`, and the two internal Russian spec documents (`TZ_Windows_Network_Policy_Manager_v2_1_RU.md`, `specifikaciya_modeli_pravil_i_marshrutizacii_v2_1_RU.md`). The spec documents must **not** be referenced in public-facing documentation.

**It holds only live work.** A new block is opened for a new *direction* of work, never for a batch of results:
- acceptance-run findings go under `## Приёмочные прогоны` as `### Прогон №NN (ДД.ММ) — тема`;
- small fixes and polish go under `## Доработки` as a dated subsection;
- once a sub-block or section has no open items left, it moves to `OLD_TASKS_RU.md` whole; individual closed items inside a live section move there too, except ones that head nested open sub-items;
- rationale, status reports and run write-ups do not belong here — reasoning lives in `notes/`, invariants and prohibitions live in this file, because this one is loaded every session and the task list is not. What stays is only what tells you when an open item is done.

Emoji are banned there as everywhere, status and warning glyphs included.

## Key Reference Files

- `AI_CONTEXT.md` / `AI_RULES.md` — working baseline rules for AI assistance
- `ARCHITECTURE.md` — component and runtime decomposition
- `TECHNICAL.md` — technical baseline, repository status, bootstrap details
- `SECURITY.md` — security model and trust boundaries
- `STRUCTURE.md` — maintained repository layout
- `configs/quality-baseline.md` — quality policy and naming conventions
