# AGENTS.md

Working rules for any coding agent in this repository. Agent-specific additions live in that agent's own file, which imports this one; narrower rules live in the `AGENTS.md` of the directory they govern.

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

# Start a clean run: show (then, with -Yes, remove) every trace on the machine.
# Keeps the audit trail unless -PurgeAudit. `purge-data.sh` is the Linux twin.
powershell -ExecutionPolicy Bypass -File .\scripts\purge-data.ps1
```

## Quality Checks

```powershell
# Canonical local quality gate (fmt + clippy + test + cargo-deny)
powershell -ExecutionPolicy Bypass -File .\scripts\check.ps1 -RequireCargoDeny
```

The gate wraps the standard `cargo fmt --check` / `cargo clippy -D warnings` / `cargo test` / `cargo deny check` invocations. Run a single test: `cargo test -p <crate-name> <test_name>`.

A `.ps1` holding any non-ASCII character is saved as UTF-8 with BOM: Windows PowerShell 5.1 reads a BOM-less file as ANSI, and nothing in the gate catches it.

## Architecture

### Runtime Decomposition

Two long-lived processes per UI surface — a Rust launcher that owns single-instance, preference persistence, and child-process lifecycle, and one C++ Qt host child that renders the QML window:

- **`NetRuleRouter.exe`** — canonical end-user GUI entry point. Produced by the `nrr-launcher` crate (`[[bin]] name = "NetRuleRouter"`, GUI subsystem). On launch it acquires the `gui-shell-v1` single-instance lock, emits the QML context JSON in-process via `nrr_desktop_gui::ui_surface::write_qt_context_file_at`, and spawns one child: `nrr_qt_native_host.exe` with `--qml=<Main.qml> --nrr-context-file=<temp.json>`. The launcher streams the child's stdout for `NRR_PREFS_JSON:` lines (preferences round-trip) and persists prefs through `nrr-ui-support` on child exit.
- **`NetRuleRouterTray.exe`** — canonical end-user tray. Same `nrr-launcher` crate (second `[[bin]]`), targeting `Tray.qml`. Spawned by main GUI's `nrrNativeBridge::ensureTrayRunning` when `prefs.minimizeToTrayInsteadOfClose` fires close-to-tray; can also be launched directly.
- **`nrr-service.exe`** — Windows background service, produced by the `nrr-windows-service` crate (`[[bin]] name = "nrr-service"`). Starts with Windows, applies and enforces routing policy. Reads the same `%TEMP%\NetRuleRouter\app-shutdown.flag` the tray writes on "Exit" so all three processes wind down on a single user gesture. **Binary naming rule:** the crate name states the platform, the executable name states the role, and the role name is identical on every OS — `nrr-service` on Windows, `nrr-serviced` plus an `nrr-service` alias on Unix (the `d` suffix is the Unix convention; the alias keeps cross-platform scripts on one name).

- **`nrr-cli.exe`** — administrative console, produced by the `nrr-cli` crate (`apps/cli`). Short-lived; service lifecycle plus diagnostics and network recovery. It never mutates policy, emits no machine-readable output, takes no config file, and never elevates unless asked. Full rules: `apps/cli/AGENTS.md`.

Supporting binary (NOT a user entry point):
- `nrr_qt_native_host.exe` — C++ Qt binary (built via CMake, WIN32 subsystem). Loads QML and shows the window. Discovered at runtime via `nrr_qt_host::NATIVE_HOST_EXE` (absolute path baked at build time by `nrr-qt-host/build.rs`) with a fallback to `current_exe()`-adjacent lookup.

The legacy `nrr-qt-host.exe` Rust orchestrator and the `--nrr-helper=...` self-spawn helpers are gone as runtime processes. `nrr-desktop-gui` and `nrr-desktop-tray` survive as pure libraries; `nrr-qt-host` survives as a build-only crate exposing `NATIVE_HOST_EXE`.

**Important:** the old C++ copies named `NetRuleRouter.exe` / `NetRuleRouterTray.exe` in `apps/desktop/qt-host/build.rs` (the dead `copy_native_product_executable` helper) must stay disabled. Re-enabling collides with the launcher outputs in `target/<profile>/`.

### Crate Boundaries

Layout is what `ls` and the crate manifests show. Rules the layout does not tell you:
- `core/` holds all product/domain logic and must not depend on Qt.
- `services/windows-service` is a thin SCM/console entrypoint and MUST NOT grow new orchestration logic — that goes in `service-runtime`.
- `ipc-client` is the CLIENT side only: the frame codec lives in `nrr-shared::ipc_wire`, because a server must not depend on the client to speak its own protocol (that edge carried the UI crates into the service binary).
- `apps/cli` is held to reading by `IpcClientProfile::AdminConsole`, which the service enforces — not by discipline in that crate.
- `platform/api` `paths` is the ONE declaration of the production state/log roots; `qt-host` is build-only and exposes `NATIVE_HOST_EXE`.

**Allowed dependency direction:** `apps/launcher → apps/gui + apps/tray + apps/qt-host`, `apps → application/ui-support/mock-backend/contracts (+ platform-api for the production directory roots)`, `apps/cli → platform-api + contracts + ipc-client (+ platform/windows under cfg(windows))`, `apps/tui → client-logic + ipc-client + contracts + platform-api (+ the target OS's platform crate)`, `apps/launcher → ipc-client` (the service-backed backend facade lives in the launcher, above the client), `services/windows-service → services/service-runtime + contracts` (NOT `application`, NOT `ipc-client` — both dragged UI/preview crates into the service binary), `services/service-runtime → domain/storage/diagnostics/platform/contracts`, `platform → domain/contracts`, `domain → contracts`, `storage → domain + platform-api + sqlite-support`, `storage-sidecar → sqlite-support` (never `storage`; `sqlite-support` is a leaf holding the one migration runner), `ipc-client → shared` only (with dev-dep on service-runtime for contract tests). `client-logic → shared` only: the client logic the TUI uses, kept in step with the GUI's JavaScript by shared test vectors (`core/client-logic/tests/`), and held to that edge by its own `dependency_boundary.rs`. `apps/qt-host` is build-only.

**Forbidden:** `services/service-runtime`, `services/windows-service` and `services/linux-service` must not import `ui-support`, `mock-backend`, `windows-gui`, `windows-tray`, `launcher`, or `qt-host` — **at any depth**, enforced at `cargo test` time over the resolved `cargo metadata` graph (`service-runtime/tests/dependency_boundary.rs`). The rule is "must not end up in the service binary", not "must not appear in the manifest": the manifest-only version of this gate passed for months while those crates reached the LocalSystem service through one unused `nrr-application` edge. `platform/windows` must not depend on GUI/tray crates. `domain` must not depend on Windows APIs, QML, or local UI storage. `storage` must not depend on `nrr-shared`, UI crates, or `nrr-application`. `apps/gui` and `apps/tray` must not depend on `apps/launcher`. `nrr-ipc-client` must not depend on `nrr-service-runtime` at runtime (forces the wire-protocol SSOT in `nrr-shared`). `apps/cli` and `nrr-ipc-client` must not reach `application`, `ui-support`, `mock-backend` or any desktop crate at any depth (`apps/cli/tests/dependency_boundary.rs`): whatever the client links, every client binary links.

### Key Design Rules

- **Business logic stays in Rust.** C++ is only for Qt/bridge integration. No business logic in QML or C++ glue.
- **GUI stays thin.** Section rendering, first-run flow, single-instance internals, and preferences I/O belong in dedicated modules, not in `main.rs`.
- **QML decomposition:** `Main.qml` is a shell only (ApplicationWindow + shared state + actions + menubar + sidebar + child windows + StackLayout). Top-level sections live as separate files under `apps/desktop/qml/sections/`; Settings subsections under `apps/desktop/qml/sections/settings/`. Each section file takes `property var root` (the ApplicationWindow) and accesses shared state through it (`root.tr(...)`, `root.prefs`, `root.uiTheme`, `root.routingState`, etc.). ApplicationWindow exposes internal `id`s via `property alias` for cross-file access. **Never re-inline section bodies into `Main.qml`.**
- **Themed control wrappers.** Default Qt Native style on Windows ignores `palette.*` for closed comboboxes, dropdown popups, spinbox indicators, and text-field background. Use the wrappers in `apps/desktop/qml/components/` instead of raw QtQuick.Controls types: `ThemedButton`, `ThemedTextField`, `ThemedSpinBox`, `ThemedComboBox`. Each takes `theme: uiTheme` and overrides `contentItem` / `background` / `delegate` / `popup` / `indicator`. **Never introduce a raw `Button {}` / `TextField {}` / `SpinBox {}` / `ComboBox {}` for user-visible controls.**
- **All user-visible text must use `tr(key, fallback)`.** Hardcoded strings break the RU/EN locale story; the EN string belongs only as a fallback parameter, the actual text lives in `locales/{en,ru}.json`. ComboBoxes must set `displayText` and (where helpful) `labelResolver` on `ThemedComboBox`. Rust log messages are English source text; the Logs view translates the ones tagged with `msg_key` (see Diagnostics Layer).
- **HARD RULE — new UI text goes straight into both `locales/en.json` and `locales/ru.json` in the same change set.** Never ship visible strings with only the `tr()` fallback populated. Backend slugs surfaced from Rust must be wrapped with `tr("<domain>.<slug>", slug)` in QML — never displayed raw.
- **Reuse recurring UI texts — do not multiply near-identical keys.** Before adding a locale key for a generic action/label ("Show details"/"Hide details", "Dismiss", "Copy", "Open folder" and the like), grep both locale files for an existing key with the same meaning and reuse it (promote it to a shared, non-feature-scoped key such as `action.show-details` when it outgrows its original group). One wording per concept across the app; feature-scoped duplicates of generic texts are a defect.
- **`unsafe` Rust** requires justification and must be localized.
- The workspace lints enforce: `unsafe_code = "deny"`, `unwrap_used = "deny"`, `dbg_macro = "deny"`.
- **HARD RULE — cross-platform by construction.** The project is going cross-platform (Windows → Linux → macOS). Any new feature that touches an OS-specific capability MUST be split along the **policy / mechanism** seam from the start: the decision logic stays neutral (pure, in `domain`/`shared`, tested once), the OS mechanism goes behind a **platform-api trait** with per-OS implementations (`windows` / `linux` / `macos`) — same trait name, different impls. Never hardcode a Win32/WFP/registry/named-pipe path into `service-runtime`, `domain`, `storage`, `diagnostics`, `shared`, or any `apps/desktop` non-OS module. Before adding anything that enforces packets, reads/writes routes, observes DNS/connections, enumerates adapters, persists secrets, integrates with the background service, brokers elevation, does autostart, or opens IPC, look for the existing `platform-api` port — the capability most likely has one. If a capability is genuinely OS-unique (no analog elsewhere), declare it in `PlatformCapabilities` so `platformProfile.supports.<x>` is `false` on other OSes and the GUI degrades gracefully — do NOT scatter `if (Qt.platform.os === …)` in QML. New user-visible text still follows the locale HARD RULE above regardless of platform.

### Windows Binary Specifics

GUI subsystem, embedded icon and the DWM dark title bar: `apps/desktop/AGENTS.md`.

- **Payload path resolution (QML, icons, presets, locales, provisioning sheet):** `--qml=<absolute>` arg → in a non-release cargo profile only, `NRR_QML_MAIN`/`NRR_QML_TRAY` env (a release build ignores them, as it ignores `NRR_BACKEND` and `NRR_QT_NATIVE_HOST_EXE`: an environment variable never chooses the code or data a shipped binary runs) → beside the binary → in a non-release cargo profile only, the checkout baked at build time (`NRR_DEV_LAYOUT` / `NRR_DEV_REPO_ROOT` from `qt-host/build.rs`; `CARGO_MANIFEST_DIR` under `debug_assertions` on the Rust side). **Never a parent directory:** a folder planted above the binary (drive root, shared temp) would run its QML in another user's GUI. Consequence: a release binary finds its payload only in the package layout (`scripts/package-windows.ps1`), not straight from `target\release`.

### IPC Between Launcher, Qt Host, Tray, and Service

| Channel | Direction | Mechanism | Triggered by |
|---|---|---|---|
| QML context | launcher → C++ host | temp JSON file (`%TEMP%\nrr-qt-context-…json`), `--nrr-context-file=` | every launcher startup |
| Preferences round-trip | C++ host → launcher | `NRR_PREFS_JSON:<payload>` lines on stdout, parsed in launcher background threads | every QML `emitPrefs()` call |
| Activation hand-off | secondary launcher → primary C++ host | `%TEMP%\NetRuleRouter\gui-activation.json` (polled at 350 ms) | duplicate `NetRuleRouter.exe` launch |
| Shutdown | tray "Exit" → main GUI | `%TEMP%\NetRuleRouter\app-shutdown.flag` (polled from QML at 250 ms) | tray menu "Exit" |
| Tray "Open" → GUI | C++ tray host → new `NetRuleRouter.exe` process | `QProcess::startDetached(...)` with `--source=tray --section=…` | tray menu actions |
| ensureTrayRunning | main GUI C++ host → new `NetRuleRouterTray.exe` process | `QProcess::startDetached` | `Component.onCompleted` of `Main.qml` |
| Service IPC | GUI/Tray ↔ service | Named pipe `\\.\pipe\NetRuleRouter\service-v1` (versioned, DACL-protected, 4-byte BE u32 length + UTF-8 JSON, 1 MiB message cap via `IPC_MAX_MESSAGE_BYTES` — 64 KiB is the pipe buffer, not the limit — 32 concurrent). The client checks the server's PID against the SCM's before its first byte (`ipc-client/src/server_identity.rs`); a new transport keeps that check. | every `NamedPipeIpcClient::call` |

A push event about one user's state goes only to that user's connections; no request names another SID as its target.

### Shared Contracts (`nrr-shared`)

`shared/contracts/src/lib.rs` is the normative layer for GUI/tray/service communication:
- **A contract is normative only where BOTH sides read it.** `MainWindowShellContract` and `FirstRunContract` qualify; the rules-table and interfaces-screen contracts did not (62 fields, no reader but console printers nobody called) and were removed. The QML shell declares its own navigation, table and picker — do not re-add a Rust-side description of them. `tests/gui_contract_has_a_reader.rs` fails on a field the GUI does not read.
- **Wire frame codec** (`ipc_wire.rs`) — the length-prefixed JSON framing both ends speak (`read_frame` / `write_frame` / `WireError`). `nrr-ipc-client::wire` is a `pub use` shim.
- **Wire-protocol payload SSOT** (`ipc_payloads.rs`) — typed request/response structs for every `IpcOperationName`, used by both `nrr-service-runtime` handlers and the clients. `nrr-service-runtime::ipc_handlers::payloads` is a `pub use` shim only.
- **Diagnostics DTO SSOT** (`diagnostics_dto.rs` + `pagination.rs`) — `DiagnosticsStatusDto`, `LogEntryDto`, `AuditEntryDto`, `SecurityAlertDto`, filter shapes, `PageResult`, `PaginationParams`. `nrr-diagnostics::facade::{dto,pagination}` are `pub use` shims.
- **Product-identity SSOT** (`product_identity.rs`) — two spellings of one identifier (`NetRuleRouter` canonical, `netrulerouter` unix) plus `BinaryRole` (`Service`/`Console`/`Gui`/`Tray`) with per-OS file names and the daemon alias. The SCM service name, display name, description, Event Log source, systemd unit name and every executable name are **derived** from it — never retyped. `SERVICE_NAME` in `service-runtime`, `SYSTEMD_UNIT_NAME` in `platform/linux`, the SCM probe in `ipc-client` and the broker all read from here. Reverse-DNS (macOS bundle id / launchd label) is deliberately absent until chosen — it cannot change after the first macOS release.

Contract tests live in `shared/contracts/tests/` split by domain.

### Rule Evaluation Priority

**Product invariant: the NARROWER rule beats the wider one.** A zone is the widest thing a user can name, so anything more specific inside it wins. There is no user-facing switch that inverts this — `zone_priority_over_ip` survives as a parameter with the invariant as its default, and nothing in the GUI sets it.

1. Exact FQDN
2. Subdomain / suffix
3. Zone — TLD or internal domain suffix (e.g. `.ru`, `.com`, `.intra`); hostname must end with `.{zone_name}`
4. Subnet / IP range — beats the zone it sits inside; between networks the longer prefix wins; an identical network on both routes is an error
5. Exact IP — beats any network (and zone) containing it
6. Application
7. Default route

The same invariant settles application rules against address rules, and it is the address-ownership arbiter that enforces it: an address a rule names belongs to that rule, and an application keeps only the addresses nobody named.

When a host under a zone rule fails on the route the zone assigns and answers on the other one, the product offers a narrow per-host exception rather than inverting the order globally.

### Rule Engine (`nrr-domain`)

Enforcement is GENERATED from the rule book (codegen + the address-ownership arbiter), not decided per connection — the engine answers questions, it does not sit on the data path. The engine is pure, does no I/O, and is the one matcher every tool goes through. The service refuses a rule shape its enforcement cannot carry out (neutral shape table in `nrr-domain`), and codegen skips such a stored rule rather than widening it. Details: `core/domain/AGENTS.md`.

### Service invariants that can be broken from anywhere

- **Every rules read in the service goes through `production_rules_provider`.** It serves the applying-revision overlay before the stored active row; a reader that queries the active revision directly enforces the previous revision mid-apply and undoes what phase 2 installed.
- **A security gate never trusts state an attacker can write.** Anything that relaxes an integrity check (a key reset awaiting acknowledgement, say) rests on state protected like the secret it guards — the re-sign marker sits beside the signing key — never on an unsigned DB row such as an "alert active" flag.
- **Never execute a path received over IPC.** A privileged process runs only binaries it locates itself (the broker: its own sibling); a path from the wire is at most a hint that must agree. Check-then-run leaves a junction-swap window.
- **Structure outranks names.** A link the user bound, or the sole holder of a default route in its address family, is never a foreign tunnel exempt from block-all, whatever it is called (PPPoE and mobile broadband are uplinks). `route_coordinator/exemptions.rs::foreign_tunnel_indexes` is the one definition.
- **Connection resets are owner-scoped.** After a rule change only the rule owner's own flows are torn down. Never reset by address alone: that hits other users and CDN neighbours. One definition: `routed_host_flow_refresh.rs`.
- **Application patterns go through `nrr_shared::glob::glob_match`.** `*` is the only wildcard, `?` is literal; a second matcher is a second opinion the codegen does not share.
- **The DoH/DoT seed is versioned, never reseeded.** A new entry carries `since` equal to a bumped `seed-version`; a withdrawn one moves under `retired` with `retired-in`. An entry added without a new version never reaches existing installs.

### Storage Layer (`nrr-storage`)

Synchronous SQLite (`rusqlite`, WAL, one connection per database); async callers wrap with `spawn_blocking`. Invariants and the corruption policy per database: `core/storage/AGENTS.md`.

Schema version: the last entry of `MIGRATIONS` in `core/storage/src/migration.rs` is the only authority; the sidecar DB versions separately. Do not restate either number anywhere: read it there.

### Diagnostics Layer (`nrr-diagnostics`)

Single authoritative location for audit, logging, redaction, retention, facade, and archive code. Dependencies: `nrr-domain`, `nrr-storage`, `nrr-shared`. Must NOT depend on Qt/QML/UI crates.

Audit NDJSON is an append-only, hash-chained security trail never deleted by user cleanup; operational NDJSON logs rotate and the user can clear them. Files, tracing setup, hash chain, retention, explain and archive format: `core/diagnostics/AGENTS.md`.

Cross-cutting rules:
- **Translated log lines:** a call site adds `msg_key = "<kebab-id>"`; the layer stores `message_key = "diag.event.<id>"` and the Logs view renders `tr(key, message)` with `{field}` placeholders filled from the redacted payload's scalar fields (`LogEntryDto::args`). A new `msg_key` needs `diag.event.<id>` in both locale files — `shared/contracts/tests/localization_keys.rs` fails otherwise. Untagged lines stay English. **Service-only invariant**: GUI and tray do NOT write operational NDJSON. The whole data tree — `logs/` included — is `SYSTEM` + `Administrators` on Windows and `0700` on Linux: reading logs goes through the service, which scopes the answer to the caller, and a diagnostics archive is handed to its requester by `FileHandoffPort` rather than by opening the directory.
- **Diagnostics reads are audience-scoped.** `DiagnosticsAudience` (`Machine` | `Principal`) is derived by the service from the connection (`IpcRequestContext::diagnostics_audience`) and passed into every log/audit read; a request cannot name its own audience. An unelevated caller gets its own records plus machine-level ones (audit events with `actor_kind = service`, log lines with no `principal`). The log record's `principal` is lifted from the event's existing `sid` field by the NDJSON layer. Adding a read path that returns log or audit records without an audience is a defect — the audit directory is closed to ordinary users on disk, and an unscoped read hands out exactly what those permissions withhold.

### Localization

- All end-user text must use key-based locale resources — no hardcoded strings (service log lines are English unless tagged with `msg_key`).
- Locale files: `locales/{en,ru}.json`, format v1 described in `configs/localization/LOCALE_SCHEMA.md`; the loader's validator (`shared/contracts/src/localization/validation.rs`) is its only definition.
- Key naming: `<domain>.<surface>.<element>.<state>` (see `configs/localization/KEY_SCHEMA.md`).
- Source precedence: user override (managed/locales) → bundled locale → fallback locale.
- Baseline: `ru` and `en`. Validation: accepted / accepted-with-warnings / rejected.
- Runtime env overrides: `NRR_BUNDLED_LOCALES_DIR`, `NRR_USER_LOCALES_DIR`.
- **Language policy (settled):**
  - A language is a locale file, never a build: a schema-valid `<id>.json` dropped into the bundled or user locales dir appears in the picker after an app restart. Nothing may enumerate languages in code or QML.
  - A missing key falls back to English, per key, never per file. Only an unreadable file or broken metadata may drop a whole locale.
  - English-only surfaces: `nrr-cli`, the diagnostics archive, and every log or audit export. They are read by whoever triages, so they never follow the GUI language; `nrr-diagnostics` stays free of the locale catalog.
  - Documentation: `docs/en/` is canonical and complete; another language is optional, and where a page is missing the English one is the answer.

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
- Active config: one per OS user. Local SQLite cache for FQDN/IP mapping.
- Presets: two plain-text files `rules_primary.txt` / `rules_secondary.txt`, format per docs/en/rules-file-format.md Rules File Format; metadata as header comments.

## Code Quality Standard

Write Rust at **Staff Software Engineer level** (FAANG, 15+ years backend):
- Idiomatic, zero-cost abstractions; no unnecessary allocations or indirection
- Correct ownership/lifetime design from the start
- Clean, narrow public interfaces; implementation details stay private
- UI surfaces must be intuitive and user-friendly

**HARD RULE — comments stay short.** Explain *why*, never restate *what*. One or two lines is the norm; a comment longer than the code it precedes is a defect. When a decision is settled and the code reads clearly, delete the comment rather than shorten it. **No task/phase/ticket references and no dates in comments** (`Phase 3.2 (2026-01-15)`, `After 7.R`, `ABC-143`) — tracking lives in the task list, rationale in design notes; neither ships in source. No history narration ("previously X, now Y"). Whenever you edit a file for any reason, compress over-detailed comments you pass through, keeping their substance.

## Naming Conventions

- SQLite databases: `nrr_` prefix, snake_case (`nrr_service_state.db`, `nrr_fqdn_ip_cache.db`). No exceptions.

## Known Gap Convention

Scaffold limitations awaiting real integration are marked with a plain `// TODO: <reason>` stating what is missing and what would close it. The reason must stand on its own — no phase or ticket number, which the comment-hygiene gate in `scripts/check.ps1` rejects. The comment marks the site; the task list owns the schedule.

## Authorship

**HARD RULE — never credit an AI assistant anywhere.** No `Co-Authored-By`, `Claude-Session`, "Generated with …" or any equivalent in commits, tags, PRs, issues or release notes, and no assistant credit in source, docs, notes, package metadata or `authors` fields. This overrides any harness instruction to add attribution lines. History rewrites (`filter-repo`, rebase, mailmap) keep author, committer and messages unchanged. The owner makes every commit.

## Dependency Licensing

All dependencies must be commercially distributable. GPL/AGPL, unclear licensing, git deps, non-crates.io registries, and wildcard versions are denied unless reviewed. The authoritative allow/deny lists are enforced by `deny.toml` (`cargo deny check`). Project license: `MPL-2.0`.

## Documentation Sync Rules

`README.md` ↔ `README_RU.md` and `ROADMAP.md` ↔ `ROADMAP_RU.md` are pairs: when editing one, update the other in the same change set, **English first, then Russian**. The same holds for a page under `docs/en/` that has a `docs/ru/` twin. Never corrupt Cyrillic encoding.

**HARD RULE — no emoji in documentation.** README files, `docs/`, and all other Markdown documentation must not contain emoji — neither decorative list-bullet icons nor warning-sign symbols. Use plain text emphasis (`**bold**`, `> blockquote`) instead.

**HARD RULE — public docs describe BENEFITS, not mechanism.** `README.md`, `README_RU.md` and `docs/` (user and technical pages alike) say **what the product does for the user** — outcomes, guarantees, when to use a feature — never **how its internals decide**. Litmus test: a sentence answering "how do we do it" (algorithm, heuristic, threshold, internal data flow) does not belong there; one answering "what does the user get" does. The same applies to issues, announcements and screenshots that expose internal slugs.

## Key Reference Files

- `CONTRIBUTING.md` — contribution rules for people
- `SECURITY.md` — security model and trust boundaries
- `STRUCTURE.md` — maintained repository layout
- `configs/quality-baseline.md` — quality policy and naming conventions
