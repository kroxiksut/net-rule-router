# Project Structure

## Purpose

This file defines the repository structure: what lives where, and why. It should be updated whenever the directory layout changes.

Maintenance rules:
- List directories and their roles, not individual files
- Do not include generated or temporary directories
- Do not include gitignored directories

## Top-Level Directories

### apps/
Application entry points and UI shells:
- **`apps/cli`** — Administrative console crate (`nrr-cli`): service lifecycle management, diagnostics, and network recovery. Never mutates policy.
- **`apps/desktop`** — Desktop runtime: Rust launcher process that spawns the C++ Qt host, Rust library crates for UI integration (`gui`, `tray`, `broker`), and build-only crate (`qt-host`) that compiles the C++ native host. Produces three binaries: `NetRuleRouter.exe` (main GUI), `NetRuleRouterTray.exe` (system tray), and `nrr_qt_native_host.exe` (C++ Qt rendering host).
  - `launcher` — User-facing Rust entry point, single-instance lock holder, preferences persistence, child process lifecycle. Also a library (`nrr_launcher`) consumed by tests and the broker
  - `gui` — GUI context and preference round-trip library
  - `tray` — System tray context library
  - `broker` — Elevation broker library: one elevated helper per session, re-entered through `NetRuleRouter.exe --nrr-elevated-broker`, so privileged operations cost one UAC prompt rather than one per action
  - `qt-host` — Build-only crate; drives CMake build of C++ host
  - `qml` — Qt/QML presentation layer: `Main.qml`, `Tray.qml`, `sections/` (+ `sections/settings/`), `flows/` (per-feature controllers), `components/`, `theme/`, `lib/` (shared JS)
  - `bridge` — Reserved for Qt bridge and tooling integration

### core/
Core product domain logic and service runtime:
- **`core/domain`** — Pure domain primitives and decision engine (routing rules, traffic classification, policy evaluation)
- **`core/application`** — Transport-agnostic backend facade
- **`core/platform/api`** — Platform-neutral port traits every OS backend implements; compiles on every target and depends on no OS API
- **`core/platform/windows`** — Windows implementations of those ports (WFP, routes, SCM, DNS, connection observation, VM inventory)
- **`core/platform/linux`** — Linux implementations (nftables, systemd, polkit, procfs observation)
- **`core/platform/nftlink`** — Crate `nftlink`: a standalone nf_tables netlink library, deliberately free of any product dependency so it can leave this repository as its own published crate (enforced by `tests/independence.rs`)
- **`core/services/windows-service`** — Windows service entrypoint: SCM/console entry, named-pipe server host, production dependency wiring. Orchestration logic belongs in `service-runtime`
- **`core/services/linux-service`** — Linux daemon entrypoint; produces `nrr-serviced` with an `nrr-service` alias
- **`core/services/service-runtime`** — Service orchestration shared by both OS entrypoints: enforcement planning and codegen, route coordination, DNS listener/resolver and fake-IP, kill-switch, auto-rules, IPC handlers, per-SID orchestration, session registry
- **`core/storage`** — SQLite persistence (domain cache, service state, traffic stats)
- **`core/storage-sidecar`** — GUI-owned SQLite sidecar (rule labels, passthrough, not-yet-applied edits); never holds routing policy
- **`core/diagnostics`** — Audit logs, operational logs, retention, archive generation
- **`core/ipc-client`** — NamedPipe IPC client for GUI/tray communication with service
- **`core/ui-support`** — UI-runtime-only modules (theme, first-run flow, preferences, tray)
- **`core/mock-backend`** — Preview/mock snapshots for development

### shared/
Shared, UI-runtime-independent contracts and types:
- **`shared/contracts`** — Crate `nrr-shared`: GUI/tray/service contracts, IPC payloads, product identity, diagnostics DTOs

### assets/
UI resources (no business logic):
- **`assets/icons`** — Icon files for app, tray, UI actions, and status indicators (multiple formats and high-contrast variants)
- **`assets/images`** — General UI images
- **`assets/brand`** — Logos and lockups

### configs/
Configuration schemas and policy templates:
- **`configs/localization`** — Locale schema, examples, and localization policy documentation
- **`configs/theme`** — Theme token definitions and dark mode guidance
- **`configs/presets`** — Built-in rule presets shipped with the product
- Ownership matrix (`OWNERSHIP.md`), quality policy (`quality-baseline.md`) and seed data (`default.config.yaml`, `doh-dot-resolvers.seed.json`) sit at this level

### docs/
User-facing and technical documentation:
- **`docs/en`** — English language user guides (CLI reference, routing modes, DNS/VPN topics, recovery procedures, component information)
- **`docs/ru`** — Russian language counterparts
- **`docs/legal`** — EULA and legal documents

### presets/
Rule set templates and examples for import/export

### locales/
Bundled baseline locale files (`en.json`, `ru.json`) — the source of truth for every user-visible string. User-supplied overrides live in managed local storage at runtime, not here.

### third_party/
Vendored third-party components redistributed with the product, with their licences

### packaging/
Files a platform's delivery installs but the build does not produce:
- **`packaging/linux`** — the two XDG desktop entries (`netrulerouter.desktop`, `netrulerouter-tray.desktop`). Their basenames are the Wayland `app_id` the Qt host declares via `setDesktopFileName`, which is how a compositor finds the window's name and icon.

### scripts/
Developer automation, PowerShell and shell side by side: bootstrap, build, run, check, service install/uninstall/status, desktop-entry install/uninstall, full data purge, network reset, smoke and speed probes, packaging, WSL gate. `scripts/lib/` holds path constants the shell scripts source (never execute); `scripts/dev/` holds one-off maintenance utilities.

### .github/
CI/CD workflow definitions (Windows and Linux quality gates)

## Workspace Root

Core configuration files:

- `Cargo.toml` — Rust workspace manifest
- `Cargo.lock` — Dependency lock
- `deny.toml` — Dependency/license policy
- `rust-toolchain.toml` — Rust version pin
- `.env.example` — Non-secret environment placeholder
- `.editorconfig` — Editor formatting
- `.gitignore` — Git exclusions
- `clippy.toml` — Lint configuration
- `README.md` / `README_RU.md` — Project overview
- `SECURITY.md` — Security model and trust boundaries
- `CONTRIBUTING.md` — How to contribute
- `AGENTS.md` — Working rules for AI assistants
- `THIRD_PARTY_LICENSES.md` — Licences of redistributed components
- `LICENSE` — MPL-2.0 license
- `STRUCTURE.md` — This file

Working documents that stay out of the published repository (architecture and technical baselines, task lists, lessons learned, design notes under `notes/`) are gitignored; see `.gitignore` for the current set.

## Crate Organization

Cargo workspace with these primary crates:
- `nrr-cli` — Console tool (apps/cli)
- `nrr-launcher` — Desktop app entry point (apps/desktop/launcher)
- `nrr-desktop-gui` — GUI library (apps/desktop/gui)
- `nrr-desktop-tray` — Tray library (apps/desktop/tray)
- `nrr-broker` — Elevation broker library (apps/desktop/broker)
- `nrr-qt-host` — Build-only crate for C++ host (apps/desktop/qt-host)
- `nrr-domain` — Domain logic
- `nrr-application` — Application facade
- `nrr-platform-api` — Platform traits
- `nrr-platform-windows` — Windows implementations
- `nrr-platform-linux` — Linux implementations
- `nftlink` — Standalone nf_tables netlink library (no product dependencies)
- `nrr-service-runtime` — Service orchestration
- `nrr-windows-service` — Windows service entrypoint
- `nrr-linux-service` — Linux daemon entrypoint
- `nrr-storage` — SQLite persistence
- `nrr-storage-sidecar` — GUI-owned SQLite sidecar
- `nrr-diagnostics` — Audit and logs
- `nrr-ipc-client` — IPC communication
- `nrr-ui-support` — UI runtime support
- `nrr-mock-backend` — Preview/mock snapshots
- `nrr-shared` — Contracts and shared types

The root `Cargo.toml` `members` list is the authority; add a crate there and here in the same change.

## Build and Runtime

**Workspace structure:**
- Root `Cargo.toml` defines the workspace
- Desktop binaries: `apps/desktop/launcher` produces both `NetRuleRouter.exe` and `NetRuleRouterTray.exe` via separate `[[bin]]` entries
- Service binary: `core/services/windows-service/` produces `nrr-service.exe` (Windows background service); `core/services/linux-service/` produces `nrr-serviced` with an `nrr-service` alias (the `d` suffix is the Unix convention, the alias keeps cross-platform scripts on one name)
- Console binary: `apps/cli/` produces `nrr-cli.exe` (administrative tool)
- C++ Qt host: `apps/desktop/qt-host/` is build-only (drives CMake, produces `nrr_qt_native_host.exe`)

**Developer scripts** (in `scripts/`):
- `bootstrap` — Prerequisite check and workspace initialization
- `build` — Compile binaries (dev or release profile)
- `run` — Launch individual components (GUI, tray, service)
- `check` — Canonical quality gate (fmt, clippy, test, cargo-deny)
- `clean-sync-duplicates` — Remove file-sync conflict copies
- `install-service` / `uninstall-service` / `service-status` / `service-smoke` — Service lifecycle for development
- `install-desktop` / `uninstall-desktop` — Linux only: desktop entries and hicolor icons, per user or machine-wide
- `purge-data` — Remove every trace the product leaves on a machine, so the next install starts clean. Shows what it would delete unless `--yes` / `-Yes` is given; keeps the audit trail unless `--purge-audit` / `-PurgeAudit` is given
- `reset-network` — Drop network state an abnormally stopped service left behind
- `wsl-gate` — Run the Linux gate from WSL2
- `package-windows` — Portable Windows package: binaries, the Qt and Visual C++
  runtimes, payload and a `build-info.json` stamp. See
  `docs/en/packaging-windows.md`.

**Quality policy:**
- `scripts/check.ps1` and `scripts/check.sh` enforce the local baseline
- `.github/workflows/windows-quality.yml` and `linux-quality.yml` mirror checks in CI
- `deny.toml` enforces dependency/license policy
- `configs/quality-baseline.md` documents quality and naming standards

## Architecture: Dependency Boundaries

### Allowed Dependencies

- `apps/desktop/launcher` can depend on: `gui/`, `tray/`, `broker/`, `qt-host/`, `application/`, `ui-support/`, `mock-backend/`, `contracts/`, `ipc-client/`, `storage-sidecar/`, `platform-api/` and the platform crate of the target OS
- `apps/cli` can depend on: `platform-api/`, `contracts/`, `ipc-client/`, plus the platform crate of the target OS
- `services/*-service` can depend on: `service-runtime/`, `contracts/`, `platform/`
- `service-runtime` can depend on: `platform/`, `domain/`, `contracts/`, `storage/`, `diagnostics/`
- `platform-api/` and the per-OS platform crates can depend on: `domain/`, `contracts/`
- `storage/` can depend on: `domain/`, `platform-api/`
- `domain/` can depend on: `contracts/` only

### Forbidden Dependencies

- Service runtime, service entrypoints and platform-specific code must not import GUI, tray, launcher, broker or preview crates — **at any depth**, enforced over the resolved dependency graph by `service-runtime/tests/dependency_boundary.rs`
- `services/*` must not depend on `application/` or `ipc-client/` — both edges dragged UI and preview crates into the service binary
- `platform/windows` and `platform/linux` must not depend on `apps/desktop/*` crates
- `domain/` must not depend on OS APIs, Qt, QML, or UI storage
- `storage/` must not depend on shared contracts, UI crates, or application layer
- `ipc-client/` must not depend on `service-runtime` at runtime (forces wire-protocol SSOT in contracts)
- `nftlink` must not depend on any `nrr-*` crate, so it can be published on its own (enforced by `core/platform/nftlink/tests/independence.rs`)

## Key Design Invariants

**Deployment:** Each of three binaries runs independently but communicates via IPC:
- `NetRuleRouter.exe` — Launcher spawns C++ Qt host child, polls host stdout for preference round-trip, persists on child exit
- `NetRuleRouterTray.exe` — Tray launcher (same architecture); can start independently or be spawned by GUI
- `nrr-service.exe` / `nrr-serviced` — background service; all processes read a shared `app-shutdown.flag` in the user runtime directory for coordinated exit
- `nrr_qt_native_host.exe` — C++ rendering process (discovered via embedded path, or adjacent binary lookup)

**IPC channels:**
- QML context → launcher via temp JSON file
- Preferences → host stdout polling (NRR_PREFS_JSON: lines)
- Backend calls → subprocess RPC over the host's stdio (`NRR_IPC_REQUEST` / `NRR_IPC_RESPONSE` / `NRR_IPC_PUSH` lines); cross-language linkage was rejected in favour of this
- Launcher ↔ elevation broker over a per-session local pipe
- GUI/Tray/Console ↔ Service via named pipe (`\\.\pipe\NetRuleRouter\service-v1`) on Windows, a unix socket under the runtime directory on Linux

**Code organization:**
- Business logic stays in Rust, never in QML or C++ glue
- GUI stays thin: section rendering, first-run flow, single-instance internals, prefs I/O belong in dedicated modules
- QML decomposition: `Main.qml` is shell only; sections as separate files under `qml/sections/`; Settings subsections under `qml/sections/settings/`; per-feature controllers under `qml/flows/`
- Cross-platform by construction: decision logic stays neutral, the OS mechanism goes behind a platform-api trait with one implementation per OS; a capability with no analog elsewhere is declared in `PlatformCapabilities` rather than branched on in QML
- All user-visible text must use `tr(key, fallback)` — locale files are the single source of truth; new text goes into both `locales/en.json` and `locales/ru.json` in the same change set
- Themed control wrappers (`ThemedButton`, `ThemedTextField`, `ThemedSpinBox`, `ThemedComboBox`) required for all user-visible controls to ensure consistent theming across light, dark, and high-contrast modes

## Maintenance Rule

If the repository layout changes, this file should be updated in the same change set.
