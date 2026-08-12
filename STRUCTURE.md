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
- **`apps/desktop`** — Windows desktop runtime: Rust launcher process that spawns the C++ Qt host, Rust library crates for UI integration (`gui`, `tray`), and build-only crate (`qt-host`) that compiles the C++ native host. Produces three binaries: `NetRuleRouter.exe` (main GUI), `NetRuleRouterTray.exe` (system tray), and `nrr_qt_native_host.exe` (C++ Qt rendering host).
  - `launcher` — User-facing Rust entry point, single-instance lock holder, preferences persistence, child process lifecycle
  - `gui` — GUI context and preference round-trip library
  - `tray` — System tray context library
  - `qt-host` — Build-only crate; drives CMake build of C++ host
  - `qml` — Qt/QML presentation layer (Main.qml, Tray.qml, reusable components, theme definitions, section files)
  - `bridge` — Reserved for Qt bridge and tooling integration

### core/
Core product domain logic and service runtime:
- **`core/domain`** — Pure domain primitives and decision engine (routing rules, traffic classification, policy evaluation)
- **`core/application`** — Transport-agnostic backend facade
- **`core/platform/windows`** — Windows-specific platform adapters
- **`core/platform/api`** — Platform-neutral port traits
- **`core/services/windows-service`** — Thin Windows service entrypoint (SCM/console entry only)
- **`core/services/service-runtime`** — Service orchestration: rule enforcement, IPC handlers, session registry
- **`core/storage`** — SQLite persistence (domain cache, service state)
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

### configs/
Configuration schemas and policy templates:
- **`configs/localization`** — Locale schema, examples, and localization policy documentation
- **`configs/theme`** — Theme token definitions and dark mode guidance

### docs/
User-facing and technical documentation:
- **`docs/en`** — English language user guides (CLI reference, routing modes, DNS/VPN topics, recovery procedures, component information)
- **`docs/ru`** — Russian language counterparts
- **`docs/legal`** — EULA and legal documents

### presets/
Rule set templates and examples for import/export

### locales/
User-provided locale override files at runtime

### scripts/
Developer automation: bootstrap, build, test, run, and code-health checking

### .github/
CI/CD workflow definitions (Windows quality gate)

## Workspace Root

Core configuration files:

- `Cargo.toml` — Rust workspace manifest
- `Cargo.lock` — Dependency lock
- `deny.toml` — Dependency/license policy
- `rust-toolchain.toml` — Rust version pin
- `.env.example` — Non-secret environment placeholder
- `.editorconfig` — Editor formatting
- `.gitignore` — Git exclusions
- `README.md` / `README_RU.md` — Project overview
- `SECURITY.md` — Security model and trust boundaries
- `LICENSE` — MPL-2.0 license
- `STRUCTURE.md` — This file

## Crate Organization

Cargo workspace with these primary crates:
- `nrr-cli` — Console tool (apps/cli)
- `nrr-launcher` — Desktop app entry point (apps/desktop/launcher)
- `nrr-desktop-gui` — GUI library (apps/desktop/gui)
- `nrr-desktop-tray` — Tray library (apps/desktop/tray)
- `nrr-qt-host` — Build-only crate for C++ host (apps/desktop/qt-host)
- `nrr-domain` — Domain logic
- `nrr-application` — Application facade
- `nrr-platform-api` — Platform traits
- `nrr-platform-windows` — Windows implementations
- `nrr-service-runtime` — Service orchestration
- `nrr-windows-service` — Windows service entrypoint
- `nrr-storage` — SQLite persistence
- `nrr-diagnostics` — Audit and logs
- `nrr-ipc-client` — IPC communication
- `nrr-ui-support` — UI runtime support
- `nrr-shared` — Contracts and shared types

## Build and Runtime

**Workspace structure:**
- Root `Cargo.toml` defines the workspace
- Desktop binaries: `apps/desktop/launcher` produces both `NetRuleRouter.exe` and `NetRuleRouterTray.exe` via separate `[[bin]]` entries
- Service binary: `core/services/windows-service/` produces `nrr-service.exe` (Windows background service)
- Console binary: `apps/cli/` produces `nrr-cli.exe` (administrative tool)
- C++ Qt host: `apps/desktop/qt-host/` is build-only (drives CMake, produces `nrr_qt_native_host.exe`)

**Developer scripts** (in `scripts/`):
- `bootstrap` — Prerequisite check and workspace initialization
- `build` — Compile binaries (dev or release profile)
- `run` — Launch individual components (GUI, tray, service)
- `check` — Canonical quality gate (fmt, clippy, test, cargo-deny)
- `clean-sync-duplicates` — Remove file-sync conflict copies
- `package-windows` — Portable Windows package: binaries, the Qt and Visual C++
  runtimes, payload and a `build-info.json` stamp. See
  `docs/en/packaging-windows.md`.

**Quality policy:**
- `scripts/check.ps1` and `scripts/check.sh` enforce the local baseline
- `.github/workflows/windows-quality.yml` mirrors checks in CI
- `deny.toml` enforces dependency/license policy
- `configs/quality-baseline.md` documents quality and naming standards

## Architecture: Dependency Boundaries

### Allowed Dependencies

- `apps/` can depend on: `application/`, `ui-support/`, `mock-backend/`, `contracts/`
- `service-runtime` can depend on: `application/`, `platform/`, `domain/`, `contracts/`, `storage/`, `diagnostics/`
- `platform-api/` and `platform/windows/` can depend on: `domain/`, `contracts/`
- `domain/` can depend on: `contracts/` only

### Forbidden Dependencies

- Service runtime and platform-specific code must not import GUI, tray, launcher, or preview crates
- `platform/windows` must not depend on `apps/desktop/*` crates
- `domain/` must not depend on Windows APIs, Qt, QML, or UI storage
- `storage/` must not depend on shared contracts, UI crates, or application layer
- `ipc-client/` must not depend on `service-runtime` at runtime (forces wire-protocol SSOT in contracts)

## Key Design Invariants

**Deployment:** Each of three binaries runs independently but communicates via IPC:
- `NetRuleRouter.exe` — Launcher spawns C++ Qt host child, polls host stdout for preference round-trip, persists on child exit
- `NetRuleRouterTray.exe` — Tray launcher (same architecture); can start independently or be spawned by GUI
- `nrr-service.exe` — Windows background service; all processes read shared `app-shutdown.flag` for coordinated exit
- `nrr_qt_native_host.exe` — C++ rendering process (discovered via embedded path, or adjacent binary lookup)

**IPC channels:**
- QML context → launcher via temp JSON file
- Preferences → host stdout polling (NRR_PREFS_JSON: lines)
- GUI/Tray ↔ Service via named pipe (`\\.\pipe\NetRuleRouter\service-v1`)

**Code organization:**
- Business logic stays in Rust, never in QML or C++ glue
- GUI stays thin: section rendering, first-run flow, single-instance internals, prefs I/O belong in dedicated modules
- QML decomposition: `Main.qml` is shell only; sections as separate files under `qml/sections/`; Settings subsections under `qml/sections/settings/`
- All user-visible text must use `tr(key, fallback)` — locale files are the single source of truth; new text goes into both `locales/en.json` and `locales/ru.json` in the same change set
- Themed control wrappers (`ThemedButton`, `ThemedTextField`, `ThemedSpinBox`, `ThemedComboBox`) required for all user-visible controls to ensure consistent theming across light, dark, and high-contrast modes

## Maintenance Rule

If the repository layout changes, this file should be updated in the same change set.
