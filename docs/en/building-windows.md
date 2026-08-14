# Building from source (Windows)

**English** · [Русский](../ru/building-windows.md)

This guide is for those who want to build NetRuleRouter themselves. If you
just want to use the app — download the ready archive from the releases
page and follow the [quick start](quickstart.md).

This page is about building for **Windows 10/11 (64-bit)**. The Linux
guide will be a separate document (`building-linux.md`) once Linux builds
are supported; macOS is later in the plan.

## What to install

| Software | Version | Why |
|----------|---------|-----|
| [Git](https://git-scm.com/download/win) | any recent | clone the repository |
| [Rust (rustup)](https://rustup.rs/) | installs via rustup | the entire main codebase |
| [Visual Studio 2022 Build Tools](https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022) | 17.x | MSVC compiler and Windows SDK |
| [Qt 6](https://www.qt.io/download-open-source) | 6.11.x (msvc2022_64) | graphical interface |
| [CMake](https://cmake.org/download/) | 3.26+ | build the native Qt part |

Details for each item:

### Rust

Install [rustup](https://rustup.rs/) — on first build it will download
the toolchain version by itself: it is pinned in `rust-toolchain.toml`
(currently `1.94.1`), you do not need to choose manually. The target
platform is `x86_64-pc-windows-msvc` (installed by default on Windows).

### Visual Studio 2022 Build Tools

Full Visual Studio is not necessary — Build Tools is enough. During
installation, mark the **Desktop development with C++** workload: it
includes MSVC v143 compiler and Windows SDK. Without MSVC, neither the
Rust part (msvc-target) nor the Qt host will build.

### Qt 6

Download the official [Qt online installer](https://www.qt.io/download-open-source)
(open-source, LGPLv3). In the installer, select:

- **Qt 6.11.x → MSVC 2022 64-bit** — the base package already contains
  all needed modules (Core, Gui, Qml, Quick, QuickControls2, Widgets);
  extra libraries (Charts, Data Visualization, etc.) are not required.

The build finds the default path itself: it takes the newest version from
`C:\Qt\<version>\msvc2022_64` (for example `C:\Qt\6.11.1\msvc2022_64`).
If Qt is installed elsewhere — see the "Environment variables" section
below.

> The package must be **MSVC**, not MinGW — otherwise linking will fail.

### CMake

CMake 3.26+ must be available in `PATH` (check: `cmake --version`).
You can install it with a separate installer (checkmark "Add CMake to
PATH") or as a component of Visual Studio Build Tools.

## Building

```powershell
# 1. Clone the repository
git clone https://github.com/kroxiksut/net-rule-router.git
cd net-rule-router

# 2. Check environment and create .env
powershell -ExecutionPolicy Bypass -File .\scripts\bootstrap.ps1

# 3. Build release binaries: GUI launcher, native Qt host, service
cargo build --release -p nrr-launcher -p nrr-qt-host -p nrr-windows-service

# 4. Run
.\target\release\NetRuleRouter.exe          # main window
.\target\release\NetRuleRouterTray.exe      # tray
```

The first build takes noticeable time: cargo builds a substantial part of
the workspace, and CMake inside `nrr-qt-host` builds the C++ host.

### Background service

The service applies and maintains the routing policy. Installation requires
administrator rights (UAC prompt raises automatically).

The easiest way is from the app itself: **Settings → Service management →
Install service**. There you can also start, stop, restart, remove, and
check the status.

From console — the same operations via scripts:

```powershell
.\scripts\install-service.ps1 -Profile release   # install and start
.\scripts\service-status.ps1                     # check status
.\scripts\uninstall-service.ps1                  # remove
```

### Dev build (for those editing code)

Same as above but without `--release` — faster to compile, with debug
info, binaries in `target\debug\`:

```powershell
cargo build -p nrr-launcher -p nrr-qt-host -p nrr-windows-service
.\target\debug\NetRuleRouter.exe
.\scripts\install-service.ps1      # without -Profile takes the freshest binary (dev or release)
```

### Building only the C++ Qt host

The Qt host has no build target of its own — it is produced by the build
script of the `nrr-qt-host` crate, so building that crate alone is enough:

```powershell
cargo build -p nrr-qt-host              # dev
cargo build -p nrr-qt-host --release    # release

# force a full CMake reconfigure after non-tracked C++ changes
cargo clean -p nrr-qt-host; cargo build -p nrr-qt-host
```

The result is `nrr_qt_native_host.exe` under
`target\<profile>\build\nrr-qt-host-*\out\qt-native-host-build\<config>\`.
It is deliberately not copied into `target\<profile>\` — the launcher finds
it by the absolute path baked in at build time. Changes to `CMakeLists.txt`,
`src\main.cpp` and `resources\app.rc.in` are picked up without `cargo clean`.

Dev builds compile the C++ host as `RelWithDebInfo`, not `Debug`: symbols are
kept, and the app links the same Qt libraries a user runs. Set
`NRR_QT_HOST_BUILD_TYPE=Debug` when the C++ itself is what you are debugging.

### Quality checks (for contributors)

```powershell
# fmt + clippy + tests + license/dependency audit
powershell -ExecutionPolicy Bypass -File .\scripts\check.ps1 -RequireCargoDeny
```

For the `-RequireCargoDeny` flag you need [cargo-deny](https://github.com/EmbarkStudios/cargo-deny):
`cargo install cargo-deny`. Without it — the same script without the flag.

## Environment variables

| Variable | When needed | Example |
|----------|-------------|---------|
| `CMAKE_PREFIX_PATH` | Qt installed not under `C:\Qt` or you need a specific version | `D:\Qt\6.11.1\msvc2022_64\lib\cmake` |
| `NRR_QT_HOST_GENERATOR` | non-standard CMake generator (default `Visual Studio 17 2022`) | `Ninja` |
| `NRR_QT_HOST_BUILD_TYPE` | CMake configuration of the C++ host (default `Release` for `--release`, otherwise `RelWithDebInfo`) | `Debug` |
| `NRR_SKIP_QT_HOST` | build the Rust part without Qt at all — used by CI; the produced binaries cannot open a window | `1` |
| `NRR_RUST_TARGET` | non-standard rust-target (default `x86_64-pc-windows-msvc`) | — |

Set for the current PowerShell session:

```powershell
$env:CMAKE_PREFIX_PATH = "D:\Qt\6.11.1\msvc2022_64\lib\cmake"
cargo build --release -p nrr-launcher -p nrr-qt-host -p nrr-windows-service
```

## Common issues

**`CMAKE_PREFIX_PATH is not set and default Qt CMake path ... was not found`**
— the build did not find Qt. Install Qt 6.11 (msvc2022_64) or set the
path via `CMAKE_PREFIX_PATH` (see above).

**`cmake: command not found` / `'cmake' is not recognized`**
— CMake is not in `PATH`. Reinstall with the "Add CMake to PATH" checkmark
or add the path manually, then restart the terminal.

**Linking errors mentioning Qt libraries**
— almost always the wrong Qt package is selected (MinGW instead of MSVC)
or bitness is not x64. You need exactly **MSVC 2022 64-bit**.

**Built `NetRuleRouter.exe` does not run on another machine**
— local builds (both dev and release) are not portable: paths to QML files
and locales are tied to the source tree on the build machine. For running
"anywhere" use the ready release archive from the releases page.

---

Русская версия: [docs/ru/building-windows.md](../ru/building-windows.md).
