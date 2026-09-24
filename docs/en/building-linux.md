# Building from source (Linux)

**English** · [Русский](../ru/building-linux.md)

This guide is for those who want to build NetRuleRouter themselves on Linux.
The Windows guide is [a separate page](building-windows.md); macOS is later in
the plan.

Linux support is younger than the Windows one. The workspace builds, the test
suite runs, and the service applies policy on real hardware — but there is no
packaged release yet, so everything below starts from a checkout.

## What to install

| Software | Version | Why |
|----------|---------|-----|
| Git | any recent | clone the repository |
| [Rust (rustup)](https://rustup.rs/) | installs via rustup | the entire main codebase |
| A C/C++ toolchain | gcc or clang | linking, and the native Qt part |
| Qt 6 | 6.6+ | graphical interface |
| CMake | 3.21+ | build the native Qt part |
| `nftables` | any current | what the service applies its rules through |

On Debian and Ubuntu that is roughly:

```bash
sudo apt install build-essential cmake nftables \
     qt6-base-dev qt6-declarative-dev
```

The toolchain version is pinned in `rust-toolchain.toml`, so rustup downloads
the right one by itself on the first build.

> Debian and Ubuntu suffix the Qt 6 tools (`qmake6`, `qtpaths6`) so they can sit
> beside Qt 5. The build looks for both spellings; what it actually needs is the
> Qt 6 CMake package.

## Build

```bash
./scripts/bootstrap.sh          # checks prerequisites, creates .env, cargo check
./scripts/build.sh              # debug build
./scripts/build.sh --profile release
```

`bootstrap.sh --strict-qt` fails instead of warning when Qt or CMake are
missing — useful in CI, where a missing GUI dependency should stop the run
rather than produce a service-only build.

To build without the Qt host at all (the service, the console and every library,
but no GUI):

```bash
NRR_SKIP_QT_HOST=1 cargo build --workspace
```

That is what the CI job does, and it is the right switch on a headless machine.
Do not set it when you intend to run the GUI: the launcher would have no host to
start.

## Run

```bash
./scripts/run.sh --component gui
./scripts/run.sh --component tray
./scripts/run.sh --component service
```

The service normally runs as a systemd unit rather than from a terminal:

```bash
./scripts/install-service.sh            # builds, stages, enables and starts it
./scripts/service-status.sh             # what the unit and the policy are doing
./scripts/uninstall-service.sh
```

The unit is staged into `/usr/lib/netrulerouter` before it is registered: it
runs with `ProtectHome=yes`, and a daemon left under `/home` could only ever
fail at exec. Only the staging copy and the registration step use `sudo` — the
build stays unprivileged, so nothing in `target/` ends up owned by root.

Desktop integration (the application menu entry and the icon) is per-user
session data and installs separately:

```bash
./scripts/install-desktop.sh            # for your user
./scripts/install-desktop.sh --system   # for everyone, needs root
```

Run the per-user form as yourself, not through `sudo`: the paths it writes to
are resolved from your own session, and under `sudo` they would resolve for
root.

## Quality gate

```bash
bash scripts/check.sh --require-cargo-deny
```

Same gates in the same order as on Windows: formatting, clippy with warnings
denied, the full test suite, then `cargo deny`. Enforcement tests that need root
(nftables, live routes) skip loudly on their own.

If you develop on Windows and build Linux through WSL, run this gate before
pushing: code that compiles on one platform is not evidence about the other.

## Removing everything

```bash
./scripts/purge-data.sh                 # dry run: shows what it would delete
./scripts/purge-data.sh --yes
```

The audit trail is kept unless you add `--purge-audit`. Where each file lives is
listed in [Where NetRuleRouter keeps its files](where-files-live.md).
