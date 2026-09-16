#!/usr/bin/env bash
# Run the Linux gate under WSL2 with a Linux-side target dir.
#
# Called as `wsl -d <distro> -- bash /mnt/d/.../scripts/wsl-gate.sh`: the
# Windows PATH WSL inherits contains parentheses, so passing this as `bash -c`
# breaks before the first command runs.
#
# Runs `scripts/check.sh` — the same gate the Linux CI job runs — rather than
# `cargo test` alone. Tests alone cannot see this class: a helper used only
# under `cfg(windows)` is alive in the test build (its unit test calls it) and
# dead in the plain lib, so only `clippy --all-targets -D warnings` reports it.
# A run that covered less than CI meant "green here, red there", which is the
# one thing this script exists to prevent.
set -uo pipefail
export PATH="$HOME/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export CARGO_TARGET_DIR="$HOME/nrr-target"
# There is no Qt toolchain here; the desktop host is a Windows-side build.
export NRR_SKIP_QT_HOST=1
cd "$(dirname "$0")/.." || exit 1
exec bash scripts/check.sh "$@"
