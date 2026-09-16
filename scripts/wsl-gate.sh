#!/usr/bin/env bash
# Run the Rust gate under WSL2 with a Linux-side target dir.
#
# Called as `wsl -d <distro> -- bash /mnt/d/.../scripts/wsl-gate.sh`: the
# Windows PATH WSL inherits contains parentheses, so passing this as `bash -c`
# breaks before the first command runs.
set -uo pipefail
export PATH="$HOME/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export CARGO_TARGET_DIR="$HOME/nrr-target"
# There is no Qt toolchain here; the desktop host is a Windows-side build.
export NRR_SKIP_QT_HOST=1
cd "$(dirname "$0")/.." || exit 1
cargo test --workspace --exclude nrr-launcher "$@"
