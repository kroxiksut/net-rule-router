#!/usr/bin/env bash
# Linux counterpart of install-service.ps1: registers the netrulerouter.service
# systemd unit. Mirrors the GUI's service-install bridge call: same
# ServiceControlPort implementation (LinuxServiceControl), different driver.
#
# Two differences from install-service.ps1:
#   * the build output is staged into /usr/lib/netrulerouter first — the unit
#     sets ProtectHome=yes and `install` refuses a daemon under /home, which
#     could only ever fail at exec with 203;
#   * `nrr-serviced install` enables AND starts the unit in one step
#     (`systemctl enable --now`), so there is no separate "start" call.
#
# Elevation: only the staging copy and the `install` invocation run under sudo,
# not the whole script — building stays unprivileged so target/ is not left
# root-owned.
#
# Usage:
#   ./scripts/install-service.sh
#   ./scripts/install-service.sh --profile release

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
# shellcheck source=lib/service-paths.sh
. "$script_dir/lib/service-paths.sh"

profile="auto"
while [ "$#" -gt 0 ]; do
  case "$1" in
    --profile)
      profile="${2:-}"
      shift 2
      ;;
    --profile=*)
      profile="${1#--profile=}"
      shift
      ;;
    *)
      echo "unknown argument: $1 (expected --profile auto|dev|release)" >&2
      exit 2
      ;;
  esac
done
case "$profile" in
  auto|dev|release) ;;
  *)
    echo "invalid --profile '$profile' (expected auto, dev or release)" >&2
    exit 2
    ;;
esac

target_root="$(nrr_target_root "$repo_root")"
exe_path="$(nrr_built_service_binary "$target_root" "$profile")"

if [ ! -f "$exe_path" ]; then
  echo "Service binary not found at $exe_path" >&2
  nrr_cyan "Building (cargo build -p nrr-linux-service)..."
  (cd "$repo_root" && cargo build -p nrr-linux-service) >/dev/null
  exe_path="$(nrr_built_service_binary "$target_root" "$profile")"
  if [ ! -f "$exe_path" ]; then
    echo "Service binary still missing after build at $exe_path" >&2
    exit 1
  fi
fi

# `enable --now` leaves an already-running unit running, so a reinstall would
# keep serving the previous image. Stopping first makes the restart the point
# of the reinstall rather than a coincidence.
if systemctl is-active --quiet "$NRR_UNIT_NAME" 2>/dev/null; then
  nrr_cyan "==> stop $NRR_UNIT_NAME (its image is about to be replaced)"
  nrr_run_privileged systemctl stop "$NRR_UNIT_NAME"
fi

nrr_cyan "==> stage $exe_path -> $NRR_STAGED_SERVICE_BINARY"
nrr_stage_service_binary "$exe_path"

# `install` registers the path it is invoked from (`current_exe()`), which is
# why this runs the staged copy and not the build output.
nrr_cyan "==> install"
nrr_run_privileged "$NRR_STAGED_SERVICE_BINARY" install

nrr_green "Service installed and started from $NRR_STAGED_SERVICE_BINARY."
"$script_dir/service-status.sh"
