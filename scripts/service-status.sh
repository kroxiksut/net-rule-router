#!/usr/bin/env bash
# Linux counterpart of service-status.ps1. Read-only, no elevation required.
#
# Combines `systemctl status` (systemd-canonical state) with a one-line
# diagnostic banner from the service binary's `status` verb. Useful as a
# quick check from any terminal — equivalent to the GUI's
# `nrrServiceController.status` property.
#
# Usage:
#   ./scripts/service-status.sh

set -uo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
# shellcheck source=lib/service-paths.sh
. "$script_dir/lib/service-paths.sh"

nrr_cyan "==> systemctl status $NRR_UNIT_NAME"
systemctl status --no-pager "$NRR_UNIT_NAME"
status_exit=$?

if [ "$status_exit" -eq 4 ]; then
  nrr_yellow "Service not registered (systemctl exit=$status_exit)."
  exit 0
fi

# The staged copy is the binary the unit actually runs, so its banner describes
# the installed service; the build output only stands in when nothing is staged.
exe_path=""
if [ -f "$NRR_STAGED_SERVICE_BINARY" ]; then
  exe_path="$NRR_STAGED_SERVICE_BINARY"
else
  candidate="$(nrr_built_service_binary "$(nrr_target_root "$repo_root")" auto)"
  [ -f "$candidate" ] && exe_path="$candidate"
fi

if [ -n "$exe_path" ]; then
  echo ""
  nrr_cyan "==> $NRR_SERVICE_EXE_NAME status"
  "$exe_path" status
else
  echo ""
  nrr_gray "(Service binary found neither staged nor in target/. Skipping orchestration banner.)"
fi
