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

cyan() { printf '\033[36m%s\033[0m\n' "$1"; }
gray() { printf '\033[90m%s\033[0m\n' "$1"; }
yellow() { printf '\033[33m%s\033[0m\n' "$1"; }

# Keep in sync with SYSTEMD_UNIT_NAME in shared/contracts/src/product_identity.rs.
unit_name="netrulerouter.service"

cyan "==> systemctl status $unit_name"
systemctl status --no-pager "$unit_name"
status_exit=$?

if [ "$status_exit" -eq 4 ]; then
  yellow "Service not registered (systemctl exit=$status_exit)."
  exit 0
fi

exe_name="nrr-serviced"

resolve_target_root() {
  local cfg="$repo_root/.cargo/config.toml" td
  if [ -f "$cfg" ]; then
    td="$(grep -oP '^\s*target-dir\s*=\s*"\K[^"]+' "$cfg" 2>/dev/null | head -n1 || true)"
    if [ -n "${td:-}" ]; then
      case "$td" in
        /*) printf '%s\n' "$td"; return ;;
        *) printf '%s\n' "$repo_root/$td"; return ;;
      esac
    fi
  fi
  printf '%s\n' "$repo_root/target"
}
target_root="$(resolve_target_root)"
debug_path="$target_root/debug/$exe_name"
release_path="$target_root/release/$exe_name"
exe_path=""
[ -f "$debug_path" ] && exe_path="$debug_path"
[ -z "$exe_path" ] && [ -f "$release_path" ] && exe_path="$release_path"

if [ -n "$exe_path" ]; then
  echo ""
  cyan "==> $exe_name status"
  "$exe_path" status
else
  echo ""
  gray "(Service binary not found in target/. Skipping orchestration banner.)"
fi
