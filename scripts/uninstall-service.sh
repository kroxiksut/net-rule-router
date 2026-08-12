#!/usr/bin/env bash
# Linux counterpart of uninstall-service.ps1. Counterpart of install-service.sh.
#
# Difference from uninstall-service.ps1: `nrr-serviced uninstall` runs
# `systemctl disable --now`, which stops the unit as part of removing it — no
# separate `sc.exe stop`-style step is needed first.
#
# No --purge flag here: unlike the Windows binary, `nrr-serviced uninstall`
# does not yet expose a purge option (it always calls the keep-data uninstall
# spec). Service data under /var/lib/netrulerouter and /var/log/netrulerouter
# is left in place either way.
#
# Usage:
#   ./scripts/uninstall-service.sh
#   ./scripts/uninstall-service.sh --profile release

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"

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

cyan() { printf '\033[36m%s\033[0m\n' "$1"; }
green() { printf '\033[32m%s\033[0m\n' "$1"; }

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

resolve_service_binary() {
  local mode="$1"
  local debug_path="$target_root/debug/$exe_name"
  local release_path="$target_root/release/$exe_name"
  case "$mode" in
    dev) printf '%s\n' "$debug_path"; return ;;
    release) printf '%s\n' "$release_path"; return ;;
  esac
  if [ -f "$debug_path" ] && [ -f "$release_path" ]; then
    if [ "$release_path" -nt "$debug_path" ]; then
      printf '%s\n' "$release_path"
    else
      printf '%s\n' "$debug_path"
    fi
  elif [ -f "$debug_path" ]; then
    printf '%s\n' "$debug_path"
  elif [ -f "$release_path" ]; then
    printf '%s\n' "$release_path"
  else
    printf '%s\n' "$debug_path"
  fi
}

exe_path="$(resolve_service_binary "$profile")"

if [ ! -f "$exe_path" ]; then
  echo "Service binary not found at $exe_path. Cannot uninstall without it (need its \`uninstall\` verb)." >&2
  exit 1
fi

cyan "==> uninstall"
if [ "$(id -u)" -eq 0 ]; then
  "$exe_path" uninstall
else
  if ! command -v sudo >/dev/null 2>&1; then
    echo "root is required to remove the systemd unit, and sudo was not found. Re-run as root." >&2
    exit 1
  fi
  sudo "$exe_path" uninstall
fi

green "Service uninstalled. State DB and audit logs preserved."
