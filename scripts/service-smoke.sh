#!/usr/bin/env bash
# Linux counterpart of service-smoke.ps1: manual smoke checklist for the
# systemd service scaffold. Run with sudo available (or as root). Walks the
# canonical lifecycle so a regression in the service entrypoint is visible in
# one command.
#
# What this checks:
#   - install (enable+start) / uninstall flow returns success
#   - `systemctl is-active` reports active after install and after an
#     explicit start
#   - `systemctl is-active` reports inactive after an explicit stop
#   - service binary path resolves correctly
#
# Out of scope here: bootstrap pipeline, policy load, IPC server, apply
# attempts, journald content.
#
# Difference from service-smoke.ps1: `nrr-serviced install` already enables
# and starts the unit, so this walks stop-then-start explicitly afterwards to
# exercise both transitions the way the Windows checklist does with
# sc.exe start / sc.exe stop.
#
# Usage:
#   ./scripts/service-smoke.sh
#   ./scripts/service-smoke.sh --profile release
#   ./scripts/service-smoke.sh --console-only

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"

profile="dev"
console_only=0
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
    --console-only) console_only=1; shift ;;
    *)
      echo "unknown argument: $1 (expected --profile dev|release, --console-only)" >&2
      exit 2
      ;;
  esac
done
case "$profile" in
  dev|release) ;;
  *)
    echo "invalid --profile '$profile' (expected dev or release)" >&2
    exit 2
    ;;
esac

cyan() { printf '\033[36m%s\033[0m\n' "$1"; }
green() { printf '\033[32m%s\033[0m\n' "$1"; }
yellow() { printf '\033[33m%s\033[0m\n' "$1"; }

exe_name="nrr-serviced"
unit_name="netrulerouter.service"
profile_dir="debug"
[ "$profile" = "release" ] && profile_dir="release"
exe_path="$repo_root/target/$profile_dir/$exe_name"

if [ ! -f "$exe_path" ]; then
  cyan "Building $exe_name ($profile profile)..."
  if [ "$profile" = "release" ]; then
    (cd "$repo_root" && cargo build --release -p nrr-linux-service) >/dev/null
  else
    (cd "$repo_root" && cargo build -p nrr-linux-service) >/dev/null
  fi
fi

cyan "==> status verb (no systemd)"
"$exe_path" status

if [ "$console_only" -eq 1 ]; then
  yellow "--console-only set — skipping install/uninstall flow."
  exit 0
fi

sudo_prefix=()
if [ "$(id -u)" -ne 0 ]; then
  if ! command -v sudo >/dev/null 2>&1; then
    echo "install/uninstall require root, and sudo was not found. Re-run as root, or pass --console-only." >&2
    exit 1
  fi
  sudo_prefix=(sudo)
fi

cyan "==> install (enables and starts the unit)"
"${sudo_prefix[@]}" "$exe_path" install

cyan "==> systemctl is-active $unit_name (post-install, expected: active)"
if ! systemctl is-active --quiet "$unit_name"; then
  echo "unit is not active after install" >&2
  exit 1
fi
systemctl is-active "$unit_name" || true

cyan "==> systemctl stop $unit_name"
"${sudo_prefix[@]}" systemctl stop "$unit_name"
if systemctl is-active --quiet "$unit_name"; then
  echo "unit is still active after stop" >&2
  exit 1
fi

cyan "==> systemctl start $unit_name"
"${sudo_prefix[@]}" systemctl start "$unit_name"
if ! systemctl is-active --quiet "$unit_name"; then
  echo "unit did not become active after start" >&2
  exit 1
fi

cyan "==> uninstall (disables and stops the unit)"
"${sudo_prefix[@]}" "$exe_path" uninstall

cyan "==> systemctl show $unit_name (post-uninstall, expected: not-found)"
load_state="$(systemctl show "$unit_name" --property=LoadState --value 2>/dev/null || true)"
if [ "$load_state" != "not-found" ]; then
  echo "service still registered after uninstall (LoadState=$load_state)" >&2
  exit 1
fi

green "smoke checklist passed."
