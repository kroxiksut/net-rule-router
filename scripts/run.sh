#!/usr/bin/env bash
# Linux counterpart of run.ps1.
#
# GUI/tray note: the Qt host is a cross-platform CMake project (qt-add-executable
# does not gate on WIN32), but running it on Linux is unverified — this script
# attempts the same build+run steps run.ps1 uses on Windows and lets a real
# cargo/cmake error surface rather than pretending success.
#
# Usage:
#   ./scripts/run.sh --component gui
#   ./scripts/run.sh --component tray
#   ./scripts/run.sh --component service
#   ./scripts/run.sh --component gui --profile release

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"

component=""
# Same name/values/default as run.ps1's -Profile: default stays 'dev' so
# existing bare invocations keep working.
profile="dev"
while [ "$#" -gt 0 ]; do
  case "$1" in
    --component)
      component="${2:-}"
      shift 2
      ;;
    --component=*)
      component="${1#--component=}"
      shift
      ;;
    --profile)
      profile="${2:-}"
      shift 2
      ;;
    --profile=*)
      profile="${1#--profile=}"
      shift
      ;;
    *)
      echo "unknown argument: $1 (expected --component gui|tray|service [--profile auto|dev|release])" >&2
      exit 2
      ;;
  esac
done

case "$component" in
  gui|tray|service) ;;
  *)
    echo "usage: $0 --component gui|tray|service [--profile auto|dev|release]" >&2
    exit 2
    ;;
esac

case "$profile" in
  auto|dev|release) ;;
  *)
    echo "invalid --profile '$profile' (expected auto, dev, or release)" >&2
    exit 2
    ;;
esac

cyan() { printf '\033[36m%s\033[0m\n' "$1"; }

# Mirrors run.ps1's Resolve-ProfileBinary: 'dev'/'release' pick their
# subfolder directly, 'auto' picks whichever exists and is newer.
resolve_profile_binary() {
  local target_root="$1" bin_name="$2" mode="$3"
  local debug_path="$target_root/debug/$bin_name"
  local release_path="$target_root/release/$bin_name"

  case "$mode" in
    dev) printf '%s\n' "$debug_path"; return ;;
    release) printf '%s\n' "$release_path"; return ;;
  esac

  if [ -e "$debug_path" ] && [ -e "$release_path" ]; then
    if [ "$release_path" -nt "$debug_path" ]; then
      printf '%s\n' "$release_path"
    else
      printf '%s\n' "$debug_path"
    fi
  elif [ -e "$debug_path" ]; then
    printf '%s\n' "$debug_path"
  elif [ -e "$release_path" ]; then
    printf '%s\n' "$release_path"
  else
    printf '%s\n' "$debug_path"
  fi
}

# `cargo metadata` reports the effective target directory honouring both
# CARGO_TARGET_DIR and `.cargo/config.toml`'s `[build] target-dir`, so the
# binaries are always found regardless of where the workspace redirects them.
cargo_target_dir() {
  local json
  json="$(cargo metadata --format-version 1 --no-deps)"
  local td
  td="$(grep -oP '"target_directory":"\K[^"]+' <<<"$json" | head -n1)"
  if [ -z "$td" ]; then
    echo "could not determine the Cargo target directory from \`cargo metadata\`." >&2
    exit 1
  fi
  printf '%s\n' "$td"
}

if [ "$component" = "gui" ] || [ "$component" = "tray" ]; then
  build_args=(build -p nrr-launcher -p nrr-qt-host)
  if [ "$profile" = "release" ]; then
    build_args+=(--release)
  fi
  cyan "[run] cargo ${build_args[*]}"
  cargo "${build_args[@]}"

  target_dir="$(cargo_target_dir)"
  if [ "$component" = "gui" ]; then
    bin_name="NetRuleRouter"
  else
    bin_name="NetRuleRouterTray"
  fi
  bin_path="$(resolve_profile_binary "$target_dir" "$bin_name" "$profile")"

  if [ ! -x "$bin_path" ]; then
    echo "executable was not found: $bin_path" >&2
    exit 1
  fi

  cyan "[run] $bin_path"
  exec "$bin_path"
fi

# `run` is the daemon body itself on Linux (systemd's ExecStart passes it too),
# unlike Windows where a bare `console` argument is required to distinguish a
# foreground dev run from the SCM entrypoint. Full behaviour still needs root
# (writes under /var/lib, /var/log) — without it the daemon degrades to a
# report with no persistence, per the current bootstrap skeleton.
run_args=(run -p nrr-linux-service)
if [ "$profile" = "release" ]; then
  run_args+=(--release)
fi
run_args+=(-- run)

cyan "[run] cargo ${run_args[*]}"
exec cargo "${run_args[@]}"
