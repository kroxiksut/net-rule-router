#!/usr/bin/env bash
# Shared path resolution and privileged helpers for the Linux service scripts
# (install / uninstall / status). Sourced, never executed.

# The checkout these scripts ship in: lib -> scripts -> repository root.
NRR_REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# Keep in sync with product_identity.rs: PRODUCT_NAME, PRODUCT_NAME_UNIX,
# SYSTEMD_UNIT_NAME and BinaryRole::Service. Both spellings are in play: our own
# directories use the unix one, the Qt organization/application pair the
# canonical one.
NRR_PRODUCT_NAME="NetRuleRouter"
NRR_PRODUCT_NAME_UNIX="netrulerouter"
NRR_TRAY_APP_NAME="NetRuleRouterTray"
NRR_UNIT_NAME="$NRR_PRODUCT_NAME_UNIX.service"
NRR_SERVICE_EXE_NAME="nrr-serviced"
NRR_SERVICE_ALIAS_NAME="nrr-service"

# The unit sets ProtectHome=yes, so a daemon under /home can never exec — the
# scripts stage the build-tree binary here and register it from this copy.
# The Windows scripts register the build output in place; nothing hides it there.
NRR_SERVICE_INSTALL_DIR="/usr/lib/$NRR_PRODUCT_NAME_UNIX"
NRR_STAGED_SERVICE_BINARY="$NRR_SERVICE_INSTALL_DIR/$NRR_SERVICE_EXE_NAME"

# The rest of the machine-wide footprint. Mirrors, in order, the install plan in
# platform/linux (systemd unit, logrotate drop-in, polkit actions), the systemd
# State/Logs/Runtime directories, and the enforcement table in lower_linux.rs.
NRR_UNIT_FILE="/etc/systemd/system/$NRR_UNIT_NAME"
NRR_LOGROTATE_CONFIG="/etc/logrotate.d/$NRR_PRODUCT_NAME_UNIX"
NRR_POLKIT_POLICY="/usr/share/polkit-1/actions/$NRR_PRODUCT_NAME_UNIX.policy"
NRR_STATE_DIR="/var/lib/$NRR_PRODUCT_NAME_UNIX"
NRR_AUDIT_DIR="$NRR_STATE_DIR/audit"
NRR_LOG_DIR="/var/log/$NRR_PRODUCT_NAME_UNIX"
NRR_RUNTIME_DIR="/run/$NRR_PRODUCT_NAME_UNIX"
NRR_NFT_FAMILY="inet"
NRR_NFT_TABLE="nrr"

# XDG autostart entry of the tray, per platform/linux autostart.rs.
NRR_TRAY_AUTOSTART_FILE="$NRR_PRODUCT_NAME_UNIX-tray.desktop"

# The per-user footprint, one absolute path per line, in the CALLER's profile —
# resolved at call time from their own XDG variables, so this must never be
# sourced by a script running as somebody else.
nrr_user_footprint_paths() {
  local home="${HOME:-}"
  [ -n "$home" ] || return 0
  local cache="${XDG_CACHE_HOME:-$home/.cache}"
  local data="${XDG_DATA_HOME:-$home/.local/share}"
  local state="${XDG_STATE_HOME:-$home/.local/state}"
  local config="${XDG_CONFIG_HOME:-$home/.config}"
  printf '%s\n' \
    "$config/$NRR_PRODUCT_NAME_UNIX" \
    "$cache/$NRR_PRODUCT_NAME_UNIX" \
    "$cache/$NRR_PRODUCT_NAME/$NRR_PRODUCT_NAME" \
    "$cache/$NRR_PRODUCT_NAME/$NRR_TRAY_APP_NAME" \
    "$data/$NRR_PRODUCT_NAME/$NRR_PRODUCT_NAME" \
    "$data/$NRR_PRODUCT_NAME/$NRR_TRAY_APP_NAME" \
    "$data/$NRR_PRODUCT_NAME/gui_metadata.db" \
    "$data/$NRR_PRODUCT_NAME/gui_metadata.db-wal" \
    "$data/$NRR_PRODUCT_NAME/gui_metadata.db-shm" \
    "$state/$NRR_PRODUCT_NAME_UNIX" \
    "$config/autostart/$NRR_TRAY_AUTOSTART_FILE" \
    "${TMPDIR:-/tmp}/$NRR_PRODUCT_NAME/managed"
  if [ -n "${XDG_RUNTIME_DIR:-}" ]; then
    printf '%s\n' "$XDG_RUNTIME_DIR/$NRR_PRODUCT_NAME_UNIX"
  fi
}

# Under sudo HOME is root's, so a per-user path set resolves for the wrong
# profile and the script reports success having touched nothing. $1 names the
# way to the privileged scope, which differs per script.
nrr_refuse_sudo() {
  if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ]; then
    echo "Run $(basename "$0") as your own user, not through sudo: the per-user" >&2
    echo "paths would resolve for root. $1" >&2
    exit 2
  fi
}

nrr_cyan() { printf '\033[36m%s\033[0m\n' "$1"; }
nrr_green() { printf '\033[32m%s\033[0m\n' "$1"; }
nrr_gray() { printf '\033[90m%s\033[0m\n' "$1"; }
nrr_yellow() { printf '\033[33m%s\033[0m\n' "$1"; }

# The effective Cargo target directory. `cargo metadata` honours both
# CARGO_TARGET_DIR and `.cargo/config.toml`, which the grep fallback cannot.
nrr_target_root() {
  local repo_root="$1" td=""
  if command -v cargo >/dev/null 2>&1; then
    td="$(cd "$repo_root" && cargo metadata --format-version 1 --no-deps 2>/dev/null |
      grep -oP '"target_directory":"\K[^"]+' | head -n1 || true)"
  fi
  if [ -z "$td" ]; then
    td="$(grep -oP '^\s*target-dir\s*=\s*"\K[^"]+' "$repo_root/.cargo/config.toml" 2>/dev/null | head -n1 || true)"
    case "$td" in
      "") td="$repo_root/target" ;;
      /*) ;;
      *) td="$repo_root/$td" ;;
    esac
  fi
  printf '%s\n' "$td"
}

# The build-tree daemon for a profile; 'auto' picks whichever exists and is newer.
nrr_built_service_binary() {
  local target_root="$1" mode="$2"
  local debug_path="$target_root/debug/$NRR_SERVICE_EXE_NAME"
  local release_path="$target_root/release/$NRR_SERVICE_EXE_NAME"
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

nrr_run_privileged() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
    return
  fi
  if ! command -v sudo >/dev/null 2>&1; then
    echo "root is required to run: $*  — and sudo was not found. Re-run as root." >&2
    return 1
  fi
  sudo "$@"
}

# Copy the built daemon to the system-wide location the unit can execute from.
# Written to a sibling and renamed: a running daemon holds its image open, and
# writing through it fails with ETXTBSY.
nrr_stage_service_binary() {
  local src="$1" tmp="$NRR_STAGED_SERVICE_BINARY.new"
  nrr_run_privileged install -D -m 0755 -T "$src" "$tmp"
  nrr_run_privileged mv -f "$tmp" "$NRR_STAGED_SERVICE_BINARY"
}
