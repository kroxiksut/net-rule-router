#!/usr/bin/env bash
# Shared paths and helpers for the Linux desktop-integration scripts
# (install-desktop / uninstall-desktop). Sourced, never executed; both scripts
# source lib/service-paths.sh first for the colours and nrr_run_privileged.

# Desktop-entry basenames. A compositor matches a window's app_id against
# these, so they must equal the setDesktopFileName values in the Qt host and
# the file names under packaging/linux.
NRR_DESKTOP_GUI_ID="netrulerouter"
NRR_DESKTOP_TRAY_ID="netrulerouter-tray"

# Icon= in both entries, and the file name under hicolor/*/apps.
NRR_DESKTOP_ICON_NAME="netrulerouter"

# Cargo artifact names. Cargo cannot name a [[bin]] per OS, so the Unix
# spelling above is assigned by this install, not by the build.
NRR_DESKTOP_GUI_CARGO_NAME="NetRuleRouter"
NRR_DESKTOP_TRAY_CARGO_NAME="NetRuleRouterTray"

# Icon sizes assets/icons/app ships; each lands in hicolor/<size>x<size>/apps.
NRR_DESKTOP_ICON_SIZES=(16 24 32 48 64 128 256)

# Data root for the requested scope. A user-scope install needs no root.
nrr_desktop_data_root() {
  case "$1" in
    system) printf '%s\n' "/usr/share" ;;
    *) printf '%s\n' "${XDG_DATA_HOME:-$HOME/.local/share}" ;;
  esac
}

nrr_desktop_run() {
  local scope="$1"
  shift
  if [ "$scope" = "system" ]; then
    nrr_run_privileged "$@"
  else
    "$@"
  fi
}

# The cargo profile directory holding the launcher binaries; 'auto' picks
# whichever has the newer main-GUI artifact.
nrr_desktop_profile_dir() {
  local target_root="$1" mode="$2"
  local debug_dir="$target_root/debug" release_dir="$target_root/release"
  case "$mode" in
    dev) printf '%s\n' "$debug_dir"; return ;;
    release) printf '%s\n' "$release_dir"; return ;;
  esac
  local debug_bin="$debug_dir/$NRR_DESKTOP_GUI_CARGO_NAME"
  local release_bin="$release_dir/$NRR_DESKTOP_GUI_CARGO_NAME"
  if [ -e "$debug_bin" ] && [ -e "$release_bin" ]; then
    if [ "$release_bin" -nt "$debug_bin" ]; then
      printf '%s\n' "$release_dir"
    else
      printf '%s\n' "$debug_dir"
    fi
  elif [ -e "$release_bin" ]; then
    printf '%s\n' "$release_dir"
  else
    printf '%s\n' "$debug_dir"
  fi
}

# Refresh the caches a desktop environment reads. Both tools are optional —
# without them the entry still works, just possibly only after a re-login.
nrr_desktop_refresh_caches() {
  local scope="$1" data_root="$2"
  if command -v update-desktop-database >/dev/null 2>&1; then
    nrr_desktop_run "$scope" update-desktop-database "$data_root/applications" || true
  fi
  if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    nrr_desktop_run "$scope" gtk-update-icon-cache -f -t "$data_root/icons/hicolor" || true
  fi
}
