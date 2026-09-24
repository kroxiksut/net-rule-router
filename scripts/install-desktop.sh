#!/usr/bin/env bash
# Installs the Linux desktop integration: the two entries from packaging/linux
# and the app icon into the hicolor theme. Without them a Wayland compositor
# has nothing to take the window name and icon from and shows the raw host
# binary name with a placeholder icon.
#
# Separate from install-service.sh by design: the service is a machine-wide
# daemon that needs root, this is session data a user installs for themselves;
# a headless machine running only the daemon has no session to integrate with.
#
# Exec is rewritten to the absolute path of the built binary — nothing installs
# the GUI itself yet, so the entry has to point into the build tree.
#
# Usage:
#   ./scripts/install-desktop.sh                    # current user
#   ./scripts/install-desktop.sh --system           # all users (needs root)
#   ./scripts/install-desktop.sh --profile release

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
# shellcheck source=lib/service-paths.sh
. "$script_dir/lib/service-paths.sh"
# shellcheck source=lib/desktop-paths.sh
. "$script_dir/lib/desktop-paths.sh"

scope="user"
profile="auto"
while [ "$#" -gt 0 ]; do
  case "$1" in
    --system)
      scope="system"
      shift
      ;;
    --user)
      scope="user"
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
      echo "unknown argument: $1 (expected --system|--user [--profile auto|dev|release])" >&2
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

if [ "$scope" = "user" ]; then
  nrr_refuse_sudo "Pass --system to act on the machine-wide scope."
fi

target_root="$(nrr_target_root "$repo_root")"
profile_dir="$(nrr_desktop_profile_dir "$target_root" "$profile")"

# The entry must launch the Unix spelling — see nrr_sync_unix_binaries.
nrr_sync_unix_binaries "$profile_dir"
nrr_desktop_unix_binary() {
  local unix_name="$1"
  if [ ! -x "$profile_dir/$unix_name" ]; then
    echo "executable was not found: $profile_dir/$unix_name" >&2
    echo "build it first: cargo build -p nrr-launcher -p nrr-qt-host" >&2
    return 1
  fi
  printf '%s\n' "$profile_dir/$unix_name"
}

gui_exec="$(nrr_desktop_unix_binary "$NRR_DESKTOP_GUI_ID")"
tray_exec="$(nrr_desktop_unix_binary "$NRR_DESKTOP_TRAY_ID")"

data_root="$(nrr_desktop_data_root "$scope")"
applications_dir="$data_root/applications"
icons_root="$data_root/icons/hicolor"

# Only the Exec line differs from the packaged entry. A path with spaces is
# quoted per the desktop-entry spec; `&` and `\` are escaped for sed.
nrr_install_entry() {
  local source_file="$1" exec_path="$2" dest_file="$3"
  case "$exec_path" in
    *\ *) exec_path="\"$exec_path\"" ;;
  esac
  local escaped
  escaped="$(printf '%s' "$exec_path" | sed -e 's/[&\\|]/\\&/g')"
  local staged
  staged="$(mktemp)"
  sed -e "s|^Exec=.*|Exec=$escaped|" "$source_file" >"$staged"
  nrr_desktop_run "$scope" install -D -m 0644 -T "$staged" "$dest_file"
  rm -f "$staged"
}

nrr_cyan "==> desktop entries -> $applications_dir"
nrr_install_entry "$repo_root/packaging/linux/$NRR_DESKTOP_GUI_ID.desktop" \
  "$gui_exec" "$applications_dir/$NRR_DESKTOP_GUI_ID.desktop"
nrr_install_entry "$repo_root/packaging/linux/$NRR_DESKTOP_TRAY_ID.desktop" \
  "$tray_exec" "$applications_dir/$NRR_DESKTOP_TRAY_ID.desktop"

nrr_cyan "==> icons -> $icons_root"
for size in "${NRR_DESKTOP_ICON_SIZES[@]}"; do
  icon_source="$repo_root/assets/icons/app/icon-$size.png"
  if [ -f "$icon_source" ]; then
    nrr_desktop_run "$scope" install -D -m 0644 -T "$icon_source" \
      "$icons_root/${size}x${size}/apps/$NRR_DESKTOP_ICON_NAME.png"
  else
    nrr_yellow "missing, skipped: $icon_source"
  fi
done
icon_svg="$repo_root/assets/icons/app/icon.svg"
if [ -f "$icon_svg" ]; then
  nrr_desktop_run "$scope" install -D -m 0644 -T "$icon_svg" \
    "$icons_root/scalable/apps/$NRR_DESKTOP_ICON_NAME.svg"
fi

nrr_desktop_refresh_caches "$scope" "$data_root"

nrr_green "Desktop integration installed ($scope scope)."
nrr_gray "GUI:  $gui_exec"
nrr_gray "Tray: $tray_exec"
nrr_gray "A running session may need a re-login before the new entries are matched."
