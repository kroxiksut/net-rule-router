#!/usr/bin/env bash
# Counterpart of install-desktop.sh: removes the two desktop entries and the
# hicolor icons it installed. The scope must match the one that installed them.
#
# The binaries and the Unix-named copies next to them are the build tree's, not
# this script's footprint, and are left alone.
#
# Usage:
#   ./scripts/uninstall-desktop.sh            # current user
#   ./scripts/uninstall-desktop.sh --system   # all users (needs root)

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/service-paths.sh
. "$script_dir/lib/service-paths.sh"
# shellcheck source=lib/desktop-paths.sh
. "$script_dir/lib/desktop-paths.sh"

scope="user"
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
    *)
      echo "unknown argument: $1 (expected --system|--user)" >&2
      exit 2
      ;;
  esac
done

data_root="$(nrr_desktop_data_root "$scope")"
applications_dir="$data_root/applications"
icons_root="$data_root/icons/hicolor"

nrr_cyan "==> remove desktop entries from $applications_dir"
nrr_desktop_run "$scope" rm -f \
  "$applications_dir/$NRR_DESKTOP_GUI_ID.desktop" \
  "$applications_dir/$NRR_DESKTOP_TRAY_ID.desktop"

nrr_cyan "==> remove icons from $icons_root"
for size in "${NRR_DESKTOP_ICON_SIZES[@]}"; do
  nrr_desktop_run "$scope" rm -f \
    "$icons_root/${size}x${size}/apps/$NRR_DESKTOP_ICON_NAME.png"
done
nrr_desktop_run "$scope" rm -f "$icons_root/scalable/apps/$NRR_DESKTOP_ICON_NAME.svg"

nrr_desktop_refresh_caches "$scope" "$data_root"

nrr_green "Desktop integration removed ($scope scope)."
