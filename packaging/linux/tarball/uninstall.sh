#!/usr/bin/env bash
# Remove what install.sh put on this machine: the service (through the
# daemon's own `uninstall` verb), the network state it left, the program files,
# the commands and the menu entries. Service data stays unless --purge; the
# audit trail stays even then, as with purge-data.sh.
#
# Ships both beside install.sh and in the installed scripts/ directory, so the
# archive is not needed to remove what it installed.
#
# Usage: sudo ./uninstall.sh [--purge]

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../../../scripts/lib/service-paths.sh
. "$script_dir/lib/service-paths.sh"
# shellcheck source=../../../scripts/lib/desktop-paths.sh
. "$script_dir/lib/desktop-paths.sh"
# shellcheck source=../maintainer/functions.sh
. "$script_dir/lib/package-functions.sh"

purge=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --purge) purge=1; shift ;;
    -h|--help)
      echo "Usage: uninstall.sh [--purge]"
      exit 0
      ;;
    *)
      echo "unknown argument: $1 (expected --purge)" >&2
      exit 2
      ;;
  esac
done

if [ "$(id -u)" -ne 0 ]; then
  if ! command -v sudo >/dev/null 2>&1; then
    echo "uninstall.sh needs root, and sudo was not found. Re-run as root." >&2
    exit 1
  fi
  args=()
  if [ "$purge" -eq 1 ]; then
    args+=(--purge)
  fi
  exec sudo -- bash "${BASH_SOURCE[0]}" ${args[@]+"${args[@]}"}
fi

nrr_refuse_if_package_managed "apt remove / dnf remove the package instead."
nrr_pkg_assert_removable "$NRR_SERVICE_INSTALL_DIR"

failures=0

# Unit, its companions and the alias link; the daemon also sweeps its nft
# table and gives DNS back.
if [ -x "$NRR_STAGED_SERVICE_BINARY" ]; then
  nrr_cyan "==> $NRR_STAGED_SERVICE_BINARY uninstall"
  if ! "$NRR_STAGED_SERVICE_BINARY" uninstall; then
    nrr_yellow "    the service did not uninstall cleanly; removing its unit by hand"
    if nrr_pkg_have_systemd; then
      systemctl disable --now "$NRR_UNIT_NAME" >/dev/null 2>&1 || true
    fi
    rm -f -- "$NRR_UNIT_FILE" "$NRR_AFTER_CRASH_UNIT_FILE" "$NRR_LOGROTATE_CONFIG" "$NRR_POLKIT_POLICY"
  fi
fi

# What `uninstall` does not cover (per-user routing rules, owned routes), and a
# second pass over what it does.
nrr_cyan "==> network state"
reset_script="$NRR_SERVICE_INSTALL_DIR/scripts/reset-network.sh"
if [ -f "$reset_script" ]; then
  bash "$reset_script" --binary "$NRR_STAGED_SERVICE_BINARY" || failures=$((failures + 1))
else
  nrr_yellow "    $reset_script is missing; giving DNS back by hand"
  nrr_pkg_undo_dns_by_hand || failures=$((failures + 1))
fi

nrr_cyan "==> commands in $NRR_COMMAND_LINK_DIR"
for link in "$NRR_COMMAND_LINK_DIR"/*; do
  [ -L "$link" ] || continue
  case "$(readlink -- "$link")" in
    "$NRR_SERVICE_INSTALL_DIR"/*) rm -f -- "$link" ;;
  esac
done

nrr_cyan "==> menu entries and icons"
rm -f -- "/usr/share/applications/$NRR_DESKTOP_GUI_ID.desktop" \
  "/usr/share/applications/$NRR_DESKTOP_TRAY_ID.desktop" \
  "/usr/share/icons/hicolor/scalable/apps/$NRR_DESKTOP_ICON_NAME.svg"
for size in "${NRR_DESKTOP_ICON_SIZES[@]}"; do
  rm -f -- "/usr/share/icons/hicolor/${size}x${size}/apps/$NRR_DESKTOP_ICON_NAME.png"
done
nrr_desktop_refresh_caches system /usr/share

nrr_cyan "==> $NRR_SERVICE_INSTALL_DIR"
rm -rf -- "$NRR_SERVICE_INSTALL_DIR"

if [ "$purge" -eq 1 ]; then
  nrr_cyan "==> service data"
  nrr_pkg_purge_data
fi

if nrr_pkg_have_systemd; then
  systemctl daemon-reload || true
  systemctl reset-failed "$NRR_UNIT_NAME" >/dev/null 2>&1 || true
fi

if [ "$failures" -gt 0 ]; then
  nrr_yellow "Removed, but the network was not fully restored; a reboot clears what is left."
  exit 1
fi
if [ "$purge" -eq 1 ]; then
  nrr_green "Removed, with the service data."
else
  nrr_green "Removed. Service data is kept in $NRR_STATE_DIR and $NRR_LOG_DIR (--purge erases it)."
fi
