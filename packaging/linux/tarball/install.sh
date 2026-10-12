#!/usr/bin/env bash
# Install this archive without a package manager. The files go where the .deb
# and .rpm put them; the service is registered by the daemon's own `install`
# verb, which then owns the unit, and scripts/uninstall.sh takes it down again.
#
# Refuses on a machine where a package already installed NetRuleRouter: one
# owner per install.
#
# Usage: sudo ./install.sh

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tree="$here/root"
# shellcheck source=../../../scripts/lib/service-paths.sh
. "$here/lib/service-paths.sh"
# shellcheck source=../../../scripts/lib/desktop-paths.sh
. "$here/lib/desktop-paths.sh"
# shellcheck source=../maintainer/functions.sh
. "$here/lib/package-functions.sh"

if [ "$(id -u)" -ne 0 ]; then
  if ! command -v sudo >/dev/null 2>&1; then
    echo "install.sh needs root, and sudo was not found. Re-run as root." >&2
    exit 1
  fi
  exec sudo -- bash "${BASH_SOURCE[0]}" "$@"
fi

nrr_refuse_if_package_managed "upgrade or remove it with the package manager instead."

payload="$tree$NRR_SERVICE_INSTALL_DIR"
if [ ! -x "$payload/$NRR_SERVICE_EXE_NAME" ]; then
  echo "This archive is incomplete: $payload/$NRR_SERVICE_EXE_NAME is missing." >&2
  exit 1
fi
nrr_pkg_assert_removable "$NRR_SERVICE_INSTALL_DIR"

# A running daemon would keep serving the files about to be replaced.
if nrr_pkg_have_systemd && systemctl is-active --quiet "$NRR_UNIT_NAME"; then
  nrr_cyan "==> stop $NRR_UNIT_NAME"
  systemctl stop "$NRR_UNIT_NAME"
fi

# No SELinux context is carried over from the extraction directory: a label
# from /home would keep systemd from running the daemon.
nrr_cyan "==> $NRR_SERVICE_INSTALL_DIR"
rm -rf -- "$NRR_SERVICE_INSTALL_DIR.new"
cp -R -P --preserve=mode,timestamps,links -- "$payload" "$NRR_SERVICE_INSTALL_DIR.new"
rm -rf -- "$NRR_SERVICE_INSTALL_DIR"
mv -f -- "$NRR_SERVICE_INSTALL_DIR.new" "$NRR_SERVICE_INSTALL_DIR"
if command -v restorecon >/dev/null 2>&1; then
  restorecon -R "$NRR_SERVICE_INSTALL_DIR" || true
fi

# A same-named program from elsewhere is somebody else's; never replace it.
nrr_cyan "==> commands in $NRR_COMMAND_LINK_DIR"
for link in "$tree$NRR_COMMAND_LINK_DIR"/*; do
  [ -L "$link" ] || continue
  name="$(basename -- "$link")"
  target="$(readlink -- "$link")"
  dest="$NRR_COMMAND_LINK_DIR/$name"
  if { [ -e "$dest" ] || [ -L "$dest" ]; } && [ "$(readlink -- "$dest" 2>/dev/null)" != "$target" ]; then
    nrr_yellow "    $dest is not ours - left alone; run $target"
    continue
  fi
  ln -sfn -- "$target" "$dest"
  nrr_gray "    $dest -> $target"
done

if [ -d "$tree/usr/share/applications" ]; then
  nrr_cyan "==> menu entries and icons"
  (cd "$tree/usr/share" && find applications icons -type f) | while IFS= read -r relative; do
    install -D -m 0644 -T "$tree/usr/share/$relative" "/usr/share/$relative"
  done
  nrr_desktop_refresh_caches system /usr/share
fi

nrr_cyan "==> register and start the service"
"$NRR_STAGED_SERVICE_BINARY" install

nrr_green "Installed. Remove with: sudo $NRR_SERVICE_INSTALL_DIR/scripts/uninstall.sh [--purge]"
