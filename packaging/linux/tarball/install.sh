#!/usr/bin/env bash
# Install this archive without a package manager. The files go where the .deb
# and .rpm put them; the service is registered by the daemon's own `install`
# verb, which then owns the unit, and scripts/uninstall.sh takes it down again.
#
# Refuses on a machine where a package already installed NetRuleRouter: one
# owner per install.
#
# Usage: sudo ./install.sh [--provision FILE] [--provision-secondary FILE]
#                           [--provision-settings FILE] [--secondary-unset direct|block]
#
# The --provision options hand the service prepared files for an unattended
# install: rules for the main and the additional route, a settings export, and
# where additional-route rules go while no additional connection is chosen.
# They are checked before anything is replaced and copied into
# /etc/netrulerouter/provision, which the service applies once at its next
# start. A refused file stops the install with the service binary's code
# (10 main rules, 11 additional rules, 12 settings, 13 option, 14 staging).

set -euo pipefail

original_args=("$@")
provision=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    --provision) provision+=(--primary "${2:?--provision needs a file}"); shift 2 ;;
    --provision-secondary) provision+=(--secondary "${2:?--provision-secondary needs a file}"); shift 2 ;;
    --provision-settings) provision+=(--settings "${2:?--provision-settings needs a file}"); shift 2 ;;
    --secondary-unset) provision+=(--secondary-unset "${2:?--secondary-unset needs direct or block}"); shift 2 ;;
    -h|--help) sed -n '2,20p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "install.sh: unknown option $1" >&2; exit 2 ;;
  esac
done

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tree="$here/root"
# shellcheck source=../../../scripts/lib/service-paths.sh
. "$here/lib/service-paths.sh"
# shellcheck source=../../../scripts/lib/desktop-paths.sh
. "$here/lib/desktop-paths.sh"
# shellcheck source=../maintainer/functions.sh
. "$here/lib/package-functions.sh"

# True when version $1 is older than $2 (dotted numbers).
version_older() {
  local IFS=. i
  local -a a b
  read -r -a a <<<"$1"
  read -r -a b <<<"$2"
  for i in 0 1 2; do
    [ "${a[i]:-0}" -lt "${b[i]:-0}" ] && return 0
    [ "${a[i]:-0}" -gt "${b[i]:-0}" ] && return 1
  done
  return 1
}

# On an older glibc the loader stops our programs before they can say why: the
# window started from the menu never appears. The floor was measured from the
# binaries as the archive was built; checked before sudo asks for a password.
refuse_older_glibc() {
  local floor system="" line number='[0-9]+(\.[0-9]+)+'
  floor="$(head -n 1 -- "$here/lib/glibc-floor" 2>/dev/null || true)"
  if ! [[ "$floor" =~ ^$number$ ]]; then
    echo "This archive is incomplete: $here/lib/glibc-floor is missing or damaged." >&2
    exit 1
  fi
  line="$(getconf GNU_LIBC_VERSION 2>/dev/null || true)"
  if [[ "$line" =~ ^glibc\ ($number) ]]; then
    system="${BASH_REMATCH[1]}"
  else
    line="$(ldd --version 2>&1 | head -n 1 || true)"
    if [[ "$line" =~ (GLIBC|GNU\ libc).*\ ($number)$ ]]; then
      system="${BASH_REMATCH[2]}"
    fi
  fi
  if [ -z "$system" ]; then
    echo "$NRR_PRODUCT_NAME needs glibc $floor or newer, and this system's C library is not glibc" >&2
    echo "(a musl-based system?) or could not be identified. Nothing was installed." >&2
    exit 1
  fi
  version_older "$system" "$floor" || return 0
  echo "This archive needs glibc $floor or newer; this system has glibc $system." >&2
  if [ -d "$tree/usr/share/applications" ]; then
    local name headless="$NRR_PRODUCT_NAME_UNIX-headless-<version>-linux-<arch>.tar.gz"
    name="$(basename -- "$here")"
    case "$name" in
      "$NRR_PRODUCT_NAME_UNIX"-[0-9]*) headless="$NRR_PRODUCT_NAME_UNIX-headless-${name#"$NRR_PRODUCT_NAME_UNIX"-}.tar.gz" ;;
    esac
    cat >&2 <<EOF
Its window would not start here, so nothing was installed. Instead, use either
  - the archive without the window, $headless,
    or the $NRR_PRODUCT_NAME_UNIX package alone: the service, nrr-cli and the
    nrr-tui terminal interface, which has the same features as the window;
  - or a system with glibc $floor or newer.
EOF
  else
    echo "Its programs would not start here, so nothing was installed. Use a system with glibc $floor or newer." >&2
  fi
  exit 1
}

refuse_older_glibc

if [ "$(id -u)" -ne 0 ]; then
  if ! command -v sudo >/dev/null 2>&1; then
    echo "install.sh needs root, and sudo was not found. Re-run as root." >&2
    exit 1
  fi
  exec sudo -- bash "${BASH_SOURCE[0]}" ${original_args[@]+"${original_args[@]}"}
fi

nrr_refuse_if_package_managed "upgrade or remove it with the package manager instead."

payload="$tree$NRR_SERVICE_INSTALL_DIR"
if [ ! -x "$payload/$NRR_SERVICE_EXE_NAME" ]; then
  echo "This archive is incomplete: $payload/$NRR_SERVICE_EXE_NAME is missing." >&2
  exit 1
fi
nrr_pkg_assert_removable "$NRR_SERVICE_INSTALL_DIR"

# Checked by this archive's own service binary before anything is replaced.
if [ "${#provision[@]}" -gt 0 ]; then
  nrr_cyan "==> check the prepared files"
  check=0
  "$payload/$NRR_SERVICE_EXE_NAME" provision-check "${provision[@]}" || check=$?
  if [ "$check" -ne 0 ]; then
    echo "install.sh: the prepared files were refused (code $check); nothing was installed." >&2
    exit "$check"
  fi
fi

# What the administrator left: an update keeps a unit they took out of start-up
# (or the start-on-demand mode, disabled but running) as it was, as the
# packages do.
was_installed=0
was_enabled=1
was_active=1
if nrr_pkg_have_systemd && [ -e "$NRR_UNIT_FILE" ]; then
  was_installed=1
  systemctl is-enabled --quiet "$NRR_UNIT_NAME" || was_enabled=0
  systemctl is-active --quiet "$NRR_UNIT_NAME" || was_active=0
fi

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

# Before the service starts, so its first start applies them.
if [ "${#provision[@]}" -gt 0 ]; then
  nrr_cyan "==> prepared files for the service"
  stage=0
  "$NRR_STAGED_SERVICE_BINARY" provision-stage "${provision[@]}" || stage=$?
  if [ "$stage" -ne 0 ]; then
    echo "install.sh: the prepared files could not be staged (code $stage)." >&2
    exit "$stage"
  fi
fi

nrr_cyan "==> register and start the service"
"$NRR_STAGED_SERVICE_BINARY" install
if [ "$was_installed" -eq 1 ] && [ "$was_enabled" -eq 0 ]; then
  nrr_cyan "==> $NRR_UNIT_NAME stays out of start-up, as it was"
  systemctl disable "$NRR_UNIT_NAME" >/dev/null 2>&1 || true
  if [ "$was_active" -eq 0 ]; then
    systemctl stop "$NRR_UNIT_NAME" >/dev/null 2>&1 || true
  fi
fi

nrr_green "Installed. Remove with: sudo $NRR_SERVICE_INSTALL_DIR/scripts/uninstall.sh [--purge]"
