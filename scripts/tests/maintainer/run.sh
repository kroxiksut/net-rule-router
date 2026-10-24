#!/bin/sh
# The package scripts' service steps against a stand-in systemctl that logs its
# arguments. An upgrade that fixes a crash loop must start the unit that
# failed: its blocks may be holding the network, and `try-restart` leaves a
# failed unit alone. A unit the administrator stopped stays stopped.
set -u
here=$(cd "$(dirname "$0")" && pwd)
functions="$here/../../../packaging/linux/maintainer/functions.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cat > "$tmp/systemctl" <<'STUB'
#!/bin/sh
echo "$*" >> "$SYSTEMCTL_LOG"
case "$1" in
  is-failed) [ "${UNIT_FAILED:-0}" = 1 ] ;;
  is-enabled) [ "${UNIT_ENABLED:-1}" = 1 ] ;;
  *) exit 0 ;;
esac
STUB
chmod +x "$tmp/systemctl"
PATH="$tmp:$PATH"
export PATH
NRR_PRODUCT_NAME=netrulerouter
NRR_UNIT_NAME=netrulerouter.service
NRR_STATE_DIR="$tmp/state"
mkdir -p "$NRR_STATE_DIR"
. "$functions"
nrr_pkg_have_systemd() { return 0; }

failures=0
upgrade() {
  log="$tmp/$1.log"
  : > "$log"
  (
    SYSTEMCTL_LOG=$log UNIT_FAILED=$2 UNIT_ENABLED=$3
    export SYSTEMCTL_LOG UNIT_FAILED UNIT_ENABLED
    nrr_pkg_restart_if_running
  ) >/dev/null 2>&1
  if grep -q "^restart $NRR_UNIT_NAME\$" "$log"; then echo started; else echo left; fi
}
expect() {
  if [ "$2" != "$3" ]; then
    echo "maintainer scripts: $1: expected $3, got $2" >&2
    failures=$((failures + 1))
  fi
}
expect "a failed, enabled unit" "$(upgrade failed 1 1)" started
expect "a unit the administrator stopped" "$(upgrade stopped 0 1)" left
expect "a failed unit the administrator disabled" "$(upgrade disabled 1 0)" left
# The restart is an upgrade's: the daemon keeps protection for the new binary.
rm -f "$NRR_STATE_DIR/upgrade-stop"
upgrade marked 0 1 >/dev/null
if [ -f "$NRR_STATE_DIR/upgrade-stop" ]; then marked=yes; else marked=no; fi
expect "the upgrade's stop is marked" "$marked" yes

# Installed into an image being built (no running systemd), the unit is still
# enabled for the image's first boot.
log="$tmp/chroot.log"
: > "$log"
(
  SYSTEMCTL_LOG=$log
  export SYSTEMCTL_LOG
  nrr_pkg_have_systemd() { return 1; }
  nrr_pkg_enable_and_start
) >/dev/null 2>&1
if grep -q "^enable $NRR_UNIT_NAME\$" "$log"; then chroot=enabled; else chroot=left; fi
expect "a first install with no running systemd" "$chroot" enabled

# A purge removes the first-start provisioning, and a file rm cannot take is
# reported and left: under `set -e` its failure left the package half removed
# and failed every later purge the same way.
NRR_AUDIT_DIR="$NRR_STATE_DIR/audit"
NRR_LOG_DIR="$tmp/log"
NRR_RUNTIME_DIR="$tmp/run"
NRR_PROVISION_DIR="$tmp/etc/netrulerouter/provision"
mkdir -p "$NRR_PROVISION_DIR" "$NRR_LOG_DIR" "$NRR_STATE_DIR/stuck"
: > "$NRR_PROVISION_DIR/rules_primary.txt"
cat > "$tmp/rm" <<'STUB'
#!/bin/sh
for arg in "$@"; do
  case "$arg" in *stuck*) exit 1 ;; esac
done
exec /bin/rm "$@"
STUB
chmod +x "$tmp/rm"
nrr_pkg_undo_dns_by_hand() { return 0; }
# Not under `if`: the shell turns `set -e` off for a tested command.
(set -e; nrr_pkg_purge_data) >/dev/null 2>&1
if [ $? -eq 0 ]; then purged=ok; else purged=failed; fi
expect "a purge with a file rm cannot take" "$purged" ok
if [ -e "$NRR_PROVISION_DIR" ]; then provision=kept; else provision=removed; fi
expect "the provisioning on purge" "$provision" removed
[ "$failures" -eq 0 ]
