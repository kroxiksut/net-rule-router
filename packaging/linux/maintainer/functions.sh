# Service lifecycle steps shared by the .deb maintainer scripts, the .rpm
# scriptlets and the tarball's uninstall.sh. Sourced or pasted, never run.
#
# POSIX sh: dpkg runs maintainer scripts with /bin/sh. Expects the NRR_* values
# of scripts/lib/service-paths.sh above it; package-linux.sh writes them in, so
# a script that runs after the package files are gone still has them.

nrr_pkg_have_systemd() {
  [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1
}

# A value that came out empty or truncated must not reach `rm -rf`.
nrr_pkg_assert_removable() {
  case "$1" in
    /?*) ;;
    *)
      echo "$NRR_PRODUCT_NAME: refusing to remove '$1'" >&2
      return 1
      ;;
  esac
  case "$1" in
    /etc | /run | /usr | /var | /var/lib | /var/log)
      echo "$NRR_PRODUCT_NAME: refusing to remove '$1'" >&2
      return 1
      ;;
  esac
}

# A unit in /etc comes from an install without the package manager
# (install-service.sh, the tarball, `nrr-cli install`) and would shadow the
# package's. Its own daemon takes it down and gives the network back; the data
# stays for the package to pick up.
nrr_pkg_take_over_hand_install() {
  [ -e "$NRR_UNIT_FILE" ] || return 0
  echo "$NRR_PRODUCT_NAME: replacing the service installed without the package manager; its data is kept."
  daemon=$(sed -n 's/^ExecStart="\([^"]*\)".*/\1/p' "$NRR_UNIT_FILE" | head -n 1)
  if [ -n "$daemon" ] && [ -x "$daemon" ] && "$daemon" uninstall; then
    return 0
  fi
  if nrr_pkg_have_systemd; then
    systemctl disable --now "$NRR_UNIT_NAME" >/dev/null 2>&1 || true
  fi
  rm -f -- "$NRR_UNIT_FILE" "$NRR_LOGROTATE_CONFIG" "$NRR_POLKIT_POLICY"
  if nrr_pkg_have_systemd; then
    systemctl daemon-reload || true
  fi
}

# First install: start now and on every boot. A failed start is reported, not
# fatal: the files are in place and the journal says why.
nrr_pkg_enable_and_start() {
  if ! nrr_pkg_have_systemd; then
    echo "$NRR_PRODUCT_NAME: systemd is not running here; enable $NRR_UNIT_NAME once it is."
    return 0
  fi
  systemctl daemon-reload || true
  # An operator's start is not a crash loop; see systemd.rs reset_start_limit.
  systemctl reset-failed "$NRR_UNIT_NAME" >/dev/null 2>&1 || true
  if ! systemctl enable --now "$NRR_UNIT_NAME"; then
    echo "$NRR_PRODUCT_NAME: the service did not start; see journalctl -u $NRR_UNIT_NAME" >&2
  fi
}

# Upgrade: the running daemon moves to the new binary; a stopped or disabled
# one stays as the administrator left it.
nrr_pkg_restart_if_running() {
  nrr_pkg_have_systemd || return 0
  systemctl daemon-reload || true
  systemctl reset-failed "$NRR_UNIT_NAME" >/dev/null 2>&1 || true
  if ! systemctl try-restart "$NRR_UNIT_NAME"; then
    echo "$NRR_PRODUCT_NAME: the service did not restart; see journalctl -u $NRR_UNIT_NAME" >&2
  fi
}

# Removal: stop for good, then give the network back through reset-network.sh,
# which runs the daemon's own `cleanup` and undoes by hand what that cannot.
# Never fails the removal: a stuck package would leave the same state behind.
nrr_pkg_stop_and_reset_network() {
  if nrr_pkg_have_systemd; then
    systemctl disable --now "$NRR_UNIT_NAME" >/dev/null 2>&1 || true
  fi
  reset_script="$NRR_SERVICE_INSTALL_DIR/scripts/reset-network.sh"
  if [ -f "$reset_script" ] && command -v bash >/dev/null 2>&1; then
    if bash "$reset_script" --binary "$NRR_STAGED_SERVICE_BINARY"; then
      return 0
    fi
  elif [ -x "$NRR_STAGED_SERVICE_BINARY" ]; then
    if "$NRR_STAGED_SERVICE_BINARY" cleanup; then
      return 0
    fi
  fi
  echo "$NRR_PRODUCT_NAME: the network may not be fully restored; a reboot clears what is left." >&2
  return 0
}

# Erase the service data. The audit trail stays, as with purge-data.sh: it is
# a security record, and deleting it is a separate, deliberate step.
nrr_pkg_purge_data() {
  audit_name=$(basename "$NRR_AUDIT_DIR")
  if [ -d "$NRR_STATE_DIR" ] && nrr_pkg_assert_removable "$NRR_STATE_DIR"; then
    find "$NRR_STATE_DIR" -mindepth 1 -maxdepth 1 ! -name "$audit_name" -exec rm -rf -- {} +
    if ! rmdir "$NRR_STATE_DIR" 2>/dev/null; then
      echo "$NRR_PRODUCT_NAME: the audit trail is kept in $NRR_AUDIT_DIR; delete it by hand if it is not needed."
    fi
  fi
  for data_dir in "$NRR_LOG_DIR" "$NRR_RUNTIME_DIR"; do
    if [ -e "$data_dir" ] && nrr_pkg_assert_removable "$data_dir"; then
      rm -rf -- "$data_dir"
    fi
  done
}
