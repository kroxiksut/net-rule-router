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

# Give DNS back without the daemon: every mechanism, each acting only on a
# trace of its own, since the machine may have changed since the daemon ran.
# Mirrors platform/linux dns_redirect (OURS_MARKER, DnsFiles::system,
# REDIRECT_LINK, the NetworkManager drop-in, the resolvconf record) and the
# by-hand undo of reset-network.sh; a drifted value here would miss the
# daemon's redirect or touch somebody else's. Returns 1 when a step failed,
# with the copies that step restores from left in place.
nrr_pkg_undo_dns_by_hand() {
  marker="# NetRuleRouter answers DNS here; the system's own file returns when it stops."
  resolv_conf="/etc/resolv.conf"
  copy="$NRR_STATE_DIR/resolv.conf.system"
  link_note="$NRR_STATE_DIR/resolv.conf.system-link"
  taken="$NRR_STATE_DIR/dns-catch-all-taken"
  drop_in="/run/NetworkManager/conf.d/99-$NRR_PRODUCT_NAME_UNIX-dns.conf"
  record="lo.$NRR_PRODUCT_NAME_UNIX"
  failed=0

  # systemd-resolved: hand `~.` back to every link it was taken from, then
  # drop the dummy link, which makes resolved forget our server.
  if [ -f "$taken" ] && command -v resolvectl >/dev/null 2>&1; then
    given_back=1
    while IFS= read -r name || [ -n "$name" ]; do
      name=$(printf '%s' "$name" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
      [ -n "$name" ] || continue
      # One `Link N (name): values` line; a link that is gone reclaims `~.`
      # itself when it returns.
      shown=$(resolvectl domain "$name" 2>/dev/null) || continue
      values=$(printf '%s\n' "$shown" | sed -n 's/^[[:space:]]*Link [0-9][0-9]* ([^)]*):[[:space:]]*//p' | head -n 1)
      case " $values " in
        *" ~. "*) continue ;;
      esac
      # shellcheck disable=SC2086
      if ! resolvectl domain "$name" $values '~.'; then
        given_back=0
      fi
    done <"$taken"
    if [ "$given_back" -eq 1 ]; then
      rm -f -- "$taken"
    else
      failed=1
    fi
  fi
  if command -v ip >/dev/null 2>&1 && ip link show dev "$NRR_PRODUCT_NAME_UNIX" >/dev/null 2>&1; then
    ip link del "$NRR_PRODUCT_NAME_UNIX" || failed=1
  fi

  if [ -e "$drop_in" ]; then
    if rm -f -- "$drop_in"; then
      nmcli general reload >/dev/null 2>&1 || true
    else
      failed=1
    fi
  fi

  for dir in /run/resolvconf/interface /run/resolvconf/interfaces; do
    [ -e "$dir/$record" ] || continue
    # openresolv wants -f to stay quiet about a record that just went away;
    # Debian's resolvconf does not know it.
    resolvconf -f -d "$record" 2>/dev/null || resolvconf -d "$record" || failed=1
    break
  done

  # The system's resolv.conf back in place of ours; anyone else's file standing
  # there now is newer than our copy, so the copy goes either way.
  if [ -r "$copy" ]; then
    ours=0
    if [ -r "$resolv_conf" ]; then
      first=$(head -n 1 "$resolv_conf" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
      [ "$first" = "$marker" ] && ours=1
    fi
    restored=1
    if [ "$ours" -eq 1 ]; then
      if [ -r "$link_note" ]; then
        target=$(head -n 1 "$link_note" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        tmp="/etc/.resolv.conf.$NRR_PRODUCT_NAME_UNIX-link"
        rm -f -- "$tmp"
        if ! { ln -s -- "$target" "$tmp" && mv -f -- "$tmp" "$resolv_conf"; }; then
          rm -f -- "$tmp"
          restored=0
        fi
      else
        tmp="/etc/.resolv.conf.$NRR_PRODUCT_NAME_UNIX-new"
        if ! { cat -- "$copy" >"$tmp" && chmod 0644 -- "$tmp" && mv -f -- "$tmp" "$resolv_conf"; }; then
          rm -f -- "$tmp"
          restored=0
        fi
      fi
    fi
    if [ "$restored" -eq 1 ]; then
      rm -f -- "$copy" "$link_note"
    else
      failed=1
    fi
  fi

  if command -v resolvectl >/dev/null 2>&1; then
    resolvectl flush-caches >/dev/null 2>&1 || true
  fi
  return "$failed"
}

# Removal: stop for good, then give the network back through reset-network.sh,
# which runs the daemon's own `cleanup` and undoes by hand what that cannot.
# Without the script, or when it fails, the DNS redirect and the packet
# filters go by hand: nothing removed with the package could lift a redirect
# that outlives the reboot. Never fails the removal: a stuck package would
# leave the same state behind.
nrr_pkg_stop_and_reset_network() {
  if nrr_pkg_have_systemd; then
    systemctl disable --now "$NRR_UNIT_NAME" >/dev/null 2>&1 || true
    # A daemon stuck in its stop would refuse the cleanup and put back what
    # the undo by hand removes.
    if systemctl is-active --quiet "$NRR_UNIT_NAME"; then
      systemctl kill -s KILL "$NRR_UNIT_NAME" >/dev/null 2>&1 || true
    fi
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
  if command -v nft >/dev/null 2>&1; then
    nft delete table "$NRR_NFT_FAMILY" "$NRR_NFT_TABLE" >/dev/null 2>&1 || true
  fi
  if nrr_pkg_undo_dns_by_hand; then
    echo "$NRR_PRODUCT_NAME: DNS was given back; a reboot clears what else is left." >&2
  else
    echo "$NRR_PRODUCT_NAME: the network may not be fully restored; a reboot clears what is left." >&2
  fi
  return 0
}

# Second chance after the files are gone: an interrupted or failed pre-removal
# step must not leave the redirect for a reboot nobody can fix. Idempotent, acts
# only on traces of ours, and never while a daemon of ours is still answering.
nrr_pkg_finish_dns_undo() {
  if nrr_pkg_have_systemd && systemctl is-active --quiet "$NRR_UNIT_NAME"; then
    return 0
  fi
  if ! nrr_pkg_undo_dns_by_hand; then
    echo "$NRR_PRODUCT_NAME: DNS could not be given back; the saved system DNS settings stay in $NRR_STATE_DIR." >&2
  fi
  return 0
}

# Erase the service data. The audit trail stays, as with purge-data.sh: it is
# a security record, and deleting it is a separate, deliberate step. The saved
# system DNS settings are restored first and erased only once they have been:
# erased unused, a redirect left by an earlier removal could never be undone.
nrr_pkg_purge_data() {
  audit_name=$(basename "$NRR_AUDIT_DIR")
  keep_dns_copies=0
  if ! nrr_pkg_undo_dns_by_hand; then
    keep_dns_copies=1
    echo "$NRR_PRODUCT_NAME: DNS could not be given back; the saved system DNS settings stay in $NRR_STATE_DIR." >&2
  fi
  if [ -d "$NRR_STATE_DIR" ] && nrr_pkg_assert_removable "$NRR_STATE_DIR"; then
    if [ "$keep_dns_copies" -eq 1 ]; then
      find "$NRR_STATE_DIR" -mindepth 1 -maxdepth 1 ! -name "$audit_name" \
        ! -name resolv.conf.system ! -name resolv.conf.system-link ! -name dns-catch-all-taken \
        -exec rm -rf -- {} +
    else
      find "$NRR_STATE_DIR" -mindepth 1 -maxdepth 1 ! -name "$audit_name" -exec rm -rf -- {} +
    fi
    if ! rmdir "$NRR_STATE_DIR" 2>/dev/null && [ -d "$NRR_AUDIT_DIR" ]; then
      echo "$NRR_PRODUCT_NAME: the audit trail is kept in $NRR_AUDIT_DIR; delete it by hand if it is not needed."
    fi
  fi
  for data_dir in "$NRR_LOG_DIR" "$NRR_RUNTIME_DIR"; do
    if [ -e "$data_dir" ] && nrr_pkg_assert_removable "$data_dir"; then
      rm -rf -- "$data_dir"
    fi
  done
}
