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
  rm -f -- "$NRR_UNIT_FILE" "$NRR_AFTER_CRASH_UNIT_FILE" "$NRR_LOGROTATE_CONFIG" "$NRR_POLKIT_POLICY"
  if nrr_pkg_have_systemd; then
    systemctl daemon-reload || true
  fi
}

# First install: start now and on every boot. A failed start is reported, not
# fatal: the files are in place and the journal says why.
nrr_pkg_enable_and_start() {
  if ! nrr_pkg_have_systemd; then
    # A chroot (an image being built): `systemctl enable` makes the links
    # without a running systemd, so the image's first boot starts the service.
    if command -v systemctl >/dev/null 2>&1 && systemctl enable "$NRR_UNIT_NAME" >/dev/null 2>&1; then
      echo "$NRR_PRODUCT_NAME: systemd is not running here; $NRR_UNIT_NAME is enabled for the next boot."
    else
      echo "$NRR_PRODUCT_NAME: systemd is not running here; enable $NRR_UNIT_NAME once it is."
    fi
    return 0
  fi
  systemctl daemon-reload || true
  # An operator's start is not a crash loop; see systemd.rs reset_start_limit.
  systemctl reset-failed "$NRR_UNIT_NAME" >/dev/null 2>&1 || true
  if ! systemctl enable --now "$NRR_UNIT_NAME"; then
    echo "$NRR_PRODUCT_NAME: the service did not start; see journalctl -u $NRR_UNIT_NAME" >&2
  fi
}

# The daemon's stop below is an upgrade's: it leaves protection in place for the
# new binary (UPGRADE_STOP_MARKER in service-runtime lifecycle.rs). Created anew
# in the root-only state directory, never written through a link.
nrr_pkg_mark_upgrade_stop() {
  [ -d "$NRR_STATE_DIR" ] && [ ! -L "$NRR_STATE_DIR" ] || return 0
  rm -f -- "$NRR_STATE_DIR/upgrade-stop"
  (set -C; : > "$NRR_STATE_DIR/upgrade-stop") 2>/dev/null || true
}

# Upgrade: the running daemon moves to the new binary; a stopped or disabled
# one stays as the administrator left it. An enabled one that failed is
# started: the upgrade may be the fix for its crash loop, its blocks may be
# holding the network, and `try-restart` leaves a failed unit alone.
nrr_pkg_restart_if_running() {
  nrr_pkg_have_systemd || return 0
  nrr_pkg_mark_upgrade_stop
  systemctl daemon-reload || true
  failed=0
  systemctl is-failed --quiet "$NRR_UNIT_NAME" && failed=1
  systemctl reset-failed "$NRR_UNIT_NAME" >/dev/null 2>&1 || true
  if [ "$failed" = 1 ] && systemctl is-enabled --quiet "$NRR_UNIT_NAME"; then
    if ! systemctl restart "$NRR_UNIT_NAME"; then
      echo "$NRR_PRODUCT_NAME: the service did not start; see journalctl -u $NRR_UNIT_NAME" >&2
    fi
  elif ! systemctl try-restart "$NRR_UNIT_NAME"; then
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
      # Created under a temporary name, the file kept that name's SELinux
      # label, and dhclient or NetworkManager enabled later could not rewrite it.
      if command -v restorecon >/dev/null 2>&1; then
        restorecon -F -- "$resolv_conf" 2>/dev/null || true
      fi
    else
      failed=1
    fi
  fi

  if command -v resolvectl >/dev/null 2>&1; then
    resolvectl flush-caches >/dev/null 2>&1 || true
  fi
  return "$failed"
}

# Mirrors of platform/linux policy_routing: PRIORITY_BAND, and SYSTEM_TABLE,
# from which every table up is ours.
nrr_pkg_rule_priority_first=30100
nrr_pkg_rule_priority_last=30119
nrr_pkg_our_table_first=2147483647

# The per-user routing rules (a uid range in our band), then the tables they
# pointed at; without its rule a table is inert, so rules go first. Mirrors
# reset-network.sh. Returns 1 when something of ours could not be removed.
nrr_pkg_undo_routing_by_hand() {
  command -v ip >/dev/null 2>&1 || return 0
  routing_failed=0
  for family in -4 -6; do
    # With IPv6 disabled `ip -6` fails outright, and nothing of ours is there.
    rules=$(ip "$family" rule show 2>/dev/null) || continue
    rule_rows=$(printf '%s\n' "$rules" |
      awk -v first="$nrr_pkg_rule_priority_first" -v last="$nrr_pkg_rule_priority_last" '{
        prio = $1
        sub(/:$/, "", prio)
        if (prio !~ /^[0-9]+$/ || prio + 0 < first + 0 || prio + 0 > last + 0) next
        uids = ""
        lookup = ""
        for (i = 2; i < NF; i++) {
          if ($i == "uidrange" && uids == "") uids = $(i + 1)
          if ($i == "lookup" && lookup == "") lookup = $(i + 1)
        }
        if (uids != "" && lookup != "") print prio, uids, lookup
      }')
    # A here-document keeps the loop in this shell, so a failure is counted.
    while read -r prio uids lookup; do
      [ -n "$prio" ] || continue
      ip "$family" rule del priority "$prio" uidrange "$uids" lookup "$lookup" >/dev/null 2>&1 ||
        routing_failed=1
    done <<EOF
$rule_rows
EOF
    tables=$(ip "$family" route show table all 2>/dev/null |
      awk -v first="$nrr_pkg_our_table_first" '{
        for (i = 1; i < NF; i++)
          if ($i == "table" && $(i + 1) ~ /^[0-9]+$/ && $(i + 1) + 0 >= first + 0 && $(i + 1) + 0 < 4294967295)
            print $(i + 1)
      }' | sort -u)
    for table in $tables; do
      ip "$family" route flush table "$table" >/dev/null 2>&1 || routing_failed=1
    done
  done
  return "$routing_failed"
}

# Removal: stop for good, then give the network back through reset-network.sh,
# which runs the daemon's own `cleanup` and undoes by hand what that cannot.
# Without the script, or when it fails, the DNS redirect, the routing rules and
# the packet filters go by hand: nothing removed with the package could lift a
# redirect that outlives the reboot, and a rule left behind keeps sending its
# user's traffic along the removed program's routes. Never fails the removal:
# a stuck package would leave the same state behind.
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
  undone=1
  nrr_pkg_undo_routing_by_hand || undone=0
  nrr_pkg_undo_dns_by_hand || undone=0
  if [ "$undone" -eq 1 ]; then
    echo "$NRR_PRODUCT_NAME: DNS and the routing rules were given back; a reboot clears what else is left." >&2
  else
    echo "$NRR_PRODUCT_NAME: the network may not be fully restored; a reboot clears what is left." >&2
  fi
  return 0
}

# Second chance after the files are gone: an interrupted or failed pre-removal
# step must not leave the redirect or the routing rules for a reboot nobody can
# fix. Idempotent, acts
# only on traces of ours, and never while a daemon of ours is still answering.
nrr_pkg_finish_dns_undo() {
  if nrr_pkg_have_systemd && systemctl is-active --quiet "$NRR_UNIT_NAME"; then
    return 0
  fi
  if ! nrr_pkg_undo_routing_by_hand; then
    echo "$NRR_PRODUCT_NAME: some routing rules could not be removed; a reboot clears them." >&2
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
    # A file rm cannot take (immutable, a mount) is reported and left: under
    # `set -e` its failure left the package half removed, and every later
    # purge failed the same way.
    if [ "$keep_dns_copies" -eq 1 ]; then
      find "$NRR_STATE_DIR" -mindepth 1 -maxdepth 1 ! -name "$audit_name" \
        ! -name resolv.conf.system ! -name resolv.conf.system-link ! -name dns-catch-all-taken \
        -exec rm -rf -- {} + || echo "$NRR_PRODUCT_NAME: some files in $NRR_STATE_DIR could not be removed and are left in place." >&2
    else
      find "$NRR_STATE_DIR" -mindepth 1 -maxdepth 1 ! -name "$audit_name" -exec rm -rf -- {} + \
        || echo "$NRR_PRODUCT_NAME: some files in $NRR_STATE_DIR could not be removed and are left in place." >&2
    fi
    if ! rmdir "$NRR_STATE_DIR" 2>/dev/null && [ -d "$NRR_AUDIT_DIR" ]; then
      echo "$NRR_PRODUCT_NAME: the audit trail is kept in $NRR_AUDIT_DIR; delete it by hand if it is not needed."
    fi
  fi
  # Provisioning left behind would seed the next install's first start.
  for data_dir in "$NRR_LOG_DIR" "$NRR_RUNTIME_DIR" "$NRR_PROVISION_DIR"; do
    if [ -e "$data_dir" ] && nrr_pkg_assert_removable "$data_dir"; then
      rm -rf -- "$data_dir" || echo "$NRR_PRODUCT_NAME: $data_dir could not be removed and is left in place." >&2
    fi
  done
  rmdir "$(dirname "$NRR_PROVISION_DIR")" 2>/dev/null || true
}
