#!/usr/bin/env bash
# Disaster recovery for a machine the daemon left without network. After a
# SIGKILL, an OOM kill or a crash the unit's stop hook could not follow, the
# nftables table keeps dropping traffic and the DNS redirect may still point
# at a listener that is gone. Linux counterpart of reset-network.ps1.
#
#   1. stop the unit, best-effort: a live daemon would put everything back;
#   2. run the daemon's own `cleanup` verb (DNS redirect, nftables table,
#      per-user routing rules, owned routes), from the staged install or the
#      build tree;
#   3. a binary older than that verb: its `restore-dns` (the unit's stop hook)
#      for the DNS redirect, then the table by hand;
#   4. with no binary, or when it fails, the same undo by hand, step for step.
#      By hand the per-user rules and tables go, but not the daemon's routes in
#      the main table; a reboot drops them.
#
# Idempotent: with nothing left behind every step is a no-op and it exits 0.
# Elevates itself through sudo.
#
# Usage:
#   ./scripts/reset-network.sh
#   ./scripts/reset-network.sh --profile release
#   ./scripts/reset-network.sh --binary /path/to/nrr-serviced

set -euo pipefail

script_path="${BASH_SOURCE[0]}"
script_dir="$(cd "$(dirname "$script_path")" && pwd)"
# shellcheck source=lib/service-paths.sh
. "$script_dir/lib/service-paths.sh"

usage() {
  cat <<'EOF'
Usage: reset-network.sh [--profile auto|dev|release] [--binary PATH]

  --profile   which build-tree daemon to use when none is staged (default: auto)
  --binary    the daemon binary to run `cleanup` from
EOF
}

profile="auto"
exe_path=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --profile) profile="${2:-}"; shift 2 ;;
    --profile=*) profile="${1#--profile=}"; shift ;;
    --binary) exe_path="${2:-}"; shift 2 ;;
    --binary=*) exe_path="${1#--binary=}"; shift ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
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

# Resolved before elevating: the caller's environment is what knows where
# cargo puts the build tree, and sudo drops it.
if [ -z "$exe_path" ]; then
  if [ -x "$NRR_STAGED_SERVICE_BINARY" ]; then
    exe_path="$NRR_STAGED_SERVICE_BINARY"
  else
    built="$(nrr_built_service_binary "$(nrr_target_root "$NRR_REPO_ROOT")" "$profile")"
    if [ -x "$built" ]; then
      exe_path="$built"
    fi
  fi
fi

if [ "$(id -u)" -ne 0 ]; then
  if ! command -v sudo >/dev/null 2>&1; then
    echo "reset-network.sh needs root, and sudo was not found. Re-run as root." >&2
    exit 1
  fi
  nrr_cyan "Elevating via sudo..."
  args=(--profile "$profile")
  if [ -n "$exe_path" ]; then
    args+=(--binary "$exe_path")
  fi
  exec sudo -- bash "$script_path" "${args[@]}"
fi

# Mirrors of platform/linux dns_redirect (REDIRECT_LINK, DnsFiles::system,
# the NetworkManager drop-in, the resolvconf record and OURS_MARKER). A drifted
# value here would miss the daemon's redirect or touch somebody else's.
dns_link="$NRR_PRODUCT_NAME_UNIX"
dns_taken_file="$NRR_STATE_DIR/dns-catch-all-taken"
nm_drop_in="/run/NetworkManager/conf.d/99-$NRR_PRODUCT_NAME_UNIX-dns.conf"
resolvconf_record="lo.$NRR_PRODUCT_NAME_UNIX"
resolvconf_record_dirs=(/run/resolvconf/interface /run/resolvconf/interfaces)
resolv_conf="/etc/resolv.conf"
resolv_system_copy="$NRR_STATE_DIR/resolv.conf.system"
resolv_system_link="$NRR_STATE_DIR/resolv.conf.system-link"
ours_marker="# NetRuleRouter answers DNS here; the system's own file returns when it stops."

# Mirrors of platform/linux policy_routing: PRIORITY_BAND, and SYSTEM_TABLE,
# from which every table up is ours.
rule_priority_first=30100
rule_priority_last=30119
our_table_first=2147483647

failures=0
fail() {
  nrr_yellow "    FAILED: $1"
  failures=$((failures + 1))
}

trim() {
  local s="$1"
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  printf '%s' "$s"
}

# The values of one `Link N (name): values` line of `resolvectl domain`,
# prefixed with `=` so a link with no domains still reads as present.
resolved_link_values() {
  awk -v want="$2" '
    {
      line = $0; sub(/^[[:space:]]+/, "", line)
      if (substr(line, 1, 5) != "Link ") next
      rest = substr(line, 6)
      sp = index(rest, " "); if (!sp) next
      if (substr(rest, 1, sp - 1) !~ /^[0-9]+$/) next
      rest = substr(rest, sp + 1); sub(/^[[:space:]]+/, "", rest)
      if (substr(rest, 1, 1) != "(") next
      rest = substr(rest, 2)
      cp = index(rest, ")"); if (!cp) next
      name = substr(rest, 1, cp - 1); gsub(/^[[:space:]]+|[[:space:]]+$/, "", name)
      rest = substr(rest, cp + 1); sub(/^[[:space:]]+/, "", rest)
      if (substr(rest, 1, 1) != ":") next
      if (name == want) { print "=" substr(rest, 2); exit }
    }' <<<"$1"
}

# systemd-resolved: hand `~.` back to every link it was taken from, then drop
# the dummy link, which makes resolved forget our server.
undo_resolved() {
  local taken=() line
  if [ -f "$dns_taken_file" ]; then
    while IFS= read -r line || [ -n "$line" ]; do
      line="$(trim "$line")"
      if [ -n "$line" ]; then
        taken+=("$line")
      fi
    done <"$dns_taken_file"
  fi
  if [ "${#taken[@]}" -gt 0 ]; then
    local domains="" given_back=1 name found value claims values=()
    if ! domains="$(resolvectl domain 2>/dev/null)"; then
      fail "resolvectl domain (the catch-all stays recorded in $dns_taken_file)"
      given_back=0
    fi
    if [ "$given_back" -eq 1 ]; then
      for name in "${taken[@]}"; do
        found="$(resolved_link_values "$domains" "$name")"
        # The connection is gone; it reclaims `~.` when it returns.
        [ -n "$found" ] || continue
        read -r -a values <<<"${found#=}"
        claims=0
        for value in ${values[@]+"${values[@]}"}; do
          if [ "$value" = "~." ]; then
            claims=1
          fi
        done
        if [ "$claims" -eq 1 ]; then
          continue
        fi
        if resolvectl domain "$name" ${values[@]+"${values[@]}"} '~.'; then
          echo "    gave ~. back to $name"
        else
          fail "resolvectl domain $name ... ~."
          given_back=0
          break
        fi
      done
    fi
    if [ "$given_back" -eq 1 ]; then
      rm -f -- "$dns_taken_file"
    fi
  fi
  if ip link show dev "$dns_link" >/dev/null 2>&1; then
    if ip link del "$dns_link"; then
      echo "    removed the DNS link $dns_link"
    else
      fail "ip link del $dns_link"
    fi
  fi
}

undo_network_manager() {
  [ -e "$nm_drop_in" ] || return 0
  if ! rm -f -- "$nm_drop_in"; then
    fail "rm $nm_drop_in"
    return
  fi
  echo "    removed $nm_drop_in"
  nmcli general reload || fail "nmcli general reload"
}

undo_resolvconf() {
  local dir present=0
  for dir in "${resolvconf_record_dirs[@]}"; do
    if [ -e "$dir/$resolvconf_record" ]; then
      present=1
    fi
  done
  [ "$present" -eq 1 ] || return 0
  # openresolv wants -f to stay quiet about a record that just went away;
  # Debian's resolvconf does not know it.
  if resolvconf -f -d "$resolvconf_record" 2>/dev/null || resolvconf -d "$resolvconf_record"; then
    echo "    removed the resolvconf record $resolvconf_record"
  else
    fail "resolvconf -d $resolvconf_record"
  fi
}

# Put the system's resolv.conf back if ours still stands in its place.
undo_resolv_conf_file() {
  [ -r "$resolv_system_copy" ] || return 0
  local ours=1 first="" dir tmp target
  if [ -r "$resolv_conf" ]; then
    IFS= read -r first <"$resolv_conf" || true
    [ "$(trim "$first")" = "$ours_marker" ] || ours=0
  fi
  if [ "$ours" -eq 1 ]; then
    dir="$(dirname "$resolv_conf")"
    if [ -r "$resolv_system_link" ]; then
      target="$(trim "$(cat "$resolv_system_link")")"
      tmp="$dir/.$(basename "$resolv_conf").netrulerouter-link"
      rm -f -- "$tmp"
      if ! { ln -s -- "$target" "$tmp" && mv -fT -- "$tmp" "$resolv_conf"; }; then
        fail "relink $resolv_conf -> $target"
        return
      fi
      echo "    restored $resolv_conf -> $target"
    else
      tmp="$dir/.$(basename "$resolv_conf").netrulerouter-new"
      if ! { cat -- "$resolv_system_copy" >"$tmp" && sync -- "$tmp" && chmod 0644 -- "$tmp" &&
        mv -fT -- "$tmp" "$resolv_conf"; }; then
        rm -f -- "$tmp"
        fail "restore $resolv_conf from $resolv_system_copy"
        return
      fi
      echo "    restored $resolv_conf from $resolv_system_copy"
    fi
  fi
  # Anyone else's file standing there now is newer than our copy.
  rm -f -- "$resolv_system_copy" "$resolv_system_link"
}

# Every mechanism, not the one this machine uses now: each acts only on a
# trace of its own, and the machine may have changed since the daemon ran.
undo_dns_by_hand() {
  undo_resolved
  undo_network_manager
  undo_resolvconf
  undo_resolv_conf_file
}

# One `ip rule` field: the word after `$2` on the line `$1`.
rule_field() {
  awk -v key="$2" '{for (i = 1; i < NF; i++) if ($i == key) { print $(i + 1); exit }}' <<<"$1"
}

# The per-user routing rules (ours: a uid range in our band), then the tables
# they pointed at. Without its rule a table is inert, so rules go first.
undo_routing_by_hand() {
  if ! command -v ip >/dev/null 2>&1; then
    nrr_gray "    ip is not installed; no rules to remove"
    return 0
  fi
  local family rules line prio uids lookup table
  for family in -4 -6; do
    # With IPv6 disabled `ip -6` fails outright, and nothing of ours is there.
    rules="$(ip "$family" rule show 2>/dev/null)" || continue
    while IFS= read -r line; do
      prio="${line%%:*}"
      case "$prio" in '' | *[!0-9]*) continue ;; esac
      if [ "$prio" -lt "$rule_priority_first" ] || [ "$prio" -gt "$rule_priority_last" ]; then
        continue
      fi
      uids="$(rule_field "$line" uidrange)"
      lookup="$(rule_field "$line" lookup)"
      [ -n "$uids" ] && [ -n "$lookup" ] || continue
      if ip "$family" rule del priority "$prio" uidrange "$uids" lookup "$lookup"; then
        echo "    removed rule $prio (ip $family, uids $uids)"
      else
        fail "ip $family rule del priority $prio uidrange $uids lookup $lookup"
      fi
    done <<<"$rules"
    while IFS= read -r table; do
      [ -n "$table" ] || continue
      if ip "$family" route flush table "$table"; then
        echo "    flushed table $table (ip $family)"
      else
        fail "ip $family route flush table $table"
      fi
    done < <(ip "$family" route show table all 2>/dev/null |
      awk -v first="$our_table_first" '{
        for (i = 1; i < NF; i++)
          if ($i == "table" && $(i + 1) ~ /^[0-9]+$/ && $(i + 1) + 0 >= first + 0 && $(i + 1) + 0 < 4294967295)
            print $(i + 1)
      }' | sort -u)
  done
}

nrr_cyan "==> stop $NRR_UNIT_NAME (best-effort)"
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  if systemctl stop "$NRR_UNIT_NAME" 2>/dev/null; then
    echo "    stopped"
  else
    nrr_gray "    not loaded; nothing to stop"
  fi
fi

# The daemon's own undo first: it is the one that knows every piece.
# 2 = a binary without the verb, 4 = the service is (still) running.
cleaned=0
dns_step="by-hand"
if [ -n "$exe_path" ]; then
  nrr_cyan "==> $exe_path cleanup"
  if "$exe_path" cleanup; then
    cleaned=1
  else
    code=$?
    case "$code" in
      2)
        dns_step="restore-dns"
        nrr_gray "    this binary predates \`cleanup\`; falling back to \`restore-dns\`"
        ;;
      4)
        nrr_yellow "The service is still running and would put back whatever is removed."
        nrr_yellow "Stop it (systemctl stop $NRR_UNIT_NAME) and run this again."
        exit 1
        ;;
      *)
        nrr_yellow "    cleanup failed (exit $code); undoing it by hand"
        ;;
    esac
  fi
else
  nrr_yellow "    no daemon binary (neither $NRR_STAGED_SERVICE_BINARY nor a build); undoing it by hand"
fi

if [ "$cleaned" -eq 0 ]; then
  nrr_cyan "==> DNS redirect"
  if [ "$dns_step" = "restore-dns" ]; then
    echo "    $exe_path restore-dns"
    if "$exe_path" restore-dns; then
      dns_step="done"
      echo "    done"
    else
      nrr_yellow "    restore-dns failed (exit $?); undoing it by hand"
    fi
  fi
  if [ "$dns_step" != "done" ]; then
    undo_dns_by_hand
  fi

  nft_label="nft table $NRR_NFT_FAMILY $NRR_NFT_TABLE"
  nrr_cyan "==> $nft_label"
  if ! command -v nft >/dev/null 2>&1; then
    nrr_gray "    nft is not installed; no table to remove"
  elif ! nft list table "$NRR_NFT_FAMILY" "$NRR_NFT_TABLE" >/dev/null 2>&1; then
    nrr_gray "    not loaded"
  elif nft delete table "$NRR_NFT_FAMILY" "$NRR_NFT_TABLE"; then
    echo "    removed"
  else
    fail "nft delete table $NRR_NFT_FAMILY $NRR_NFT_TABLE"
  fi

  nrr_cyan "==> per-user routing rules"
  undo_routing_by_hand
fi

echo
if [ "$failures" -gt 0 ]; then
  nrr_yellow "Network reset finished with $failures failure(s)."
  nrr_yellow "A reboot drops the table and every redirect except a rewritten $resolv_conf;"
  nrr_yellow "the system's own copy of that file is $resolv_system_copy."
  exit 1
fi
nrr_green "Network reset complete."
