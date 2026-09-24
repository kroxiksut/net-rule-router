#!/usr/bin/env bash
# Remove every trace of the product from this machine: the systemd unit and the
# rest of the install footprint, the service data tree, the live nft table, and
# the files the desktop surfaces write into the caller's own profile. Linux
# counterpart of purge-data.ps1.
#
# Dry-run by default: it prints what it would remove and touches nothing. Only
# --yes deletes, and only the paths declared in lib/service-paths.sh — no
# pattern is ever expanded against the home directory.
#
# The desktop entries and icons go through uninstall-desktop.sh, which owns
# those paths.
#
# The audit trail is not part of a user cleanup, so /var/lib/netrulerouter/audit
# survives unless --purge-audit says otherwise.
#
# Usage:
#   ./scripts/purge-data.sh                     # show what would go
#   ./scripts/purge-data.sh --yes
#   ./scripts/purge-data.sh --yes --purge-audit

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/service-paths.sh
. "$script_dir/lib/service-paths.sh"

usage() {
  cat <<'EOF'
Usage: purge-data.sh [--yes] [--purge-audit] [--profile auto|dev|release]

  --yes           actually delete; without it nothing is touched
  --purge-audit   also delete the audit trail (kept by default)
  --profile       passed to uninstall-service.sh (default: auto)
EOF
}

apply=0
purge_audit=0
profile="auto"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --yes) apply=1; shift ;;
    --purge-audit) purge_audit=1; shift ;;
    --profile) profile="${2:-}"; shift 2 ;;
    --profile=*) profile="${1#--profile=}"; shift ;;
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

# The per-user half comes from the caller's own XDG variables; the privileged
# steps elevate one at a time on their own.
nrr_refuse_sudo "Privileged steps elevate themselves."

removed_list=""
absent_list=""
failed_list=""

mark_removed() { removed_list="$removed_list  $1"$'\n'; }
mark_absent() { absent_list="$absent_list  $1"$'\n'; }
mark_failed() { failed_list="$failed_list  $1"$'\n'; }

# A constant that came out empty or truncated must not turn into `rm -rf /`.
assert_purgeable() {
  case "$1" in
    /*) ;;
    *)
      echo "refusing to remove a non-absolute path: '$1'" >&2
      exit 1
      ;;
  esac
  case "$1" in
    /|/etc|/run|/tmp|/usr|/usr/lib|/usr/share|/var|/var/lib|/var/log|"${HOME:-/nonexistent}")
      echo "refusing to remove '$1'" >&2
      exit 1
      ;;
  esac
}

# $2 selects the privileged form, used for everything outside the profile.
purge_path() {
  local path="$1" scope="${2:-user}"
  assert_purgeable "$path"
  if [ ! -e "$path" ] && [ ! -L "$path" ]; then
    nrr_gray "  absent       $path"
    mark_absent "$path"
    return
  fi
  if [ "$apply" -eq 0 ]; then
    nrr_yellow "  would remove $path"
    return
  fi
  local ok=0
  if [ "$scope" = "system" ]; then
    if nrr_run_privileged rm -rf -- "$path"; then ok=1; fi
  else
    if rm -rf -- "$path"; then ok=1; fi
  fi
  if [ "$ok" -eq 1 ]; then
    nrr_green "  removed      $path"
    mark_removed "$path"
  else
    nrr_yellow "  FAILED       $path"
    mark_failed "$path"
  fi
}

# The state tree minus the audit directory, which a user cleanup never takes.
purge_state_dir() {
  assert_purgeable "$NRR_STATE_DIR"
  if [ "$purge_audit" -eq 1 ]; then
    purge_path "$NRR_STATE_DIR" system
    return
  fi
  if [ ! -e "$NRR_STATE_DIR" ]; then
    nrr_gray "  absent       $NRR_STATE_DIR"
    mark_absent "$NRR_STATE_DIR"
    return
  fi
  if [ "$apply" -eq 0 ]; then
    nrr_yellow "  would remove $NRR_STATE_DIR/* (keeping $NRR_AUDIT_DIR)"
    return
  fi
  if nrr_run_privileged find "$NRR_STATE_DIR" -mindepth 1 -maxdepth 1 \
    ! -name audit -exec rm -rf -- {} +; then
    nrr_green "  removed      $NRR_STATE_DIR/* (kept $NRR_AUDIT_DIR)"
    mark_removed "$NRR_STATE_DIR/* (audit kept)"
  else
    nrr_yellow "  FAILED       $NRR_STATE_DIR"
    mark_failed "$NRR_STATE_DIR"
  fi
}

# Whatever the daemon left loaded. Listing the table needs root, so the dry run
# states the intent instead of probing.
purge_nft_table() {
  local label="nft table $NRR_NFT_FAMILY $NRR_NFT_TABLE"
  if [ "$apply" -eq 0 ]; then
    nrr_yellow "  would remove $label (if loaded)"
    return
  fi
  if ! command -v nft >/dev/null 2>&1; then
    nrr_gray "  absent       $label (nft is not installed)"
    mark_absent "$label"
    return
  fi
  if ! nrr_run_privileged nft list table "$NRR_NFT_FAMILY" "$NRR_NFT_TABLE" >/dev/null 2>&1; then
    nrr_gray "  absent       $label"
    mark_absent "$label"
    return
  fi
  if nrr_run_privileged nft delete table "$NRR_NFT_FAMILY" "$NRR_NFT_TABLE"; then
    nrr_green "  removed      $label"
    mark_removed "$label"
  else
    nrr_yellow "  FAILED       $label"
    mark_failed "$label"
  fi
}

# Take the unit down before the data goes, so a running daemon cannot rewrite
# what was just deleted.
run_uninstall() {
  if [ "$apply" -eq 0 ]; then
    nrr_yellow "  would run    $script_dir/uninstall-service.sh --profile $profile"
    return
  fi
  if "$script_dir/uninstall-service.sh" --profile "$profile"; then
    return
  fi
  # No daemon binary to run `uninstall` from; the unit still has to stop, and
  # its file is removed below either way.
  nrr_yellow "uninstall-service.sh failed — disabling $NRR_UNIT_NAME directly"
  nrr_run_privileged systemctl disable --now "$NRR_UNIT_NAME" || true
}

# The desktop entries and hicolor icons are the desktop script's footprint, in
# this same profile; it owns their paths, so purge delegates rather than
# restating them.
run_uninstall_desktop() {
  if [ "$apply" -eq 0 ]; then
    nrr_yellow "  would run    $script_dir/uninstall-desktop.sh"
    return
  fi
  "$script_dir/uninstall-desktop.sh" >/dev/null || nrr_yellow "uninstall-desktop.sh failed"
}

if [ "$apply" -eq 0 ]; then
  nrr_cyan "==> dry run: nothing will be deleted (pass --yes to act)"
fi
if [ "$purge_audit" -eq 0 ]; then
  nrr_gray "    audit trail at $NRR_AUDIT_DIR is kept (--purge-audit removes it)"
fi

nrr_cyan "==> service"
run_uninstall

nrr_cyan "==> machine-wide footprint"
purge_path "$NRR_UNIT_FILE" system
purge_path "$NRR_LOGROTATE_CONFIG" system
purge_path "$NRR_POLKIT_POLICY" system
purge_path "$NRR_SERVICE_INSTALL_DIR" system
purge_state_dir
purge_path "$NRR_LOG_DIR" system
purge_path "$NRR_RUNTIME_DIR" system
purge_nft_table

nrr_cyan "==> profile of $(id -un)"
run_uninstall_desktop
user_paths="$(nrr_user_footprint_paths)"
while IFS= read -r user_path; do
  [ -n "$user_path" ] || continue
  purge_path "$user_path" user
done <<<"$user_paths"

if [ "$apply" -eq 1 ]; then
  nrr_run_privileged systemctl daemon-reload || true
  nrr_run_privileged systemctl reset-failed "$NRR_UNIT_NAME" >/dev/null 2>&1 || true
fi

echo
if [ "$apply" -eq 0 ]; then
  nrr_cyan "Dry run complete — nothing was deleted. Re-run with --yes to act."
  exit 0
fi

nrr_cyan "==> summary"
if [ -n "$removed_list" ]; then
  nrr_green "removed:"
  printf '%s' "$removed_list"
else
  nrr_gray "removed: nothing"
fi
if [ -n "$absent_list" ]; then
  nrr_gray "not present:"
  printf '%s' "$absent_list"
fi
if [ -n "$failed_list" ]; then
  nrr_yellow "could not remove:"
  printf '%s' "$failed_list"
  exit 1
fi

nrr_green "Purge complete."
