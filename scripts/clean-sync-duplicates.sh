#!/usr/bin/env bash
# Linux counterpart of clean-sync-duplicates.ps1: same rule, same roots.
#
# A file-sync client resolves its own conflicts by leaving `name (2).ext` next
# to `name.ext`. Cargo auto-discovers `tests/*.rs`, so one such copy fails the
# build outright. A copy is deleted only when its bytes equal the original's:
# the sync client parks real edits in such copies, so one that differs (or
# cannot be read) stops the run for a person to merge.
#
# Usage:
#   ./scripts/clean-sync-duplicates.sh               clean the repository
#   ./scripts/clean-sync-duplicates.sh --self-test   prove both branches

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"

# Prints one line per copy left in place; returns 1 when there is any.
clean_root() {
  local base="$1" roots=() d
  for d in apps core shared scripts locales configs docs; do
    [ -d "$base/$d" ] && roots+=("$base/$d")
  done
  [ "${#roots[@]}" -eq 0 ] && return 0

  local removed=0 kept=0 copy name original rc newer
  while IFS= read -r -d '' copy; do
    name="$(basename "$copy")"
    original="$(dirname "$copy")/$(sed -E 's/^(.+) \([0-9]+\)(\.[^.]+)$/\1\2/' <<<"$name")"
    [ "$original" = "$(dirname "$copy")/$name" ] && continue
    [ -e "$original" ] || continue
    rc=0
    cmp -s -- "$copy" "$original" || rc=$?
    case "$rc" in
      0)
        rm -f -- "$copy"
        printf '  removed %s\n' "$copy"
        removed=$((removed + 1))
        ;;
      1)
        newer="original"
        [ "$copy" -nt "$original" ] && newer="copy"
        printf '\033[31m  differs: %s (newer: %s)\033[0m\n' "$copy" "$newer"
        kept=$((kept + 1))
        ;;
      *)
        printf '\033[31m  unreadable: %s (is the sync client running?)\033[0m\n' "$copy"
        kept=$((kept + 1))
        ;;
    esac
  done < <(find "${roots[@]}" -type f -name '* (*)*' -not -path '*/target/*' \
    -regextype posix-extended -regex '.*/.+ \([0-9]+\)\.[^./]+$' -print0)

  if [ "$removed" -gt 0 ]; then
    printf '\033[33m[clean] removed %d cloud-sync duplicate file(s)\033[0m\n' "$removed"
  fi
  if [ "$kept" -gt 0 ]; then
    echo "[clean] $kept cloud-sync copy(ies) differ from the original: merge each by hand, then delete the copy." >&2
    return 1
  fi
}

self_test() {
  local tmp rc=0
  tmp="$(mktemp -d)"
  trap 'rm -rf -- "$tmp"' RETURN
  mkdir -p "$tmp/core"
  printf 'same\n' >"$tmp/core/a.rs"
  printf 'same\n' >"$tmp/core/a (2).rs"
  clean_root "$tmp" >/dev/null 2>&1 || rc=$?
  if [ "$rc" -ne 0 ] || [ -e "$tmp/core/a (2).rs" ]; then
    echo "sync duplicates self-test failed: an identical copy was not removed." >&2
    return 1
  fi
  printf 'old\n' >"$tmp/core/b.rs"
  printf 'edit\n' >"$tmp/core/b (2).rs"
  rc=0
  clean_root "$tmp" >/dev/null 2>&1 || rc=$?
  if [ "$rc" -eq 0 ] || [ ! -e "$tmp/core/b (2).rs" ]; then
    echo "sync duplicates self-test failed: a differing copy was deleted or did not stop the run." >&2
    return 1
  fi
}

case "${1:-}" in
  --self-test) self_test ;;
  '') clean_root "$repo_root" ;;
  *) echo "unknown argument: $1 (expected --self-test)" >&2; exit 2 ;;
esac
