#!/usr/bin/env bash
# Linux counterpart of clean-sync-duplicates.ps1: same rule, same roots.
#
# A file-sync client resolves its own conflicts by leaving `name (2).ext` next
# to `name.ext`. Cargo auto-discovers `tests/*.rs`, so one such copy fails the
# build outright. Deleted only when the original sits in the same directory:
# that is what makes the file a copy rather than a deliberate name.
#
# Usage:
#   ./scripts/clean-sync-duplicates.sh

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"

roots=()
for d in apps core shared scripts locales configs docs; do
  [ -d "$repo_root/$d" ] && roots+=("$repo_root/$d")
done
[ "${#roots[@]}" -eq 0 ] && exit 0

removed=0
while IFS= read -r -d '' copy; do
  base="$(basename "$copy")"
  original="$(dirname "$copy")/$(sed -E 's/^(.+) \([0-9]+\)(\.[^.]+)$/\1\2/' <<<"$base")"
  [ "$original" = "$(dirname "$copy")/$base" ] && continue
  [ -e "$original" ] || continue
  rm -f -- "$copy"
  printf '  removed %s\n' "$copy"
  removed=$((removed + 1))
done < <(find "${roots[@]}" -type f -name '* (*)*' -not -path '*/target/*' \
  -regextype posix-extended -regex '.*/.+ \([0-9]+\)\.[^./]+$' -print0)

if [ "$removed" -gt 0 ]; then
  printf '\033[33m[clean] removed %d cloud-sync duplicate file(s)\033[0m\n' "$removed"
fi
