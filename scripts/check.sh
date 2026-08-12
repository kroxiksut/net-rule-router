#!/usr/bin/env bash
# Linux counterpart of check.ps1: same gates, same order.
#
# Difference from check.ps1: PowerShell's $ErrorActionPreference turns a
# native tool's stderr output into a terminating error, so check.ps1 has to
# demote it around every call. Bash only reacts to exit codes, so no
# equivalent wrapper is needed here.
#
# Usage:
#   ./scripts/check.sh
#   ./scripts/check.sh --require-cargo-deny

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"

require_cargo_deny=0
for arg in "$@"; do
  case "$arg" in
    --require-cargo-deny) require_cargo_deny=1 ;;
    *)
      echo "unknown argument: $arg (expected --require-cargo-deny)" >&2
      exit 2
      ;;
  esac
done

cyan() { printf '\033[36m%s\033[0m\n' "$1"; }
green() { printf '\033[32m%s\033[0m\n' "$1"; }
yellow() { printf '\033[33m%s\033[0m\n' "$1" >&2; }

# Source comments must not carry task tracking. The repository is public, and
# block/phase/ticket numbers and dates are meaningless to anyone reading it.
# Only comment text is scanned — the same words inside string literals, test
# data or schema version facts are legitimate.
check_comment_hygiene() {
  local roots=()
  local d
  for d in apps core shared scripts; do
    [ -d "$repo_root/$d" ] && roots+=("$repo_root/$d")
  done
  [ "${#roots[@]}" -eq 0 ] && return 0

  # The sub-block form is fenced on both sides so dotted-quad addresses in
  # comments (10.0.0.0/8, 172.16.0.0/12) are not read as block numbers.
  local markers exempt
  markers='Block\s+\d|блок\s+\d|(?<![\d.])1\d\.\d+\.[0-9A-Z](?!\.?\d)|NRR-\d+|TODO\(block|Phase\s+[A-Z]\b|20\d\d-[01]\d-[0-3]\d'
  # A date used as arithmetic in a worked example is documentation, not a
  # tracking stamp.
  exempt='UTC|epoch|RFC|ISO\s?8601|≈|\d_\d{3}_'

  local offences=() total=0
  local file rest line_no content prefix before after

  while IFS= read -r hit; do
    file="${hit%%:*}"
    rest="${hit#*:}"
    line_no="${rest%%:*}"
    content="${rest#*:}"

    case "$file" in
      *.sh|*.ps1) prefix='#' ;;
      *) prefix='//' ;;
    esac

    before="${content%%"$prefix"*}"
    [ "$before" = "$content" ] && continue
    after="${content#*"$prefix"}"

    grep -qP "$markers" <<<"$after" || continue
    grep -qP "$exempt" <<<"$content" && continue

    total=$((total + 1))
    if [ "$total" -le 20 ]; then
      offences+=("$file:$line_no: $content")
    fi
  done < <(grep -RnP \
    --include='*.rs' --include='*.qml' --include='*.cpp' --include='*.h' \
    --include='*.js' --include='*.ps1' --include='*.sh' \
    -e "$markers" "${roots[@]}" 2>/dev/null | grep -v '/target/')

  if [ "$total" -gt 0 ]; then
    local o
    for o in "${offences[@]}"; do
      yellow "  $o"
    done
    if [ "$total" -gt 20 ]; then
      yellow "  ... and $((total - 20)) more"
    fi
    echo "comment hygiene failed: $total comment(s) carry task references or dates." >&2
    return 1
  fi
  return 0
}

cyan "[check] NetRuleRouter workspace quality baseline"

cyan "[check] sync duplicates"
"$script_dir/clean-sync-duplicates.sh"

cyan "[check] comment hygiene: no task references or dates in comments"
check_comment_hygiene

# Invoked as `cargo-fmt`, not `cargo fmt`: a user-level cargo alias named
# `fmt` shadows the subcommand and makes cargo emit a warning on stderr,
# which this gate would otherwise mistake for a failure.
if ! command -v cargo-fmt >/dev/null 2>&1; then
  echo "cargo-fmt is not installed. Install it with \`rustup component add rustfmt\`." >&2
  exit 1
fi
cyan "[check] format: cargo-fmt --all -- --check"
cargo-fmt --all -- --check

cyan "[check] clippy: cargo clippy --workspace --all-targets -- -D warnings"
cargo clippy --workspace --all-targets -- -D warnings

cyan "[check] tests: cargo test --workspace"
cargo test --workspace

if ! command -v cargo-deny >/dev/null 2>&1; then
  message='cargo-deny is not installed. Install it with `cargo install --locked cargo-deny` to enable dependency/license checks.'
  if [ "$require_cargo_deny" -eq 1 ]; then
    echo "$message" >&2
    exit 1
  fi
  yellow "$message"
else
  local_cargo_home="$repo_root/.cargo-home"
  mkdir -p "$local_cargo_home"

  advisory_root="$local_cargo_home/advisory-dbs"
  if [ -d "$advisory_root" ]; then
    find "$advisory_root" -mindepth 1 -maxdepth 1 -type d -name 'advisory-db-*' -print0 |
      while IFS= read -r -d '' stale; do
        yellow "Refreshing advisory cache: $stale"
        rm -rf "$stale"
      done
  fi

  cyan "[check] cargo-deny: cargo-deny check advisories licenses bans sources"
  # CARGO_HOME is scoped to this subshell only, so the caller's environment
  # is untouched regardless of how cargo-deny exits.
  (
    export CARGO_HOME="$local_cargo_home"
    cargo-deny check advisories licenses bans sources
  )
fi

green "[check] quality baseline completed successfully"
