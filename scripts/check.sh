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
#   ./scripts/check.sh --comment-hygiene-only

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"

require_cargo_deny=0
comment_hygiene_only=0
for arg in "$@"; do
  case "$arg" in
    --require-cargo-deny) require_cargo_deny=1 ;;
    --comment-hygiene-only) comment_hygiene_only=1 ;;
    *)
      echo "unknown argument: $arg (expected --require-cargo-deny or --comment-hygiene-only)" >&2
      exit 2
      ;;
  esac
done

cyan() { printf '\033[36m%s\033[0m\n' "$1"; }
green() { printf '\033[32m%s\033[0m\n' "$1"; }
yellow() { printf '\033[33m%s\033[0m\n' "$1" >&2; }

# Source must not carry task tracking: the repository is public, and block,
# phase and ticket numbers or dates mean nothing to its readers. What counts as
# a marker lives in lib/comment-hygiene.rules, shared with check.ps1; the
# scanner runs over what git would publish (tracked plus unignored files).
hygiene_rules="$script_dir/lib/comment-hygiene.rules"
hygiene_fixture="$script_dir/tests/comment-hygiene"

# Paths on stdin (NUL-separated, relative to $1); prints `path:line<TAB>text`.
scan_hygiene() {
  perl "$script_dir/lib/comment-hygiene.pl" "$hygiene_rules" "$1"
}

# The gate first proves it still sees what it is meant to see: a pattern edit
# that blinds it fails here instead of passing the whole tree silently.
check_comment_hygiene_self_test() {
  local got expected
  got="$(cd "$hygiene_fixture" && find . -type f ! -name expected.txt -printf '%P\0' |
    scan_hygiene "$hygiene_fixture" | cut -f1 | LC_ALL=C sort)"
  expected="$(tr -d '\r' <"$hygiene_fixture/expected.txt" | LC_ALL=C sort)"
  if [ "$got" != "$expected" ]; then
    diff <(printf '%s\n' "$expected") <(printf '%s\n' "$got") >&2 || true
    echo "comment hygiene self-test failed: the scanner no longer matches $hygiene_fixture/expected.txt." >&2
    return 1
  fi
}

check_comment_hygiene() {
  check_comment_hygiene_self_test
  local report total o
  report="$(git -C "$repo_root" ls-files -z --cached --others --exclude-standard |
    scan_hygiene "$repo_root")"
  [ -z "$report" ] && return 0
  total="$(printf '%s\n' "$report" | wc -l)"
  while IFS= read -r o; do
    yellow "  ${o/$'\t'/: }"
  done < <(printf '%s\n' "$report" | head -n 20)
  if [ "$total" -gt 20 ]; then
    yellow "  ... and $((total - 20)) more"
  fi
  echo "comment hygiene failed: $total line(s) or file name(s) carry task references or dates." >&2
  return 1
}

cyan "[check] NetRuleRouter workspace quality baseline"

cyan "[check] sync duplicates"
# Through `bash`, like CI invokes this script: the .sh files are recorded in
# git without an executable bit, so a direct call fails on a fresh checkout.
bash "$script_dir/clean-sync-duplicates.sh"

cyan "[check] comment hygiene and public-docs terms"
# A word repeated back to back in a comment. Eight of these shipped at once when
# a blind find-and-replace put a replacement word into sentences that already
# carried it, and the gate above had no reason to look: nothing about them is a
# task reference or a date. `(?!-)` spares the legitimate case where the repeat
# starts a hyphenated word.
check_doubled_words() {
  local roots=()
  local d
  for d in apps core shared scripts; do
    [ -d "$repo_root/$d" ] && roots+=("$repo_root/$d")
  done
  [ "${#roots[@]}" -eq 0 ] && return 0

  local offences=() total=0
  local hit file rest line_no content prefix after

  while IFS= read -r hit; do
    file="${hit%%:*}"
    rest="${hit#*:}"
    line_no="${rest%%:*}"
    content="${rest#*:}"

    case "$file" in
      *.sh|*.ps1) prefix='#' ;;
      *) prefix='//' ;;
    esac
    case "$content" in
      *"$prefix"*) after="${content#*"$prefix"}" ;;
      *) continue ;;
    esac

    grep -qP '\b([A-Za-z]{3,})\s+\1\b(?!-)' <<<"$after" || continue

    total=$((total + 1))
    if [ "$total" -le 20 ]; then
      offences+=("$file:$line_no: $content")
    fi
  done < <(grep -RnP \
    --include='*.rs' --include='*.qml' --include='*.cpp' --include='*.h' \
    --include='*.js' --include='*.ps1' --include='*.sh' \
    -e '\b([A-Za-z]{3,})\s+\1\b(?!-)' "${roots[@]}" 2>/dev/null | grep -v '/target/')

  if [ "$total" -gt 0 ]; then
    local o
    for o in "${offences[@]}"; do
      yellow "  $o"
    done
    if [ "$total" -gt 20 ]; then
      yellow "  ... and $((total - 20)) more"
    fi
    echo "doubled words: $total comment(s) repeat a word." >&2
    return 1
  fi
  return 0
}

# Public documentation names benefits, never internal mechanisms or private
# documents. The terms live in lib/public-docs-terms.rules, shared with
# check.ps1; code is not scanned, the slugs are legal there.
check_public_docs_terms() {
  local rules="$script_dir/lib/public-docs-terms.rules"
  local patterns=() line pat sample
  while IFS= read -r line; do
    line="${line%$'\r'}"
    case "$line" in '' | '#'*) continue ;; esac
    pat="${line%%$'\t'*}"
    sample="${line#*$'\t'}"
    if ! grep -qiP -e "$pat" <<<"$sample"; then
      echo "public docs gate self-test failed: '$pat' no longer matches its sample." >&2
      return 1
    fi
    patterns+=("$pat")
  done <"$rules"
  [ "${#patterns[@]}" -eq 0 ] && { echo "public docs gate: $rules holds no patterns." >&2; return 1; }

  local joined="" p
  for p in "${patterns[@]}"; do joined="${joined:+$joined|}$p"; done

  local scope='^((README|ROADMAP)[^/]*\.md|CONTRIBUTING\.md|SECURITY\.md|STRUCTURE\.md|(.*/)?AGENTS\.md|docs/.*\.md)$'
  local report
  report="$(git -C "$repo_root" ls-files -z --cached --others --exclude-standard |
    { grep -zE "$scope" || true; } |
    (cd "$repo_root" && xargs -0 -r grep -nIiP -e "$joined" || true))"
  [ -z "$report" ] && return 0
  local total o
  total="$(printf '%s\n' "$report" | wc -l)"
  while IFS= read -r o; do
    yellow "  $o"
  done < <(printf '%s\n' "$report" | head -n 20)
  if [ "$total" -gt 20 ]; then
    yellow "  ... and $((total - 20)) more"
  fi
  echo "public docs: $total line(s) name an internal mechanism or a private document." >&2
  return 1
}

check_comment_hygiene
check_doubled_words
check_public_docs_terms

if [ "$comment_hygiene_only" -eq 1 ]; then
  green "[check] comment hygiene only: passed"
  exit 0
fi

# Invoked as `cargo-fmt`, not `cargo fmt`: a user-level cargo alias named
# `fmt` shadows the subcommand and makes cargo emit a warning on stderr,
# which this gate would otherwise mistake for a failure.
if ! command -v cargo-fmt >/dev/null 2>&1; then
  echo "cargo-fmt is not installed. Install it with \`rustup component add rustfmt\`." >&2
  exit 1
fi
# The Qt host is built by `nrr-qt-host`'s build script through CMake. On a
# machine without Qt — a CI runner, or the WSL environment the Linux port is
# developed in — that script aborts and takes the whole gate with it, including
# the crates that have nothing to do with the GUI. Skipping it there is what
# makes this script runnable on Linux at all; the switch is the one the build
# script already honours. Announced, never silent: a gate that quietly covers
# less than it claims is worse than one that refuses to run.
if [ -z "${NRR_SKIP_QT_HOST:-}" ] && ! command -v cmake >/dev/null 2>&1; then
  yellow "[check] cmake not found — setting NRR_SKIP_QT_HOST=1; the Qt host is NOT built or checked by this run."
  export NRR_SKIP_QT_HOST=1
fi

cyan "[check] format: cargo-fmt --all -- --check"
cargo-fmt --all -- --check

cyan "[check] clippy: cargo clippy --workspace --all-targets -- -D warnings"
cargo clippy --workspace --all-targets -- -D warnings

cyan "[check] tests: cargo test --workspace"
# Tests get a temp directory of their own, removed however the run ends, so
# nothing a test fails to clean up stays in /tmp.
test_tmp="$(mktemp -d "${TMPDIR:-/tmp}/nrr-gate.XXXXXX")"
trap 'rm -rf "$test_tmp"' EXIT
TMPDIR="$test_tmp" cargo test --workspace

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
