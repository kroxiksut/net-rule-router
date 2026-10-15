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
#   ./scripts/check.sh --qmllint-only
#   ./scripts/check.sh --require-qmllint    (CI: a runner without qmllint fails)
#   ./scripts/check.sh --fuzz [seconds]     (opt-in: every fuzz target, 60 s each by default)

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"

require_cargo_deny=0
comment_hygiene_only=0
require_qmllint=0
qmllint_only=0
fuzz_seconds=0
while [ "$#" -gt 0 ]; do
  arg="$1"
  shift
  case "$arg" in
    --require-cargo-deny) require_cargo_deny=1 ;;
    --comment-hygiene-only) comment_hygiene_only=1 ;;
    --require-qmllint) require_qmllint=1 ;;
    --qmllint-only) qmllint_only=1 ;;
    --fuzz)
      # The optional duration is the next argument when it is a whole number.
      fuzz_seconds=60
      if [ "$#" -gt 0 ] && [[ "$1" =~ ^[0-9]+$ ]]; then
        fuzz_seconds="$1"
        shift
      fi
      ;;
    *)
      echo "unknown argument: $arg (expected --require-cargo-deny, --comment-hygiene-only, --require-qmllint, --qmllint-only or --fuzz [seconds])" >&2
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

# Nothing compiles QML, so a syntax error that keeps the main window from
# loading passes every Rust gate. qmllint tags such an error `[syntax]` yet may
# still exit 0, so the tag is the verdict; its ordinary warnings (unresolved
# imports, unqualified access) are not.
qmllint_fixture="$script_dir/tests/qmllint"

find_qmllint() {
  local entries=() entry candidate newest
  IFS=':' read -ra entries <<<"${CMAKE_PREFIX_PATH:-}"
  for entry in ${entries[@]+"${entries[@]}"}; do
    # Either the kit or its lib/cmake, as the Qt host's build takes it.
    entry="${entry%/}"
    entry="${entry%/lib/cmake}"
    if [ -n "$entry" ] && [ -x "$entry/bin/qmllint" ]; then
      printf '%s\n' "$entry/bin/qmllint"
      return 0
    fi
  done
  # The Qt online installer's place, newest version first; then the
  # distribution's Qt 6 (Debian/Ubuntu, then lib64 distributions), then PATH.
  newest="$(printf '%s\n' "${HOME:-}"/Qt/[0-9]*.[0-9]*.[0-9]*/gcc_*/bin/qmllint | sort -V | tail -n 1)"
  for candidate in "$newest" /usr/lib/qt6/bin/qmllint /usr/lib64/qt6/bin/qmllint \
    "$(command -v qmllint6 || true)" "$(command -v qmllint-qt6 || true)" "$(command -v qmllint || true)"; do
    if [ -n "$candidate" ] && [ -x "$candidate" ]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

# Runs qmllint $2 from directory $1 over the remaining arguments; leaves its
# combined output in qmllint_out and its exit code in qmllint_status.
run_qmllint() {
  local dir="$1" tool="$2"
  shift 2
  qmllint_status=0
  qmllint_out="$(cd "$dir" && "$tool" "$@" 2>&1)" || qmllint_status=$?
}

check_qmllint() {
  local tool o total syntax path
  if ! tool="$(find_qmllint)"; then
    local message='qmllint not found (CMAKE_PREFIX_PATH, ~/Qt/<version>/gcc_*/bin, /usr/lib/qt6/bin, PATH): QML is NOT checked by this run.'
    if [ "$require_qmllint" -eq 1 ]; then
      echo "$message" >&2
      return 1
    fi
    yellow "[check] $message"
    return 0
  fi

  # The gate first proves it still sees a syntax error: a qmllint that stops
  # tagging them would otherwise pass every file silently.
  run_qmllint "$qmllint_fixture" "$tool" broken.qml
  if ! grep -qF '[syntax]' <<<"$qmllint_out"; then
    while IFS= read -r o; do
      yellow "  $o"
    done < <(printf '%s\n' "$qmllint_out" | tail -n 20)
    echo "qmllint self-test failed: '$tool' reports no [syntax] line for $qmllint_fixture/broken.qml." >&2
    return 1
  fi

  # Every QML file git would publish, wherever it lives; the fixture is not one.
  local files=()
  while IFS= read -r -d '' path; do
    case "$path" in
      scripts/tests/qmllint/*) continue ;;
      *.qml) ;;
      *) continue ;;
    esac
    if [ -f "$repo_root/$path" ]; then
      files+=("$path")
    fi
  done < <(git -C "$repo_root" ls-files -z --cached --others --exclude-standard)
  if [ "${#files[@]}" -eq 0 ]; then
    echo "qmllint: git lists no .qml file, so the scan would check nothing." >&2
    return 1
  fi

  cyan "[check] qmllint: $tool over ${#files[@]} file(s)"
  run_qmllint "$repo_root" "$tool" "${files[@]}"
  syntax="$(grep -F '[syntax]' <<<"$qmllint_out" || true)"
  if [ -n "$syntax" ]; then
    total="$(printf '%s\n' "$syntax" | wc -l)"
    while IFS= read -r o; do
      yellow "  $o"
    done < <(printf '%s\n' "$syntax" | head -n 20)
    if [ "$total" -gt 20 ]; then
      yellow "  ... and $((total - 20)) more"
    fi
    echo "qmllint: $total syntax error(s); a QML file with one does not load." >&2
    return 1
  fi
  if [ "$qmllint_status" -ne 0 ]; then
    while IFS= read -r o; do
      yellow "  $o"
    done < <(printf '%s\n' "$qmllint_out" | tail -n 20)
    echo "qmllint failed with exit code $qmllint_status." >&2
    return 1
  fi
}

if [ "$qmllint_only" -eq 1 ]; then
  check_qmllint
  green "[check] qmllint only: passed"
  exit 0
fi

cyan "[check] NetRuleRouter workspace quality baseline"

cyan "[check] sync duplicates"
# Through `bash`, like CI invokes this script: the .sh files are recorded in
# git without an executable bit, so a direct call fails on a fresh checkout.
bash "$script_dir/clean-sync-duplicates.sh" --self-test
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

# Containing a panic on foreign bytes (catch_unwind on every parser path, the
# DNS restore in Drop) works only while panics unwind: under `abort` one bad
# packet stops the service. Cargo takes profiles from the workspace root alone,
# but a config file or the environment can force the strategy as well.
find_panic_abort() {
  local path
  for path in "$@"; do
    [ -f "$path" ] || continue
    sed -E 's/(^|[[:space:]])#.*$//' "$path" |
      { grep -nP 'panic\s*=\s*["\x27]?abort\b' || true; } |
      sed "s|^|$path:|"
  done
}

check_panic_strategy() {
  local fixture="$script_dir/tests/panic-strategy" probe offences
  probe="$(find_panic_abort "$fixture/Cargo.toml.fixture" "$fixture/config.toml.fixture")"
  if [ "$(printf '%s' "$probe" | grep -c '')" -ne 3 ]; then
    [ -n "$probe" ] && yellow "$probe"
    echo "panic strategy self-test failed: expected 3 findings in $fixture." >&2
    return 1
  fi

  offences="$(
    find_panic_abort "$repo_root/Cargo.toml" "$repo_root/.cargo/config.toml" "$repo_root/.cargo/config"
    env | { grep -E '^(RUSTFLAGS|CARGO_[A-Z0-9_]*RUSTFLAGS)=' || true; } |
      { grep -P 'panic\s*=\s*["\x27]?abort\b' || true; } | sed 's/^/environment: /'
    env | { grep -E '^CARGO_PROFILE_[A-Z0-9_]+_PANIC=[[:space:]]*abort[[:space:]]*$' || true; } |
      sed 's/^/environment: /'
  )"
  [ -z "$offences" ] && return 0
  yellow "$offences"
  echo "panic strategy: settings make panics abort; the service relies on unwinding." >&2
  return 1
}

check_comment_hygiene
check_doubled_words
check_public_docs_terms
cyan "[check] panic strategy: panics unwind"
check_panic_strategy

if [ "$comment_hygiene_only" -eq 1 ]; then
  green "[check] comment hygiene only: passed"
  exit 0
fi

cyan "[check] qmllint: no QML syntax errors"
check_qmllint

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

# Opt-in: the parsers of bytes another party shapes, each under libFuzzer for
# a fixed time. Nightly-only and slow, so it is a pre-release soak, not a
# per-commit gate; scripts/fuzz.sh is the whole of it.
if [ "$fuzz_seconds" -gt 0 ]; then
  cyan "[check] fuzz: scripts/fuzz.sh --seconds $fuzz_seconds"
  bash "$script_dir/fuzz.sh" --seconds "$fuzz_seconds"
fi

green "[check] quality baseline completed successfully"
