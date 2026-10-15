#!/usr/bin/env bash
# Runs every fuzz target under fuzz/ for a fixed time each and fails on any
# crash, hang or out-of-memory finding. Linux only: cargo-fuzz drives
# libFuzzer, which needs the nightly toolchain.
#
# One-time setup:
#   rustup toolchain install nightly
#   cargo install cargo-fuzz
#
# Usage:
#   ./scripts/fuzz.sh                       # 60 s per target
#   ./scripts/fuzz.sh --seconds 300         # longer soak
#   ./scripts/fuzz.sh --target dns_wire_query
#   ./scripts/fuzz.sh --list
#
# New inputs the fuzzer finds go to fuzz/work/<target>/ (ignored by git); the
# committed seeds stay in fuzz/corpus/<target>/. A crash lands in
# fuzz/artifacts/<target>/ with the libFuzzer report on stderr.

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
fuzz_dir="$repo_root/fuzz"

seconds=60
only_target=""
list_only=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --seconds)
      [ "$#" -ge 2 ] || { echo "--seconds needs a number" >&2; exit 2; }
      seconds="$2"
      shift 2
      ;;
    --target)
      [ "$#" -ge 2 ] || { echo "--target needs a name" >&2; exit 2; }
      only_target="$2"
      shift 2
      ;;
    --list) list_only=1; shift ;;
    *)
      echo "unknown argument: $1 (expected --seconds N, --target NAME or --list)" >&2
      exit 2
      ;;
  esac
done
case "$seconds" in
  ''|*[!0-9]*) echo "--seconds takes a whole number of seconds, got '$seconds'" >&2; exit 2 ;;
esac

cyan() { printf '\033[36m%s\033[0m\n' "$1"; }
green() { printf '\033[32m%s\033[0m\n' "$1"; }
red() { printf '\033[31m%s\033[0m\n' "$1" >&2; }

# The targets are the binaries the fuzz manifest declares, in its order.
targets=()
while IFS= read -r name; do
  targets+=("$name")
done < <(grep -A1 '^\[\[bin\]\]' "$fuzz_dir/Cargo.toml" | sed -n 's/^name = "\(.*\)"/\1/p')
[ "${#targets[@]}" -gt 0 ] || { red "no fuzz targets declared in $fuzz_dir/Cargo.toml"; exit 1; }

if [ "$list_only" -eq 1 ]; then
  printf '%s\n' "${targets[@]}"
  exit 0
fi

if [ -n "$only_target" ]; then
  found=0
  for t in "${targets[@]}"; do [ "$t" = "$only_target" ] && found=1; done
  [ "$found" -eq 1 ] || { red "unknown target '$only_target'; --list names them"; exit 2; }
  targets=("$only_target")
fi

if [ "$(uname -s)" != "Linux" ]; then
  red "fuzz.sh runs on Linux only (libFuzzer through cargo-fuzz)."
  exit 1
fi
if ! rustup run nightly cargo --version >/dev/null 2>&1; then
  red "the nightly toolchain is missing: rustup toolchain install nightly"
  exit 1
fi
if ! cargo +nightly fuzz --version >/dev/null 2>&1; then
  red "cargo-fuzz is missing: cargo install cargo-fuzz"
  exit 1
fi

# A timeout is a hang: no parser here has a reason to spend ten seconds on one
# input. The memory cap is per process; the stack target builds a whole
# user-space TCP/IP stack per input, which is still far under it.
timeout_secs=10
rss_limit_mb=2048
max_len=65536

cyan "[fuzz] ${#targets[@]} target(s), ${seconds}s each, timeout ${timeout_secs}s, rss limit ${rss_limit_mb} MB"

failed=()
passed=()
for target in "${targets[@]}"; do
  seed_dir="$fuzz_dir/corpus/$target"
  work_dir="$fuzz_dir/work/$target"
  mkdir -p "$work_dir" "$seed_dir"
  cyan "[fuzz] $target"
  status=0
  (
    cd "$repo_root"
    cargo +nightly fuzz run --fuzz-dir "$fuzz_dir" "$target" \
      "$work_dir" "$seed_dir" -- \
      -max_total_time="$seconds" \
      -timeout="$timeout_secs" \
      -rss_limit_mb="$rss_limit_mb" \
      -max_len="$max_len" \
      -print_final_stats=1
  ) || status=$?
  if [ "$status" -eq 0 ]; then
    passed+=("$target")
  else
    failed+=("$target")
    red "[fuzz] $target: libFuzzer exited with $status (artifact under fuzz/artifacts/$target/)"
  fi
done

echo
cyan "[fuzz] summary"
for t in ${passed[@]+"${passed[@]}"}; do green "  pass  $t"; done
for t in ${failed[@]+"${failed[@]}"}; do red "  FAIL  $t"; done
if [ "${#failed[@]}" -gt 0 ]; then
  red "[fuzz] ${#failed[@]} target(s) found a crash, hang or memory blow-up."
  exit 1
fi
green "[fuzz] all ${#passed[@]} target(s) ran ${seconds}s without a finding"
