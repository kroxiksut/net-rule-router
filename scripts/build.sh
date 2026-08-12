#!/usr/bin/env bash
# Linux counterpart of build.ps1. Same behaviour: --target is only passed
# when NRR_RUST_TARGET is set, otherwise cargo builds for the host triple —
# an explicit triplet moves artifacts to target/<triplet>/<profile>/, which
# the rest of the scripts don't look in.
#
# Usage:
#   ./scripts/build.sh
#   ./scripts/build.sh --profile release

set -euo pipefail

profile="dev"
while [ "$#" -gt 0 ]; do
  case "$1" in
    --profile)
      profile="${2:-}"
      shift 2
      ;;
    --profile=*)
      profile="${1#--profile=}"
      shift
      ;;
    *)
      echo "unknown argument: $1 (expected --profile dev|release)" >&2
      exit 2
      ;;
  esac
done

case "$profile" in
  dev|release) ;;
  *)
    echo "invalid --profile '$profile' (expected dev or release)" >&2
    exit 2
    ;;
esac

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
"$script_dir/clean-sync-duplicates.sh"

cargo_args=(build --workspace)
if [ -n "${NRR_RUST_TARGET:-}" ]; then
  cargo_args+=(--target "$NRR_RUST_TARGET")
fi
if [ "$profile" = "release" ]; then
  cargo_args+=(--release)
fi

printf '\033[36m[build] cargo %s\033[0m\n' "${cargo_args[*]}"
cargo "${cargo_args[@]}"

printf '\033[32m[build] completed successfully\033[0m\n'
