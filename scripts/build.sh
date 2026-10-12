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
# shellcheck source=lib/service-paths.sh
. "$script_dir/lib/service-paths.sh"
# shellcheck source=lib/desktop-paths.sh
. "$script_dir/lib/desktop-paths.sh"
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

# The menu entry launches the Unix-named copy; without this it keeps starting
# the previous build.
profile_dir="$(nrr_target_root "$NRR_REPO_ROOT")"
if [ -n "${NRR_RUST_TARGET:-}" ]; then
  profile_dir="$profile_dir/$NRR_RUST_TARGET"
fi
if [ "$profile" = "release" ]; then
  profile_dir="$profile_dir/release"
else
  profile_dir="$profile_dir/debug"
fi
nrr_sync_unix_binaries "$profile_dir"

printf '\033[32m[build] completed successfully\033[0m\n'
