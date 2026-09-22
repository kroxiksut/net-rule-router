#!/usr/bin/env bash
# Linux counterpart of uninstall-service.ps1. Counterpart of install-service.sh:
# removes the unit AND the staged copy under /usr/lib/netrulerouter that
# install-service.sh put there.
#
# Difference from uninstall-service.ps1: `nrr-serviced uninstall` runs
# `systemctl disable --now`, which stops the unit as part of removing it — no
# separate `sc.exe stop`-style step is needed first.
#
# No --purge flag here: unlike the Windows binary, `nrr-serviced uninstall`
# does not yet expose a purge option (it always calls the keep-data uninstall
# spec). Service data under /var/lib/netrulerouter and /var/log/netrulerouter
# is left in place either way.
#
# Usage:
#   ./scripts/uninstall-service.sh
#   ./scripts/uninstall-service.sh --profile release

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
# shellcheck source=lib/service-paths.sh
. "$script_dir/lib/service-paths.sh"

profile="auto"
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
      echo "unknown argument: $1 (expected --profile auto|dev|release)" >&2
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

# The staged copy is the registered daemon, so it answers `uninstall` even when
# the build tree has been cleaned; the build output is the fallback.
exe_path="$NRR_STAGED_SERVICE_BINARY"
if [ ! -f "$exe_path" ]; then
  target_root="$(nrr_target_root "$repo_root")"
  exe_path="$(nrr_built_service_binary "$target_root" "$profile")"
fi

if [ ! -f "$exe_path" ]; then
  echo "Service binary found neither at $NRR_STAGED_SERVICE_BINARY nor in target/. Cannot uninstall without it (need its \`uninstall\` verb)." >&2
  exit 1
fi

nrr_cyan "==> uninstall"
nrr_run_privileged "$exe_path" uninstall

# The uninstall plan removes the unit, the drop-ins and the alias symlink; the
# staged binary is this script's own footprint, so this script clears it.
if [ -f "$NRR_STAGED_SERVICE_BINARY" ]; then
  nrr_cyan "==> remove $NRR_STAGED_SERVICE_BINARY"
  nrr_run_privileged rm -f "$NRR_STAGED_SERVICE_BINARY" "$NRR_SERVICE_INSTALL_DIR/$NRR_SERVICE_ALIAS_NAME"
  nrr_run_privileged rmdir --ignore-fail-on-non-empty "$NRR_SERVICE_INSTALL_DIR"
fi

nrr_green "Service uninstalled. State DB and audit logs preserved."
