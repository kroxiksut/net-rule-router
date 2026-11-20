#!/usr/bin/env bash
# Regression: an exited disk monitor must not keep the stand lock in its sleep child.
set -euo pipefail
if [ "$#" -ne 2 ]; then
  echo 'Usage: test-stand-lock.sh RUNNER DEDICATED_ROOT' >&2
  exit 2
fi
runner=$1
root=$2
test_dir=$(mktemp -d "$root/.lock-test.XXXXXXXX")
cleanup() {
  # Let any deliberately delayed monitor child exit before deleting its stub.
  /bin/sleep 3
  rm -f -- "$test_dir/sleep"
  rmdir -- "$test_dir"
}
trap cleanup EXIT
printf '#!/bin/sh\nexec /bin/sleep 3\n' > "$test_dir/sleep"
chmod 700 "$test_dir/sleep"
export PATH="$test_dir:$PATH"
for ((i=0; i<3; i++)); do
  bash "$runner" --root "$root" --version >/dev/null
  if ! bash "$runner" --root "$root" --version >/dev/null; then
    echo "Immediate next run could not acquire the stand lock (iteration $i)." >&2
    exit 1
  fi
done
