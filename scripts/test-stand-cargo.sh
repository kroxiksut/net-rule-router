#!/usr/bin/env bash
# Opt-in Cargo runner for a dedicated test-laptop directory.
set -euo pipefail

if [ "$#" -lt 2 ] || [ "$1" != "--root" ] || [ "$#" -lt 3 ]; then
  echo 'Usage: bash scripts/test-stand-cargo.sh --root /absolute/dedicated/directory <cargo arguments...>' >&2
  exit 2
fi
root=$2
shift 2
case "$root" in /*) ;; *) echo 'The stand root must be an absolute path.' >&2; exit 2 ;; esac
unsupported=$(printf '%s' "$root" | LC_ALL=C tr -d 'a-zA-Z0-9_./-')
if [ -n "$unsupported" ]; then echo 'The stand root must use only ASCII letters, digits, slash, dot, underscore or hyphen.' >&2; exit 2; fi
if [ ! -d "$root" ] || [ -L "$root" ] || [ "$(realpath -e -- "$root")" != "${root%/}" ]; then
  echo 'Create a dedicated, canonical directory without symbolic links first.' >&2
  exit 2
fi
if [ "$(stat -c %u -- "$root")" != "$(id -u)" ]; then
  echo 'The stand root must belong to the current user.' >&2
  exit 2
fi
if [ -n "${RUSTC_WRAPPER:-}" ] || [ -n "${RUSTC_WORKSPACE_WRAPPER:-}" ] || env | grep -q '^SCCACHE_'; then
  echo 'Unset Rust wrappers and SCCACHE_* before starting the isolated stand.' >&2
  exit 2
fi
command -v cargo >/dev/null
command -v sccache >/dev/null
command -v setsid >/dev/null
command -v flock >/dev/null
available_kib=$(df -Pk -- "$root" | awk 'NR == 2 {print $4}')
if [ "$available_kib" -lt 15728640 ]; then
  echo 'The stand volume needs at least 15 GiB free before the run.' >&2
  exit 2
fi
for path in "$root/target" "$root/cache"; do
  if [ -L "$path" ] || { [ -e "$path" ] && [ ! -d "$path" ]; }; then
    echo "Refusing non-directory or symlink: $path" >&2
    exit 2
  fi
done
mkdir -p -- "$root/target" "$root/cache"
lock_file="$root/.nrr-stand.lock"
if [ -L "$lock_file" ]; then echo 'The stand lock cannot be a symlink.' >&2; exit 2; fi
exec {lock_fd}> "$lock_file"
if ! flock -n "$lock_fd"; then echo 'Another stand run holds this root.' >&2; exit 2; fi

config="$root/sccache-empty.toml"
if [ -L "$config" ] || { [ -e "$config" ] && { [ ! -f "$config" ] || [ -s "$config" ]; }; }; then
  echo 'The stand configuration must be an empty regular file.' >&2
  exit 2
fi
: > "$config"
# A private socket directory avoids adopting or stopping an unrelated server.
socket_dir=$(mktemp -d "$root/.sccache-socket.XXXXXXXX")
chmod 700 "$socket_dir"
socket_path="$socket_dir/server.sock"
if [ "${#socket_path}" -gt 100 ]; then
  rmdir -- "$socket_dir"
  echo 'The stand root is too long for a private Unix socket.' >&2
  exit 2
fi
server_started=0
finish() {
  if [ "$server_started" -eq 1 ] && [ -S "$socket_path" ]; then sccache --stop-server >/dev/null 2>&1 || true; fi
  if [ -S "$socket_path" ]; then rm -f -- "$socket_path"; fi
  rmdir -- "$socket_dir" 2>/dev/null || true
}
trap finish EXIT
export CARGO_TARGET_DIR="$root/target" CARGO_INCREMENTAL=0
export RUSTC_WRAPPER="$(command -v sccache)" SCCACHE_DIR="$root/cache"
export SCCACHE_CACHE_SIZE=10G SCCACHE_CONF="$config" SCCACHE_SERVER_UDS="$socket_path"
export SCCACHE_IDLE_TIMEOUT=60
sccache --start-server
if [ ! -S "$socket_path" ]; then
  echo 'sccache did not create its private Unix socket; refusing to use or stop another server.' >&2
  exit 1
fi
server_started=1
echo "[stand] target=$CARGO_TARGET_DIR cache=$SCCACHE_DIR (max 10G)"
setsid cargo "$@" &
cargo_pid=$!
if kill -0 "$cargo_pid" 2>/dev/null; then
  cargo_pgid=''
  for _ in {1..50}; do
    cargo_pgid=$(ps -o pgid= -p "$cargo_pid" | tr -d '[:space:]') || cargo_pgid=''
    [ "$cargo_pgid" = "$cargo_pid" ] && break
    kill -0 "$cargo_pid" 2>/dev/null || break
    sleep 0.02
  done
  if kill -0 "$cargo_pid" 2>/dev/null && [ "$cargo_pgid" != "$cargo_pid" ]; then
    echo '[stand] Could not isolate the build process group.' >&2
    kill -TERM "$cargo_pid" 2>/dev/null || true
    wait "$cargo_pid" 2>/dev/null || true
    exit 1
  fi
fi
(
  while kill -0 "$cargo_pid" 2>/dev/null; do
    free=$(df -Pk -- "$root" | awk 'NR == 2 {print $4}') || free=0
    if [ "${free:-0}" -lt 7340032 ]; then
      echo '[stand] Disk reserve threatened; stopping this build.' >&2
      kill -TERM -- "-$cargo_pid" 2>/dev/null || true
      exit 1
    fi
    sleep 1
  done
) &
monitor_pid=$!
interrupt() {
  trap - INT TERM
  kill -TERM -- "-$cargo_pid" 2>/dev/null || true
  kill "$monitor_pid" 2>/dev/null || true
  wait "$cargo_pid" 2>/dev/null || true
  wait "$monitor_pid" 2>/dev/null || true
  exit 130
}
trap interrupt INT TERM
status=0
wait "$cargo_pid" || status=$?
kill "$monitor_pid" 2>/dev/null || true
wait "$monitor_pid" 2>/dev/null || true
trap - INT TERM
sccache --show-stats || true
exit "$status"
