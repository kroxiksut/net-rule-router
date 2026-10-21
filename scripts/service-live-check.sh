#!/usr/bin/env bash
# Linux counterpart of service-live-check.ps1: is the running service alive,
# not just started? Run after every install of a new build, before handing it
# over.
#
# Green gates do not prove it: a deadlock between two background tasks passes
# every unit test and still leaves the service answering nothing, with the
# system DNS pointed at its stalled resolver. The supervisor reports a task
# that misses its deadline as `supervised-task-hung`, and the log stays
# readable while the rest is stuck, so that is what this reads.
#
# Waits until the service has run --min-uptime seconds since its last start,
# then fails when a task was reported hung since that start and has not
# recovered, when the log read through the service does not come back in
# time, or when --resolve does not resolve through the system resolver.
#
# Usage:
#   ./scripts/service-live-check.sh [--min-uptime 150] [--resolve api.github.com]
#                                   [--cli PATH] [--log-file FILE]
# --log-file judges a saved log (NDJSON, e.g. from a diagnostic archive)
# instead of asking the service, without waiting.

set -uo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/service-paths.sh
. "$script_dir/lib/service-paths.sh"

min_uptime=150
resolve_name="api.github.com"
answer_timeout=20
cli=""
log_file=""
while [ $# -gt 0 ]; do
  case "$1" in
    --min-uptime) min_uptime="$2"; shift 2 ;;
    --resolve) resolve_name="$2"; shift 2 ;;
    --cli) cli="$2"; shift 2 ;;
    --log-file) log_file="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [ -z "$log_file" ]; then
  [ -n "$cli" ] || cli="$(command -v nrr-cli || true)"
  [ -x "$cli" ] || { echo "nrr-cli not found (pass --cli)" >&2; exit 2; }
fi

read_log() {
  if [ -n "$log_file" ]; then
    cat -- "$log_file"
  else
    timeout "$answer_timeout" "$cli" diag logs --tail=2000
  fi
}

number_of() { grep -o "\"$1\":\"\\?[0-9]*" | grep -o '[0-9]*$'; }
text_of() { grep -o "\"$1\":\"[^\"]*\"" | sed 's/^.*:"//; s/"$//'; }

last_start() {
  grep '"message_key":"diag.event.svc-boot-stage-entered"' |
    grep '"stage":"build-deps"' | tail -n 1 | number_of created_at
}

log="$(read_log)" || { echo "the service did not return its log within ${answer_timeout} s" >&2; exit 1; }
start="$(last_start <<<"$log")"
[ -n "$start" ] || { echo "no service start in the last 2000 log lines; is the service running?" >&2; exit 1; }

if [ -z "$log_file" ]; then
  now_ms=$(( $(date +%s) * 1000 ))
  wait_ms=$(( start + min_uptime * 1000 - now_ms ))
  if [ "$wait_ms" -gt 0 ]; then
    nrr_cyan "[live-check] waiting $(( (wait_ms + 999) / 1000 )) s until the service has run ${min_uptime} s"
    sleep $(( (wait_ms + 999) / 1000 ))
  fi
fi

failures=()
began=$(date +%s%N)
if ! log="$(read_log)"; then
  failures+=("the service did not return its log within ${answer_timeout} s")
else
  nrr_gray "[live-check] log answered in $(( ($(date +%s%N) - began) / 1000000 )) ms"
  [ "$(last_start <<<"$log")" = "$start" ] || failures+=("the service restarted while being checked")
  declare -A hung=()
  while IFS= read -r line; do
    at="$(number_of created_at <<<"$line" | head -n 1)"
    [ -n "$at" ] && [ "$at" -ge "$start" ] || continue
    task="$(text_of task <<<"$line" | head -n 1)"
    case "$line" in
      *'"message_key":"diag.event.supervised-task-hung"'*)
        hung["$task"]="$(number_of seconds <<<"$line" | head -n 1)" ;;
      *'"message_key":"diag.event.supervised-task-responsive"'*)
        unset 'hung[$task]' ;;
    esac
  done < <(grep -E 'supervised-task-(hung|responsive)' <<<"$log")
  for task in "${!hung[@]}"; do
    failures+=("task '$task' hung (${hung[$task]} s past its deadline)")
  done
fi

getent ahostsv4 "$resolve_name" >/dev/null 2>&1 || failures+=("$resolve_name did not resolve")

if [ "${#failures[@]}" -gt 0 ]; then
  for f in "${failures[@]}"; do printf '\033[31m[live-check] FAIL: %s\033[0m\n' "$f"; done
  exit 1
fi
nrr_green "[live-check] the service is alive: no hung task, log answered, DNS resolves"
