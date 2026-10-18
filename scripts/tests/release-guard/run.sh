#!/usr/bin/env bash
# Self-test of scripts/release-guard.sh against a fake `gh` and a fixture
# checkout: no network, no token. Run by the guard job before the guard.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
guard="$here/../../release-guard.sh"
work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT

pin="0123456789abcdef0123456789abcdef01234567"
make_root() {
  local root="$work/root"
  rm -rf -- "$root"
  mkdir -p "$root/.github/workflows"
  printf '[workspace]\nmembers = []\n\n[workspace.package]\nversion = "1.2.3-alpha"\n' >"$root/Cargo.toml"
  for wf in linux-quality windows-quality; do
    printf 'name: %s\non:\n  push:\njobs:\n  baseline:\n    steps:\n      - uses: actions/checkout@%s # v4\n' "$wf" "$pin" \
      >"$root/.github/workflows/$wf.yml"
  done
  printf 'name: release\non:\n  push:\n    tags: ["v*"]\njobs:\n  a:\n    steps:\n      - uses: ./.github/actions/local\n' \
    >"$root/.github/workflows/release.yml"
  printf 'name: codeql\non:\n  workflow_dispatch:\n' >"$root/.github/workflows/codeql.yml"
}

# The fake prints $FAKE_RUNS as the `--jq` output would look, or fails.
cat >"$work/gh" <<'FAKE'
#!/usr/bin/env bash
[ -z "${FAKE_FAIL:-}" ] || { echo "HTTP 403: Resource not accessible by integration" >&2; exit 1; }
printf '%b' "${FAKE_RUNS:-}"
FAKE
chmod +x "$work/gh"

ok=".github/workflows/linux-quality.yml\tcompleted\tsuccess\thttps://x/1\n.github/workflows/windows-quality.yml\tcompleted\tsuccess\thttps://x/2\n"
failures=0
# expect <exit code> <text the output must hold, or ""> <guard args...>
expect() {
  local want="$1" text="$2" got=0 out
  shift 2
  out="$(GH="$work/gh" GITHUB_ACTIONS="" bash "$guard" --sha abc --repo o/r --root "$work/root" "$@" 2>&1)" || got=$?
  if [ "$got" -ne "$want" ] || { [ -n "$text" ] && ! grep -qF -- "$text" <<<"$out"; }; then
    echo "FAIL: ${case_name}: exit $got (want $want), output:" >&2
    printf '%s\n' "$out" >&2
    failures=$((failures + 1))
  else
    echo "ok: ${case_name}"
  fi
}

make_root
case_name="green, matching tag"; FAKE_RUNS="$ok" expect 0 "Release guard passed" --tag v1.2.3-alpha
case_name="branch run, no tag"; FAKE_RUNS="$ok" expect 0 "version check is skipped"
case_name="tag of another version"; FAKE_RUNS="$ok" expect 1 "does not match version 1.2.3-alpha" --tag v1.2.4
case_name="red commit"; FAKE_RUNS="${ok}.github/workflows/linux-quality.yml\tcompleted\tfailure\thttps://x/3\n" \
  expect 1 "CI failed on abc: linux-quality.yml https://x/3" --tag v1.2.3-alpha
case_name="CI still running"; FAKE_RUNS=".github/workflows/linux-quality.yml\tcompleted\tsuccess\thttps://x/1\n.github/workflows/windows-quality.yml\tin_progress\t-\thttps://x/4\n" \
  expect 1 "still running on abc: windows-quality.yml https://x/4" --tag v1.2.3-alpha
case_name="duplicate run of the tag push still going"; FAKE_RUNS="${ok}.github/workflows/windows-quality.yml\tqueued\t-\thttps://x/5\n" \
  expect 0 "" --tag v1.2.3-alpha
case_name="CI never ran"; FAKE_RUNS=".github/workflows/linux-quality.yml\tcompleted\tsuccess\thttps://x/1\n" \
  expect 1 "no successful run of windows-quality.yml" --tag v1.2.3-alpha
case_name="only a cancelled run"; FAKE_RUNS=".github/workflows/linux-quality.yml\tcompleted\tsuccess\thttps://x/1\n.github/workflows/windows-quality.yml\tcompleted\tcancelled\thttps://x/6\n" \
  expect 1 "no successful run of windows-quality.yml" --tag v1.2.3-alpha
case_name="runs not readable"; FAKE_FAIL=1 expect 1 "could not list the workflow runs" --tag v1.2.3-alpha

printf '      - uses: actions/upload-artifact@v4\n' >>"$work/root/.github/workflows/linux-quality.yml"
case_name="action pinned to a tag"; FAKE_RUNS="$ok" expect 1 "linux-quality.yml:8:      - uses: actions/upload-artifact@v4" --tag v1.2.3-alpha

make_root
printf 'name: lint\non: [push, pull_request]\n' >"$work/root/.github/workflows/lint.yml"
case_name="new push workflow not counted"; FAKE_RUNS="$ok" expect 1 "workflow lint.yml runs on push but is not counted" --tag v1.2.3-alpha

make_root
rm "$work/root/.github/workflows/windows-quality.yml"
case_name="CI workflow renamed away"; FAKE_RUNS="$ok" expect 1 "CI workflow windows-quality.yml is gone" --tag v1.2.3-alpha

[ "$failures" -eq 0 ] || { echo "release-guard self-test: $failures case(s) failed" >&2; exit 1; }
echo "release-guard self-test passed."
