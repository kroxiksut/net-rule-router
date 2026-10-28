#!/usr/bin/env bash
# Release guard: the first job of release.yml. A tag reaches the build only
# when it names the workspace version, the agreement is dated the release day,
# every action the workflows use is pinned to a commit, and CI on the tagged
# commit is green.
#
# CI is the workflows in `required_workflows` below. Every other workflow that
# runs on push must be named in `not_ci`, so a new CI workflow cannot be
# skipped silently. A required workflow counts as green when one of its runs
# on the commit succeeded and none failed; a run still going, or no finished
# run at all, fails the guard rather than waiting.
#
# Usage:
#   release-guard.sh --sha SHA --repo OWNER/REPO [--tag NAME] [--root DIR]
#     --tag   the tag being released; a manual run from a branch omits it and
#             is checked for CI alone (such a run drafts no release)
#     --root  the checkout to read Cargo.toml and the workflows from
#     --commit-time  the commit's time in Unix seconds; read from git by default
# Needs `gh` (or $GH) with a token that may read Actions. Self-test, no
# network: scripts/tests/release-guard/run.sh.

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/workspace-version.sh
. "$script_dir/lib/workspace-version.sh"

required_workflows=(linux-quality.yml windows-quality.yml)
not_ci=(release.yml)

sha=""
repo=""
tag=""
commit_time=""
root="$(cd "$script_dir/.." && pwd)"
while [ "$#" -gt 0 ]; do
  case "$1" in
    --sha) sha="${2:-}"; shift 2 ;;
    --repo) repo="${2:-}"; shift 2 ;;
    --tag) tag="${2:-}"; shift 2 ;;
    --root) root="${2:-}"; shift 2 ;;
    --commit-time) commit_time="${2:-}"; shift 2 ;;
    *) echo "release-guard.sh: unknown argument: $1" >&2; exit 2 ;;
  esac
done
[ -n "$sha" ] && [ -n "$repo" ] || { echo "release-guard.sh: --sha and --repo are required" >&2; exit 2; }

problems=()
problem() { problems+=("$1"); }

# ── Tag and version ──────────────────────────────────────────────────────────

version="$(nrr_workspace_version "$root/Cargo.toml")"
if [ -z "$version" ]; then
  problem "no version in [workspace.package] of Cargo.toml."
elif [ -n "$tag" ] && [ "$tag" != "v$version" ]; then
  problem "tag $tag does not match version $version in [workspace.package] of Cargo.toml. Tag the commit as v$version, or bump the version, commit, and tag that commit."
elif [ -z "$tag" ]; then
  echo "Not a tag: the version check is skipped (Cargo.toml says $version)."
else
  echo "Tag $tag matches the workspace version."
fi

# ── Agreement date ───────────────────────────────────────────────────────────

# The agreement compiled into the release carries the release day. Both
# languages name one day, at most a day from the tagged commit's UTC date:
# the owner dates it in his own time zone.
agreement_date() {
  local file="$root/docs/legal/$1" line
  line="$(sed 's/\r$//' "$file" 2>/dev/null | grep -m 1 -E "^$2 [0-9]+ " || true)"
  case "$1" in
    *.en.md) printf '%s' "$line" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}' | head -n 1 || true ;;
    *) printf '%s' "$line" | grep -oE '[0-9]{2}\.[0-9]{2}\.[0-9]{4}' | head -n 1 |
      awk -F. '{ print $3 "-" $2 "-" $1 }' || true ;;
  esac
}

if [ -n "$tag" ]; then
  en_date="$(agreement_date eula.en.md 'Agreement revision')"
  ru_date="$(agreement_date eula.ru.md 'Редакция соглашения')"
  [ -z "$commit_time" ] && commit_time="$(git -C "$root" show -s --format=%ct "$sha" 2>/dev/null || true)"
  if [ -z "$en_date" ]; then
    problem "no agreement date in the header of docs/legal/eula.en.md."
  elif [ -z "$ru_date" ]; then
    problem "no agreement date in the header of docs/legal/eula.ru.md."
  elif [ "$en_date" != "$ru_date" ]; then
    problem "docs/legal/eula.ru.md is dated $ru_date, docs/legal/eula.en.md $en_date: both carry the release day."
  elif ! printf '%s' "$commit_time" | grep -Eq '^[0-9]+$'; then
    problem "could not read the date of commit $sha, so the agreement date cannot be checked."
  else
    commit_day="$(date -u -d "@$commit_time" +%F)"
    agreement_s="$(date -u -d "$en_date" +%s 2>/dev/null || echo invalid)"
    commit_day_s="$(date -u -d "$commit_day" +%s)"
    if [ "$agreement_s" = invalid ] ||
      [ "$agreement_s" -lt $((commit_day_s - 86400)) ] || [ "$agreement_s" -gt $((commit_day_s + 86400)) ]; then
      problem "the agreement is dated $en_date, but the tagged commit was made on $commit_day: put the release day into the headers of docs/legal/eula.en.md and eula.ru.md, commit, and tag that commit."
    else
      echo "Agreement dated $en_date, the release day."
    fi
  fi
fi

# ── Which workflows are CI ───────────────────────────────────────────────────

workflow_dir="$root/.github/workflows"
for wf in "${required_workflows[@]}"; do
  [ -f "$workflow_dir/$wf" ] ||
    problem "CI workflow $wf is gone from .github/workflows: update required_workflows in scripts/release-guard.sh."
done
for file in "$workflow_dir"/*.yml "$workflow_dir"/*.yaml; do
  [ -f "$file" ] || continue
  name="${file##*/}"
  # A push trigger as a key under `on:`, or inline in `on: [push, ...]`.
  grep -Eq '^[[:space:]]+push:|^on:.*push' "$file" || continue
  listed=0
  for known in "${required_workflows[@]}" "${not_ci[@]}"; do
    [ "$name" = "$known" ] && listed=1
  done
  [ "$listed" -eq 1 ] ||
    problem "workflow $name runs on push but is not counted: add it to required_workflows or not_ci in scripts/release-guard.sh."
done

# ── Actions pinned to commits ────────────────────────────────────────────────

# A tag of an action can be moved; a commit cannot. Local actions are ours.
unpinned="$(cd "$workflow_dir" && grep -HnE '^[[:space:]]*(-[[:space:]]+)?uses:' -- *.yml 2>/dev/null |
  grep -vE "uses:[[:space:]]*[\"']?(\./|docker://)" |
  grep -vE "@[0-9a-f]{40}([\"'[:space:]]|\$)" || true)"
if [ -n "$unpinned" ]; then
  problem "actions not pinned to a full commit SHA:
$unpinned"
fi

# ── CI on the commit ─────────────────────────────────────────────────────────

gh_bin="${GH:-gh}"
if ! runs="$("$gh_bin" api --paginate "repos/$repo/actions/runs?head_sha=$sha&per_page=100" \
  --jq '.workflow_runs[] | [.path, .status, (.conclusion // "-"), .html_url] | @tsv' 2>&1)"; then
  problem "could not list the workflow runs of $sha (does the job grant actions: read?): $runs"
  runs=""
fi

for wf in "${required_workflows[@]}"; do
  green=0
  red=""
  pending=""
  while IFS=$'\t' read -r path status conclusion url; do
    [ -n "$path" ] || continue
    path="${path%%@*}"
    [ "${path##*/}" = "$wf" ] || continue
    if [ "$status" != completed ]; then
      pending="$pending $url"
      continue
    fi
    case "$conclusion" in
      success) green=1 ;;
      failure|timed_out|startup_failure) red="$red $url" ;;
    esac
  done <<<"$runs"
  if [ -n "$red" ]; then
    problem "CI failed on $sha: $wf$red. A release is built only from a commit whose CI is green."
  elif [ "$green" -eq 1 ]; then
    echo "CI green on $sha: $wf."
  elif [ -n "$pending" ]; then
    problem "CI is still running on $sha: $wf$pending. Wait for it to finish, then re-run this workflow."
  else
    problem "no successful run of $wf on $sha. Push the commit to a branch so CI runs, wait for it to pass, then re-run this workflow."
  fi
done

# ── Verdict ──────────────────────────────────────────────────────────────────

if [ "${#problems[@]}" -gt 0 ]; then
  for message in "${problems[@]}"; do
    if [ "${GITHUB_ACTIONS:-}" = true ]; then
      # An annotation is one line; the full text follows in the log.
      echo "::error title=release guard::${message%%$'\n'*}"
    fi
    echo "release guard: $message" >&2
  done
  exit 1
fi
echo "Release guard passed."
