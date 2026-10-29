#!/usr/bin/env bash
# The product version: `version` in [workspace.package] of Cargo.toml, read
# without cargo so a machine with only the binaries can package them. One
# reader, so the packages and the release guard cannot disagree on it.
# Sourced, never executed.

# Prints the version from the Cargo.toml at $1; prints nothing when absent.
nrr_workspace_version() {
  awk '
    { sub(/\r$/, "") }
    /^[ \t]*\[/ {
      header = $0
      sub(/^[ \t]*/, "", header)
      sub(/[ \t]*(#.*)?$/, "", header)
      in_package = (header == "[workspace.package]")
      next
    }
    in_package && /^[ \t]*version[ \t]*=/ {
      v = $0
      sub(/^[^"]*"/, "", v)
      sub(/".*$/, "", v)
      print v
      exit
    }
  ' "$1"
}

# Prints the version $1 as dpkg and rpm order it: a tilde sorts a pre-release
# before its release. Fails, printing nothing, for a pre-release outside the
# order the Windows installers rank, so a build the package managers would
# misorder stops instead of shipping.
nrr_package_version() {
  local base="${1%%-*}" pre stage number
  if [ "$base" = "$1" ]; then
    printf '%s' "$1"
    return 0
  fi
  pre="${1#*-}"
  stage="${pre%%.*}"
  number="${pre#"$stage"}"
  case "$number" in
    "" | .[0-9] | .[0-9][0-9]) ;;
    *) return 1 ;;
  esac
  case "$stage" in
    # Two tildes: letter by letter `prealpha` would sort after `alpha`.
    dev | prealpha) [ -z "$number" ] || return 1; printf '%s~~%s' "$base" "$pre" ;;
    alpha | beta | rc) printf '%s~%s' "$base" "$pre" ;;
    *) return 1 ;;
  esac
}
