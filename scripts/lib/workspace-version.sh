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
