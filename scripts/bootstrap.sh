#!/usr/bin/env bash
# Linux counterpart of bootstrap.ps1. Same steps, POSIX tools.
#
# Usage:
#   ./scripts/bootstrap.sh
#   ./scripts/bootstrap.sh --strict-qt

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"

strict_qt=0
for arg in "$@"; do
  case "$arg" in
    --strict-qt) strict_qt=1 ;;
    *)
      echo "unknown argument: $arg (expected --strict-qt)" >&2
      exit 2
      ;;
  esac
done

cyan() { printf '\033[36m%s\033[0m\n' "$1"; }
green() { printf '\033[32m%s\033[0m\n' "$1"; }
yellow() { printf '\033[33m%s\033[0m\n' "$1" >&2; }

have() { command -v "$1" >/dev/null 2>&1; }

cyan "[bootstrap] NetRuleRouter development bootstrap"

if ! have rustup; then
  echo "rustup was not found. Install Rust toolchain first." >&2
  exit 1
fi
if ! have cargo; then
  echo "cargo was not found. Install Rust toolchain first." >&2
  exit 1
fi

target="${NRR_RUST_TARGET:-$(rustc -vV | sed -n 's/^host: //p')}"
if [ -z "$target" ]; then
  echo "could not determine the host Rust target triple." >&2
  exit 1
fi

if ! rustup target list --installed | grep -qx "$target"; then
  cyan "[bootstrap] adding rust target $target"
  rustup target add "$target"
fi

if [ ! -f "$repo_root/.env" ]; then
  cp "$repo_root/.env.example" "$repo_root/.env"
  cyan "[bootstrap] created .env from .env.example"
else
  cyan "[bootstrap] .env already exists; skip"
fi

# Debian/Ubuntu suffix the Qt6 tools (`qmake6`, `qtpaths6`) so they can sit
# beside Qt5; other distributions and the Qt installer ship them unsuffixed.
# What the build actually needs is the Qt6 CMake package, which the tool only
# stands in for here.
qt_tool_found=0
for qt_tool in qmake6 qtpaths6 qmake qtpaths; do
  if have "$qt_tool"; then
    qt_tool_found=1
    break
  fi
done
cmake_found=0
have cmake && cmake_found=1

if [ "$strict_qt" -eq 1 ]; then
  if [ "$qt_tool_found" -eq 0 ]; then
    echo "Qt tool not found (qmake6/qtpaths6/qmake/qtpaths). Install Qt 6.6+ for GUI integration." >&2
    exit 1
  fi
  if [ "$cmake_found" -eq 0 ]; then
    echo "cmake not found. Install CMake 3.26+ for Qt build integration." >&2
    exit 1
  fi
else
  if [ "$qt_tool_found" -eq 0 ]; then
    yellow "Qt tool not found (qmake6/qtpaths6/qmake/qtpaths). Rust workspace is still bootstrap-able, but Qt GUI wiring will require it."
  fi
  if [ "$cmake_found" -eq 0 ]; then
    yellow "cmake not found. Rust workspace is still bootstrap-able, but Qt integration will require it."
  fi
fi

cargo check --workspace

green "[bootstrap] completed successfully"
