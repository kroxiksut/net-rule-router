#!/usr/bin/env bash
# Turn a Linux release build into installable packages: .deb, .rpm and .tar.gz.
#
# Two packages per package format, so switching between "with a window" and
# "without" is an install or a removal, never a swap of two packages fighting
# over one service:
#   netrulerouter      the service, the nrr-cli console, the nrr-tui interface
#   netrulerouter-gui  the window and the tray; requires netrulerouter of the
#                      same version and Qt 6.6 or newer
# The archives come whole: a full one, and a headless one without the GUI.
#
# One owner per install for the systemd unit: a .deb or .rpm ships the unit the
# daemon renders (`nrr-serviced package-files`) and enables it from its own
# scripts, and while that unit is there `nrr-serviced install` / `uninstall`
# and the install scripts refuse. An archive has no package manager, so there
# the daemon's own `install` verb owns the unit.
#
# Layout: everything sits beside the daemon in /usr/libexec/netrulerouter, the
# GUI binaries under their Unix names, with links in /usr/bin. The launcher and
# the terminal programs find their QML, locales and presets beside the binary,
# which is the only place a release build looks.
#
# Usage:
#   ./scripts/package-linux.sh                       # full set from an existing release build
#   ./scripts/package-linux.sh --build               # build first (needs Qt 6.6+ for the GUI)
#   ./scripts/package-linux.sh --headless --build    # no GUI, no Qt (the glibc 2.28 baseline)
#   ./scripts/package-linux.sh --formats deb,tar --out /tmp/nrr-packages
#
# Every package is checked against packaging/linux/package-contents.txt once
# built; a missing file fails the run.

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
# shellcheck source=lib/service-paths.sh
. "$script_dir/lib/service-paths.sh"
# shellcheck source=lib/desktop-paths.sh
. "$script_dir/lib/desktop-paths.sh"
# shellcheck source=lib/workspace-version.sh
. "$script_dir/lib/workspace-version.sh"

usage() {
  cat <<'EOF'
Usage: package-linux.sh [options]

  --build              build the release binaries first (cargo build --release --locked)
  --headless           no GUI: skip netrulerouter-gui and the full archive; needs no Qt
  --formats LIST       comma-separated subset of deb,rpm,tar (default: all three)
  --arch ARCH          x86_64 or aarch64 (default: this machine)
  --release N          package release number (default: 1)
  --out DIR            output directory (default: <cargo target dir>/packages)
  --maintainer TEXT    Maintainer of the .deb and Packager of the .rpm (default:
                       $NRR_PACKAGE_MAINTAINER, else "NetRuleRouter <fmalkov91@gmail.com>")
  --max-glibc X.Y      fail when the service, nrr-cli or nrr-tui need a glibc newer
                       than X.Y (the release passes 2.28 for the headless build)
EOF
}

die() {
  echo "package-linux.sh: $*" >&2
  exit 1
}

do_build=0
headless=0
formats="deb,rpm,tar"
arch=""
release="1"
out_dir=""
maintainer="${NRR_PACKAGE_MAINTAINER:-NetRuleRouter <fmalkov91@gmail.com>}"
max_glibc=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --build) do_build=1; shift ;;
    --headless) headless=1; shift ;;
    --formats) formats="${2:-}"; shift 2 ;;
    --formats=*) formats="${1#--formats=}"; shift ;;
    --arch) arch="${2:-}"; shift 2 ;;
    --arch=*) arch="${1#--arch=}"; shift ;;
    --release) release="${2:-}"; shift 2 ;;
    --release=*) release="${1#--release=}"; shift ;;
    --out) out_dir="${2:-}"; shift 2 ;;
    --out=*) out_dir="${1#--out=}"; shift ;;
    --maintainer) maintainer="${2:-}"; shift 2 ;;
    --maintainer=*) maintainer="${1#--maintainer=}"; shift ;;
    --max-glibc) max_glibc="${2:-}"; shift 2 ;;
    --max-glibc=*) max_glibc="${1#--max-glibc=}"; shift ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

want_deb=0
want_rpm=0
want_tar=0
IFS=',' read -r -a requested_formats <<<"$formats"
for format in "${requested_formats[@]}"; do
  case "$format" in
    deb) want_deb=1 ;;
    rpm) want_rpm=1 ;;
    tar|tar.gz|tgz) want_tar=1 ;;
    *) die "unknown format '$format' (expected deb, rpm or tar)" ;;
  esac
done
[ $((want_deb + want_rpm + want_tar)) -gt 0 ] || die "no format selected"
case "$release" in
  ''|*[!0-9]*) die "--release must be a number, got '$release'" ;;
esac
if [ -n "$max_glibc" ] && ! printf '%s' "$max_glibc" | grep -Eq '^[0-9]+\.[0-9]+$'; then
  die "--max-glibc takes a version like 2.28, got '$max_glibc'"
fi

# ── Architecture ─────────────────────────────────────────────────────────────

normalize_arch() {
  case "$1" in
    x86_64|amd64) echo x86_64 ;;
    aarch64|arm64) echo aarch64 ;;
    *) echo "$1" ;;
  esac
}
host_arch="$(normalize_arch "$(uname -m)")"
arch="$(normalize_arch "${arch:-$host_arch}")"
case "$arch" in
  x86_64) deb_arch=amd64; rust_triple=x86_64-unknown-linux-gnu ;;
  aarch64) deb_arch=arm64; rust_triple=aarch64-unknown-linux-gnu ;;
  *) die "unsupported architecture '$arch' (expected x86_64 or aarch64)" ;;
esac
rpm_arch="$arch"
# Another architecture is built for its own triple. The unit is rendered by
# running that daemon, so the machine must be able to execute it (binfmt).
rust_target="${NRR_RUST_TARGET:-}"
if [ "$arch" != "$host_arch" ] && [ -z "$rust_target" ]; then
  rust_target="$rust_triple"
fi

# ── Tools ────────────────────────────────────────────────────────────────────

missing=()
need_tool() {
  command -v "$1" >/dev/null 2>&1 || missing+=("$1 - $2")
}
for tool in tar gzip sha256sum find sort comm awk sed install; do
  need_tool "$tool" "coreutils/findutils/tar/gzip/sed/gawk from the distribution"
done
need_tool readelf "Debian/Ubuntu/Astra: apt install binutils; RHEL-like/RED OS: dnf install binutils"
if [ "$want_deb" -eq 1 ]; then
  need_tool dpkg-deb "apt install dpkg-dev"
  need_tool dpkg-shlibdeps "apt install dpkg-dev (a .deb is built on a Debian-family system)"
fi
if [ "$want_rpm" -eq 1 ]; then
  need_tool rpmbuild "Debian/Ubuntu/Astra: apt install rpm; RHEL-like/RED OS: dnf install rpm-build"
  need_tool rpm "Debian/Ubuntu/Astra: apt install rpm; RHEL-like/RED OS: dnf install rpm"
fi
if [ "$do_build" -eq 1 ]; then
  need_tool cargo "install Rust through rustup (see docs/en/building-linux.md)"
fi
if [ "${#missing[@]}" -gt 0 ]; then
  echo "package-linux.sh: missing tools:" >&2
  printf '  %s\n' "${missing[@]}" >&2
  echo "Install them, or leave a format out with --formats." >&2
  exit 1
fi

# ── Version and revision ─────────────────────────────────────────────────────

version="$(nrr_workspace_version "$repo_root/Cargo.toml")"
[ -n "$version" ] || die "no version in [workspace.package] of $repo_root/Cargo.toml"
case "$version" in
  [0-9]*) ;;
  *) die "version '$version' does not start with a digit" ;;
esac
case "$version" in
  *[!A-Za-z0-9.+-]*) die "version '$version' has characters a package version cannot carry" ;;
esac
# A pre-release sorts before its release only after a tilde, in dpkg and rpm alike.
package_version="$(printf '%s' "$version" | sed 's/-/~/')"
case "$package_version" in
  *-*) die "version '$version' has more than one '-'" ;;
esac
deb_version="$package_version-$release"

commit="unknown"
commit_date=""
uncommitted=false
if command -v git >/dev/null 2>&1 && git -C "$repo_root" rev-parse --git-dir >/dev/null 2>&1; then
  commit="$(git -C "$repo_root" rev-parse --short=12 HEAD 2>/dev/null || echo unknown)"
  commit_date="$(git -C "$repo_root" log -1 --format=%cI 2>/dev/null || true)"
  if [ -n "$(git -C "$repo_root" status --porcelain --untracked-files=no 2>/dev/null)" ]; then
    uncommitted=true
  fi
  : "${SOURCE_DATE_EPOCH:=$(git -C "$repo_root" log -1 --format=%ct 2>/dev/null || date +%s)}"
fi
: "${SOURCE_DATE_EPOCH:=$(date +%s)}"
export SOURCE_DATE_EPOCH

# ── Contents check ───────────────────────────────────────────────────────────

contents_manifest="$repo_root/packaging/linux/package-contents.txt"

manifest_lines() {
  sed -e 's/\r$//' -e 's/#.*//' -e '/^[[:space:]]*$/d' "$contents_manifest"
}

# Read before the build, so a typo fails in seconds.
[ -f "$contents_manifest" ] || die "missing $contents_manifest"
while read -r set path rest; do
  case "$set" in
    base|service|gui|archive) ;;
    *) die "$contents_manifest: unknown set '$set'" ;;
  esac
  [ -n "$path" ] && [ -z "$rest" ] || die "$contents_manifest: expected '<set> <path>', got '$set $path $rest'"
  rest="${path//@libexec@/}"
  case "${rest//@unitdir@/}" in
    *@*) die "$contents_manifest: unknown token in '$path'" ;;
  esac
done < <(manifest_lines)

# The files of a checkout directory a payload copy takes, relative to it.
payload_files() {
  local rel="$1" list file
  if command -v git >/dev/null 2>&1 && git -C "$repo_root" rev-parse --git-dir >/dev/null 2>&1; then
    list="$(git -C "$repo_root" ls-files -- "$rel")" || return 1
    while IFS= read -r file; do
      if [ -n "$file" ] && [ -f "$repo_root/$file" ]; then
        printf '%s\n' "${file#"$rel"/}"
      fi
    done <<<"$list"
  else
    (cd "$repo_root/$rel" && find . -type f -printf '%P\n')
  fi
}

# The paths a package of the sets $2... must hold; $1 is its unit directory.
expected_paths() {
  local unit_dir="$1" set listed path name size lines
  shift
  lines="$(manifest_lines)" || return 1
  for set in "$@"; do
    case "$set" in
      base)
        printf '%s\n' "$libexec/$NRR_SERVICE_EXE_NAME"
        for name in "${NRR_CONSOLE_EXE_NAMES[@]}"; do
          printf '%s\n' "$libexec/$name" "$NRR_COMMAND_LINK_DIR/$name"
        done
        name="$(payload_files locales)" || return 1
        printf '%s\n' "$name" | sed -e '/^$/d' -e "s|^|$libexec/locales/|"
        name="$(payload_files presets)" || return 1
        printf '%s\n' "$name" | sed -e '/^$/d' -e "s|^|$libexec/presets/|"
        ;;
      service)
        printf '%s\n' "$unit_dir/$NRR_UNIT_NAME" "$libexec/$NRR_SERVICE_ALIAS_NAME" \
          "$NRR_LOGROTATE_CONFIG" "$NRR_POLKIT_POLICY"
        ;;
      gui)
        for name in "$NRR_DESKTOP_GUI_ID" "$NRR_DESKTOP_TRAY_ID"; do
          printf '%s\n' "$libexec/$name" "$NRR_COMMAND_LINK_DIR/$name" "/usr/share/applications/$name.desktop"
        done
        for size in "${NRR_DESKTOP_ICON_SIZES[@]}"; do
          printf '%s\n' "/usr/share/icons/hicolor/${size}x${size}/apps/$NRR_DESKTOP_ICON_NAME.png"
        done
        name="$(payload_files apps/desktop/qml)" || return 1
        printf '%s\n' "$name" | sed -e '/^$/d' -e "s|^|$libexec/apps/desktop/qml/|"
        ;;
    esac
    while read -r listed path; do
      [ "$listed" = "$set" ] || continue
      path="${path//@libexec@/$libexec}"
      printf '%s\n' "${path//@unitdir@/$unit_dir}"
    done <<<"$lines"
  done
}

# Fails when the listing $2 (one path per line) lacks a path of $3.
require_contents() {
  local artifact="$1" missing
  missing="$(printf '%s\n' "$3" | LC_ALL=C sort -u |
    LC_ALL=C comm -23 - <(printf '%s\n' "$2" | LC_ALL=C sort -u))"
  [ -z "$missing" ] ||
    die "$artifact lacks files packaging/linux/package-contents.txt requires:
$missing"
  nrr_gray "    $artifact: contents checked"
}

# A .deb or .rpm of package $2 holding the sets $4...; $3 is its unit directory.
check_package() {
  local file="$1" package="$2" unit_dir="$3" listing expected
  shift 3
  case "$file" in
    *.deb) listing="$(dpkg-deb --fsys-tarfile "$file" | tar -tf - | sed -e 's|^\./|/|' -e 's|/$||')" ;;
    *.rpm) listing="$(rpm -qlp "$file")" ;;
  esac || die "could not list the files of $file"
  expected="$(expected_paths "$unit_dir" "$@")" || die "could not work out what $file must hold"
  require_contents "$(basename "$file")" "$listing" "$expected
/usr/share/doc/$package/copyright"
}

# An archive whose top folder is $2, holding the sets $3... under root/.
check_tarball() {
  local file="$1" stem="$2" listing top expected
  shift 2
  listing="$(tar -tzf "$file" | sed -e "s|^$stem/||" -e 's|/$||')" || die "could not list the files of $file"
  top="$(expected_paths "" archive)" || die "could not work out what $file must hold"
  expected="$(expected_paths "" "$@")" || die "could not work out what $file must hold"
  require_contents "$(basename "$file")" "$listing" "$top
$(printf '%s\n' "$expected" | sed 's|^|root|')"
}

# ── Build ────────────────────────────────────────────────────────────────────

bash "$script_dir/clean-sync-duplicates.sh"

if [ "$do_build" -eq 1 ]; then
  cargo_args=(build --release --locked -p nrr-linux-service -p nrr-cli -p nrr-tui)
  if [ "$headless" -eq 0 ]; then
    cargo_args+=(-p nrr-launcher -p nrr-qt-host)
  fi
  if [ -n "$rust_target" ]; then
    cargo_args+=(--target "$rust_target")
  fi
  nrr_cyan "==> cargo ${cargo_args[*]}"
  if [ "$headless" -eq 1 ]; then
    (cd "$repo_root" && NRR_SKIP_QT_HOST=1 cargo "${cargo_args[@]}")
  else
    (cd "$repo_root" && cargo "${cargo_args[@]}")
  fi
fi

target_root="$(nrr_target_root "$repo_root")"
bin_dir="$target_root"
if [ -n "$rust_target" ]; then
  bin_dir="$bin_dir/$rust_target"
fi
bin_dir="$bin_dir/release"

require_binary() {
  [ -x "$1" ] || die "$1 is missing. Build it with --build, or: cargo build --release $2"
}
service_bin="$bin_dir/$NRR_SERVICE_EXE_NAME"
require_binary "$service_bin" "-p nrr-linux-service"
for name in "${NRR_CONSOLE_EXE_NAMES[@]}"; do
  require_binary "$bin_dir/$name" "-p nrr-cli -p nrr-tui"
done
base_elves=("$service_bin")
for name in "${NRR_CONSOLE_EXE_NAMES[@]}"; do
  base_elves+=("$bin_dir/$name")
done

gui_elves=()
native_host=""
qt_version=""
if [ "$headless" -eq 0 ]; then
  for name in "$NRR_DESKTOP_GUI_CARGO_NAME" "$NRR_DESKTOP_TRAY_CARGO_NAME"; do
    [ -x "$bin_dir/$name" ] ||
      die "$bin_dir/$name is missing. Build with --build (needs Qt 6.6+), or package without the GUI: --headless"
  done
  # The newest host cargo built for this profile, as package-windows.ps1 picks it.
  native_host="$(find "$bin_dir/build" -path '*/qt-native-host-build/*' -name nrr_qt_native_host -type f \
    -printf '%T@ %p\n' 2>/dev/null | sort -n | tail -n 1 | cut -d' ' -f2- || true)"
  [ -n "$native_host" ] ||
    die "nrr_qt_native_host was not built under $bin_dir/build (was NRR_SKIP_QT_HOST set?). Build with --build, or pass --headless"
  gui_elves=("$bin_dir/$NRR_DESKTOP_GUI_CARGO_NAME" "$bin_dir/$NRR_DESKTOP_TRAY_CARGO_NAME" "$native_host")
  host_build_dir="${native_host%/qt-native-host-build/*}/qt-native-host-build"
  qt_dir="$(sed -n 's/^Qt6_DIR:PATH=//p' "$host_build_dir/CMakeCache.txt" 2>/dev/null | head -n 1 || true)"
  if [ -n "$qt_dir" ] && [ -f "$qt_dir/Qt6ConfigVersion.cmake" ]; then
    qt_version="$(sed -n 's/^set(PACKAGE_VERSION "\([^"]*\)").*/\1/p' "$qt_dir/Qt6ConfigVersion.cmake" | head -n 1)"
  fi
fi

# A run path makes the loader take libraries from the build machine's
# directories, which on the installed machine may be anyone's.
for elf in "${base_elves[@]}" ${gui_elves[@]+"${gui_elves[@]}"}; do
  if readelf -W -d "$elf" 2>/dev/null | grep -Eq '\((RPATH|RUNPATH)\)'; then
    die "$elf carries an RPATH/RUNPATH (a private Qt kit?). Packages link the distribution's libraries: build against its Qt 6 packages."
  fi
done

# The newest glibc symbol version the binaries need: the oldest glibc they run on.
glibc_floor() {
  { readelf -W --version-info "$@" 2>/dev/null || true; } |
    grep -o 'GLIBC_[0-9][0-9.]*' | sed 's/^GLIBC_//' | sort -u -V | tail -n 1 || true
}
glibc_base="$(glibc_floor "${base_elves[@]}")"
glibc_gui=""
if [ "$headless" -eq 0 ]; then
  glibc_gui="$(glibc_floor "${gui_elves[@]}")"
fi
# Asserted, not only measured: a binary needing a newer glibc than promised
# installs on the old systems and then fails to start.
if [ -n "$max_glibc" ]; then
  [ -n "$glibc_base" ] ||
    die "could not measure the glibc the service, nrr-cli and nrr-tui need (readelf found no GLIBC_ versions), so --max-glibc $max_glibc cannot be checked"
  if [ "$(printf '%s\n%s\n' "$max_glibc" "$glibc_base" | sort -V | tail -n 1)" != "$max_glibc" ]; then
    die "the service, nrr-cli and nrr-tui need glibc $glibc_base, newer than the allowed $max_glibc: build them on a system whose glibc is $max_glibc or older"
  fi
fi

# ── Output ───────────────────────────────────────────────────────────────────

out_dir="${out_dir:-$target_root/packages}"
mkdir -p "$out_dir"
out_dir="$(cd "$out_dir" && pwd)"
work="$(mktemp -d "$out_dir/.work.XXXXXX")"
trap 'rm -rf -- "$work"' EXIT
artifacts=()

base_name="$NRR_PRODUCT_NAME_UNIX"
gui_name="$NRR_PRODUCT_NAME_UNIX-gui"
libexec="$NRR_SERVICE_INSTALL_DIR"

nrr_cyan "==> $NRR_PRODUCT_NAME $version ($deb_version), $arch, revision $commit$([ "$uncommitted" = true ] && echo ' + uncommitted changes')"
nrr_gray "    binaries: $bin_dir"
nrr_gray "    glibc: $glibc_base or newer$([ -n "$glibc_gui" ] && echo " (GUI: $glibc_gui)")"
[ -z "$qt_version" ] || nrr_gray "    Qt the GUI was built with: $qt_version"

# ── Staging ──────────────────────────────────────────────────────────────────

# Payload files exactly as the checkout tracks them, so nothing stray in the
# working tree ships. Without git, the directory as it is.
copy_payload() {
  local rel="$1" dest="$2" file
  if command -v git >/dev/null 2>&1 && git -C "$repo_root" rev-parse --git-dir >/dev/null 2>&1; then
    while IFS= read -r -d '' file; do
      [ -f "$repo_root/$file" ] || continue
      install -D -m 0644 -T "$repo_root/$file" "$dest/${file#"$rel"/}"
    done < <(git -C "$repo_root" ls-files -z -- "$rel")
  else
    mkdir -p "$dest"
    cp -R -- "$repo_root/$rel/." "$dest/"
  fi
}

# Modes as a package must carry them, whatever the umask was.
normalize_modes() {
  find "$1" -type d -exec chmod 0755 {} +
  find "$1" -type f -perm -u+x -exec chmod 0755 {} +
  find "$1" -type f ! -perm -u+x -exec chmod 0644 {} +
}

write_build_info() {
  cat >"$1" <<EOF
{
  "product": "$NRR_PRODUCT_NAME",
  "version": "$version",
  "commit": "$commit",
  "commit_date": "$commit_date",
  "uncommitted": $uncommitted,
  "built_at_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "profile": "release",
  "platform": "linux-$arch",
  "glibc_min": "$glibc_base",
  "qt_version": "$qt_version"
}
EOF
}

# The service, the console, the terminal interface, and what they read beside
# themselves. Shared by the netrulerouter package and both archives.
stage_base() {
  local root="$1" name
  install -d -m 0755 "$root$libexec" "$root$NRR_COMMAND_LINK_DIR"
  install -m 0755 "$service_bin" "$root$libexec/$NRR_SERVICE_EXE_NAME"
  for name in "${NRR_CONSOLE_EXE_NAMES[@]}"; do
    install -m 0755 "$bin_dir/$name" "$root$libexec/$name"
    # A link, so /proc/<pid>/exe names the real file and the program finds its
    # locales beside it.
    ln -s "$libexec/$name" "$root$NRR_COMMAND_LINK_DIR/$name"
  done
  copy_payload locales "$root$libexec/locales"
  copy_payload presets "$root$libexec/presets"
  # Recovery for a machine the service left without network.
  install -D -m 0755 -T "$script_dir/reset-network.sh" "$root$libexec/scripts/reset-network.sh"
  install -D -m 0644 -T "$script_dir/lib/service-paths.sh" "$root$libexec/scripts/lib/service-paths.sh"
  write_build_info "$root$libexec/build-info.json"
}

# The window and the tray under their Unix names (BinaryRole::unix_file_name):
# the service tells its clients apart by the executable name, and a copy keeps
# that name in /proc/<pid>/exe where a symlink would not.
stage_gui() {
  local root="$1" size icon
  install -d -m 0755 "$root$libexec" "$root$NRR_COMMAND_LINK_DIR"
  install -m 0755 "$bin_dir/$NRR_DESKTOP_GUI_CARGO_NAME" "$root$libexec/$NRR_DESKTOP_GUI_ID"
  install -m 0755 "$bin_dir/$NRR_DESKTOP_TRAY_CARGO_NAME" "$root$libexec/$NRR_DESKTOP_TRAY_ID"
  install -m 0755 "$native_host" "$root$libexec/nrr_qt_native_host"
  ln -s "$libexec/$NRR_DESKTOP_GUI_ID" "$root$NRR_COMMAND_LINK_DIR/$NRR_DESKTOP_GUI_ID"
  ln -s "$libexec/$NRR_DESKTOP_TRAY_ID" "$root$NRR_COMMAND_LINK_DIR/$NRR_DESKTOP_TRAY_ID"
  # The QML addresses its icons three levels up from itself, so it keeps the
  # checkout's depth, as in the Windows package.
  copy_payload apps/desktop/qml "$root$libexec/apps/desktop/qml"
  copy_payload assets/icons "$root$libexec/assets/icons"
  copy_payload assets/images "$root$libexec/assets/images"
  copy_payload configs "$root$libexec/configs"
  # The entries name the commands in /usr/bin as they are; only a build-tree
  # install rewrites Exec=.
  install -D -m 0644 -T "$repo_root/packaging/linux/$NRR_DESKTOP_GUI_ID.desktop" \
    "$root/usr/share/applications/$NRR_DESKTOP_GUI_ID.desktop"
  install -D -m 0644 -T "$repo_root/packaging/linux/$NRR_DESKTOP_TRAY_ID.desktop" \
    "$root/usr/share/applications/$NRR_DESKTOP_TRAY_ID.desktop"
  for size in "${NRR_DESKTOP_ICON_SIZES[@]}"; do
    icon="$repo_root/assets/icons/app/icon-$size.png"
    [ -f "$icon" ] || die "missing icon $icon"
    install -D -m 0644 -T "$icon" "$root/usr/share/icons/hicolor/${size}x${size}/apps/$NRR_DESKTOP_ICON_NAME.png"
  done
  install -D -m 0644 -T "$repo_root/assets/icons/app/icon.svg" \
    "$root/usr/share/icons/hicolor/scalable/apps/$NRR_DESKTOP_ICON_NAME.svg"
}

# What only a package carries: the unit and its companions, rendered by the
# daemon itself so they cannot differ from what `install` writes, and the
# licence where the distribution looks for it.
add_package_footprint() {
  local root="$1" package="$2" with_service="$3"
  install -D -m 0644 -T "$repo_root/LICENSE" "$root/usr/share/doc/$package/copyright"
  [ "$with_service" -eq 1 ] || return 0
  "$service_bin" package-files "$root" >/dev/null ||
    die "$service_bin package-files failed (for another architecture this machine must be able to run it)"
  local unit="$root${NRR_PACKAGE_UNIT_FILES[0]}"
  [ -f "$unit" ] || die "the daemon did not write $unit: lib/service-paths.sh and systemd.rs disagree"
  grep -q "^ExecStart=\"$NRR_STAGED_SERVICE_BINARY\" run\$" "$unit" ||
    die "$unit does not start $NRR_STAGED_SERVICE_BINARY: lib/service-paths.sh and systemd.rs disagree"
}

base_root="$work/base"
stage_base "$base_root"
normalize_modes "$base_root"
staged_roots=("$base_root")
gui_root=""
if [ "$headless" -eq 0 ]; then
  gui_root="$work/gui"
  stage_gui "$gui_root"
  normalize_modes "$gui_root"
  staged_roots+=("$gui_root")
fi

# rpm reads %files as globs and macros; keep every name plain.
for root in "${staged_roots[@]}"; do
  bad="$(cd "$root" && find . -mindepth 1 | grep -v '^[A-Za-z0-9._/+@,-]*$' || true)"
  [ -z "$bad" ] || die "file names a package cannot list safely: $bad"
done

base_pkg_root="$work/pkg-base"
cp -a "$base_root" "$base_pkg_root"
add_package_footprint "$base_pkg_root" "$base_name" 1
normalize_modes "$base_pkg_root"
gui_pkg_root=""
if [ "$headless" -eq 0 ]; then
  gui_pkg_root="$work/pkg-gui"
  cp -a "$gui_root" "$gui_pkg_root"
  add_package_footprint "$gui_pkg_root" "$gui_name" 0
  normalize_modes "$gui_pkg_root"
fi

# ── Maintainer scripts ───────────────────────────────────────────────────────

# The values a maintainer script needs, written in rather than sourced: postrm
# runs after the package files, lib/service-paths.sh among them, are gone.
maintainer_prelude() {
  local var value
  for var in NRR_PRODUCT_NAME NRR_PRODUCT_NAME_UNIX NRR_UNIT_NAME NRR_SERVICE_INSTALL_DIR \
    NRR_STAGED_SERVICE_BINARY NRR_UNIT_FILE NRR_LOGROTATE_CONFIG NRR_POLKIT_POLICY \
    NRR_STATE_DIR NRR_AUDIT_DIR NRR_LOG_DIR NRR_RUNTIME_DIR NRR_NFT_FAMILY NRR_NFT_TABLE; do
    value="${!var}"
    case "$value" in
      ''|*\'*) die "$var is empty or holds a quote" ;;
    esac
    printf "%s='%s'\n" "$var" "$value"
  done
  printf "NRR_PKG_FIRST_INSTALL_FLAG='/run/%s-package-first-install'\n" "$NRR_PRODUCT_NAME_UNIX"
  echo
  cat "$repo_root/packaging/linux/maintainer/functions.sh"
  echo
}

summary_base="Routes traffic across the network interfaces you already have"
summary_gui="Window and tray icon for NetRuleRouter"
description_base="NetRuleRouter decides which of the network connections a machine already
has - the main one, a VPN, a second uplink - carries which traffic, by rules
you write. It is not a VPN client and not a proxy.
This package holds the background service, the nrr-cli console and the
nrr-tui terminal interface. Add netrulerouter-gui for the window and the tray."
description_gui="The graphical interface and the tray icon of NetRuleRouter. Requires Qt 6.6
or newer from the distribution."

# ── .deb ─────────────────────────────────────────────────────────────────────

# Library dependencies as dpkg knows them (libc6 among them, which carries the
# glibc floor). dpkg-shlibdeps insists on a debian/control in its directory.
deb_shlibs() {
  local dir="$work/shlibdeps" output
  mkdir -p "$dir/debian"
  printf 'Source: %s\n\nPackage: %s\nArchitecture: any\n' "$base_name" "$base_name" >"$dir/debian/control"
  local args=()
  local elf
  for elf in "$@"; do
    args+=("-e$elf")
  done
  if ! output="$(cd "$dir" && dpkg-shlibdeps -O "${args[@]}" 2>"$dir/stderr")"; then
    cat "$dir/stderr" >&2
    die "dpkg-shlibdeps could not resolve the libraries (a library no package of this system provides?)"
  fi
  printf '%s\n' "${output#shlibs:Depends=}"
}

# A control-file description: the summary line, then each line indented.
deb_description() {
  printf 'Description: %s\n' "$1"
  printf '%s\n' "$2" | sed 's/^/ /'
}

# Where this machine's systemd takes packaged units. Before merged /usr
# (Debian 10, Astra 1.7) that is /lib/systemd/system, and a unit shipped under
# /usr/lib leaves dpkg a directory no package owns.
deb_unit_dir() {
  local dir
  dir="$(pkg-config --variable=systemdsystemunitdir systemd 2>/dev/null || true)"
  if [ -z "$dir" ]; then
    if [ -L /lib ]; then dir=/usr/lib/systemd/system; else dir=/lib/systemd/system; fi
  fi
  printf '%s\n' "$dir"
}

build_deb() {
  local package="$1" pkg_root="$2" depends="$3" recommends="$4" summary="$5" description="$6"
  local root="$work/deb-$package" hook file unit_dir
  cp -a "$pkg_root" "$root"
  unit_dir="$(deb_unit_dir)"
  if [ "$unit_dir" != /usr/lib/systemd/system ] && [ -d "$root/usr/lib/systemd/system" ]; then
    install -d -m 0755 "$root$unit_dir"
    mv "$root/usr/lib/systemd/system/"* "$root$unit_dir/"
    rm -r "$root/usr/lib/systemd"
    rmdir "$root/usr/lib" 2>/dev/null || true
  fi
  install -d -m 0755 "$root/DEBIAN"
  local size
  size="$(du -sk "$pkg_root" | cut -f1)"
  {
    printf 'Package: %s\n' "$package"
    printf 'Version: %s\n' "$deb_version"
    printf 'Architecture: %s\n' "$deb_arch"
    printf 'Maintainer: %s\n' "$maintainer"
    printf 'Installed-Size: %s\n' "$size"
    printf 'Depends: %s\n' "$depends"
    [ -z "$recommends" ] || printf 'Recommends: %s\n' "$recommends"
    printf 'Section: net\n'
    printf 'Priority: optional\n'
    deb_description "$summary" "$description"
  } >"$root/DEBIAN/control"
  if [ -f "$root$NRR_LOGROTATE_CONFIG" ]; then
    printf '%s\n' "$NRR_LOGROTATE_CONFIG" >"$root/DEBIAN/conffiles"
  fi
  if [ "$package" = "$base_name" ]; then
    for hook in preinst postinst prerm postrm; do
      {
        printf '#!/bin/sh\nset -e\n\n'
        maintainer_prelude
        cat "$repo_root/packaging/linux/maintainer/deb/$hook.in"
      } >"$root/DEBIAN/$hook"
      chmod 0755 "$root/DEBIAN/$hook"
    done
  fi
  (cd "$root" && find . -type f ! -path './DEBIAN/*' -printf '%P\0' | sort -z | xargs -0 -r md5sum) \
    >"$root/DEBIAN/md5sums"
  chmod 0644 "$root/DEBIAN/control" "$root/DEBIAN/md5sums"
  [ ! -f "$root/DEBIAN/conffiles" ] || chmod 0644 "$root/DEBIAN/conffiles"
  file="$out_dir/${package}_${deb_version}_${deb_arch}.deb"
  # xz, not the zstd newer dpkg defaults to: older dpkg (Debian 11, Astra)
  # cannot read zstd members.
  dpkg-deb --root-owner-group -Zxz --build "$root" "$file" >/dev/null
  artifacts+=("$(basename "$file")")
  nrr_green "    $(basename "$file")"
  if [ "$package" = "$base_name" ]; then
    check_package "$file" "$package" "$unit_dir" base service
  else
    check_package "$file" "$package" "$unit_dir" gui
  fi
}

if [ "$want_deb" -eq 1 ]; then
  nrr_cyan "==> .deb"
  # nftables 0.9.6 is the oldest release the service's rule set was checked on.
  depends="$(deb_shlibs "${base_elves[@]}"), nftables (>= 0.9.6), iproute2, systemd"
  build_deb "$base_name" "$base_pkg_root" "$depends" "polkitd | policykit-1, logrotate" \
    "$summary_base" "$description_base"
  if [ "$headless" -eq 0 ]; then
    # The QML modules the interface imports, each at the Qt floor the host is
    # built against: an older Qt is refused by the package manager by name.
    qt_floor="6.6"
    qt_modules=""
    for module in qml6-module-qtquick qml6-module-qtquick-controls qml6-module-qtquick-templates \
      qml6-module-qtquick-layouts qml6-module-qtquick-window qml6-module-qtquick-dialogs \
      qml6-module-qt-labs-platform qml6-module-qtqml-workerscript qt6-qpa-plugins; do
      qt_modules="$qt_modules, $module (>= $qt_floor)"
    done
    depends="$base_name (= $deb_version), $(deb_shlibs "${gui_elves[@]}")$qt_modules"
    depends="$depends, polkitd | policykit-1, pkexec | policykit-1"
    build_deb "$gui_name" "$gui_pkg_root" "$depends" "qt6-wayland" "$summary_gui" "$description_gui"
  fi
fi

# ── .rpm ─────────────────────────────────────────────────────────────────────

# %files for a staged root. A package owns the directories it creates inside
# the install directory (the directory itself only for netrulerouter) and its
# doc directory; the shared system directories belong to the distribution.
rpm_files() {
  local root="$1" package="$2" kind path
  echo '%defattr(-,root,root,-)'
  while IFS=' ' read -r kind path; do
    path="/$path"
    case "$kind" in
      d)
        case "$path" in
          "$libexec")
            if [ "$package" = "$base_name" ]; then
              printf '%%dir "%s"\n' "$path"
            fi
            ;;
          "$libexec"/* | "/usr/share/doc/$package")
            printf '%%dir "%s"\n' "$path"
            ;;
        esac
        ;;
      f)
        if [ "$path" = "$NRR_LOGROTATE_CONFIG" ]; then
          printf '%%config(noreplace) "%s"\n' "$path"
        else
          printf '"%s"\n' "$path"
        fi
        ;;
      l) printf '"%s"\n' "$path" ;;
    esac
  done < <(cd "$root" && find . -mindepth 1 -printf '%y %P\n' | sort -k2)
}

# A scriptlet body in a spec: the prelude, then the hook; `%` is a macro there.
rpm_scriptlet() {
  printf '%s\n' "$1"
  { maintainer_prelude; printf '%s\n' "$2"; } | sed 's/%/%%/g'
  printf 'exit 0\n\n'
}

build_rpm() {
  local package="$1" pkg_root="$2" summary="$3" description="$4"
  shift 4
  local spec="$work/$package.spec" topdir="$work/rpmbuild-$package" dependency
  mkdir -p "$topdir/tmp"
  {
    # No debuginfo split and no build-id links: both packages would carry
    # links for the same binaries. xz, which every supported rpm reads.
    echo '%global debug_package %{nil}'
    echo '%global _build_id_links none'
    echo '%global _binary_payload w9.xzdio'
    echo "Name: $package"
    echo "Version: $package_version"
    echo "Release: $release"
    echo "Summary: $summary"
    echo "License: MPL-2.0"
    echo "Packager: $maintainer"
    for dependency in "$@"; do
      echo "$dependency"
    done
    echo
    echo '%description'
    printf '%s\n\n' "$description"
    echo '%install'
    echo 'mkdir -p %{buildroot}'
    printf 'cp -a "%s/." %%{buildroot}/\n\n' "$pkg_root"
    if [ "$package" = "$base_name" ]; then
      rpm_scriptlet '%pre' 'if [ "$1" -eq 1 ]; then
  nrr_pkg_take_over_hand_install
fi'
      # An upgrade restarts here, on the new files; the old package's %preun
      # and %postun then see $1 = 1 and leave the service alone.
      rpm_scriptlet '%post' 'if [ "$1" -eq 1 ]; then
  nrr_pkg_enable_and_start
else
  nrr_pkg_restart_if_running
fi'
      rpm_scriptlet '%preun' 'if [ "$1" -eq 0 ]; then
  nrr_pkg_stop_and_reset_network
fi'
      rpm_scriptlet '%postun' 'if [ "$1" -eq 0 ] && nrr_pkg_have_systemd; then
  systemctl daemon-reload || true
  systemctl reset-failed "$NRR_UNIT_NAME" >/dev/null 2>&1 || true
fi'
    fi
    echo '%files'
    rpm_files "$pkg_root" "$package"
  } >"$spec"
  rpmbuild -bb --quiet --target "$rpm_arch" \
    --define "_topdir $topdir" \
    --define "_tmppath $topdir/tmp" \
    --define "_rpmdir $out_dir" \
    --define '_build_name_fmt %%{NAME}-%%{VERSION}-%%{RELEASE}.%%{ARCH}.rpm' \
    "$spec" >/dev/null
  local file="$package-$package_version-$release.$rpm_arch.rpm"
  [ -f "$out_dir/$file" ] || die "rpmbuild did not produce $out_dir/$file"
  artifacts+=("$file")
  nrr_green "    $file"
  if [ "$package" = "$base_name" ]; then
    check_package "$out_dir/$file" "$package" "${NRR_PACKAGE_UNIT_FILES[0]%/*}" base service
  else
    check_package "$out_dir/$file" "$package" "${NRR_PACKAGE_UNIT_FILES[0]%/*}" gui
  fi
}

if [ "$want_rpm" -eq 1 ]; then
  nrr_cyan "==> .rpm"
  # Library requirements, glibc's among them, are generated by rpmbuild from
  # the binaries. RHEL-family names; other rpm families are not verified.
  build_rpm "$base_name" "$base_pkg_root" "$summary_base" "$description_base" \
    "Requires: nftables >= 0.9.6" \
    "Requires: iproute" \
    "Requires: systemd" \
    "Requires(post): systemd" \
    "Requires(preun): systemd" \
    "Requires(postun): systemd" \
    "Recommends: polkit" \
    "Recommends: logrotate"
  if [ "$headless" -eq 0 ]; then
    # rpm's library requirements carry no Qt version, so the floor is the Qt
    # the host was built with: it may use symbols an older Qt lacks.
    rpm_qt_floor="$(printf '6.6\n%s\n' "$(printf '%s' "$qt_version" | cut -d. -f1,2)" | sort -V | tail -n 1)"
    build_rpm "$gui_name" "$gui_pkg_root" "$summary_gui" "$description_gui" \
      "Requires: $base_name = $package_version-$release" \
      "Requires: qt6-qtbase-gui >= $rpm_qt_floor" \
      "Requires: qt6-qtdeclarative >= $rpm_qt_floor" \
      "Requires: polkit" \
      "Recommends: qt6-qtwayland"
  fi
fi

# ── .tar.gz ──────────────────────────────────────────────────────────────────

write_tarball_readme() {
  local file="$1" flavour="$2" requirements="$3" glibc="$4"
  cat >"$file" <<EOF
$NRR_PRODUCT_NAME $version for Linux ($arch), $flavour
Revision $commit$([ "$uncommitted" = true ] && echo ' (built with uncommitted changes)'). Details: $libexec/build-info.json
once installed; attach that file if you report a problem.

Prefer the .deb or .rpm where your distribution takes one: the package manager
then checks the requirements and handles upgrades. This archive is for the rest.

Install:   sudo ./install.sh
Remove:    sudo $libexec/scripts/uninstall.sh            (keeps the service data)
           sudo $libexec/scripts/uninstall.sh --purge    (erases it; the audit trail stays)

Requires: systemd, nftables 0.9.6 or newer, iproute2, glibc $glibc or newer$requirements.
polkit is recommended: without it only root can make privileged changes.

If the service left this machine without network:
    sudo $libexec/scripts/reset-network.sh
EOF
}

write_tarball_readme_ru() {
  local file="$1" flavour="$2" requirements="$3" glibc="$4"
  cat >"$file" <<EOF
$NRR_PRODUCT_NAME $version для Linux ($arch), $flavour
Ревизия $commit$([ "$uncommitted" = true ] && echo ' (собрано с незакоммиченными правками)'). Подробности после установки:
$libexec/build-info.json; приложите этот файл к сообщению о проблеме.

Где дистрибутив принимает .deb или .rpm, лучше ставить их: тогда требования
проверит менеджер пакетов, и он же будет обновлять. Этот архив - для остальных.

Установка:  sudo ./install.sh
Удаление:   sudo $libexec/scripts/uninstall.sh            (данные службы остаются)
            sudo $libexec/scripts/uninstall.sh --purge    (стирает их; журнал аудита остаётся)

Нужно: systemd, nftables 0.9.6 или новее, iproute2, glibc $glibc или новее$requirements.
Желателен polkit: без него привилегированные изменения доступны только root.

Если служба оставила машину без сети:
    sudo $libexec/scripts/reset-network.sh
EOF
}

build_tarball() {
  local stem="$1" flavour="$2" flavour_ru="$3" requirements="$4" requirements_ru="$5" glibc="$6"
  shift 6
  local top="$work/tar/$stem" root
  mkdir -p "$top"
  root="$top/root"
  mkdir -p "$root"
  for root_part in "$@"; do
    cp -a "$root_part/." "$root/"
  done
  # The archive installs without a package manager, so it carries its own
  # removal, kept with the installed files.
  install -D -m 0755 -T "$repo_root/packaging/linux/tarball/uninstall.sh" "$root$libexec/scripts/uninstall.sh"
  install -D -m 0644 -T "$script_dir/lib/desktop-paths.sh" "$root$libexec/scripts/lib/desktop-paths.sh"
  install -D -m 0644 -T "$repo_root/packaging/linux/maintainer/functions.sh" \
    "$root$libexec/scripts/lib/package-functions.sh"
  install -m 0755 "$repo_root/packaging/linux/tarball/install.sh" "$top/install.sh"
  install -m 0755 "$repo_root/packaging/linux/tarball/uninstall.sh" "$top/uninstall.sh"
  install -D -m 0644 -T "$script_dir/lib/service-paths.sh" "$top/lib/service-paths.sh"
  install -D -m 0644 -T "$script_dir/lib/desktop-paths.sh" "$top/lib/desktop-paths.sh"
  install -D -m 0644 -T "$repo_root/packaging/linux/maintainer/functions.sh" "$top/lib/package-functions.sh"
  install -m 0644 "$repo_root/LICENSE" "$top/LICENSE"
  write_tarball_readme "$top/README.txt" "$flavour" "$requirements" "$glibc"
  write_tarball_readme_ru "$top/README.ru.txt" "$flavour_ru" "$requirements_ru" "$glibc"
  normalize_modes "$top"
  local file="$stem.tar.gz"
  (cd "$work/tar" && tar --sort=name --owner=0 --group=0 --numeric-owner \
    --mtime="@$SOURCE_DATE_EPOCH" -cf - "$stem") | gzip -9n >"$out_dir/$file"
  artifacts+=("$file")
  nrr_green "    $file"
}

if [ "$want_tar" -eq 1 ]; then
  nrr_cyan "==> .tar.gz"
  build_tarball "$NRR_PRODUCT_NAME_UNIX-headless-$version-linux-$arch" \
    "without the GUI (service, nrr-cli, nrr-tui)" "без GUI (служба, nrr-cli, nrr-tui)" \
    "" "" "$glibc_base" "$base_root"
  check_tarball "$out_dir/$NRR_PRODUCT_NAME_UNIX-headless-$version-linux-$arch.tar.gz" \
    "$NRR_PRODUCT_NAME_UNIX-headless-$version-linux-$arch" base
  if [ "$headless" -eq 0 ]; then
    newest_glibc="$(printf '%s\n%s\n' "$glibc_base" "$glibc_gui" | sort -V | tail -n 1)"
    build_tarball "$NRR_PRODUCT_NAME_UNIX-$version-linux-$arch" \
      "full (GUI, tray, service, nrr-cli, nrr-tui)" "полный (GUI, трей, служба, nrr-cli, nrr-tui)" \
      "; for the GUI, Qt 6.6 or newer with Qt Quick Controls, Layouts, Dialogs and Qt.labs.platform" \
      "; для GUI - Qt 6.6 или новее с Qt Quick Controls, Layouts, Dialogs и Qt.labs.platform" \
      "$newest_glibc" "$base_root" "$gui_root"
    check_tarball "$out_dir/$NRR_PRODUCT_NAME_UNIX-$version-linux-$arch.tar.gz" \
      "$NRR_PRODUCT_NAME_UNIX-$version-linux-$arch" base gui
  fi
fi

# ── Checksums ────────────────────────────────────────────────────────────────

(cd "$out_dir" && sha256sum -- "${artifacts[@]}") >"$out_dir/SHA256SUMS"
nrr_green "Packages in $out_dir (checksums in SHA256SUMS)."
