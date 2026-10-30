#!/usr/bin/env bash
# Prepare the AUR package netrulerouter-bin for one release and print the
# commands that publish it. Nothing is sent anywhere: the owner runs the
# printed commands by hand (the AUR key never lives in CI).
#
# Usage:
#   ./scripts/aur-update.sh v0.1.0-alpha.1 path/to/SHA256SUMS [--out DIR]
#
# SHA256SUMS is the checksum file of the GitHub release; the lines of the two
# full archives (linux-x86_64 and linux-aarch64) are taken from it.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
template_dir="$repo_root/packaging/linux/aur/netrulerouter-bin"
pkgname=netrulerouter-bin

die() { echo "aur-update: $*" >&2; exit 1; }

[ $# -ge 2 ] || die "usage: $0 <tag> <SHA256SUMS> [--out DIR]"
tag="$1"
sums="$2"
shift 2
out="$repo_root/target/aur/$pkgname"
while [ $# -gt 0 ]; do
  case "$1" in
    --out) [ $# -ge 2 ] || die "--out needs a directory"; out="$2"; shift 2 ;;
    *) die "unknown argument: $1" ;;
  esac
done

case "$tag" in
  v[0-9]*) ;;
  *) die "the tag must look like v0.1.0 or v0.1.0-alpha.1, got '$tag'" ;;
esac
[ -f "$sums" ] || die "no checksum file at $sums"

version="${tag#v}"
# pacman forbids '-' in pkgver; '_' keeps the pre-release part readable.
pkgver="${version//-/_}"

sum_of() {
  local file="netrulerouter-$version-linux-$1.tar.gz" sum
  sum="$(awk -v f="$file" '{ name = $2; sub(/^\*/, "", name) } name == f { print $1 }' "$sums")"
  [ -n "$sum" ] || die "$file is not in $sums"
  printf '%s' "$sum"
}
sha_x86_64="$(sum_of x86_64)"
sha_aarch64="$(sum_of aarch64)"

mkdir -p "$out"
sed -e "s|@TAG@|$tag|" -e "s|@PKGVER@|$pkgver|" \
    -e "s|@SHA256_X86_64@|$sha_x86_64|" -e "s|@SHA256_AARCH64@|$sha_aarch64|" \
    "$template_dir/PKGBUILD.in" >"$out/PKGBUILD"
install -m 0644 "$template_dir/netrulerouter.install" "$out/netrulerouter.install"

# .SRCINFO is what the AUR web reads. Written here so no Arch machine is needed;
# `makepkg --printsrcinfo` on Arch must give the same text.
url="https://github.com/kroxiksut/net-rule-router"
{
  printf 'pkgbase = %s\n' "$pkgname"
  printf '\tpkgdesc = %s\n' "$(sed -n 's/^pkgdesc="\(.*\)"$/\1/p' "$out/PKGBUILD")"
  printf '\tpkgver = %s\n\tpkgrel = 1\n\turl = %s\n' "$pkgver" "$url"
  printf '\tinstall = netrulerouter.install\n'
  printf '\tarch = x86_64\n\tarch = aarch64\n\tlicense = MPL-2.0\n'
  for dep in glibc systemd nftables iproute2 qt6-base qt6-declarative qt6-svg; do
    printf '\tdepends = %s\n' "$dep"
  done
  printf '\toptdepends = polkit: privileged changes without root\n'
  printf '\toptdepends = qt6-wayland: the window and the tray on a Wayland session\n'
  printf '\tprovides = netrulerouter\n\tconflicts = netrulerouter\n'
  printf '\tsource_x86_64 = %s/releases/download/%s/netrulerouter-%s-linux-x86_64.tar.gz\n' "$url" "$tag" "$version"
  printf '\tsha256sums_x86_64 = %s\n' "$sha_x86_64"
  printf '\tsource_aarch64 = %s/releases/download/%s/netrulerouter-%s-linux-aarch64.tar.gz\n' "$url" "$tag" "$version"
  printf '\tsha256sums_aarch64 = %s\n' "$sha_aarch64"
  printf '\npkgname = %s\n' "$pkgname"
} >"$out/.SRCINFO"

cat <<EOF
Ready in $out: PKGBUILD, .SRCINFO, netrulerouter.install ($pkgname $pkgver).

Publish (first time: the clone is empty, that is expected):
    git clone ssh://aur@aur.archlinux.org/$pkgname.git ~/aur-$pkgname
    cp "$out/PKGBUILD" "$out/.SRCINFO" "$out/netrulerouter.install" ~/aur-$pkgname/
    cd ~/aur-$pkgname
    git add PKGBUILD .SRCINFO netrulerouter.install
    git commit -m "Update to $pkgver"
    git push

Check before pushing, on Arch or in an archlinux container:
    makepkg --printsrcinfo | diff - .SRCINFO
    makepkg -si && namcap PKGBUILD ./*.pkg.tar.zst
EOF
