# tappers — provenance of the vendored source

This directory holds the source of the `tappers` crate (TUN, TAP and vETH
interfaces) by Nathaniel Bennett, taken from the NetRuleRouter maintainer's
fork, which carries fixes offered upstream and not yet released there. The
files are copied **unmodified**; nothing here was edited, reformatted or
relicensed. The crate stays under its own licence, MIT or Apache-2.0 at the
user's option (`LICENSE-MIT`, `LICENSE-APACHE`), with its copyright notices
and `authors` field as published.

| Field | Value |
|-------|-------|
| Crate | `tappers` 0.4.3 |
| Author | Nathaniel Bennett |
| Upstream | `https://github.com/pkts-rs/tappers` |
| Upstream base | `1278101e1de395fcd6839e6040d4f49176af39d9` (master, "Merge pull request #63") |
| Fork | `https://github.com/kroxiksut/tappers`, branch `wintun-fixes` |
| Copied commit | `844b0393a9bf060c200242716b5fe8a9c6b9f739` |
| Commit tree | `e49cbf7c7317ab98ca3dde10ad5d3d0221ef127c` (`src/`: `39f1edda38c7a4453bb0f14e400d9c9f09c6ae45`) |
| Upstream pull request | pkts-rs/tappers #64 |
| Copied | 2026-10-20 |
| Licence | MIT OR Apache-2.0 |

## Fork commits on top of upstream

| Commit | Change |
|--------|--------|
| `661fdd3` | Fix fd leaks hidden in `debug_assert_eq!` in release builds |
| `105f313` | Return the `socket()` error from Linux `Tun::exists()` |
| `0a0df8d` | Update `windows-sys` to 0.61 |
| `b731ca8` | Fix Wintun adapters on Windows; load `wintun.dll` safely; add `set_mtu()` |
| `844b039` | Run Windows CI tests without the elevating runner |

## Files kept here

Copied with `git archive` of the commit above, so the bytes are the committed
ones whatever the local checkout does to line endings:

- `Cargo.toml`, `LICENSE-MIT`, `LICENSE-APACHE`, `FAQ.md`, `RELEASE_NOTES.md`
- `src/` in full, including the macOS, BSD and Windows code the product does
  not build

Left out, none of which the crate needs to build:

- `README.md` — its platform table uses emoji glyphs, which this repository's
  Markdown never carries; read it upstream.
- `.cargo/config.toml` — runs the crate's tests under `sudo` or an elevating
  runner, which must never apply to a build here.
- `.github/`, `ci/`, `.gitignore` — upstream's own CI.

## How it is built here

The directory is excluded from the workspace and compiled only as a path
dependency of `nrr-platform-linux`, under `cfg(target_os = "linux")` and with
no features. Its tests are not run by the workspace (they create real
interfaces and need root), and the workspace lints, which deny `unsafe`, do not
apply to it: the crate keeps its own `unsafe` for the system calls it makes.
Windows builds do not link it and keep using `wintun-bindings`.

`core/platform/linux/tests/vendored_tappers.rs` checks on the resolved
dependency graph that the copy reaches no `nrr-*` crate and that only a Linux
build links it.

## How to re-verify

```sh
git clone https://github.com/kroxiksut/tappers && cd tappers
mkdir ../tappers-check
git archive 844b0393a9bf060c200242716b5fe8a9c6b9f739 \
  Cargo.toml LICENSE-APACHE LICENSE-MIT FAQ.md RELEASE_NOTES.md src \
  | tar -x -C ../tappers-check
diff -r ../tappers-check <path-to-NetRuleRouter>/third_party/tappers
```

The only difference must be this `PROVENANCE.md`.

## Leaving the copy

When upstream releases the fixes on crates.io (or the fork is published
there), point `nrr-platform-linux` at that version, delete this directory and
its `exclude` entry in the root `Cargo.toml`, and drop the `tappers` section
from `THIRD_PARTY_LICENSES.md`. To take a newer fork commit instead, repeat the
copy above and update the commit, tree and table in this file.
