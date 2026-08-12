# Third-party components

NetRuleRouter is distributed under the Mozilla Public License 2.0. It also
includes components owned by third parties, listed here with their publishers
and licences. This notice must be kept with any distribution of the product.

Rust library dependencies are pulled from crates.io at build time under
permissive licences (MIT / Apache-2.0 / BSD / Unicode-3.0 / CDLA-Permissive-2.0);
the authoritative allow-list is enforced by `cargo deny check licenses` against
`deny.toml`. The section below covers components that are **shipped as binaries**
alongside the product, which carry obligations beyond the crate licences.

Both components below are also listed inside the application, in
**Help → Licenses → Third-party components**, together with a live check of the
binary on disk. See
[`docs/en/third-party-components.md`](docs/en/third-party-components.md).

## Tabler Icons (all platforms)

- **Author:** Tabler
- **Licence:** MIT
- **Home page:** <https://tabler.io/icons>
- **Details:** [`assets/icons/THIRD_PARTY.md`](assets/icons/THIRD_PARTY.md)

The interface, status and tray icons come from the Tabler outline set. The MIT
licence requires the copyright notice to travel with the work, which is what
this section and the in-app Licenses window do. The application's own logo is
in-house and is not part of that set.

## Wintun (Windows builds only)

- **Publisher:** WireGuard LLC
- **Version:** 0.14.1
- **Home page:** <https://www.wintun.net/>
- **Licence:** Wintun Prebuilt Binaries License — full text in
  [`third_party/wintun/LICENSE.txt`](third_party/wintun/LICENSE.txt)
- **Provenance and checksums:**
  [`third_party/wintun/PROVENANCE.md`](third_party/wintun/PROVENANCE.md)

Wintun is a layer-3 network adapter driver for Windows. NetRuleRouter ships the
official signed `wintun.dll` unmodified and uses it exclusively through its
published API, which is what its licence permits. The driver is required for the
fake-IP feature; without it that feature reports itself unavailable and the rest
of the product is unaffected.

Windows is the only supported platform that needs it: Linux uses the kernel's
native `/dev/net/tun` and macOS its native `utun`, so builds for those systems
ship no third-party binary at all.

The Rust bindings used to call the driver are the `wintun-bindings` crate (MIT),
which is an ordinary crates.io dependency and not part of this notice's
redistribution obligations.

### Verifying the driver you received

The application reports, for the copy of `wintun.dll` it actually loads, the
file path, its SHA-256, and the Authenticode signer — so the driver's
authenticity can be confirmed on the running system rather than taken on trust.
The manual equivalents are documented in
[`third_party/wintun/PROVENANCE.md`](third_party/wintun/PROVENANCE.md).
