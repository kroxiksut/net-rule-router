# Wintun — provenance of the vendored binaries

This directory holds the **official, unmodified** Wintun release from WireGuard
LLC. Nothing here was built, patched, repacked, or re-signed by the
NetRuleRouter project. The prebuilt-binaries licence permits redistribution only
alongside software that uses the driver through its published API, and forbids
removing proprietary notices — hence `LICENSE.txt` next to the binaries and the
attribution surfaced in the application.

| Field | Value |
|-------|-------|
| Component | Wintun |
| Publisher | WireGuard LLC |
| Version | 0.14.1 |
| Source archive | `https://www.wintun.net/builds/wintun-0.14.1.zip` |
| Archive SHA-256 | `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51` |
| Archive SHA-256 published by upstream | identical (checked at download time) |
| Downloaded | 2026-07-20 |
| Licence | `LICENSE.txt` (Wintun Prebuilt Binaries License) |

## Files kept here

| File | SHA-256 |
|------|---------|
| `bin/amd64/wintun.dll` | `e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce` |
| `bin/arm64/wintun.dll` | `f7ba89005544be9d85231a9e0d5f23b2d15b3311667e2dad0debd344918a3f80` |
| `bin/x86/wintun.dll` | `d694fa46ab4cfebcb2632d094c7aa97278eef2f8052438621766d863ae98a931` |
| `LICENSE.txt` | `183adac21e7d96c508c8fd34d394b7b6708bc81564ad1bad61ab66143a008cd2` |
| `wintun.h` | `510a5984fbf73efd21a61ada60edfe05e1a38a77c8c47f6d62e0ab1cdbdd460f` |

The driver is matched to the architecture of the PROCESS that loads it, not of
the OS: a 32-bit build on 64-bit Windows needs the `x86` DLL. The upstream
archive also contains a 32-bit `arm` build, which is not shipped — that target
is not supported. `wintun.h` is kept for reference; the code calls the driver
through the `wintun-bindings` crate, not the header.

Every DLL above carries a valid Authenticode signature issued to
`CN=WireGuard LLC, O=WireGuard LLC, L=Boulder, S=Colorado, C=US`.

## How to re-verify

```powershell
# 1. Signature and signer
Get-AuthenticodeSignature .\bin\amd64\wintun.dll | Format-List Status, SignerCertificate

# 2. Hash against the table above
Get-FileHash .\bin\amd64\wintun.dll -Algorithm SHA256

# 3. Independently: re-download from wintun.net and compare with the archive hash
```

The same two checks run automatically:

- `cargo test -p nrr-platform-windows fake_ip` asserts the vendored hash still
  matches the value pinned in `nrr_platform_api::third_party::WINTUN_COMPONENT`
  and that the driver loads through the signature-verifying loader.
- At runtime the application re-checks the copy actually in use and reports the
  result to the user (path, hash, signer), so a substituted DLL is visible
  rather than silently trusted.

## Updating to a new upstream release

1. Download the new archive from `https://www.wintun.net/builds/` and compare
   its SHA-256 with the value published on that page.
2. Replace the files here and update every hash in this document.
3. Update `version` and `known_sha256` in
   `core/platform/api/src/third_party.rs`.
4. Run `cargo test -p nrr-platform-windows fake_ip` — the pin-drift test fails
   until step 3 is done, by design.
5. Update `THIRD_PARTY_LICENSES.md` if the licence text changed.
