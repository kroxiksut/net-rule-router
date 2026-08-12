# Third-party components

[Русский](../ru/third-party-components.md)

NetRuleRouter is built mostly from its own code, but a few pieces come from
other authors. This page lists them, explains why they are there, and shows how
you can check for yourself that the copy on your computer is the genuine one.

You can see the same information inside the application: **Help → Licenses →
Third-party components** (the Licenses window also opens from the About window
and from the tray menu). For every component the app shows the author, the
version, the licence, and — for executable components — where the file is, its
checksum, and who signed it.

## What is shipped, and why

| Component | Author | Licence | Platforms | What it is for |
|-----------|--------|---------|-----------|----------------|
| Wintun | WireGuard LLC | Wintun Prebuilt Binaries License | Windows only | Per-site virtual addresses (fake-IP) |
| Tabler Icons | Tabler | MIT | All | The icons in the interface |

Nothing else is shipped as a separate file. The Rust libraries the application
is built from are compiled into its executables and are covered by permissive
licences; the full list is verified on every build.

### Wintun (Windows only)

The fake-IP feature gives each site its own address inside the application, so
routing and leak protection can be decided per site instead of per IP address.
Doing that requires a network adapter the application can read traffic from.
Linux and macOS provide such an adapter in the operating system itself, so
builds for those systems ship nothing extra. Windows does not, so the Windows
build includes Wintun — the same adapter used by WireGuard and by several
well-known commercial VPN clients.

Practical consequences:

- Wintun is used **only** by the fake-IP feature. If the feature is off, the
  adapter is not created.
- If the component is missing, fake-IP reports itself unavailable and
  **everything else keeps working** — routing, rules, leak protection.
- The file is shipped exactly as its author published it, signed by them. It is
  never modified, rebuilt, or repackaged by this project.

### Tabler Icons

The icons in the interface come from the Tabler set, under the MIT licence,
which asks only that the authors are credited — which is what the Licenses
window does. The application's own logo is not part of that set.

## Checking that a component is genuine

Claiming "this is the original file" in an About box proves nothing, so the
application checks it instead and shows you the result. Open **Help → Licenses →
Third-party components**. For each executable component you will see one of:

| Verdict | What it means |
|---------|---------------|
| Genuine | The file matches the build shipped with the product and carries a valid signature from its author. |
| Does not match | The file is not the build shipped with the product, or its signature could not be confirmed. Reinstall the product. |
| Not installed | The component is absent. The feature that needs it is unavailable; nothing else is affected. |

The check is the same one the application performs before it loads the
component, so the window cannot show a green verdict for a file the application
would refuse to use.

If you would rather verify by hand on Windows, the shown file path and checksum
are all you need:

```powershell
Get-AuthenticodeSignature "<path shown in the window>" | Format-List Status, SignerCertificate
Get-FileHash "<path shown in the window>" -Algorithm SHA256
```

The signature must be `Valid` and issued to WireGuard LLC, and the checksum must
match the one shown in the window. Both can also be compared against the copy
published by the author at <https://www.wintun.net/>.

## Licence texts

The full licence texts are shipped with the product and are also in the
repository:

- [`THIRD_PARTY_LICENSES.md`](../../THIRD_PARTY_LICENSES.md) — the notice that
  travels with every distribution
- [`third_party/wintun/LICENSE.txt`](../../third_party/wintun/LICENSE.txt) —
  Wintun, verbatim
- [`third_party/wintun/PROVENANCE.md`](../../third_party/wintun/PROVENANCE.md) —
  where the files came from, their checksums, and how to re-verify them
- [`assets/icons/THIRD_PARTY.md`](../../assets/icons/THIRD_PARTY.md) — the icon
  set attribution
