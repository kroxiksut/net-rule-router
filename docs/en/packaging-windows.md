# Packaging a portable build for Windows

`scripts/package-windows.ps1` turns a checkout into a folder that runs on a
clean Windows machine: no Qt, no Rust toolchain, no repository, no installer.
Copy the folder to the target machine and start `NetRuleRouter.exe`.

## Running it

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\package-windows.ps1 -Zip
```

The package lands in `C:\temp\NetRuleRouter\dist\NetRuleRouter`, and `-Zip`
puts an archive of it beside the folder.

| Parameter | What it does |
|---|---|
| `-OutputRoot <path>` | Where the package folder is created. Default `C:\temp\NetRuleRouter\dist`. |
| `-SkipBuild` | Package the release binaries already present instead of building. |
| `-QtBin <path>` | Qt `bin` directory holding `windeployqt.exe`. Autodetected under `C:\Qt` otherwise. |
| `-Full` | Ship the complete Qt runtime instead of the trimmed one. |
| `-Zip` | Also produce `NetRuleRouter-windows-x64-<version>+<commit>.zip`. |
| `-Force` | Replace a package folder left by a previous run. |

The script refuses to delete a folder it did not produce: it drops a
`.nrr-package` marker before copying anything, and `-Force` only clears a
directory carrying that marker.

## What ends up in the package

```
NetRuleRouter\
  NetRuleRouter.exe     start here
  READ-ME.txt           end-user notes, in Russian
  build-info.json       version, revision, build time
  <tray, service, console, Qt host, the Qt runtime, wintun.dll>
  qml\                  Qt's own modules
  apps\desktop\qml\     the application's QML
  locales\  presets\  configs\  assets\  scripts\
```

Two details of that layout are load bearing rather than cosmetic:

- **The application's QML keeps its `apps\desktop\qml` path.** The QML
  addresses its icons relative to itself (`../../../assets/icons/...`), so a
  shallower location leaves every icon unresolved. It also keeps the tree from
  colliding with `qml\`, which Qt owns for its own modules.
- **Binaries sit in the package root.** Windows resolves a DLL from the
  executable's own folder first, which is what lets the Qt runtime and the
  Visual C++ runtime travel with the application.

## What the build stamp is for

Every package carries `build-info.json`:

```json
{
  "product": "NetRuleRouter",
  "version": "0.1.0-prealpha",
  "commit": "19670e8",
  "commit_date": "2026-08-07T22:37:22+08:00",
  "uncommitted": true,
  "built_at_utc": "2026-08-10T14:17:40Z",
  "profile": "release",
  "platform": "windows-x64",
  "qt_version": "6.11.1",
  "qt_runtime": "trimmed"
}
```

`uncommitted` records whether the working tree had local changes when the
package was built. When it is `true`, `commit` alone does not identify this
code — say so in any report about that copy. The same version and revision are
printed at the top of `READ-ME.txt`, and `-Zip` puts them in the archive name
so two builds cannot be mistaken for one another.

## Installing the service on the target machine

The service is installed from the application, which asks for administrator
approval. There is no separate installer.

Before installing it, put the folder somewhere ordinary users cannot write to,
such as `C:\Program Files\NetRuleRouter`. The service runs under a system
account, so whoever can modify files in its directory can replace its
executable and gain those privileges. Running the application from a flash
drive to look at the interface is fine; installing the service from there is
not. See [Security](../../SECURITY.md), "Service Installation Scope".

## The trimmed Qt runtime

By default the script omits parts of Qt this application never loads: Qt's own
translations, the software OpenGL rasterizer, the legacy Direct3D shader
compiler, the QML debugging plugins, and every Qt Quick Controls style except
the one the application selects (plus `Basic`, the fallback Qt itself uses).
That is roughly 37 MB out of a 134 MB full deployment.

Use `-Full` when a Qt problem is suspected and you want the untouched runtime
to compare against.

## Requirements on the build machine

- Rust toolchain and `cargo` on `PATH`
- Qt 6 with an **x64** desktop kit (an arm64 kit cannot run on an x64 host)
- Visual Studio with the C++ workload — its redistributable DLLs are copied
  into the package
- `git`, to stamp the revision. Without it the package still builds and records
  the revision as `unknown`.

## Known limitations

- **Windows only.** A Linux counterpart is a different job — a systemd unit, no
  `windeployqt`, no wintun — so it will be written alongside the Linux build
  rather than translated from this script.
- **The binaries are unsigned**, so SmartScreen warns on first run.
- **Scripts under `scripts\` that expect a build tree** (`install-service.ps1`,
  `build.ps1`, `run.ps1`) do not work from the package. The ones worth having
  there are `reset-network.ps1`, `service-status.ps1` and `service-smoke.ps1`.
