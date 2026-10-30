# Packaging NetRuleRouter for Windows

**English** · [Русский](../ru/packaging-windows.md)

`scripts/package-windows.ps1` turns a checkout into a folder that runs on a
clean Windows machine: no Qt, no Rust toolchain, no repository, no installer.
Copy the folder to the target machine and start `NetRuleRouter.exe`.

On request the same run also builds two installers from that folder, an EXE
and an MSI. They put the program in Program Files, set up
the background service and remove both cleanly again. See
[Installers](#installers).

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
| `-Arch x64` / `-Arch arm64` | The processor the package is for. Default `x64`. See [ARM64 packages](#arm64-packages). |
| `-QtBin <path>` | Qt `bin` directory of the kit for `-Arch`. By default the kit the Qt host was built with is used; a different kit is refused. |
| `-Full` | Ship the complete Qt runtime instead of the trimmed one. |
| `-Zip` | Also produce `NetRuleRouter-windows-<arch>-<version>-portable.zip` and the symbols archive of the build. |
| `-Installers` | Also build the EXE installer and the MSI, plus a checksum file for everything the run produced. |
| `-NoSymbols` | Skip the symbols archive, for a test build. A release always has it. |
| `-Exe` / `-Msi` | Build only one of the two installers. |
| `-Headless` | Package without the window and the tray: the service, `nrr-cli` and `nrr-tui`, for servers and Windows without a desktop session. The folder is `NetRuleRouter-headless`, and every artifact name carries `-headless` after the version (`...-<version>-headless-portable.zip`). |
| `-Force` | Replace a package folder left by a previous run. |

The script refuses to delete a folder it did not produce: it drops a
`.nrr-package` marker before copying anything, and `-Force` only clears a
directory carrying that marker.

## What ends up in the package

```
NetRuleRouter\
  NetRuleRouter.exe     start here
  README.txt            end-user notes (English)
  README.ru.txt         the same notes in Russian
  build-info.json       version, revision, build time
  <tray, service, console, terminal interface, Qt host, the Qt runtime, wintun.dll>
  qml\                  Qt's own modules
  apps\desktop\qml\     the application's QML
  locales\  presets\  configs\  assets\  scripts\
  licenses\            licence texts: this product, Wintun, and (full package) Qt
  docs\                these pages as offline HTML, docs\<language>\index.html
```

The offline pages are what Help > Documentation opens. Building them stops
the run when a page links to something that is not there.

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
  "version": "0.1.0-alpha.1",
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
printed at the top of both README files. File names carry the version only, so
two local builds of one version share names: `build-info.json` tells them apart.

## Installers

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\package-windows.ps1 -Zip -Installers
```

Everything lands beside the package folder, with the processor (`x64` or
`arm64`) and the version in every name:

| File | What it is |
|---|---|
| `NetRuleRouter-windows-<arch>-<version>-portable.zip` | The portable build (`-Zip`): unpack and run, nothing to install. |
| `NetRuleRouter-windows-<arch>-<version>-setup.exe` | The EXE installer, in English and Russian. |
| `NetRuleRouter-windows-<arch>-<version>.msi` | The MSI, for software-deployment tools and `msiexec`, in English and Russian: it follows the Windows display language. |
| `NetRuleRouter-windows-<arch>-<version>-symbols.zip` | The debug symbols of this build. Not needed to run or install anything; see [Debug symbols](#debug-symbols). |
| `NetRuleRouter-windows-<arch>-<version>-SHA256SUMS.txt` | SHA-256 checksums of every file above, checkable with `sha256sum -c`. |

An installer only starts on the processor it was built for: the `x64` one on
x64 Windows, the `arm64` one on Windows on ARM.

### Debug symbols

The package and both installers carry no debug symbols, which keeps them
about half the size. The symbols of the same build come as a separate
`-symbols.zip`, produced with any archive or installer (a test build may skip
it with `-NoSymbols`) and attached to each
release, for x64 and for ARM64 alike. Users never need it: it is for
developers reading a crash of exactly that build. Symbols from another build
do not fit. The Linux symbols are a separate download as well, see
[Debug symbols](packaging-linux.md#debug-symbols).

What both installers do:

- Before installing, they show the NetRuleRouter end-user agreement in the
  installer's language, to read and accept. The Windows account that accepted
  it there is not asked again when it first starts the application. Every
  other account is asked at its own first launch: accepting it while
  installing does not accept it for the other people using the PC. When the
  EXE installer was approved with another administrator's password, the
  agreement counts as accepted by that administrator, so the person who
  started it is asked at first launch. A later version with a changed
  agreement asks everyone again.
- They ask for administrator rights and install into
  `C:\Program Files\NetRuleRouter` by default. Another folder can be chosen,
  as long as it is inside Program Files: the service runs with system rights,
  so it runs only from a folder ordinary users cannot modify. A folder
  elsewhere is refused with a message saying so.
- The window, the tray, the background service and the console (`nrr-cli`)
  are always installed: removing and repairing the program rely on the
  console. The terminal interface (`nrr-tui`) is ticked by default and can be
  left out.
- The offline documentation (these pages as HTML, opened by Help >
  Documentation without an internet connection) is ticked by default and can
  be left out; the application then opens the pages online.
- They add NetRuleRouter to the Start menu, and on request to the desktop
  (unticked by default). They ask whether these shortcuts and the PATH entry
  below are for every user of the computer (the default) or only for you; the
  program and its service are installed for the whole computer either way.
- On request (unticked by default) they put `nrr-cli` and `nrr-tui` on PATH,
  so they run from any new terminal. Only these two commands are added, not
  the program folder.
- The last page offers to start NetRuleRouter. It starts as you, not with the
  installer's administrator rights.
- Updating or removing the program closes its window, tray and terminal tools
  by itself, in every signed-in account; nothing has to be closed by hand.
- They set up the background service and start it. It starts with Windows;
  when the service was already set to start with the application instead,
  that choice is kept.
- Installing a newer build over an older one stops the service, replaces the
  files and starts it again. Settings, rules and the audit trail are kept.

### Removing an installed copy

Removal always runs as administrator and stops the service first. Both modes
remove the service and put back the network settings it changed (packet
filters, routes, DNS), so the computer is left with the network it had before.

| Mode | Removed | Kept |
|---|---|---|
| Remove the program (the default) | The program and its service | Settings, rules, service data and the audit trail of every user, so installing again picks up where you left off |
| Remove completely | Also the service's data and the settings of the person removing it | The audit trail, rule files you saved in your own folders, and the data of other Windows accounts |
| Remove completely, audit trail included | Also the audit trail | Rule files you saved in your own folders, and the data of other Windows accounts |

Data that other Windows accounts on the PC keep is listed, not deleted: the
uninstaller says so and names the folders, and each account can remove its own
when signed in.

**EXE.** Uninstalling from Settings > Apps asks which mode to use, and, for
complete removal, whether to erase the audit trail too. A silent uninstall
keeps the data unless told otherwise:

```powershell
& "C:\Program Files\NetRuleRouter\unins000.exe" /VERYSILENT                                # keep data
& "C:\Program Files\NetRuleRouter\unins000.exe" /VERYSILENT /REMOVEALLDATA                 # remove completely
& "C:\Program Files\NetRuleRouter\unins000.exe" /VERYSILENT /REMOVEALLDATA /REMOVEAUDIT    # audit trail too
```

**MSI.** Uninstalling from Settings > Apps opens the installer's window:
choose **Remove**, and it asks which mode to use and, for complete removal,
whether to erase the audit trail too. A silent removal, from an administrator
console, keeps the data unless told otherwise:

```powershell
msiexec /x NetRuleRouter-windows-<arch>-<version>.msi /qn                                  # keep data
msiexec /x NetRuleRouter-windows-<arch>-<version>.msi /qn REMOVEALLDATA=1                  # remove completely
msiexec /x NetRuleRouter-windows-<arch>-<version>.msi /qn REMOVEALLDATA=1 REMOVEAUDIT=1    # audit trail too
```

`REMOVEAUDIT=1` only counts together with `REMOVEALLDATA=1`. The MSI names
the folders left in other Windows accounts in its log; add `/l*v <file>` to
keep one.

### What the build machine needs for installers

- **EXE:** [Inno Setup](https://jrsoftware.org/isinfo.php) 6.3 or newer within
  version 6, with `ISCC.exe` on `PATH` or in its default install folder.
- **MSI:** [WiX Toolset](https://wixtoolset.org/) 5.0.2 as a .NET tool, with
  its two extensions:

  ```powershell
  dotnet tool install --global wix --version 5.0.2
  wix extension add -g WixToolset.Util.wixext/5.0.2
  wix extension add -g WixToolset.UI.wixext/5.0.2
  ```

  Other WiX versions are refused: WiX 6 and later come with a maintenance-fee
  licence.

The script checks for these tools before it builds anything, so a missing one
stops the run at once with the command that fixes it.

### Installer logs

Both installers keep a log of every run, installing and removing alike, in the
`%TEMP%` folder of the account that ran them: the EXE as dated `.txt` logs
plus `NetRuleRouter-setup.log` for its service steps, the MSI as
`MSI….LOG` files. Attach the newest ones when an installation or a removal
goes wrong.

While they work, both wizards say which step is running: closing the
program, stopping, registering and starting the service. On the last page the
EXE offers **Show the installation log**, and the MSI names its log file.

A removal started from Settings > Apps writes a dated `Uninstall Log ….txt`
as well. One started by running `unins000.exe` directly leaves no log of
Inno Setup's own; its steps, from the choice made to the end of the removal,
are in `NetRuleRouter-setup.log`. Add `/LOG` to the command to get both.

## Installing the service from the portable folder

The installers do this step for you. From the portable folder, the service is
installed from the application (Settings, Service management) or with
`nrr-cli install`; either asks for administrator approval.

The portable folder can stay where you unpacked it — the desktop, a flash
drive. The service runs under a system account, so it is never started from a
folder ordinary users can change: installing from such a folder copies the
service into `C:\Program Files\NetRuleRouter Service`, a folder only
administrators can change, and runs it from there. Installing again from a
newer portable copy updates that copy; removing the service removes the folder,
and so does uninstalling with the installers. Moving or deleting the portable
folder afterwards does not affect the installed service. See
[Security](../../SECURITY.md), "Installation scope".

## The trimmed Qt runtime

By default the script omits parts of Qt this application never loads: Qt's own
translations, the software OpenGL rasterizer, the legacy Direct3D shader
compiler, the QML debugging plugins, and every Qt Quick Controls style except
the one the application selects (plus `Basic`, the fallback Qt itself uses).
That is roughly 37 MB out of a 134 MB full deployment.

Use `-Full` when a Qt problem is suspected and you want the untouched runtime
to compare against.

## If the window does not start

When part of the installation is missing, for example a Qt library was deleted
or a copy was not finished, `NetRuleRouter.exe` and `NetRuleRouterTray.exe` show
their own message instead of a system error: the installation is incomplete,
reinstall the program. The message names the log file with the details,
`%TEMP%\NetRuleRouter\launcher-main.log` (or `launcher-tray.log` for the tray).

## Requirements on the build machine

- Rust toolchain and `cargo` on `PATH`
- Qt 6 with the desktop kit of the target processor: `msvc2022_64` for x64,
  `msvc2022_arm64` for ARM64 (not needed with `-Headless`)
- For an x64 package, an x64 Windows machine; for an ARM64 one, an ARM64 or an
  x64 machine. Any other pairing stops with an explanation rather than mixing
  in mismatched components
- Visual Studio with the C++ workload — its redistributable DLLs are copied
  into the package. An ARM64 package also needs the ARM64 build tools of that
  workload
- `git`, to stamp the revision. Without it the package still builds and records
  the revision as `unknown`.

## ARM64 packages

`-Arch arm64` builds the package for Windows on ARM: the same folder, the same
installers, with the window and the tray, and with `-Headless` without them.

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\package-windows.ps1 -Arch arm64 -Zip -Installers
```

What the build machine needs on top of the list above:

- The Rust target: `rustup target add aarch64-pc-windows-msvc`.
- `clang.exe`, from LLVM or from the "C++ Clang tools for Windows" component
  of Visual Studio. When it is not on `PATH`, the script looks for it in those
  two places itself.
- Qt's `msvc2022_arm64` kit, which `CMAKE_PREFIX_PATH` names, or the newest one
  under `C:\Qt` when the variable is unset. A `CMAKE_PREFIX_PATH` that names
  another kit is refused before the build starts.

On an ARM64 machine that is all. On an x64 machine the ARM64 kit is a
cross-compiled one: it has no tools of its own, so `QT_HOST_PATH` must name the
x64 kit of the same Qt version as well:

```powershell
$env:CMAKE_PREFIX_PATH = 'C:\Qt\6.8.3\msvc2022_arm64'
$env:QT_HOST_PATH = 'C:\Qt\6.8.3\msvc2022_64'
powershell -ExecutionPolicy Bypass -File .\scripts\package-windows.ps1 -Arch arm64 -Zip -Installers
```

An ARM64 package built on x64 is checked on an ARM64 machine: the build
machine cannot start it.

## Known limitations

- **Windows only.** A Linux counterpart is a different job — a systemd unit, no
  `windeployqt`, no wintun — so it will be written alongside the Linux build
  rather than translated from this script.
- **The binaries and installers are unsigned**, so SmartScreen warns on first
  run.
- **Use one installer per machine.** The EXE and the MSI are separate
  installations of the same program: to switch from one to the other, remove
  the first.
- **The `.msi` file shows the Windows Installer icon** in File Explorer:
  Windows draws it for every MSI, whatever the package carries. Once
  installed, Settings > Apps shows the NetRuleRouter icon.
- **`scripts\` holds only what a user of the package needs:**
  `reset-network.ps1`, `service-status.ps1`, `uninstall-service.ps1` and
  `purge-data.ps1`; an installed copy also carries `setup-actions.ps1`, which
  the installers run. Build, check and development scripts stay in the checkout.
  For everyday checks and network recovery use the console beside the
  application: `nrr-cli status`, `nrr-cli diag doctor`,
  `nrr-cli reset-network --confirm`. See [the console](cli.md).
