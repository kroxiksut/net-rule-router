# Packaging for Linux

**English** · [Русский](../ru/packaging-linux.md)

`scripts/package-linux.sh` turns a release build into packages that install on
a machine with no Rust toolchain and no repository: `.deb` for Debian, Ubuntu
and Astra Linux, `.rpm` for the Red Hat family (RHEL, AlmaLinux, Rocky, Fedora,
RED OS), and `.tar.gz` archives for everything else. How to build the programs
themselves is on [Building from source (Linux)](building-linux.md).

## What you get

| File | What it holds |
|---|---|
| `netrulerouter_<version>_amd64.deb`, `netrulerouter-<version>.x86_64.rpm` | The service, the `nrr-cli` console and the [`nrr-tui` terminal interface](tui.md) |
| `netrulerouter-gui_<version>_amd64.deb`, `netrulerouter-gui-<version>.x86_64.rpm` | The window and the tray icon, with the menu entry; requires `netrulerouter` of the same version |
| `netrulerouter-<version>-linux-x86_64.tar.gz` | Everything, for systems that take neither package format |
| `netrulerouter-headless-<version>-linux-x86_64.tar.gz` | The same without the window and the tray |
| `netrulerouter-<version>-linux-x86_64-symbols.tar.xz`, `netrulerouter-headless-<version>-linux-x86_64-symbols.tar.xz` | The debug symbols of the matching archive; see [Debug symbols](#debug-symbols) |
| `SHA256SUMS` | Checksums of all of the above |

The names above are those of an x86_64 build. Packages for 64-bit ARM carry
`arm64` (`.deb`) or `aarch64` (`.rpm`, archives) in their place: the script
names them after the machine it runs on, or after `--arch`.

So the **full** installation is `netrulerouter` plus `netrulerouter-gui`, and
the installation **without a GUI** is `netrulerouter` alone. Adding or removing
the window later is installing or removing one package; the service and its
data are not touched.

## Debug symbols

The packages and archives carry no debug symbols, which keeps them small. The
symbols of the same build come as a separate `-symbols.tar.xz` per
architecture (x86_64 and aarch64), attached to each release. You never need
one to install or run the product: it is for reading a crash or stepping
through the program in a debugger.

- It fits only the build it was taken from. Take the one with the same version
  and architecture as the archive or the packages you installed; the
  `netrulerouter-headless-` one matches the service, `nrr-cli` and `nrr-tui`,
  the other one also the window and the tray.
- To use it, unpack it over the system; `gdb` then finds the files under
  `/usr/lib/debug` by itself:

```sh
sudo tar -xJf netrulerouter-<version>-linux-x86_64-symbols.tar.xz --strip-components=1 -C /
gdb /usr/libexec/netrulerouter/nrr-service
```

- To remove them, delete `/usr/lib/debug/usr/libexec/netrulerouter` and the
  `.build-id` files the archive listed.

## Building the packages

The script needs a few tools from your distribution's own repositories:

| Tool | Debian, Ubuntu, Astra | RHEL family, RED OS |
|---|---|---|
| `dpkg-deb`, `dpkg-shlibdeps` (for `.deb`) | `sudo apt install dpkg-dev` | build `.deb` on a Debian-family system |
| `rpmbuild` (for `.rpm`) | `sudo apt install rpm` | `sudo dnf install rpm-build` |
| `readelf` | `sudo apt install binutils` | `sudo dnf install binutils` |

A tool that is missing is named in the error, together with the package that
provides it. `--formats` leaves out a format you cannot or do not want to build.
Rust (`cargo`) is needed even when packaging an existing build: every package
carries these pages as offline HTML, and the script builds them. A page that
links to something that is not there stops the run.

Full set, on a system with Qt 6.6 or newer (Ubuntu 24.10 and later, Debian 13,
Astra 1.8, Fedora):

```bash
./scripts/package-linux.sh --build
```

Without the GUI, which needs no Qt at all — the way to build on Astra Linux 1.7,
RED OS 7.3 or a RHEL 8 relative:

```bash
./scripts/package-linux.sh --headless --build
```

Without `--build` the script packages the release binaries already in the
Cargo target directory. The packages land in `target/packages/`.

| Option | What it does |
|---|---|
| `--build` | Build the release binaries first. |
| `--headless` | Leave out the GUI: no `netrulerouter-gui` and no full archive. Needs no Qt. |
| `--formats deb,rpm,tar` | Build only the listed formats. Default: all three. |
| `--arch x86_64` | Target architecture, `x86_64` or `aarch64`. Default: this machine. |
| `--release N` | Package release number, for a rebuild of the same version. Default: `1`. |
| `--out DIR` | Where the packages go. Default: `target/packages`. |
| `--maintainer "Name <email>"` | The maintainer named in the `.deb` and the packager in the `.rpm`; `NetRuleRouter <fmalkov91@gmail.com>` unless set. Also read from `NRR_PACKAGE_MAINTAINER`. |

### Which machine to build on

A Linux program runs on the C library (glibc) it was built with and on any
newer one, never on an older one. Build on the oldest system you want the
packages to install on:

- the packages without a GUI built on a glibc 2.28 system (Astra Linux 1.7,
  RED OS 7.3, RHEL 8 and its relatives) install on every newer system as well;
- the GUI needs Qt 6.6 or newer, so it is built on a system that has it, and
  installs on systems at least as new.

The script prints the oldest glibc the binaries accept, writes it into
`build-info.json` inside the package, and the package itself declares it, so an
older system refuses the package instead of failing at start.

The GUI has to be built against the distribution's own Qt packages. A build
against a Qt kit unpacked into a home folder is refused: the installed program
would look for its libraries in the build machine's folders.

## Installing

```bash
# Debian, Ubuntu, Astra: full, or the first file alone for no GUI
sudo apt install ./netrulerouter_*.deb ./netrulerouter-gui_*.deb

# RHEL family, RED OS
sudo dnf install ./netrulerouter-*.rpm ./netrulerouter-gui-*.rpm
```

The service starts right away and then with every boot. `nrr-cli`, `nrr-tui`
and, with the GUI, `netrulerouter` are available by name from any shell, and
the application menu has a NetRuleRouter entry. Help > Documentation in the
window, and About in `nrr-tui`, point to these pages installed offline.

If the system's Qt is older than 6.6, the package manager refuses
`netrulerouter-gui` and names the Qt packages it lacks. Then either install a
newer Qt from your distribution (a backports repository or a newer release),
or use NetRuleRouter without the window: `netrulerouter` alone gives you the
service and the [terminal interface](tui.md), which covers the same features
as the window. Likewise, a system with nftables older than 0.9.6 refuses the package.

From an archive:

```bash
tar xzf netrulerouter-<version>-linux-x86_64.tar.gz
cd netrulerouter-<version>-linux-x86_64
sudo ./install.sh
```

The archive puts the files in the same places the packages do. On a system too
old to run what it carries, `install.sh` installs nothing and says what to use
instead: the archive without the window or the `netrulerouter` package alone,
which give you the service and the [terminal interface](tui.md), or a newer
system. Nothing checks its other requirements for you; they are listed in its
`README.txt`. Prefer a package wherever your distribution takes one.

## What each variant requires

| | Without GUI | Full |
|---|---|---|
| systemd | required | required |
| nftables 0.9.6 or newer | required | required |
| iproute2 | required | required |
| glibc | as old as the build machine's | as old as the build machine's |
| polkit | recommended: without it only root makes privileged changes | required |
| Qt 6.6 or newer (Qt Quick, Controls, Layouts, Dialogs, `Qt.labs.platform`) | not needed | required |

Package names follow Debian and Ubuntu for `.deb`, and RHEL and Fedora for
`.rpm`. Distributions that name their packages differently (ALT, openSUSE) may
not resolve the `.rpm` requirements; use the archive there.

## If the window does not start

When a library the window needs is missing or too old, the program says so
instead of failing silently: in the terminal it was started from and, where
`notify-send` is available, as a desktop notification. The message names the
library and the log file, `~/.local/state/netrulerouter/launcher-main.log`. A
system Qt older than 6.6 is reported this way too: update it, or use the
terminal interface `nrr-tui`, which needs no Qt.

## Upgrading

Install the newer packages over the old ones, the same way as above. A running
service moves to the new version straight away; one you stopped or disabled
stays that way. Rules, settings and history are kept.

## Removing

| What you run | Service | Network | Service data | Audit trail |
|---|---|---|---|---|
| `sudo apt remove netrulerouter-gui netrulerouter` | stopped and removed | given back | kept | kept |
| `sudo apt purge netrulerouter-gui netrulerouter` | stopped and removed | given back | erased | kept |
| `sudo dnf remove netrulerouter-gui netrulerouter` | stopped and removed | given back | kept | kept |
| `sudo /usr/libexec/netrulerouter/scripts/uninstall.sh` (archive) | stopped and removed | given back | kept | kept |
| the same with `--purge` | stopped and removed | given back | erased | kept |

"Given back" means the machine's network is left as it was before
NetRuleRouter: its packet filters, its routes and its DNS redirect are removed.

The service data lives in `/var/lib/netrulerouter` and `/var/log/netrulerouter`.
The audit trail in `/var/lib/netrulerouter/audit` is the record of what changed
your routing, and no removal deletes it; remove that folder by hand once you no
longer need it. `rpm` has no counterpart of `apt purge`; after `dnf remove`,
erase the data by hand:

```bash
sudo find /var/lib/netrulerouter -mindepth 1 -maxdepth 1 ! -name audit -exec rm -rf {} +
sudo rm -rf /var/log/netrulerouter
```

What each user keeps in their own home folder (settings, caches) is never
touched by a package; [Where NetRuleRouter keeps its files](where-files-live.md)
lists it.

## The package manager owns the service

On a machine where NetRuleRouter came from a package, the package manager
installs, upgrades and removes the service. `nrr-cli install`, `uninstall` and
`reinstall`, and the install scripts from a checkout, refuse there and say so;
starting and stopping still work through `nrr-cli start` / `nrr-cli stop` or
`systemctl`.

Installing a package on a machine where the service was installed from a
checkout or an archive takes that installation over: the old service is
removed, its data is kept, and the package's service starts in its place.

## If the network is gone

If the service stopped in a way that left the machine without network, give
the network back with:

```bash
sudo nrr-cli reset-network --confirm
```

or, if the console is not available, with
`sudo /usr/libexec/netrulerouter/scripts/reset-network.sh`. See
[Recovering network access](recovering-network-access.md).
