# The `nrr-cli` console

**English** · [Русский](../ru/cli.md)

`nrr-cli` is the administrative console that ships with NetRuleRouter. It exists
for one job: keeping the background service healthy — installing it, starting
and stopping it, and telling you what is wrong when something is.

Routing policy is not edited here. Rules, adapters, and applying changes live in
the application window. That is a deliberate boundary, not a missing feature: a
second, unaudited way to change what the machine enforces is exactly what a
security-relevant product should not have.

> Pre-release software. Verbs, flags, and exit codes may still change between
> builds. The **text** this console prints is never a stable interface — do not
> write scripts that parse it. Verbs and exit codes are what you may rely on,
> and only from the beta stage onwards.

## Running it

The console is installed next to the application, and it is **not** added to
your `PATH` automatically — changing the environment of every future shell is
something you should opt into, not something an install does quietly. Either
call it by its path, or register it once (see below).

**In PowerShell, being in the console's folder is not enough.** PowerShell
deliberately does not run programs from the current directory by name, so
`nrr-cli.exe status` fails there with *"is not recognized as the name of a
cmdlet, function, script file, or operable program"* — which reads like the
file is missing even though it is right there. Prefix it with `.\`:

```powershell
.\nrr-cli.exe status
.\nrr-cli.exe diag doctor
```

`cmd.exe` does run programs from the current directory, so there the bare name
works. On Linux and macOS the same rule as PowerShell applies to the shell —
use `./nrr-cli`.

To stop typing a path at all, open **Settings → Command-line console** in the
application and press **Add console to PATH**. It registers the folder for your
user only. Terminals that are already open keep the `PATH` they started with:
open a new one, or paste the one-line command the panel shows you.

Verbs marked *administrator* need an elevated console. The console never
elevates itself: it prints the exact command to repeat and exits with code `3`.
On Windows, open a console as administrator and run the command again; there is
no `--elevate` flag, because an elevated child process on Windows gets its own
window, and the output you were waiting for would disappear with it.

## Verbs

| Verb | What it does | Needs |
|------|--------------|-------|
| `install` | Register the service with the operating system | administrator |
| `uninstall` | Deregister the service | administrator |
| `start` | Start the service | administrator |
| `stop` | Stop the service | administrator |
| `restart` | Stop, then start the service | administrator |
| `status` | Whether the service is installed, running, and how it starts | anyone |
| `diag doctor` | Check this installation and report what is wrong with it | anyone |
| `version` | Print the console version | anyone |
| `help` | List the verbs, rendered from the same table this page documents | anyone |

Flags:

| Flag | Verb | Meaning |
|------|------|---------|
| `--start-mode=<auto\|on-demand>` | `install` | Start with the operating system (default), or when the application is launched |
| `--purge` | `uninstall` | Also delete the service-owned data directory. Your rule files are kept either way |

`status` answers without talking to the running service, because that is the
question people ask precisely when the service is not answering.

`diag doctor` is the command to run before filing a bug. It checks the things
that decide where a problem lives — is the service registered, is it running,
is the registered binary the one shipped next to this console, does this
platform support a background service at all — and prints one report. That
report names paths and service states only: no rules, no host names, no
addresses, so it is safe to attach to an issue.

Not in this build yet: `diag export` (collect the diagnostic archive from the
console; the application already has the button) and `reset-network` (emergency
network recovery; for now use the documented
[recovery procedure](recovering-network-access.md)).

## Exit codes

The exit code is the one part of the output a script may depend on. It is the
same set on every operating system.

| Code | Meaning |
|------|---------|
| `0` | The operation completed |
| `1` | The operation was understood but did not succeed |
| `2` | The command line was not valid |
| `3` | An elevated console is required |
| `4` | The service is not installed |
| `5` | The service is installed but not answering |
| `6` | The operation has no meaning on this platform |
| `7` | Refused because a dangerous command was not confirmed |

`diag doctor` reports warnings without failing: being stopped, or being
installed from another directory, exits `0` with the finding printed. A code
other than `0` from `doctor` means something is actually broken — and it is the
most specific code available, so a script can tell "not installed" (`4`) from
"broken" (`1`) without reading the text.

## What this console will not do

These are decisions, not gaps:

- No rule editing, no applying, no switching routes, no pausing enforcement.
- No machine-readable output mode. Not `--json`, not anything else.
- No config file input, no batch mode, no remote target, no resident watch mode.
- No non-interactive privilege: no tokens or keys as a substitute for the
  operating system's own elevation prompt.

Automation of routing policy is out of scope for this console by design.
Keeping a single machine alive — including recovering it — is not, and never
will be.
