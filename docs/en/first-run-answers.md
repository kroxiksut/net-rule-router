# Answering the setup questions ahead of time

**English** · [Русский](../ru/first-run-answers.md)

The first time NetRuleRouter starts it asks a short set of questions: which
connections to use, how strongly to protect against leaks, and which rule set
to begin with. If those answers are already known — an installer collected
them, or an administrator is preparing several machines alike — they can be
supplied in a file, and the setup window does not appear.

## Where the file goes

Name it `first-run.json`.

**On Windows**, put it next to `NetRuleRouter.exe`, in the folder the program
was installed to — `C:\Program Files\NetRuleRouter` unless another folder was
chosen during installation. The file is used only when that folder can be
changed by administrators alone, as an installed program's folder can; a copy
of the program in a folder any user can write to — a download, a desktop
folder, a USB stick — ignores the file, and the setup window asks as usual.

**On Linux**, put it in either place:

- next to the program (`netrulerouter`), in an installed program's folder;
- in `/etc/netrulerouter/`, for an administrator preparing a machine, which
  `sudo install -D -m 644 first-run.json /etc/netrulerouter/first-run.json`
  sets up.

In both places the file, its folder and every folder above it must belong to
root and be writable by nobody else; a file anyone else could have changed —
next to a copy in a home folder, say — is ignored.

The folder next to the program wins when both exist.

## What it contains

```json
{
  "primary-connection": "Ethernet",
  "secondary-connection": "hidemy.name VPN",
  "leak-protection": "sites",
  "doh-lockdown": true,
  "fake-ip": true,
  "rule-set": "ru/osnovnoy-i-zarubezh",
  "language": "ru"
}
```

| Key | Meaning |
|---|---|
| `primary-connection` | Name of the connection everything travels by default. Matched against the connection name Windows shows, or the adapter description. |
| `secondary-connection` | Name of the additional connection your rules send traffic to. |
| `leak-protection` | What happens while the additional connection is down: `"off"` lets traffic continue over the main connection; `"sites"` keeps what your rules send through the additional connection from going out the main one; `"everything"` holds all traffic except your local network and what your rules send over the main connection. When the additional connection is the default route, `"sites"` is taken as `"everything"`. |
| `doh-lockdown` | `true` keeps browsers from resolving routed sites past NetRuleRouter. |
| `fake-ip` | `true` routes sites by name, so an address shared with another site is not dragged along. |
| `rule-set` | Bundled rule set to start from, as `<country>/<pack>`. Use `"none"` to start with an empty table. |
| `language` | Interface language (`"ru"`, `"en"`). Omit to follow the operating system. |

Every key is optional. Unknown keys are refused — the file is ignored rather
than half-applied, so a typo cannot quietly leave a protection off.

## When the setup window still appears

The window is skipped only when `leak-protection`, `doh-lockdown`, `fake-ip` and
`rule-set` are all answered. The two connection names are not part of that bar:
a VPN adapter usually does not exist until its client connects for the first
time, so an installer cannot name it in advance. A connection named in the file
but missing from the machine leaves that role unassigned, and the app asks for
it in the usual way.

The file is read, never written. Changing settings later in the app does not
alter it, and the app does not consult it again after the first run.
