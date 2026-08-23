# Answering the setup questions ahead of time

The first time NetRuleRouter starts it asks a short set of questions: which
connections to use, whether to arm the protections, and which rule set to begin
with. If those answers are already known — an installer collected them, or a
portable copy is being prepared for several machines — they can be supplied in a
file, and the setup window does not appear.

## Where the file goes

Name it `first-run.json` and put it in either place:

- next to `NetRuleRouter.exe` (portable copy, or an installer's program folder);
- in the machine data folder, `%ProgramData%\NetRuleRouter\`.

The folder next to the executable wins when both exist.

## What it contains

```json
{
  "primary-connection": "Ethernet",
  "secondary-connection": "hidemy.name VPN",
  "kill-switch": true,
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
| `kill-switch` | `true` holds traffic rather than letting it leak out the main connection while the additional one is down. |
| `doh-lockdown` | `true` keeps browsers from resolving routed sites past NetRuleRouter. |
| `fake-ip` | `true` routes sites by name, so an address shared with another site is not dragged along. |
| `rule-set` | Bundled rule set to start from, as `<country>/<pack>`. Use `"none"` to start with an empty table. |
| `language` | Interface language (`"ru"`, `"en"`). Omit to follow the operating system. |

Every key is optional. Unknown keys are refused — the file is ignored rather
than half-applied, so a typo cannot quietly leave a protection off.

## When the setup window still appears

The window is skipped only when `kill-switch`, `doh-lockdown`, `fake-ip` and
`rule-set` are all answered. The two connection names are not part of that bar:
a VPN adapter usually does not exist until its client connects for the first
time, so an installer cannot name it in advance. A connection named in the file
but missing from the machine leaves that role unassigned, and the app asks for
it in the usual way.

The file is read, never written. Changing settings later in the app does not
alter it, and the app does not consult it again after the first run.
