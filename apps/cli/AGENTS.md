# nrr-cli — administrative console

Short-lived, not a long-running process. Free surface is deliberately narrow: service lifecycle (`install`/`uninstall`/`start`/`stop`/`restart`/`status`) plus — once wired — diagnostics and network recovery. It never mutates policy, emits no machine-readable output, and takes no config file.

- **Elevation is opt-in, never automatic:** with no terminal (a script, CI, a scheduled task) an access-denied still prints the exact command to repeat and exits 3 — nothing pops up. Only an explicit `--elevate`, or a `y` to the question an interactive console asks, re-runs the verb elevated (`platform-api::elevation::PrivilegedRelaunchPort`; UAC on Windows, `pkexec` on Linux, `sudo` when macOS lands). The command is always tried first and elevation is requested only if it was actually refused, so an SCM grant that lets a user control the service unprivileged prompts for nothing. Declining the OS prompt exits 8, distinct from both 3 and a failed run.
- The verb table in `apps/cli/src/verbs.rs` is the single declaration from which help is rendered; tests there reject policy verbs and automation flags by name.
- **Output is English only** (an admin interface, never localized).
- **`status` describes the service** — installed / running / version / start mode — and never the policy, because "N rules applied" immediately raises "whose", which is per-SID and therefore not Free console territory.
- The **service binary's own verbs** (`console`, `run`, `set-start-auto`, `query-start-mode`, `update`, SCM mode) stay internal — the broker, GUI and systemd invoke them, they are not publicly documented and may change freely.
- Holds no OS-specific logic — `platform.rs` is the single cfg, and it only picks an implementation of the service-control port. The IPC client is what lets `diag export` ask the SERVICE for the archive instead of assembling a second one.
