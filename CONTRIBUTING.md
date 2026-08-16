# Contributing

NetRuleRouter is pre-alpha. Windows builds and runs today; Linux is in progress
and macOS has not started. That shapes what is useful right now: a precise bug
report is worth more than a feature patch, and an issue before a pull request
saves both of us the work of discovering that a change does not fit.

## Reporting a bug

Say what you did, what you expected, and what happened instead. Then attach the
diagnostic archive from **Settings → Diagnostics and logs** — it collects the
service logs, health and environment facts in one file, and never packages your
rules or the databases.

At the standard level the log lines are structured events rather than free text,
so they carry no raw host names or addresses, and the archive is safe to attach
to a public issue. **Full diagnostics** is different: it is less redacted and
can include the destination host name of sampled routing decisions, so review it
before sharing. [`docs/en/diagnostic-archive.md`](docs/en/diagnostic-archive.md)
lists every file and what is in it.

If the machine has lost network access and you need it back before anything
else, [`docs/en/recovering-network-access.md`](docs/en/recovering-network-access.md)
is the page to open first.

## Reporting a security issue

Do not open a public issue. Use GitHub's **Report a vulnerability** button on
the repository's Security tab, which opens a private advisory. Include the
version, the platform, and what an attacker would gain — that last part decides
how fast it moves. The trust boundaries the product is built around are written
down in [`SECURITY.md`](SECURITY.md); a report that names the boundary it
crosses is much easier to act on.

## Suggesting a feature

Open an issue and describe the situation you are in, not the mechanism you have
in mind. The scope is deliberately narrow, and two limits come up often enough
to state here:

**It is a routing manager, not a security suite.** It decides which of your
existing connections traffic leaves through. Tracker blocking, ad filtering,
traffic obfuscation and anonymity are out of scope — not because they are bad
ideas, but because they are a different product.

**Some things are Pro-only by design.** Multiple saved profiles, three or more
routes at once, automated switching and richer rule types are planned for a
paid tier. The free tier stays one active configuration per user. A patch that
moves a Pro capability into the free tier cannot be merged, so please ask before
writing one.

## Building

Prerequisites, the Qt setup and the exact commands live in
[`docs/en/building-windows.md`](docs/en/building-windows.md). The short version:

```powershell
# Prerequisites and .env
powershell -ExecutionPolicy Bypass -File .\scripts\bootstrap.ps1

# Build the desktop and runtime pieces
cargo build -p nrr-launcher -p nrr-qt-host
```

Packaging a distributable folder is
[`docs/en/packaging-windows.md`](docs/en/packaging-windows.md).

## The quality gate

Run the same gate CI runs, before you open the pull request:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\check.ps1 -RequireCargoDeny
```

It wraps `cargo fmt --check`, `cargo clippy --workspace --all-targets -D warnings`,
`cargo test --workspace` and `cargo deny check`. All four have to be green.

Two practical notes. Run the crate's tests in full — `cargo test -p <crate>`,
not `--lib`: integration tests live in `tests/` and have caught regressions the
unit tests could not see. And stop the background service before a full build or
test run: a running `nrr-service.exe` holds its own binary, and the link step
fails on a locked file.

## Code standards

The bar is idiomatic, review-ready Rust: correct ownership from the start, no
allocation or indirection that earns nothing, and a narrow public surface with
the implementation kept private.

The workspace lints are not advisory — `unsafe_code`, `unwrap_used` and
`dbg_macro` are all `deny`. `unsafe` appears only where a call into the OS makes
it unavoidable (the per-OS platform crates, the IPC transport, the elevation
broker), always behind a local `#[allow(unsafe_code)]` on the smallest possible
scope, and always with a `// SAFETY:` comment stating why the contract holds. If
a patch introduces the first `unsafe` in a crate that had none, expect that to
be the whole review.

Comments explain **why**, never restate **what**. One or two lines is the norm,
and a comment longer than the code above it is a defect. Do not put task
numbers, block numbers, ticket ids or dates in comments — a hygiene check in
`scripts/check.ps1` rejects them.

## Architectural rules a review will check

These are the ones that reject otherwise-good patches, so they are worth knowing
before you write code. [`ARCHITECTURE.md`](ARCHITECTURE.md) has the full map.

**Crate boundaries are enforced by tests, not by convention.** Business logic
lives in `core/`, never in C++ or QML. The background service must not import
UI, preview or launcher crates; `domain` must not reach for OS APIs; `storage`
must not depend on the contracts crate. `cargo test` fails if these are crossed.

**Cross-platform by construction.** Anything touching an OS capability splits
along the policy/mechanism seam from the first commit: the decision logic stays
neutral and testable on any host, the OS mechanism goes behind a trait in
`core/platform/api` with a per-OS implementation. Do not hardcode a Win32, WFP,
registry or named-pipe path into neutral code. If a capability genuinely has no
analogue elsewhere, declare it in `PlatformCapabilities` so other platforms
degrade gracefully — rather than scattering platform checks through the UI.

**The GUI stays thin, and QML stays decomposed.** `Main.qml` is a shell;
sections live in their own files. Use the themed control wrappers in
`apps/desktop/qml/components/` instead of raw QtQuick controls — the native
Windows style ignores the palette, so a raw control looks wrong in dark and
high-contrast themes.

**Accessibility is a baseline, not a follow-up.** Interactive controls need
accessible names and roles, keyboard reachability and a visible focus ring.

## User-visible text

Every string a user can see goes through `tr(key, fallback)` and lands in
**both** `locales/en.json` and `locales/ru.json` in the same change. A string
shipped with only the English fallback is a defect, not a follow-up. Before
adding a key for a generic action ("Copy", "Dismiss", "Show details"), search
for an existing one — one wording per concept across the app.

Diagnostic and log lines written from Rust are the exception: they stay English.

## Documentation

Several documents exist as English and Russian pairs (`README.md` ↔
`README_RU.md`, `ARCHITECTURE.md` ↔ `ARCHITECTURE_RU.md`). Edit both in one
change, English first.

Two house rules: **no emoji** anywhere in documentation, and public docs
describe **what the user gets**, not how a mechanism works internally. Algorithms,
heuristics and thresholds belong in the internal design notes, not in `README`
or `docs/`.

## Dependencies

A new dependency needs a licence the allow-list in `deny.toml` already permits,
and `cargo deny check` has to stay green. GPL and AGPL are denied; so are git
dependencies, wildcard versions and non-crates.io registries.

One trap worth naming: `cargo deny` inspects Rust crates only. If a crate links
a system C library, the licence of that library never enters the graph, and the
gate passes an FFI wrapper over a copyleft library without a word. Any `-sys`
dependency needs its native library's licence checked by hand.

## Pull requests

Keep a pull request to one subject; a refactor bundled with a fix is two
reviews wearing one coat. Say what the change does and why the alternative was
worse — the second half is what a reviewer cannot reconstruct. New behaviour
comes with tests, and a bug fix comes with the test that fails without it.

Commits are plain English, imperative, and under 200 characters in the subject.

## Licence of contributions

The product is distributed under the **Mozilla Public License 2.0** (see
[`LICENSE`](LICENSE)), and contributions are accepted under the same licence.
Third-party components shipped alongside the binaries are listed in
[`THIRD_PARTY_LICENSES.md`](THIRD_PARTY_LICENSES.md).

### One exception: `nftlink`

The Linux enforcement backend drives `nft` today. Its direct-netlink
replacement is being written as a self-contained crate, **`nftlink`**, which
lives in this repository for now and is meant to become an independent project
published on crates.io. It knows nothing about NetRuleRouter — it speaks
nf_tables (tables, chains, rules, sets, batches) and nothing of this product's
domain, and a test fails the build if that boundary is crossed.

While it lives here it is covered by this repository's MPL-2.0. On the way out
it will be relicensed to **MIT OR Apache-2.0**, the licence such a library
should have.

**If you want to change or extend `nftlink`, open an issue — do not send a
patch.** Only the copyright holder can relicense, so a contribution accepted
under MPL-2.0 would permanently close the door on that relicensing and on
publishing the crate. Your interest is the signal that it has outgrown this
repository: the answer to such an issue is to split it into its own repository
under its own licence, and to take your patch there. That is the outcome we
want — it just has to happen in that order.
