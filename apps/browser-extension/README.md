# NetRuleRouter browser extension

An initial standalone extension for Chromium 120+ and Firefox 128+. It works without the NetRuleRouter desktop application. The popup edits the current site's profile; Settings provides global defaults, profiles, and the supported browser-wide setting.

Opening the extension does not opt the user into changes. Saving a language profile requests the necessary site permission and applies that selection. An interrupted, explicitly requested operation can resume when the background starts again.

## Current behavior

- Language profiles change the `Accept-Language` request header for matching HTTP(S) **destination hosts**. They do not change `navigator.language`, `navigator.languages`, JavaScript workers, time zones, browser UI language, or other fingerprint properties. A page's third-party requests follow their own destination profiles and available host permissions.
- Global language can use the browser default or a manual language tag, such as `en-US`. Site profiles can select a manual language or preserve the browser default. An explicit browser-default profile stops inheritance for its scope. Choosing inheritance removes the site's explicit profile and restores the next matching broader profile or the global default. More specific hosts take precedence; subdomain scope is optional.
- Changes affect subsequent requests. Reloading is an explicit user action; the extension does not reload tabs automatically. Sites can still choose language through cookies, account settings, or their own code.
- Chromium offers an explicit WebRTC setting, `disable_non_proxied_udp`, after explaining its consequences and requesting `privacy` permission. It applies to the entire browser profile using the browser's `regular` scope, including other tabs; Chromium can inherit that setting into incognito windows. Calls and screen sharing may be affected. Releasing it clears this extension's value when it still controls the expected setting. It does not select or verify a network route.
- Firefox WebRTC control is disabled in this version: the same setting has different behavior when no proxy is configured. The extension does not substitute a stronger setting silently.

There is no native messaging host or desktop connection yet. Route-following language, route-derived time zones, desktop policy inheritance, and returning browser choices to NRR are not implemented. The UI reports standalone mode and the limited scope of the language change.

## Source and outputs

| Path | Purpose |
| --- | --- |
| `src/ui/` | Popup, Settings, profile list, shared UI code and styles |
| `src/_locales/{en,ru}/` | Extension locale catalogs |
| `src/controller.js`, `src/background.js` | Browser integration |
| `policy/` | Dependency-free Rust policy crate and native tests |
| `manifests/` | Separate Chromium service-worker and Firefox event-page manifests |
| `scripts/build.mjs` | WASM build and unpacked extension assembly |
| `tests/` | Controller, localization and real WASM integration tests |
| `dist/chromium/`, `dist/firefox/` | Generated unpacked extensions; install these directories |
| `policy/target/` | Generated Rust and WASM artifacts |

The build copies the application's icons from `assets/icons/app/`. Generated directories are ignored by Git. Editing `dist/` does not change the source.

## Build and check

Prerequisites: Node.js 22+, Cargo/Rust, and the `wasm32-unknown-unknown` Rust target. The JavaScript package has no external dependencies. Follow the repository's execution rules for the machine on which commands run.

From the repository root:

```powershell
rustup target add wasm32-unknown-unknown
npm --prefix apps/browser-extension run build
npm --prefix apps/browser-extension test
cargo test --manifest-path apps/browser-extension/policy/Cargo.toml --target-dir apps/browser-extension/policy/target
```

The build must precede the JavaScript tests because one test loads the actual release WASM module. The build uses the locked Rust manifest and checks extension locale-key parity. It produces both browser directories; it does not publish or sign them.

The equivalent direct Node commands, from `apps/browser-extension/`, are:

```powershell
node scripts/build.mjs
node --test tests/*.test.mjs
```

## Load for development

For Chrome, open `chrome://extensions`; for Edge, open `edge://extensions`. Enable Developer mode, choose **Load unpacked**, and select `apps/browser-extension/dist/chromium`. After rebuilding, reload the extension on that page and reopen the popup or Settings.

For Firefox, open `about:debugging#/runtime/this-firefox`, choose **Load Temporary Add-on**, and select `apps/browser-extension/dist/firefox/manifest.json`. This temporary installation lasts until Firefox closes. Use its **Reload** action after rebuilding. A signed distribution package is not produced by this build.

## Permissions and stored state

Required permissions are `storage`, `activeTab`, and `declarativeNetRequestWithHostAccess`. Host permissions are optional: a site change requests that host, an included-subdomains change requests that scope, and a manual global language requests all HTTP(S) hosts. Chromium WebRTC control separately requests optional `privacy` permission.

Profiles are stored locally, without account sync. If applying a requested change fails or is interrupted, the UI can show it as pending. Browser changes are limited to requested language rules and explicit WebRTC actions.

## Integration work remaining

- An authenticated, versioned native messaging host and desktop-side browser settings contract.
- Explicit global/route/site precedence shared with NRR, capability negotiation, consent scope, and synchronization of browser edits back to the application.
- Connection freshness, offline behavior, and verified route status before exposing route-following settings.
- A supported, scoped time-zone mechanism with clear limits for documents, frames and workers before offering that control.
- Signed packaging and distribution.
