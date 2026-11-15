# NetRuleRouter browser extension

An initial standalone extension for Chromium 120+ and Firefox 128+. It works without the NetRuleRouter desktop application. The popup edits the current site's profile; Settings provides global defaults, profiles, and the supported browser-wide setting.

Opening the extension does not opt the user into changes. Saving a language profile requests the necessary site permission and applies that selection. An interrupted, explicitly requested operation can resume when the background starts again.

## Current behavior

- Language profiles change the `Accept-Language` request header for matching HTTP(S) **destination hosts**. They do not change `navigator.language`, `navigator.languages`, JavaScript workers, time zones, browser UI language, or other fingerprint properties. A page's third-party requests follow their own destination profiles and available host permissions.
- Global language can use the browser default or a manual language tag, such as `en-US`. Site profiles can select a manual language or preserve the browser default. An explicit browser-default profile stops inheritance for its scope. Choosing inheritance removes the site's explicit profile and restores the next matching broader profile or the global default. More specific hosts take precedence; subdomain scope is optional.
- Changes affect subsequent requests. Reloading is an explicit user action; the extension does not reload tabs automatically. Sites can still choose language through cookies, account settings, or their own code.
- In supported Chromium browsers, the user can explicitly request the WebRTC setting `disable_non_proxied_udp` after reviewing its consequences and granting `privacy` permission. The requested `regular` scope covers the browser profile and may be inherited by incognito windows. Availability and behavior depend on the browser; a successful readback confirms the setting's value, not its network effect or route. Calls and screen sharing may be affected. Releasing it clears this extension's value when it still controls the expected setting.
- Firefox WebRTC control is disabled in this version: the same setting has different behavior when no proxy is configured. The extension does not substitute a stronger setting silently.

An experimental native host can answer a user-initiated local check. It does not authenticate the host or query the NRR service; an answer does not confirm routing or protection. The host is not registered by this build. Route-following language, route-derived time zones, desktop policy inheritance, and returning browser choices to NRR are not implemented. Profiles continue to work standalone.

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

## License

The extension source is available under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option. The included application icons have separate distribution permission and brand restrictions, described in [NOTICE.md](NOTICE.md). Each browser build includes both license texts and the notice. The rest of the repository remains under [MPL-2.0](../../LICENSE), subject to its third-party notices.

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

The optional visible-browser acceptance test uses a disposable profile and a loopback HTTP server. Build the extension first on a designated test machine, set `NRR_VISIBLE_ROOT` to a new absolute directory on a drive with sufficient free space, and set `NRR_VISIBLE_EXTENSION` and `NRR_VISIBLE_EDGE` to the unpacked Chromium build and test-browser executable. Run `node tests/permission-browser.mjs` from `apps/browser-extension/` in the interactive desktop session. Grant only the displayed request for `127.0.0.1`; the test checks the original `Accept-Language`, the manually selected `fr-CA`, and the return to inheritance. The result is written to `events.jsonl` in the test directory. The test closes its browser but leaves its profile and log for inspection and safe cleanup; it is not part of the normal Node suite.

## Load for development

For Chrome, open `chrome://extensions`; for Edge, open `edge://extensions`. Enable Developer mode, choose **Load unpacked**, and select `apps/browser-extension/dist/chromium`. After rebuilding, reload the extension on that page and reopen the popup or Settings.

Yandex Browser with Alice is a target for the first release, but this extension's installation and capabilities have not yet been verified there. Yandex may disable extensions from outside supported stores; its [extension verification guidance](https://yandex.ru/support/browser/ru/security/check-extensions) recommends the beta browser for extension development. Do not bypass browser security checks or managed policies.

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
