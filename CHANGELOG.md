# Changelog

Notable changes to NetRuleRouter are recorded here. This file follows the structure of [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); entries remain under **Unreleased** until a release is published.

**English** · [Русский](CHANGELOG_RU.md)

## [Unreleased]

### Added

- Added the first standalone browser extension for Chromium and Firefox, with local per-site `Accept-Language` profiles, inheritance, permissions limited to selected domains, and English and Russian interfaces.
- Added an explicit Chromium WebRTC `disable_non_proxied_udp` control with a warning about its effect on calls. The setting applies to the whole browser profile and does not select or verify a network route.
- Added browser DNS compatibility diagnostics for Secure DNS/DoH, DNS blocked by NRR, an unavailable local resolver, and an unavailable additional route, with results and rechecks available in the GUI and TUI.
- Added discovery episodes that explain why a destination was observed, which checks it passed, and why a rule suggestion was created or rejected.
- Extended manual site checks to compare the primary and additional routes at the DNS, connection, TLS/HTTPS, and redirect stages.
- Added richer connection, outage, and site-discovery context to diagnostics. Related values in exported archives can be correlated without revealing redacted addresses.

### Changed

- First-run and status views now report service health separately from actual routing readiness, including the number of affected assignments.
- DNS upstreams are reselected after network changes or VPN interface replacement; an upstream is no longer considered usable merely because it answered before the change.
- Reworked the Fake-IP and relay lifecycle around address-pool conflicts, safe release and reuse, and network changes.
- Verified VPN clients and their transport connections are handled separately so protection of the additional route does not prevent the VPN itself from reconnecting.
- Kept the new diagnostic states and actions aligned between the GUI and TUI.
- Updated the roadmap to reflect completed work and the remaining scope of the next development stage.

### Fixed

- An explicit primary-route rule is no longer captured by strict additional-route protection when rules share the same destination IP.
- Corrected handling of a disappearing and returning additional interface so a stale binding is not reused after the tunnel returns under a new index.
- DNS queries no longer have to wait for the client's full timeout when an upstream is unavailable: the failure is contained and a working replacement can be selected.
- Fixed races in Fake-IP release and reuse so a recently used address is not silently reassigned to another hostname.
- Tightened site-check verdicts so a local resolver response or an established TCP connection alone is not treated as proof of the selected route.

[Unreleased]: https://github.com/kroxiksut/net-rule-router/compare/v0.1.0-alpha.1...HEAD
