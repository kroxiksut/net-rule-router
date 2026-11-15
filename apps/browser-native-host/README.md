# Browser native host

This experimental component answers a browser extension's diagnostic handshake. A reply expires when the host exits, at most 60 seconds after launch. It does not authenticate the host, confirm that the NRR service is running, report a route, or change browser or NRR settings.

The host is not registered or included in a production package yet. The browser integration stays optional, and the extension remains usable without it. Registration, authenticated service access and synchronization require further work and verification on supported systems.
