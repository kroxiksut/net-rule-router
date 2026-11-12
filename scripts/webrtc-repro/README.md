# WebRTC routing reproduction

Internal diagnostic fixture, English-only like diagnostic exports. Run only on
the designated test laptops. It does not change NRR, browser settings, DNS,
routes or firewall rules. It uses the browser's native WebRTC implementation,
manual SDP exchange and a small data channel; no camera or microphone is needed.
No third-party JavaScript or public ICE server is bundled.

## Local fixture smoke

Copy this directory into a fresh private scratch directory on the test laptop;
do not overwrite its shared checkout. On Ubuntu use the test `/data` partition.
Use the installed Python and Node, without installing dependencies:

```text
node --check probe.js
python -m http.server 8765 --bind 127.0.0.1 --directory .
```

Open `http://127.0.0.1:8765/` in an isolated test browser profile. Leave ICE URLs
empty. Start an offer and verify candidate events or an explicit browser error.
Stop must close the connection. Downloaded JSON must contain neither TURN
credentials nor SDP. This verifies the fixture, not routing through Secondary.
The script has a 10–300 second run limit, a 15-second gathering wait, a 512-event
ring and a 64 KiB SDP limit. It reports discarded events; retain packet capture
for first-packet evidence. A gathering timeout leaves a partial SDP, not success.

For a connection smoke, open a second fixture tab. Exchange complete SDP as the
page instructs. Both peers should report `data-open`, received counters and,
where the browser exposes it, `selected-pair`. A connection between local tabs
is not a remote-route test. No nominated pair is inferred to be selected.

## Route-test prerequisites

### First pass without a private server

Use the locally served fixture and enter `stun:stun.cloudflare.com:3478` manually,
with policy `all`, no TURN credentials and a 30-second limit. Cloudflare documents
this as its [public STUN service](https://developers.cloudflare.com/realtime/turn/faq/).
It sees the source address of the probe. There is no account, TURN allocation or
automatic endpoint in this fixture. First establish reachability, then compare
the browser-rule cases W3/W4/W6 under packet capture when the test setup is ready.
Record the current resolved server addresses for capture filters; do not hardcode
them or treat a failed public-server response as successful protection.

This first pass can expose a UDP route mismatch without a private STUN server.
It cannot supply controlled server logs, TURN, a chosen nonstandard port, or the
controlled HTTPS domain-only case W1. Those remain blocked until provisioned.
The public [Trickle ICE sample](https://webrtc.github.io/samples/src/content/peerconnection/trickle-ice/)
can provide a separate exploratory page-domain case, but is not our controlled
fixture: remove its default ICE servers, decline media permissions, record its
actual dependencies and do not use it to close controlled-host acceptance.

### Full controlled matrix

- Record browser/OS and NRR binary build identity, active rule revision,
  Primary/Secondary bindings, IPv4/IPv6 readiness, protection scope and protocol
  selections. Record shared-IP exceptions, withdrawn app destinations and any
  more-specific Primary rules. Do not equate a saved setting with an installed
  filter. Capture before opening the page or starting ICE.
- Use a controlled STUN/TURN endpoint outside the laptop's attached local
  networks, reachable through both routes. Its address must differ from the VPN
  gateway and the web page's address. A LAN/loopback endpoint can exercise ICE
  but cannot prove external-route protection. Verify both egress addresses
  independently; do not infer them from the browser's candidate list.
- For the domain-only case, serve these same files on a controlled HTTPS host
  with a trusted certificate and ordinary DNS. Localhost is insufficient for
  this case. Assign only that page hostname to Secondary first; keep STUN and
  peer addresses outside its rule. Do not add a global UDP block or change browser
  WebRTC policy before collecting the baseline.
- Use an existing controlled coturn installation, with short-lived test
  credentials, client restrictions and a bounded relay-port range. Exercise
  UDP/3478 and a separately configured nonstandard port, TURN/UDP, TURN/TCP and
  TURN/TLS with a trusted certificate. Never disable certificate checks. Keep
  credentials, deployment addresses and private server configuration outside
  the repository. The fixture neither provisions nor starts a TURN server.
- For live data, use a second peer on an appropriate separate network and
  exchange SDP manually. Same-LAN direct ICE may correctly choose the LAN;
  classify it separately. `relay` requires TURN and rules out direct candidates;
  it does not prove which interface carries the connection to TURN.
- Record existing camera/microphone permissions and browser IP-handling policy.
  Browsers may gather a different interface set when media permissions exist;
  this fixture requests none. A fresh headless profile is a smoke result, not
  proof that a normal browser profile behaves identically. Keep both cases distinct.
- Keep a management path independent of the adapter being tested. Do not drop
  a live tunnel used by another test or SSH session. Arrange a timed recovery
  before a disruptive case; do not alter the owner's workstation or saved VPN
  credentials. Missing infrastructure makes a case blocked, never passed.

## Case matrix

Repeat relevant rows for IPv4-only, IPv6-only and dual-stack endpoints, and a
Secondary with no IPv6 path. Browsers have no portable per-peer IPv4-only switch:
use controlled endpoint families and verify actual candidates/packets. An A-only
STUN hostname does not disable IPv6 host candidates or an IPv6 direct peer.
The current `route_codegen.rs` has `APP_IPV6_ROUTES = false`: an application rule
does not itself install learned IPv6 routes. With an effective app guard, blocking
that unsupported IPv6 path is an expected safe outcome; do not require a working
IPv6 call to pass leak protection. Linux currently cannot lower that app guard,
so its IPv6 case needs separate evidence even when the Windows case blocks safely.

| Case | Setup and trigger | Required distinction |
| --- | --- | --- |
| W0 | No routing rule; gather, then establish a remote data channel | Establish endpoint reachability and observed baseline; no leak verdict |
| W1 | Only page hostname on Secondary; unrelated STUN/peer destinations | Page routing does not imply routing its unrelated UDP; compare winning rules |
| W2 | Page plus explicit STUN/peer destination rules | Protection for these destinations; first packet stays on the permitted route or is blocked |
| W3 | Actual browser executable on Secondary; protection active; no narrower exception | Fresh UDP to an unseen address, literal IP and hostname; either Secondary or block, in both families |
| W4 | W3 with an explicit narrower Primary destination rule | Record an intentional exception, not an unexplained bypass |
| W5 | W3 after a distinct process uses the same controlled address | Observe address withdrawal and any app-specific Primary permit; do not assume strict app coverage |
| W6 | Secondary unavailable before Start | Protected traffic must not appear directly on Primary; failed gathering alone is insufficient |
| W7 | Drop Secondary during established data transfer; restore with changed adapter identity | Capture the existing UDP tuple, retries, candidate-pair change, first resumed packet and new flow |
| W8 | Establish before the app rule, then apply the rule without restarting the page | Check old UDP flows separately from new flows; TCP reset behavior proves nothing about UDP |
| W9 | Repeat with UDP/3478, nonstandard STUN, TURN/UDP, TURN/TCP, TURN/TLS | A port-specific block or missing relay endpoint cannot count as leak protection |

For every row record the expected route from the effective rules, not just from
the page rule or process name. Use fresh peers for clean cases; use the same
peer deliberately for W7/W8. Export before replacement: starting again resets
the in-memory report. Select a long enough run limit to finish manual signalling.

## Packet evidence

Use existing capture tooling on each laptop. Capture the controlled server and
remote peer addresses on both interfaces, from before the first ICE attempt.
Also retain STUN/TURN server source-address logs and the fixture JSON. A sample
Linux invocation, after setting these variables to verified test values:

```sh
sudo timeout 120 tcpdump -i "$PRIMARY_IF" -nn -s 256 -w "$PRIVATE_OUT/primary.pcap" "$TEST_FILTER"
sudo timeout 120 tcpdump -i "$SECONDARY_IF" -nn -s 256 -w "$PRIVATE_OUT/secondary.pcap" "$TEST_FILTER"
```

Run the two captures concurrently in separate terminals. `TEST_FILTER` should
name only the controlled STUN/TURN and peer IPs, not arbitrary browsing traffic.
On Windows prefer an existing dumpcap installation with both interfaces selected;
otherwise inspect `pktmon start help` on that Windows build and use its NIC capture
with endpoint filters. Do not clear another operator's pktmon filters/session.
Retain ETL/pcapng component identifiers so an interface can be established; an
aggregate packet list without that mapping cannot prove the egress interface.

NRR diagnostics supplement capture: Windows ETW currently observes TCP, while
the normal merged WFP observer requests drops only. Linux procfs observes remote
endpoints of connected sockets, not sendto destinations of unconnected UDP.
Empty NRR history therefore cannot establish the absence of WebRTC traffic.

Distinguish direct packets to the STUN/peer on Primary from encrypted VPN outer
packets to its gateway on Primary. Host/mDNS ICE candidates alone are not proof
of a packet-route leak. A server-reflexive address proves an observed NAT mapping,
not that every later media/data packet follows that path. The data channel tests
ICE/DTLS/SCTP transport; it does not replace later audio/video-call acceptance.

## Result and cleanup

Record each case in the existing `TASKS_RU.md` acceptance section: passed, failed
or blocked, versions/build identity, effective rule and protection state,
candidate-pair evidence, packet interface/destination/timestamp and private
artifact location. Do not commit captures, full SDP, credentials or real user
traffic. Confirmed violation of active Fail-Closed is P0; unexplained wrong-route
traffic otherwise is P1. An unsupported capability is not a successful test.

Stop peers and the temporary HTTP server, finish only captures started for this
run, restore only the test's own rules and network changes, verify DNS and both
routes, then remove the temporary browser profile and scratch data after retaining
necessary evidence privately. Production fixes require a failing regression test
from the reproduced defect before the fix; this fixture is not that regression.

References: [WFP ALE layers](https://learn.microsoft.com/en-us/windows/win32/fwp/ale-layers),
[WebRTC statistics](https://www.w3.org/TR/webrtc-stats/),
[coturn configuration](https://github.com/coturn/coturn/blob/master/examples/etc/turnserver.conf).
