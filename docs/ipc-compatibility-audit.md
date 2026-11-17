# IPC compatibility audit

Audit date: 2026-11-16. Scope: the current shared contracts, client negotiation, service negotiation and desktop preference bridge. This is an alpha compatibility policy, not a promise that arbitrary releases interoperate.

## Existing protection

`shared/contracts/src/ipc/protocol.rs` separates protocol version 1 (framing/envelope) from payload revision 3. `IpcContractVersionPolicy` requires explicit negotiation and incompatible-version refusal; `IpcVersionCompatibilityMatrix` describes older/newer/incompatible cases. Those declarations are a vocabulary, not permission to ignore the stricter executable gates.

The service's `ipc_handlers/contract_negotiate.rs` rejects clients below its minimum protocol or current payload revision. The client in `core/ipc-client/src/protocol.rs` requires the negotiated protocol to match and refuses mutating operations across a payload revision skew; reads and diagnostic actions remain available where their payload decoders support the response. Semver is information for the user, not the negotiation key. Older clients are not promised access to newer mutation semantics merely because Serde ignores unknown fields.

The current handler does not compute an operation/feature intersection from `ContractNegotiateRequest.supported_features`. The matrix's capability-negotiation wording is not evidence of general feature-level interoperability; the executable protocol/revision gates above define the current limited behaviour.

Existing tests already cover shared request/envelope decoding, version refusal, skew write guards, field-name sets pinned to contract revision, the route-policy QML wire table and defaults, and Rust/JavaScript client-logic parity vectors. `released_user_settings_files.rs` already checks historical settings files and preservation of unknown values. Those are persistence fixtures, not historic IPC messages. Ordinary round trips prove serializer agreement but cannot independently prove old sender semantics.

The Qt preference bridge currently uses `QtPreferencesPayload::apply_over`: omitted fields preserve current settings, explicit false updates a boolean, and `present` with `Option<Option<T>>` distinguishes omission from an explicit null for clearable fields. A full configuration's construction default must not be substituted for a partial update's absence semantics. This audit makes no preference protocol changes.

`contract_fingerprint()` is a snapshot-cache discriminator: crate version plus rules-file schema. It is not a DTO schema hash and does not automatically move for every DTO or payload-revision change. The comment now states that limit. No new versioning subsystem or cache-format change was introduced.

## Supported scope and directions

| Pair/direction | Actual gate and supported interpretation |
| --- | --- |
| Matching negotiated protocol and payload revision | Normal operations, subject to existing identity, profile, validation and capability checks. |
| Current client reading release `v0.1.0-alpha.1` responses | Representative reconstructed payloads are checked for protocol 1/revision 3; explicit choices and unknown diagnostic details retain their meaning. This is decoder compatibility, not a whole-release end-to-end certification. |
| Newer client with older service revision | Only compatible reads/diagnostic actions; client refuses mutations. A decoder can still reject an unsupported response shape. |
| Older client with newer service revision | Current service rejects negotiation below its minimum payload revision. No generic old-writer guarantee. |
| Different negotiated protocol | Client rejects. A newer advertised server protocol is acceptable only if it actually negotiates the client's protocol. |
| Unknown future fields or versions | Additive display metadata may be ignored; this grants no new mutation semantics or future-version support. |

## Confirmed gaps and corrections

1. **Handshake numeric narrowing:** the client manually converted `u64` protocol numbers with `as u32`. `4294967297` became supported version 1. Malformed present revision values also collapsed into the missing-field default. The regression test `malformed_handshake_numbers_cannot_alias_a_supported_protocol` failed on the old code on Windows 10 (exit 101, overflowing `server-version`). The fix decodes protocol numbers as checked Serde `u32` values, rejects a different protocol, then decodes the existing shared `ContractNegotiateResponse` for a matching protocol. This preserves defaults for absent legacy fields while rejecting malformed present fields. No enforcement decision changes.
2. **Independent historical semantics:** no dedicated released IPC corpus was found; the existing settings corpus and current-shape tests remain intact. Four representative payloads are reconstructed from the published release's types, with provenance and a release-source verification helper. `released_ipc_semantics.rs` asserts literal safety choices, false/zero/empty preservation and unknown-vs-negative diagnostics. Synthetic mutations check missing/null/unknown required protection and additive optional metadata. They are explicitly not historical captures.
3. **Misleading cache description:** corrected the `contract_fingerprint()` documentation to match implementation. Unchanged semver can still leave the same fingerprint after an unrelated DTO edit; cache invalidation must be considered separately. This audit does not claim that risk is eliminated.

The existing bounded frame codec is reused. `fuzz/fuzz_targets/ipc_payloads.rs` now also invokes the real negotiation response decoder; no new parser or dependency was added.

| Contract and source | Risk assessed | Coverage decision |
| --- | --- | --- |
| `ipc_payloads/route_policy.rs::RoutePolicyDto` | Default-true switches could overwrite explicit false; missing protection must not become off. | Existing current-default/QML field tests retained; release-source explicit opt-outs and incompatible required protection added. No policy default changed. |
| `ipc_payloads.rs::FakeIpDatapathDto` | Missing newer `last_failure` could be mistaken for a healthy datapath or a known cause. | Release desired=true/running=false/zombies=0 preserved; missing optional detail remains None. |
| `ipc_payloads/site_check.rs::SiteCheckNameDto` | Old silent/inconclusive result lacks newer DNS, rule and refusal metadata. | Release completion does not imply page success; absent details remain absent/empty, not invented fresh evidence. |
| GUI `QtPreferencesPayload` and launcher `preferences_round_trip.rs` | Missing update versus false/null/empty reset. | Existing partial-update and persistence checks reused; no duplicate DTO/version layer. |
| `lib.rs::contract_fingerprint` and client `snapshot_cache.rs` | A DTO-only semantic default change at unchanged package/schema can retain the cache fingerprint. | Documentation corrected; no claim of automatic detection or complete invalidation coverage. |

Unknown-field tolerance alone is not a security compatibility guarantee. Existing revision-pinned field sets cover the route-policy/import shapes, not every future DTO; a new authorization-relevant meaning needs a revision/support-policy review even if Serde can deserialize it.

The initial full-body-first correction exposed an existing Linux regression test: `client_unix::tests::a_protocol_mismatch_gives_the_socket_back`. A peer speaking protocol 99 omits our session fields, and must still produce a terminal mismatch and release the socket; demanding the current full schema first incorrectly retried as `Connecting`. The test expectation was retained. Protocol-number classification now precedes version-specific body decoding. This is why the Unix transport checks accompany the neutral unit tests.

## CI and validation

The new integration test is discovered by the existing `nrr-shared` test target, and the handshake regression is in the existing client unit target. The Windows and Linux quality workflows already invoke the workspace checks; no additional workflow or parallel version matrix is necessary. Source-reconstruction verification deliberately runs against the frozen release source, separately from current CI. Execution results and unrun checks are recorded below when available.

| Check | Environment | Result |
| --- | --- | --- |
| Regression on original client parser | Windows test laptop; Rust 1.94.1; `cargo test -p nrr-ipc-client malformed_handshake_numbers_cannot_alias_a_supported_protocol --lib --offline --locked -j2` | RED, exit 101: overflowing `server-version=4294967297` was accepted. |
| Release-source constructor verification | Ubuntu test laptop; release tag source; Rust 1.94.1; `cargo test -p nrr-shared --test verify_release_source --offline --locked -j2` | PASS, 1 test. All four release serializer outputs equal the frozen examples. Log SHA-256 `e16eead5d34607dfb10bcbf19b4053deda68f075150cf91b047778ae948ba2d4`. |
| Corrected client unit target | Windows 10 IoT Enterprise LTSC 10.0.19044 x64; Rust 1.94.1; `cargo test -p nrr-ipc-client --lib --offline --locked -j2` | PASS, 100 tests, including the original failing regression and release-handshake write guard. An initial compile typo in the new test's operation name was corrected before this successful run. |
| Shared contracts | Same Windows laptop; `cargo test -p nrr-shared --offline --locked -j2` | PASS, including the new release-semantic cases and existing field/default gates. |
| Service negotiation | Same Windows laptop; `cargo test -p nrr-service-runtime contract_negotiate --lib --offline --locked -j2` | PASS, 6 tests, including older-client refusal and newer-client revision reporting. |
| Client/service wire integration | Same Windows laptop; `cargo test -p nrr-ipc-client --test wire_contract --offline --locked -j2` | PASS. In-process framed duplex/router integration, not a live mixed-release named-pipe certification. |
| Desktop partial-preference contract | Same Windows laptop; `cargo test -p nrr-launcher --test preferences_round_trip --offline --locked -j2` | PASS. Existing missing-key, explicit-value and persistence behavior retained. |
| Client logic and Rust/JavaScript parity | Same Windows laptop; `cargo test -p nrr-client-logic --offline --locked -j2` | PASS, 312 tests across 52 test binaries, including 37 parity integration targets. |
| Shared contracts on Linux | Ubuntu 26.04 LTS, kernel 7.0.0-43-generic; Rust 1.94.1; `cargo test -p nrr-shared --offline --locked -j2` | PASS, 525 unit tests plus integration/doc targets. |
| Dependency policy | Both test laptops; canonical `cargo deny check` | FAIL, exit 1: advisory database reports `RUSTSEC-2026-0459` for existing `libsqlite3-sys 0.30.1` via `rusqlite 0.32.1`. Bans, licenses and sources pass. The task did not change `Cargo.lock` or dependencies; the unrelated SQLite upgrade was not folded into this IPC correction. |
| Final corrected client on Windows | Same Windows laptop; `cargo test -p nrr-ipc-client --offline --locked -j2` | PASS: 100 unit tests, 1 stderr integration and 6 wire-contract tests; 1 doctest ignored. Related package rerun after protocol-first correction; unrelated passing suites were not repeated. |
| Final corrected client on Linux | Same Ubuntu laptop; targeted `a_protocol_mismatch_gives_the_socket_back`, then `cargo test -p nrr-ipc-client --offline --locked -j2` | PASS: targeted regression, then 118 unit tests, 1 integration and 6 wire-contract tests; 1 ignored test. Existing socket-release expectation unchanged. |
| Formatting | Windows laptop; `cargo fmt --all -- --check` | PASS after formatting the two task-owned Rust files; no unrelated file reformatted. |
| Focused linting | Windows laptop; `cargo clippy -p nrr-shared -p nrr-ipc-client --all-targets --offline --locked -j2 -- -D warnings`; final IPC-only repeat after protocol-first correction | PASS. |
| Linux linting | Ubuntu laptop; same focused shared/client all-target Clippy, then final IPC-only repeat after the correction | PASS, `-D warnings`, exit 0. |
| Fuzz target build and campaign | Ubuntu laptop has nightly and cargo-fuzz 0.13.2, but lacks nightly `rust-src` required by its build-std path | NOT RUN. No toolchain installation or long fuzz campaign. Response decoder and a valid synthetic seed were added to the existing target; compilation/fuzz execution is not claimed. |

All repository code execution took place on the test laptops through mechanical `gpt-6-luna` agents. The workstation was used for inspection, editing and source/evidence transfer. Full workspace tests/Clippy, QML lint and privileged routing/enforcement checks were not rerun for this IPC-only patch. The recorded commands are the scoped quality checks, not a green claim for the entire canonical gate.

Retained local evidence (ignored, not part of the source commit) is under `target/qa-ipc-compat-20261116/`: `evidence-windows.zip`, SHA-256 `DA3DB3FF8B6D38AF615FE77CAC36C405D7D2C9DA1F58E4B79DF543E6AFB91C84`; `evidence-linux.tar`, SHA-256 `CA7EEDF312BCDD00617D6B3EAA83682670E71CEE568B39CBC703726A41540184`. These preserve RED/GREEN logs, exit codes and source hashes. The final tested `protocol.rs` SHA-256 is `DB4194A11E308DD7501A99752FF88C6B2D9B6F1C2DE670666CCD18D80159F45F` on both laptops and the workstation.

Owned inactive staging/source copies and isolated build targets were cleaned after verifying resolved paths, links and active users/processes; evidence and shared caches were retained. Windows cleanup left C: at 142.15 GiB before/after and increased D: from 205.95 to 206.21 GiB free. Ubuntu `/data` increased from 105 to 109 GiB. The workstation's first staging cleanup left C: at 174.86 GiB before/after and increased D: from 302.85 to 302.98 GiB; after evidence transfer and removal of a duplicate release archive the latest free-space reading was C: 174.30 GiB, D: 302.92 GiB. The 5 GiB C: reserve remained satisfied.

## Remaining limits

Future differential processing checks must run the historical input through the available release implementation and compare explicitly selected common contractual fields, or a documented semantic normalization, with the current implementation. New-only fields require separate expectations for absence, explicit values and invalid values as applicable. Comparing complete cross-version objects is not a valid default: an added field alone is not a regression, and normalization must not erase meaningful changes. Known defects in the old implementation are not normative expectations.

The executed release helper establishes serializer provenance, not an old-receiver processing oracle. Whole-object equality there compares two values of the same release schema. Current-reader semantic tests compare individual fields and separately assert defaults of newer fields; old/new differential processing has not been executed and is not reported as passed.

Only the locally available published alpha release is represented. No raw historical service capture was available, and no other released version is claimed. The fixture constructors exercise controlled release-type values rather than every production handler outcome. Whole application rollout, live named-pipe/Unix-socket mixed-release sessions, every DTO, and long-running fuzz campaigns need separate evidence; a unit decoder test is not an OS enforcement test. Router API, Plugin API and OpenWrt contracts were not designed or changed here.
