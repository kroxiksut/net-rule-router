# Released IPC fixture provenance

These small payloads are **source-reconstructed examples, not captured production messages**. They are not current DTOs with fields removed. Their constructors target the published release's own types and serializer.

Source: [v0.1.0-alpha.1](https://github.com/kroxiksut/net-rule-router/releases/tag/v0.1.0-alpha.1), published 2026-10-30, commit `27980e39f83793ae5ffe08baaedce222de66771d`. The source blob `shared/contracts/src/ipc_payloads.rs` is `7f1cc720a97468a25f5f4855fe6f0bca08a27f59`; `shared/contracts/src/ipc/protocol.rs` is `2e535e0782602e136446ff8f1acc1088be0db821`. That release declares protocol 1 and payload revision 3.

| File | Release type | Meaning retained by the current reader |
| --- | --- | --- |
| `negotiate.json` | `ContractNegotiateResponse` | Protocol 1, revision 3, stated service version; future revision skew must still prevent writes. |
| `route-policy.json` | `RoutePolicyDto` | Explicit opt-outs stay false even where missing fields default true; empty provider list does not grant a transport exception. |
| `health.json` | `ServiceHealthResponse` | Requested datapath is down, zero zombies; absent newer failure detail means unknown cause. |
| `site-check.json` | `SiteCheckStatus` | Finished check is inconclusive and did not read HTTPS; missing newer DNS/rule metadata does not prove fresh DNS or success. |

Fixture strings, IDs and RFC 5737 addresses are deterministic invented inputs to the release constructors. They contain no user capture. The complete constructor helper is `verify_release_source.rs`, intentionally nested so today's test discovery does not compile it against today's structs. Verify on a test laptop by extracting the release source into an isolated directory, copying `v0.1.0-alpha.1/` into its `shared/contracts/tests/fixtures/released_ipc/` and copying the helper to its `shared/contracts/tests/verify_release_source.rs`, then running `cargo test -p nrr-shared --test verify_release_source --locked`. The helper compares the release serializer's output to each frozen JSON. Never adapt that helper to current types to make a verification pass.

`released_ipc_semantics.rs` checks independent literal expectations on the current reader. Mutations described as synthetic in that test are negative/additive cases, not historical samples. Current serializer round trips cannot rewrite these fixtures or their expected meanings.

For differential processing checks, use the available release code to decode/process the historical input and obtain the old implementation's result. Compare an explicit projection of the common contractual fields, or a documented normalization that preserves their meaning; assert the new-only fields separately against independently specified expectations. Do not compare complete objects from different versions or silently drop every difference: normalization must name each excluded field and why it is version-specific. An old implementation is evidence of previous behavior, not authority to preserve a known defect.

The current release helper verifies historical serialization provenance only; it does not execute the old receiver's processing logic. The current-reader tests use field-level semantic assertions, including separate expectations for newer absent fields. Full JSON equality in the release helper is intentional: both sides represent the same release schema, not objects from different versions. Differential old/new processing is not claimed by this corpus.

Scope is release service payload → current client decoder for these four representative shapes. This does not promise every old client can mutate a newer service, every operation works across revisions, or unknown future versions are supported. Existing user-settings file fixtures cover persistence separately. See `docs/ipc-compatibility-audit.md` for the version policy and limits.
