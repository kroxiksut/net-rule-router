# nrr-domain — rule engine

The public entrypoint is `match_sample(...) -> RequestedRouteDecision` in `core/domain/src/decision_engine_input.rs`, which answers "which rule would win for this destination" over `decision_rules_matching::match_rules`. Enforcement itself is GENERATED from the rule book (codegen + the address-ownership arbiter), not decided per connection — the engine answers questions, it does not sit on the data path. Design invariants:
- **Pure and deterministic**: identical inputs → identical outputs.
- **No I/O**: never DNS, SQLite, OS route apply. All data is injected by the caller.
- **App-filter is AND**: a rule with both `address_match` and `app_match` requires both to match. That is the spec, not a promise of enforcement: the service accepts only rule shapes its enforcement implements (the neutral shape table in this crate), and codegen skips — never widens — a stored rule it cannot enforce.
- **One matcher, no second opinion**: the explain probe and any future simulator go through `match_sample`, so tooling cannot drift from what the codegen enforces.
- Input normalization and fixture helpers live in the same module. `test_support` is always compiled (not `#[cfg(test)]`).
