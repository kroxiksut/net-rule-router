//! production [`RulesProvider`] that reads the
//! currently-active rules revision from `nrr_service_state.db` and
//! projects it into an [`ActiveRulesSnapshot`].
//!
//! ## Decode path
//!
//! 1. `RevisionsRepository::get_active` → returns the row whose
//!    `status='active'` (at most one — partial unique index on
//!    `revisions.status` enforces the invariant at the SQL layer).
//! 2. Parse the row's `rules_json` blob via
//!    [`nrr_shared::rules_json::from_canonical_string`] — wire-shape
//!    sanity check (schema version, structural validity).
//! 3. Decode the wire DTO into a domain
//!    [`RulesRevisionContent`](nrr_domain::rules_revision::RulesRevisionContent)
//!    via [`nrr_domain::rules_json_codec::decode`] — applies the
//!    canonical sort + checks the "≥1 match" invariant.
//! 4. Wrap the resulting [`CanonicalRuleBook`] in an
//!    [`ActiveRulesSnapshot`] with a placeholder
//!    `behavior_mode = PreferPrimary`. The per-SID
//!    `PerSidPolicySnapshot.mode` always wins inside
//!    `behavior_mode_for_codegen`, so the snapshot-level value is
//!    effectively cosmetic until block 16.12.A.5 introduces
//!    revision-level default modes as a first-class concept.
//!
//! ## Error handling
//!
//! Every storage error or codec error degrades to `None` + a
//! `tracing::warn!` log. The orchestrator interprets `None` as "no
//! active rules" — it records the SID and installs zero filters
//! rather than crashing. This matches the trait contract documented
//! in [`crate::per_sid_orchestrator::RulesProvider`].

use std::sync::{Arc, Mutex};

use nrr_domain::rules_json_codec;
use nrr_shared::rules_json;
use nrr_shared::RouteBehaviorMode;
use nrr_storage::revisions::{RevisionRecord, RevisionsRepository};
use nrr_storage::BASELINE_PRINCIPAL;
use rusqlite::Connection;

use crate::per_sid_orchestrator::{ActiveRulesSnapshot, RulesProvider};

/// Production [`RulesProvider`] backed by `nrr_service_state.db`.
///
/// Shares the `Arc<Mutex<Connection>>` with the other production
/// settings providers — the storage layer's WAL mode + the
/// connection's busy_timeout absorb the brief lock contention this
/// adds during orchestrator install/recompile passes.
pub struct ProductionRulesProvider {
    conn: Arc<Mutex<Connection>>,
}

impl ProductionRulesProvider {
    pub fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self { conn }
    }

    /// Decode one active `revisions` row into an [`ActiveRulesSnapshot`].
    /// Returns `None` (with a `tracing::warn!`) on any parse/codec failure.
    fn snapshot_from_record(record: &RevisionRecord) -> Option<ActiveRulesSnapshot> {
        decode_rules_snapshot(&record.rules_json, &record.revision_id)
    }
}

/// decode a canonical rules-JSON blob into an
/// [`ActiveRulesSnapshot`], the SAME wire-parse + domain-codec path
/// `ProductionRulesProvider` runs on an active `revisions` row. Used by the
/// activation dispatcher to apply the revision content it was HANDED (the
/// active pointer is not committed yet at dispatch time). `origin` labels the
/// warn logs (a revision id at the provider, a correlation hint at the
/// dispatcher). Returns `None` (with a `tracing::warn!`) on any failure.
pub fn decode_rules_snapshot(rules_json: &str, origin: &str) -> Option<ActiveRulesSnapshot> {
    // Wire-layer parse: the JSON string must be a canonical-wire
    // `CanonicalRulesJsonV1`.
    let dto = match rules_json::from_canonical_string(rules_json) {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(
                target: "nrr::rules-provider",
                error = %e,
                origin = %origin,
                "canonical rules-json parse failed; treating as no active rules",
            );
            return None;
        }
    };
    // Domain decode: schema_version check, IPv4 parse, "≥1 match"
    // invariant. Failures here are typically caused by a bumped
    // schema version on a downgrade path — log and degrade.
    let content = match rules_json_codec::decode(dto) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(
                target: "nrr::rules-provider",
                error = %e,
                origin = %origin,
                "rules-json codec decode failed; treating as no active rules",
            );
            return None;
        }
    };
    Some(ActiveRulesSnapshot {
        rule_book: content.rule_book,
        // placeholder: the per-SID `PerSidBehaviorMode` wins inside
        // `behavior_mode_for_codegen`, so this default is only used when
        // a future caller ignores the per-SID override. `PreferPrimary` is
        // the safe baseline (matches the default the GUI ships with).
        behavior_mode: RouteBehaviorMode::PreferPrimary,
    })
}

impl RulesProvider for ProductionRulesProvider {
    fn active_rules(&self) -> Option<ActiveRulesSnapshot> {
        // Back-compat: the no-principal entry point reads the baseline
        // principal's active revision.
        self.active_rules_for(BASELINE_PRINCIPAL)
    }

    /// the active rules for one `principal`, with
    /// **lazy divergence (read-through to baseline)**: if the principal
    /// has no active revision of its own it inherits the admin-managed
    /// baseline live. A user only diverges once they edit (which
    /// materialises their own active revision under their SID); until
    /// then they track baseline automatically with no copied rows. This
    /// is the resolution to the "seed-on-first-use trigger" open
    /// question — there is no separate seed step.
    fn active_rules_for(&self, principal: &str) -> Option<ActiveRulesSnapshot> {
        let guard = match self.conn.lock() {
            Ok(g) => g,
            Err(_) => {
                tracing::warn!(
                    target: "nrr::rules-provider",
                    "state DB mutex poisoned; treating as no active rules",
                );
                return None;
            }
        };
        let repo = RevisionsRepository::new(&guard);
        let lookup = |p: &str| match repo.get_active_for(p) {
            Ok(found) => Ok(found),
            Err(e) => {
                tracing::warn!(
                    target: "nrr::rules-provider",
                    error = %e,
                    principal = %p,
                    "revisions.get_active_for failed; treating as no active rules",
                );
                Err(())
            }
        };
        let record = match lookup(principal) {
            Ok(Some(r)) => r,
            // No own revision → read through to the baseline principal.
            Ok(None) if principal != BASELINE_PRINCIPAL => match lookup(BASELINE_PRINCIPAL) {
                Ok(Some(r)) => r,
                _ => return None,
            },
            Ok(None) => return None,
            Err(()) => return None,
        };
        let mut snapshot = Self::snapshot_from_record(&record)?;
        // subdomain coverage (ON by default since
        // , applied HERE at the enforcement-read layer (this snapshot
        // feeds the WFP codegen, the route codegen and the DNS-observation
        // seeder) and NEVER to the stored/hashed rule book — the drift detector
        // must keep hashing the bare rules (`rules.list` / the canonical hash use
        // a separate path). The toggle is read for the CALLING principal's own
        // policy even when the rules read through to the baseline. Degrades to
        // OFF on a storage error (the narrow rule book, never a guess).
        if Self::reads_include_subdomains(&guard, principal) {
            snapshot.rule_book = snapshot.rule_book.with_subdomain_coverage();
        }
        Some(snapshot)
    }
}

impl ProductionRulesProvider {
    /// Read the per-SID `include_subdomains` flag from `secondary_block_policy`
    /// (ON by default since ; a SID with no policy row gets the
    /// default from the storage layer). Degrades to `false` on a storage error —
    /// an unreadable policy must not be guessed at.
    fn reads_include_subdomains(guard: &Connection, principal: &str) -> bool {
        include_subdomains_for(guard, principal)
    }
}

/// the per-SID `include_subdomains` flag, shared with
/// the activation dispatcher so a snapshot decoded from dispatched rules-JSON
/// gets the SAME subdomain widening `active_rules_for` applies. ON by default
/// ; degrades to `false` on a storage error.
pub fn include_subdomains_for(guard: &Connection, principal: &str) -> bool {
    nrr_storage::route_bindings::RouteBindingsRepository::new(guard)
        .load_for_sid(principal)
        .map(|p| p.include_subdomains)
        .unwrap_or(false)
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_storage::migration::SqliteMigrationRunner;
    use nrr_storage::repository::MigrationRunner;

    /// Build a state-DB connection with the v7 schema applied.
    fn make_state_conn() -> Arc<Mutex<Connection>> {
        let conn = Connection::open_in_memory().expect("open in-memory");
        let runner = SqliteMigrationRunner::for_state_db(conn);
        runner.run_pending_migrations().expect("migrate");
        Arc::new(Mutex::new(runner.into_connection()))
    }

    /// Insert a single `status='active'` row into `revisions` with the
    /// given canonical rules-json blob. Mirrors what the activation
    /// coordinator would do in production but skipping the LKG /
    /// hash-chain plumbing we don't need for this test.
    fn insert_active_revision(conn: &Mutex<Connection>, rules_json: &str) {
        let g = conn.lock().unwrap();
        // `revisions` is now per-principal. This provider
        // reads the baseline principal via the storage back-compat shim, so
        // seed the row under `BASELINE_PRINCIPAL`.
        g.execute(
            "INSERT INTO revisions (
                principal, revision_id, content_hash, rules_json, status, source,
                correlation_id, created_at, activated_at
             ) VALUES (?1, ?2, ?3, ?4, 'active', 'gui-rules-edit', ?5, ?6, ?6)",
            rusqlite::params![
                nrr_storage::BASELINE_PRINCIPAL,
                "rev-test-001",
                "abc",
                rules_json,
                "corr-1",
                1_700_000_000_i64
            ],
        )
        .expect("insert");
    }

    #[test]
    fn returns_none_when_no_active_revision() {
        let conn = make_state_conn();
        let provider = ProductionRulesProvider::new(conn);
        assert!(provider.active_rules().is_none());
    }

    #[test]
    fn decodes_active_revision_into_rule_book() {
        use nrr_shared::rules_json::{
            AddressMatchDto, CanonicalRulesJsonV1, RuleDto, RULES_JSON_SCHEMA_VERSION,
        };
        let dto = CanonicalRulesJsonV1 {
            schema_version: RULES_JSON_SCHEMA_VERSION,
            primary: vec![RuleDto {
                id: "r-1".into(),
                enabled: true,
                address_match: Some(AddressMatchDto::ExactIpv4 {
                    address: "203.0.113.5".into(),
                }),
                app_match: None,
                comment: String::new(),
                action: nrr_shared::rules_json::RuleAction::Route,
                origin: None,
            }],
            secondary: vec![],
        };
        let json = rules_json::to_canonical_string(&dto).expect("serialise");

        let conn = make_state_conn();
        insert_active_revision(&conn, &json);

        let provider = ProductionRulesProvider::new(conn);
        let snap = provider.active_rules().expect("active rules present");
        assert_eq!(snap.rule_book.primary.rules().len(), 1);
        assert_eq!(snap.rule_book.secondary.rules().len(), 0);
        assert_eq!(snap.behavior_mode, RouteBehaviorMode::PreferPrimary);
    }

    #[test]
    fn malformed_rules_json_degrades_to_none() {
        let conn = make_state_conn();
        insert_active_revision(&conn, "{not json");
        let provider = ProductionRulesProvider::new(conn);
        assert!(provider.active_rules().is_none());
    }

    #[test]
    fn unsupported_schema_version_degrades_to_none() {
        let json = r#"{"schema-version":999,"primary":[],"secondary":[]}"#;
        let conn = make_state_conn();
        insert_active_revision(&conn, json);
        let provider = ProductionRulesProvider::new(conn);
        assert!(provider.active_rules().is_none());
    }

    /// the enforcement snapshot expands a bare `ExactFqdn`
    /// rule with a `SuffixDomain` sibling IFF the per-SID `include_subdomains`
    /// toggle is on. Since  the toggle is ON by default, so a SID with
    /// no policy row expands; only an explicit `0` leaves the rule untouched.
    #[test]
    fn subdomain_coverage_expands_exact_fqdn_only_when_toggle_on() {
        use nrr_domain::canonical::CanonicalAddressMatch;
        use nrr_shared::rules_json::{
            AddressMatchDto, CanonicalRulesJsonV1, RuleDto, RULES_JSON_SCHEMA_VERSION,
        };
        let dto = CanonicalRulesJsonV1 {
            schema_version: RULES_JSON_SCHEMA_VERSION,
            primary: vec![],
            secondary: vec![RuleDto {
                id: "r-fqdn".into(),
                enabled: true,
                address_match: Some(AddressMatchDto::ExactFqdn {
                    value: "whatismyip.com".into(),
                }),
                app_match: None,
                comment: String::new(),
                action: nrr_shared::rules_json::RuleAction::Route,
                origin: None,
            }],
        };
        let json = rules_json::to_canonical_string(&dto).expect("serialise");
        let sid = "S-1-5-21-sub";
        let conn = make_state_conn();
        insert_active_revision_for(&conn, sid, &json);
        let provider = ProductionRulesProvider::new(Arc::clone(&conn));

        let has_suffix_sibling = |snap: &crate::per_sid_orchestrator::ActiveRulesSnapshot| {
            snap.rule_book.secondary.rules().iter().any(|r| {
                matches!(
                    &r.address_match,
                    Some(CanonicalAddressMatch::SuffixDomain(d)) if d == "whatismyip.com"
                )
            })
        };

        // No policy row → the  default (ON) → apex + subdomain sibling.
        let default_on = provider.active_rules_for(sid).expect("rules present");
        assert_eq!(
            default_on.rule_book.secondary.rules().len(),
            2,
            "no policy row → default ON → apex + subdomain sibling",
        );
        assert!(
            has_suffix_sibling(&default_on),
            "a SuffixDomain sibling for the domain must be present",
        );

        // Seed the per-SID toggle explicitly OFF.
        {
            let g = conn.lock().unwrap();
            g.execute(
                "INSERT INTO secondary_block_policy
                    (sid, block_secondary_when_unavailable, kill_switch_fail_closed,
                     kill_switch_protocols, include_subdomains, updated_at)
                 VALUES (?1, 1, 1, 127, 0, ?2)",
                rusqlite::params![sid, 1_700_000_000_i64],
            )
            .expect("seed policy");
        }
        let off = provider.active_rules_for(sid).expect("rules present");
        assert_eq!(
            off.rule_book.secondary.rules().len(),
            1,
            "explicit toggle off → no subdomain expansion",
        );

        // Flip the stored toggle back ON.
        {
            let g = conn.lock().unwrap();
            g.execute(
                "UPDATE secondary_block_policy SET include_subdomains = 1 WHERE sid = ?1",
                rusqlite::params![sid],
            )
            .expect("update policy");
        }
        let on = provider.active_rules_for(sid).expect("rules present");
        assert_eq!(
            on.rule_book.secondary.rules().len(),
            2,
            "toggle on → apex + subdomain sibling",
        );
        assert!(
            has_suffix_sibling(&on),
            "a SuffixDomain sibling for the domain must be present",
        );
    }

    /// Insert an active revision under an arbitrary principal.
    fn insert_active_revision_for(conn: &Mutex<Connection>, principal: &str, rules_json: &str) {
        let g = conn.lock().unwrap();
        g.execute(
            "INSERT INTO revisions (
                principal, revision_id, content_hash, rules_json, status, source,
                correlation_id, created_at, activated_at
             ) VALUES (?1, ?2, ?3, ?4, 'active', 'gui-rules-edit', ?5, ?6, ?6)",
            rusqlite::params![
                principal,
                format!("rev-{principal}"),
                format!("hash-{principal}"),
                rules_json,
                "corr-1",
                1_700_000_000_i64
            ],
        )
        .expect("insert");
    }

    fn single_rule_json(addr: &str) -> String {
        use nrr_shared::rules_json::{
            AddressMatchDto, CanonicalRulesJsonV1, RuleDto, RULES_JSON_SCHEMA_VERSION,
        };
        let dto = CanonicalRulesJsonV1 {
            schema_version: RULES_JSON_SCHEMA_VERSION,
            primary: vec![RuleDto {
                id: "r-1".into(),
                enabled: true,
                address_match: Some(AddressMatchDto::ExactIpv4 {
                    address: addr.into(),
                }),
                app_match: None,
                comment: String::new(),
                action: nrr_shared::rules_json::RuleAction::Route,
                origin: None,
            }],
            secondary: vec![],
        };
        rules_json::to_canonical_string(&dto).expect("serialise")
    }

    #[test]
    fn active_rules_for_reads_through_to_baseline_when_principal_has_none() {
        // a principal with no own active revision inherits
        // the baseline (lazy divergence). No rows are created for the user.
        let conn = make_state_conn();
        insert_active_revision(&conn, &single_rule_json("203.0.113.5"));
        let provider = ProductionRulesProvider::new(conn);

        let snap = provider
            .active_rules_for("S-1-5-21-NEW-USER")
            .expect("read-through to baseline");
        assert_eq!(snap.rule_book.primary.rules().len(), 1);
    }

    #[test]
    fn active_rules_for_prefers_principals_own_revision_over_baseline() {
        // Once a user has their own active revision it wins over baseline.
        let conn = make_state_conn();
        insert_active_revision(&conn, &single_rule_json("203.0.113.5")); // baseline: 1 rule
        let user = "S-1-5-21-DIVERGED";
        // User's own revision has a different (still single-rule) book; the
        // point is it is THEIR row, not the baseline row.
        insert_active_revision_for(&conn, user, &single_rule_json("198.51.100.9"));
        let provider = ProductionRulesProvider::new(conn);

        let snap = provider.active_rules_for(user).expect("own revision");
        assert_eq!(snap.rule_book.primary.rules().len(), 1);
        // Baseline still resolves independently for a different fresh user.
        let other = provider
            .active_rules_for("S-1-5-21-OTHER")
            .expect("read-through");
        assert_eq!(other.rule_book.primary.rules().len(), 1);
    }
}
