//! production [`RulesProvider`] that reads the
//! currently-active rules revision from `nrr_service_state.db` and
//! projects it into an [`ActiveRulesSnapshot`].
//!
//! ## Decode path
//!
//! 0. A revision mid-activation (`applying_revision_overlay`) wins
//!    over the stored row for its principal.
//! 1. `RevisionsRepository::get_active` → returns the row whose
//!    `status='active'` (at most one — partial unique index on
//!    `revisions.status` enforces the invariant at the SQL layer).
//! 2. Parse the row's `rules_json` blob via [`read_stored_rules`] — wire-shape
//!    sanity check, and a rule on an address that is never a destination is
//!    dropped (every service reader of a stored book reads through it).
//! 3. Decode the wire DTO into a domain
//!    [`RulesRevisionContent`](nrr_domain::rules_revision::RulesRevisionContent)
//!    via [`nrr_domain::rules_json_codec::decode`] — applies the
//!    canonical sort + checks the "≥1 match" invariant.
//! 4. Wrap the resulting [`CanonicalRuleBook`] in an
//!    [`ActiveRulesSnapshot`] with a placeholder
//!    `behavior_mode = PreferPrimary`. The per-SID
//!    `PerSidPolicySnapshot.mode` always wins inside
//!    `behavior_mode_for_codegen`, so the snapshot-level value is
//!    effectively cosmetic — nothing yet gives a revision its own
//!    default mode.
//!
//! Steps 2–4 run once per source: each read checks only the source's identity
//! (overlay blob or active revision id + hash), the subdomain flag and the
//! principal's check verdicts, and serves the kept decode while they are
//! unchanged.
//!
//! ## Error handling
//!
//! Every storage error or codec error degrades to `None` + a
//! `tracing::warn!` log. The orchestrator interprets `None` as "no
//! active rules" — it records the SID and installs zero filters
//! rather than crashing. This matches the trait contract documented
//! in [`crate::per_sid_orchestrator::RulesProvider`].

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use nrr_domain::rules_json_codec;
use nrr_shared::rules_json;
use nrr_shared::RouteBehaviorMode;
use nrr_storage::revisions::{RevisionRecord, RevisionsRepository};
use nrr_storage::BASELINE_PRINCIPAL;
use rusqlite::Connection;

use crate::applying_revision_overlay;
use crate::per_sid_orchestrator::{ActiveRulesSnapshot, RulesProvider};

/// Production [`RulesProvider`] backed by `nrr_service_state.db`.
///
/// Shares the `Arc<Mutex<Connection>>` with the other production
/// settings providers — the storage layer's WAL mode + the
/// connection's busy_timeout absorb the brief lock contention this
/// adds during orchestrator install/recompile passes.
pub struct ProductionRulesProvider {
    conn: Arc<Mutex<Connection>>,
    // Every DNS query reads the book; decoding it each time is on the traffic
    // path, so the decoded book is kept per principal until its source changes.
    decoded: Mutex<HashMap<String, DecodedRead>>,
    decodes: AtomicU64,
}

/// What a decoded book was built from; any change forces a fresh decode.
#[derive(Clone)]
struct ReadKey {
    source: Source,
    include_subdomains: bool,
    /// Generation of the principal's check verdicts (`verify_overlay`).
    verify_generation: u64,
}

#[derive(Clone)]
enum Source {
    /// Identity is the published blob itself: every publish allocates anew.
    Applying {
        principal: String,
        rules_json: Arc<str>,
    },
    Stored {
        principal: String,
        revision_id: String,
        content_hash: String,
    },
}

impl PartialEq for Source {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::Applying {
                    principal: a,
                    rules_json: x,
                },
                Self::Applying {
                    principal: b,
                    rules_json: y,
                },
            ) => a == b && Arc::ptr_eq(x, y),
            (
                Self::Stored {
                    principal: a,
                    revision_id: r1,
                    content_hash: h1,
                },
                Self::Stored {
                    principal: b,
                    revision_id: r2,
                    content_hash: h2,
                },
            ) => a == b && r1 == r2 && h1 == h2,
            _ => false,
        }
    }
}

impl PartialEq for ReadKey {
    fn eq(&self, other: &Self) -> bool {
        self.source == other.source
            && self.include_subdomains == other.include_subdomains
            && self.verify_generation == other.verify_generation
    }
}

struct DecodedRead {
    key: ReadKey,
    snapshot: Option<ActiveRulesSnapshot>,
}

impl ProductionRulesProvider {
    /// `for_enforcement` widens the book (subdomain coverage) and uses the
    /// decode cache; a writer gets the book exactly as stored.
    fn read_rules(&self, principal: &str, for_enforcement: bool) -> Option<ActiveRulesSnapshot> {
        let guard = match self.conn.lock() {
            Ok(g) => g,
            Err(_) => {
                tracing::warn!(
                    target: "nrr::rules-provider",
                    msg_key = "prod-rules-state-db-mutex-poisoned",
                    "state DB mutex poisoned; treating as no active rules",
                );
                return None;
            }
        };
        let repo = RevisionsRepository::new(&guard);
        let warn = |p: &str, e: &dyn std::fmt::Display| {
            tracing::warn!(
                target: "nrr::rules-provider",
                msg_key = "prod-rules-get-active-failed",
                error = %e,
                principal = %p,
                "revisions.get_active_for failed; treating as no active rules",
            );
        };
        // A revision mid-activation wins over the stored pointer, which still
        // names the previous one until phase 3a commits.
        let resolve = |p: &str| -> Result<Option<Source>, ()> {
            if let Some(rules_json) = applying_revision_overlay::applying_for(&guard, p) {
                return Ok(Some(Source::Applying {
                    principal: p.to_owned(),
                    rules_json,
                }));
            }
            match repo.active_identity_for(p) {
                Ok(found) => Ok(found.map(|(revision_id, content_hash)| Source::Stored {
                    principal: p.to_owned(),
                    revision_id,
                    content_hash,
                })),
                Err(e) => {
                    warn(p, &e);
                    Err(())
                }
            }
        };
        let source = match resolve(principal) {
            Ok(Some(s)) => s,
            // No own revision → read through to the baseline principal.
            Ok(None) if principal != BASELINE_PRINCIPAL => match resolve(BASELINE_PRINCIPAL) {
                Ok(Some(s)) => s,
                _ => return None,
            },
            Ok(None) | Err(()) => return None,
        };
        // Subdomain coverage and check verdicts are the CALLING principal's
        // even when the rules read through to the baseline.
        let verify = for_enforcement.then(|| crate::verify_overlay::moved_for(principal));
        let key = ReadKey {
            source,
            include_subdomains: for_enforcement
                && Self::reads_include_subdomains(&guard, principal),
            verify_generation: verify.as_ref().map_or(0, |(generation, _)| *generation),
        };
        let mut decoded = self.decoded.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(hit) = decoded
            .get(principal)
            .filter(|d| for_enforcement && d.key == key)
        {
            return hit.snapshot.clone();
        }
        self.decodes.fetch_add(1, Ordering::Relaxed);
        let (key, bare) = match key.source {
            Source::Applying { ref rules_json, .. } => {
                let bare = decode_rules_snapshot(rules_json, "applying-revision");
                (key, bare)
            }
            Source::Stored {
                principal: ref p, ..
            } => match repo.get_active_for(p) {
                // Keyed by the row actually decoded: another connection may
                // have switched the active revision since the identity read.
                Ok(Some(record)) => (
                    ReadKey {
                        source: Source::Stored {
                            principal: p.clone(),
                            revision_id: record.revision_id.clone(),
                            content_hash: record.content_hash.clone(),
                        },
                        include_subdomains: key.include_subdomains,
                        verify_generation: key.verify_generation,
                    },
                    Self::snapshot_from_record(&record),
                ),
                Ok(None) => return None,
                Err(e) => {
                    warn(p, &e);
                    return None;
                }
            },
        };
        // Subdomain coverage (ON by default) widens only this enforcement read,
        // NEVER the stored/hashed rule book the drift detector hashes bare; a
        // storage error reads as OFF (the narrow book, never a guess).
        let snapshot = bare.map(|mut s| {
            // `?` rules are routes of their own set, or of the other one under
            // a verdict; before the widening, so a twin lands with its rule.
            if let Some((_, moved)) = verify.as_ref() {
                s.rule_book = s.rule_book.with_verify_effective(moved);
            }
            if key.include_subdomains {
                s.rule_book = s.rule_book.with_subdomain_coverage();
            }
            s
        });
        if !for_enforcement {
            return snapshot;
        }
        decoded.insert(
            principal.to_owned(),
            DecodedRead {
                key,
                snapshot: snapshot.clone(),
            },
        );
        snapshot
    }

    pub fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self {
            conn,
            decoded: Mutex::new(HashMap::new()),
            decodes: AtomicU64::new(0),
        }
    }

    #[cfg(test)]
    fn decode_count(&self) -> u64 {
        self.decodes.load(Ordering::Relaxed)
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
    let dto = match read_stored_rules(rules_json, origin) {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(
                target: "nrr::rules-provider",
                msg_key = "prod-rules-json-parse-failed",
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
    let content =
        match rules_json_codec::decode(dto, nrr_domain::rules_file::HostPlatform::compiled()) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(
                    target: "nrr::rules-provider",
                    msg_key = "prod-rules-codec-decode-failed",
                    error = %e,
                    origin = %origin,
                    "rules-json codec decode failed; treating as no active rules",
                );
                return None;
            }
        };
    crate::production_mutation_executor::report_unrecognized_rules(
        rules_json,
        content.unrecognized.len(),
        "",
    );
    Some(ActiveRulesSnapshot {
        rule_book: content.rule_book,
        // placeholder: the per-SID `PerSidBehaviorMode` wins inside
        // `behavior_mode_for_codegen`, so this default is only used when
        // a future caller ignores the per-SID override. `PreferPrimary` is
        // the safe baseline (matches the default the GUI ships with).
        behavior_mode: RouteBehaviorMode::PreferPrimary,
    })
}

/// A stored rule book as every service reader reads it: a rule no book may hold
/// (an address never a destination, an application value the pipeline refuses)
/// is dropped and the rest loads, so saving what was read leaves it out for good.
pub(crate) fn read_stored_rules(
    rules_json: &str,
    origin: &str,
) -> Result<rules_json::CanonicalRulesJsonV1, rules_json::RulesJsonCodecError> {
    let mut dto = rules_json::from_canonical_string(rules_json)?;
    let dropped = nrr_domain::rule_value_validation::drop_rules_refused_outright(&mut dto);
    if !dropped.is_empty() && first_report_of(rules_json) {
        report_dropped_rules(dropped.len(), origin);
    }
    Ok(dto)
}

/// The one line saying stored rules no book may hold were dropped on read.
pub(crate) fn report_dropped_rules(dropped: usize, origin: &str) {
    if dropped == 0 {
        return;
    }
    tracing::warn!(
        target: "nrr::rules-provider",
        msg_key = "stored-rules-dropped",
        dropped,
        origin = %origin,
        "dropped stored rules no rule set may hold",
    );
}

/// Every reader of one stored book would repeat the line: once per book per run.
fn first_report_of(rules_json: &str) -> bool {
    use std::collections::HashSet;
    use std::hash::{Hash, Hasher};
    static REPORTED: std::sync::OnceLock<Mutex<HashSet<u64>>> = std::sync::OnceLock::new();
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    rules_json.hash(&mut hasher);
    let mut reported = REPORTED
        .get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    if reported.len() >= 64 {
        reported.clear();
    }
    reported.insert(hasher.finish())
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
        self.read_rules(principal, true)
    }

    fn stored_rules_for(&self, principal: &str) -> Option<ActiveRulesSnapshot> {
        self.read_rules(principal, false)
    }

    fn rules_are_baseline_for(&self, principal: &str) -> bool {
        if principal == BASELINE_PRINCIPAL {
            return true;
        }
        // Unreadable: the user's own scope is the smaller blast radius.
        let Ok(guard) = self.conn.lock() else {
            return false;
        };
        applying_revision_overlay::applying_for(&guard, principal).is_none()
            && matches!(
                RevisionsRepository::new(&guard).active_identity_for(principal),
                Ok(None)
            )
    }

    fn stored_revision_for(&self, principal: &str) -> Option<String> {
        let guard = self.conn.lock().ok()?;
        let repo = RevisionsRepository::new(&guard);
        // Outer `None`: no stable name. A revision mid-activation is known by
        // its published blob alone, and a failed read names nothing.
        let name = |p: &str| -> Option<Option<String>> {
            if applying_revision_overlay::applying_for(&guard, p).is_some() {
                return None;
            }
            let found = repo.active_identity_for(p).ok()?;
            Some(
                found
                    .map(|(revision_id, content_hash)| format!("{p}:{revision_id}:{content_hash}")),
            )
        };
        match name(principal)? {
            Some(own) => Some(own),
            None if principal != BASELINE_PRINCIPAL => name(BASELINE_PRINCIPAL)?,
            None => None,
        }
    }
}

impl ProductionRulesProvider {
    /// Read the per-SID `include_subdomains` flag from `secondary_block_policy`
    /// (ON by default; a SID with no policy row gets the storage layer's
    /// default). Degrades to `false` on a storage error — an unreadable policy
    /// must not be guessed at.
    fn reads_include_subdomains(guard: &Connection, principal: &str) -> bool {
        include_subdomains_for(guard, principal)
    }
}

/// The per-SID `include_subdomains` flag, shared with the activation dispatcher
/// so a snapshot decoded from dispatched rules-JSON gets the SAME subdomain
/// widening `active_rules_for` applies. ON by default; degrades to `false` on a
/// storage error.
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
        // `revisions` is per-principal. This provider
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
    fn reading_a_book_with_unrecognized_rules_reports_it_once() {
        let json = serde_json::json!({
            "schema-version": 3,
            "primary": [
                {
                    "id": "r-known",
                    "enabled": true,
                    "address-match": { "kind": "exact-fqdn", "value": "provider-unknown.example" },
                    "comment": "",
                    "action": "route",
                },
                {
                    "id": "r-future",
                    "enabled": true,
                    "address-match": { "kind": "port-span", "from": 8000, "to": 8100 },
                    "comment": "",
                    "action": "route",
                },
            ],
            "secondary": [],
        })
        .to_string();
        let snap = decode_rules_snapshot(&json, "test").expect("the known rule loads");
        assert_eq!(snap.rule_book.primary.rules().len(), 1);
        // The read already took the one report this book gets.
        assert!(!crate::production_mutation_executor::first_report_of_book(
            &json
        ));
        assert!(decode_rules_snapshot(&json, "test").is_some());
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

    /// A book stored before the service refused bad rule values still loads:
    /// the valid rules are enforced, the refused value stays as it was stored.
    #[test]
    fn a_stored_book_with_a_refused_value_still_serves_its_valid_rules() {
        use nrr_domain::canonical::CanonicalAddressMatch;
        use nrr_shared::rules_json::{
            AddressMatchDto, CanonicalRulesJsonV1, RuleDto, RULES_JSON_SCHEMA_VERSION,
        };
        let rule = |id: &str, address_match: AddressMatchDto| RuleDto {
            id: id.into(),
            enabled: true,
            address_match: Some(address_match),
            app_match: None,
            comment: String::new(),
            action: nrr_shared::rules_json::RuleAction::Route,
            origin: None,
        };
        let dto = CanonicalRulesJsonV1 {
            schema_version: RULES_JSON_SCHEMA_VERSION,
            primary: vec![
                rule(
                    "r-1",
                    AddressMatchDto::ExactFqdn {
                        value: "192.168.1.1".into(),
                    },
                ),
                rule("r-2", AddressMatchDto::Zone { name: "123".into() }),
                rule(
                    "r-3",
                    AddressMatchDto::ExactFqdn {
                        value: "example.com".into(),
                    },
                ),
                rule(
                    "r-4",
                    AddressMatchDto::ExactIpv4 {
                        address: "203.0.113.5".into(),
                    },
                ),
            ],
            secondary: vec![],
        };
        let conn = make_state_conn();
        insert_active_revision(&conn, &rules_json::to_canonical_string(&dto).expect("json"));

        let snap = ProductionRulesProvider::new(conn)
            .active_rules()
            .expect("the stored book loads");
        let held: Vec<_> = snap
            .rule_book
            .primary
            .rules()
            .iter()
            .filter_map(|r| r.address_match.clone())
            .collect();
        assert!(held.contains(&CanonicalAddressMatch::ExactFqdn("example.com".into())));
        assert!(held.contains(&CanonicalAddressMatch::ExactIp(
            std::net::Ipv4Addr::new(203, 0, 113, 5).into()
        )));
        assert!(held.contains(&CanonicalAddressMatch::Zone("123".into())));
    }

    /// A stored rule on an address that is never a destination is gone once
    /// read: enforcement and the rules table both get the rest of the book, and
    /// what they would save no longer holds it.
    #[test]
    fn a_stored_rule_on_no_destination_is_dropped_on_read() {
        use crate::ipc_handlers::providers::RulesSnapshotProvider as _;
        use nrr_shared::ipc_payloads::RulesRouteFilter;
        use nrr_shared::rules_json::{
            AddressMatchDto, CanonicalRulesJsonV1, RuleDto, RULES_JSON_SCHEMA_VERSION,
        };
        let rule = |id: &str, address: &str| RuleDto {
            id: id.into(),
            enabled: true,
            address_match: Some(AddressMatchDto::ExactIpv4 {
                address: address.into(),
            }),
            app_match: None,
            comment: String::new(),
            action: nrr_shared::rules_json::RuleAction::Route,
            origin: None,
        };
        let dto = CanonicalRulesJsonV1 {
            schema_version: RULES_JSON_SCHEMA_VERSION,
            primary: vec![rule("r-1", "203.0.113.5"), rule("r-2", "255.255.255.255")],
            secondary: vec![rule("r-3", "0.0.0.0"), rule("r-4", "198.51.100.9")],
        };
        let conn = make_state_conn();
        insert_active_revision(&conn, &rules_json::to_canonical_string(&dto).expect("json"));

        let snap = ProductionRulesProvider::new(Arc::clone(&conn))
            .active_rules()
            .expect("the rest of the book loads");
        let ids = |set: &nrr_domain::canonical::CanonicalRuleSet| -> Vec<String> {
            set.rules()
                .iter()
                .map(|r| r.id.as_str().to_owned())
                .collect()
        };
        assert_eq!(ids(&snap.rule_book.primary), ["r-1"]);
        assert_eq!(ids(&snap.rule_book.secondary), ["r-4"]);

        let rows = crate::production_handlers_misc::ProductionRulesSnapshotProvider::new(conn)
            .rules_snapshot(RulesRouteFilter::All)
            .rows;
        let row_ids: Vec<&str> = rows.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(row_ids, ["r-1", "r-4"]);

        let saved = rules_json_codec::encode(&nrr_domain::rules_revision::RulesRevisionContent {
            unrecognized: Default::default(),
            rule_book: snap.rule_book,
            format_version: nrr_domain::rules_revision::RULES_REVISION_FORMAT_VERSION,
        });
        let saved = rules_json::to_canonical_string(&saved).expect("json");
        assert!(!saved.contains("255.255.255.255") && !saved.contains("0.0.0.0"));
    }

    /// An application row the pipeline refuses — too long, a control
    /// character, the bare `*` — stored before the check is dropped on read the
    /// same way; the rest of the book is in force and saving it leaves them out.
    #[test]
    fn a_stored_application_the_pipeline_refuses_is_dropped_on_read() {
        use nrr_shared::rules_json::{
            AppMatchDto, AppPatternDto, CanonicalRulesJsonV1, RuleDto, RULES_JSON_SCHEMA_VERSION,
        };
        let rule = |id: &str, value: &str| RuleDto {
            id: id.into(),
            enabled: true,
            address_match: None,
            app_match: Some(AppMatchDto {
                pattern: AppPatternDto::Exact {
                    value: value.into(),
                },
                include_child_processes: false,
            }),
            comment: String::new(),
            action: nrr_shared::rules_json::RuleAction::Route,
            origin: None,
        };
        let long = format!("{}.exe", "a".repeat(300));
        let dto = CanonicalRulesJsonV1 {
            schema_version: RULES_JSON_SCHEMA_VERSION,
            primary: vec![
                rule("r-1", "chrome.exe"),
                rule("r-2", &long),
                rule("r-3", "bell\u{7}.exe"),
            ],
            secondary: vec![rule("r-4", "*"), rule("r-5", "tab\tname.exe")],
        };
        let conn = make_state_conn();
        insert_active_revision(&conn, &rules_json::to_canonical_string(&dto).expect("json"));

        let snap = ProductionRulesProvider::new(conn)
            .active_rules()
            .expect("the rest of the book loads");
        let ids = |set: &nrr_domain::canonical::CanonicalRuleSet| -> Vec<String> {
            set.rules()
                .iter()
                .map(|r| r.id.as_str().to_owned())
                .collect()
        };
        assert_eq!(ids(&snap.rule_book.primary), ["r-1"]);
        assert_eq!(ids(&snap.rule_book.secondary), ["r-5"]);

        let saved = rules_json_codec::encode(&nrr_domain::rules_revision::RulesRevisionContent {
            unrecognized: Default::default(),
            rule_book: snap.rule_book,
            format_version: nrr_domain::rules_revision::RULES_REVISION_FORMAT_VERSION,
        });
        let saved = rules_json::to_canonical_string(&saved).expect("json");
        let mut reread = read_stored_rules(&saved, "test").expect("read");
        assert!(
            nrr_domain::rule_value_validation::drop_rules_refused_outright(&mut reread).is_empty()
        );
        assert_eq!(reread.primary.len() + reread.secondary.len(), 2);
    }

    #[test]
    fn malformed_rules_json_degrades_to_none() {
        let conn = make_state_conn();
        insert_active_revision(&conn, "{not json");
        let provider = ProductionRulesProvider::new(conn);
        assert!(provider.active_rules().is_none());
    }

    #[test]
    fn a_newer_schema_is_read_rather_than_dropped() {
        // A revision a newer build wrote survives a downgrade: its unknown
        // kinds are kept aside, the rest applies.
        let json = r#"{"schema-version":999,"primary":[],"secondary":[]}"#;
        let conn = make_state_conn();
        insert_active_revision(&conn, json);
        let provider = ProductionRulesProvider::new(conn);
        assert!(provider.active_rules().is_some());
    }

    #[test]
    fn schema_zero_degrades_to_none() {
        let json = r#"{"schema-version":0,"primary":[],"secondary":[]}"#;
        let conn = make_state_conn();
        insert_active_revision(&conn, json);
        let provider = ProductionRulesProvider::new(conn);
        assert!(provider.active_rules().is_none());
    }

    /// The enforcement snapshot expands a bare `ExactFqdn`
    /// rule with a `SuffixDomain` sibling IFF the per-SID `include_subdomains`
    /// toggle is on. The toggle is ON by default, so a SID with no policy
    /// row expands; only an explicit `0` leaves the rule untouched.
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
                    value: "site.example".into(),
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
                    Some(CanonicalAddressMatch::SuffixDomain(d)) if d == "site.example"
                )
            })
        };

        // No policy row → the default (ON) → apex + subdomain sibling.
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
        // A writer reads what is stored: the sibling written back would become
        // a rule the user never wrote.
        let stored = provider.stored_rules_for(sid).expect("rules present");
        assert_eq!(stored.rule_book.secondary.rules().len(), 1);
        assert!(!has_suffix_sibling(&stored));
        // ...and that read leaves the enforcement view's cache entry alone.
        assert!(has_suffix_sibling(
            &provider.active_rules_for(sid).expect("rules present")
        ));

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

    /// A `?` rule is a route of its own set; a live verdict moves it to the
    /// other one for enforcement only, and a writer reads it as stored.
    #[test]
    fn a_verify_rule_follows_its_verdict_for_enforcement_and_is_untouched_for_writers() {
        use nrr_domain::{RuleAction, RuleId};
        use nrr_shared::rules_json::{
            AddressMatchDto, CanonicalRulesJsonV1, RuleDto, RULES_JSON_SCHEMA_VERSION,
        };
        let dto = CanonicalRulesJsonV1 {
            schema_version: RULES_JSON_SCHEMA_VERSION,
            primary: vec![],
            secondary: vec![RuleDto {
                id: "r-verify".into(),
                enabled: true,
                address_match: Some(AddressMatchDto::SuffixDomain {
                    suffix: "proton.example".into(),
                }),
                app_match: None,
                comment: String::new(),
                action: nrr_shared::rules_json::RuleAction::VerifyPrimary,
                origin: None,
            }],
        };
        let json = rules_json::to_canonical_string(&dto).expect("serialise");
        // Own principal: the verdict registry is process-wide.
        let sid = "S-1-5-21-provider-verify";
        let conn = make_state_conn();
        insert_active_revision_for(&conn, sid, &json);
        let provider = ProductionRulesProvider::new(Arc::clone(&conn));

        let enforced = provider.active_rules_for(sid).expect("rules present");
        assert!(enforced.rule_book.primary.is_empty());
        assert!(!enforced.rule_book.secondary.is_empty());
        assert!(enforced
            .rule_book
            .secondary
            .rules()
            .iter()
            .all(|r| r.action == RuleAction::Route));

        // A verdict moves it; the cached decode does not hide the change.
        crate::verify_overlay::set(sid, [RuleId("r-verify".into())].into_iter().collect());
        let moved = provider.active_rules_for(sid).expect("rules present");
        assert!(moved.rule_book.secondary.is_empty());
        assert!(!moved.rule_book.primary.is_empty());

        let stored = provider.stored_rules_for(sid).expect("rules present");
        assert!(stored.rule_book.primary.is_empty());
        assert_eq!(stored.rule_book.secondary.len(), 1);
        assert_eq!(
            stored.rule_book.secondary.rules()[0].action,
            RuleAction::Verify
        );

        // Dropped: back where it is written.
        crate::verify_overlay::set(sid, std::collections::BTreeSet::new());
        let back = provider.active_rules_for(sid).expect("rules present");
        assert!(back.rule_book.primary.is_empty());
        assert!(!back.rule_book.secondary.is_empty());
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
    fn the_stored_revision_name_follows_the_book_a_writer_reads() {
        let conn = make_state_conn();
        let provider = ProductionRulesProvider::new(Arc::clone(&conn));
        let user = "S-1-5-21-NAMED";
        assert_eq!(provider.stored_revision_for(user), None, "no book at all");

        insert_active_revision(&conn, &single_rule_json("203.0.113.5"));
        let inherited = provider.stored_revision_for(user).expect("baseline named");
        assert!(inherited.starts_with(nrr_storage::BASELINE_PRINCIPAL));

        insert_active_revision_for(&conn, user, &single_rule_json("198.51.100.9"));
        let own = provider.stored_revision_for(user).expect("own named");
        assert_ne!(own, inherited, "diverging is a new book");
        assert_eq!(provider.stored_revision_for(user), Some(own));
        assert_eq!(provider.decode_count(), 0, "naming decodes nothing");
    }

    /// A user reading the baseline through carries the administrator's
    /// machine-wide blocks; one with a book of their own does not.
    #[test]
    fn only_a_read_through_book_is_the_baseline() {
        let conn = make_state_conn();
        let provider = ProductionRulesProvider::new(Arc::clone(&conn));
        let user = "S-1-5-21-OWNBOOK";
        assert!(provider.rules_are_baseline_for(nrr_storage::BASELINE_PRINCIPAL));
        insert_active_revision(&conn, &single_rule_json("203.0.113.5"));
        assert!(
            provider.rules_are_baseline_for(user),
            "reads the baseline through"
        );
        insert_active_revision_for(&conn, user, &single_rule_json("198.51.100.9"));
        assert!(
            !provider.rules_are_baseline_for(user),
            "a book of their own"
        );
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

    /// The overlay is keyed by database path, so these need a real file.
    fn make_file_state_conn(dir: &tempfile::TempDir) -> Arc<Mutex<Connection>> {
        let conn = Connection::open(dir.path().join("state.db")).expect("open");
        let runner = SqliteMigrationRunner::for_state_db(conn);
        runner.run_pending_migrations().expect("migrate");
        Arc::new(Mutex::new(runner.into_connection()))
    }

    fn names(snap: &ActiveRulesSnapshot, addr: &str) -> bool {
        format!("{:?}", snap.rule_book.primary.rules()).contains(addr)
    }

    #[test]
    fn a_revision_mid_activation_wins_over_the_stored_one_until_withdrawn() {
        let dir = tempfile::tempdir().expect("tempdir");
        let conn = make_file_state_conn(&dir);
        let user = "S-1-5-21-APPLYING";
        insert_active_revision_for(&conn, user, &single_rule_json("203.0.113.5"));
        let provider = ProductionRulesProvider::new(Arc::clone(&conn));

        let guard = {
            let g = conn.lock().unwrap();
            applying_revision_overlay::publish(&g, user, &single_rule_json("198.51.100.9"))
        };
        let during = provider.active_rules_for(user).expect("rules");
        assert!(
            names(&during, "198.51.100.9"),
            "the applying revision is served"
        );
        drop(guard);
        let after = provider.active_rules_for(user).expect("rules");
        assert!(names(&after, "203.0.113.5"), "the stored revision is back");
    }

    #[test]
    fn an_unchanged_source_is_decoded_once_and_any_change_is_seen_at_once() {
        let dir = tempfile::tempdir().expect("tempdir");
        let conn = make_file_state_conn(&dir);
        let user = "S-1-5-21-CACHED";
        insert_active_revision_for(&conn, user, &single_rule_json("203.0.113.5"));
        let provider = ProductionRulesProvider::new(Arc::clone(&conn));

        for _ in 0..5 {
            let snap = provider.active_rules_for(user).expect("rules");
            assert!(names(&snap, "203.0.113.5"));
        }
        assert_eq!(provider.decode_count(), 1, "unchanged revision: one decode");

        // Activation of a new revision: served on the very next read.
        {
            let g = conn.lock().unwrap();
            g.execute(
                "UPDATE revisions SET status = 'superseded' WHERE principal = ?1",
                rusqlite::params![user],
            )
            .expect("supersede");
            g.execute(
                "INSERT INTO revisions (
                    principal, revision_id, content_hash, rules_json, status, source,
                    correlation_id, created_at, activated_at
                 ) VALUES (?1, 'rev-2', 'hash-2', ?2, 'active', 'gui-rules-edit', 'c2', 2, 2)",
                rusqlite::params![user, single_rule_json("198.51.100.9")],
            )
            .expect("insert");
        }
        let next = provider.active_rules_for(user).expect("rules");
        assert!(names(&next, "198.51.100.9"), "new revision seen at once");
        provider.active_rules_for(user).expect("rules");
        assert_eq!(provider.decode_count(), 2);

        // The applying overlay and its withdrawal are both seen at once.
        let guard = {
            let g = conn.lock().unwrap();
            applying_revision_overlay::publish(&g, user, &single_rule_json("192.0.2.7"))
        };
        let during = provider.active_rules_for(user).expect("rules");
        assert!(names(&during, "192.0.2.7"));
        provider.active_rules_for(user).expect("rules");
        assert_eq!(provider.decode_count(), 3);
        drop(guard);
        let after = provider.active_rules_for(user).expect("rules");
        assert!(names(&after, "198.51.100.9"));

        // A subdomain-setting flip is a new source too.
        let before_flip = provider.decode_count();
        {
            let g = conn.lock().unwrap();
            g.execute(
                "INSERT INTO secondary_block_policy
                    (sid, block_secondary_when_unavailable, kill_switch_fail_closed,
                     kill_switch_protocols, include_subdomains, updated_at)
                 VALUES (?1, 1, 1, 127, 0, 1)",
                rusqlite::params![user],
            )
            .expect("seed policy");
        }
        provider.active_rules_for(user).expect("rules");
        assert_eq!(provider.decode_count(), before_flip + 1);
    }

    #[test]
    fn a_baseline_mid_activation_reaches_inheriting_users_only() {
        let dir = tempfile::tempdir().expect("tempdir");
        let conn = make_file_state_conn(&dir);
        insert_active_revision(&conn, &single_rule_json("203.0.113.5"));
        let diverged = "S-1-5-21-DIVERGED";
        insert_active_revision_for(&conn, diverged, &single_rule_json("192.0.2.7"));
        let provider = ProductionRulesProvider::new(Arc::clone(&conn));

        let _guard = {
            let g = conn.lock().unwrap();
            applying_revision_overlay::publish(
                &g,
                BASELINE_PRINCIPAL,
                &single_rule_json("198.51.100.9"),
            )
        };
        let inheriting = provider.active_rules_for("S-1-5-21-NEW").expect("rules");
        assert!(names(&inheriting, "198.51.100.9"));
        let own = provider.active_rules_for(diverged).expect("rules");
        assert!(names(&own, "192.0.2.7"));
    }
}
