//! Launcher-side handlers for `sidecar.*` RPC operations.
//!
//! These operations are **not** forwarded to the Windows service —
//! they read and write a GUI-only per-user SQLite database that
//! holds rule comments, foreign-OS passthrough sections, and the
//! "Work without service" pending-apply snapshot. See the
//! [`nrr-storage-sidecar`] crate docs for the rationale.
//!
//! The dispatcher in `rpc_dispatcher.rs` matches request operations
//! by the `sidecar.` prefix and routes them through
//! [`handle_sidecar_request`] instead of the IPC client. A failed
//! sidecar op never aborts the GUI; it surfaces as a structured
//! RPC error response so QML callbacks can degrade gracefully
//! (comments don't appear this session, but the rule table still
//! renders).
//!
//! ## Operation catalogue
//!
//! | Slug                          | Description                                                    |
//! |-------------------------------|----------------------------------------------------------------|
//! | `sidecar.comment.read`        | Read one comment by signature                                  |
//! | `sidecar.comment.read-all`    | Bulk read every stored comment (one RPC for the snapshot bind) |
//! | `sidecar.comment.write`       | Write/replace one comment (empty string deletes)               |
//! | `sidecar.comment.gc`          | Drop comments not in the supplied active-signature list        |
//! | `sidecar.passthrough.read`    | Read all passthrough sections for a route                      |
//! | `sidecar.passthrough.write`   | Atomically replace the route's passthrough sections            |
//! | `sidecar.pending-apply.read`  | Read the parked pending-apply snapshot, honouring TTL          |
//! | `sidecar.pending-apply.write` | Park a fresh pending-apply snapshot                            |
//! | `sidecar.pending-apply.clear` | Drop the parked snapshot                                       |
//! | `sidecar.external-ip.read-all`  | Bulk read every cached last-known external IP                |
//! | `sidecar.external-ip.write-all` | Upsert last-known external IPs for one or more adapters      |
//! | `sidecar.vacuum`              | Force-vacuum the sidecar (Settings → Reset application data)   |
//! | `sidecar.reset`               | Full reset — wipe all comments/passthrough/pending-apply       |
//!
//! Slug shape mirrors the IpcOperationName convention
//! (`<domain>.<resource>.<verb>`) so QML developers don't have to
//! remember a different pattern when looking up bridge calls.

use std::sync::{Arc, Mutex};

use serde_json::{json, Value};

use nrr_storage_sidecar::{
    rule_metadata::sanitize_comment, RuleSignature, SidecarDb, SidecarError,
};

/// Shared handle to the launcher's singleton `SidecarDb`. Wrapped in
/// `Arc<Mutex<Option<...>>>` because:
///
/// * `Arc` — the same handle is cloned into each dispatcher worker.
/// * `Mutex` — `SidecarDb` is not `Sync` (it owns a `RefCell`), so
///   only one worker at a time can touch it.
/// * `Option` — the singleton is created lazily on the first
///   `sidecar.*` request so we never open the file on a session that
///   never needed metadata (e.g. an early launch failure before the
///   GUI fully boots).
pub type SidecarHandle = Arc<Mutex<Option<SidecarDb>>>;

/// Create an empty, uninitialised `SidecarHandle`. The actual
/// [`SidecarDb::open_default`] call happens inside [`handle_sidecar_request`]
/// on first use.
pub fn new_handle() -> SidecarHandle {
    Arc::new(Mutex::new(None))
}

/// Outcome of one `sidecar.*` request. `Ok(Value)` is returned to QML
/// as the response payload; `Err(SidecarError)` is converted into the
/// structured RPC error envelope by the dispatcher.
pub type SidecarHandlerResult = Result<Value, SidecarError>;

/// Handle one request whose operation slug starts with `sidecar.`.
/// The dispatcher already verified the prefix; we match on the suffix
/// to dispatch and call the appropriate DAO method.
///
/// Errors are folded into [`SidecarError`] and bubble up to the
/// dispatcher, which serialises them as RPC error responses.
pub fn handle_sidecar_request(
    handle: &SidecarHandle,
    operation: &str,
    payload: &Value,
) -> SidecarHandlerResult {
    let mut guard = handle.lock().unwrap_or_else(|e| e.into_inner());
    if guard.is_none() {
        match SidecarDb::open_default() {
            Ok(db) => *guard = Some(db),
            // The one request that has to work on a database we cannot open is
            // the one that throws it away. It used to fail with the same error
            // as everything else — the open happened before dispatch — so the
            // recovery the crate documents ("let the user pick Reset
            // application data") was unreachable exactly when it was needed.
            Err(open_error) if operation == RESET_OPERATION => {
                return rebuild_unopenable_sidecar(&mut guard, open_error);
            }
            Err(open_error) => return Err(open_error),
        }
    }
    // SAFETY-from-`unwrap`: we just inserted `Some(...)` above.
    let db = guard.as_mut().ok_or_else(|| SidecarError::PathResolution {
        reason: "sidecar handle was unexpectedly empty after init".into(),
    })?;
    dispatch(db, operation, payload)
}

/// The operation that must survive a database it cannot open.
const RESET_OPERATION: &str = "sidecar.reset";

/// Throw away a sidecar that will not open and put a fresh one in its place.
///
/// Only ever reached from an explicit `sidecar.reset` — the crate's rule is
/// that a non-empty user database is never auto-truncated, and this does not
/// change that: the user asked. What it does change is that asking now works.
/// The `-wal` and `-shm` companions go too; leaving them behind is how a
/// "fresh" database inherits the journal of the broken one.
fn rebuild_unopenable_sidecar(
    guard: &mut Option<SidecarDb>,
    open_error: SidecarError,
) -> SidecarHandlerResult {
    let path = nrr_storage_sidecar::profile::resolve_path()?;
    for companion in ["", "-wal", "-shm"] {
        let mut victim = path.clone().into_os_string();
        victim.push(companion);
        match std::fs::remove_file(std::path::PathBuf::from(victim)) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            // Could not remove it: report the ORIGINAL failure, which is what
            // the user is actually looking at, not a second one about a file
            // they never heard of.
            Err(_) => return Err(open_error),
        }
    }
    let db = SidecarDb::open_default()?;
    *guard = Some(db);
    Ok(json!({ "reset": true, "rebuilt": true }))
}

fn dispatch(db: &SidecarDb, operation: &str, payload: &Value) -> SidecarHandlerResult {
    match operation {
        "sidecar.comment.read" => handle_comment_read(db, payload),
        "sidecar.comment.read-all" => handle_comment_read_all(db),
        "sidecar.comment.write" => handle_comment_write(db, payload),
        "sidecar.comment.gc" => handle_comment_gc(db, payload),
        "sidecar.passthrough.read" => handle_passthrough_read(db, payload),
        "sidecar.passthrough.write" => handle_passthrough_write(db, payload),
        "sidecar.pending-apply.read" => handle_pending_apply_read(db),
        "sidecar.pending-apply.write" => handle_pending_apply_write(db, payload),
        "sidecar.pending-apply.clear" => handle_pending_apply_clear(db),
        "sidecar.external-ip.read-all" => handle_external_ip_read_all(db),
        "sidecar.external-ip.write-all" => handle_external_ip_write_all(db, payload),
        "sidecar.vacuum" => handle_vacuum(db, payload),
        RESET_OPERATION => handle_reset(db),
        other => Err(SidecarError::PathResolution {
            reason: format!("unknown sidecar operation: {other}"),
        }),
    }
}

// ── comment.* ──────────────────────────────────────────────────────────

fn handle_comment_read(db: &SidecarDb, payload: &Value) -> SidecarHandlerResult {
    let sig = read_signature(payload)?;
    let comment = db.read_comment(&sig)?;
    Ok(json!({ "comment": comment }))
}

fn handle_comment_read_all(db: &SidecarDb) -> SidecarHandlerResult {
    let comments = db.read_all_comments()?;
    // BTreeMap → JSON object preserves the deterministic ordering
    // we get from the DAO, which keeps integration test fixtures
    // stable. The GUI looks rows up by key so order is informational.
    let mut obj = serde_json::Map::with_capacity(comments.len());
    for (sig, comment) in comments {
        obj.insert(sig, Value::String(comment));
    }
    Ok(json!({ "comments": Value::Object(obj) }))
}

fn handle_comment_write(db: &SidecarDb, payload: &Value) -> SidecarHandlerResult {
    let sig = read_signature(payload)?;
    let comment = payload.get("comment").and_then(Value::as_str).unwrap_or("");
    let sanitised = sanitize_comment(comment);
    db.write_comment(&sig, &sanitised)?;
    Ok(json!({ "comment": sanitised }))
}

fn handle_comment_gc(db: &SidecarDb, payload: &Value) -> SidecarHandlerResult {
    let arr = payload
        .get("active-signatures")
        .and_then(Value::as_array)
        .ok_or_else(|| missing("active-signatures (array of {type,value,route})"))?;
    let mut sigs: Vec<RuleSignature> = Vec::with_capacity(arr.len());
    for entry in arr {
        sigs.push(read_signature(entry)?);
    }
    let removed = db.gc_orphans(&sigs)?;
    Ok(json!({ "removed": removed }))
}

// ── passthrough.* ──────────────────────────────────────────────────────

fn handle_passthrough_read(db: &SidecarDb, payload: &Value) -> SidecarHandlerResult {
    let route = payload
        .get("route")
        .and_then(Value::as_str)
        .ok_or_else(|| missing("route"))?;
    let sections = db.read_passthrough(route)?;
    Ok(json!({ "sections": sections }))
}

fn handle_passthrough_write(db: &SidecarDb, payload: &Value) -> SidecarHandlerResult {
    let route = payload
        .get("route")
        .and_then(Value::as_str)
        .ok_or_else(|| missing("route"))?;
    let raw_sections = payload
        .get("sections")
        .and_then(Value::as_object)
        .ok_or_else(|| missing("sections (object: name → raw text)"))?;
    let mut map = std::collections::BTreeMap::new();
    for (name, value) in raw_sections {
        let text = value.as_str().ok_or_else(|| SidecarError::PathResolution {
            reason: format!("sections.{name} must be a string"),
        })?;
        map.insert(name.clone(), text.to_string());
    }
    db.write_passthrough(route, &map)?;
    Ok(json!({ "saved": map.len() }))
}

// ── pending-apply.* ────────────────────────────────────────────────────

fn handle_pending_apply_read(db: &SidecarDb) -> SidecarHandlerResult {
    let entry = db.read_pending_apply()?;
    let value = entry.map(|e| {
        json!({
            "summary-json":   e.summary_json,
            "content-hash":   e.content_hash,
            "modified-at-ms": e.modified_at_ms,
            "expires-at-ms":  e.expires_at_ms,
        })
    });
    Ok(json!({ "entry": value }))
}

fn handle_pending_apply_write(db: &SidecarDb, payload: &Value) -> SidecarHandlerResult {
    let summary_json = payload
        .get("summary-json")
        .and_then(Value::as_str)
        .ok_or_else(|| missing("summary-json"))?;
    let content_hash = payload
        .get("content-hash")
        .and_then(Value::as_str)
        .ok_or_else(|| missing("content-hash"))?;
    db.write_pending_apply(summary_json, content_hash)?;
    Ok(json!({}))
}

fn handle_pending_apply_clear(db: &SidecarDb) -> SidecarHandlerResult {
    db.clear_pending_apply()?;
    Ok(json!({}))
}

// ── external-ip.* ──────────────────────────────────────────────────────

fn handle_external_ip_read_all(db: &SidecarDb) -> SidecarHandlerResult {
    let cache = db.read_all_external_ip_cache()?;
    let mut obj = serde_json::Map::with_capacity(cache.len());
    for (key, entry) in cache {
        obj.insert(
            key,
            json!({
                "external-ip":     entry.external_ip,
                "observed-at-ms":  entry.observed_at_ms,
            }),
        );
    }
    Ok(json!({ "entries": Value::Object(obj) }))
}

fn handle_external_ip_write_all(db: &SidecarDb, payload: &Value) -> SidecarHandlerResult {
    let arr = payload
        .get("entries")
        .and_then(Value::as_array)
        .ok_or_else(|| missing("entries (array of {key, external-ip, observed-at-ms})"))?;
    let mut rows = Vec::with_capacity(arr.len());
    for entry in arr {
        let key = entry
            .get("key")
            .and_then(Value::as_str)
            .ok_or_else(|| missing("entries[].key"))?;
        let ip = entry
            .get("external-ip")
            .and_then(Value::as_str)
            .ok_or_else(|| missing("entries[].external-ip"))?;
        let observed_at_ms = entry
            .get("observed-at-ms")
            .and_then(Value::as_i64)
            .ok_or_else(|| missing("entries[].observed-at-ms"))?;
        rows.push((key.to_string(), ip.to_string(), observed_at_ms));
    }
    db.write_external_ip_cache_entries(&rows)?;
    Ok(json!({ "saved": rows.len() }))
}

// ── vacuum ─────────────────────────────────────────────────────────────

fn handle_vacuum(db: &SidecarDb, payload: &Value) -> SidecarHandlerResult {
    let force = payload
        .get("force")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if force {
        db.vacuum_now()?;
        Ok(json!({ "vacuumed": true, "forced": true }))
    } else {
        let ran = db.maybe_vacuum()?;
        Ok(json!({ "vacuumed": ran, "forced": false }))
    }
}

// ── reset ──────────────────────────────────────────────────────────────

/// Full-reset: wipe every GUI-local data row (comments, passthrough,
/// pending-apply) so the sidecar returns to its post-install empty shape.
/// Schema/migration state is preserved.
fn handle_reset(db: &SidecarDb) -> SidecarHandlerResult {
    db.reset_all()?;
    Ok(json!({ "reset": true }))
}

// ── helpers ────────────────────────────────────────────────────────────

fn read_signature(payload: &Value) -> Result<RuleSignature, SidecarError> {
    let rule_type = payload
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| missing("type"))?;
    let value = payload
        .get("value")
        .and_then(Value::as_str)
        .ok_or_else(|| missing("value"))?;
    let route = payload
        .get("route")
        .and_then(Value::as_str)
        .ok_or_else(|| missing("route"))?;
    RuleSignature::build(rule_type, value, route).ok_or_else(|| SidecarError::PathResolution {
        reason: "rule signature components must be non-empty and free of `|`".to_string(),
    })
}

fn missing(field: &str) -> SidecarError {
    SidecarError::PathResolution {
        reason: format!("missing required payload field: {field}"),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fresh_handle(env_path: &std::path::Path) -> SidecarHandle {
        // Use a tempfile path; we open the DB eagerly here so the
        // handler doesn't try the real %APPDATA% during tests.
        let db = SidecarDb::open(env_path).expect("open sidecar");
        Arc::new(Mutex::new(Some(db)))
    }

    /// The crate documents "reset application data" as THE answer to a sidecar
    /// that will not open. It was not an answer: the open happened before
    /// dispatch, so `sidecar.reset` failed with the same error as every other
    /// request and the user had no way out short of deleting the file by hand.
    ///
    /// Serialised on the env override (`NRR_SIDECAR_PATH` is process-global),
    /// so this test owns it for its duration.
    #[test]
    fn a_sidecar_that_cannot_be_opened_is_rebuilt_by_an_explicit_reset() {
        let tmp = tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir: {e}"));
        let path = tmp.path().join("broken.db");
        // Not a database at all: SQLite refuses it at open.
        std::fs::write(&path, b"this is not a sqlite file, not even close")
            .unwrap_or_else(|e| panic!("write: {e}"));

        let previous = std::env::var_os(nrr_storage_sidecar::profile::NRR_SIDECAR_PATH_ENV);
        std::env::set_var(nrr_storage_sidecar::profile::NRR_SIDECAR_PATH_ENV, &path);

        let handle = new_handle();
        // Any other request still reports the failure — nothing is thrown away
        // behind the user's back.
        let read = handle_sidecar_request(&handle, "sidecar.comment.read-all", &json!({}));
        assert!(read.is_err(), "a broken sidecar must not read as empty");

        let reset = handle_sidecar_request(&handle, "sidecar.reset", &json!({}))
            .unwrap_or_else(|e| panic!("reset must succeed on a broken sidecar: {e}"));
        assert_eq!(reset["reset"], json!(true));
        assert_eq!(reset["rebuilt"], json!(true));

        // And the handle now serves a working database.
        let after = handle_sidecar_request(&handle, "sidecar.comment.read-all", &json!({}))
            .unwrap_or_else(|e| panic!("post-reset read: {e}"));
        assert_eq!(
            after["comments"],
            json!({}),
            "a rebuilt sidecar starts empty"
        );

        match previous {
            Some(value) => {
                std::env::set_var(nrr_storage_sidecar::profile::NRR_SIDECAR_PATH_ENV, value)
            }
            None => std::env::remove_var(nrr_storage_sidecar::profile::NRR_SIDECAR_PATH_ENV),
        }
    }

    #[test]
    fn comment_read_write_roundtrip() {
        let tmp = tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir: {e}"));
        let handle = fresh_handle(&tmp.path().join("sidecar.db"));
        let sig = json!({ "type": "zone", "value": "ru", "route": "primary" });

        let write = handle_sidecar_request(
            &handle,
            "sidecar.comment.write",
            &json!({ "type": "zone", "value": "ru", "route": "primary", "comment": "Россия" }),
        )
        .expect("write");
        assert_eq!(write["comment"], "Россия");

        let read = handle_sidecar_request(&handle, "sidecar.comment.read", &sig).expect("read");
        assert_eq!(read["comment"], "Россия");
    }

    #[test]
    fn comment_read_all_returns_map() {
        let tmp = tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir: {e}"));
        let handle = fresh_handle(&tmp.path().join("sidecar.db"));
        for (rule_type, value, route, comment) in [
            ("zone", "ru", "primary", "Россия"),
            ("domain", "ab.test", "secondary", "Соцсеть"),
        ] {
            handle_sidecar_request(
                &handle,
                "sidecar.comment.write",
                &json!({ "type": rule_type, "value": value, "route": route, "comment": comment }),
            )
            .expect("write");
        }
        let all = handle_sidecar_request(&handle, "sidecar.comment.read-all", &json!({}))
            .expect("read-all");
        let map = all["comments"].as_object().expect("comments object");
        assert_eq!(map.len(), 2);
        assert_eq!(map["zone|ru|primary"], "Россия");
        assert_eq!(map["domain|ab.test|secondary"], "Соцсеть");
    }

    #[test]
    fn comment_read_all_empty_on_fresh() {
        let tmp = tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir: {e}"));
        let handle = fresh_handle(&tmp.path().join("sidecar.db"));
        let all = handle_sidecar_request(&handle, "sidecar.comment.read-all", &json!({}))
            .expect("read-all");
        let map = all["comments"].as_object().expect("comments object");
        assert!(map.is_empty());
    }

    #[test]
    fn passthrough_read_write_roundtrip() {
        let tmp = tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir: {e}"));
        let handle = fresh_handle(&tmp.path().join("sidecar.db"));
        let _ = handle_sidecar_request(
            &handle,
            "sidecar.passthrough.write",
            &json!({
                "route": "primary",
                "sections": { "Linux": "firefox\n", "MacOS": "Safari\n" }
            }),
        )
        .expect("write");

        let read = handle_sidecar_request(
            &handle,
            "sidecar.passthrough.read",
            &json!({ "route": "primary" }),
        )
        .expect("read");
        assert_eq!(read["sections"]["Linux"], "firefox\n");
        assert_eq!(read["sections"]["MacOS"], "Safari\n");
    }

    #[test]
    fn pending_apply_lifecycle() {
        let tmp = tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir: {e}"));
        let handle = fresh_handle(&tmp.path().join("sidecar.db"));
        let empty = handle_sidecar_request(&handle, "sidecar.pending-apply.read", &json!({}))
            .expect("read");
        assert!(empty["entry"].is_null());

        let _ = handle_sidecar_request(
            &handle,
            "sidecar.pending-apply.write",
            &json!({
                "rules-json":   "{}",
                "summary-json": "{}",
                "content-hash": "deadbeef",
            }),
        )
        .expect("write");

        let filled = handle_sidecar_request(&handle, "sidecar.pending-apply.read", &json!({}))
            .expect("read");
        assert_eq!(filled["entry"]["content-hash"], "deadbeef");

        let _ = handle_sidecar_request(&handle, "sidecar.pending-apply.clear", &json!({}))
            .expect("clear");
        let after_clear = handle_sidecar_request(&handle, "sidecar.pending-apply.read", &json!({}))
            .expect("read");
        assert!(after_clear["entry"].is_null());
    }

    #[test]
    fn unknown_operation_errors_cleanly() {
        let tmp = tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir: {e}"));
        let handle = fresh_handle(&tmp.path().join("sidecar.db"));
        let err = handle_sidecar_request(&handle, "sidecar.bogus.op", &json!({}));
        assert!(err.is_err(), "unknown ops must error out");
    }

    #[test]
    fn external_ip_write_all_then_read_all_roundtrip() {
        let tmp = tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir: {e}"));
        let handle = fresh_handle(&tmp.path().join("sidecar.db"));
        let write = handle_sidecar_request(
            &handle,
            "sidecar.external-ip.write-all",
            &json!({
                "entries": [
                    { "key": "adapter-a", "external-ip": "203.0.113.10", "observed-at-ms": 1000 },
                    { "key": "adapter-b", "external-ip": "198.51.100.7", "observed-at-ms": 2000 },
                ]
            }),
        )
        .expect("write-all");
        assert_eq!(write["saved"], 2);

        let read = handle_sidecar_request(&handle, "sidecar.external-ip.read-all", &json!({}))
            .expect("read-all");
        let entries = read["entries"].as_object().expect("entries object");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries["adapter-a"]["external-ip"], "203.0.113.10");
        assert_eq!(entries["adapter-a"]["observed-at-ms"], 1000);
        assert_eq!(entries["adapter-b"]["external-ip"], "198.51.100.7");
    }

    #[test]
    fn external_ip_read_all_empty_on_fresh() {
        let tmp = tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir: {e}"));
        let handle = fresh_handle(&tmp.path().join("sidecar.db"));
        let read = handle_sidecar_request(&handle, "sidecar.external-ip.read-all", &json!({}))
            .expect("read-all");
        assert!(read["entries"]
            .as_object()
            .expect("entries object")
            .is_empty());
    }

    #[test]
    fn external_ip_write_all_rejects_missing_field() {
        let tmp = tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir: {e}"));
        let handle = fresh_handle(&tmp.path().join("sidecar.db"));
        let err = handle_sidecar_request(
            &handle,
            "sidecar.external-ip.write-all",
            &json!({ "entries": [ { "key": "adapter-a" } ] }),
        );
        assert!(err.is_err(), "missing external-ip must error out");
    }

    #[test]
    fn vacuum_force_path() {
        let tmp = tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir: {e}"));
        let handle = fresh_handle(&tmp.path().join("sidecar.db"));
        let res = handle_sidecar_request(&handle, "sidecar.vacuum", &json!({ "force": true }))
            .expect("vacuum");
        assert_eq!(res["vacuumed"], true);
        assert_eq!(res["forced"], true);
    }

    #[test]
    fn comment_gc_drops_orphans() {
        let tmp = tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir: {e}"));
        let handle = fresh_handle(&tmp.path().join("sidecar.db"));
        for v in ["ru", "рф", "su"] {
            let _ = handle_sidecar_request(
                &handle,
                "sidecar.comment.write",
                &json!({ "type": "zone", "value": v, "route": "primary", "comment": v }),
            )
            .expect("write");
        }
        let res = handle_sidecar_request(
            &handle,
            "sidecar.comment.gc",
            &json!({
                "active-signatures": [
                    { "type": "zone", "value": "ru", "route": "primary" }
                ]
            }),
        )
        .expect("gc");
        assert_eq!(res["removed"], 2);
    }

    #[test]
    fn both_parks_expire_on_the_same_window() {
        // The rules park (sidecar) and the routing-intent park (preferences)
        // record the same thing — work the service has not seen. Two windows
        // meant one lapsed while the other applied a month later. This crate is
        // the only one that can see both declarations.
        assert_eq!(
            nrr_storage_sidecar::PENDING_APPLY_TTL_SECONDS,
            nrr_shared::PARKED_INTENT_TTL_SECONDS
        );
    }
}
