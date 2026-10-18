//! First-start apply: what the installer staged goes into the administrator's
//! baseline through the ordinary preset import, so it meets the parser, the
//! submission gates and the revision audit a typed rule set does.
//!
//! A refusal changes nothing in force: the baseline and the install policy
//! stay as they were, the trail records why, and a security alert (one that
//! holds no rule edits) tells whoever opens the window.

use std::path::Path;
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use nrr_diagnostics::audit::alert::{SecurityAlert, SecurityAlertState, SecurityAlertsRepository};
use nrr_diagnostics::reason::import;
use nrr_diagnostics::{ActorKind, AuditEventInput, AuditEventKind, AuditEventResult, AuditWriter};
use nrr_domain::rules_file::HostPlatform;
use nrr_storage::install_policy::{InstallPolicy, InstallPolicyRepository};
use rusqlite::Connection;

use super::bundle::{check_bundle, BundleBytes, CheckedBundle, ProvisionPart, ProvisionRefusal};
use super::folder::{mark_processed, read_bundle_owned_by, ProcessedAs, ROOT_UID};
use crate::ipc_handlers::mutation_token_store::StoredMutation;
use crate::ipc_handlers::payloads::MutationKind;
use crate::ipc_handlers::providers::{MutationExecutor, MutationOutcome};

/// What one start did with the folder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProvisionApplyOutcome {
    NothingStaged,
    Applied { rules: bool, policy: bool },
    Refused(ProvisionRefusal),
}

/// Everything the apply touches, borrowed from the service wiring.
pub struct ProvisionApplier<'a> {
    pub executor: &'a dyn MutationExecutor,
    pub conn: &'a Arc<Mutex<Connection>>,
    pub audit: Option<&'a AuditWriter>,
    pub alerts: Option<&'a dyn SecurityAlertsRepository>,
    pub now_ms: i64,
    /// Who must own the staged files off Windows; root in production.
    pub owner: u32,
}

impl<'a> ProvisionApplier<'a> {
    pub fn new(executor: &'a dyn MutationExecutor, conn: &'a Arc<Mutex<Connection>>) -> Self {
        Self {
            executor,
            conn,
            audit: None,
            alerts: None,
            now_ms: now_ms(),
            owner: ROOT_UID,
        }
    }
}

/// Apply what `dir` holds, once. Logged, audited and marked whatever happens;
/// the outcome is returned for the caller's own record.
pub fn apply_staged(dir: &Path, applier: &ProvisionApplier<'_>) -> ProvisionApplyOutcome {
    let outcome = match read_bundle_owned_by(dir, applier.owner) {
        Ok(None) => return ProvisionApplyOutcome::NothingStaged,
        Ok(Some(bytes)) => apply_bundle(&bytes, applier),
        Err(refusal) => Err(refusal),
    };
    match outcome {
        Ok((rules, policy)) => {
            tracing::info!(
                target: "nrr::provisioning",
                msg_key = "provisioning-applied",
                rules,
                policy,
                "install-time files applied to the shared rules and settings",
            );
            audit_applied(applier, rules, policy);
            mark(dir, ProcessedAs::Applied);
            ProvisionApplyOutcome::Applied { rules, policy }
        }
        Err(refusal) => {
            tracing::warn!(
                target: "nrr::provisioning",
                msg_key = "provisioning-refused",
                part = refusal.part.slug(),
                code = %refusal.code,
                detail = %refusal.detail,
                "install-time files refused; the shared rules were left as they were",
            );
            audit_refused(applier, &refusal);
            mark(dir, ProcessedAs::Refused);
            ProvisionApplyOutcome::Refused(refusal)
        }
    }
}

/// Check, then import the rules, then store the policy: a refused import
/// leaves the policy untouched too.
fn apply_bundle(
    bytes: &BundleBytes,
    applier: &ProvisionApplier<'_>,
) -> Result<(bool, bool), ProvisionRefusal> {
    let checked = check_bundle(bytes, HostPlatform::compiled())?;
    if checked.has_rules() {
        import_rules(bytes, applier)?;
    }
    let policy = store_policy(&checked, applier)?;
    Ok((checked.has_rules(), policy))
}

fn import_rules(
    bytes: &BundleBytes,
    applier: &ProvisionApplier<'_>,
) -> Result<(), ProvisionRefusal> {
    let part = if bytes.primary.is_some() {
        ProvisionPart::Primary
    } else {
        ProvisionPart::Secondary
    };
    let mut payload = serde_json::json!({
        "include-child-processes": false,
        "import-only-active": false,
    });
    if let Some(primary) = bytes.primary.as_deref() {
        payload["primary-bytes-b64"] = BASE64_STANDARD.encode(primary).into();
    }
    if let Some(secondary) = bytes.secondary.as_deref() {
        payload["secondary-bytes-b64"] = BASE64_STANDARD.encode(secondary).into();
    }
    let stored = StoredMutation {
        kind: MutationKind::PresetImport,
        payload,
        // No correlation id: nobody is subscribed this early, and progress
        // events would only fill the bus.
        correlation_id: None,
        issuer_sid: String::new(),
        // The administrator who ran the installer; the rules lock binds users.
        caller_is_elevated: true,
    };
    match applier
        .executor
        .execute(stored, nrr_storage::BASELINE_PRINCIPAL)
    {
        MutationOutcome::Completed(_) => Ok(()),
        MutationOutcome::Failed(error) => {
            Err(ProvisionRefusal::new(part, &error.code, error.message))
        }
    }
}

/// `Ok(true)` when the install policy was written.
fn store_policy(
    checked: &CheckedBundle,
    applier: &ProvisionApplier<'_>,
) -> Result<bool, ProvisionRefusal> {
    let unset = checked.options.secondary_unset;
    let mode = checked.settings.and_then(|s| s.route_mode);
    if unset.is_none() && mode.is_none() {
        return Ok(false);
    }
    let failed = |e: String| ProvisionRefusal::new(ProvisionPart::Options, "policy-not-stored", e);
    let guard = applier
        .conn
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let repo = InstallPolicyRepository::new(&guard);
    let current = repo.get().map_err(|e| failed(e.to_string()))?;
    let next = InstallPolicy {
        secondary_unset: unset.unwrap_or(current.secondary_unset),
        default_route_mode: mode.or(current.default_route_mode),
    };
    repo.set(&next, applier.now_ms)
        .map_err(|e| failed(e.to_string()))?;
    Ok(true)
}

fn mark(dir: &Path, outcome: ProcessedAs) {
    if let Err(e) = mark_processed(dir, outcome) {
        tracing::error!(
            target: "nrr::provisioning",
            msg_key = "provisioning-mark-failed",
            error = %e,
            "install-time files could not be marked done; the next start would read them again",
        );
    }
}

fn audit_applied(applier: &ProvisionApplier<'_>, rules: bool, policy: bool) {
    let Some(audit) = applier.audit else {
        return;
    };
    let input = AuditEventInput {
        event_id: crate::recovery_audit::next_event_id(),
        kind: AuditEventKind::ImportCreated,
        created_at: applier.now_ms,
        actor_kind: ActorKind::Service,
        actor_id_hash: None,
        revision_id: None,
        risk_level: Some("medium".to_owned()),
        result: AuditEventResult::Success,
        reason_code: import::CANDIDATE_CREATED,
        payload_summary_json: Some(
            serde_json::json!({ "source": "provisioning", "rules": rules, "policy": policy })
                .to_string(),
        ),
    };
    if let Err(e) = audit.append_located(input) {
        tracing::error!(target: "nrr::provisioning", error = %e, "could not audit the applied install-time files");
    }
}

/// Audited, then raised as an alert pointing at the event. Without a trail the
/// alert still goes up: the notice matters more than its back-reference.
fn audit_refused(applier: &ProvisionApplier<'_>, refusal: &ProvisionRefusal) {
    let kind = AuditEventKind::ProvisioningRefused;
    let located = applier.audit.and_then(|audit| {
        let input = AuditEventInput {
            event_id: crate::recovery_audit::next_event_id(),
            kind,
            created_at: applier.now_ms,
            actor_kind: ActorKind::Service,
            actor_id_hash: None,
            revision_id: None,
            risk_level: Some("high".to_owned()),
            result: AuditEventResult::Failure,
            reason_code: import::VALIDATION_FAILED,
            // The code only: the detail can quote the file.
            payload_summary_json: Some(
                serde_json::json!({
                    "source": "provisioning",
                    "part": refusal.part.slug(),
                    "code": refusal.code,
                })
                .to_string(),
            ),
        };
        match audit.append_located(input) {
            Ok(at) => Some(at),
            Err(e) => {
                tracing::error!(target: "nrr::provisioning", error = %e, "could not audit the refused install-time files");
                None
            }
        }
    });
    let Some(alerts) = applier.alerts else {
        return;
    };
    let alert = SecurityAlert {
        alert_id: format!("alt-provisioning-{}", applier.now_ms),
        kind: kind.as_str().to_owned(),
        state: SecurityAlertState::Active,
        raised_event_seq: located.as_ref().map_or(0, |at| at.seq),
        raised_file: located.map(|at| at.file_name).unwrap_or_default(),
        ack_event_seq: None,
        ack_file: None,
        resolved_event_seq: None,
        resolved_file: None,
        created_at: applier.now_ms,
        updated_at: applier.now_ms,
        reason_code: import::VALIDATION_FAILED.as_str().to_owned(),
    };
    if let Err(e) = alerts.insert(&alert) {
        tracing::error!(target: "nrr::provisioning", error = %e, "could not raise the alert for refused install-time files");
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}
