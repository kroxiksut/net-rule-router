//! Importing a preset file as a revision.
//!
//! Decode the wire payload, canonicalize each route's bytes, merge with the
//! active revision's other-route rules (single-route imports) or assemble
//! both routes, encode to canonical `rules_json`, then run the standard
//! preview/execute flow. The assembly is the part with the rules, and it
//! is why this is its own file.
//!
//! Same inherent impl, split across files. Behaviour is unchanged.

use super::*;

// Carried over from the impl this was split out of — the same code under the
// same exemption, not a new one.
#[allow(clippy::unwrap_used, clippy::expect_used)]
impl ProductionMutationExecutor {
    /// Preview path for `MutationKind::PresetImport`. Decodes the wire
    /// payload, canonicalizes each route's bytes, merges with the
    /// active revision's other-route rules (single-route imports only)
    /// or assembles both routes (both-routes imports), encodes into
    /// canonical `rules_json`, then runs the standard
    /// preview flow — planned from the payload, stored only on execute.
    // `pub(super)` because the impl is split across files and the caller
    // is now another module.
    pub(super) fn preview_preset_import(
        &self,
        payload: &serde_json::Value,
        principal: &str,
    ) -> ReviewSummaryResponse {
        let assembled = match self.assemble_preset_import(payload, principal) {
            Ok(a) => a,
            Err(e) => return preset_failure_summary(&e),
        };
        if let Err(e) = Self::enforce_free_rule_cap(&assembled.rules_json) {
            return malformed_summary(&e.message);
        }
        let scored = self.score_candidate_for_payload(&assembled.rules_json, principal);
        // Planned from the assembled rules, not from a stored candidate — see
        // the rules-preview path above.
        let summary =
            self.coordinator
                .dry_run_rules(principal, &assembled.rules_json, "ipc-dry-run");
        dry_run_to_review_summary(&summary, scored)
    }

    /// Execute path for `MutationKind::PresetImport`. Same assembly as
    /// preview, then issues a confirmation token and activates.
    // `pub(super)` because the impl is split across files and the caller
    // is now another module.
    pub(super) fn execute_preset_import(
        &self,
        payload: &serde_json::Value,
        principal: &str,
    ) -> MutationOutcome {
        let assembled = match self.assemble_preset_import(payload, principal) {
            Ok(a) => a,
            Err(e) => return MutationOutcome::Failed(e),
        };
        if let Err(e) = Self::enforce_free_rule_cap(&assembled.rules_json) {
            return MutationOutcome::Failed(e);
        }
        let correlation = assembled
            .correlation_id
            .clone()
            .unwrap_or_else(|| "ipc-execute".to_string());
        let submission = preset_submission_from(&assembled, &correlation, principal);
        let revision_id = match self.coordinator.submit_candidate(submission) {
            Ok(id) => id,
            Err(e) => return policy_error_outcome(&e),
        };
        tracing::info!(
            target: "nrr::mutation::preset",
            revision_id = %revision_id,
            content_hash = %assembled.content_hash,
            "preset candidate submitted (a deduped id == an existing/active \
             revision means no new rules were detected)"
        );
        if let Some(outcome) =
            self.drive_deduped_revision_active(&revision_id, &correlation, principal)
        {
            return outcome;
        }
        let token = match self
            .coordinator
            .issue_confirmation_token(&revision_id, COORDINATOR_TOKEN_TTL_SECS)
        {
            Ok(t) => t,
            Err(e) => return policy_error_outcome(&e),
        };
        match self
            .coordinator
            .activate(&revision_id, &token, &correlation)
        {
            Ok(outcome) => {
                tracing::info!(
                    target: "nrr::mutation::preset",
                    revision_id = %revision_id,
                    "preset activate OK"
                );
                activation_to_outcome(outcome)
            }
            Err(e) => {
                tracing::warn!(
                    target: "nrr::mutation::preset",
                    revision_id = %revision_id,
                    error = ?e,
                    "preset activate FAILED"
                );
                policy_error_outcome(&e)
            }
        }
    }

    /// Common assembly: payload deserialization → byte decoding →
    /// validate → canonicalize → merge with active → encode. Returns
    /// the materials needed by both `preview_preset_import` and
    /// `execute_preset_import`.
    fn assemble_preset_import(
        &self,
        payload: &serde_json::Value,
        principal: &str,
    ) -> Result<AssembledPresetImport, OperationError> {
        let parsed: PresetImportPayload =
            serde_json::from_value(payload.clone()).map_err(|e| OperationError {
                code: "malformed-payload".into(),
                message: format!("PresetImport payload invalid: {e}"),
            })?;
        let target = parsed.target().map_err(|e| OperationError {
            code: "malformed-payload".into(),
            message: match e {
                PresetImportPayloadError::NoBytesSupplied => {
                    "PresetImport: no bytes supplied".into()
                }
                PresetImportPayloadError::RouteMismatch => {
                    "PresetImport: route hint mismatches populated bytes field".into()
                }
            },
        })?;

        // Decode + canonicalize each route's bytes.
        let primary_set = match (parsed.primary_bytes_b64.as_deref(), &target) {
            (Some(b64), _) => Some(canonicalize_route_bytes(
                b64,
                RouteRole::Primary,
                parsed.include_child_processes,
                parsed.import_only_active,
            )?),
            _ => None,
        };
        let secondary_set = match (parsed.secondary_bytes_b64.as_deref(), &target) {
            (Some(b64), _) => Some(canonicalize_route_bytes(
                b64,
                RouteRole::Secondary,
                parsed.include_child_processes,
                parsed.import_only_active,
            )?),
            _ => None,
        };

        // Build the full canonical book. For single-route imports, the
        // OTHER route is carried over from the currently-active revision
        // (or starts empty if none).
        // Each match arm's `expect()` is an invariant: the `target` discriminant
        // already proves the matching `*_set` Option is `Some` (decoded above).
        #[allow(clippy::expect_used)]
        let book = match target {
            PresetImportTarget::BothRoutes => CanonicalRuleBook {
                primary: primary_set.expect("BothRoutes implies primary bytes"),
                secondary: secondary_set.expect("BothRoutes implies secondary bytes"),
            },
            PresetImportTarget::SingleRoute(RouteRole::Primary) => {
                let other = load_active_secondary(self.state_conn.as_ref(), principal);
                CanonicalRuleBook {
                    primary: primary_set.expect("SingleRoute(Primary) implies primary bytes"),
                    secondary: other,
                }
            }
            PresetImportTarget::SingleRoute(RouteRole::Secondary) => {
                let other = load_active_primary(self.state_conn.as_ref(), principal);
                CanonicalRuleBook {
                    primary: other,
                    secondary: secondary_set
                        .expect("SingleRoute(Secondary) implies secondary bytes"),
                }
            }
        };

        let content = RulesRevisionContent::new(book);
        let dto = rules_json_codec::encode(&content);
        let rules_json = rules_json::to_canonical_string(&dto).map_err(|e| OperationError {
            code: "internal".into(),
            message: format!("PresetImport canonical serialise failed: {e}"),
        })?;
        let mut hasher = Sha256::new();
        hasher.update(rules_json.as_bytes());
        let content_hash = format!("{:x}", hasher.finalize());

        tracing::info!(
            target: "nrr::mutation::preset",
            rules_json_len = rules_json.len(),
            content_hash = %content_hash,
            "preset assembled canonical book (rules_json_len is the populated \
             size; an empty book serialises to ~50 bytes)"
        );
        Ok(AssembledPresetImport {
            rules_json,
            content_hash,
            correlation_id: parsed.correlation_id,
        })
    }
}
