//! The explain probe: which rule would win for a sample, and how much of that
//! answer the caller's privacy tier allows.
//!
//! Split out of `diagnostics_handlers`; the code is unchanged.

use super::*;

// ── ExplainGetHandler ────────────────────────────────────────────────────────

/// Dependency triple for the kill-switch enforcement
/// verdict: per-SID policy reader + FQDN-cache presence + active SID.
pub type ExplainEnforcementDeps = (
    Arc<dyn crate::ipc_handlers::providers::RoutePolicyProvider>,
    Arc<dyn crate::fqdn_cache_lookup::FqdnCacheLookup>,
    crate::dns_observation_consumer::ActiveSidFn,
);

pub struct ExplainGetHandler {
    diagnostics: Arc<dyn DiagnosticsFacade>,
    /// Optional inputs for the kill-switch enforcement
    /// verdict stamped onto the compact view. All-or-nothing: absent deps
    /// leave `compact.enforcement` empty (rule verdict only), matching every
    /// existing test/mock construction.
    enforcement: Option<ExplainEnforcementDeps>,
    /// Read-only view of the live hostname → fake-address (fake-IP)
    /// map so a synthetic hostname probe shows the virtual address the
    /// resolver is answering with. `None` (default) leaves the field empty.
    fake_ip: Option<crate::fake_ip::FakeIpBindingView>,
}

impl ExplainGetHandler {
    pub fn new(diagnostics: Arc<dyn DiagnosticsFacade>) -> Self {
        Self {
            diagnostics,
            enforcement: None,
            fake_ip: None,
        }
    }

    /// Enable the enforcement verdict (see the field doc).
    pub fn with_enforcement_verdict(
        mut self,
        policy: Arc<dyn crate::ipc_handlers::providers::RoutePolicyProvider>,
        fqdn: Arc<dyn crate::fqdn_cache_lookup::FqdnCacheLookup>,
        active_sid: crate::dns_observation_consumer::ActiveSidFn,
    ) -> Self {
        self.enforcement = Some((policy, fqdn, active_sid));
        self
    }

    /// Enable the fake-address (fake-IP) stamp (see the field doc).
    pub fn with_fake_ip_bindings(mut self, view: crate::fake_ip::FakeIpBindingView) -> Self {
        self.fake_ip = Some(view);
        self
    }

    /// The kill-switch verdict for a SYNTHETIC hostname probe, on top of the
    /// rule verdict (`route`). Config-based — deliberately independent of the
    /// live armed/disarmed runtime state, so the answer explains what the
    /// CURRENT SETTINGS do to this host whenever the switch arms:
    /// - kill-switch ON + coverage `fail-closed-unknown` (block-all) + the
    ///   hostname has NO cached IPs → no permit can compile → while armed the
    ///   catch-all drops it, even though the rule verdict says primary/none;
    /// - secondary-routed host + kill-switch ON → while the secondary is down
    ///   the fail-closed block holds it (never leaks via primary);
    /// - a primary/default host whose cached IPs the shared-IP census flags
    ///   (shared with secondary rules): under the strict policy those IPs are
    ///   pinned/blocked, under smart they are exempted (host works, leak
    ///   possible). Returns `(slug, shared_ip_count, total_ip_count)`; the
    ///   counts are non-zero only for the collateral slugs.
    fn enforcement_verdict(&self, hostname: &str, route: &str) -> (String, u32, u32) {
        let none = (String::new(), 0, 0);
        let Some((policy, fqdn, active_sid)) = self.enforcement.as_ref() else {
            return none;
        };
        if hostname.is_empty() {
            return none;
        }
        let Some(sid) = active_sid() else {
            return none;
        };
        let Some(dto) = policy.get_for_sid(&sid) else {
            return none;
        };
        if !dto.kill_switch_enabled {
            return none;
        }
        if route == "secondary" {
            return ("fail-closed-when-secondary-down".to_string(), 0, 0);
        }
        let cached_ips = fqdn.ips_for_hostname(hostname);
        let block_all_unknown = dto.mode_a_coverage_strategy == "fail-closed-unknown";
        if block_all_unknown && cached_ips.is_empty() {
            return ("blocked-unknown-under-block-all".to_string(), 0, 0);
        }
        // Shared-IP collateral for a primary/default host. The census
        // holds exactly the IPs that are BOTH secondary-owned and seen on a
        // direct host, so an intersection with this host's cached IPs is the
        // collateral set.
        if !cached_ips.is_empty() {
            let census = fqdn.shared_direct_ips();
            let shared = cached_ips
                .iter()
                .filter_map(|ip| match ip {
                    std::net::IpAddr::V4(v4) => Some(v4),
                    std::net::IpAddr::V6(_) => None,
                })
                .filter(|ip| census.contains(ip))
                .count() as u32;
            if shared > 0 {
                let slug = if dto.kill_switch_strict_shared_ips {
                    // Strict: these IPs stay pinned → blocked whenever the
                    // secondary is down.
                    "collateral-blocked-strict"
                } else {
                    // Smart (default): exempted from the kill-switch → the
                    // host keeps working, at the cost of unprotected
                    // secondary-rule traffic on those IPs.
                    "collateral-smart-exempt"
                };
                return (slug.to_string(), shared, cached_ips.len() as u32);
            }
        } else if !fqdn
            .hostnames_under_suffix(hostname, RISK_SUBDOMAIN_PROBE_LIMIT)
            .is_empty()
        {
            // Host itself is un-cached (never matches a rule — e.g. bare
            // search.example), but rule-cached subdomains exist under it
            // (gemini.search.example). Same-front-end CDNs serve both from one IP
            // pool, so collateral is likely even before it is observed.
            return ("collateral-risk-subdomain-rules".to_string(), 0, 0);
        }
        none
    }
}

/// How many cached subdomains are enough to call a probe host
/// "collateral at risk" (1 suffices; the tiny cap keeps the probe cheap).
const RISK_SUBDOMAIN_PROBE_LIMIT: usize = 4;

impl IpcHandler for ExplainGetHandler {
    fn handle(&self, request: &IpcRequestEnvelope, ctx: &IpcRequestContext) -> HandlerOutcome {
        const OP: &str = "diagnostics.explain.get";
        let req: ExplainGetRequest =
            serde_json::from_value(request.payload.clone()).map_err(|e| malformed(OP, e))?;

        // Discriminate the two variants. Ambiguity is treated as
        // structural malformation — defensive boundary check before
        // the facade.
        let query = match (req.decision_id.as_deref(), req.input_sample.as_ref()) {
            (None, None) => {
                return Err(malformed_msg(
                    OP,
                    "request must carry exactly one of decision-id / input-sample",
                ));
            }
            (Some(_), Some(_)) => {
                return Err(malformed_msg(
                    OP,
                    "request must NOT set both decision-id and input-sample",
                ));
            }
            (Some(id), None) => {
                if id.is_empty() {
                    return Err(malformed_msg(OP, "decision-id must not be empty"));
                }
                ExplainQuery::HistoricalDecision {
                    decision_id: DecisionId(id.to_string()),
                }
            }
            (None, Some(sample)) => {
                let mut input = RuntimeInputSample::new();
                if let Some(h) = sample.hostname.clone() {
                    input = input.with_hostname(h);
                }
                if let Some(ip) = sample.observed_ip.clone() {
                    input = input.with_ip(ip);
                }
                if let Some(p) = sample.process_name.clone() {
                    input = input.with_process(p);
                }
                ExplainQuery::Synthetic {
                    input_sample: input,
                }
            }
        };

        let level = parse_detail_level(req.detail_level.as_deref());
        // Pass the caller SID so the synthetic probe applies that user's
        // per-SID behavior_mode.
        let response = self
            .diagnostics
            .get_explain(&query, level, ctx.caller_stored())
            .map_err(|e| internal(OP, format!("facade.get_explain: {e}")))?;

        let mut compact = compact_view(&response);
        // Synthetic hostname probes additionally carry the kill-switch
        // verdict, so "primary" never hides "but block-all will drop this".
        if let ExplainQuery::Synthetic { input_sample } = &query {
            if let Some(host) = input_sample.hostname.as_deref() {
                let (slug, shared, total) = self.enforcement_verdict(host, &compact.route);
                compact.enforcement = slug;
                compact.enforcement_shared_ips = shared;
                compact.enforcement_total_ips = total;
                // The virtual address the resolver currently answers for
                // this host (fake-IP active), so "why 198.18.x.x?" is
                // explained in place. Read-only lookup, empty when unmapped.
                compact.fake_ip = self
                    .fake_ip
                    .as_ref()
                    .and_then(|v| v.fake_v4_for(host))
                    .map(|ip| ip.to_string())
                    .unwrap_or_default();
            }
        }
        let full = serde_json::to_value(&response)
            .map_err(|e| internal(OP, format!("explain response serialise: {e}")))?;

        let wire = ExplainGetResponse {
            compact,
            full,
            // diagnostic_ids enrichment via audit-log lookup is not yet
            // wired. The wire field stays — empty vector serialises as an
            // omitted field thanks to `skip_serializing_if = "Vec::is_empty"`.
            diagnostic_ids: Vec::new(),
        };
        serialise(OP, &wire)
    }
}

fn parse_detail_level(slug: Option<&str>) -> ExplainDetailLevel {
    match slug {
        Some("diagnostics") => ExplainDetailLevel::Diagnostics,
        Some("developer-trace") | Some("developer_trace") => ExplainDetailLevel::DeveloperTrace,
        _ => ExplainDetailLevel::CompactUi,
    }
}

/// Project the full `ExplainResponse` into the 3-field compact view
/// the diagnostics section's "explain sample" widget renders today
/// (input → route + reason key). The full response is shipped
/// alongside for future detail surfaces.
fn compact_view(response: &ExplainResponse) -> ExplainCompactViewDto {
    let input = response
        .input
        .as_ref()
        .and_then(|i| {
            i.destination_hostname
                .clone()
                .or_else(|| i.destination_ip.clone())
                .or_else(|| i.process_name.clone())
        })
        .unwrap_or_else(|| "-".to_string());

    let route = response
        .final_action_section
        .as_ref()
        .map(|f| {
            f.route_role
                .clone()
                .unwrap_or_else(|| match f.action_key.as_str() {
                    k if k.contains("block") => "blocked".to_string(),
                    _ => "none".to_string(),
                })
        })
        .unwrap_or_else(|| "none".to_string());

    let reason_key = response
        .final_action_section
        .as_ref()
        .map(|f| f.reason_key.clone())
        .unwrap_or_else(|| response.summary.summary_key.clone());

    ExplainCompactViewDto {
        input,
        route,
        reason_key,
        // Stamped by the handler for synthetic hostname probes (needs the
        // policy/cache deps the pure projection does not have).
        enforcement: String::new(),
        enforcement_shared_ips: 0,
        enforcement_total_ips: 0,
        fake_ip: String::new(),
    }
}
