//! Per-user routing readiness shown by both clients.

use nrr_shared::ipc_payloads::SnapshotInitialResponse;

/// Service health is reported beside routing readiness, never used as a
/// substitute for it. Counts stay unknown when the service did not provide
/// them. Twin of `routingReadiness` in `pure.js`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RoutingReadiness {
    pub service: &'static str,
    pub routing: &'static str,
    pub primary: &'static str,
    pub secondary: &'static str,
    pub affected_assignments: Option<u32>,
}

#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn routing_readiness(
    service_healthy: bool,
    primary_bound: bool,
    primary_status: &str,
    secondary_required: bool,
    secondary_bound: bool,
    secondary_status: &str,
    active_rule_count: Option<u32>,
    secondary_rule_count: Option<u32>,
) -> RoutingReadiness {
    let primary = role_state(primary_bound, primary_status);
    let secondary = if secondary_required {
        role_state(secondary_bound, secondary_status)
    } else {
        "not-required"
    };
    let routing = if primary == "ready" && matches!(secondary, "ready" | "not-required") {
        "ready"
    } else if primary == "unknown" || secondary == "unknown" {
        "unknown"
    } else {
        "limited"
    };
    let affected_assignments = match routing {
        "ready" => Some(0),
        _ if primary != "ready" => active_rule_count,
        _ => secondary_rule_count,
    };
    RoutingReadiness {
        service: if service_healthy {
            "healthy"
        } else {
            "unhealthy"
        },
        routing,
        primary,
        secondary,
        affected_assignments,
    }
}

fn role_state(bound: bool, status: &str) -> &'static str {
    if !bound {
        "not-chosen"
    } else if status == "ok" {
        "ready"
    } else if status.is_empty() {
        "unknown"
    } else {
        "not-ready"
    }
}

/// Reads the service's per-SID snapshot into the neutral decision above.
#[must_use]
pub fn snapshot_routing_readiness(snapshot: &SnapshotInitialResponse) -> RoutingReadiness {
    let status = |role: &str, bound: bool| {
        snapshot
            .enforcement_status
            .iter()
            .find(|report| report.role == role)
            .map_or(if bound { "ok" } else { "" }, |report| {
                report.status.as_str()
            })
    };
    snapshot_routing_readiness_with_status(
        snapshot,
        status("primary", snapshot_role_bound(snapshot, "primary")),
        status("secondary", snapshot_role_bound(snapshot, "secondary")),
    )
}

/// Reads snapshot facts while the caller supplies the latest standing role
/// states. This keeps a push received after the snapshot authoritative.
#[must_use]
pub fn snapshot_routing_readiness_with_status(
    snapshot: &SnapshotInitialResponse,
    primary_status: &str,
    secondary_status: &str,
) -> RoutingReadiness {
    let policy = snapshot.route_policy.as_ref();
    let active_count = snapshot.active_rule_count;
    let no_rules = active_count == Some(0);
    let primary_bound = no_rules || policy.and_then(|p| p.primary.as_ref()).is_some();
    let secondary_required = snapshot
        .active_secondary_rule_count
        .is_some_and(|count| count > 0);
    let secondary_bound = policy.and_then(|p| p.secondary.as_ref()).is_some();
    routing_readiness(
        snapshot.health.worst_severity == "ok",
        primary_bound,
        primary_status,
        secondary_required,
        secondary_bound,
        secondary_status,
        active_count,
        snapshot.active_secondary_rule_count,
    )
}

fn snapshot_role_bound(snapshot: &SnapshotInitialResponse, role: &str) -> bool {
    let no_rules = snapshot.active_rule_count == Some(0);
    let binding = snapshot
        .route_policy
        .as_ref()
        .and_then(|policy| match role {
            "primary" => policy.primary.as_ref(),
            "secondary" => policy.secondary.as_ref(),
            _ => None,
        });
    (role == "primary" && no_rules) || binding.is_some()
}
