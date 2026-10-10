//! The service accounts' share of the owner's guard, as WFP filters.
//!
//! The same emitters as the owner's pins, re-scoped: only the ALE filters carry
//! a user condition, so only they are twinned — the transport-layer halves are
//! machine-wide and already the owner's.

use nrr_platform_api::types::SERVICE_ACCOUNTS_PRINCIPAL;

use crate::enforcement_planner::{ServiceAccountGuard, ServiceAccountPosture};

use super::*;

/// The id seed of `owner`'s service-account twins. Their own, so an owner
/// change retires one set and installs the other instead of two owners
/// claiming the same ids.
#[must_use]
pub fn service_account_seed(owner: &str) -> String {
    format!("{owner}|svc")
}

/// `guard` as filters scoped to the service accounts. A pin needs the tunnel's
/// LUID and fails open without one, like the owner's. `exempt_apps` — our own
/// executable and the tunnel clients — sit in the app-exemption band, above
/// every pin.
#[must_use]
pub fn service_account_filters(
    owner: &str,
    guard: &ServiceAccountGuard,
    secondary_luid: u64,
    protocols: KillSwitchProtocols,
    exempt_apps: &[String],
) -> Vec<WfpFilterSpec> {
    let seed = service_account_seed(owner);
    let mut out = match guard.posture {
        ServiceAccountPosture::Pin => {
            let mut out =
                kill_switch_filters(&seed, &guard.destinations, secondary_luid, protocols);
            out.extend(kill_switch_network_filters(
                &seed,
                &guard.holds,
                secondary_luid,
                protocols,
            ));
            out
        }
        ServiceAccountPosture::Block => {
            let mut out = fail_closed_block_destinations(&seed, &guard.destinations, protocols);
            out.extend(fail_closed_network_filters(&seed, &guard.holds, protocols));
            out
        }
    };
    out.extend(primary_app_exempt_filters(&seed, exempt_apps));
    out.retain(|spec| spec.layer.supports_ale_scoping());
    for spec in &mut out {
        spec.user_sid = Some(SERVICE_ACCOUNTS_PRINCIPAL.to_string());
    }
    out
}
