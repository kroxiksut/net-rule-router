// The advisory route-role recommendation, and the one resolver that finds the
// adapter a saved binding names. Every producer of rows (the service's snapshot,
// the desktop's own enumeration) runs the same scoring, so a row reads alike
// whichever path delivered it.

use super::*;

/// Score every row and write its advisory recommendation.
///
/// A function of the rows alone: the user's bindings are not an input, because
/// the service answers every caller from one enumeration and a refresh must
/// not re-rank what a cold start showed. The role the user bound is shown
/// separately (`selected_role`).
pub fn assign_recommendations(rows: &mut [InterfaceRouteRow]) {
    let sole_uplink = sole_uplink_index(rows);
    let scores = rows
        .iter()
        .enumerate()
        .map(|(index, row)| score_row(row, sole_uplink == Some(index)))
        .collect::<Vec<_>>();
    let eligible = rows
        .iter()
        .enumerate()
        .map(|(index, row)| role_eligibility(row, sole_uplink == Some(index)))
        .collect::<Vec<_>>();

    // A row barred from a role must not take that role's maximum either:
    // winning it and then being classed "not recommended" left no preferred
    // adapter at all and pointed every other row at it.
    let best_primary_index = scores
        .iter()
        .enumerate()
        .filter(|(index, score)| !score.blocked && eligible[*index].primary)
        .max_by_key(|(index, score)| (score.primary, primary_tie_break(&rows[*index])))
        .map(|(index, _)| index);
    let best_secondary_index = scores
        .iter()
        .enumerate()
        .filter(|(index, score)| {
            !score.blocked && eligible[*index].secondary && Some(*index) != best_primary_index
        })
        .max_by_key(|(index, score)| (score.secondary, secondary_tie_break(&rows[*index])))
        .map(|(index, _)| index);

    let best_primary_name =
        best_primary_index.map(|index| format!("better-primary-candidate={}", rows[index].name));
    let best_secondary_name = best_secondary_index
        .map(|index| format!("better-secondary-candidate={}", rows[index].name));

    for (index, score) in scores.into_iter().enumerate() {
        let class = if score.blocked {
            RecommendationClass::NotRecommended
        } else if Some(index) == best_primary_index && score.primary >= 6 {
            RecommendationClass::PreferredPrimary
        } else if Some(index) == best_secondary_index && score.secondary >= 5 {
            RecommendationClass::PreferredSecondary
        } else {
            RecommendationClass::AllowedButNotRecommended
        };

        let mut excluded_alternatives = Vec::new();
        if class != RecommendationClass::PreferredPrimary && best_primary_index != Some(index) {
            excluded_alternatives.extend(best_primary_name.clone());
        }
        if class != RecommendationClass::PreferredSecondary && best_secondary_index != Some(index) {
            excluded_alternatives.extend(best_secondary_name.clone());
        }

        rows[index].recommendation = RouteRoleRecommendation {
            class,
            confidence: score.confidence,
            advisory_only: true,
            key_signals: score.key_signals,
            excluded_alternatives,
        };
    }
}

/// The row a saved binding names: by persistent id first, else by name.
///
/// Trimmed and case-insensitive on both, so a setting that reads "ethernet "
/// finds the adapter every surface shows. `excluded` keeps one row out (the
/// primary, when resolving the secondary).
#[must_use]
pub fn find_adapter_index(
    rows: &[InterfaceRouteRow],
    persistent_id: Option<&str>,
    name: Option<&str>,
    excluded: Option<usize>,
) -> Option<usize> {
    let find = |wanted: Option<&str>, field: fn(&InterfaceRouteRow) -> &str| {
        let wanted = wanted.map(str::trim).filter(|value| !value.is_empty())?;
        rows.iter()
            .enumerate()
            .find(|(index, row)| {
                Some(*index) != excluded && field(row).trim().eq_ignore_ascii_case(wanted)
            })
            .map(|(index, _)| index)
    };
    find(persistent_id, |row| &row.persistent_id).or_else(|| find(name, |row| &row.name))
}

/// Would the router actually route through this adapter?
///
/// A gateway-less tunnel (OpenVPN / WireGuard split defaults to the peer)
/// reports no default route yet forwards fine; `has_forwarding_path` is the
/// platform's own answer for that case. `None` falls back to the visible
/// default route.
fn carries_traffic(row: &InterfaceRouteRow) -> bool {
    row.has_forwarding_path.unwrap_or(row.has_default_route)
}

/// The one row that is this machine's way out, judged by structure alone: the
/// sole holder of a default route, else the sole row that forwards at all. It
/// is the uplink whatever its kind says (a PPPoE link, a bridge carrying the
/// host's address), so its kind neither bars nor penalises it.
fn sole_uplink_index(rows: &[InterfaceRouteRow]) -> Option<usize> {
    let only = |holds: fn(&InterfaceRouteRow) -> bool| {
        let mut holders = rows
            .iter()
            .enumerate()
            .filter(|(_, row)| holds(row))
            .map(|(index, _)| index);
        let first = holders.next()?;
        holders.next().is_none().then_some(first)
    };
    if rows.iter().any(|row| row.has_default_route) {
        only(|row| row.has_default_route)
    } else {
        only(carries_traffic)
    }
}

fn is_bluetooth(row: &InterfaceRouteRow) -> bool {
    row.is_bluetooth_like || row.kind == AdapterKind::Bluetooth
}

struct RoleEligibility {
    primary: bool,
    secondary: bool,
}

/// Which roles a row may be recommended for. A tunnel is a secondary and never
/// the primary; a VM's or container's adapter is neither; a Bluetooth link is
/// never preferred, whatever it holds.
fn role_eligibility(row: &InterfaceRouteRow, sole_uplink: bool) -> RoleEligibility {
    let (primary, secondary) = if is_bluetooth(row) {
        (false, false)
    } else if sole_uplink {
        (true, true)
    } else {
        match row.kind {
            AdapterKind::Tunnel => (false, true),
            AdapterKind::Virtual => (false, false),
            _ => (true, true),
        }
    };
    RoleEligibility { primary, secondary }
}

struct RowScore {
    primary: i32,
    secondary: i32,
    blocked: bool,
    confidence: RecommendationConfidence,
    key_signals: Vec<String>,
}

fn score_row(row: &InterfaceRouteRow, sole_uplink: bool) -> RowScore {
    let mut primary = 0;
    let mut secondary = 0;
    let mut key_signals = Vec::new();
    let mut signal = |slug: &str| key_signals.push(slug.to_string());

    let vpn_likelihood = row.derived_assessment.vpn_tunnel_likelihood;
    let tunnel_kind = row.kind == AdapterKind::Tunnel && !sole_uplink;
    let tunnel_shaped = tunnel_kind || vpn_likelihood == DerivedLikelihood::Likely;
    if sole_uplink {
        signal("sole-uplink-by-structure");
    } else if tunnel_kind {
        signal("adapter-kind-tunnel");
    } else if row.kind == AdapterKind::Virtual {
        signal("adapter-kind-virtual");
    }

    let mut blocked = false;
    if row.availability_status == BasicAvailabilityStatus::Unavailable {
        blocked = true;
        signal("blocked-unavailable-interface");
    }
    if row.runtime_data_unavailable {
        // Every row reads "-" because the query failed; blocking on that would
        // report "no usable adapter" for a machine whose link is fine.
        signal("adapter-data-unreadable");
    } else if row.local_ip == "-" {
        blocked = true;
        signal("blocked-missing-local-ip");
    }
    // Two of the signals behind this verdict are what an unreadable query
    // looks like, so it cannot block when the data never arrived.
    if row.derived_assessment.service_interface_likelihood == DerivedLikelihood::Likely
        && !row.runtime_data_unavailable
    {
        blocked = true;
        signal("blocked-service-interface-likely");
    }

    let (p, s, slug) = match row.observed_facts.connectivity_state {
        ConnectivityState::Available => (4, 2, "connectivity-available"),
        ConnectivityState::Degraded => (2, 2, "connectivity-degraded"),
        ConnectivityState::Timeout => (-1, -1, "connectivity-timeout"),
        ConnectivityState::Unknown => (-1, -1, "connectivity-unknown"),
        ConnectivityState::Unavailable => (-4, -3, "connectivity-unavailable"),
    };
    primary += p;
    secondary += s;
    signal(slug);

    if row.has_default_route {
        primary += 3;
        signal("has-default-route");
    } else if carries_traffic(row) {
        primary += 3;
        signal("forwarding-path-without-gateway");
    } else if row.has_forwarding_path == Some(false) && !tunnel_shaped {
        // Evaluated, no way out, and not tunnel-shaped (host-only switch):
        // preferring it as the secondary would route rules into nothing. A
        // tunnel is exempt because it is normally still down while the user
        // binds it.
        primary -= 2;
        secondary -= 3;
        signal("no-forwarding-path");
    } else {
        primary -= 2;
        secondary += 1;
        signal("no-default-route");
    }

    match row.observed_facts.external_ip_status {
        ExternalIpStatus::Resolved => {
            primary += 2;
            secondary += 1;
            signal("external-ip-resolved");
        }
        ExternalIpStatus::NotChecked => signal("external-ip-not-checked"),
        ExternalIpStatus::CheckFailed
        | ExternalIpStatus::RateLimited
        | ExternalIpStatus::Blocked => {
            primary -= 1;
            signal("external-ip-check-not-successful");
        }
    }

    match vpn_likelihood {
        DerivedLikelihood::Likely => signal("vpn-tunnel-likely"),
        DerivedLikelihood::Possible => signal("vpn-tunnel-possible"),
        DerivedLikelihood::Unlikely | DerivedLikelihood::Unknown => {}
    }
    // The name and the kind are two readings of one fact: counted once.
    let (p, s) = if tunnel_shaped {
        (-4, 4)
    } else {
        match vpn_likelihood {
            DerivedLikelihood::Possible => (-1, 2),
            DerivedLikelihood::Unlikely => (1, 0),
            DerivedLikelihood::Likely | DerivedLikelihood::Unknown => (0, 0),
        }
    };
    primary += p;
    secondary += s;

    if row.derived_assessment.virtual_interface_likelihood == DerivedLikelihood::Likely {
        primary -= 3;
        secondary -= 2;
        signal("virtual-interface-likely");
    }
    if is_bluetooth(row) {
        primary -= 4;
        secondary -= 2;
        signal("bluetooth-adapter-nondefault-routing-profile");
    }
    if !row.persistent_id.trim().is_empty() {
        primary += 1;
        secondary += 1;
        signal("stable-identity-present");
    }

    let confidence = if blocked {
        RecommendationConfidence::High
    } else {
        match primary.max(secondary) {
            9.. => RecommendationConfidence::High,
            6..=8 => RecommendationConfidence::Medium,
            3..=5 => RecommendationConfidence::Low,
            _ => RecommendationConfidence::Unknown,
        }
    };

    RowScore {
        primary,
        secondary,
        blocked,
        confidence,
        key_signals,
    }
}

fn primary_tie_break(row: &InterfaceRouteRow) -> i32 {
    let mut weight = 0;
    if !row.persistent_id.trim().is_empty() {
        weight += 10;
    }
    if carries_traffic(row) {
        weight += 5;
    }
    weight
}

fn secondary_tie_break(row: &InterfaceRouteRow) -> i32 {
    let mut weight = 0;
    if !row.persistent_id.trim().is_empty() {
        weight += 10;
    }
    if row.kind == AdapterKind::Tunnel
        || row.derived_assessment.vpn_tunnel_likelihood == DerivedLikelihood::Likely
    {
        weight += 8;
    }
    weight
}

#[cfg(test)]
mod tests;
