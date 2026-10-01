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
    let scores = rows.iter().map(score_row).collect::<Vec<_>>();

    // A Bluetooth link is never preferred, so it must not take the maximum
    // either: winning it and then being classed "not recommended" left no
    // preferred primary at all and pointed every other row at it.
    let contenders = || {
        scores
            .iter()
            .enumerate()
            .filter(|(index, score)| !score.blocked && !rows[*index].is_bluetooth_like)
    };
    let best_primary_index = contenders()
        .max_by_key(|(index, score)| (score.primary, primary_tie_break(&rows[*index])))
        .map(|(index, _)| index);
    let best_secondary_index = contenders()
        .filter(|(index, _)| Some(*index) != best_primary_index)
        .max_by_key(|(index, score)| (score.secondary, secondary_tie_break(&rows[*index])))
        .map(|(index, _)| index);

    let best_primary_name =
        best_primary_index.map(|index| format!("better-primary-candidate={}", rows[index].name));
    let best_secondary_name = best_secondary_index
        .map(|index| format!("better-secondary-candidate={}", rows[index].name));

    for (index, score) in scores.into_iter().enumerate() {
        let class = if score.blocked {
            RecommendationClass::NotRecommended
        } else if rows[index].is_bluetooth_like {
            RecommendationClass::AllowedButNotRecommended
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

struct RowScore {
    primary: i32,
    secondary: i32,
    blocked: bool,
    confidence: RecommendationConfidence,
    key_signals: Vec<String>,
}

fn score_row(row: &InterfaceRouteRow) -> RowScore {
    let mut primary = 0;
    let mut secondary = 0;
    let mut key_signals = Vec::new();
    let mut signal = |slug: &str| key_signals.push(slug.to_string());

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
    } else if row.has_forwarding_path == Some(false)
        && row.derived_assessment.vpn_tunnel_likelihood != DerivedLikelihood::Likely
    {
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

    match row.derived_assessment.vpn_tunnel_likelihood {
        DerivedLikelihood::Likely => {
            primary -= 4;
            secondary += 4;
            signal("vpn-tunnel-likely");
        }
        DerivedLikelihood::Possible => {
            primary -= 1;
            secondary += 2;
            signal("vpn-tunnel-possible");
        }
        DerivedLikelihood::Unlikely => primary += 1,
        DerivedLikelihood::Unknown => {}
    }

    if row.derived_assessment.virtual_interface_likelihood == DerivedLikelihood::Likely {
        primary -= 3;
        secondary -= 2;
        signal("virtual-interface-likely");
    }
    if row.is_bluetooth_like {
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
    if row.derived_assessment.vpn_tunnel_likelihood == DerivedLikelihood::Likely {
        weight += 8;
    }
    weight
}

#[cfg(test)]
mod tests;
