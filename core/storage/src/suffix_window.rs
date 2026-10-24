//! Which cached names under a zone or suffix rule earn filters and routes when
//! there are more of them than the fan-out holds.
//!
//! The candidates come newest first. A page can make the browser resolve
//! thousands of names of one site of its own (`nNNN.attacker.ru`); taken by
//! recency alone they would fill the window and push the user's real hosts of
//! the zone out of its protection. So under that pressure one site, the label
//! right below the rule's own, holds at most a sixteenth of the window, and the
//! places left over go to the rest in order: a rule whose hosts are mostly one
//! site keeps them all when nobody else competes.

use std::collections::HashMap;

/// The share of the window one site may hold while others wait for a place.
const SITE_SHARE_DIVISOR: usize = 16;

/// Recency is compared to the hour: a host seen again in the same hour keeps
/// its place, so the window is not rebuilt, and its filters redone, on every
/// visit.
pub const RECENCY_BUCKET_MS: i64 = 3_600_000;

/// Up to `limit` names from `ordered` (newest first), under `suffix`.
pub fn fair_suffix_window<I>(ordered: I, suffix: &str, limit: usize) -> Vec<String>
where
    I: IntoIterator<Item = String>,
{
    if limit == 0 {
        return Vec::new();
    }
    let suffix = suffix.trim().trim_end_matches('.').to_ascii_lowercase();
    let cap = (limit / SITE_SHARE_DIVISOR).max(1);
    let mut held: HashMap<String, usize> = HashMap::new();
    let mut out = Vec::with_capacity(limit.min(1024));
    let mut waiting = Vec::new();
    for host in ordered {
        if out.len() == limit {
            break;
        }
        let count = held.entry(site_of(&host, &suffix)).or_insert(0);
        if *count < cap {
            *count += 1;
            out.push(host);
        } else if waiting.len() < limit {
            waiting.push(host);
        }
    }
    let room = limit - out.len();
    out.extend(waiting.into_iter().take(room));
    out
}

/// `attacker.ru` for `a.b.attacker.ru` under `ru`; the name itself when it is
/// not under the suffix.
fn site_of(host: &str, suffix: &str) -> String {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let Some(rest) = host
        .strip_suffix(suffix)
        .and_then(|rest| rest.strip_suffix('.'))
    else {
        return host;
    };
    let label = rest.rsplit('.').next().unwrap_or(rest);
    format!("{label}.{suffix}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn a_rule_of_one_site_keeps_its_hosts_when_nobody_competes() {
        let hosts: Vec<String> = (0..40).map(|i| format!("h{i}.cdn.example.com")).collect();
        let window = fair_suffix_window(hosts.clone(), "example.com", 32);
        assert_eq!(window, hosts[..32].to_vec());
    }

    #[test]
    fn each_tenant_of_a_hosting_platform_is_its_own_site() {
        assert_eq!(
            site_of("x.attacker.github.io", "github.io"),
            "attacker.github.io"
        );
        assert_eq!(
            site_of("attacker.github.io", "github.io"),
            "attacker.github.io"
        );
        assert_eq!(site_of("a.b.attacker.ru.", "ru"), "attacker.ru");
        assert_eq!(site_of("elsewhere.example", "ru"), "elsewhere.example");
    }

    #[test]
    fn the_newest_site_does_not_take_every_place() {
        let mut hosts: Vec<String> = (0..40).map(|i| format!("n{i}.attacker.ru")).collect();
        hosts.extend(names(&["real.ru", "other.ru"]));
        let window = fair_suffix_window(hosts, "ru", 16);
        assert_eq!(window.len(), 16);
        assert!(window.contains(&"real.ru".to_owned()));
        assert!(window.contains(&"other.ru".to_owned()));
    }
}
