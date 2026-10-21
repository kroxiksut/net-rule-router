//! The hosts-file bypass for rule-host resolution is one machine-wide switch
//! (the resolvers and the address cache are shared), read from every served
//! user's own setting.

use std::sync::Mutex;

use rusqlite::Connection;

/// Bypass is on when ANY served user wants it: it only adds a routable public
/// address, while a user who turned it off still gets the hosts file's answer
/// from their own lookups. Nobody served, or an unreadable row, is the default (on).
pub fn bypass_wanted_by_any(
    users: &[String],
    mut setting: impl FnMut(&str) -> Option<bool>,
) -> bool {
    users.is_empty() || users.iter().any(|sid| setting(sid).unwrap_or(true))
}

/// [`bypass_wanted_by_any`] over the stored per-user policy.
pub fn stored_bypass_wanted_by_any(conn: &Mutex<Connection>, users: &[String]) -> bool {
    let Ok(guard) = conn.lock() else {
        return true;
    };
    let repo = nrr_storage::route_bindings::RouteBindingsRepository::new(&guard);
    bypass_wanted_by_any(users, |sid| {
        repo.load_for_sid(sid)
            .ok()
            .map(|record| record.resolve_hosts_bypass)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn users(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn a_second_user_who_wants_bypass_keeps_it_on_when_the_first_turned_it_off() {
        let off_for_a = |sid: &str| Some(sid != "A");
        assert!(bypass_wanted_by_any(&users(&["A", "B"]), off_for_a));
        assert!(!bypass_wanted_by_any(&users(&["A"]), off_for_a));
    }

    #[test]
    fn nobody_served_or_an_unreadable_row_is_the_default() {
        assert!(bypass_wanted_by_any(&[], |_| Some(false)));
        assert!(bypass_wanted_by_any(&users(&["A"]), |_| None));
    }
}
