//! The global DNS suffix search list, kept filled while our catch-all rule is
//! in force.
//!
//! A name the catch-all NRPT rule captures is completed only with the global
//! search list and the primary suffix — never with the suffix a connection
//! carries. On a machine with neither, every single-label name fails before it
//! reaches any resolver (`ERROR_INVALID_NAME`), so `ping printer` stops working
//! the moment the product arms. Writing the connections' suffixes into the
//! global list gives the names back.
//!
//! A list someone else set is never edited: a local one already decides
//! completion without us, and a policy one overrides whatever we would write.
//! What we wrote is noted on disk, so a successor can take back a list left by
//! an instance that was killed rather than stopped.

use crate::error::PlatformError;

/// What completion looks like on the machine right now.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SearchListView {
    /// The configured global list.
    pub global: Vec<String>,
    /// The primary DNS suffix.
    pub primary: Option<String>,
    /// A domain policy owns the list.
    pub policy_managed: bool,
}

/// The OS side — the registry, the DNS client and the note on disk.
pub trait SearchListStore: Send + Sync {
    fn read(&self) -> Result<SearchListView, PlatformError>;
    /// Make `suffixes` the global list in force; empty clears it.
    fn write(&self, suffixes: &[String]) -> Result<(), PlatformError>;
    /// Every suffix a list we wrote may hold. Empty when we hold none.
    fn noted(&self) -> Vec<String>;
    fn note(&self, suffixes: &[String]) -> Result<(), PlatformError>;
}

/// What a sync did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SearchListOutcome {
    Unchanged,
    Written(Vec<String>),
    Cleared,
    /// A list we did not write is in force; completion is left to it.
    NotOurs,
}

/// A list is ours when we noted every entry of it. The note is a superset
/// while a write is in flight, so a crash between the steps still reads as ours.
fn is_ours(global: &[String], noted: &[String]) -> bool {
    !global.is_empty() && global.iter().all(|s| noted.contains(s))
}

fn push_unique(list: &mut Vec<String>, suffix: &str) {
    if !suffix.is_empty() && !list.iter().any(|s| s == suffix) {
        list.push(suffix.to_string());
    }
}

/// Bring the global list to what completion needs now: the primary suffix
/// first, as the DNS client puts it, then `connections`, then `extra`.
///
/// `connections` are the suffixes of the connections exempt from the
/// catch-all — the DNS client skips those when completing, and a suffix not
/// exempt would send internal names to the public upstream. The caller passes
/// the set it exempted, so the machine is enumerated once for both.
///
/// With nothing but the primary suffix to add the list stays empty — the DNS
/// client applies that one on its own.
pub fn sync_search_list(
    store: &dyn SearchListStore,
    connections: &[String],
    extra: &[String],
) -> Result<SearchListOutcome, PlatformError> {
    let view = store.read()?;
    let noted = store.noted();
    let ours = is_ours(&view.global, &noted);
    if view.policy_managed || (!view.global.is_empty() && !ours) {
        // A policy only hides the local list: ours comes back into force when
        // the policy goes, so the note stays until the local list itself
        // leaves what we wrote.
        if !ours && !noted.is_empty() {
            store.note(&[])?;
        }
        return Ok(SearchListOutcome::NotOurs);
    }
    let mut wanted = Vec::new();
    for suffix in connections.iter().chain(extra) {
        push_unique(&mut wanted, suffix);
    }
    if let Some(primary) = view.primary.as_deref() {
        wanted.retain(|s| s != primary);
        if !wanted.is_empty() {
            wanted.insert(0, primary.to_string());
        }
    }
    if wanted == view.global {
        if wanted.is_empty() && !noted.is_empty() {
            store.note(&[])?;
        }
        return Ok(SearchListOutcome::Unchanged);
    }
    if wanted.is_empty() {
        store.write(&[])?;
        store.note(&[])?;
        return Ok(SearchListOutcome::Cleared);
    }
    let mut in_flight = noted;
    for suffix in &wanted {
        push_unique(&mut in_flight, suffix);
    }
    store.note(&in_flight)?;
    store.write(&wanted)?;
    store.note(&wanted)?;
    Ok(SearchListOutcome::Written(wanted))
}

/// Take back a list we wrote. `Ok(true)` when there was one.
///
/// Reads the note first and touches nothing else without it, so the common
/// case — nothing written — costs one file probe. Our local list is cleared
/// under a policy too: nothing would take it back once the policy goes.
pub fn release_search_list(store: &dyn SearchListStore) -> Result<bool, PlatformError> {
    let noted = store.noted();
    if noted.is_empty() {
        return Ok(false);
    }
    let view = store.read()?;
    let ours = is_ours(&view.global, &noted);
    if ours {
        store.write(&[])?;
    }
    store.note(&[])?;
    Ok(ours)
}

#[cfg(any(target_os = "windows", test))]
/// A suffix is only ever letters, digits, hyphens and dots — anything else is
/// refused before it reaches a script.
fn is_plain_suffix(suffix: &str) -> bool {
    !suffix.is_empty()
        && suffix
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
}

#[cfg(any(target_os = "windows", test))]
fn validated(suffixes: &[String]) -> Result<(), PlatformError> {
    match suffixes.iter().find(|s| !is_plain_suffix(s)) {
        Some(bad) => Err(PlatformError::Transient {
            operation: "dns.search_list.validate",
            detail: format!("not a DNS suffix: {bad:?}"),
        }),
        None => Ok(()),
    }
}

#[cfg(any(target_os = "windows", test))]
/// The list as `SetDnsSettings` takes it: comma-separated, empty to clear.
pub fn comma_list(suffixes: &[String]) -> Result<String, PlatformError> {
    validated(suffixes)?;
    Ok(suffixes.join(","))
}

#[cfg(any(target_os = "windows", test))]
/// The script that makes `suffixes` the list in force, for Windows builds
/// without `SetDnsSettings`. Through the DNS client's own cmdlet: a registry
/// write alone stays unseen until the next reboot.
pub fn write_script(suffixes: &[String]) -> Result<String, PlatformError> {
    validated(suffixes)?;
    let list = if suffixes.is_empty() {
        "''".to_string()
    } else {
        suffixes
            .iter()
            .map(|s| format!("'{s}'"))
            .collect::<Vec<_>>()
            .join(",")
    };
    Ok(format!(
        "$ErrorActionPreference='Stop'; Set-DnsClientGlobalSetting -SuffixSearchList @({list})"
    ))
}

#[cfg(target_os = "windows")]
pub use live::WindowsSearchList;

#[cfg(target_os = "windows")]
mod live {
    use super::{comma_list, write_script, SearchListStore, SearchListView};
    use crate::dns_redirect::{CommandRunner, PowerShellRunner};
    use crate::error::PlatformError;

    /// Note of the list we wrote, beside the service's other state.
    const NOTE_FILE: &str = "dns-search-list.owned";

    fn note_path() -> Option<std::path::PathBuf> {
        nrr_platform_api::paths::production_data_root().map(|root| root.join(NOTE_FILE))
    }

    #[derive(Debug, Default, Clone, Copy)]
    pub struct WindowsSearchList;

    impl SearchListStore for WindowsSearchList {
        fn read(&self) -> Result<SearchListView, PlatformError> {
            Ok(SearchListView {
                global: crate::dns_scope::global_search_list(),
                primary: crate::dns_scope::primary_dns_suffix(),
                policy_managed: crate::dns_scope::search_list_is_policy_managed(),
            })
        }

        fn write(&self, suffixes: &[String]) -> Result<(), PlatformError> {
            // No child process: the resolver stop path clears the list within
            // a budget a PowerShell start alone can exceed.
            let list = comma_list(suffixes)?;
            if let Some(applied) = crate::win32_ffi::dns_settings::set_global_search_list(&list) {
                return applied;
            }
            let out = PowerShellRunner.run_powershell(&write_script(suffixes)?)?;
            if out.success {
                Ok(())
            } else {
                Err(PlatformError::Transient {
                    operation: "dns.search_list.write",
                    detail: out.stderr.trim().to_string(),
                })
            }
        }

        fn noted(&self) -> Vec<String> {
            note_path()
                .and_then(|path| std::fs::read_to_string(path).ok())
                .map(|text| {
                    text.lines()
                        .map(str::trim)
                        .filter(|l| !l.is_empty())
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default()
        }

        fn note(&self, suffixes: &[String]) -> Result<(), PlatformError> {
            let Some(path) = note_path() else {
                return Err(PlatformError::Transient {
                    operation: "dns.search_list.note",
                    detail: "no data directory".to_string(),
                });
            };
            let result = if suffixes.is_empty() {
                match std::fs::remove_file(&path) {
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                    other => other,
                }
            } else {
                if let Some(dir) = path.parent() {
                    let _ = std::fs::create_dir_all(dir);
                }
                std::fs::write(&path, suffixes.join("\n"))
            };
            result.map_err(|e| PlatformError::Transient {
                operation: "dns.search_list.note",
                detail: e.to_string(),
            })
        }
    }
}

/// The store in memory, for the tests of this module and of the redirect.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct FakeList {
    view: std::sync::Mutex<SearchListView>,
    noted: std::sync::Mutex<Vec<String>>,
    writes: std::sync::Mutex<Vec<Vec<String>>>,
    fail_write: bool,
}

#[cfg(test)]
impl FakeList {
    fn with(view: SearchListView) -> Self {
        Self {
            view: std::sync::Mutex::new(view),
            ..Self::default()
        }
    }
    fn global(&self) -> Vec<String> {
        self.view
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .global
            .clone()
    }
    fn noted_now(&self) -> Vec<String> {
        self.noted.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }
    fn writes(&self) -> usize {
        self.writes.lock().unwrap_or_else(|p| p.into_inner()).len()
    }
}

#[cfg(test)]
impl SearchListStore for FakeList {
    fn read(&self) -> Result<SearchListView, PlatformError> {
        Ok(self.view.lock().unwrap_or_else(|p| p.into_inner()).clone())
    }
    fn write(&self, suffixes: &[String]) -> Result<(), PlatformError> {
        if self.fail_write {
            return Err(PlatformError::Transient {
                operation: "test",
                detail: "refused".into(),
            });
        }
        self.writes
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(suffixes.to_vec());
        self.view.lock().unwrap_or_else(|p| p.into_inner()).global = suffixes.to_vec();
        Ok(())
    }
    fn noted(&self) -> Vec<String> {
        self.noted_now()
    }
    fn note(&self, suffixes: &[String]) -> Result<(), PlatformError> {
        *self.noted.lock().unwrap_or_else(|p| p.into_inner()) = suffixes.to_vec();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    fn corp() -> Vec<String> {
        strings(&["branch.corp.example"])
    }

    /// The field case: a VPN suffix, no global list, no primary suffix.
    #[test]
    fn a_connections_suffix_goes_into_an_empty_global_list_and_is_noted() {
        let store = FakeList::default();
        let outcome = sync_search_list(&store, &corp(), &[]).expect("sync");
        assert_eq!(
            outcome,
            SearchListOutcome::Written(strings(&["branch.corp.example"]))
        );
        assert_eq!(store.global(), strings(&["branch.corp.example"]));
        assert_eq!(store.noted_now(), strings(&["branch.corp.example"]));

        assert_eq!(
            sync_search_list(&store, &corp(), &[]).expect("again"),
            SearchListOutcome::Unchanged
        );
        assert_eq!(store.writes(), 1, "an unchanged machine writes nothing");
    }

    /// Setting a global list stops the DNS client appending the primary
    /// suffix on its own, so it has to lead the list we write.
    #[test]
    fn the_primary_suffix_leads_and_the_users_suffix_follows() {
        let store = FakeList::with(SearchListView {
            primary: Some("hq.example".into()),
            ..SearchListView::default()
        });
        sync_search_list(&store, &corp(), &strings(&["lab.example", "hq.example"])).expect("sync");
        assert_eq!(
            store.global(),
            strings(&["hq.example", "branch.corp.example", "lab.example"])
        );
    }

    #[test]
    fn a_primary_suffix_alone_needs_no_list() {
        let store = FakeList::with(SearchListView {
            primary: Some("hq.example".into()),
            ..SearchListView::default()
        });
        assert_eq!(
            sync_search_list(&store, &[], &[]).expect("sync"),
            SearchListOutcome::Unchanged
        );
        assert_eq!(store.writes(), 0);
    }

    #[test]
    fn a_list_someone_else_set_is_left_alone() {
        let store = FakeList::with(SearchListView {
            global: strings(&["admin.example"]),
            ..SearchListView::default()
        });
        assert_eq!(
            sync_search_list(&store, &corp(), &[]).expect("sync"),
            SearchListOutcome::NotOurs
        );
        assert_eq!(store.global(), strings(&["admin.example"]));
        assert!(!release_search_list(&store).expect("release"));
        assert_eq!(store.global(), strings(&["admin.example"]));
    }

    #[test]
    fn a_policy_owned_list_is_never_written() {
        let store = FakeList::with(SearchListView {
            policy_managed: true,
            ..SearchListView::default()
        });
        assert_eq!(
            sync_search_list(&store, &corp(), &[]).expect("sync"),
            SearchListOutcome::NotOurs
        );
        assert_eq!(store.writes(), 0);
    }

    fn set_policy(store: &FakeList, managed: bool) {
        store
            .view
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .policy_managed = managed;
    }

    /// Our list outlives a policy laid over it, and is ours again after.
    #[test]
    fn a_policy_over_our_list_keeps_the_note_until_the_policy_goes() {
        let store = FakeList::default();
        sync_search_list(&store, &corp(), &[]).expect("arm");
        set_policy(&store, true);
        assert_eq!(
            sync_search_list(&store, &corp(), &[]).expect("under policy"),
            SearchListOutcome::NotOurs
        );
        assert_eq!(store.noted_now(), corp());
        assert_eq!(store.writes(), 1);

        set_policy(&store, false);
        assert_eq!(
            sync_search_list(&store, &[], &[]).expect("policy gone"),
            SearchListOutcome::Cleared
        );
        assert!(store.global().is_empty());
    }

    #[test]
    fn a_local_list_replaced_under_a_policy_drops_the_note() {
        let store = FakeList::default();
        sync_search_list(&store, &corp(), &[]).expect("arm");
        set_policy(&store, true);
        store.view.lock().unwrap_or_else(|p| p.into_inner()).global = strings(&["admin.example"]);
        assert_eq!(
            sync_search_list(&store, &corp(), &[]).expect("sync"),
            SearchListOutcome::NotOurs
        );
        assert!(store.noted_now().is_empty());
        assert_eq!(store.global(), strings(&["admin.example"]));
    }

    #[test]
    fn release_under_a_policy_still_clears_our_local_list() {
        let store = FakeList::default();
        sync_search_list(&store, &corp(), &[]).expect("arm");
        set_policy(&store, true);
        sync_search_list(&store, &corp(), &[]).expect("under policy");
        assert!(release_search_list(&store).expect("release"));
        assert!(store.global().is_empty());
        assert!(store.noted_now().is_empty());
    }

    #[test]
    fn a_disconnected_vpn_takes_its_suffix_back_out() {
        let store = FakeList::default();
        sync_search_list(&store, &corp(), &[]).expect("arm");
        assert_eq!(
            sync_search_list(&store, &[], &[]).expect("sync"),
            SearchListOutcome::Cleared
        );
        assert!(store.global().is_empty());
        assert!(store.noted_now().is_empty());
    }

    /// A user who replaced our list while we ran keeps theirs, at every exit.
    #[test]
    fn a_list_replaced_while_we_ran_is_not_ours_to_clear() {
        let store = FakeList::default();
        sync_search_list(&store, &corp(), &[]).expect("arm");
        store.view.lock().unwrap_or_else(|p| p.into_inner()).global = strings(&["admin.example"]);
        assert!(!release_search_list(&store).expect("release"));
        assert_eq!(store.global(), strings(&["admin.example"]));
        assert!(store.noted_now().is_empty());
    }

    #[test]
    fn release_clears_our_list_and_the_note() {
        let store = FakeList::default();
        sync_search_list(&store, &corp(), &[]).expect("arm");
        assert!(release_search_list(&store).expect("release"));
        assert!(store.global().is_empty());
        assert!(store.noted_now().is_empty());
        assert!(!release_search_list(&store).expect("idempotent"));
    }

    /// The note covers the old list and the new one until the write lands, so
    /// a failed write leaves a list the next release still recognises.
    #[test]
    fn a_failed_write_leaves_a_note_covering_what_may_be_in_force() {
        let store = FakeList::default();
        sync_search_list(&store, &corp(), &[]).expect("arm");
        let failing = FakeList {
            view: Mutex::new(SearchListView {
                global: strings(&["branch.corp.example"]),
                ..SearchListView::default()
            }),
            noted: Mutex::new(store.noted_now()),
            fail_write: true,
            ..FakeList::default()
        };
        let widened = strings(&["branch.corp.example", "lab.example"]);
        assert!(sync_search_list(&failing, &widened, &[]).is_err());
        assert_eq!(failing.noted_now(), widened);
    }

    #[test]
    fn the_script_names_each_suffix_and_clears_with_an_empty_entry() {
        assert_eq!(
            write_script(&strings(&["a.example", "b-c.example"])).expect("script"),
            "$ErrorActionPreference='Stop'; Set-DnsClientGlobalSetting -SuffixSearchList @('a.example','b-c.example')"
        );
        assert!(write_script(&[])
            .expect("script")
            .ends_with("-SuffixSearchList @('')"));
    }

    #[test]
    fn anything_but_a_plain_suffix_never_reaches_the_script() {
        for bad in ["a'b.example", "a;b", "a b", "a$b", "", "a,b.example"] {
            assert!(write_script(&strings(&[bad])).is_err(), "{bad:?}");
            assert!(comma_list(&strings(&[bad])).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_api_list_is_comma_separated_and_clears_when_empty() {
        assert_eq!(
            comma_list(&strings(&["a.example", "b-c.example"])).expect("list"),
            "a.example,b-c.example"
        );
        assert_eq!(comma_list(&[]).expect("list"), "");
    }
}
