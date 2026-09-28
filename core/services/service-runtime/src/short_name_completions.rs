//! Short names our resolver completed, and the full name each one became.
//!
//! A bare label (`intranet`) is answered against the question the program
//! asked, so everything downstream of the resolver only ever sees the label.
//! An offer built on it would read `*.intranet` — a rule for a whole top-level
//! label. This memory is how an offer names the host the answer came from.

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Long enough to outlive the connections a completed answer led to.
const ENTRY_TTL: Duration = Duration::from_secs(60 * 60);

/// Short names a machine actually uses number in the dozens.
const MAX_ENTRIES: usize = 256;

#[derive(Default)]
pub struct ShortNameCompletions {
    inner: Mutex<HashMap<String, (String, Instant)>>,
}

impl ShortNameCompletions {
    pub fn record(&self, label: &str, full: &str) {
        let label = label.trim_end_matches('.').to_ascii_lowercase();
        if label.is_empty() || label.contains('.') {
            return;
        }
        let Ok(mut map) = self.inner.lock() else {
            return;
        };
        if map.len() >= MAX_ENTRIES && !map.contains_key(&label) {
            map.retain(|_, (_, at)| at.elapsed() < ENTRY_TTL);
            if map.len() >= MAX_ENTRIES {
                let oldest = map
                    .iter()
                    .min_by_key(|(_, (_, at))| *at)
                    .map(|(k, _)| k.clone());
                if let Some(oldest) = oldest {
                    map.remove(&oldest);
                }
            }
        }
        map.insert(label, (full.to_ascii_lowercase(), Instant::now()));
    }

    /// `host` as an offer may name it: unchanged when it has a dot, its
    /// completion when it is a bare label we completed, `None` otherwise.
    pub fn qualify<'a>(&self, host: &'a str) -> Option<Cow<'a, str>> {
        let trimmed = host.trim_end_matches('.');
        if trimmed.contains('.') {
            return Some(Cow::Borrowed(host));
        }
        let map = self.inner.lock().ok()?;
        let (full, at) = map.get(&trimmed.to_ascii_lowercase())?;
        (at.elapsed() < ENTRY_TTL).then(|| Cow::Owned(full.clone()))
    }
}

pub fn global_short_name_completions() -> &'static ShortNameCompletions {
    static GLOBAL: OnceLock<ShortNameCompletions> = OnceLock::new();
    GLOBAL.get_or_init(ShortNameCompletions::default)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_dotted_name_passes_unchanged() {
        let names = ShortNameCompletions::default();
        assert_eq!(
            names.qualify("www.example.com").as_deref(),
            Some("www.example.com")
        );
    }

    #[test]
    fn a_bare_label_nobody_completed_is_refused() {
        let names = ShortNameCompletions::default();
        assert_eq!(names.qualify("intranet"), None);
    }

    #[test]
    fn a_completed_label_becomes_its_full_name() {
        let names = ShortNameCompletions::default();
        names.record("Intranet", "intranet.corp.example");
        assert_eq!(
            names.qualify("intranet").as_deref(),
            Some("intranet.corp.example")
        );
        assert_eq!(
            names.qualify("intranet.").as_deref(),
            Some("intranet.corp.example")
        );
        assert_eq!(names.qualify("wiki"), None);
    }

    #[test]
    fn the_memory_stays_bounded() {
        let names = ShortNameCompletions::default();
        for i in 0..(MAX_ENTRIES + 10) {
            names.record(&format!("host{i}"), &format!("host{i}.corp.example"));
        }
        let len = names.inner.lock().map(|m| m.len()).unwrap_or(usize::MAX);
        assert!(len <= MAX_ENTRIES);
        let last = format!("host{}", MAX_ENTRIES + 9);
        assert!(names.qualify(&last).is_some());
    }
}
