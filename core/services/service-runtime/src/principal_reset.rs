//! Who holds a user's state in memory, so a full reset can empty it.
//!
//! Erasing the rows is not enough while the service runs: a holder that still
//! has the user's ledger writes it back on its next tick, and the reset undoes
//! itself.

use std::sync::{Arc, Mutex, OnceLock, Weak};

/// A component that keeps per-user state in memory between ticks.
pub trait PrincipalStateHolder: Send + Sync {
    /// Drops everything held for `sid`.
    fn forget_principal(&self, sid: &str);
    /// Drops everything held for every user.
    fn forget_everyone(&self);
}

fn holders() -> &'static Mutex<Vec<Weak<dyn PrincipalStateHolder>>> {
    static HOLDERS: OnceLock<Mutex<Vec<Weak<dyn PrincipalStateHolder>>>> = OnceLock::new();
    HOLDERS.get_or_init(|| Mutex::new(Vec::new()))
}

/// Adds a holder. Held weakly: a holder that is gone is skipped.
pub fn register(holder: &Arc<dyn PrincipalStateHolder>) {
    let mut all = holders().lock().unwrap_or_else(|p| p.into_inner());
    all.retain(|w| w.strong_count() > 0);
    all.push(Arc::downgrade(holder));
}

fn live() -> Vec<Arc<dyn PrincipalStateHolder>> {
    holders()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .iter()
        .filter_map(Weak::upgrade)
        .collect()
}

/// A full reset of `sid`: every registered holder forgets them.
pub fn forget_principal(sid: &str) {
    for holder in live() {
        holder.forget_principal(sid);
    }
}

/// A full reset of every user.
pub fn forget_everyone() {
    for holder in live() {
        holder.forget_everyone();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Default)]
    struct Counting {
        one: AtomicUsize,
        all: AtomicUsize,
    }

    impl PrincipalStateHolder for Counting {
        fn forget_principal(&self, _sid: &str) {
            self.one.fetch_add(1, Ordering::SeqCst);
        }
        fn forget_everyone(&self) {
            self.all.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn a_reset_reaches_every_live_holder_and_skips_dropped_ones() {
        let kept = Arc::new(Counting::default());
        let kept_dyn: Arc<dyn PrincipalStateHolder> = kept.clone();
        register(&kept_dyn);
        let gone: Arc<dyn PrincipalStateHolder> = Arc::new(Counting::default());
        register(&gone);
        drop(gone);

        forget_principal("S-reset");
        forget_everyone();

        assert!(kept.one.load(Ordering::SeqCst) >= 1);
        assert!(kept.all.load(Ordering::SeqCst) >= 1);
    }
}
