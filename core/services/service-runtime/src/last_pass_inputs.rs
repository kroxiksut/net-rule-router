//! What each user's last full pass planned from, for a first contact on the
//! DNS answer path: it plans from these instead of reading the stores every
//! settings write locks. Up to one pass stale; the pass a first contact
//! forces brings it up to date.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub(crate) struct LastPassInputs<T> {
    state: Mutex<State<T>>,
}

struct State<T> {
    /// The last finished pass's, by user.
    kept: HashMap<String, Arc<T>>,
    /// The running pass's so far. A user it does not plan has no inputs once
    /// it ends, so a pass that found no rules leaves no book behind.
    staged: Option<HashMap<String, Arc<T>>>,
}

impl<T> Default for LastPassInputs<T> {
    fn default() -> Self {
        Self {
            state: Mutex::new(State {
                kept: HashMap::new(),
                staged: None,
            }),
        }
    }
}

impl<T> LastPassInputs<T> {
    fn state(&self) -> std::sync::MutexGuard<'_, State<T>> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub(crate) fn begin_pass(&self) {
        self.state().staged = Some(HashMap::new());
    }

    /// [`Self::begin_pass`] now and [`Self::end_pass`] when the guard drops,
    /// however the pass returns.
    pub(crate) fn pass(&self) -> PassGuard<'_, T> {
        self.begin_pass();
        PassGuard(self)
    }

    /// The running pass's inputs become the ones first contacts read.
    pub(crate) fn end_pass(&self) {
        let mut state = self.state();
        if let Some(staged) = state.staged.take() {
            state.kept = staged;
        }
    }

    /// `principal`'s inputs, planned from just now. Outside a pass they are
    /// kept at once.
    pub(crate) fn record(&self, principal: &str, inputs: T) {
        let mut state = self.state();
        let state = &mut *state;
        state
            .staged
            .as_mut()
            .unwrap_or(&mut state.kept)
            .insert(principal.to_owned(), Arc::new(inputs));
    }

    /// The running pass keeps what the last one had for `principal`: their
    /// book could not be read, and the plan in force is carried too.
    pub(crate) fn carry(&self, principal: &str) {
        let mut state = self.state();
        let state = &mut *state;
        if let (Some(staged), Some(kept)) = (state.staged.as_mut(), state.kept.get(principal)) {
            staged.insert(principal.to_owned(), Arc::clone(kept));
        }
    }

    pub(crate) fn last(&self, principal: &str) -> Option<Arc<T>> {
        self.state().kept.get(principal).map(Arc::clone)
    }
}

pub(crate) struct PassGuard<'a, T>(&'a LastPassInputs<T>);

impl<T> Drop for PassGuard<'_, T> {
    fn drop(&mut self) {
        self.0.end_pass();
    }
}
