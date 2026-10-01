//! Test-only allocation counter. A test binary holds one global allocator, so
//! every hot-path test that asserts an allocation count shares this one.

#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

// Counts allocations on the arming thread only, so parallel tests do not
// disturb the measurement.
struct CountingAlloc;

thread_local! {
    static ARMED: Cell<bool> = const { Cell::new(false) };
    static COUNT: Cell<usize> = const { Cell::new(0) };
}

// SAFETY: forwards every call to `System` unchanged; the thread-locals are
// const-initialised `Cell`s, which never allocate.
unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        note_alloc();
        // SAFETY: same contract as the caller's.
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: same contract as the caller's.
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        note_alloc();
        // SAFETY: same contract as the caller's.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

fn note_alloc() {
    let _ = ARMED.try_with(|armed| {
        if armed.get() {
            let _ = COUNT.try_with(|c| c.set(c.get() + 1));
        }
    });
}

#[global_allocator]
static GLOBAL: CountingAlloc = CountingAlloc;

/// Allocations and reallocations `f` makes on the calling thread.
pub(crate) fn allocations_during(f: impl FnOnce()) -> usize {
    COUNT.with(|c| c.set(0));
    ARMED.with(|a| a.set(true));
    f();
    ARMED.with(|a| a.set(false));
    COUNT.with(Cell::get)
}

#[test]
fn the_counter_sees_an_allocation() {
    assert!(allocations_during(|| drop(std::hint::black_box(vec![0u8; 64]))) > 0);
    assert_eq!(allocations_during(|| {}), 0);
}
