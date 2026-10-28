//! How many times a panic at one place is printed to stderr.
//!
//! A panic contained to its unit of work (one datagram, one connection, one
//! request) still runs the panic hook, which prints a report every time. A
//! local process that finds one input that panics could then grow the stderr
//! file by a report per packet until the disk is full. Reports are printed on
//! the 1st, 2nd, 4th, 8th... panic at a place, each saying how many there were.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

/// Distinct places remembered; past it every new place shares one count.
const PLACES_KEPT: usize = 256;

#[derive(Default)]
pub struct PanicReportThrottle {
    counts: Mutex<HashMap<(String, u32), u64>>,
}

impl PanicReportThrottle {
    /// The count to print with this panic, or `None` to stay quiet.
    pub fn admit(&self, file: &str, line: u32) -> Option<u64> {
        let mut counts = self.counts.lock().unwrap_or_else(PoisonError::into_inner);
        let key = if counts.len() < PLACES_KEPT || counts.contains_key(&(file.to_owned(), line)) {
            (file.to_owned(), line)
        } else {
            (String::new(), 0)
        };
        let count = counts.entry(key).or_insert(0);
        *count += 1;
        count.is_power_of_two().then_some(*count)
    }
}

/// Installs the throttle in front of the default hook, for the service only.
pub fn install_throttled_panic_reports() {
    let throttle = PanicReportThrottle::default();
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let (file, line) = info.location().map_or(("", 0), |l| (l.file(), l.line()));
        let Some(count) = throttle.admit(file, line) else {
            return;
        };
        if count > 1 {
            eprintln!("nrr-service: panic number {count} at {file}:{line}; repeats in between were not printed");
        }
        default_hook(info);
    }));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_panic_repeating_at_one_place_is_printed_a_logarithmic_number_of_times() {
        let throttle = PanicReportThrottle::default();
        let printed = (0..100_000)
            .filter(|_| throttle.admit("dns_wire.rs", 42).is_some())
            .count();
        assert_eq!(printed, 17, "1, 2, 4 ... 65536");
        assert_eq!(
            throttle.admit("other.rs", 1),
            Some(1),
            "another place starts afresh"
        );
    }

    #[test]
    fn panics_at_ever_new_places_cannot_grow_the_memory_without_bound() {
        let throttle = PanicReportThrottle::default();
        for line in 0..10_000 {
            throttle.admit("generated.rs", line);
        }
        let kept = throttle.counts.lock().map(|c| c.len()).unwrap_or(0);
        assert!(kept <= PLACES_KEPT + 1, "kept {kept} places");
    }
}
