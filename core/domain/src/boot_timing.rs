//! When the service started, relative to the moment the machine asked the user
//! to sign in.
//!
//! The question this answers came from a real accusation: a boot took 35 s
//! instead of the usual 20-28, and the natural suspicion was that the service
//! was holding it up. It was not — the sign-in prompt appeared at 09:33:20 and
//! the service started at 09:33:26, six seconds LATER, so it could not have
//! delayed anything that happened before it existed.
//!
//! Saying that convincingly needs evidence, not reassurance, so the product
//! reports the measured relationship and lets the user read it. Pure by
//! construction: the two timestamps are supplied, one by the OS log and one by
//! the service itself, and this module only subtracts them and names the
//! result.

/// Where the service's start sits relative to the sign-in prompt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceStartRelativeToSignIn {
    /// The service started this many milliseconds AFTER the prompt appeared —
    /// it cannot have delayed anything that happened before it.
    After { millis: u64 },
    /// The service started BEFORE the prompt. Reported as its own case rather
    /// than folded into "after 0 s": it is the shape in which the service COULD
    /// be part of the wait, and hiding that would make the diagnostic a
    /// reassurance instead of a measurement.
    Before { millis: u64 },
    /// One of the two moments is not known on this host — the log has no such
    /// record, or the platform has no equivalent. Not an error and not a zero.
    Unknown,
}

impl ServiceStartRelativeToSignIn {
    /// Stable slug for the wire and for locale keys.
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::After { .. } => "after",
            Self::Before { .. } => "before",
            Self::Unknown => "unknown",
        }
    }

    /// The measured gap, whichever side it falls on. `None` when unknown.
    #[must_use]
    pub const fn millis(self) -> Option<u64> {
        match self {
            Self::After { millis } | Self::Before { millis } => Some(millis),
            Self::Unknown => None,
        }
    }
}

/// How long after boot both moments must fall to describe that boot's startup.
///
/// Outside it the answer measures something else: a prompt stamped before the
/// clock was stepped back (RTC kept in local time, a dual-boot machine, NTP),
/// or a service process restarted long after the boot it would be judged for.
pub const BOOT_STARTUP_WINDOW_MS: u64 = 10 * 60 * 1000;

/// Subtract the two moments and name the result.
///
/// All three are milliseconds on the same clock (Unix epoch). A missing one,
/// or a moment outside [`BOOT_STARTUP_WINDOW_MS`] from boot, yields
/// [`ServiceStartRelativeToSignIn::Unknown`] — never a zero or invented gap.
#[must_use]
pub fn service_start_relative_to_sign_in(
    boot_started_at_ms: Option<u64>,
    sign_in_prompt_at_ms: Option<u64>,
    service_started_at_ms: Option<u64>,
) -> ServiceStartRelativeToSignIn {
    let (Some(boot), Some(prompt), Some(started)) = (
        boot_started_at_ms,
        sign_in_prompt_at_ms,
        service_started_at_ms,
    ) else {
        return ServiceStartRelativeToSignIn::Unknown;
    };
    let in_startup = |at: u64| {
        at.checked_sub(boot)
            .is_some_and(|d| d <= BOOT_STARTUP_WINDOW_MS)
    };
    if !in_startup(prompt) || !in_startup(started) {
        return ServiceStartRelativeToSignIn::Unknown;
    }
    if started >= prompt {
        ServiceStartRelativeToSignIn::After {
            millis: started - prompt,
        }
    } else {
        ServiceStartRelativeToSignIn::Before {
            millis: prompt - started,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOOT: u64 = 970_000;

    fn verdict(prompt: u64, started: u64) -> ServiceStartRelativeToSignIn {
        service_start_relative_to_sign_in(Some(BOOT), Some(prompt), Some(started))
    }

    #[test]
    fn a_service_that_started_after_the_prompt_reports_the_gap() {
        // The field case: prompt 09:33:20, service 09:33:26.
        let verdict = verdict(1_000_000, 1_006_000);
        assert_eq!(
            verdict,
            ServiceStartRelativeToSignIn::After { millis: 6_000 }
        );
        assert_eq!(verdict.slug(), "after");
        assert_eq!(verdict.millis(), Some(6_000));
    }

    #[test]
    fn a_service_that_started_first_is_told_apart_from_one_that_started_with_it() {
        // Folding "before" into "after 0" would turn a measurement into a
        // reassurance: starting first is the shape in which the service COULD
        // be part of the wait.
        assert_eq!(
            verdict(1_006_000, 1_000_000),
            ServiceStartRelativeToSignIn::Before { millis: 6_000 }
        );
        assert_eq!(
            verdict(1_000_000, 1_000_000),
            ServiceStartRelativeToSignIn::After { millis: 0 }
        );
    }

    #[test]
    fn a_missing_moment_is_unknown_rather_than_zero() {
        for triple in [
            (None, Some(BOOT), Some(BOOT)),
            (Some(BOOT), None, Some(BOOT)),
            (Some(BOOT), Some(BOOT), None),
        ] {
            assert_eq!(
                service_start_relative_to_sign_in(triple.0, triple.1, triple.2),
                ServiceStartRelativeToSignIn::Unknown,
                "a record we do not have must not read as a zero gap"
            );
        }
        assert_eq!(ServiceStartRelativeToSignIn::Unknown.millis(), None);
    }

    #[test]
    fn a_prompt_stamped_before_the_clock_stepped_back_is_unknown() {
        // Field case: the RTC ran five hours ahead, the prompt was stamped on
        // that clock, and the card claimed the service started 12863.9 s before it.
        let five_hours = 5 * 3_600_000;
        assert_eq!(
            verdict(BOOT + 7_000 + five_hours, BOOT + 20_000),
            ServiceStartRelativeToSignIn::Unknown
        );
    }

    #[test]
    fn a_moment_outside_this_boots_startup_is_unknown() {
        let late = BOOT + BOOT_STARTUP_WINDOW_MS + 1;
        // A prompt from an earlier boot.
        assert_eq!(
            verdict(BOOT - 1, BOOT + 20_000),
            ServiceStartRelativeToSignIn::Unknown
        );
        // A service restarted long after the boot it would be judged for.
        assert_eq!(
            verdict(BOOT + 7_000, late),
            ServiceStartRelativeToSignIn::Unknown
        );
        // The edge of the window still measures.
        assert_eq!(
            verdict(BOOT + 7_000, BOOT + BOOT_STARTUP_WINDOW_MS),
            ServiceStartRelativeToSignIn::After {
                millis: BOOT_STARTUP_WINDOW_MS - 7_000
            }
        );
    }
}
