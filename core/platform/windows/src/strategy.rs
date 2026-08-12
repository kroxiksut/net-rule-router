//! Rule-implementation strategy classification (`rule_strategy`,
//! `RuleImplementationStrategy`) and the IPv6 detection helper
//! (`is_ipv6_address`) are pure/neutral policy, so they live in
//! `nrr_platform_api::strategy`. Shim for source compatibility.

pub use nrr_platform_api::strategy::*;
