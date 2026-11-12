const INHERIT: u32 = 0;
const SYSTEM: u32 = 1;
const FOLLOW_ROUTE: u32 = 3;
const INVALID_INPUT: u32 = 0;
const CONSENT_REQUIRED: u32 = 4;
const ROUTE_UNAVAILABLE: u32 = 5;
const UNSUPPORTED: u32 = 6;

/// Resolves modes 0 (inherit), 1 (system), 2 (manual), and 3 (route).
/// Returns a resolved mode or 0 (invalid), 4 (consent), 5 (route), 6 (support).
/// Flags are strictly 0 or 1; route knowledge must belong to the current request.
// This module owns the WASM export name; the ABI contains only integers.
#[cfg_attr(target_arch = "wasm32", allow(unsafe_code))]
#[cfg_attr(target_arch = "wasm32", no_mangle)]
pub extern "C" fn resolve_mode(
    site_mode: u32,
    global_mode: u32,
    consented: u32,
    route_known: u32,
    capability: u32,
) -> u32 {
    if site_mode > FOLLOW_ROUTE
        || !(SYSTEM..=FOLLOW_ROUTE).contains(&global_mode)
        || consented > 1
        || route_known > 1
        || capability > 1
    {
        return INVALID_INPUT;
    }

    let effective_mode = if site_mode == INHERIT {
        global_mode
    } else {
        site_mode
    };

    if effective_mode == SYSTEM {
        return SYSTEM;
    }
    if consented == 0 {
        return CONSENT_REQUIRED;
    }
    if capability == 0 {
        return UNSUPPORTED;
    }
    if effective_mode == FOLLOW_ROUTE && route_known == 0 {
        return ROUTE_UNAVAILABLE;
    }

    effective_mode
}
