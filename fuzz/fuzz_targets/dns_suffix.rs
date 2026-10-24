#![no_main]
//! A DNS suffix from a DHCP lease, the registry of another adapter or an IPC
//! list: normalising never panics, what it keeps is a bounded hostname, and the
//! platform's reading of an OS claim is the list's own definition.

use libfuzzer_sys::fuzz_target;
use nrr_platform_api::dns_scope;
use nrr_shared::local_dns_suffixes::{covers, normalize_list, normalize_suffix, MAX_SUFFIXES};

/// A registry value or an IPC entry is far shorter; well above keeps long inputs in.
const MAX_INPUT: usize = 64 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT {
        return;
    }
    let text = String::from_utf8_lossy(data);
    let strict = normalize_suffix(&text);
    assert_eq!(dns_scope::normalize_suffix(&text), strict.clone().ok());
    if let Ok(suffix) = &strict {
        assert!(!suffix.is_empty() && suffix.len() <= 253, "{text:?}");
        assert_eq!(normalize_suffix(suffix).as_ref(), Ok(suffix), "{text:?}");
        assert!(covers(suffix, suffix));
    }
    let entries: Vec<String> = text.split(',').map(str::to_owned).collect();
    if let Ok(list) = normalize_list(&entries) {
        assert!(list.len() <= MAX_SUFFIXES);
        for (i, a) in list.iter().enumerate() {
            assert!(!list[i + 1..].contains(a), "{text:?}");
        }
    }
});
