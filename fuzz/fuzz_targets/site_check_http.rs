#![no_main]
//! The head of a site's HTTPS answer, as the site check reads it: the status
//! line and headers, and where its `Location` sends the next request.

use libfuzzer_sys::fuzz_target;
use nrr_service_runtime::site_check::http_answer;

fuzz_target!(|data: &[u8]| {
    if data.len() > 2 * http_answer::MAX_HEAD_BYTES {
        return;
    }
    if let Ok(answer) = http_answer::parse_head(data) {
        if let Some(location) = answer.location.as_deref() {
            let _ = http_answer::next_hop(location);
        }
    }
    let text = String::from_utf8_lossy(data);
    let _ = http_answer::next_hop(&text);
    let _ = http_answer::request_for(&text);
    // One redirect chain where every hop answers with these same bytes.
    let _ = http_answer::follow("site.example", 5, |h| h.ends_with("example"), |_| {
        http_answer::parse_head(data).ok()
    });
});
