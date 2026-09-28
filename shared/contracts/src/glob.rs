//! The one wildcard matcher for application patterns.
//!
//! Patterns come from rule sets someone else wrote, and they are matched on
//! the explain probe, the connection-observation path and the resolvers. The
//! recursive `(0..=len).any(...)` form re-explores every suffix once per `*`
//! and goes exponential on `*a*a*a…b`, which wedges whichever thread met it.
//! Every caller goes through this one, so no two paths can disagree on a
//! pattern.

/// Does `pattern` match all of `text`?
///
/// `*` matches any run of characters, including none and including path
/// separators. It is the only wildcard — `?` is an ordinary character — because
/// the published rules format promises exactly that and the engine and the
/// enforcement resolvers must agree. ASCII letters compare case-insensitively,
/// everything else exactly. Worst case O(|pattern| · |text|), no recursion, no
/// allocation.
#[must_use]
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let (pat, txt) = (pattern.as_bytes(), text.as_bytes());
    let (mut p, mut t) = (0usize, 0usize);
    // Where to resume after a failed attempt: the pattern index just past the
    // last `*`, and how far into the text that `*` had reached.
    let mut star: Option<(usize, usize)> = None;

    loop {
        if pat.get(p) == Some(&b'*') {
            while pat.get(p) == Some(&b'*') {
                p += 1;
            }
            if p == pat.len() {
                return true;
            }
            star = Some((p, t));
            continue;
        }
        if let (Some(&pc), Some(&tc)) = (pat.get(p), txt.get(t)) {
            // Byte-wise is exact on UTF-8: a literal run can only line up with
            // the text at a character boundary, and folding touches ASCII only.
            if pc.eq_ignore_ascii_case(&tc) {
                p += 1;
                t += 1;
                continue;
            }
        }
        if p == pat.len() && t == txt.len() {
            return true;
        }
        match star {
            // Hand the last `*` one more character and try again.
            Some((resume_p, resume_t)) if resume_t < txt.len() => {
                p = resume_p;
                t = resume_t + char_width(txt[resume_t]);
                star = Some((resume_p, t));
            }
            _ => return false,
        }
    }
}

/// Length of the UTF-8 sequence `lead` starts. Only ever called on a lead byte:
/// every step lands the text index on a character boundary.
fn char_width(lead: u8) -> usize {
    (lead.leading_ones() as usize).max(1)
}

#[cfg(test)]
mod tests;
