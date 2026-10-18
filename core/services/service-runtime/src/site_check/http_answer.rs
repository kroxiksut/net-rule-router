//! The head of a site's HTTPS answer: its status code and where `Location`
//! sends the next request. The bytes come from a remote server, so every read
//! is bounded and nothing here panics; the body is never looked at.

use nrr_domain::decision_engine_input::hostname_ace;

/// The most of a response head read before giving up on it.
pub const MAX_HEAD_BYTES: usize = 16 * 1024;
/// Header lines read before the head is refused.
pub const MAX_HEADERS: usize = 64;
/// The longest `Location` value taken.
pub const MAX_LOCATION_LEN: usize = 2048;

/// What the head says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeadAnswer {
    pub status: u16,
    pub location: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeadError {
    /// No blank line yet: more bytes could still complete it.
    Incomplete,
    /// No blank line within [`MAX_HEAD_BYTES`].
    TooLarge,
    /// The first line is not an HTTP/1.x status line.
    NotHttp,
    TooManyHeaders,
    /// A header line that cannot be read, or a `Location` that is not one.
    BadHeader,
}

/// The status line and `Location` of the head at the start of `bytes`. Reads
/// up to the blank line that ends the head, never past it.
pub fn parse_head(bytes: &[u8]) -> Result<HeadAnswer, HeadError> {
    let window = &bytes[..bytes.len().min(MAX_HEAD_BYTES)];
    let Some(end) = head_end(window) else {
        return Err(if bytes.len() >= MAX_HEAD_BYTES {
            HeadError::TooLarge
        } else {
            HeadError::Incomplete
        });
    };
    let mut lines = window[..end]
        .split(|b| *b == b'\n')
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l));
    let status = status_of(lines.next().unwrap_or_default())?;
    let mut location = None;
    let mut headers = 0usize;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        headers += 1;
        if headers > MAX_HEADERS {
            return Err(HeadError::TooManyHeaders);
        }
        // Folded continuation lines are obsolete and a smuggling vector.
        if line.first().is_some_and(|b| *b == b' ' || *b == b'\t') {
            return Err(HeadError::BadHeader);
        }
        let colon = line
            .iter()
            .position(|b| *b == b':')
            .ok_or(HeadError::BadHeader)?;
        let (name, value) = (&line[..colon], &line[colon + 1..]);
        if name.is_empty() || !name.iter().all(|b| is_token_byte(*b)) {
            return Err(HeadError::BadHeader);
        }
        if !name.eq_ignore_ascii_case(b"location") {
            continue;
        }
        let value = trim(value);
        if location.is_some()
            || value.is_empty()
            || value.len() > MAX_LOCATION_LEN
            || !value.iter().all(|b| (0x21..=0x7e).contains(b))
        {
            return Err(HeadError::BadHeader);
        }
        location = Some(String::from_utf8_lossy(value).into_owned());
    }
    Ok(HeadAnswer { status, location })
}

/// Where the head ends: the offset of the blank line, either line ending.
fn head_end(bytes: &[u8]) -> Option<usize> {
    let crlf = bytes.windows(4).position(|w| w == b"\r\n\r\n");
    let lf = bytes.windows(2).position(|w| w == b"\n\n");
    match (crlf, lf) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

/// `HTTP/1.x NNN [reason]`.
fn status_of(line: &[u8]) -> Result<u16, HeadError> {
    let rest = line.strip_prefix(b"HTTP/1.").ok_or(HeadError::NotHttp)?;
    match rest {
        [minor, b' ', a, b, c, tail @ ..]
            if minor.is_ascii_digit()
                && [a, b, c].iter().all(|d| d.is_ascii_digit())
                && (tail.is_empty() || tail[0] == b' ') =>
        {
            let code = u16::from(a - b'0') * 100 + u16::from(b - b'0') * 10 + u16::from(c - b'0');
            if (100..=599).contains(&code) {
                Ok(code)
            } else {
                Err(HeadError::NotHttp)
            }
        }
        _ => Err(HeadError::NotHttp),
    }
}

fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

fn trim(value: &[u8]) -> &[u8] {
    let start = value.iter().position(|b| !b.is_ascii_whitespace());
    let end = value.iter().rposition(|b| !b.is_ascii_whitespace());
    match (start, end) {
        (Some(s), Some(e)) => &value[s..=e],
        _ => &[],
    }
}

/// Where a redirect sends the next request. Only the host is kept: a path or
/// query can carry a sign-in token, and the check asks for `/` every time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NextHop {
    /// An HTTPS address on this host.
    Host(String),
    /// Somewhere else on the same host.
    SameHost,
    /// Away from HTTPS, to this host.
    NotHttps(String),
    /// Nothing the check can follow or name.
    Unusable,
}

pub fn next_hop(location: &str) -> NextHop {
    let location = location.trim();
    let lower = location.get(..8).map(str::to_ascii_lowercase);
    let (authority, https) = if lower.as_deref() == Some("https://") {
        (&location[8..], true)
    } else if lower.as_deref().is_some_and(|l| l.starts_with("http://")) {
        (&location[7..], false)
    } else if let Some(rest) = location.strip_prefix("//") {
        (rest, true)
    } else if location.starts_with('/') || !location.contains(':') {
        return NextHop::SameHost;
    } else {
        return NextHop::Unusable;
    };
    let end = authority
        .find(['/', '?', '#', '\\'])
        .unwrap_or(authority.len());
    let authority = &authority[..end];
    // Credentials in a redirect are a trick, never a sign-in page.
    if authority.contains('@') || authority.starts_with('[') {
        return NextHop::Unusable;
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };
    let Some(host) = hostname_ace(host) else {
        return NextHop::Unusable;
    };
    match (https, port) {
        (true, None | Some("443")) => NextHop::Host(host),
        (false, None | Some("80")) => NextHop::NotHttps(host),
        _ => NextHop::Unusable,
    }
}

/// The request the check sends: `GET /` for `host`, closing after the answer.
/// `None` for anything but a plain host name, so nothing can be injected
/// into the request line or a header.
pub fn request_for(host: &str) -> Option<Vec<u8>> {
    if host.is_empty()
        || host.len() > 253
        || !host
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
    {
        return None;
    }
    Some(
        format!(
            "GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: NetRuleRouter-site-check\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        )
        .into_bytes(),
    )
}

/// What following a site's redirects found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ChainReport {
    /// The first answer's status code.
    pub status: Option<u16>,
    /// The hosts the chain went through after the first, in order.
    pub hosts: Vec<String>,
}

/// Follow `start`'s redirects through `fetch`, at most `max_hops` of them, and
/// only while they stay on hosts `same_site` admits; a host off the site is
/// named and not visited. A host seen twice ends the chain: that is a loop.
pub fn follow(
    start: &str,
    max_hops: usize,
    same_site: impl Fn(&str) -> bool,
    mut fetch: impl FnMut(&str) -> Option<HeadAnswer>,
) -> ChainReport {
    let mut report = ChainReport::default();
    let mut current = start.to_owned();
    for hop in 0..=max_hops {
        let Some(answer) = fetch(&current) else {
            break;
        };
        if hop == 0 {
            report.status = Some(answer.status);
        }
        let Some(location) = answer
            .location
            .filter(|_| (300..400).contains(&answer.status))
        else {
            break;
        };
        let next = match next_hop(&location) {
            NextHop::Host(host) => host,
            NextHop::NotHttps(host) => {
                report.hosts.push(host);
                break;
            }
            NextHop::SameHost | NextHop::Unusable => break,
        };
        if next == current {
            break;
        }
        let looped = next == start || report.hosts.contains(&next);
        report.hosts.push(next.clone());
        if looped || !same_site(&next) || report.hosts.len() >= max_hops {
            break;
        }
        current = next;
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(text: &str) -> Result<HeadAnswer, HeadError> {
        parse_head(text.as_bytes())
    }

    #[test]
    fn a_redirect_head_gives_its_status_and_location() {
        assert_eq!(
            head(concat!(
                "HTTP/1.1 302 Found\r\nServer: x\r\n",
                "Location: https://login.site.example/?a=1\r\n\r\nbody"
            )),
            Ok(HeadAnswer {
                status: 302,
                location: Some("https://login.site.example/?a=1".into())
            })
        );
        assert_eq!(
            head("HTTP/1.0 200\n\n"),
            Ok(HeadAnswer {
                status: 200,
                location: None
            })
        );
    }

    #[test]
    fn hostile_heads_are_refused_not_trusted() {
        assert_eq!(head("HTTP/1.1 302 Found\r\n"), Err(HeadError::Incomplete));
        assert_eq!(head("SSH-2.0-x\r\n\r\n"), Err(HeadError::NotHttp));
        assert_eq!(head("HTTP/1.1 999 Odd\r\n\r\n"), Err(HeadError::NotHttp));
        assert_eq!(head("HTTP/1.1 30 x\r\n\r\n"), Err(HeadError::NotHttp));
        assert_eq!(
            head("HTTP/1.1 302 x\r\nLocation: /a\r\nLocation: /b\r\n\r\n"),
            Err(HeadError::BadHeader),
            "two locations are two answers"
        );
        assert_eq!(
            head("HTTP/1.1 302 x\r\nLocation: /a\r\n continued\r\n\r\n"),
            Err(HeadError::BadHeader)
        );
        assert_eq!(
            head("HTTP/1.1 302 x\r\nLocation: /a b\r\n\r\n"),
            Err(HeadError::BadHeader)
        );
        assert_eq!(
            head("HTTP/1.1 200 x\r\nno colon\r\n\r\n"),
            Err(HeadError::BadHeader)
        );
        let many = format!(
            "HTTP/1.1 200 x\r\n{}\r\n",
            "A: b\r\n".repeat(MAX_HEADERS + 1)
        );
        assert_eq!(head(&many), Err(HeadError::TooManyHeaders));
        let long = vec![b'a'; MAX_HEAD_BYTES + 10];
        assert_eq!(parse_head(&long), Err(HeadError::TooLarge));
        let endless = format!("HTTP/1.1 200 x\r\nA: {}", "b".repeat(MAX_HEAD_BYTES));
        assert_eq!(head(&endless), Err(HeadError::TooLarge));
        let huge = format!(
            "HTTP/1.1 302 x\r\nLocation: /{}\r\n\r\n",
            "a".repeat(MAX_LOCATION_LEN)
        );
        assert_eq!(head(&huge), Err(HeadError::BadHeader));
    }

    #[test]
    fn only_the_host_of_a_redirect_is_kept() {
        assert_eq!(
            next_hop("https://Login.Site.Example:443/auth?token=secret"),
            NextHop::Host("login.site.example".into())
        );
        assert_eq!(
            next_hop("//id.site.example/x"),
            NextHop::Host("id.site.example".into())
        );
        assert_eq!(next_hop("/feed"), NextHop::SameHost);
        assert_eq!(next_hop("feed?x=1"), NextHop::SameHost);
        assert_eq!(
            next_hop("http://site.example/"),
            NextHop::NotHttps("site.example".into())
        );
        for odd in [
            "javascript:alert(1)",
            "https://user:pw@site.example/",
            "https://site.example:8443/",
            "https://[2001:db8::1]/",
            "https:///nohost",
        ] {
            assert_eq!(next_hop(odd), NextHop::Unusable, "{odd}");
        }
    }

    #[test]
    fn the_request_names_a_plain_host_or_nothing() {
        let request = request_for("site.example").expect("plain host");
        assert!(request.starts_with(b"GET / HTTP/1.1\r\nHost: site.example\r\n"));
        assert!(request.ends_with(b"\r\n\r\n"));
        assert!(request_for("site.example\r\nX-Evil: 1").is_none());
        assert!(request_for("Site.Example").is_none());
        assert!(request_for("").is_none());
    }

    fn answer(status: u16, location: Option<&str>) -> Option<HeadAnswer> {
        Some(HeadAnswer {
            status,
            location: location.map(str::to_owned),
        })
    }

    #[test]
    fn a_chain_is_followed_on_the_site_and_named_off_it() {
        let site = |h: &str| h.ends_with("site.example");
        let report = follow("site.example", 5, site, |host| match host {
            "site.example" => answer(302, Some("https://login.site.example/")),
            "login.site.example" => answer(302, Some("https://sso.elsewhere.example/")),
            _ => panic!("{host} is off the site and must not be visited"),
        });
        assert_eq!(report.status, Some(302));
        assert_eq!(
            report.hosts,
            ["login.site.example", "sso.elsewhere.example"]
        );
    }

    #[test]
    fn a_loop_and_the_hop_limit_both_end_the_chain() {
        let mut visits = 0;
        let report = follow(
            "site.example",
            5,
            |_| true,
            |host| {
                visits += 1;
                match host {
                    "site.example" => answer(302, Some("https://login.site.example/")),
                    _ => answer(302, Some("https://site.example/")),
                }
            },
        );
        assert_eq!(report.hosts, ["login.site.example", "site.example"]);
        assert_eq!(visits, 2, "the loop is reported, not walked");

        let mut n = 0;
        let report = follow(
            "h0.example",
            2,
            |_| true,
            |_| {
                n += 1;
                answer(301, Some(format!("https://h{n}.example/").as_str()))
            },
        );
        assert_eq!(report.hosts.len(), 2);
        assert_eq!(n, 2);
    }

    #[test]
    fn an_answer_that_is_not_a_redirect_ends_the_chain() {
        let report = follow(
            "site.example",
            5,
            |_| true,
            |_| answer(200, Some("https://x.example/")),
        );
        assert_eq!(report.status, Some(200));
        assert!(report.hosts.is_empty());
        let silent = follow("site.example", 5, |_| true, |_| None);
        assert_eq!(silent, ChainReport::default());
    }
}
