//! Operator block-page hosts — the pages an ISP redirects to instead of the
//! site the user asked for.
//!
//! Resolving one of these right after a rule-less host is the evidence that the
//! host is blocked upstream rather than broken: the browser was sent to the
//! operator's notice page. The signal is a plain name lookup, so nothing has to
//! read the traffic.
//!
//! Matching is by host suffix, so `m.warning.rt.ru` counts as `warning.rt.ru`.
//! An entry names the operator only for diagnostics; the routing decision never
//! depends on which operator it was.

/// One operator's notice page.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockPageHost {
    /// Host as the resolver sees it, lower-case, no trailing dot.
    pub host: &'static str,
    /// Operator this page belongs to. Diagnostics only.
    pub operator: &'static str,
    /// ISO-3166 alpha-2 of the country whose operators use it.
    pub country: &'static str,
}

/// Notice pages shipped as the starting set. An operator can change its page at
/// any time, so this is a seed for the learner, not the authority: an unknown
/// page costs a suggestion, never a wrong route.
pub const BLOCK_PAGE_HOSTS: &[BlockPageHost] = &[
    BlockPageHost {
        host: "warning.rt.ru",
        operator: "Rostelecom",
        country: "ru",
    },
    BlockPageHost {
        host: "warning.rest",
        operator: "Rostelecom",
        country: "ru",
    },
    BlockPageHost {
        host: "fz139.ttk.ru",
        operator: "TTK",
        country: "ru",
    },
    BlockPageHost {
        host: "blackhole.beeline.ru",
        operator: "Beeline",
        country: "ru",
    },
    BlockPageHost {
        host: "blocked.mts.ru",
        operator: "MTS",
        country: "ru",
    },
    BlockPageHost {
        host: "block.mts.ru",
        operator: "MTS",
        country: "ru",
    },
    BlockPageHost {
        host: "unblock.mts.ru",
        operator: "MTS",
        country: "ru",
    },
    BlockPageHost {
        host: "block.megafon.ru",
        operator: "MegaFon",
        country: "ru",
    },
    BlockPageHost {
        host: "lp.megafon.tv",
        operator: "MegaFon",
        country: "ru",
    },
    BlockPageHost {
        host: "m.megafonpro.ru",
        operator: "MegaFon",
        country: "ru",
    },
    BlockPageHost {
        host: "t2blocked.com",
        operator: "Tele2",
        country: "ru",
    },
    BlockPageHost {
        host: "t2-blocked.com",
        operator: "Tele2",
        country: "ru",
    },
    BlockPageHost {
        host: "forbidden.yota.ru",
        operator: "Yota",
        country: "ru",
    },
    BlockPageHost {
        host: "lawfilter.ertelecom.ru",
        operator: "ER-Telecom",
        country: "ru",
    },
    BlockPageHost {
        host: "internetpositif.id",
        operator: "Komdigi",
        country: "id",
    },
    BlockPageHost {
        host: "internetsehatku.com",
        operator: "Komdigi",
        country: "id",
    },
    BlockPageHost {
        host: "trustpositif.komdigi.go.id",
        operator: "Komdigi",
        country: "id",
    },
    BlockPageHost {
        host: "trustpositif.kominfo.go.id",
        operator: "Komdigi",
        country: "id",
    },
    BlockPageHost {
        host: "peyvandha.ir",
        operator: "Iran national filter",
        country: "ir",
    },
    BlockPageHost {
        host: "internet.btk.gov.tr",
        operator: "BTK",
        country: "tr",
    },
    BlockPageHost {
        host: "ukispcourtorders.co.uk",
        operator: "BT",
        country: "gb",
    },
];

/// The notice page `hostname` belongs to, if any. Exact host or any subdomain
/// of it; case and a trailing dot are ignored.
#[must_use]
pub fn block_page_for_hostname(hostname: &str) -> Option<&'static BlockPageHost> {
    let host = hostname.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }
    BLOCK_PAGE_HOSTS.iter().find(|entry| {
        host == entry.host
            || (host.len() > entry.host.len()
                && host.ends_with(entry.host)
                && host.as_bytes()[host.len() - entry.host.len() - 1] == b'.')
    })
}

/// Is `hostname` an operator notice page?
#[must_use]
pub fn is_block_page_hostname(hostname: &str) -> bool {
    block_page_for_hostname(hostname).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_page_observed_in_the_field_is_recognised() {
        let hit = block_page_for_hostname("fz139.ttk.ru").expect("known page");
        assert_eq!(hit.operator, "TTK");
        assert_eq!(hit.country, "ru");
    }

    #[test]
    fn a_subdomain_of_a_notice_page_counts_but_a_lookalike_does_not() {
        assert!(is_block_page_hostname("m.warning.rt.ru"));
        assert!(is_block_page_hostname("WARNING.RT.RU."));
        // Same tail, different name — the boundary must be a real label break.
        assert!(!is_block_page_hostname("notwarning.rt.ru"));
        // The operator's ordinary site is not a notice page.
        assert!(!is_block_page_hostname("rt.ru"));
        assert!(!is_block_page_hostname("mts.ru"));
    }

    #[test]
    fn ordinary_hosts_and_blank_input_never_match() {
        assert!(!is_block_page_hostname("youporn.com"));
        assert!(!is_block_page_hostname(""));
        assert!(!is_block_page_hostname("   "));
    }

    #[test]
    fn a_shared_hosting_domain_is_never_an_entry() {
        // Some operators serve their notice from a domain that also carries
        // ordinary assets (Virgin Media's `assets.virginmedia.com`). Matching
        // that would call every asset fetch a block, so such pages stay out.
        assert!(!is_block_page_hostname("assets.virginmedia.com"));
    }

    #[test]
    fn every_entry_is_a_normalised_host() {
        for entry in BLOCK_PAGE_HOSTS {
            assert_eq!(entry.host, entry.host.to_ascii_lowercase(), "{entry:?}");
            assert!(!entry.host.ends_with('.'), "{entry:?}");
            assert!(entry.host.contains('.'), "{entry:?}");
            assert!(!entry.operator.is_empty(), "{entry:?}");
            assert_eq!(entry.country.len(), 2, "{entry:?}");
        }
    }
}
