//! Zones anybody can register a name under, and what a name there may bring
//! into the tunnel.
//!
//! A zone rule on a public top-level name (`ru`, `com`) covers names their
//! owners choose, the owner of a hostile page included. Such a name answering
//! with a private address points the tunnel at the user's own or the tunnel's
//! internal network on a stranger's say-so, so that address is not routed
//! there. A zone the public cannot register under (`intra`, `corp.example.com`)
//! names hosts of whoever runs it, and a corporate tunnel to 10.x keeps working.

use std::net::IpAddr;

/// Generic top-level names. Not the root zone: the ones a zone rule is
/// plausibly written for. A label missing here keeps the private addresses
/// it answers with, as every zone did before.
const GENERIC_TLDS: &[&str] = &[
    "com",
    "net",
    "org",
    "info",
    "biz",
    "edu",
    "gov",
    "mil",
    "int",
    "name",
    "pro",
    "mobi",
    "asia",
    "tel",
    "travel",
    "jobs",
    "aero",
    "coop",
    "museum",
    "cat",
    "xyz",
    "top",
    "online",
    "site",
    "store",
    "shop",
    "app",
    "dev",
    "club",
    "live",
    "tech",
    "space",
    "website",
    "fun",
    "icu",
    "vip",
    "work",
    "life",
    "world",
    "today",
    "news",
    "blog",
    "cloud",
    "link",
    "click",
    "page",
    "media",
    "art",
    "one",
    "group",
    "global",
    "digital",
    "network",
    "email",
    "games",
    "agency",
    "solutions",
    "services",
    "company",
    "center",
    "zone",
    "moscow",
    "tatar",
];

/// Internationalised country names, as stored (ACE).
const IDN_COUNTRY_TLDS: &[&str] = &[
    "xn--p1ai",          // рф
    "xn--p1acf",         // рус
    "xn--90ais",         // бел
    "xn--j1amh",         // укр
    "xn--80ao21a",       // қаз
    "xn--d1alf",         // мкд
    "xn--90a3ac",        // срб
    "xn--l1acc",         // мон
    "xn--90ae",          // бг
    "xn--node",          // გე
    "xn--y9a3aq",        // հայ
    "xn--fiqs8s",        // 中国
    "xn--fiqz9s",        // 中國
    "xn--j6w193g",       // 香港
    "xn--kprw13d",       // 台湾
    "xn--3e0b707e",      // 한국
    "xn--wgbh1c",        // مصر
    "xn--mgberp4a5d4ar", // السعودية
    "xn--mgbaam7a8h",    // امارات
    "xn--h2brj9c",       // भारत
    "xn--o3cw4h",        // ไทย
];

/// ISO 3166 codes reserved for private use: never delegated as countries.
fn is_private_use_code(code: &[u8; 2]) -> bool {
    matches!(
        code,
        [b'a', b'a'] | [b'q', b'm'..=b'z'] | [b'x', b'a'..=b'z'] | [b'z', b'z']
    )
}

/// Whether `label` is a top-level name the public registers under: every
/// two-letter country code, the generic names above, and the country names
/// in other scripts.
#[must_use]
pub fn is_public_tld(label: &str) -> bool {
    let label = label.trim_matches('.').to_ascii_lowercase();
    if let [a, b] = label.as_bytes() {
        let code = [*a, *b];
        return code.iter().all(u8::is_ascii_lowercase) && !is_private_use_code(&code);
    }
    GENERIC_TLDS.contains(&label.as_str()) || IDN_COUNTRY_TLDS.contains(&label.as_str())
}

/// Whether a zone rule is a public top-level name: one label, registrable by
/// anyone.
#[must_use]
pub fn is_public_zone(zone: &str) -> bool {
    let zone = zone.trim_matches('.');
    !zone.is_empty() && !zone.contains('.') && is_public_tld(zone)
}

/// Whether a name held only through the public zone its last label names
/// may bring `ip` into the tunnel. A private or shared address may not.
#[must_use]
pub fn admits_zone_learned_address(host: &str, ip: IpAddr) -> bool {
    let tld = host.trim_end_matches('.').rsplit('.').next().unwrap_or("");
    !(is_public_zone(tld) && crate::ip_network_policy::is_private_address(ip))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn country_and_generic_names_are_public_and_internal_ones_are_not() {
        for public in ["ru", "RU", "com", "xn--p1ai", "by", ".ru."] {
            assert!(is_public_zone(public), "{public}");
        }
        for internal in [
            "intra", "corp", "local", "lan", "internal", "home", "zz", "xa", "qm",
        ] {
            assert!(!is_public_zone(internal), "{internal}");
        }
        assert!(!is_public_zone("corp.example.com"), "several labels");
        assert!(!is_public_zone(""));
    }

    #[test]
    fn a_public_zone_name_brings_no_private_address() {
        let private = [
            "10.1.2.3",
            "172.16.0.9",
            "192.168.1.1",
            "100.64.0.5",
            "fd00::1",
        ];
        for ip in private {
            let ip: IpAddr = ip.parse().expect("literal");
            assert!(!admits_zone_learned_address("a1.attacker.ru", ip), "{ip}");
            assert!(admits_zone_learned_address("git.corp.intra", ip), "{ip}");
        }
        let public: IpAddr = "203.0.113.7".parse().expect("literal");
        assert!(admits_zone_learned_address("a1.attacker.ru", public));
    }
}
