//! Public suffixes: the registries under which unrelated owners hold their
//! own names (`co.uk`, `com.br`, every bare top-level name).

/// Two-label public suffixes under which a name is registered one label
/// deeper (`AUTO_RULE_MULTI_LABEL_SUFFIXES`). Not the Public Suffix List: the
/// endings that show up under the countries the presets cover.
pub const MULTI_LABEL_SUFFIXES: &[&str] = &[
    "co.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk", "ac.uk", "gov.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au", "co.nz", "net.nz", "org.nz",
    "govt.nz", "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp", "co.kr", "or.kr", "ne.kr", "go.kr",
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "com.br", "net.br", "org.br", "gov.br",
    "com.mx", "org.mx", "gob.mx", "com.ar", "net.ar", "org.ar", "gob.ar", "co.in", "net.in",
    "org.in", "gov.in", "firm.in", "gen.in", "ind.in", "ac.in", "edu.in", "res.in", "co.za",
    "org.za", "net.za", "gov.za", "com.tr", "org.tr", "net.tr", "gov.tr", "edu.tr", "co.il",
    "org.il", "net.il", "gov.il", "com.sg", "net.sg", "org.sg", "gov.sg", "com.hk", "org.hk",
    "net.hk", "gov.hk", "com.tw", "org.tw", "net.tw", "gov.tw", "com.my", "net.my", "org.my",
    "gov.my", "com.ua", "net.ua", "org.ua", "gov.ua", "net.ru", "org.ru", "com.ru", "pp.ru",
    "msk.ru", "spb.ru", "co.ae", "net.ae", "org.ae", "gov.ae", "sch.ae", "ac.ae", "com.bh",
    "net.bh", "org.bh", "gov.bh", "com.eg", "net.eg", "org.eg", "gov.eg", "edu.eg", "sci.eg",
    "co.id", "net.id", "or.id", "web.id", "my.id", "biz.id", "ac.id", "sch.id", "go.id", "co.ir",
    "net.ir", "org.ir", "gov.ir", "sch.ir", "ac.ir", "com.kw", "net.kw", "org.kw", "edu.kw",
    "gov.kw", "org.kz", "edu.kz", "net.kz", "gov.kz", "mil.kz", "com.kz", "co.om", "com.om",
    "net.om", "org.om", "edu.om", "gov.om", "com.qa", "net.qa", "org.qa", "edu.qa", "gov.qa",
    "com.sa", "net.sa", "org.sa", "gov.sa", "med.sa", "pub.sa", "edu.sa", "sch.sa", "com.vn",
    "net.vn", "org.vn", "gov.vn", "edu.vn",
];

/// Whether a domain value is itself a public suffix (`isPublicSuffixValue`):
/// a suffix rule over one routes strangers, not a service, which is what a
/// zone rule is for. A leading `*.` and one trailing dot are not part of it.
pub fn is_public_suffix_value(value: &str) -> bool {
    let lower = value.to_lowercase();
    let host = lower.strip_prefix("*.").unwrap_or(&lower);
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty() || is_dotted_quad(host) {
        return false;
    }
    match host.split('.').count() {
        1 => true,
        2 => MULTI_LABEL_SUFFIXES.contains(&host),
        _ => false,
    }
}

/// `/^\d+\.\d+\.\d+\.\d+$/`.
pub(crate) fn is_dotted_quad(host: &str) -> bool {
    let parts: Vec<&str> = host.split('.').collect();
    parts.len() == 4
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}
