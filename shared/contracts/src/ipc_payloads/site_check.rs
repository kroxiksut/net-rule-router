use super::*;

// ── "Check site": us or the site ─────────────────────────────────────────────

/// The longest name a `diagnostics.site-check.run` request may carry.
pub const SITE_CHECK_MAX_HOST_LEN: usize = 253;

/// Names one check examines, the one asked about included.
pub const SITE_CHECK_MAX_NAMES: usize = 8;

/// Redirects followed per name before the chain is reported as it stands.
pub const SITE_CHECK_MAX_REDIRECTS: usize = 5;

/// The first labels a site's sign-in usually lives under.
pub const SITE_CHECK_SIGN_IN_LABELS: [&str; 3] = ["login", "id", "auth"];

/// The site answers over its route; what is left lives in the browser.
pub const SITE_CHECK_VERDICT_FINE: &str = "fine";
/// The site's sign-in goes over another route than the site itself.
pub const SITE_CHECK_VERDICT_SIGN_IN_SPLIT: &str = "sign-in-split";
/// The site does not answer over its route.
pub const SITE_CHECK_VERDICT_NOT_ANSWERING: &str = "not-answering";
/// The route the site uses is not up.
pub const SITE_CHECK_VERDICT_ROUTE_DOWN: &str = "route-down";
/// A deny rule of the caller's holds the site.
pub const SITE_CHECK_VERDICT_BLOCKED: &str = "blocked";
/// Nothing could be measured, most often because no address is known yet.
pub const SITE_CHECK_VERDICT_UNCLEAR: &str = "unclear";
/// The site's certificate does not verify on its route: something there
/// answers in the site's place.
pub const SITE_CHECK_VERDICT_CERTIFICATE_UNTRUSTED: &str = "certificate-untrusted";

pub const SITE_CHECK_VERDICTS: [&str; 7] = [
    SITE_CHECK_VERDICT_FINE,
    SITE_CHECK_VERDICT_SIGN_IN_SPLIT,
    SITE_CHECK_VERDICT_CERTIFICATE_UNTRUSTED,
    SITE_CHECK_VERDICT_NOT_ANSWERING,
    SITE_CHECK_VERDICT_ROUTE_DOWN,
    SITE_CHECK_VERDICT_BLOCKED,
    SITE_CHECK_VERDICT_UNCLEAR,
];

/// What one name's check found.
pub const SITE_CHECK_ANSWERS: [&str; 7] = [
    "answered",
    "certificate-untrusted",
    "silent",
    "unclear",
    "no-address",
    "route-down",
    "blocked",
];

/// Why a name is part of the check.
pub const SITE_CHECK_ROLES: [&str; 3] = ["site", "sign-in", "seen-with"];

/// No check asked for since the service started.
pub const SITE_CHECK_STATE_IDLE: &str = "idle";
pub const SITE_CHECK_STATE_RUNNING: &str = "running";
pub const SITE_CHECK_STATE_DONE: &str = "done";
pub const SITE_CHECK_STATES: [&str; 3] = [
    SITE_CHECK_STATE_IDLE,
    SITE_CHECK_STATE_RUNNING,
    SITE_CHECK_STATE_DONE,
];

/// `diagnostics.site-check.run` — start checking one site over the caller's
/// own routes. The check runs on its own thread; the answer is read with
/// `diagnostics.site-check.result`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct SiteCheckRequest {
    /// A host name, at most [`SITE_CHECK_MAX_HOST_LEN`] bytes.
    pub host: String,
}

/// One name the check examined.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct SiteCheckNameDto {
    pub name: String,
    /// One of [`SITE_CHECK_ROLES`].
    pub role: String,
    /// The IPv4 address checked, or empty when none is known.
    #[serde(default)]
    pub address: String,
    /// `primary`, `secondary` or `blocked`: the route the caller's rules give it.
    pub route: String,
    /// One of [`SITE_CHECK_ANSWERS`].
    pub answer: String,
    /// The HTTPS status code, when this build reads the answer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// The hosts the `Location` chain went through, in order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redirects: Vec<String>,
}

/// What one finished check found.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct SiteCheckReport {
    /// The name checked, normalised.
    pub site: String,
    /// One of [`SITE_CHECK_VERDICTS`].
    pub verdict: String,
    /// The route the caller's rules give the site.
    pub site_route: String,
    pub names: Vec<SiteCheckNameDto>,
    /// The sign-in names on another route than the site, for the move the
    /// [`SITE_CHECK_VERDICT_SIGN_IN_SPLIT`] verdict offers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub move_names: Vec<String>,
    /// Whether the status code and the `Location` chain were read.
    #[serde(default)]
    pub reads_answer: bool,
}

/// `diagnostics.site-check.result` — the caller's latest check. Nothing to send.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct SiteCheckResultRequest {}

/// The answer of both site-check operations: the caller's latest check.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct SiteCheckStatus {
    /// One of [`SITE_CHECK_STATES`].
    pub state: String,
    /// The name the latest check is about, normalised; empty while idle.
    #[serde(default)]
    pub host: String,
    /// Set once the check is done.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report: Option<SiteCheckReport>,
}
