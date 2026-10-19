use super::*;

// ── What a rule by program path covers for the caller ────────────────────────

/// `outcome` of an [`AppPathCoverageResponse`]: the value is a name, not a
/// path.
pub const APP_PATH_COVERAGE_NOT_A_PATH: &str = "not-a-path";
/// The value is a path that names no program (`form` says why).
pub const APP_PATH_COVERAGE_INVALID: &str = "invalid";
/// The rule may not be saved (`refusal-key` says why); the disk was not
/// listed for it.
pub const APP_PATH_COVERAGE_REFUSED: &str = "refused";
/// The place exists; `programs` is what it holds now.
pub const APP_PATH_COVERAGE_FOUND: &str = "found";
/// Nothing is there yet.
pub const APP_PATH_COVERAGE_MISSING: &str = "missing";
/// This platform applies no rule by path.
pub const APP_PATH_COVERAGE_UNSUPPORTED: &str = "unsupported";

/// `rules.app-path-coverage.get` — what an application rule by path would
/// cover for the caller, asked by the rule form while it is open.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct AppPathCoverageRequest {
    /// The value as the form holds it; rule flags (`+children`) are not part
    /// of the path. Bounded like a rule value.
    pub value: String,
    /// The route the form has chosen (`primary`, `secondary`, `block`): what
    /// the protection of system programs judges.
    #[serde(default)]
    pub route: String,
}

/// The answer to [`AppPathCoverageRequest`]. Only the caller's own folders
/// are read; another user's profile is refused before the disk is touched.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct AppPathCoverageResponse {
    /// What the value names, as `app_value_form` spells it (`folder-tree`,
    /// `path-star`, `name`, …).
    pub form: String,
    /// One of the `APP_PATH_COVERAGE_*` slugs.
    pub outcome: String,
    /// Programs the rule covers now, at most what one rule covers.
    #[serde(default)]
    pub programs: u32,
    /// The folder holds more programs than one rule covers.
    #[serde(default)]
    pub truncated: bool,
    /// The place for the caller as the disk has it, profile folders resolved
    /// and links followed; empty when unknown.
    #[serde(default)]
    pub place: String,
    /// Anyone may put a program there: a warning, and never an exemption
    /// from leak protection.
    #[serde(default)]
    pub anyone_can_write: bool,
    /// The locale key of why the rule may not be saved; empty when it may.
    #[serde(default)]
    pub refusal_key: String,
    /// The locale key of a warning about the place the disk revealed.
    #[serde(default)]
    pub warning_key: String,
}
