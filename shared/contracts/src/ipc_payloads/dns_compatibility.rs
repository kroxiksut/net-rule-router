use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsCompatibilityRecheckRequest {}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct DnsCompatibilityDto {
    #[serde(default)]
    pub instance_id: String,
    #[serde(default)]
    pub sequence: u64,
    #[serde(default)]
    pub verified_program: Option<String>,
    #[serde(default)]
    pub history_incomplete: bool,
    pub status: DnsCompatibilityStatus,
    pub issues: Vec<DnsCompatibilityIssueDto>,
    pub last_checked_ms: Option<u64>,
    pub recovery_pending: bool,
    pub resolver: DnsResolverReadinessDto,
    #[serde(default)]
    pub browser_settings: Vec<crate::browser_dns_settings::BrowserDnsSettingsDto>,
    #[serde(default = "dns_compatibility_actions")]
    pub available_actions: Vec<DnsCompatibilityAction>,
    #[serde(default = "unchecked_readiness")]
    pub secondary_readiness: String,
}

impl Default for DnsCompatibilityDto {
    fn default() -> Self {
        Self {
            instance_id: String::new(),
            sequence: 0,
            verified_program: None,
            history_incomplete: false,
            status: DnsCompatibilityStatus::Unchecked,
            issues: Vec::new(),
            last_checked_ms: None,
            recovery_pending: false,
            resolver: DnsResolverReadinessDto::default(),
            browser_settings: Vec::new(),
            available_actions: dns_compatibility_actions(),
            secondary_readiness: unchecked_readiness(),
        }
    }
}

fn unchecked_readiness() -> String {
    "unchecked".to_owned()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DnsCompatibilityAction {
    Recheck,
    BrowserInstructions,
    CheckSecondary,
    DiagnoseSite,
}

pub fn dns_compatibility_actions() -> Vec<DnsCompatibilityAction> {
    vec![
        DnsCompatibilityAction::Recheck,
        DnsCompatibilityAction::BrowserInstructions,
        DnsCompatibilityAction::CheckSecondary,
        DnsCompatibilityAction::DiagnoseSite,
    ]
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct DnsResolverReadinessDto {
    pub listener: String,
    pub redirect: String,
    pub upstream: String,
}

impl Default for DnsResolverReadinessDto {
    fn default() -> Self {
        Self {
            listener: "unchecked".to_owned(),
            redirect: "unchecked".to_owned(),
            upstream: "unchecked".to_owned(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DnsCompatibilityStatus {
    Limited,
    NeedsRecheck,
    Verified,
    #[default]
    #[serde(other)]
    Unchecked,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct DnsCompatibilityIssueDto {
    pub program: String,
    pub reason: String,
    pub evidence: String,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    pub attempts: u32,
    pub needs_recheck: bool,
}
