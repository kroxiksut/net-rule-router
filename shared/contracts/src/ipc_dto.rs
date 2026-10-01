/// IPC-shape mirror of `nrr-domain::revision::RiskLevel` (Low / Medium / High).
///
/// The two enums have identical variants but distinct types because the
/// dependency direction is `domain → shared` — `nrr-shared` cannot import
/// from `nrr-domain`, so the wire-level DTO type lives here and the domain
/// keeps its own canonical type. Service-runtime is responsible for the
/// trivial projection in both directions when constructing IPC responses or
/// consuming IPC requests; the canonical conversion lives in
/// `nrr-domain::revision` (`impl From<ReviewRiskLevel> for RiskLevel` and the
/// reverse), reusing the slug strings exposed by `as_slug` / `from_slug`.
///
/// Slugs match `nrr-domain::revision::RiskLevel`'s `Display` output:
/// `"low" | "medium" | "high" | "critical"`.
///
/// `Critical` is reserved for genuinely catastrophic configurations —
/// lock-out scenarios where the user is about to cut themselves off from
/// the network. Today no scoring path emits it (the production triggers —
/// primary↔secondary swap under fail-closed — need additional bindings +
/// behavior_mode plumbing). The level exists so the wire contract is
/// stable when those triggers land.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ReviewRiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl ReviewRiskLevel {
    pub const fn as_slug(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    pub fn from_slug(slug: &str) -> Option<Self> {
        match slug {
            "low" => Some(Self::Low),
            "medium" => Some(Self::Medium),
            "high" => Some(Self::High),
            "critical" => Some(Self::Critical),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ReviewRiskLevel;

    #[test]
    fn every_slug_round_trips() {
        for level in [
            ReviewRiskLevel::Low,
            ReviewRiskLevel::Medium,
            ReviewRiskLevel::High,
            ReviewRiskLevel::Critical,
        ] {
            assert_eq!(ReviewRiskLevel::from_slug(level.as_slug()), Some(level));
        }
    }

    #[test]
    fn an_unknown_slug_is_not_silently_mapped() {
        assert_eq!(ReviewRiskLevel::from_slug("catastrophic"), None);
    }
}
