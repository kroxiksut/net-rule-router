//! Troubleshooting playbooks.
//!
//! Playbooks describe common symptoms and step-by-step remediation actions.
//! Text is represented as localization keys — the GUI resolves them; this
//! module only generates a Markdown skeleton for the archive `troubleshooting.md`.

// ── TroubleshootingStep ───────────────────────────────────────────────────────

pub struct TroubleshootingStep {
    /// Localization key for the step title.
    pub title_key: &'static str,
    /// Localization key for the step description.
    pub description_key: &'static str,
}

// ── TroubleshootingPlaybook ───────────────────────────────────────────────────

pub struct TroubleshootingPlaybook {
    /// Localization key for the symptom title.
    pub symptom_key: &'static str,
    /// Stable identifier used in Markdown anchors.
    pub id: &'static str,
    /// Ordered list of remediation steps.
    pub steps: Vec<TroubleshootingStep>,
}

// ── Canonical playbooks ───────────────────────────────────────────────────────

/// Returns all canonical troubleshooting playbooks.
pub fn all_playbooks() -> Vec<TroubleshootingPlaybook> {
    vec![
        service_unavailable_playbook(),
        secondary_no_ip_playbook(),
        fail_closed_block_playbook(),
        stale_cache_playbook(),
        audit_integrity_failure_playbook(),
        import_pending_playbook(),
    ]
}

fn service_unavailable_playbook() -> TroubleshootingPlaybook {
    TroubleshootingPlaybook {
        symptom_key: "troubleshoot.service_unavailable.symptom",
        id: "service-unavailable",
        steps: vec![
            TroubleshootingStep {
                title_key: "troubleshoot.service_unavailable.step1.title",
                description_key: "troubleshoot.service_unavailable.step1.description",
            },
            TroubleshootingStep {
                title_key: "troubleshoot.service_unavailable.step2.title",
                description_key: "troubleshoot.service_unavailable.step2.description",
            },
            TroubleshootingStep {
                title_key: "troubleshoot.service_unavailable.step3.title",
                description_key: "troubleshoot.service_unavailable.step3.description",
            },
        ],
    }
}

fn secondary_no_ip_playbook() -> TroubleshootingPlaybook {
    TroubleshootingPlaybook {
        symptom_key: "troubleshoot.secondary_no_ip.symptom",
        id: "secondary-no-ip",
        steps: vec![
            TroubleshootingStep {
                title_key: "troubleshoot.secondary_no_ip.step1.title",
                description_key: "troubleshoot.secondary_no_ip.step1.description",
            },
            TroubleshootingStep {
                title_key: "troubleshoot.secondary_no_ip.step2.title",
                description_key: "troubleshoot.secondary_no_ip.step2.description",
            },
        ],
    }
}

fn fail_closed_block_playbook() -> TroubleshootingPlaybook {
    TroubleshootingPlaybook {
        symptom_key: "troubleshoot.fail_closed_block.symptom",
        id: "fail-closed-block",
        steps: vec![
            TroubleshootingStep {
                title_key: "troubleshoot.fail_closed_block.step1.title",
                description_key: "troubleshoot.fail_closed_block.step1.description",
            },
            TroubleshootingStep {
                title_key: "troubleshoot.fail_closed_block.step2.title",
                description_key: "troubleshoot.fail_closed_block.step2.description",
            },
            TroubleshootingStep {
                title_key: "troubleshoot.fail_closed_block.step3.title",
                description_key: "troubleshoot.fail_closed_block.step3.description",
            },
        ],
    }
}

fn stale_cache_playbook() -> TroubleshootingPlaybook {
    TroubleshootingPlaybook {
        symptom_key: "troubleshoot.stale_cache.symptom",
        id: "stale-cache",
        steps: vec![
            TroubleshootingStep {
                title_key: "troubleshoot.stale_cache.step1.title",
                description_key: "troubleshoot.stale_cache.step1.description",
            },
            TroubleshootingStep {
                title_key: "troubleshoot.stale_cache.step2.title",
                description_key: "troubleshoot.stale_cache.step2.description",
            },
        ],
    }
}

fn audit_integrity_failure_playbook() -> TroubleshootingPlaybook {
    TroubleshootingPlaybook {
        symptom_key: "troubleshoot.audit_integrity_failure.symptom",
        id: "audit-integrity-failure",
        steps: vec![
            TroubleshootingStep {
                title_key: "troubleshoot.audit_integrity_failure.step1.title",
                description_key: "troubleshoot.audit_integrity_failure.step1.description",
            },
            TroubleshootingStep {
                title_key: "troubleshoot.audit_integrity_failure.step2.title",
                description_key: "troubleshoot.audit_integrity_failure.step2.description",
            },
            TroubleshootingStep {
                title_key: "troubleshoot.audit_integrity_failure.step3.title",
                description_key: "troubleshoot.audit_integrity_failure.step3.description",
            },
        ],
    }
}

fn import_pending_playbook() -> TroubleshootingPlaybook {
    TroubleshootingPlaybook {
        symptom_key: "troubleshoot.import_pending.symptom",
        id: "import-pending",
        steps: vec![
            TroubleshootingStep {
                title_key: "troubleshoot.import_pending.step1.title",
                description_key: "troubleshoot.import_pending.step1.description",
            },
            TroubleshootingStep {
                title_key: "troubleshoot.import_pending.step2.title",
                description_key: "troubleshoot.import_pending.step2.description",
            },
        ],
    }
}

// ── Markdown renderer ─────────────────────────────────────────────────────────

/// Renders playbooks as a Markdown document for the archive.
///
/// Text is shown as localization key references since the archive may be
/// opened without the application.  A note explains this at the top.
pub fn render_playbooks_markdown(playbooks: &[TroubleshootingPlaybook]) -> String {
    let mut md = String::new();
    md.push_str("# NetRuleRouter — Troubleshooting Guide\n\n");
    md.push_str("> **Note:** This file uses localization key references.\n");
    md.push_str("> Open the Troubleshooting section in the application for\n");
    md.push_str("> fully localized instructions.\n\n");
    md.push_str("---\n\n");

    for playbook in playbooks {
        md.push_str(&format!(
            "## {} (`{}`)\n\n",
            playbook.symptom_key, playbook.id
        ));
        for (i, step) in playbook.steps.iter().enumerate() {
            md.push_str(&format!(
                "**Step {}: {}**\n\n{}\n\n",
                i + 1,
                step.title_key,
                step.description_key
            ));
        }
        md.push_str("---\n\n");
    }

    md
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_playbooks_returns_six_scenarios() {
        let playbooks = all_playbooks();
        assert_eq!(playbooks.len(), 6);
    }

    #[test]
    fn all_playbooks_have_stable_ids() {
        let playbooks = all_playbooks();
        let ids: Vec<&str> = playbooks.iter().map(|p| p.id).collect();
        assert!(ids.contains(&"service-unavailable"));
        assert!(ids.contains(&"fail-closed-block"));
        assert!(ids.contains(&"audit-integrity-failure"));
        assert!(ids.contains(&"stale-cache"));
        assert!(ids.contains(&"import-pending"));
        assert!(ids.contains(&"secondary-no-ip"));
    }

    #[test]
    fn all_playbook_keys_have_troubleshoot_prefix() {
        for p in all_playbooks() {
            assert!(
                p.symptom_key.starts_with("troubleshoot."),
                "symptom key must have troubleshoot. prefix: {}",
                p.symptom_key
            );
            for step in &p.steps {
                assert!(step.title_key.starts_with("troubleshoot."));
                assert!(step.description_key.starts_with("troubleshoot."));
            }
        }
    }

    #[test]
    fn rendered_markdown_contains_all_ids() {
        let playbooks = all_playbooks();
        let md = render_playbooks_markdown(&playbooks);
        for p in &playbooks {
            assert!(md.contains(p.id), "markdown must contain id: {}", p.id);
        }
    }

    #[test]
    fn rendered_markdown_starts_with_header() {
        let playbooks = all_playbooks();
        let md = render_playbooks_markdown(&playbooks);
        assert!(md.starts_with("# NetRuleRouter"));
    }

    #[test]
    fn each_playbook_has_at_least_two_steps() {
        for p in all_playbooks() {
            assert!(
                p.steps.len() >= 2,
                "playbook '{}' must have at least 2 steps",
                p.id
            );
        }
    }
}
