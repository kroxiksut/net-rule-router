//! Troubleshooting playbooks for the diagnostic archive.
//!
//! Six symptoms a person actually reports, each with the steps that resolve it
//! or narrow it down, rendered into the archive's `troubleshooting.md`.
//!
//! The text is English and lives here as prose rather than as localization
//! keys. The keys were the original design and they produced a page of
//! unresolved names (`troubleshoot.stale_cache.step1.title`) pointing at an
//! in-app screen that does not exist — in every support archive. Whoever opens
//! this file is reading `manifest.json` and `health.json` beside it, which are
//! English too; a support bundle is not a localized surface.

// ── TroubleshootingStep ───────────────────────────────────────────────────────

pub struct TroubleshootingStep {
    /// What to do, as a short imperative.
    pub title: &'static str,
    /// Why, and what the outcome tells you.
    pub description: &'static str,
}

// ── TroubleshootingPlaybook ───────────────────────────────────────────────────

pub struct TroubleshootingPlaybook {
    /// The symptom in the reporter's words.
    pub symptom: &'static str,
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
        symptom: "The app says the background service is not running",
        id: "service-unavailable",
        steps: vec![
            TroubleshootingStep {
                title: "Check whether the service is running",
                description: "Run `nrr-cli status`, or open Services and look for \
                              NetRuleRouter. The console prints whether the service is \
                              installed, whether it is running, and which version it is.",
            },
            TroubleshootingStep {
                title: "Start it",
                description: "Run `nrr-cli start`. It needs administrator rights: an \
                              interactive console asks before elevating, and a script \
                              gets the exact command to repeat rather than a prompt \
                              nobody is there to answer.",
            },
            TroubleshootingStep {
                title: "If it starts and stops again, read the last lines before the stop",
                description: "`logs.ndjson` in this archive holds the service's own \
                              account of what it was doing. A service that exits on its \
                              own says why on the way out.",
            },
        ],
    }
}

fn secondary_no_ip_playbook() -> TroubleshootingPlaybook {
    TroubleshootingPlaybook {
        symptom: "The additional connection is selected but has no address",
        id: "secondary-no-ip",
        steps: vec![
            TroubleshootingStep {
                title: "Bring the connection up in its own client first",
                description: "NetRuleRouter routes over connections that already exist; \
                              it does not establish them. Until the client reports the \
                              connection as up and its adapter holds an IPv4 address, \
                              there is nothing to route onto.",
            },
            TroubleshootingStep {
                title: "Check that the adapter you picked is the one the client raised",
                description: "Some clients create a new adapter when they update, so the \
                              one chosen earlier can still exist while sitting idle. \
                              Interfaces and routes lists every adapter with its current \
                              address — pick the one holding the address.",
            },
        ],
    }
}

fn fail_closed_block_playbook() -> TroubleshootingPlaybook {
    TroubleshootingPlaybook {
        symptom: "A site does not open and the app reports the traffic as blocked",
        id: "fail-closed-block",
        steps: vec![
            TroubleshootingStep {
                title: "Check whether the additional connection is up",
                description: "While it is down, traffic your rules send through it is \
                              blocked rather than allowed out the main connection. That \
                              is leak protection working as configured, and it clears by \
                              itself once the connection returns.",
            },
            TroubleshootingStep {
                title: "Decide whether you want that trade",
                description: "Leak protection can be switched off in Settings, Routing. \
                              The same traffic then leaves over the main connection while \
                              the additional one is down — reachable, and visible to \
                              whoever can see that link.",
            },
            TroubleshootingStep {
                title: "If the connection is up and traffic is still blocked, read the notice",
                description: "The block notice in the app names what stopped the \
                              connection: a rule you wrote, or a switch such as the IPv6 \
                              cut or the DNS lockdown, which have no rule behind them. \
                              `health.json` in this archive states the same posture the \
                              service was in.",
            },
        ],
    }
}

fn stale_cache_playbook() -> TroubleshootingPlaybook {
    TroubleshootingPlaybook {
        symptom: "A site takes the wrong connection, or stops opening, after its addresses changed",
        id: "stale-cache",
        steps: vec![
            TroubleshootingStep {
                title: "Open the site again",
                description: "A rule follows the addresses its name currently answers \
                              with, so a name whose addresses have just moved can be \
                              enforced on the previous ones for a short while. One fresh \
                              lookup normally settles it.",
            },
            TroubleshootingStep {
                title: "If it persists, clear the name caches and retry",
                description: "Clear the browser's own resolver cache and the operating \
                              system's, then open the site again. A name the machine \
                              never re-resolves cannot be re-learned.",
            },
        ],
    }
}

fn audit_integrity_failure_playbook() -> TroubleshootingPlaybook {
    TroubleshootingPlaybook {
        symptom: "The app reports that the audit trail failed its integrity check",
        id: "audit-integrity-failure",
        steps: vec![
            TroubleshootingStep {
                title: "Nothing about your routing is affected",
                description: "The audit trail is a record of what was done, not a control \
                              over what happens. Rules keep being enforced exactly as \
                              before while this is investigated.",
            },
            TroubleshootingStep {
                title: "Look for something editing the data directory",
                description: "The check fails when audit files were changed or truncated \
                              outside the app — a backup tool, an antivirus quarantine, \
                              or a manual edit. Excluding the data directory from such \
                              tools prevents a recurrence.",
            },
            TroubleshootingStep {
                title: "Send this archive",
                description: "`audit_summary.json` shows where the record stops being \
                              self-consistent, which is what identifies the moment \
                              something else touched it.",
            },
        ],
    }
}

fn import_pending_playbook() -> TroubleshootingPlaybook {
    TroubleshootingPlaybook {
        symptom: "An imported rule set is shown in the app but is not being applied",
        id: "import-pending",
        steps: vec![
            TroubleshootingStep {
                title: "An import is a proposal until you apply it",
                description: "The table shows what the file holds; the service keeps \
                              enforcing what it already had. Use Save and review to see \
                              what would change, then confirm it.",
            },
            TroubleshootingStep {
                title: "If applying is refused, the message names the reason",
                description: "A value that is not valid, or more rules than a set may \
                              hold. Rules the app will not apply are marked in the table; \
                              fix those lines and apply again.",
            },
        ],
    }
}

// ── Markdown renderer ─────────────────────────────────────────────────────────

/// Renders playbooks as a Markdown document for the archive.
pub fn render_playbooks_markdown(playbooks: &[TroubleshootingPlaybook]) -> String {
    let mut md = String::new();
    md.push_str("# NetRuleRouter — Troubleshooting Guide\n\n");
    md.push_str("Common symptoms and what to check for each. Everything referenced\n");
    md.push_str("here (`health.json`, `logs.ndjson`, `audit_summary.json`) is in this\n");
    md.push_str("archive next to this file.\n\n");
    md.push_str("---\n\n");

    for playbook in playbooks {
        md.push_str(&format!("## {} (`{}`)\n\n", playbook.symptom, playbook.id));
        for (i, step) in playbook.steps.iter().enumerate() {
            md.push_str(&format!(
                "**Step {}: {}**\n\n{}\n\n",
                i + 1,
                step.title,
                step.description
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

    /// The defect this file was rewritten for: a support archive full of
    /// unresolved key names. A key is recognisable by its shape, so the shape
    /// is what the test refuses.
    #[test]
    fn no_playbook_text_is_a_localization_key() {
        for p in all_playbooks() {
            let mut texts = vec![p.symptom];
            for step in &p.steps {
                texts.push(step.title);
                texts.push(step.description);
            }
            for text in texts {
                assert!(
                    !text.starts_with("troubleshoot."),
                    "playbook '{}' still carries a key instead of text: {text}",
                    p.id
                );
                assert!(
                    text.contains(' '),
                    "playbook '{}' carries a single token where a sentence belongs: {text}",
                    p.id
                );
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
