use nrr_application::backend_facade::security_status::security_status_preview_snapshot;
use nrr_shared::{AppShellModel, SecurityIndicatorId, VisibilityScope};

pub fn render_global_security_status(shell: &AppShellModel) {
    let security = security_status_preview_snapshot();
    println!("Global security status banner:");

    for rule in shell.security_visibility.rules {
        if matches!(rule.scope, VisibilityScope::AlwaysVisible) {
            let value = match rule.indicator {
                SecurityIndicatorId::ActiveRevision => security.active_revision,
                SecurityIndicatorId::PendingChanges => security.pending_changes.title(),
                SecurityIndicatorId::TamperAlerts => security.tamper_alerts.title(),
                SecurityIndicatorId::RollbackState => security.rollback_state.title(),
                SecurityIndicatorId::ServiceStatus => security.service_status.title(),
                SecurityIndicatorId::ExplainWarnings => security.explain_warnings.title(),
            };
            println!("- {}: {}", rule.indicator.title(), value);
        }
    }
}

pub fn render_screen_only_security_status(shell: &AppShellModel) {
    let security = security_status_preview_snapshot();
    for rule in shell.security_visibility.rules {
        if matches!(rule.scope, VisibilityScope::ScreenOnly) {
            let value = match rule.indicator {
                SecurityIndicatorId::ExplainWarnings => security.explain_warnings.title(),
                _ => "n/a",
            };
            println!("- Screen-only status {}: {}", rule.indicator.title(), value);
        }
    }
}
