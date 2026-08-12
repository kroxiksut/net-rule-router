use nrr_application::backend_facade::rules::{rules_screen_preview_snapshot, RulesScreenRequest};
use nrr_shared::{AppShellModel, RouteRole};

pub fn render_rules_screen(shell: &AppShellModel) {
    let snapshot = rules_screen_preview_snapshot(RulesScreenRequest::default());

    println!("Rules screen (block 2 preview):");
    println!("- Data source: {}", snapshot.data_source.title());
    println!("- {}", snapshot.preview_notice);
    println!("- Shared rules policy: {}", shell.rules.preview_notice);
    println!(
        "- Review is required before replace: {}",
        snapshot.load_list_dialog.requires_review_before_replace
    );
    let rule_types = snapshot
        .supported_rule_types
        .iter()
        .map(|rule_type| rule_type.title())
        .collect::<Vec<_>>()
        .join(", ");
    println!("- Supported Free rule types: {}", rule_types);
    let list_types = snapshot
        .supported_list_types
        .iter()
        .map(|list_type| list_type.title())
        .collect::<Vec<_>>()
        .join(", ");
    println!("- Supported Free list types: {}", list_types);
    let scenarios = snapshot
        .placeholder_scenarios
        .iter()
        .map(|scenario| scenario.title())
        .collect::<Vec<_>>()
        .join(", ");
    println!("- Placeholder scenarios: {}", scenarios);
    println!("- Active scenario: {}", snapshot.active_scenario.title());
    if let Some(search) = snapshot.applied_search_query.as_deref() {
        println!("- Applied search query: {}", search);
    } else {
        println!("- Applied search query: <none>");
    }
    if let Some(type_filter) = snapshot.applied_type_filter {
        println!("- Applied type filter: {}", type_filter.label());
    } else {
        println!("- Applied type filter: <none>");
    }
    println!("- Rule form fields and constraints:");
    for field in snapshot.form_fields {
        println!(
            "  {} | required={} | constraint={}",
            field.id.title(),
            field.required,
            field.constraint_hint
        );
    }
    println!("- Rules list:");
    for row in snapshot.rows {
        let target_route = match row.target_route {
            RouteRole::Primary => "primary",
            RouteRole::Secondary => "secondary",
        };
        println!(
            "  {} | enabled={} | type={} | value={} | target={} | comment={}",
            row.id,
            row.enabled,
            row.rule_type.title(),
            row.match_value,
            target_route,
            row.comment
        );
    }
    println!(
        "- Load list dialog fields: {}",
        snapshot.load_list_dialog.fields.join(", ")
    );
    println!(
        "- Load list accepted formats: {}",
        snapshot.load_list_dialog.accepted_formats.join(", ")
    );
    println!(
        "- Edit list dialog fields: {}",
        snapshot.edit_list_dialog.fields.join(", ")
    );
    println!(
        "- Replace review dialog fields: {}",
        snapshot.replace_review_dialog.fields.join(", ")
    );
}
